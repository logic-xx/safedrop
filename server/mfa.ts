import { createHmac, randomBytes, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, openSync, writeFileSync, fsyncSync, closeSync, mkdirSync, realpathSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { need, Fault, digest, type Store } from './store.ts';
import { separate } from './backup.ts';

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(bytes: Uint8Array) {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { out += alphabet[(value >>> (bits -= 5)) & 31]; } }
  if (bits) out += alphabet[(value << (5 - bits)) & 31]; return out;
}
export function unbase32(value: string) {
  need(/^[A-Z2-7]+$/.test(value), 'MFA_INVALID_SECRET'); let bits = 0, buffer = 0; const out: number[] = [];
  for (const c of value) { buffer = (buffer << 5) | alphabet.indexOf(c); bits += 5; if (bits >= 8) out.push((buffer >>> (bits -= 8)) & 255); }
  return Buffer.from(out);
}
// RFC 4226 dynamic truncation; RFC 6238 uses floor(Unix time / 30 seconds).
export function hotp(secret: Uint8Array, counter: number, digits = 6) {
  const moving = Buffer.alloc(8); moving.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', secret).update(moving).digest(), offset = h[h.length - 1] & 15;
  return String((h.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits).padStart(digits, '0');
}
export function totp(secret: Uint8Array, now = Date.now(), digits = 6) { return hotp(secret, Math.floor(now / 30000), digits); }
function matchingCounter(secret: Uint8Array, code: unknown, now: number) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return undefined;
  const current = Math.floor(now / 30000);
  for (const step of [0, -1, 1]) { const counter = current + step; if (counter >= 0 && timingSafeEqual(Buffer.from(code), Buffer.from(hotp(secret, counter)))) return counter; }
}
function normalizeRecovery(value: unknown) { return typeof value === 'string' && value.length <= 64 ? value.replace(/[\s-]/g, '').toLowerCase() : ''; }
export type Factor = 'totp' | 'recovery';
export type MfaProof = { method: Factor; consume: () => void };
export class MfaGuard {
  private key?: Buffer;
  constructor(public store: Store, public keyFile: string, public now = () => Date.now(), public backupRoot = store.root + '.backups') {
    this.isolated(keyFile);
    // A missing or incorrect deployment key must never silently disable enrolled MFA.
    for (const row of store.all('SELECT userId,secret FROM mfa_settings')) this.decrypt(row.userId, row.secret);
  }
  private isolated(path: string) { try { separate(this.store.root, path); separate(this.backupRoot, path); } catch { throw new Fault('MFA_KEY_PATH_UNSAFE'); } }
  private master(create = false) {
    if (this.key) return this.key;
    if (!existsSync(this.keyFile)) {
      need(create, 'MFA_KEY_UNAVAILABLE'); mkdirSync(dirname(this.keyFile), { recursive: true, mode: 0o700 });
      this.isolated(join(realpathSync(dirname(this.keyFile)), basename(this.keyFile)));
      let fd: number | undefined;
      try { fd = openSync(this.keyFile, 'wx', 0o600); writeFileSync(fd, randomBytes(32)); fsyncSync(fd); }
      catch (e) { if (!(e instanceof Error && 'code' in e && e.code === 'EEXIST')) throw new Fault('MFA_KEY_UNAVAILABLE'); }
      finally { if (fd !== undefined) closeSync(fd); }
    }
    const s = lstatSync(this.keyFile); need(s.isFile() && !s.isSymbolicLink() && s.size === 32, 'MFA_KEY_UNAVAILABLE');
    try { separate(realpathSync(this.store.root), realpathSync(this.keyFile)); if (existsSync(this.backupRoot)) separate(realpathSync(this.backupRoot), realpathSync(this.keyFile)); } catch { throw new Fault('MFA_KEY_PATH_UNSAFE'); }
    this.key = readFileSync(this.keyFile); need(this.key.length === 32, 'MFA_KEY_UNAVAILABLE'); return this.key;
  }
  private encrypt(userId: string, secret: Buffer) {
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', this.master(true), iv); cipher.setAAD(Buffer.from('SafeDrop MFA/1 ' + userId));
    const bytes = Buffer.concat([cipher.update(secret), cipher.final()]);
    return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), bytes.toString('base64url')].join('.');
  }
  private decrypt(userId: string, value: string) {
    const key = this.master();
    try {
      const parts = value.split('.'); need(parts.length === 4 && parts[0] === 'v1', 'MFA_SECRET_INVALID');
      const iv = Buffer.from(parts[1], 'base64url'), tag = Buffer.from(parts[2], 'base64url'); need(iv.length === 12 && tag.length === 16, 'MFA_SECRET_INVALID');
      const decipher = createDecipheriv('aes-256-gcm', key, iv); decipher.setAAD(Buffer.from('SafeDrop MFA/1 ' + userId)); decipher.setAuthTag(tag);
      const secret = Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64url')), decipher.final()]); need(secret.length === 20, 'MFA_SECRET_INVALID'); return secret;
    } catch { throw new Fault('MFA_KEY_UNAVAILABLE'); }
  }
  enabled(userId: string) { return Boolean(this.store.get('SELECT userId FROM mfa_settings WHERE userId=?', userId)); }
  status(userId: string) { return { enabled: this.enabled(userId), recoveryRemaining: this.store.get('SELECT COUNT(*) AS n FROM mfa_recovery WHERE userId=?', userId)!.n }; }
  factor(sessionId: string, userId: string, authVersion: number): Factor | undefined { return this.store.get('SELECT method FROM mfa_sessions WHERE sessionId=? AND userId=? AND authVersion=?', sessionId, userId, authVersion)?.method; }
  checkLimit(userId: string) { const row = this.store.get('SELECT blockedUntil FROM mfa_attempts WHERE userId=?', userId); need(!row || row.blockedUntil <= this.now(), 'MFA_RATE_LIMITED'); }
  private failed(userId: string): never {
    const now = this.now(), row = this.store.get('SELECT * FROM mfa_attempts WHERE userId=?', userId);
    const fresh = !row || now - row.windowStart >= 300000, failures = fresh ? 1 : row.failures + 1;
    this.store.run('INSERT INTO mfa_attempts VALUES(?,?,?,?) ON CONFLICT(userId) DO UPDATE SET failures=excluded.failures,windowStart=excluded.windowStart,blockedUntil=excluded.blockedUntil', userId, failures, fresh ? now : row.windowStart, failures >= 5 ? now + 300000 : 0);
    throw new Fault(failures >= 5 ? 'MFA_RATE_LIMITED' : 'MFA_INVALID');
  }
  proof(userId: string, code: unknown, recovery = false): MfaProof {
    this.checkLimit(userId); const row = this.store.get('SELECT * FROM mfa_settings WHERE userId=?', userId); need(row, 'MFA_NOT_ENABLED');
    if (recovery) {
      const normalized = normalizeRecovery(code), hash = digest(userId + ':' + normalized);
      if (!/^[a-f0-9]{32}$/.test(normalized) || !this.store.get('SELECT hash FROM mfa_recovery WHERE userId=? AND hash=?', userId, hash)) this.failed(userId);
      return { method: 'recovery', consume: () => { need(this.store.run('DELETE FROM mfa_recovery WHERE userId=? AND hash=?', userId, hash).changes === 1, 'MFA_INVALID'); this.store.run('DELETE FROM mfa_attempts WHERE userId=?', userId); } };
    }
    const secret = this.decrypt(userId, row.secret); let counter: number | undefined;
    try { counter = matchingCounter(secret, code, this.now()); } finally { secret.fill(0); }
    if (counter === undefined || counter <= row.lastCounter) this.failed(userId);
    return { method: 'totp', consume: () => { need(this.store.run('UPDATE mfa_settings SET lastCounter=? WHERE userId=? AND lastCounter<? AND secret=?', counter!, userId, counter!, row.secret).changes === 1, 'MFA_INVALID'); this.store.run('DELETE FROM mfa_attempts WHERE userId=?', userId); } };
  }
  enroll(userId: string, secret: Buffer, code: unknown) {
    this.checkLimit(userId); const counter = matchingCounter(secret, code, this.now()); if (counter === undefined) this.failed(userId);
    const sealed = this.encrypt(userId, secret);
    // Validate before the caller's transaction so failed-attempt counters cannot roll back.
    return () => {
      this.store.run('INSERT INTO mfa_settings VALUES(?,?,?,?) ON CONFLICT(userId) DO UPDATE SET secret=excluded.secret,lastCounter=excluded.lastCounter,created=excluded.created', userId, sealed, counter, this.now());
      this.store.run('DELETE FROM mfa_attempts WHERE userId=?', userId); return this.recoveryCodes(userId);
    };
  }
  recoveryCodes(userId: string) {
    const codes = Array.from({ length: 10 }, () => randomBytes(16).toString('hex').match(/.{4}/g)!.join('-'));
    this.store.run('DELETE FROM mfa_recovery WHERE userId=?', userId);
    for (const code of codes) this.store.run('INSERT INTO mfa_recovery VALUES(?,?)', userId, digest(userId + ':' + normalizeRecovery(code)));
    return codes;
  }
}
