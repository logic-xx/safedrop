import { createServer as httpsServer } from 'node:https';
import { createServer as httpServer, type IncomingMessage } from 'node:http';
import { readFileSync, existsSync, createReadStream, statSync } from 'node:fs';
import { open, rename, unlink, stat } from 'node:fs/promises';
import { resolve, join, sep, extname } from 'node:path';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';
import { CHUNK, MAX_FRAME, encode, decode, type Frame } from '../shared/protocol.ts';
import { Store, Fault, need, text, integer, id, digest, passwordCheck, passwordHash, validAccount, verifyAudit, type Row, type Checkpoint } from './store.ts';
import { Bandwidth, RateGate } from './limits.ts';
import { createHash } from 'node:crypto';
import { StorageGuard, type StoragePolicy } from './storage.ts';
import { backupList, createBackup } from './backup.ts';
import { backupKeyLocation, readBackupKeys, backupKeyInfo } from './backup-keys.ts';
import { MfaGuard, base32, type MfaProof } from './mfa.ts';
import { ScanGuard } from './scans.ts';
import type { ScanEngine } from './clamd.ts';

export interface Config { root: string; origin: string; tls?: { cert: Buffer; key: Buffer }; webRoot?: string; reportPath?: string; maxFile?: number; quota?: number; normalRate?: number; vipRate?: number; sessionMs?: number; loginLimit?: number; storage?: StoragePolicy; mfaKeyFile?: string; mfaClock?: () => number; backupKeyFile?: string; scanner?: ScanEngine; scanMaxAgeMs?: number; scanClock?: () => number; deliveryClock?: () => number }
interface Context { ws: WebSocket; connection: string; ip: string; agent: string; session?: string; user?: Row; abort: AbortController; pending: number; alive: boolean; startedDownloads: Set<string>; challenge?: { key: Row; message: string; expires: number }; mfaLogin?: { userId: string; authVersion: number; id: string; expires: number; attempts: number }; mfaSetup?: { secret: Buffer; expires: number; authVersion: number } }
function filename(value: unknown) {
  const name = text(value); need(!/[\\/\x00-\x1f\x7f:]/.test(name) && !['.', '..'].includes(name) && name.trim().length > 0, 'INVALID_FILENAME'); return name;
}
async function hashFile(path: string, bytes?: number, signal?: AbortSignal) {
  const h = createHash('sha256');
  signal?.throwIfAborted();
  if (bytes === 0) return h.digest('hex');
  const stream = createReadStream(path, { ...(bytes === undefined ? {} : { start: 0, end: bytes - 1 }), signal });
  try { for await (const chunk of stream) h.update(chunk); }
  finally { await new Promise<void>(done => { if (stream.closed) done(); else { stream.once('close', done); stream.destroy(); } }); }
  return h.digest('hex');
}
export function createApp(config: Config) {
  const store = new Store(config.root, config.storage?.auditLimit ?? 64 * 1024 ** 2);
  const backupRoot = resolve(config.storage?.backupRoot ?? config.root + '.backups');
  const backupKeyFile = resolve(config.backupKeyFile ?? config.root + '.backup-keys');
  let mfa: MfaGuard;
  try { mfa = new MfaGuard(store, resolve(config.mfaKeyFile ?? config.root + '.mfa-key'), config.mfaClock, backupRoot); }
  catch (e) { store.close(); throw e; }
  const storage = new StorageGuard(store, config.storage ?? {});
  need(verifyAudit(store.all('SELECT * FROM audit ORDER BY seq')).ok, 'AUDIT_INTEGRITY_FAILURE');
  store.run('UPDATE sessions SET revoked=1 WHERE revoked=0');
  const rate = new RateGate(), bw = new Bandwidth(config.normalRate, config.vipRate);
  const deliveryNow = config.deliveryClock ?? Date.now;
  const deliveryExpired = (d: Row) => d.reason === 'expired' || !d.revoked && d.expires > 0 && d.expires <= deliveryNow();
  const deliveryFields = (d: Row) => ({ ...d, expired: Boolean(deliveryExpired(d)) });
  const contexts = new Set<Context>(), locks = new Set<string>();
  const operations = new Set<Promise<void>>();
  const activeDispatches = new Set<Promise<unknown>>();
  let maintenanceBusy = false, cleanupBusy = false, auditReserved = 0;
  const scans = new ScanGuard(store, config.scanner, locks, () => !maintenanceBusy, () => {
    if (store.auditBytes + auditReserved + 8192 > store.auditLimit) return;
    auditReserved += 8192; return () => { auditReserved -= 8192; };
  }, config.scanMaxAgeMs, config.scanClock);
  const scanFields = (file: Row) => { const { state, checked, code } = scans.status(file); return { ...file, scan: { state, checked, code } }; };
  const readOnly = new Set(['hello', 'ping', 'files.list', 'files.scan.status', 'transfers.list', 'storage.usage', 'sessions.list', 'keys.list', 'events.list', 'invitations.list', 'users.list', 'report.latest', 'audit.page', 'audit.verify', 'maintenance.status', 'mfa.status']);
  type DownloadJob = { abort: AbortController; done: Promise<void>; userId: string; ownerId: string; deliveryId?: string };
  const downloads = new Map<string, Set<DownloadJob>>();
  let hashing = 0, authenticating = 0, queuedBytes = 0;
  const root = resolve(config.webRoot ?? 'dist');
  const request = (req: IncomingMessage, res: import('node:http').ServerResponse) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405).end(); return; }
    if (req.url === '/health') { res.setHeader('Content-Type', 'application/json'); res.end('{"status":"ok","protocol":"SFT/1"}'); return; }
    let path: string;
    try { path = resolve(root, '.' + decodeURIComponent(new URL(req.url ?? '/', 'https://local').pathname)); }
    catch { res.writeHead(400).end(); return; }
    if (path !== root && !path.startsWith(root + sep)) { res.writeHead(403).end(); return; }
    if (path === root || !existsSync(path) && !extname(path)) path = join(root, 'index.html');
    const mime: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
    if (!existsSync(path) || !mime[extname(path)]) { res.writeHead(404).end(); return; }
    res.setHeader('Content-Type', mime[extname(path)]); res.setHeader('Cache-Control', extname(path) === '.html' ? 'no-store' : 'public,max-age=3600');
    const stream = createReadStream(path); stream.on('error', () => { if (!res.headersSent) res.writeHead(500); res.end(); }); stream.pipe(res);
  };
  const server = config.tls ? httpsServer({ ...config.tls, minVersion: 'TLSv1.2', handshakeTimeout: 8000 }, request) : httpServer(request);
  server.maxConnections = 64; server.headersTimeout = 8000; server.requestTimeout = 15000; server.maxHeadersCount = 40;
  server.on('connection', socket => { socket.setKeepAlive(true, 30000); socket.setNoDelay(true); socket.setTimeout(60000, () => socket.destroy()); });
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME, perMessageDeflate: false });
  server.on('upgrade', (req, socket, head) => {
    const ip = req.socket.remoteAddress ?? 'unknown';
    if (req.url !== '/ws' || req.headers.origin !== config.origin || contexts.size >= 48 || !rate.allow('upgrade:' + ip, 120)) { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return; }
    wss.handleUpgrade(req, socket, head, ws => { req.socket.setTimeout(0); wss.emit('connection', ws, req); });
  });
  const audit = (c: Context, action: string, result: string, detail: Record<string, unknown> = {}) => store.audit(c.user?.name ?? 'anonymous', action, result, detail);
  function authorized(c: Context, recoveryAllowed = false) {
    need(!c.abort.signal.aborted && c.user && c.session, 'AUTH_REQUIRED');
    const s = store.get('SELECT * FROM sessions WHERE id=?', c.session);
    const u = store.get('SELECT * FROM users WHERE id=?', c.user.id);
    need(s && !s.revoked && s.expires > Date.now() && u && !u.disabled, 'SESSION_EXPIRED');
    if (u.role === 'admin' && mfa.enabled(u.id)) {
      const factor = mfa.factor(s.id, u.id, u.authVersion); need(factor, 'MFA_REQUIRED');
      need(recoveryAllowed || factor !== 'recovery', 'MFA_RECOVERY_ONLY');
    }
    c.user = u; return u;
  }
  const admin = (c: Context) => need(authorized(c).role === 'admin', 'FORBIDDEN');
  function stopUser(userId: string, reason: string, replyContext?: Context, keepReply = false) {
    for (const ctx of contexts) {
      if (ctx.challenge?.key.userId === userId) ctx.challenge = undefined;
      if (ctx.mfaLogin?.userId === userId) ctx.mfaLogin = undefined;
      if (ctx.user?.id !== userId) continue;
      if (ctx.mfaSetup) { ctx.mfaSetup.secret.fill(0); ctx.mfaSetup = undefined; }
      if (ctx === replyContext && keepReply) continue;
      const stop = () => { ctx.abort.abort(); ctx.ws.close(4001, reason); };
      // The database is already revoked; allow only this operation's acknowledgement.
      if (ctx === replyContext) setTimeout(stop, 10); else stop();
    }
  }
  function establish(c: Context, u: Row, method: string, proof?: MfaProof) {
    need(!c.user, 'ALREADY_AUTHENTICATED');
    const current = store.get('SELECT * FROM users WHERE id=?', u.id);
    need(current && !current.disabled && current.authVersion === u.authVersion, 'INVALID_CREDENTIALS');
    const enabled = current.role === 'admin' && mfa.enabled(current.id); need(!enabled || proof, 'MFA_PASSWORD_REQUIRED');
    need(store.get('SELECT COUNT(*) AS n FROM sessions WHERE userId=? AND revoked=0 AND expires>?', u.id, Date.now())!.n < 8, 'SESSION_LIMIT');
    const session = id();
    store.transaction(() => {
      proof?.consume();
      store.run('INSERT INTO sessions VALUES(?,?,?,?,0,?,?)', session, u.id, Date.now(), Date.now() + Math.min(config.sessionMs ?? 3600000, proof?.method === 'recovery' ? 300000 : Number.MAX_SAFE_INTEGER), c.agent, c.ip);
      if (proof) store.run('INSERT INTO mfa_sessions VALUES(?,?,?,?)', session, u.id, u.authVersion, proof.method);
      store.audit(u.name, 'auth.login', 'allowed', { method });
    });
    c.user = u; c.session = session;
    return { user: { name: u.name, role: u.role, tier: u.tier, rate: bw.rate(u.tier), mfaEnabled: enabled, recoveryOnly: proof?.method === 'recovery' }, session: c.session, connection: c.connection };
  }
  function upgradeFactor(c: Context, u: Row, enabled: boolean) {
    store.run('UPDATE users SET authVersion=authVersion+1 WHERE id=?', u.id);
    store.run('UPDATE sessions SET revoked=1 WHERE userId=? AND id<>?', u.id, c.session!);
    store.run('DELETE FROM keys WHERE userId=?', u.id);
    if (enabled) store.run("INSERT INTO mfa_sessions VALUES(?,?,?,'totp') ON CONFLICT(sessionId) DO UPDATE SET authVersion=excluded.authVersion,method='totp'", c.session!, u.id, u.authVersion + 1);
    else store.run('DELETE FROM mfa_sessions WHERE userId=?', u.id);
  }
  async function mfaPassword(c: Context, u: Row, value: unknown) {
    need(rate.allow('reauth:' + u.id, 10) && authenticating < 4, 'RATE_LIMITED'); authenticating++;
    try { need(await passwordCheck(text(value, 256), u.hash), 'INVALID_CREDENTIALS'); }
    finally { authenticating--; }
    need(authorized(c, true).authVersion === u.authVersion, 'SESSION_EXPIRED');
  }
  function owned(c: Context, table: 'transfers' | 'files', transferId: unknown) {
    const u = authorized(c); const row = store.get(`SELECT * FROM ${table} WHERE id=? AND userId=?`, text(transferId, 80), u.id); need(row, 'NOT_FOUND'); return row;
  }
  function notDeleting(table: 'transfers' | 'files', targetId: string) {
    need(!store.get('SELECT id FROM deletions WHERE id=? AND kind=?', targetId, table), table === 'files' ? 'FILE_DELETING' : 'TRANSFER_CANCELING');
  }
  function available(c: Context, table: 'transfers' | 'files', targetId: unknown) {
    const row = owned(c, table, targetId); notDeleting(table, row.id); return row;
  }
  function accessible(c: Context, fileId: unknown, deliveryId?: unknown): { file: Row; delivery?: Row } {
    const u = authorized(c), fid = text(fileId, 80);
    if (deliveryId === undefined) return { file: available(c, 'files', fid) };
    const delivery = store.get('SELECT d.*,o.name AS sender,r.name AS recipient,o.disabled AS ownerDisabled FROM deliveries d JOIN users o ON o.id=d.ownerId JOIN users r ON r.id=d.recipientId WHERE d.id=? AND d.fileId=? AND d.recipientId=?', text(deliveryId, 80), fid, u.id);
    need(delivery, 'NOT_FOUND');
    need(delivery.reason !== 'expired', 'DELIVERY_EXPIRED');
    const file = store.get('SELECT * FROM files WHERE id=? AND userId=?', fid, delivery.ownerId);
    need(!delivery.revoked && !delivery.ownerDisabled && file && !store.get("SELECT id FROM deletions WHERE id=? AND kind='files'", fid), 'DELIVERY_UNAVAILABLE');
    need(!deliveryExpired(delivery), 'DELIVERY_EXPIRED');
    return { file, delivery };
  }
  function readable(c: Context, fileId: unknown, deliveryId?: unknown) {
    const access = accessible(c, fileId, deliveryId); scans.requireClean(access.file); return access;
  }
  function deliveryAudit(c: Context, action: string, d: Row, extra: Row = {}) {
    audit(c, action, 'allowed', { deliveryId: d.id, fileId: d.fileId, ownerId: d.ownerId, recipientId: d.recipientId, sender: d.sender, recipient: d.recipient, expires: d.expires, ...extra });
  }
  function markDeliveryExpired(d: Row) {
    store.run("UPDATE deliveries SET revoked=1,revokedAt=expires,reason='expired' WHERE id=? AND revoked=0", d.id);
    store.audit('system', 'deliveries.expire', 'allowed', { deliveryId: d.id, fileId: d.fileId, ownerId: d.ownerId, recipientId: d.recipientId, sender: d.sender, recipient: d.recipient, expires: d.expires });
    void stopDownloads(job => job.deliveryId === d.id, new Fault('DELIVERY_EXPIRED'));
  }
  function endDeliveries(c: Context, where: string, args: string[], reason: string) {
    const rows = store.all(`SELECT d.*,o.name AS sender,r.name AS recipient FROM deliveries d JOIN users o ON o.id=d.ownerId JOIN users r ON r.id=d.recipientId WHERE d.revoked=0 AND (${where})`, ...args);
    for (const d of rows) {
      if (deliveryExpired(d)) { markDeliveryExpired(d); continue; }
      store.run('UPDATE deliveries SET revoked=1,revokedAt=?,reason=? WHERE id=?', Date.now(), reason, d.id); deliveryAudit(c, 'deliveries.revoke', d, { reason });
    }
  }
  function stopDownloads(predicate: (job: DownloadJob) => boolean, reason?: Fault) {
    const jobs = [...downloads.values()].flatMap(set => [...set]).filter(predicate);
    for (const job of jobs) job.abort.abort(reason);
    return Promise.all(jobs.map(job => job.done));
  }
  function downloadStarted(c: Context, access: { file: Row; delivery?: Row }, offset: number, explicit: boolean) {
    if (!access.delivery) return;
    const key = access.delivery.id;
    if (explicit || !c.startedDownloads.has(key)) {
      deliveryAudit(c, 'deliveries.download', access.delivery, { offset });
      if (c.startedDownloads.size >= 128) c.startedDownloads.delete(c.startedDownloads.values().next().value!);
      c.startedDownloads.add(key);
    }
  }
  async function downloading<T>(c: Context, fileId: string, deliveryId: unknown, fn: (signal: AbortSignal) => Promise<T>) {
    const access = readable(c, fileId, deliveryId);
    const abort = new AbortController(); let settled!: () => void;
    const job: DownloadJob = { abort, done: new Promise<void>(r => { settled = r; }), userId: c.user!.id, ownerId: access.file.userId, deliveryId: access.delivery?.id };
    let jobs = downloads.get(fileId); if (!jobs) downloads.set(fileId, jobs = new Set()); jobs.add(job);
    let expiryTimer: ReturnType<typeof setTimeout> | undefined;
    const checkExpiry = () => {
      if (!access.delivery?.expires) return;
      const remaining = access.delivery.expires - deliveryNow();
      if (remaining <= 0) abort.abort(new Fault('DELIVERY_EXPIRED'));
      else { expiryTimer = setTimeout(checkExpiry, Math.min(remaining, 2147483647)); expiryTimer.unref(); }
    };
    checkExpiry();
    try { return await fn(AbortSignal.any([c.abort.signal, abort.signal])); }
    catch (e) { if (abort.signal.aborted) throw abort.signal.reason instanceof Fault ? abort.signal.reason : new Fault(job.deliveryId ? 'DELIVERY_UNAVAILABLE' : 'FILE_DELETING'); throw e; }
    finally { clearTimeout(expiryTimer); jobs.delete(job); if (!jobs.size) downloads.delete(fileId); settled(); }
  }
  async function erase(c: Context, table: 'transfers' | 'files', targetId: unknown, expired?: Row) {
    const row = expired ?? owned(c, table, targetId), op = expired ? 'maintenance.expire' : table === 'files' ? 'files.delete' : 'upload.cancel';
    if (table === 'files') { await scans.cancel(row.id); if (!expired) owned(c, table, row.id); }
    need(!locks.has(row.id), table === 'files' ? 'FILE_BUSY' : 'TRANSFER_BUSY'); locks.add(row.id);
    try {
      // The durable intent stops future access, but keeps the original row charged.
      store.transaction(() => {
        const inserted = store.run('INSERT OR IGNORE INTO deletions VALUES(?,?,?,?)', row.id, table, row.userId, Date.now());
        if (inserted.changes) audit(c, op + '.requested', 'allowed', { id: row.id });
        if (table === 'files') endDeliveries(c, 'd.fileId=?', [row.id], 'file-deleted');
      });
      if (table === 'files') {
        const jobs = [...(downloads.get(row.id) ?? [])]; for (const job of jobs) job.abort.abort();
        await Promise.all(jobs.map(job => job.done));
      }
      // A crashed finish can leave a final object with an uncompleted transfer.
      for (const folder of table === 'files' ? ['objects'] : ['staging', 'objects']) {
        try { await unlink(join(config.root, folder, row.id)); }
        catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw new Fault('DELETE_FAILED'); }
      }
      // Once accepted, finish cleanup even if the requester disconnects or is revoked.
      store.transaction(() => {
        store.run(`DELETE FROM ${table} WHERE id=? AND userId=?`, row.id, row.userId);
        if (table === 'transfers') store.run('DELETE FROM transfer_activity WHERE id=?', row.id);
        store.run('DELETE FROM deletions WHERE id=? AND kind=?', row.id, table);
        audit(c, op, 'allowed', { id: row.id, size: row.size });
      });
      return { meta: { deleted: true, id: row.id } };
    } finally { locks.delete(row.id); }
  }
  async function cleanup(c?: Context) {
    need(!cleanupBusy && !maintenanceBusy, 'MAINTENANCE_BUSY'); cleanupBusy = true;
    const result = { removed: 0, failed: 0, activeSkipped: 0 };
    try {
      for (const row of storage.expired()) {
        if (locks.has(row.id)) { result.activeSkipped++; continue; }
        const current = store.get('SELECT t.id FROM transfers t LEFT JOIN transfer_activity a ON a.id=t.id WHERE t.id=? AND COALESCE(a.touched,t.created)<?', row.id, Date.now() - (config.storage?.staleMs ?? 7 * 86400000));
        if (!current) { result.activeSkipped++; continue; }
        const user = store.get('SELECT * FROM users WHERE id=?', row.userId);
        const actor = c ?? { user } as Context;
        try { await erase(actor, 'transfers', row.id, row); result.removed++; }
        catch { result.failed++; }
      }
      return result;
    } finally { cleanupBusy = false; }
  }
  async function dispatch(c: Context, f: Frame): Promise<{ meta?: Row; payload?: Uint8Array }> {
    const m = f.meta, op = text(m.op, 64);
    need(f.type === 1 && f.requestId > 0, 'INVALID_REQUEST');
    if (op !== 'upload.chunk') need(f.payload.length === 0, 'UNEXPECTED_PAYLOAD');
    if (op === 'hello') return { meta: { protocol: 'SFT/1', connection: c.connection, chunkSize: CHUNK, maxFile: config.maxFile ?? 512 * 1024 ** 2, heartbeatSeconds: 20, registration: store.registration() } };
    if (op === 'ping') return { meta: { time: Date.now() } };
    if (op === 'auth.register') {
      need(!c.user, 'ALREADY_AUTHENTICATED');
      need(rate.allow('register:' + c.ip, 6) && rate.allow('register:global', 30) && authenticating < 4, 'RATE_LIMITED');
      need(store.registration() === 'invitation', 'REGISTRATION_CLOSED');
      const token = text(m.token, 64), name = text(m.name, 32), pass = text(m.password, 256);
      validAccount(name, pass); need(/^sd1_[A-Za-z0-9_-]{43}$/.test(token), 'INVITATION_INVALID');
      const tokenHash = digest(token);
      const usable = () => {
        need(store.registration() === 'invitation', 'REGISTRATION_CLOSED');
        const invite = store.get('SELECT * FROM invitations WHERE tokenHash=?', tokenHash);
        need(invite && !invite.revoked && !invite.usedBy && invite.expires > Date.now(), 'INVITATION_INVALID'); return invite;
      };
      usable(); authenticating++;
      try {
        const hash = await passwordHash(pass); c.abort.signal.throwIfAborted();
        const userId = id();
        store.transaction(() => {
          const invite = usable(); need(!store.get('SELECT id FROM users WHERE name=?', name), 'ACCOUNT_UNAVAILABLE');
          store.run("INSERT INTO users(id,name,hash,role,tier) VALUES(?,?,?,'user','normal')", userId, name, hash);
          store.run('UPDATE invitations SET usedBy=?,usedAt=? WHERE id=?', userId, Date.now(), invite.id);
          store.audit(name, op, 'allowed', { invitationId: invite.id });
        });
        return { meta: { registered: true } };
      } finally { authenticating--; }
    }
    if (op === 'auth.password') {
      need(!c.user, 'ALREADY_AUTHENTICATED');
      need(rate.allow('login:' + c.ip, config.loginLimit ?? 10) && authenticating < 4, 'RATE_LIMITED'); authenticating++;
      try {
        const name = text(m.name, 64), pass = text(m.password, 256), u = store.get('SELECT * FROM users WHERE name=?', name);
        // A dummy hash performs equivalent work for unknown accounts.
        const valid = await passwordCheck(pass, u?.hash ?? ('0'.repeat(32) + ':' + '0'.repeat(64)));
        need(u && valid, 'INVALID_CREDENTIALS'); c.abort.signal.throwIfAborted();
        const current = store.get('SELECT * FROM users WHERE id=?', u.id);
        need(current && !current.disabled && current.authVersion === u.authVersion, 'INVALID_CREDENTIALS');
        if (current.role === 'admin' && mfa.enabled(current.id)) {
          mfa.checkLimit(current.id); c.challenge = undefined;
          c.mfaLogin = { userId: current.id, authVersion: current.authVersion, id: id(), expires: mfa.now() + 120000, attempts: 0 };
          return { meta: { mfaRequired: true, challenge: c.mfaLogin.id, expires: c.mfaLogin.expires } };
        }
        return { meta: establish(c, current, 'password') };
      } finally { authenticating--; }
    }
    if (op === 'auth.mfa') {
      need(!c.user, 'ALREADY_AUTHENTICATED'); const pending = c.mfaLogin;
      need(pending && pending.id === m.challenge && pending.expires > mfa.now() && pending.attempts < 5, 'MFA_CHALLENGE_INVALID');
      need(rate.allow('mfa-ip:' + c.ip, 30, 300000), 'MFA_RATE_LIMITED'); pending.attempts++;
      const u = store.get('SELECT * FROM users WHERE id=?', pending.userId);
      need(u && !u.disabled && u.role === 'admin' && u.authVersion === pending.authVersion && mfa.enabled(u.id), 'MFA_CHALLENGE_INVALID');
      need((m.code !== undefined) !== (m.recoveryCode !== undefined), 'INVALID_INPUT');
      const proof = mfa.proof(u.id, m.recoveryCode ?? m.code, m.recoveryCode !== undefined);
      const result = establish(c, u, 'password+' + proof.method, proof); c.mfaLogin = undefined; return { meta: result };
    }
    if (op === 'auth.challenge') {
      need(!c.user && rate.allow('challenge:' + c.ip, 30), 'RATE_LIMITED');
      const key = store.get('SELECT k.*,u.name FROM keys k JOIN users u ON u.id=k.userId WHERE k.id=? AND u.name=? AND u.disabled=0', text(m.keyId, 80), text(m.name, 64));
      if (key) need(!mfa.enabled(key.userId), 'MFA_PASSWORD_REQUIRED');
      need(key, 'INVALID_CREDENTIALS'); const expires = Date.now() + 30000;
      const message = JSON.stringify(['SFT/1 AUTH', c.connection, key.name, key.id, randomBytes(32).toString('base64url'), expires]);
      c.challenge = { key, message, expires }; return { meta: { message, expires } };
    }
    if (op === 'auth.prove') {
      const challenge = c.challenge; c.challenge = undefined;
      need(challenge && challenge.expires > Date.now(), 'CHALLENGE_INVALID');
      need(store.get('SELECT id FROM keys WHERE id=?', challenge.key.id), 'CHALLENGE_INVALID');
      need(!mfa.enabled(challenge.key.userId), 'MFA_PASSWORD_REQUIRED');
      const publicKey = createPublicKey({ key: JSON.parse(challenge.key.jwk), format: 'jwk' });
      need(verify('sha256', Buffer.from(challenge.message), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(text(m.signature, 256), 'base64')), 'INVALID_SIGNATURE');
      return { meta: establish(c, store.get('SELECT * FROM users WHERE id=?', challenge.key.userId)!, 'public-key') };
    }
    const u = authorized(c, ['mfa.status', 'mfa.setup', 'mfa.enable', 'mfa.cancel', 'auth.logout'].includes(op));
    if (op.startsWith('mfa.')) {
      need(u.role === 'admin', 'FORBIDDEN');
      if (op === 'mfa.status') return { meta: { ...mfa.status(u.id), recoveryOnly: mfa.factor(c.session!, u.id, u.authVersion) === 'recovery' } };
      if (op === 'mfa.cancel') { c.mfaSetup?.secret.fill(0); c.mfaSetup = undefined; return {}; }
      if (op === 'mfa.setup') {
        await mfaPassword(c, u, m.password);
        need(!mfa.enabled(u.id) || mfa.factor(c.session!, u.id, u.authVersion) === 'recovery', 'MFA_ALREADY_ENABLED');
        audit(c, op, 'allowed'); c.mfaSetup?.secret.fill(0);
        c.mfaSetup = { secret: randomBytes(20), expires: mfa.now() + 300000, authVersion: u.authVersion };
        return { meta: { secret: base32(c.mfaSetup.secret), issuer: 'SafeDrop', account: u.name, period: 30, digits: 6, expires: c.mfaSetup.expires } };
      }
      if (op === 'mfa.enable') {
        const pending = c.mfaSetup; need(pending && pending.expires > mfa.now() && pending.authVersion === u.authVersion, 'MFA_SETUP_EXPIRED');
        need(m.confirm === '启用双因素认证', 'INVALID_INPUT');
        need(!mfa.enabled(u.id) || mfa.factor(c.session!, u.id, u.authVersion) === 'recovery', 'MFA_ALREADY_ENABLED');
        const enroll = mfa.enroll(u.id, pending.secret, m.code);
        const codes = store.transaction(() => { const codes = enroll(); upgradeFactor(c, u, true); audit(c, op, 'allowed', { sessions: 'others-revoked', keys: 'revoked' }); return codes; });
        stopUser(u.id, 'MFA_CHANGED', c, true); return { meta: { enabled: true, recoveryCodes: codes } };
      }
      if (op === 'mfa.disable' || op === 'mfa.recovery') {
        need(mfa.enabled(u.id), 'MFA_NOT_ENABLED'); await mfaPassword(c, u, m.password);
        need(m.confirm === (op === 'mfa.disable' ? '停用双因素认证' : '更新恢复码'), 'INVALID_INPUT');
        const proof = mfa.proof(u.id, m.code); let codes: string[] | undefined;
        store.transaction(() => {
          proof.consume();
          if (op === 'mfa.disable') { store.run('DELETE FROM mfa_settings WHERE userId=?', u.id); store.run('DELETE FROM mfa_recovery WHERE userId=?', u.id); }
          else codes = mfa.recoveryCodes(u.id);
          upgradeFactor(c, u, op !== 'mfa.disable'); audit(c, op, 'allowed', { sessions: 'others-revoked', keys: 'revoked' });
        });
        stopUser(u.id, 'MFA_CHANGED', c, true); return { meta: { enabled: op !== 'mfa.disable', ...(codes ? { recoveryCodes: codes } : {}) } };
      }
      throw new Fault('UNKNOWN_OPERATION');
    }
    if (op === 'maintenance.status') {
      admin(c); const backups = await backupList(backupRoot);
      let backupEncryption: Record<string, unknown>;
      try { await backupKeyLocation(backupKeyFile, config.root, backupRoot, resolve(config.mfaKeyFile ?? config.root + '.mfa-key')); const ring = await readBackupKeys(backupKeyFile); backupEncryption = { required: true, configured: true, ...backupKeyInfo(ring) }; }
      catch (error) { backupEncryption = { required: true, configured: false, error: error instanceof Fault ? error.code : 'BACKUP_KEY_UNAVAILABLE' }; }
      return { meta: { storage: storage.usage(), audit: { bytes: store.auditBytes, limit: store.auditLimit, protected: store.auditBytes + 65536 > store.auditLimit }, staleDays: (config.storage?.staleMs ?? 7 * 86400000) / 86400000, expiredBatch: storage.expired().length, cleanupAutomatic: Boolean(config.storage?.cleanupIntervalMs), backups, backupEncryption, scanning: scans.summary(), backupCount: config.storage?.backupCount ?? 3, busy: maintenanceBusy } };
    }
    if (op === 'maintenance.cleanup') {
      admin(c); need(m.confirm === '清理过期上传', 'INVALID_INPUT'); need(rate.allow('maintenance:' + u.id, 6), 'RATE_LIMITED');
      return { meta: await cleanup(c) };
    }
    if (op === 'maintenance.backup') {
      admin(c); need(rate.allow('maintenance:' + u.id, 6), 'RATE_LIMITED'); need(!maintenanceBusy && !cleanupBusy, 'MAINTENANCE_BUSY');
      maintenanceBusy = true;
      try {
        await Promise.allSettled([...activeDispatches]); await scans.idle(); authorized(c);
        await backupKeyLocation(backupKeyFile, config.root, backupRoot, resolve(config.mfaKeyFile ?? config.root + '.mfa-key'));
        audit(c, 'maintenance.backup.begin', 'allowed');
        const s = storage.usage();
        const result = await createBackup(store, backupRoot, { quota: config.storage?.backupQuota ?? 20 * 1024 ** 3, count: config.storage?.backupCount ?? 3, minFree: s.minFree, pending: s.pending, keyFile: backupKeyFile });
        audit(c, 'maintenance.backup', 'allowed', { backupId: result.id, bytes: result.bytes, encrypted: true, keyId: result.keyId }); return { meta: result };
      } finally { maintenanceBusy = false; scans.wake(); }
    }
    if (op === 'account.password') {
      need(rate.allow('reauth:' + u.id, 10) && authenticating < 4, 'RATE_LIMITED');
      const oldPass = text(m.password, 256), newPass = text(m.newPassword, 256); validAccount(u.name, newPass);
      need(oldPass !== newPass, 'PASSWORD_UNCHANGED'); authenticating++;
      try {
        need(await passwordCheck(oldPass, u.hash), 'INVALID_CREDENTIALS');
        const hash = await passwordHash(newPass); authorized(c);
        store.transaction(() => {
          need(store.get('SELECT authVersion FROM users WHERE id=?', u.id)!.authVersion === u.authVersion, 'SESSION_EXPIRED');
          store.run('UPDATE users SET hash=?,authVersion=authVersion+1 WHERE id=?', hash, u.id);
          store.run('UPDATE sessions SET revoked=1 WHERE userId=?', u.id);
          store.run('DELETE FROM keys WHERE userId=?', u.id);
          audit(c, op, 'allowed', { sessions: 'revoked', keys: 'revoked' });
        });
        stopUser(u.id, 'PASSWORD_CHANGED', c); return {};
      } finally { authenticating--; }
    }
    if (op === 'registration.set') {
      admin(c); need(m.mode === 'invitation' || m.mode === 'closed', 'INVALID_INPUT');
      store.transaction(() => { store.run("UPDATE settings SET value=? WHERE key='registration'", m.mode); audit(c, op, 'allowed', { mode: m.mode }); }); return {};
    }
    if (op === 'invitations.create') {
      admin(c); need(store.registration() === 'invitation', 'REGISTRATION_CLOSED');
      need(rate.allow('invite-create:' + u.id, 10), 'RATE_LIMITED');
      const hours = integer(m.hours, 168); need(hours >= 1, 'INVALID_INPUT');
      need(store.get('SELECT COUNT(*) AS n FROM invitations WHERE usedBy IS NULL AND revoked=0 AND expires>?', Date.now())!.n < 100, 'INVITATION_LIMIT');
      const inviteId = id(), token = 'sd1_' + randomBytes(32).toString('base64url'), created = Date.now(), expires = created + hours * 3600000;
      store.transaction(() => { store.run('INSERT INTO invitations(id,tokenHash,createdBy,created,expires) VALUES(?,?,?,?,?)', inviteId, digest(token), u.id, created, expires); audit(c, op, 'allowed', { invitationId: inviteId, expires }); });
      return { meta: { id: inviteId, token, expires } };
    }
    if (op === 'invitations.list') {
      admin(c); return { meta: { registration: store.registration(), invitations: store.all('SELECT id,created,expires,usedAt,revoked FROM invitations ORDER BY created DESC,id DESC LIMIT 12 OFFSET ?', integer(m.offset ?? 0, 10000)) } };
    }
    if (op === 'invitations.revoke') {
      admin(c); const inviteId = text(m.invitationId, 80); need(store.get('SELECT id FROM invitations WHERE id=?', inviteId), 'NOT_FOUND');
      store.transaction(() => { store.run('UPDATE invitations SET revoked=1 WHERE id=?', inviteId); audit(c, op, 'allowed', { invitationId: inviteId }); }); return {};
    }
    if (op === 'users.list') {
      admin(c); return { meta: { users: store.all('SELECT id,name,role,tier,disabled FROM users ORDER BY name LIMIT 12 OFFSET ?', integer(m.offset ?? 0, 10000)) } };
    }
    if (op === 'users.disable') {
      admin(c); const userId = text(m.userId, 80);
      store.transaction(() => {
        const target = store.get('SELECT * FROM users WHERE id=?', userId); need(target, 'NOT_FOUND');
        if (!target.disabled && target.role === 'admin') need(store.get("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0")!.n > 1, 'LAST_ADMIN');
        store.run('UPDATE users SET disabled=1,authVersion=authVersion+1 WHERE id=?', userId);
        store.run('UPDATE sessions SET revoked=1 WHERE userId=?', userId);
        store.run('DELETE FROM keys WHERE userId=?', userId);
        endDeliveries(c, 'd.ownerId=? OR d.recipientId=?', [userId, userId], 'account-disabled');
        audit(c, op, 'allowed', { userId, sessions: 'revoked', keys: 'revoked' });
      });
      void stopDownloads(job => job.userId === userId || job.ownerId === userId);
      stopUser(userId, 'ACCOUNT_DISABLED', c); return {};
    }
    if (op === 'deliveries.prepare' || op === 'deliveries.create') {
      const file = available(c, 'files', m.fileId);
      scans.requireClean(file);
      need(rate.allow('delivery-lookup:' + u.id, 30), 'RATE_LIMITED');
      const name = text(m.recipient, 32);
      const recipient = /^[a-zA-Z0-9_-]{3,32}$/.test(name) ? store.get('SELECT id,name FROM users WHERE name=? AND disabled=0 AND id<>?', name, u.id) : undefined;
      need(recipient, 'RECIPIENT_UNAVAILABLE');
      const hours = m.hours === undefined ? 168 : m.hours;
      need(typeof hours === 'number' && Number.isSafeInteger(hours) && hours >= 1 && hours <= 720, 'INVALID_DELIVERY_EXPIRY');
      if (op === 'deliveries.prepare') return { meta: { recipient: { name: recipient.name }, file: { id: file.id, name: file.name, size: file.size }, hours } };
      need(rate.allow('delivery-create:' + u.id, 30), 'RATE_LIMITED');
      return store.transaction(() => {
        const existing = store.get('SELECT d.*,o.name AS sender,r.name AS recipient FROM deliveries d JOIN users o ON o.id=d.ownerId JOIN users r ON r.id=d.recipientId WHERE d.fileId=? AND d.recipientId=? AND d.revoked=0', file.id, recipient.id);
        if (existing && !deliveryExpired(existing)) return { meta: { deliveryId: existing.id, created: false, expires: existing.expires } };
        if (existing) markDeliveryExpired(existing);
        const now = deliveryNow();
        need(store.get('SELECT COUNT(*) AS n FROM deliveries WHERE ownerId=? AND revoked=0 AND (expires=0 OR expires>?)', u.id, now)!.n < 1000 && store.get('SELECT COUNT(*) AS n FROM deliveries WHERE recipientId=? AND revoked=0 AND (expires=0 OR expires>?)', recipient.id, now)!.n < 1000 && store.get('SELECT COUNT(*) AS n FROM deliveries WHERE fileId=? AND revoked=0 AND (expires=0 OR expires>?)', file.id, now)!.n < 32, 'DELIVERY_LIMIT');
        const d = { id: id(), fileId: file.id, ownerId: u.id, recipientId: recipient.id, sender: u.name, recipient: recipient.name, expires: now + hours * 3600000 };
        store.run('INSERT INTO deliveries(id,fileId,ownerId,recipientId,name,created,expires) VALUES(?,?,?,?,?,?,?)', d.id, file.id, u.id, recipient.id, file.name, now, d.expires);
        deliveryAudit(c, op, d); return { meta: { deliveryId: d.id, created: true, expires: d.expires } };
      });
    }
    if (op === 'deliveries.received') return { meta: { now: deliveryNow(), deliveries: store.all("SELECT f.id,f.name,f.size,f.sha256,f.created,d.id AS deliveryId,d.created AS sentAt,d.expires,d.revoked,d.reason,o.name AS sender FROM deliveries d JOIN files f ON f.id=d.fileId AND f.userId=d.ownerId JOIN users o ON o.id=d.ownerId LEFT JOIN deletions x ON x.id=f.id AND x.kind='files' WHERE d.recipientId=? AND (d.revoked=0 OR d.reason='expired') AND o.disabled=0 AND x.id IS NULL ORDER BY d.created DESC,d.id DESC LIMIT 12 OFFSET ?", u.id, integer(m.offset ?? 0, 10000)).map(scanFields).map(deliveryFields) } };
    if (op === 'deliveries.sent') return { meta: { now: deliveryNow(), deliveries: store.all("SELECT d.id AS deliveryId,d.fileId,COALESCE(f.name,d.name) AS name,d.created AS sentAt,d.expires,d.revoked,d.revokedAt,d.reason,r.name AS recipient FROM deliveries d JOIN users r ON r.id=d.recipientId LEFT JOIN files f ON f.id=d.fileId AND f.userId=d.ownerId WHERE d.ownerId=? ORDER BY d.created DESC,d.id DESC LIMIT 12 OFFSET ?", u.id, integer(m.offset ?? 0, 10000)).map(deliveryFields) } };
    if (op === 'deliveries.revoke') {
      const d = store.get('SELECT id FROM deliveries WHERE id=? AND ownerId=?', text(m.deliveryId, 80), u.id); need(d, 'NOT_FOUND');
      need(rate.allow('delivery-revoke:' + u.id, 60), 'RATE_LIMITED');
      store.transaction(() => endDeliveries(c, 'd.id=?', [d.id], 'revoked'));
      await stopDownloads(job => job.deliveryId === d.id); return {};
    }
    if (op === 'storage.usage') return { meta: store.usage(u.id, config.quota ?? 1024 ** 3) };
    if (op === 'files.list') return { meta: { files: store.all("SELECT f.id,f.name,f.size,f.sha256,f.created,d.id IS NOT NULL AS deleting FROM files f LEFT JOIN deletions d ON d.id=f.id AND d.kind='files' WHERE f.userId=? ORDER BY f.created DESC,f.id DESC LIMIT 12 OFFSET ?", u.id, integer(m.offset ?? 0, 10000)).map(scanFields) } };
    if (op === 'files.scan.status') { const { file } = accessible(c, m.fileId, m.deliveryId); return { meta: { fileId: file.id, scan: scans.status(file) } }; }
    if (op === 'files.scan') {
      const file = available(c, 'files', m.fileId);
      need(rate.allow('scan-request:' + u.id, 30) && rate.allow('scan-file:' + file.id, 6), 'RATE_LIMITED');
      store.transaction(() => { if (scans.enqueue(file)) audit(c, 'files.scan.request', 'allowed', { fileId: file.id }); });
      await stopDownloads(job => downloads.get(file.id)?.has(job) ?? false, new Fault('FILE_SCAN_REQUIRED')); scans.wake();
      return { meta: { fileId: file.id, scan: scans.status(file) } };
    }
    if (op === 'transfers.list') return { meta: { transfers: store.all("SELECT t.id,t.name,t.size,t.sha256,t.offset,t.created,d.id IS NOT NULL AS deleting FROM transfers t LEFT JOIN deletions d ON d.id=t.id AND d.kind='transfers' WHERE t.userId=? ORDER BY t.created DESC LIMIT 16", u.id) } };
    if (op === 'files.rename' || op === 'files.delete' || op === 'upload.cancel') {
      need(rate.allow('file-mutation:' + u.id, 60), 'RATE_LIMITED');
      if (op === 'files.delete' || op === 'upload.cancel') return erase(c, op === 'files.delete' ? 'files' : 'transfers', op === 'files.delete' ? m.fileId : m.transferId);
      const file = available(c, 'files', m.fileId), name = filename(m.name); need(!locks.has(file.id), 'FILE_BUSY');
      store.transaction(() => { store.run('UPDATE files SET name=? WHERE id=? AND userId=?', name, file.id, u.id); audit(c, op, 'allowed', { fileId: file.id, oldName: file.name, name }); });
      return { meta: { file: scanFields({ id: file.id, name, size: file.size, sha256: file.sha256, created: file.created, deleting: 0 }) } };
    }
    if (op === 'upload.init') {
      const name = filename(m.name);
      const size = integer(m.size, config.maxFile ?? 512 * 1024 ** 2), sha = text(m.sha256, 64); need(/^[a-f0-9]{64}$/.test(sha), 'INVALID_HASH');
      if (m.transferId) { const t = store.get('SELECT * FROM transfers WHERE id=? AND userId=?', text(m.transferId, 80), u.id) ?? store.get('SELECT *,size AS offset,1 AS completed FROM files WHERE id=? AND userId=?', m.transferId, u.id); need(t, 'NOT_FOUND'); notDeleting(t.completed ? 'files' : 'transfers', t.id); need(t.name === name && t.size === size && t.sha256 === sha, 'FILE_CHANGED'); if (!t.completed) storage.touch(t.id); return { meta: t }; }
      const usage = store.usage(u.id, config.quota ?? 1024 ** 3);
      need(usage.fileCount + usage.transferCount < 1000, 'FILE_COUNT_LIMIT');
      need(usage.transferCount < 16, 'TRANSFER_LIMIT');
      need(usage.used + usage.reserved + size <= usage.limit, 'STORAGE_QUOTA');
      storage.allocate(size);
      const transferId = id(); store.run('INSERT INTO transfers VALUES(?,?,?,?,?,0,?)', transferId, u.id, name, size, sha, Date.now());
      storage.touch(transferId);
      locks.add(transferId);
      try {
        try { const h = await open(join(config.root, 'staging', transferId), 'wx', 0o600); await h.close(); }
        catch {
          store.transaction(() => { store.run("INSERT INTO deletions VALUES(?,'transfers',?,?)", transferId, u.id, Date.now()); audit(c, 'upload.prepare', 'denied', { transferId, code: 'UPLOAD_PREPARE_FAILED' }); });
          throw new Fault('UPLOAD_PREPARE_FAILED');
        }
        audit(c, op, 'allowed', { transferId, size }); return { meta: { id: transferId, offset: 0 } };
      } finally { locks.delete(transferId); }
    }
    if (['upload.chunk', 'upload.finish'].includes(op)) {
      if (op === 'upload.finish') { const done = store.get('SELECT * FROM files WHERE id=? AND userId=?', text(m.transferId, 80), u.id); if (done) { notDeleting('files', done.id); return { meta: { fileId: done.id, sha256: done.sha256, scan: scans.status(done) } }; } }
      const t = available(c, 'transfers', m.transferId); need(!locks.has(t.id), 'TRANSFER_BUSY'); locks.add(t.id);
      const path = join(config.root, 'staging', t.id);
      try {
        if (op === 'upload.chunk') {
          const offset = integer(m.offset, t.size); need(f.payload.length > 0 && offset + f.payload.length <= t.size && offset <= t.offset, 'INVALID_OFFSET');
          await bw.take(u.id, u.tier, f.payload.length, c.abort.signal); authorized(c);
          storage.write();
          const h = await open(path, 'r+');
          try {
            authorized(c);
            if (offset < t.offset) {
              need(offset + f.payload.length <= t.offset, 'INVALID_OFFSET'); const buf = Buffer.alloc(f.payload.length); const { bytesRead } = await h.read(buf, 0, buf.length, offset);
              need(bytesRead === buf.length && buf.equals(Buffer.from(f.payload)), 'CHUNK_CONFLICT');
            } else {
              let written = 0; while (written < f.payload.length) { authorized(c); const r = await h.write(f.payload, written, f.payload.length - written, offset + written); need(r.bytesWritten > 0, 'WRITE_FAILED'); written += r.bytesWritten; }
              await h.sync(); authorized(c); store.run('UPDATE transfers SET offset=? WHERE id=?', offset + written, t.id); t.offset = offset + written;
            }
          } finally { await h.close(); }
          storage.touch(t.id);
          return { meta: { offset: t.offset } };
        }
        need(t.offset === t.size, 'INCOMPLETE_FILE'); need(hashing < 4, 'SERVER_BUSY'); hashing++;
        try {
          const final = join(config.root, 'objects', t.id), source = existsSync(path) ? path : final;
          need((await stat(source)).size === t.size && await hashFile(source) === t.sha256, 'HASH_MISMATCH'); authorized(c);
          if (source !== final) await rename(path, final);
          authorized(c);
          store.transaction(() => { store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', t.id, u.id, t.name, t.size, t.sha256, Date.now()); store.run('DELETE FROM transfers WHERE id=?', t.id); store.run('DELETE FROM transfer_activity WHERE id=?', t.id); scans.enqueue(t); audit(c, op, 'allowed', { fileId: t.id, size: t.size, sha256: t.sha256, scan: 'pending' }); });
          scans.wake(); return { meta: { fileId: t.id, sha256: t.sha256, scan: scans.status(t) } };
        } finally { hashing--; }
      } finally { locks.delete(t.id); }
    }
    if (op === 'download.init') {
      const { file } = readable(c, m.fileId, m.deliveryId), offset = integer(m.offset ?? 0, file.size);
      return downloading(c, file.id, m.deliveryId, async signal => {
        if (offset) { need(hashing < 4, 'SERVER_BUSY'); hashing++; try { need(await hashFile(join(config.root, 'objects', file.id), offset, signal) === m.prefixHash, 'PREFIX_MISMATCH'); } finally { hashing--; } }
        const access = readable(c, file.id, m.deliveryId); downloadStarted(c, access, offset, true);
        if (!access.delivery) audit(c, op, 'allowed', { fileId: file.id, offset });
        return { meta: { id: file.id, name: access.file.name, size: file.size, sha256: file.sha256, created: file.created } };
      });
    }
    if (op === 'download.chunk') {
      const { file } = readable(c, m.fileId, m.deliveryId), offset = integer(m.offset, file.size), length = Math.min(CHUNK, file.size - offset);
      return downloading(c, file.id, m.deliveryId, async signal => {
        await bw.take(u.id, u.tier, length, signal); readable(c, file.id, m.deliveryId);
        const h = await open(join(config.root, 'objects', file.id), 'r'), out = Buffer.alloc(length);
        try { signal.throwIfAborted(); readable(c, file.id, m.deliveryId); const { bytesRead } = await h.read(out, 0, length, offset); need(bytesRead === length, 'READ_FAILED'); } finally { await h.close(); }
        downloadStarted(c, readable(c, file.id, m.deliveryId), offset, false); return { meta: { offset, next: offset + length, eof: offset + length === file.size }, payload: out };
      });
    }
    if (op === 'sessions.list') return { meta: { sessions: store.all('SELECT id,created,expires,agent,ip FROM sessions WHERE userId=? AND revoked=0 AND expires>? ORDER BY created DESC', u.id, Date.now()), current: c.session } };
    if (op === 'sessions.revoke' || op === 'auth.logout') {
      const sid = op === 'auth.logout' ? c.session! : text(m.sessionId, 80);
      need(store.get('SELECT id FROM sessions WHERE id=? AND userId=?', sid, u.id), 'NOT_FOUND');
      store.transaction(() => { store.run('UPDATE sessions SET revoked=1 WHERE id=?', sid); audit(c, 'sessions.revoke', 'allowed', {}); });
      setTimeout(() => { for (const ctx of contexts) if (ctx.session === sid) { ctx.abort.abort(); ctx.ws.close(4001, 'SESSION_REVOKED'); } }, 10);
      return {};
    }
    if (op === 'keys.list') return { meta: { keys: store.all('SELECT id,label,created FROM keys WHERE userId=?', u.id) } };
    if (op === 'keys.enroll' || op === 'keys.revoke') {
      if (op === 'keys.enroll') need(!mfa.enabled(u.id), 'MFA_PASSWORD_REQUIRED');
      need(rate.allow('reauth:' + u.id, 10) && authenticating < 4, 'RATE_LIMITED'); authenticating++;
      try { need(await passwordCheck(text(m.password, 256), u.hash), 'INVALID_CREDENTIALS'); } finally { authenticating--; }
      need(authorized(c).authVersion === u.authVersion, 'SESSION_EXPIRED');
      if (op === 'keys.revoke') { need(store.get('SELECT id FROM keys WHERE id=? AND userId=?', text(m.keyId, 80), u.id), 'NOT_FOUND'); store.transaction(() => { store.run('DELETE FROM keys WHERE id=?', m.keyId); audit(c, op, 'allowed'); }); return {}; }
      need(store.get('SELECT COUNT(*) AS n FROM keys WHERE userId=?', u.id)!.n < 5, 'KEY_LIMIT');
      need(m.jwk && typeof m.jwk === 'object', 'INVALID_KEY'); const j = m.jwk as Row;
      need(j.kty === 'EC' && j.crv === 'P-256' && !j.d && typeof j.x === 'string' && typeof j.y === 'string', 'INVALID_KEY');
      const jwk = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: j.x, y: j.y }, format: 'jwk' }).export({ format: 'jwk' });
      const keyId = id(); store.transaction(() => { store.run('INSERT INTO keys VALUES(?,?,?,?,?)', keyId, u.id, JSON.stringify(jwk), text(m.label, 60), Date.now()); audit(c, op, 'allowed', { keyId }); }); return { meta: { keyId } };
    }
    if (op === 'events.list') {
      const events = store.all('SELECT seq,event FROM audit ORDER BY seq DESC LIMIT 300').map(r => ({ seq: r.seq, ...JSON.parse(r.event) })).filter(r => u.role === 'admin' || r.user === u.name || ['files.scan.begin', 'files.scan'].includes(r.action) && r.detail.ownerId === u.id || ['deliveries.create', 'deliveries.revoke', 'deliveries.download', 'deliveries.expire'].includes(r.action) && (r.detail.ownerId === u.id || r.detail.recipientId === u.id)).slice(0, 24);
      while (Buffer.byteLength(JSON.stringify({ events })) > 12 * 1024) events.pop();
      return { meta: { events } };
    }
    if (op === 'audit.page') { admin(c); return { meta: { rows: store.all('SELECT * FROM audit WHERE seq>? ORDER BY seq LIMIT 8', integer(m.after ?? 0)), checkpoint: store.checkpoint() } }; }
    if (op === 'audit.verify') { admin(c); const anchor = m.checkpoint as Checkpoint | undefined; if (anchor) { integer(anchor.count); need(/^[a-f0-9]{64}$/.test(anchor.head), 'INVALID_CHECKPOINT'); } return { meta: verifyAudit(store.all('SELECT * FROM audit ORDER BY seq'), anchor) }; }
    if (op === 'report.latest') {
      admin(c); const p = config.reportPath ?? resolve('reports/latest.json');
      if (!existsSync(p)) return { meta: { report: null } };
      // Reports grow with the verification suite; keep them out of the 16 KiB metadata field.
      need(statSync(p).size <= CHUNK, 'REPORT_TOO_LARGE');
      const payload = readFileSync(p); need(payload.length <= CHUNK, 'REPORT_TOO_LARGE'); JSON.parse(payload.toString('utf8'));
      return { meta: { reportEncoding: 'json' }, payload };
    }
    throw new Fault('UNKNOWN_OPERATION');
  }
  wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
    const c: Context = { ws, connection: id(), ip: req.socket.remoteAddress ?? 'unknown', agent: (req.headers['user-agent'] ?? 'unknown').slice(0, 160), abort: new AbortController(), pending: 0, alive: true, startedDownloads: new Set() };
    contexts.add(c); let queue = Promise.resolve();
    let authDeadline = setTimeout(function deadline() {
      if (!c.user) { if (c.mfaLogin && c.mfaLogin.expires > mfa.now()) authDeadline = setTimeout(deadline, c.mfaLogin.expires - mfa.now()); else ws.close(4003, 'AUTH_TIMEOUT'); }
    }, 30000);
    ws.on('pong', () => { c.alive = true; });
    ws.on('message', (data, binary) => {
      const bytes = Buffer.isBuffer(data) ? data : Buffer.concat(Array.isArray(data) ? data : [Buffer.from(data)]);
      if (!binary || c.pending >= 8 || queuedBytes + bytes.length > 16 * 1024 ** 2 || !rate.allow('messages:' + c.connection, 1200)) { c.abort.abort(); ws.close(4008, 'RATE_LIMITED'); return; }
      c.pending++; queuedBytes += bytes.length;
      queue = queue.then(async () => {
        let frame: Frame | undefined;
        try {
          c.abort.signal.throwIfAborted(); frame = decode(bytes);
          need(!maintenanceBusy || ['hello', 'ping', 'maintenance.status'].includes(String(frame.meta.op)), 'MAINTENANCE_BUSY');
          const reserve = readOnly.has(String(frame.meta.op)) ? 0 : frame.meta.op === 'users.disable' ? 4 * 1024 ** 2 : frame.meta.op === 'maintenance.backup' || String(frame.meta.op).startsWith('auth.') ? 8192 : 65536;
          need(store.auditBytes + auditReserved + reserve <= store.auditLimit, 'AUDIT_CAPACITY'); auditReserved += reserve;
          let result: { meta?: Row; payload?: Uint8Array };
          try { const work = dispatch(c, frame); activeDispatches.add(work); try { result = await work; } finally { activeDispatches.delete(work); } }
          finally { auditReserved -= reserve; }
          const response = encode(2, frame.requestId, { ok: true, ...result.meta }, result.payload, frame.streamId);
          if (frame.meta.op === 'download.chunk' || frame.meta.op === 'download.init') readable(c, frame.meta.fileId, frame.meta.deliveryId);
          if (ws.readyState === WebSocket.OPEN && !c.abort.signal.aborted) ws.send(response);
        } catch (e) {
          const code = e instanceof Fault ? e.code : frame ? 'INTERNAL_ERROR' : 'INVALID_FRAME';
          if (!c.abort.signal.aborted && store.auditBytes + 4096 < store.auditLimit && rate.allow('audit-denied:' + c.ip, 30)) try { audit(c, typeof frame?.meta.op === 'string' ? frame.meta.op.slice(0, 64) : 'protocol.invalid', 'denied', { code }); } catch { /* A full or failed audit volume must not turn error handling into an uncaught exception. */ }
          if (frame && ws.readyState === WebSocket.OPEN) ws.send(encode(2, frame.requestId, { ok: false, code }));
          else ws.close(4002, 'INVALID_FRAME');
        } finally { c.pending--; queuedBytes -= bytes.length; }
      }).catch(() => { ws.terminate(); });
      const work = queue; operations.add(work); void work.then(() => operations.delete(work));
    });
    ws.on('error', () => { /* Peer protocol violations must not crash the server. */ });
    ws.on('close', () => { clearTimeout(authDeadline); c.abort.abort(); c.mfaLogin = undefined; c.mfaSetup?.secret.fill(0); c.mfaSetup = undefined; contexts.delete(c); if (c.session) try { store.run('UPDATE sessions SET revoked=1 WHERE id=?', c.session); } catch { /* The connection is already invalid; a storage failure must not escape this event handler. */ } });
  });
  const heartbeat = setInterval(() => {
    for (const c of contexts) {
      if (!c.alive) { c.ws.terminate(); continue; }
      if (c.session) try { authorized(c, true); } catch { c.abort.abort(); c.ws.close(4001, 'SESSION_EXPIRED'); continue; }
      c.alive = false; c.ws.ping();
    }
  }, 20000); heartbeat.unref();
  const cleanupTimer = config.storage?.cleanupIntervalMs ? setInterval(() => {
    if (!maintenanceBusy && !cleanupBusy && store.auditBytes + auditReserved + 65536 <= store.auditLimit) {
      auditReserved += 65536; const work = cleanup().then(() => {}, () => {}).finally(() => { auditReserved -= 65536; }); operations.add(work); void work.finally(() => operations.delete(work));
    }
  }, config.storage.cleanupIntervalMs) : undefined; cleanupTimer?.unref();
  const expiryTimer = setInterval(() => {
    if (maintenanceBusy || store.auditBytes + auditReserved + 65536 > store.auditLimit) return;
    auditReserved += 65536;
    try {
      const due = store.all('SELECT d.*,o.name AS sender,r.name AS recipient FROM deliveries d JOIN users o ON o.id=d.ownerId JOIN users r ON r.id=d.recipientId WHERE d.revoked=0 AND d.expires>0 AND d.expires<=? ORDER BY d.expires,d.id LIMIT 16', deliveryNow());
      store.transaction(() => { for (const d of due) markDeliveryExpired(d); });
    } catch { /* Expiry checks and download deadlines still deny access if audit storage fails. */ }
    finally { auditReserved -= 65536; }
  }, 1000); expiryTimer.unref();
  if (store.auditBytes + 4096 < store.auditLimit) store.audit('system', 'server.start', 'allowed', { protocol: 'SFT/1' });
  return { server, store, bw, storage, scans, async close() { clearInterval(heartbeat); clearInterval(cleanupTimer); clearInterval(expiryTimer); for (const c of contexts) { c.abort.abort(); c.ws.terminate(); } await scans.close(); await new Promise<void>(r => wss.close(() => r())); await Promise.allSettled([...operations]); await new Promise<void>(r => server.close(() => r())); store.close(); } };
}
