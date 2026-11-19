import assert from 'node:assert/strict';
import { once } from 'node:events';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes, generateKeyPairSync, sign } from 'node:crypto';
import { WebSocket } from 'ws';
import { createTestApp as createApp, type Config } from './test-scanner.ts';
import { Store, digest, verifyAudit } from '../server/store.ts';
import { MfaGuard, unbase32, totp } from '../server/mfa.ts';
import { verifyBackup, restoreBackup } from '../server/backup.ts';
import { changeBackupKeys } from '../server/backup-keys.ts';
import { certificates } from '../scripts/certificates.ts';
import { Peer, type Result } from './suite.ts';

export async function runMfaSuite(onResult?: (r: Result) => void) {
  mkdirSync('tmp', { recursive: true }); const root = mkdtempSync(resolve('tmp/mfa-')); certificates(join(root, 'tls'));
  const tls = { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) }, ca = readFileSync(join(root, 'tls/ca.crt'));
  const password = randomBytes(24).toString('base64url'), results: Result[] = [];
  async function fixture() {
    let now = Math.floor(Date.now() / 30000) * 30000 + 1000;
    const config: Config = { root: mkdtempSync(join(root, 'data-')), origin: 'https://localhost', tls, loginLimit: 1000, mfaClock: () => now };
    let app = createApp(config); const secrets: string[] = [password];
    const adminId = await app.store.addUser('admin', password, 'admin'), userId = await app.store.addUser('reader', password);
    const start = async () => { app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening'); }; await start();
    const connect = async (target = app) => { const ws = new WebSocket(`wss://127.0.0.1:${(target.server.address() as { port: number }).port}/ws`, { ca, rejectUnauthorized: true, headers: { Origin: config.origin } }); await once(ws, 'open'); return new Peer(ws); };
    const login = async (name = 'admin') => { const p = await connect(); const response = await p.rpc('auth.password', { name, password }); return { p, response }; };
    const admin = (await login()).p;
    const setup = async (p = admin) => { const response = await p.rpc('mfa.setup', { password }); const secret = String(response.meta.secret); secrets.push(secret); return secret; };
    const code = (secret: string) => totp(unbase32(secret), now);
    const enable = async (p = admin) => { const secret = await setup(p), response = await p.rpc('mfa.enable', { code: code(secret), confirm: '启用双因素认证' }); const codes = response.meta.recoveryCodes as string[]; secrets.push(...codes); return { secret, codes }; };
    const factorLogin = async (secret: string, recoveryCode?: string) => { const { p, response } = await login(); const result = await p.rpc('auth.mfa', { challenge: response.meta.challenge, ...(recoveryCode ? { recoveryCode } : { code: code(secret) }) }); return { p, response: result }; };
    return { config, adminId, userId, admin, secrets, connect, login, setup, enable, code, factorLogin, advance(ms = 30000) { now += ms; }, get app() { return app; },
      async restart() { await app.close(); app = createApp(config); await start(); },
      async close() { const audit = app.store.all('SELECT * FROM audit ORDER BY seq'); assert.ok(verifyAudit(audit).ok); for (const value of secrets) assert.ok(!JSON.stringify(audit).includes(value), '敏感认证资料不得进入审计'); await app.close(); }
    };
  }
  type Fixture = Awaited<ReturnType<typeof fixture>>;
  async function run(name: string, fn: (f: Fixture) => Promise<void>) {
    const at = performance.now(); let f: Fixture | undefined, failure: unknown;
    try { f = await fixture(); await fn(f); } catch (e) { failure = e; }
    finally { if (f) try { await f.close(); } catch (e) { failure ??= e; } }
    const result = { name, ok: !failure, ms: Math.round(performance.now() - at), detail: failure instanceof Error ? failure.message : failure ? String(failure) : '真实 TLS/WSS、双因素状态、会话权限及持久化断言通过。' }; results.push(result); onResult?.(result);
  }
  await run('MFA 权限：匿名和普通用户不能查询、配置或停用管理员双因素', async f => {
    const anon = await f.connect(), user = (await f.login('reader')).p;
    for (const op of ['mfa.status', 'mfa.setup', 'mfa.enable', 'mfa.disable', 'mfa.recovery', 'mfa.cancel']) { await assert.rejects(anon.rpc(op), /AUTH_REQUIRED/); await assert.rejects(user.rpc(op), /FORBIDDEN/); }
  });
  await run('MFA 配置：验证当前口令、连接绑定、期限和验证码后才启用', async f => {
    await assert.rejects(f.admin.rpc('mfa.setup', { password: 'incorrect' }), /INVALID_CREDENTIALS/);
    const secret = await f.setup(), other = (await f.login()).p;
    await assert.rejects(other.rpc('mfa.enable', { code: f.code(secret), confirm: '启用双因素认证' }), /MFA_SETUP_EXPIRED/);
    await assert.rejects(f.admin.rpc('mfa.enable', { code: f.code(secret), confirm: 'yes' }), /INVALID_INPUT/);
    await assert.rejects(f.admin.rpc('mfa.enable', { code: 'invalid', confirm: '启用双因素认证' }), /MFA_INVALID/);
    assert.equal((await f.admin.rpc('mfa.status')).meta.enabled, false); f.advance(300001);
    await assert.rejects(f.admin.rpc('mfa.enable', { code: f.code(secret), confirm: '启用双因素认证' }), /MFA_SETUP_EXPIRED/);
  });
  await run('MFA 保存：密钥加密、恢复码仅摘要，启用撤销其他会话和旧公钥', async f => {
    const other = (await f.login()).p, pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    await f.admin.rpc('keys.enroll', { password, label: 'test', jwk: pair.publicKey.export({ format: 'jwk' }) });
    const closed = once(other.ws, 'close'), { secret, codes } = await f.enable(); await closed;
    const row = f.app.store.get('SELECT * FROM mfa_settings WHERE userId=?', f.adminId)!;
    assert.match(row.secret, /^v1\./); assert.ok(!row.secret.includes(secret)); assert.equal(readFileSync(f.config.root + '.mfa-key').length, 32);
    assert.equal(codes.length, 10); assert.equal(new Set(codes).size, 10); assert.equal(f.app.store.all('SELECT * FROM mfa_recovery').length, 10);
    for (const code of codes) assert.ok(!JSON.stringify(f.app.store.all('SELECT * FROM mfa_recovery')).includes(code));
    assert.equal(f.app.store.all('SELECT * FROM keys').length, 0); assert.equal((await f.admin.rpc('maintenance.status')).meta.ok, true);
    assert.equal((await f.admin.rpc('mfa.status')).meta.recoveryRemaining, 10);
  });
  await run('MFA 登录：口令阶段无业务会话，第二步绑定原连接并会过期', async f => {
    const { secret } = await f.enable(); f.advance(); const { p, response } = await f.login();
    assert.equal(response.meta.mfaRequired, true); assert.equal(response.meta.session, undefined); assert.equal(response.meta.user, undefined);
    await assert.rejects(p.rpc('maintenance.status'), /AUTH_REQUIRED/); const other = await f.connect();
    await assert.rejects(other.rpc('auth.mfa', { challenge: response.meta.challenge, code: f.code(secret) }), /MFA_CHALLENGE_INVALID/);
    f.advance(120001); await assert.rejects(p.rpc('auth.mfa', { challenge: response.meta.challenge, code: f.code(secret) }), /MFA_CHALLENGE_INVALID/);
  });
  await run('MFA 重放：启用和登录验证码只消费一次且跨重启保留', async f => {
    const { secret } = await f.enable(), same = await f.login();
    await assert.rejects(same.p.rpc('auth.mfa', { challenge: same.response.meta.challenge, code: f.code(secret) }), /MFA_INVALID/);
    f.advance(); const full = await f.factorLogin(secret); assert.equal(full.response.meta.user && (full.response.meta.user as Record<string, unknown>).recoveryOnly, false);
    assert.equal((await full.p.rpc('files.list')).meta.ok, true); await f.restart(); const replay = await f.login();
    await assert.rejects(replay.p.rpc('auth.mfa', { challenge: replay.response.meta.challenge, code: f.code(secret) }), /MFA_INVALID/);
    f.advance(); assert.equal((await (await f.factorLogin(secret)).p.rpc('mfa.status')).meta.enabled, true);
  });
  await run('MFA 频率：五次失败锁定账号，换连接和重启均不能绕过', async f => {
    const { secret } = await f.enable(); f.advance();
    for (let i = 0; i < 5; i++) { const { p, response } = await f.login(); await assert.rejects(p.rpc('auth.mfa', { challenge: response.meta.challenge, code: 'invalid' }), i === 4 ? /MFA_RATE_LIMITED/ : /MFA_INVALID/); }
    await f.restart(); await assert.rejects(f.login(), /MFA_RATE_LIMITED/); f.advance(300001);
    assert.equal((await (await f.factorLogin(secret)).p.rpc('maintenance.status')).meta.ok, true);
  });
  await run('MFA 公钥：旧挑战、遗留公钥和新增绑定都不能绕过口令加验证码', async f => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), jwk = pair.publicKey.export({ format: 'jwk' });
    const keyId = (await f.admin.rpc('keys.enroll', { password, label: 'test', jwk })).meta.keyId, pending = await f.connect();
    const challenge = await pending.rpc('auth.challenge', { name: 'admin', keyId }); await f.enable();
    const signature = sign('sha256', Buffer.from(String(challenge.meta.message)), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
    await assert.rejects(pending.rpc('auth.prove', { signature }), /CHALLENGE_INVALID|MFA_PASSWORD_REQUIRED/);
    f.app.store.run('INSERT INTO keys VALUES(?,?,?,?,?)', keyId, f.adminId, JSON.stringify(jwk), 'legacy', Date.now());
    await assert.rejects(pending.rpc('auth.challenge', { name: 'admin', keyId }), /MFA_PASSWORD_REQUIRED/);
    await assert.rejects(f.admin.rpc('keys.enroll', { password, label: 'test', jwk }), /MFA_PASSWORD_REQUIRED/);
  });
  await run('MFA 恢复：一次性恢复码只取得重新绑定权限，不能进入业务或停用 MFA', async f => {
    const { secret, codes } = await f.enable(), recovery = await f.factorLogin(secret, codes[0]);
    assert.equal((recovery.response.meta.user as Record<string, unknown>).recoveryOnly, true);
    for (const op of ['files.list', 'maintenance.status', 'report.latest', 'users.list', 'keys.enroll', 'account.password', 'mfa.disable', 'mfa.recovery']) await assert.rejects(recovery.p.rpc(op), /MFA_RECOVERY_ONLY/);
    assert.equal((await recovery.p.rpc('mfa.status')).meta.recoveryOnly, true); assert.equal((await recovery.p.rpc('mfa.status')).meta.recoveryRemaining, 9);
    await assert.rejects(f.factorLogin(secret, codes[0]), /MFA_INVALID/); assert.equal((await recovery.p.rpc('auth.logout')).meta.ok, true);
  });
  await run('MFA 重新绑定：恢复会话必须验证新密钥，旧密钥和旧恢复码失效', async f => {
    const { secret, codes } = await f.enable(), recovery = (await f.factorLogin(secret, codes[0])).p, replacement = await f.enable(recovery);
    assert.ok(secret !== replacement.secret); assert.equal((await recovery.rpc('maintenance.status')).meta.ok, true);
    assert.equal((await recovery.rpc('mfa.status')).meta.recoveryOnly, false); f.advance();
    await assert.rejects(f.factorLogin(secret), /MFA_INVALID/); await assert.rejects(f.factorLogin(replacement.secret, codes[1]), /MFA_INVALID/);
    assert.equal((await (await f.factorLogin(replacement.secret)).p.rpc('files.list')).meta.ok, true);
  });
  await run('MFA 恢复码轮换：重新验证口令和新验证码，旧码及其他会话失效', async f => {
    const { secret, codes } = await f.enable(); f.advance(); const other = await f.factorLogin(secret); f.advance();
    await assert.rejects(f.admin.rpc('mfa.recovery', { password: 'incorrect', code: f.code(secret), confirm: '更新恢复码' }), /INVALID_CREDENTIALS/);
    const closed = once(other.p.ws, 'close'), result = await f.admin.rpc('mfa.recovery', { password, code: f.code(secret), confirm: '更新恢复码' }); await closed;
    const next = result.meta.recoveryCodes as string[]; f.secrets.push(...next); assert.equal(next.length, 10); await assert.rejects(f.factorLogin(secret, codes[1]), /MFA_INVALID/);
    assert.equal((await f.factorLogin(secret, next[0])).response.meta.user && true, true);
  });
  await run('MFA 停用：口令、明确确认及未使用验证码缺一不可，旧公钥不恢复', async f => {
    const { secret } = await f.enable();
    await assert.rejects(f.admin.rpc('mfa.disable', { password, code: f.code(secret), confirm: '停用双因素认证' }), /MFA_INVALID/); f.advance();
    await assert.rejects(f.admin.rpc('mfa.disable', { password, code: f.code(secret), confirm: 'yes' }), /INVALID_INPUT/);
    await f.admin.rpc('mfa.disable', { password, code: f.code(secret), confirm: '停用双因素认证' });
    assert.equal((await f.admin.rpc('mfa.status')).meta.enabled, false); assert.equal(f.app.store.all('SELECT * FROM mfa_recovery').length, 0); assert.equal(f.app.store.all('SELECT * FROM keys').length, 0);
    assert.ok((await f.login()).response.meta.session); assert.equal((await f.admin.rpc('maintenance.status')).meta.ok, true);
  });
  await run('MFA 改密：保留双因素配置，旧口令和旧会话失效', async f => {
    const { secret } = await f.enable(), nextPassword = randomBytes(24).toString('base64url'); f.secrets.push(nextPassword);
    await f.admin.rpc('account.password', { password, newPassword: nextPassword });
    await assert.rejects(f.login(), /INVALID_CREDENTIALS/); const peer = await f.connect();
    const first = await peer.rpc('auth.password', { name: 'admin', password: nextPassword }); assert.equal(first.meta.mfaRequired, true); f.advance();
    await peer.rpc('auth.mfa', { challenge: first.meta.challenge, code: f.code(secret) }); assert.equal((await peer.rpc('mfa.status')).meta.enabled, true);
  });
  await run('MFA 停用账号：待验证码挑战不能在账号停用后建立会话', async f => {
    const second = await f.app.store.addUser('second-admin', password, 'admin'), control = (await f.login('second-admin')).p;
    assert.ok(second); const { secret } = await f.enable(); f.advance(); const pending = await f.login();
    await control.rpc('users.disable', { userId: f.adminId });
    await assert.rejects(pending.p.rpc('auth.mfa', { challenge: pending.response.meta.challenge, code: f.code(secret) }), /MFA_CHALLENGE_INVALID/);
  });
  await run('MFA 认证竞争：正在计算的旧口令登录不能留下未验证会话', async f => {
    const secret = await f.setup(), peer = await f.connect(), entering = peer.rpc('auth.password', { name: 'admin', password }).catch(() => undefined);
    const response = await f.admin.rpc('mfa.enable', { code: f.code(secret), confirm: '启用双因素认证' }); f.secrets.push(...response.meta.recoveryCodes as string[]); await entering;
    await assert.rejects(peer.rpc('maintenance.status'), /AUTH_REQUIRED|SESSION_EXPIRED|MFA_REQUIRED|CONNECTION_CLOSED/);
  });
  await run('MFA 启用审计失败：配置、恢复码、身份版本及其他会话原子回滚', async f => {
    const secret = await f.setup(), other = (await f.login()).p, audit = f.app.store.audit, version = f.app.store.get('SELECT authVersion FROM users WHERE id=?', f.adminId)!.authVersion;
    f.app.store.audit = () => { throw new Error('audit unavailable'); };
    try { await assert.rejects(f.admin.rpc('mfa.enable', { code: f.code(secret), confirm: '启用双因素认证' }), /INTERNAL_ERROR/); }
    finally { f.app.store.audit = audit; }
    assert.equal(f.app.store.all('SELECT * FROM mfa_settings').length, 0); assert.equal(f.app.store.all('SELECT * FROM mfa_recovery').length, 0);
    assert.equal(f.app.store.get('SELECT authVersion FROM users WHERE id=?', f.adminId)!.authVersion, version); assert.equal((await other.rpc('files.list')).meta.ok, true);
    const result = await f.admin.rpc('mfa.enable', { code: f.code(secret), confirm: '启用双因素认证' }); f.secrets.push(...result.meta.recoveryCodes as string[]);
  });
  await run('MFA 登录审计失败：验证码和恢复码不被提前消费，也不产生会话', async f => {
    const { secret, codes } = await f.enable(); f.advance();
    for (const recovery of [false, true]) {
      const pending = await f.login(), audit = f.app.store.audit, before = f.app.store.get('SELECT COUNT(*) AS n FROM sessions')!.n;
      f.app.store.audit = () => { throw new Error('audit unavailable'); };
      try { await assert.rejects(pending.p.rpc('auth.mfa', { challenge: pending.response.meta.challenge, ...(recovery ? { recoveryCode: codes[0] } : { code: f.code(secret) }) }), /INTERNAL_ERROR/); }
      finally { f.app.store.audit = audit; }
      assert.equal(f.app.store.get('SELECT COUNT(*) AS n FROM sessions')!.n, before);
      await pending.p.rpc('auth.mfa', { challenge: pending.response.meta.challenge, ...(recovery ? { recoveryCode: codes[0] } : { code: f.code(secret) }) });
    }
  });
  await run('MFA 备份恢复：保留加密配置和消费状态，缺少独立密钥时拒绝启动', async f => {
    const { secret } = await f.enable(), backupKeysFile = f.config.root + '.backup-keys'; await changeBackupKeys(backupKeysFile);
    const backup = await f.admin.rpc('maintenance.backup'), source = join(f.config.root + '.backups', String(backup.meta.id)), target = join(root, 'restored-' + crypto.randomUUID());
    const manifest = await verifyBackup(source, undefined, { keyFile: backupKeysFile }); assert.ok(manifest.entries.every(e => !e.path.includes('mfa-key') && !e.path.includes('backup-keys'))); await restoreBackup(source, target, manifest.checkpoint, { keyFile: backupKeysFile });
    assert.throws(() => createApp({ ...f.config, root: target }), /MFA_KEY_UNAVAILABLE/);
    const keyFile = target + '.mfa-key'; writeFileSync(keyFile, randomBytes(32), { mode: 0o600 }); assert.throws(() => createApp({ ...f.config, root: target }), /MFA_KEY_UNAVAILABLE/);
    copyFileSync(f.config.root + '.mfa-key', keyFile); const restored = createApp({ ...f.config, root: target }); restored.server.listen(0, '127.0.0.1'); await once(restored.server, 'listening');
    try { f.advance(); const p = await f.connect(restored), first = await p.rpc('auth.password', { name: 'admin', password }); await p.rpc('auth.mfa', { challenge: first.meta.challenge, code: f.code(secret) }); assert.equal((await p.rpc('maintenance.status')).meta.ok, true); }
    finally { await restored.close(); }
  });
  await run('MFA 密钥保护：密文不能在管理员之间移植，错误密钥拒绝加载', async f => {
    await f.enable(); const other = await f.app.store.addUser('another-admin', password, 'admin'), sealed = f.app.store.get('SELECT secret FROM mfa_settings WHERE userId=?', f.adminId)!.secret;
    f.app.store.run('INSERT INTO mfa_settings VALUES(?,?,?,?)', other, sealed, -1, Date.now());
    try { assert.throws(() => new MfaGuard(f.app.store, f.config.root + '.mfa-key'), /MFA_KEY_UNAVAILABLE/); }
    finally { f.app.store.run('DELETE FROM mfa_settings WHERE userId=?', other); }
  });
  await run('MFA 密钥隔离：拒绝把部署密钥放入业务数据或备份目录', async f => {
    assert.throws(() => new MfaGuard(f.app.store, join(f.config.root, 'objects', 'key')), /MFA_KEY_PATH_UNSAFE/);
    assert.throws(() => new MfaGuard(f.app.store, join(f.config.root + '.backups', 'key')), /MFA_KEY_PATH_UNSAFE/);
  });
  await run('MFA 迁移：版本 4 原账号、文件任务及审计保持，升级不会自动启用', async f => {
    const bytes = Buffer.from('legacy-mfa-migration'), sha = digest(bytes), transfer = (await f.admin.rpc('upload.init', { name: 'legacy.bin', size: bytes.length, sha256: sha })).meta.id;
    f.app.store.db.exec('DROP TABLE mfa_settings; DROP TABLE mfa_recovery; DROP TABLE mfa_sessions; DROP TABLE mfa_attempts; PRAGMA user_version=4;');
    const users = JSON.stringify(f.app.store.all('SELECT * FROM users')), transfers = JSON.stringify(f.app.store.all('SELECT * FROM transfers')), anchor = f.app.store.checkpoint();
    await f.restart(); assert.equal(f.app.store.get('PRAGMA user_version')!.user_version, 6); assert.equal(JSON.stringify(f.app.store.all('SELECT * FROM users')), users); assert.equal(JSON.stringify(f.app.store.all('SELECT * FROM transfers')), transfers); assert.ok(verifyAudit(f.app.store.all('SELECT * FROM audit ORDER BY seq'), anchor).ok);
    const admin = (await f.login()).p; assert.equal((await admin.rpc('mfa.status')).meta.enabled, false); assert.equal((await admin.rpc('upload.init', { transferId: transfer, name: 'legacy.bin', size: bytes.length, sha256: sha })).meta.offset, 0);
  });
  await run('MFA 升级证据：多个账号和全部恢复码逐条指纹保留，不互相覆盖', async f => {
    await f.enable(); await f.app.store.addUser('snapshot-admin', password, 'admin'); await f.enable((await f.login('snapshot-admin')).p);
    for (const row of f.app.store.all('SELECT userId FROM mfa_settings')) f.app.store.run('INSERT INTO mfa_attempts VALUES(?,?,?,?)', row.userId, 1, Date.now(), 0);
    const snapshot = JSON.parse(execFileSync(process.execPath, ['scripts/data-snapshot.mjs'], { encoding: 'utf8', env: { ...process.env, DATA_DIR: f.config.root }, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }));
    assert.equal(Object.keys(snapshot.tables.mfa_settings).length, 2); assert.equal(Object.keys(snapshot.tables.mfa_recovery).length, 20); assert.equal(Object.keys(snapshot.tables.mfa_sessions).length, 2); assert.equal(Object.keys(snapshot.tables.mfa_attempts).length, 2);
  });
  await run('MFA 取消配置：取消后旧密钥无法启用，未开启的普通公钥路径保持兼容', async f => {
    const secret = await f.setup(); await f.admin.rpc('mfa.cancel'); await assert.rejects(f.admin.rpc('mfa.enable', { code: f.code(secret), confirm: '启用双因素认证' }), /MFA_SETUP_EXPIRED/);
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), keyId = (await f.admin.rpc('keys.enroll', { password, label: 'legacy', jwk: pair.publicKey.export({ format: 'jwk' }) })).meta.keyId, p = await f.connect();
    const challenge = await p.rpc('auth.challenge', { name: 'admin', keyId }); const signature = sign('sha256', Buffer.from(String(challenge.meta.message)), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
    assert.ok((await p.rpc('auth.prove', { signature })).meta.session); assert.equal(existsSync(f.config.root + '.mfa-key'), false);
  });
  return results;
}
