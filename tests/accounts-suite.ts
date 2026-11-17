import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes, generateKeyPairSync, sign } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { execFileSync } from 'node:child_process';
import { WebSocket } from 'ws';
import { createApp } from '../server/app.ts';
import { Store, digest, passwordHash, verifyAudit } from '../server/store.ts';
import { certificates } from '../scripts/certificates.ts';
import { Peer, type Result } from './suite.ts';
import { CHUNK } from '../shared/protocol.ts';

export async function runAccountSuite(onResult?: (r: Result) => void) {
  mkdirSync('tmp', { recursive: true }); const root = mkdtempSync(resolve('tmp/accounts-'));
  certificates(join(root, 'tls'));
  const ca = readFileSync(join(root, 'tls/ca.crt')), tls = { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) };
  const results: Result[] = [], pass = randomBytes(24).toString('base64url'), nextPass = randomBytes(24).toString('base64url');
  const secrets = [pass, nextPass];
  async function fixture() {
    const data = mkdtempSync(join(root, 'data-')), config = { root: data, origin: 'https://localhost', tls, loginLimit: 1000 };
    let app = createApp(config); const peers: Peer[] = [];
    const adminId = await app.store.addUser('admin', pass, 'admin');
    const start = async () => { app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening'); };
    await start();
    const connect = async () => {
      const port = (app.server.address() as { port: number }).port;
      const ws = new WebSocket(`wss://127.0.0.1:${port}/ws`, { ca, rejectUnauthorized: true, headers: { Origin: config.origin } });
      await once(ws, 'open'); const p = new Peer(ws); peers.push(p); return p;
    };
    const login = async (name = 'admin', password = pass) => { const p = await connect(); await p.rpc('auth.password', { name, password }); return p; };
    const admin = await login();
    const invite = async () => { const r = (await admin.rpc('invitations.create', { hours: 24 })).meta; secrets.push(String(r.token)); return r; };
    const enroll = async (p: Peer) => {
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const keyId = (await p.rpc('keys.enroll', { password: pass, jwk: pair.publicKey.export({ format: 'jwk' }), label: 'account-check' })).meta.keyId;
      return { keyId, signature: (message: unknown) => sign('sha256', Buffer.from(String(message)), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64') };
    };
    return { get app() { return app; }, data, adminId, admin, connect, login, invite, enroll,
      async restart() { await app.close(); app = createApp(config); await start(); },
      async close() {
        const events = JSON.stringify(app.store.all('SELECT * FROM audit'));
        for (const secret of secrets) assert.equal(events.includes(secret), false, 'Secret leaked into audit');
        await app.close();
      }
    };
  }
  type Fixture = Awaited<ReturnType<typeof fixture>>;
  async function run(name: string, fn: (f: Fixture) => Promise<void>, detail: string) {
    const at = performance.now(); let f: Fixture | undefined, failure: unknown;
    try { f = await fixture(); await fn(f); } catch (e) { failure = e; }
    finally { if (f) try { await f.close(); } catch (e) { failure ??= e; } }
    const result = { name, ok: !failure, ms: Math.round(performance.now() - at), detail: failure instanceof Error ? failure.message : failure ? String(failure) : detail };
    results.push(result); onResult?.(result);
  }
  // Resolve after the server reads a credential snapshot, while scrypt is pending.
  function observed(store: Store, predicate: (sql: string, args: any[]) => boolean) {
    const original = store.get;
    return new Promise<void>(resolve => {
      store.get = function(sql, ...args) { const row = original.call(this, sql, ...args); if (predicate(sql, args)) { this.get = original; resolve(); } return row; };
    });
  }
  await run('账号权限：匿名及普通用户不能管理注册、邀请或账号', async f => {
    await f.app.store.addUser('ordinary', pass); const user = await f.login('ordinary'), anon = await f.connect();
    assert.equal((await anon.rpc('hello')).meta.registration, 'invitation');
    for (const [op, data] of [ ['registration.set', { mode: 'closed' }], ['invitations.create', { hours: 24 }], ['invitations.list', {}], ['invitations.revoke', { invitationId: 'unknown' }], ['users.list', {}], ['users.disable', { userId: f.adminId }] ] as const) {
      await assert.rejects(anon.rpc(op, data), /AUTH_REQUIRED/); await assert.rejects(user.rpc(op, data), /FORBIDDEN/);
    }
    await assert.rejects(f.admin.rpc('registration.set', { mode: 'open' }), /INVALID_INPUT/);
  }, '六类管理操作均由服务端鉴权；仅支持 invitation/closed，拒绝开放注册模式。');
  await run('邀请注册：令牌摘要保存、用户自设口令、重放拒绝', async f => {
    const i = await f.invite(), p = await f.connect(); assert.match(String(i.token), /^sd1_[A-Za-z0-9_-]{43}$/);
    assert.equal(f.app.store.get('SELECT tokenHash FROM invitations WHERE id=?', i.id)!.tokenHash, digest(String(i.token)));
    assert.equal(JSON.stringify(f.app.store.all('SELECT * FROM invitations')).includes(String(i.token)), false);
    await p.rpc('auth.register', { token: i.token, name: 'invited', password: pass, role: 'admin', tier: 'vip' });
    await assert.rejects(p.rpc('files.list'), /AUTH_REQUIRED/);
    const u = f.app.store.get('SELECT * FROM users WHERE name=?', 'invited')!; assert.equal(u.role, 'user'); assert.equal(u.tier, 'normal'); assert.notEqual(u.hash, pass);
    await assert.rejects(p.rpc('auth.register', { token: i.token, name: 'replay', password: pass }), /INVITATION_INVALID/);
    await p.rpc('auth.password', { name: 'invited', password: pass });
    const list = JSON.stringify((await f.admin.rpc('invitations.list')).meta); assert.equal(list.includes(String(i.token)), false); assert.equal(list.includes('tokenHash'), false);
    assert.equal(JSON.stringify((await f.admin.rpc('users.list')).meta).includes(u.hash), false);
  }, '256 位随机邀请只返回一次；数据库保存 SHA-256，领取仅产生普通标准账号，不自动登录。');
  await run('邀请边界：到期、撤销、伪造与无效输入被拒绝', async f => {
    const expired = await f.invite(), revoked = await f.invite(), p = await f.connect();
    f.app.store.run('UPDATE invitations SET expires=? WHERE id=?', Date.now() - 1, expired.id);
    await f.admin.rpc('invitations.revoke', { invitationId: revoked.id });
    for (const token of [expired.token, revoked.token, 'sd1_' + randomBytes(32).toString('base64url'), 'bad']) await assert.rejects(p.rpc('auth.register', { token, name: 'blocked', password: pass }), /INVITATION_INVALID/);
    for (const hours of [0, 169, 1.5, '24']) await assert.rejects(f.admin.rpc('invitations.create', { hours }), /INVALID_INPUT|INVALID_INTEGER/);
    await assert.rejects(p.rpc('auth.register', { token: expired.token, name: '../bad', password: 'short' }), /INVALID_USER/);
    assert.equal(f.app.store.all('SELECT * FROM users').length, 1);
  }, '失效邀请无法创建账号，期限必须为 1～168 整数小时，账号和口令检查生效。');
  await run('邀请并发：同一邀请只能由一个连接领取', async f => {
    const i = await f.invite(), peers = await Promise.all([f.connect(), f.connect()]);
    const results = await Promise.allSettled(peers.map((p, n) => p.rpc('auth.register', { token: i.token, name: 'claim-' + n, password: pass })));
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.match(String((results.find(r => r.status === 'rejected') as PromiseRejectedResult).reason), /INVITATION_INVALID/);
    assert.equal(f.app.store.get("SELECT COUNT(*) AS n FROM users WHERE name LIKE 'claim-%'")!.n, 1);
  }, '两个独立 TLS/WSS 连接并发领取；事务复查并消费邀请，只有一个账号创建成功。');
  await run('邀请并发：重复账号不消耗失败方邀请', async f => {
    const invites = await Promise.all([f.invite(), f.invite()]), peers = await Promise.all([f.connect(), f.connect()]);
    const results = await Promise.allSettled(peers.map((p, n) => p.rpc('auth.register', { token: invites[n].token, name: 'duplicate', password: pass })));
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    const loser = results.findIndex(r => r.status === 'rejected'); assert.match(String((results[loser] as PromiseRejectedResult).reason), /ACCOUNT_UNAVAILABLE/);
    assert.equal(f.app.store.get('SELECT usedBy FROM invitations WHERE id=?', invites[loser].id)!.usedBy, null);
    await peers[loser].rpc('auth.register', { token: invites[loser].token, name: 'renamed', password: pass });
  }, '用户名竞争失败整笔事务回滚；该邀请仍可用于其他合法账号。');
  await run('注册限流：换连接不能绕过每 IP 尝试额度', async f => {
    const token = 'sd1_' + randomBytes(32).toString('base64url');
    for (let n = 0; n < 6; n++) await assert.rejects((await f.connect()).rpc('auth.register', { token, name: 'limited', password: pass }), /INVITATION_INVALID/);
    await assert.rejects((await f.connect()).rpc('auth.register', { token, name: 'limited', password: pass }), /RATE_LIMITED/);
    assert.equal((await f.admin.rpc('users.list')).meta.ok, true);
  }, '每 IP 每分钟 6 次注册尝试，跨连接共享，限流不影响已登录管理操作。');
  await run('注册开关：关闭期间现有邀请失效，重新开启后恢复', async f => {
    const i = await f.invite(), p = await f.connect(); await f.admin.rpc('registration.set', { mode: 'closed' });
    assert.equal((await p.rpc('hello')).meta.registration, 'closed');
    await assert.rejects(p.rpc('auth.register', { token: i.token, name: 'closed-user', password: pass }), /REGISTRATION_CLOSED/);
    await assert.rejects(f.admin.rpc('invitations.create', { hours: 1 }), /REGISTRATION_CLOSED/);
    await f.admin.rpc('registration.set', { mode: 'invitation' }); await p.rpc('auth.register', { token: i.token, name: 'closed-user', password: pass });
  }, '关闭自助注册不删除账号和邀请；管理员持久化控制策略，普通登录仍可用。');
  await run('注册竞争：散列计算期间关闭注册、撤销或到期不能领取', async f => {
    for (const kind of ['closed', 'expired', 'revoked']) {
      const i = await f.invite(), p = await f.connect(), seen = observed(f.app.store, sql => sql.includes('WHERE tokenHash=?'));
      const pending = p.rpc('auth.register', { token: i.token, name: 'race-' + kind, password: pass });
      const rejection = assert.rejects(pending, kind === 'closed' ? /REGISTRATION_CLOSED/ : /INVITATION_INVALID/);
      await seen;
      if (kind === 'closed') await f.admin.rpc('registration.set', { mode: 'closed' });
      else if (kind === 'expired') f.app.store.run('UPDATE invitations SET expires=? WHERE id=?', Date.now() - 1, i.id);
      else await f.admin.rpc('invitations.revoke', { invitationId: i.id });
      await rejection; assert.equal(f.app.store.get('SELECT usedBy FROM invitations WHERE id=?', i.id)!.usedBy, null);
      await f.admin.rpc('registration.set', { mode: 'invitation' });
    }
  }, '异步 scrypt 返回后在事务内复查开关、撤销状态与到期时间，失败不消费邀请。');
  await run('修改口令：错误旧口令和短口令不改变身份', async f => {
    await assert.rejects(f.admin.rpc('account.password', { password: 'wrong', newPassword: nextPass }), /INVALID_CREDENTIALS/);
    await assert.rejects(f.admin.rpc('account.password', { password: pass, newPassword: 'short' }), /INVALID_USER/);
    await assert.rejects(f.admin.rpc('account.password', { password: pass, newPassword: pass }), /PASSWORD_UNCHANGED/);
    await f.login(); assert.equal(f.app.store.get('SELECT authVersion FROM users WHERE id=?', f.adminId)!.authVersion, 0);
  }, '修改口令只针对当前账号，验证旧口令与新口令规则，失败保留原会话。');
  await run('修改口令：全部旧会话、公钥及未完成挑战撤销', async f => {
    const other = await f.login(), key = await f.enroll(f.admin), proof = await f.connect();
    const challenge = (await proof.rpc('auth.challenge', { name: 'admin', keyId: key.keyId })).meta.message;
    const keyed = await f.connect(), signed = (await keyed.rpc('auth.challenge', { name: 'admin', keyId: key.keyId })).meta.message;
    await keyed.rpc('auth.prove', { signature: key.signature(signed) });
    const closures = [f.admin, other, keyed].map(p => once(p.ws, 'close'));
    await f.admin.rpc('account.password', { password: pass, newPassword: nextPass, userId: 'someone-else' }); await Promise.all(closures);
    assert.equal(f.app.store.get('SELECT COUNT(*) AS n FROM sessions WHERE revoked=0')!.n, 0); assert.equal(f.app.store.all('SELECT * FROM keys').length, 0);
    await assert.rejects(proof.rpc('auth.prove', { signature: key.signature(challenge) }), /CHALLENGE_INVALID/);
    const p = await f.connect(); await assert.rejects(p.rpc('auth.password', { name: 'admin', password: pass }), /INVALID_CREDENTIALS/);
    await assert.rejects(p.rpc('auth.challenge', { name: 'admin', keyId: key.keyId }), /INVALID_CREDENTIALS/);
    await p.rpc('auth.password', { name: 'admin', password: nextPass });
  }, '当前、其他口令会话、公钥会话全部关闭；旧口令、公钥及在途挑战不可再用，新口令成功。');
  await run('停用账号：口令、公钥、会话、等待上传与下载全部停止', async f => {
    const uid = await f.app.store.addUser('disabled', pass), up = await f.login('disabled'), down = await f.login('disabled');
    const key = await f.enroll(up), proof = await f.connect(), message = (await proof.rpc('auth.challenge', { name: 'disabled', keyId: key.keyId })).meta.message;
    const keyed = await f.connect(), keyMessage = (await keyed.rpc('auth.challenge', { name: 'disabled', keyId: key.keyId })).meta.message;
    await keyed.rpc('auth.prove', { signature: key.signature(keyMessage) });
    const bytes = randomBytes(CHUNK), sha = digest(bytes);
    const transferId = (await up.rpc('upload.init', { name: 'pending.bin', size: bytes.length, sha256: sha })).meta.id;
    const fileId = crypto.randomUUID(); writeFileSync(join(f.data, 'objects', fileId), bytes);
    f.app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', fileId, uid, 'owned.bin', bytes.length, sha, Date.now());
    // Hold both operations in the real bandwidth wait; cancellation must beat the five-second reservation.
    f.app.bw.next.set(uid, performance.now() + 5000);
    let count = 0, started!: () => void; const waiting = new Promise<void>(r => started = r), take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.take = async (...args) => { if (++count === 2) started(); return take(...args); };
    const upload = assert.rejects(up.rpc('upload.chunk', { transferId, offset: 0 }, bytes), /CLOSED|SESSION_EXPIRED/);
    const download = assert.rejects(down.rpc('download.chunk', { fileId, offset: 0 }), /CLOSED|SESSION_EXPIRED/);
    const closed = [up, down, keyed].map(p => once(p.ws, 'close')); await waiting;
    const at = performance.now(); await f.admin.rpc('users.disable', { userId: uid }); await Promise.all([...closed, upload, download]);
    assert.ok(performance.now() - at < 1500, 'Revocation did not interrupt bandwidth wait');
    assert.equal(f.app.store.get('SELECT offset FROM transfers WHERE id=?', transferId)!.offset, 0);
    assert.equal(f.app.store.get('SELECT sha256 FROM files WHERE id=?', fileId)!.sha256, sha);
    assert.equal(f.app.store.get('SELECT COUNT(*) AS n FROM sessions WHERE userId=? AND revoked=0', uid)!.n, 0);
    const p = await f.connect(); await assert.rejects(p.rpc('auth.password', { name: 'disabled', password: pass }), /INVALID_CREDENTIALS/);
    await assert.rejects(p.rpc('auth.challenge', { name: 'disabled', keyId: key.keyId }), /INVALID_CREDENTIALS/);
    await assert.rejects(proof.rpc('auth.prove', { signature: key.signature(message) }), /CHALLENGE_INVALID/);
    await assert.rejects(f.admin.rpc('download.init', { fileId }), /NOT_FOUND/); await assert.rejects(f.admin.rpc('upload.cancel', { transferId }), /NOT_FOUND/);
  }, '停用立即中止真实带宽等待，确认偏移不前移；文件与任务保留，管理员仍无跨用户读取或取消权限。');
  await run('修改口令：带宽等待中的双向传输立即取消', async f => {
    const uid = await f.app.store.addUser('password-transfer', pass), control = await f.login('password-transfer'), up = await f.login('password-transfer'), down = await f.login('password-transfer');
    const bytes = randomBytes(CHUNK), sha = digest(bytes), fileId = crypto.randomUUID();
    const transferId = (await up.rpc('upload.init', { name: 'waiting.bin', size: bytes.length, sha256: sha })).meta.id;
    writeFileSync(join(f.data, 'objects', fileId), bytes); f.app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', fileId, uid, 'existing.bin', bytes.length, sha, Date.now());
    f.app.bw.next.set(uid, performance.now() + 5000);
    let count = 0, started!: () => void; const waiting = new Promise<void>(r => started = r), take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.take = async (...args) => { if (++count === 2) started(); return take(...args); };
    const upload = assert.rejects(up.rpc('upload.chunk', { transferId, offset: 0 }, bytes), /CLOSED|SESSION_EXPIRED/), download = assert.rejects(down.rpc('download.chunk', { fileId, offset: 0 }), /CLOSED|SESSION_EXPIRED/);
    const closed = [control, up, down].map(p => once(p.ws, 'close')); await waiting;
    const at = performance.now(); await control.rpc('account.password', { password: pass, newPassword: nextPass }); await Promise.all([...closed, upload, download]);
    assert.ok(performance.now() - at < 1500); assert.equal(f.app.store.get('SELECT offset FROM transfers WHERE id=?', transferId)!.offset, 0);
    const p = await f.login('password-transfer', nextPass); assert.equal((await p.rpc('download.init', { fileId })).meta.sha256, sha);
    assert.equal((await p.rpc('transfers.list')).meta.transfers instanceof Array, true);
  }, '修改口令取消五秒带宽等待中的上传、下载；重新登录后原文件和任务仍可访问。');
  await run('停用竞争：正在计算的口令登录不能建立新会话', async f => {
    const uid = await f.app.store.addUser('login-race', pass), p = await f.connect();
    const seen = observed(f.app.store, (sql, args) => sql === 'SELECT * FROM users WHERE name=?' && args[0] === 'login-race');
    const rejection = assert.rejects(p.rpc('auth.password', { name: 'login-race', password: pass }), /INVALID_CREDENTIALS/);
    await seen; await f.admin.rpc('users.disable', { userId: uid }); await rejection;
    assert.equal(f.app.store.get('SELECT COUNT(*) AS n FROM sessions WHERE userId=? AND revoked=0', uid)!.n, 0);
  }, '登录使用的旧账号快照在 scrypt 结束后重新核验，停用期间不能补建会话。');
  await run('停用竞争：正在重新认证的改密和公钥绑定不能回写', async f => {
    const snapshots: Array<{ uid: string; oldHash: string }> = [];
    for (const op of ['account.password', 'keys.enroll']) {
      const name = op === 'account.password' ? 'change-race' : 'enroll-race', uid = await f.app.store.addUser(name, pass), peer = await f.login(name);
      const oldHash = f.app.store.get('SELECT hash FROM users WHERE id=?', uid)!.hash;
      snapshots.push({ uid, oldHash });
      const seen = observed(f.app.store, (sql, args) => sql === 'SELECT * FROM users WHERE id=?' && args[0] === uid);
      const jwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
      const rejection = assert.rejects(peer.rpc(op, { password: pass, newPassword: nextPass, jwk, label: 'race' }), /CLOSED|AUTH_REQUIRED|SESSION_EXPIRED/);
      await seen; await f.admin.rpc('users.disable', { userId: uid }); await rejection;
    }
    // Shutdown drains pending reauthentication before closing SQLite, so inspection
    // occurs after all old work has settled rather than after a guessed timeout.
    await f.restart();
    for (const { uid, oldHash } of snapshots) {
      assert.equal(f.app.store.get('SELECT hash FROM users WHERE id=?', uid)!.hash, oldHash);
      assert.equal(f.app.store.get('SELECT COUNT(*) AS n FROM keys WHERE userId=?', uid)!.n, 0);
    }
  }, '账号停用会使异步旧口令校验失效，不能再写入口令或补绑公钥。');
  await run('管理员保护：最后一个可用管理员不能停用', async f => {
    await assert.rejects(f.admin.rpc('users.disable', { userId: f.adminId }), /LAST_ADMIN/);
    const uid = await f.app.store.addUser('second-admin', pass, 'admin'), second = await f.login('second-admin');
    const closed = once(second.ws, 'close'); await second.rpc('users.disable', { userId: uid }); await closed;
    await assert.rejects(f.admin.rpc('users.disable', { userId: f.adminId }), /LAST_ADMIN/);
    assert.equal(f.app.store.get("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0")!.n, 1);
  }, '有两名管理员时允许本人停用；已停用管理员不计入可用数量。');
  await run('管理员竞争：互相停用不能使可用管理员归零', async f => {
    const uid = await f.app.store.addUser('other-admin', pass, 'admin'), other = await f.login('other-admin');
    const outcomes = await Promise.allSettled([f.admin.rpc('users.disable', { userId: uid }), other.rpc('users.disable', { userId: f.adminId })]);
    assert.equal(outcomes.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(f.app.store.get("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0")!.n, 1);
  }, '事务内检查最后管理员，并逐请求重新验证权限，交错请求只有一方成功。');
  await run('账号持久化：开关、停用状态、邀请与审计跨重启保留', async f => {
    const uid = await f.app.store.addUser('persist-disabled', pass), used = await f.invite(), unused = await f.invite(), p = await f.connect();
    await p.rpc('auth.register', { token: used.token, name: 'persist-user', password: pass });
    await f.admin.rpc('users.disable', { userId: uid }); await f.admin.rpc('registration.set', { mode: 'closed' });
    const anchor = f.app.store.checkpoint(); await f.restart(); const admin = await f.login();
    assert.equal((await admin.rpc('invitations.list')).meta.registration, 'closed'); assert.equal(f.app.store.get('SELECT disabled FROM users WHERE id=?', uid)!.disabled, 1);
    assert.equal(verifyAudit(f.app.store.all('SELECT * FROM audit ORDER BY seq'), anchor).ok, true);
    await admin.rpc('registration.set', { mode: 'invitation' }); const q = await f.connect();
    await assert.rejects(q.rpc('auth.register', { token: used.token, name: 'after-replay', password: pass }), /INVITATION_INVALID/);
    await q.rpc('auth.register', { token: unused.token, name: 'after-restart', password: pass });
    await assert.rejects((await f.connect()).rpc('auth.password', { name: 'persist-disabled', password: pass }), /INVALID_CREDENTIALS/);
  }, '重启后使用原数据库，不重建账号；已领取邀请不能重放，未使用邀请仍可领取。');

  // Actual pre-migration schema and rows, not a database created by the new Store.
  await run('数据库兼容：旧版账号、文件、任务、公钥和审计无损升级', async f => {
    const legacyRoot = mkdtempSync(join(root, 'legacy-')); mkdirSync(join(legacyRoot, 'objects')); mkdirSync(join(legacyRoot, 'staging'));
    const db = new DatabaseSync(join(legacyRoot, 'safedrop.sqlite'));
    db.exec(`CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,hash TEXT NOT NULL,role TEXT NOT NULL,tier TEXT NOT NULL);
      CREATE TABLE sessions(id TEXT PRIMARY KEY,userId TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,agent TEXT NOT NULL,ip TEXT NOT NULL);
      CREATE TABLE keys(id TEXT PRIMARY KEY,userId TEXT NOT NULL,jwk TEXT NOT NULL,label TEXT NOT NULL,created INTEGER NOT NULL);
      CREATE TABLE files(id TEXT PRIMARY KEY,userId TEXT NOT NULL,name TEXT NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,created INTEGER NOT NULL);
      CREATE TABLE transfers(id TEXT PRIMARY KEY,userId TEXT NOT NULL,name TEXT NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,offset INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL);
      CREATE TABLE audit(seq INTEGER PRIMARY KEY,event TEXT NOT NULL,prev TEXT NOT NULL,hash TEXT NOT NULL);`);
    const hash = await passwordHash(pass), pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), bytes = Buffer.from('原有文件及续传数据'), sha = digest(bytes);
    db.prepare('INSERT INTO users VALUES(?,?,?,?,?)').run('legacy-id', 'legacy', hash, 'admin', 'vip');
    db.prepare('INSERT INTO sessions VALUES(?,?,?,?,?,?,?)').run('legacy-session', 'legacy-id', 1, Date.now() + 3600000, 0, 'existing-agent', '127.0.0.1');
    db.prepare('INSERT INTO keys VALUES(?,?,?,?,?)').run('legacy-key', 'legacy-id', JSON.stringify(pair.publicKey.export({ format: 'jwk' })), '已有设备', 1);
    db.prepare('INSERT INTO files VALUES(?,?,?,?,?,?)').run('legacy-file', 'legacy-id', '原有文件.bin', bytes.length, sha, 1);
    db.prepare('INSERT INTO transfers VALUES(?,?,?,?,?,?,?)').run('legacy-transfer', 'legacy-id', '未完成.bin', bytes.length, sha, 3, 1);
    const event = JSON.stringify({ time: '2026-11-12', user: 'legacy', action: 'legacy.event', result: 'allowed', detail: {} }), prev = '0'.repeat(64), head = digest(prev + event);
    db.prepare('INSERT INTO audit VALUES(?,?,?,?)').run(1, event, prev, head); db.close();
    writeFileSync(join(legacyRoot, 'objects', 'legacy-file'), bytes); writeFileSync(join(legacyRoot, 'staging', 'legacy-transfer'), bytes.subarray(0, 3));
    const snapshot = () => JSON.parse(execFileSync(process.execPath, [resolve('scripts/data-snapshot.mjs')], { env: { ...process.env, DATA_DIR: legacyRoot }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
    const before = snapshot(); assert.equal(JSON.stringify(before).includes(hash), false);
    const app = createApp({ root: legacyRoot, origin: 'https://localhost', tls });
    try {
      const after = snapshot();
      for (const [table, records] of Object.entries(before.tables)) for (const [key, hash] of Object.entries(records as Record<string, string>)) assert.equal(after.tables[table][key], hash);
      const u = app.store.get('SELECT * FROM users')!; assert.equal(u.hash, hash); assert.equal(u.disabled, 0); assert.equal(u.authVersion, 0);
      assert.equal(app.store.get('SELECT * FROM sessions')!.revoked, 1); assert.equal(app.store.get('SELECT * FROM keys')!.id, 'legacy-key');
      assert.equal(app.store.get('SELECT * FROM transfers')!.offset, 3); assert.deepEqual(readFileSync(join(legacyRoot, 'objects', 'legacy-file')), bytes);
      assert.deepEqual(readFileSync(join(legacyRoot, 'staging', 'legacy-transfer')), bytes.subarray(0, 3));
      assert.equal(verifyAudit(app.store.all('SELECT * FROM audit ORDER BY seq'), { count: 1, head }).ok, true);
      app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening');
      const port = (app.server.address() as { port: number }).port, ws = new WebSocket(`wss://127.0.0.1:${port}/ws`, { ca, headers: { Origin: 'https://localhost' } }); await once(ws, 'open'); const p = new Peer(ws);
      await p.rpc('auth.password', { name: 'legacy', password: pass }); assert.equal((await p.rpc('download.chunk', { fileId: 'legacy-file', offset: 0 })).payload.length, bytes.length);
      await p.rpc('upload.chunk', { transferId: 'legacy-transfer', offset: 3 }, bytes.subarray(3)); assert.equal((await p.rpc('upload.finish', { transferId: 'legacy-transfer' })).meta.sha256, sha);
      const other = new Store(legacyRoot); assert.equal(other.get('PRAGMA user_version')!.user_version, 3); assert.equal(other.get('SELECT COUNT(*) AS n FROM users')!.n, 1); other.close();
    } finally { await app.close(); }
  }, '真实旧表结构迁移后原口令可登录、原文件可下载、原偏移可续传；公钥及历史审计保留，重复打开不再迁移。');
  return results;
}
