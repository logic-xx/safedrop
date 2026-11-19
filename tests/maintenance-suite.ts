import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, readdirSync, renameSync, rmdirSync, existsSync } from 'node:fs';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join, resolve } from 'node:path';
import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { WebSocket } from 'ws';
import { DatabaseSync } from 'node:sqlite';
import { createTestApp as createApp, type Config } from './test-scanner.ts';
import { digest, Store, verifyAudit, type Checkpoint } from '../server/store.ts';
import { verifyBackup, restoreBackup, createBackup } from '../server/backup.ts';
import { changeBackupKeys, readBackupKeys } from '../server/backup-keys.ts';
import { BackupCipher, newBackupHeader } from '../server/backup-crypto.ts';
import { certificates } from '../scripts/certificates.ts';
import { Peer, type Result } from './suite.ts';
import { CHUNK } from '../shared/protocol.ts';
import { setTimeout as pause } from 'node:timers/promises';

export async function runMaintenanceSuite(onResult?: (r: Result) => void) {
  mkdirSync('tmp', { recursive: true }); const root = mkdtempSync(resolve('tmp/maintenance-')); certificates(join(root, 'tls'));
  const ca = readFileSync(join(root, 'tls/ca.crt')), tls = { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) }, pass = randomBytes(24).toString('base64url'), results: Result[] = [];
  async function fixture() {
    const config: Config = { root: mkdtempSync(join(root, 'data-')), origin: 'https://localhost', tls, loginLimit: 1000, normalRate: CHUNK * 64, storage: { globalQuota: 1024 ** 2, minFree: 0, staleMs: 10000 } };
    const keyFile = config.root + '.backup-keys'; await changeBackupKeys(keyFile);
    let app = createApp(config); const ids: Record<string, string> = {};
    for (const name of ['owner', 'reader', 'admin']) ids[name] = await app.store.addUser(name, pass, name === 'admin' ? 'admin' : 'user');
    const start = async () => { app.storage.free = () => 1024 ** 3; app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening'); }; await start();
    const connect = async () => { const ws = new WebSocket(`wss://127.0.0.1:${(app.server.address() as { port: number }).port}/ws`, { ca, rejectUnauthorized: true, headers: { Origin: config.origin } }); await once(ws, 'open'); return new Peer(ws); };
    const login = async (name: string) => { const p = await connect(); await p.rpc('auth.password', { name, password: pass }); return p; };
    const owner = await login('owner'), reader = await login('reader'), admin = await login('admin');
    const upload = async (bytes: Buffer, p = owner, complete = true) => { const id = String((await p.rpc('upload.init', { name: '维护样本.bin', size: bytes.length, sha256: digest(bytes) })).meta.id); if (bytes.length) await p.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes); if (complete) await p.rpc('upload.finish', { transferId: id }); return id; };
    const expire = (id: string) => app.store.run('UPDATE transfer_activity SET touched=0 WHERE id=?', id);
    return { config, ids, owner, reader, admin, connect, login, upload, expire, keyFile, get app() { return app; }, backupRoot: config.root + '.backups',
      verifyBackup: (source: string, anchor?: Checkpoint) => verifyBackup(source, anchor, { keyFile }),
      restoreBackup: (source: string, target: string, anchor?: Checkpoint) => restoreBackup(source, target, anchor, { keyFile }),
      async restart() { await app.close(); app = createApp(config); await start(); },
      async close() { assert.equal(verifyAudit(app.store.all('SELECT * FROM audit ORDER BY seq')).ok, true); assert.equal(JSON.stringify(app.store.all('SELECT * FROM audit')).includes(pass), false); await app.close(); }
    };
  }
  type Fixture = Awaited<ReturnType<typeof fixture>>;
  async function run(name: string, fn: (f: Fixture) => Promise<void>) {
    const at = performance.now(); let f: Fixture | undefined, failure: unknown;
    try { f = await fixture(); await fn(f); } catch (e) { failure = e; }
    finally { if (f) try { await f.close(); } catch (e) { failure ??= e; } }
    const r = { name, ok: !failure, ms: Math.round(performance.now() - at), detail: failure instanceof Error ? failure.message : failure ? String(failure) : '真实 TLS/WSS、磁盘对象、恢复结果及状态断言通过。' }; results.push(r); onResult?.(r);
  }
  const cleanup = (p: Peer) => p.rpc('maintenance.cleanup', { confirm: '清理过期上传' });
  await run('维护权限：匿名和普通用户不能获取全局状态、清理或备份', async f => {
    const anon = await f.connect();
    for (const op of ['maintenance.status', 'maintenance.cleanup', 'maintenance.backup']) {
      await assert.rejects(anon.rpc(op), /AUTH_REQUIRED/); await assert.rejects(f.owner.rpc(op), /FORBIDDEN/);
    }
    await assert.rejects(f.admin.rpc('maintenance.cleanup', { confirm: 'yes' }), /INVALID_INPUT/);
    const status = (await f.admin.rpc('maintenance.status')).meta; assert.equal(status.cleanupAutomatic, false); assert.equal('files' in status, false);
  });
  await run('全局预算：不同账号并发预留不能突破总容量', async f => {
    f.config.storage!.globalQuota = 10;
    const responses = await Promise.allSettled([f.owner, f.reader].map(p => p.rpc('upload.init', { name: 'x', size: 7, sha256: digest(Buffer.alloc(7)) })));
    assert.equal(responses.filter(r => r.status === 'fulfilled').length, 1); assert.match(String((responses.find(r => r.status === 'rejected') as PromiseRejectedResult).reason), /GLOBAL_STORAGE_QUOTA/);
    assert.equal(f.app.storage.usage().reserved, 7); assert.equal(readdirSync(join(f.config.root, 'staging')).length, 1);
  });
  await run('全局统计：预留转已用且多接收授权不重复计费', async f => {
    const id = await f.upload(Buffer.alloc(41)); await f.owner.rpc('deliveries.create', { fileId: id, recipient: 'reader' });
    const s = f.app.storage.usage(); assert.equal(s.used, 41); assert.equal(s.reserved, 0); assert.equal(s.pending, 0);
    await f.owner.rpc('files.delete', { fileId: id }); assert.equal(f.app.storage.usage().used, 0);
  });
  await run('全局数量：零字节文件不能绕过跨账号对象上限', async f => {
    f.config.storage!.globalCount = 2;
    await f.upload(Buffer.alloc(0)); await f.upload(Buffer.alloc(0), f.reader, false);
    await assert.rejects(f.admin.rpc('upload.init', { name: 'empty', size: 0, sha256: digest('') }), /GLOBAL_OBJECT_LIMIT/);
    assert.equal(f.app.storage.usage().objects, 2); assert.equal(f.app.storage.usage().used + f.app.storage.usage().reserved, 0);
  });
  await run('磁盘余量：完整未写预留与最低余量共同约束新分配', async f => {
    f.config.storage!.minFree = 100; f.app.storage.free = () => 200;
    await f.owner.rpc('upload.init', { name: 'x', size: 80, sha256: digest(Buffer.alloc(80)) });
    await assert.rejects(f.reader.rpc('upload.init', { name: 'y', size: 21, sha256: digest(Buffer.alloc(21)) }), /DISK_SPACE_LOW/);
    assert.equal(f.app.storage.usage().reserved, 80);
  });
  await run('磁盘压力：等待后重新检测，拒绝写入且保留原确认偏移', async f => {
    const bytes = Buffer.alloc(31), t = String((await f.owner.rpc('upload.init', { name: 'x', size: bytes.length, sha256: digest(bytes) })).meta.id);
    f.app.bw.next.set(f.ids.owner, performance.now() + 100);
    const write = assert.rejects(f.owner.rpc('upload.chunk', { transferId: t, offset: 0 }, bytes), /DISK_SPACE_LOW/); f.app.storage.free = () => 0; await write;
    assert.equal(f.app.store.get('SELECT offset FROM transfers WHERE id=?', t)!.offset, 0); assert.equal(f.app.storage.usage().reserved, bytes.length);
    f.app.storage.free = () => 1024 ** 3; assert.equal((await f.owner.rpc('upload.chunk', { transferId: t, offset: 0 }, bytes)).meta.offset, bytes.length);
  });
  await run('磁盘检测失败：分配失败关闭，已有文件仍可读取', async f => {
    const id = await f.upload(Buffer.from('readable')); f.app.storage.free = () => { throw new Error('disk unavailable'); };
    await assert.rejects(f.reader.rpc('upload.init', { name: 'x', size: 1, sha256: digest('x') }), /STORAGE_UNAVAILABLE/);
    assert.equal((await f.owner.rpc('download.chunk', { fileId: id, offset: 0 })).payload.toString(), 'readable');
  });
  await run('过期清理：只清未完成任务，释放精确全局预留并保留已完成文件', async f => {
    const complete = await f.upload(Buffer.alloc(11)), expired = await f.upload(Buffer.alloc(27), f.reader, false); f.expire(expired);
    const fresh = await f.upload(Buffer.alloc(19), f.owner, false), result = await cleanup(f.admin);
    assert.equal(result.meta.removed, 1); assert.equal(f.app.store.get('SELECT id FROM transfers WHERE id=?', expired), undefined);
    assert.ok(f.app.store.get('SELECT id FROM files WHERE id=?', complete)); assert.ok(f.app.store.get('SELECT id FROM transfers WHERE id=?', fresh)); assert.equal(f.app.storage.usage().reserved, 19);
  });
  await run('活动时间：恢复请求刷新过期时间并跨重启保留', async f => {
    const bytes = Buffer.alloc(23), id = await f.upload(bytes, f.owner, false); f.expire(id);
    await f.owner.rpc('upload.init', { transferId: id, name: '维护样本.bin', size: bytes.length, sha256: digest(bytes) });
    await f.restart(); const admin = await f.login('admin'); assert.equal((await cleanup(admin)).meta.removed, 0); assert.ok(f.app.store.get('SELECT id FROM transfers WHERE id=?', id));
  });
  await run('清理竞争：带宽等待中的上传持有互斥锁，不被误删', async f => {
    const bytes = Buffer.alloc(7), id = String((await f.owner.rpc('upload.init', { name: 'x', size: bytes.length, sha256: digest(bytes) })).meta.id); f.expire(id);
    let begin!: () => void; const started = new Promise<void>(r => begin = r), take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.next.set(f.ids.owner, performance.now() + 150); f.app.bw.take = async (...args) => { begin(); return take(...args); };
    const writing = f.owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes); await started;
    assert.equal((await cleanup(f.admin)).meta.activeSkipped, 1); await writing; assert.equal(f.app.store.get('SELECT offset FROM transfers WHERE id=?', id)!.offset, bytes.length);
  });
  await run('清理失败：真实 unlink 错误保留任务、意图和完整预留，恢复后重试', async f => {
    const id = await f.upload(Buffer.alloc(29), f.owner, false); f.expire(id); const path = join(f.config.root, 'staging', id); renameSync(path, path + '.saved'); mkdirSync(path);
    assert.equal((await cleanup(f.admin)).meta.failed, 1); assert.equal(f.app.storage.usage().reserved, 29); assert.ok(f.app.store.get('SELECT id FROM deletions WHERE id=?', id));
    rmdirSync(path); renameSync(path + '.saved', path); assert.equal((await cleanup(f.admin)).meta.removed, 1); assert.equal(f.app.storage.usage().reserved, 0);
  });
  await run('批次竞争：清理前已恢复的后续候选必须跳过', async f => {
    const bytes = Buffer.alloc(7), first = await f.upload(bytes, f.owner, false), second = await f.upload(bytes, f.owner, false); f.expire(first); f.expire(second);
    const original = fsPromises.unlink; let begin!: () => void, release!: () => void; const started = new Promise<void>(r => begin = r), gate = new Promise<void>(r => release = r);
    fsPromises.unlink = async path => { if (String(path) === join(f.config.root, 'staging', [first, second].sort()[0])) { begin(); await gate; } return original(path); }; syncBuiltinESMExports();
    const later = [first, second].sort()[1];
    try { const clearing = cleanup(f.admin); await started; await f.owner.rpc('upload.init', { transferId: later, name: '维护样本.bin', size: bytes.length, sha256: digest(bytes) }); release(); const r = await clearing; assert.equal(r.meta.removed, 1); assert.equal(r.meta.activeSkipped, 1); assert.ok(f.app.store.get('SELECT id FROM transfers WHERE id=?', later)); }
    finally { release(); fsPromises.unlink = original; syncBuiltinESMExports(); }
  });
  await run('后台清理：仅显式启用后运行，每批仍执行同样的保护', async f => {
    const id = await f.upload(Buffer.alloc(17), f.owner, false); f.expire(id); f.config.storage!.cleanupIntervalMs = 20; await f.restart();
    for (let i = 0; i < 100 && f.app.store.get('SELECT id FROM transfers WHERE id=?', id); i++) await pause(10);
    assert.equal(f.app.store.get('SELECT id FROM transfers WHERE id=?', id), undefined); assert.equal(f.app.storage.usage().reserved, 0);
  });
  await run('审计容量：保护阈值拒绝新变更并保留完整链，拒绝日志也有上限', async f => {
    f.app.store.auditLimit = f.app.store.auditBytes + 10000;
    await assert.rejects(f.owner.rpc('upload.init', { name: 'x', size: 1, sha256: digest('x') }), /AUDIT_CAPACITY/);
    assert.equal(f.app.store.all('SELECT * FROM transfers').length, 0); const before = f.app.store.checkpoint();
    for (let i = 0; i < 40; i++) await assert.rejects(f.owner.rpc('unknown.operation'), /AUDIT_CAPACITY/);
    assert.ok(f.app.store.auditBytes <= f.app.store.auditLimit); assert.ok(f.app.store.checkpoint().count >= before.count); assert.equal((await f.admin.rpc('maintenance.status')).meta.audit && true, true);
  });
  await run('审计写入故障：登录事务回滚，不留下无审计的业务会话', async f => {
    const p = await f.connect(), audit = f.app.store.audit, before = f.app.store.all('SELECT id FROM sessions');
    f.app.store.audit = () => { throw new Error('audit write failed'); };
    try { await assert.rejects(p.rpc('auth.password', { name: 'reader', password: pass }), /INTERNAL_ERROR/); assert.deepEqual(f.app.store.all('SELECT id FROM sessions'), before); await assert.rejects(p.rpc('files.list'), /AUTH_REQUIRED/); }
    finally { f.app.store.audit = audit; }
  });
  await run('审计写入故障：公钥绑定与会话撤销的元数据不发生半提交', async f => {
    const audit = f.app.store.audit, pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), session = (await f.reader.rpc('sessions.list')).meta.current;
    f.app.store.audit = () => { throw new Error('audit write failed'); };
    try {
      await assert.rejects(f.owner.rpc('keys.enroll', { jwk: pair.publicKey.export({ format: 'jwk' }), label: 'test', password: pass }), /INTERNAL_ERROR/); assert.equal(f.app.store.all('SELECT * FROM keys').length, 0);
      await assert.rejects(f.reader.rpc('sessions.revoke', { sessionId: session }), /INTERNAL_ERROR/); assert.equal(f.app.store.get('SELECT revoked FROM sessions WHERE id=?', session)!.revoked, 0);
    } finally { f.app.store.audit = audit; }
  });
  await run('一致备份：数据库、对象、部分上传、授权和链段可完整校验', async f => {
    const id = await f.upload(Buffer.alloc(43)), partial = await f.upload(Buffer.alloc(17), f.owner, false);
    const delivery = (await f.owner.rpc('deliveries.create', { fileId: id, recipient: 'reader' })).meta.deliveryId, anchor = f.app.store.checkpoint();
    const result = await f.admin.rpc('maintenance.backup'), source = join(f.backupRoot, String(result.meta.id)), manifest = await f.verifyBackup(source, anchor);
    assert.ok(manifest.entries.some(e => e.path === 'objects/' + id)); assert.ok(manifest.entries.some(e => e.path === 'staging/' + partial));
    const view = join(root, 'backup-view-' + crypto.randomUUID()); await f.restoreBackup(source, view, anchor);
    const db = new DatabaseSync(join(view, 'safedrop.sqlite'), { readOnly: true }); try { assert.equal(db.prepare('SELECT revoked FROM deliveries WHERE id=?').get(String(delivery))!.revoked, 0); } finally { db.close(); }
    assert.equal(f.app.store.all('SELECT * FROM audit').length > manifest.checkpoint.count, true);
  });
  await run('备份互斥：等在途写入完成，期间拒绝新业务并随后恢复', async f => {
    const bytes = Buffer.alloc(19), id = String((await f.owner.rpc('upload.init', { name: 'x', size: bytes.length, sha256: digest(bytes) })).meta.id);
    let begin!: () => void, release!: () => void; const started = new Promise<void>(r => begin = r), gate = new Promise<void>(r => release = r), take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.take = async (...args) => { begin(); await gate; return take(...args); };
    const writing = f.owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes); await started;
    const copying = f.admin.rpc('maintenance.backup');
    try { const admin2 = await f.connect(); await assert.rejects(admin2.rpc('auth.password', { name: 'admin', password: pass }), /MAINTENANCE_BUSY/); }
    finally { release(); }
    await writing; const result = await copying, view = join(root, 'barrier-view-' + crypto.randomUUID()); await f.restoreBackup(join(f.backupRoot, String(result.meta.id)), view);
    const db = new DatabaseSync(join(view, 'safedrop.sqlite'), { readOnly: true });
    try { assert.equal(db.prepare('SELECT offset FROM transfers WHERE id=?').get(id)!.offset, bytes.length); } finally { db.close(); }
    assert.equal((await f.owner.rpc('files.list')).meta.ok, true);
  });
  await run('备份失败：异常对象和容量不足不产出成功副本，服务恢复', async f => {
    await f.upload(Buffer.alloc(37)); f.config.storage!.backupQuota = 1;
    await assert.rejects(f.admin.rpc('maintenance.backup'), /BACKUP_CAPACITY/); assert.equal((await f.admin.rpc('maintenance.status')).meta.backups instanceof Array, true);
    assert.equal(((await f.admin.rpc('maintenance.status')).meta.backups as unknown[]).length, 0); assert.equal((await f.owner.rpc('ping')).meta.ok, true);
    assert.equal(readdirSync(f.backupRoot).filter(x => x.endsWith('.partial')).length, 1);
  });
  await run('备份份数：已完成及失败副本共同占用上限，不自动删除历史', async f => {
    f.config.storage!.backupCount = 1; const first = await f.admin.rpc('maintenance.backup');
    await assert.rejects(f.admin.rpc('maintenance.backup'), /BACKUP_CAPACITY/); assert.ok(existsSync(join(f.backupRoot, String(first.meta.id), 'manifest.json')));
  });
  await run('备份源异常：目录对象不能被当成普通文件复制，失败后仍可操作', async f => {
    const id = await f.upload(Buffer.alloc(13)), path = join(f.config.root, 'objects', id); renameSync(path, path + '-saved'); mkdirSync(path);
    try { await assert.rejects(f.admin.rpc('maintenance.backup'), /BACKUP_SOURCE_UNSAFE/); assert.equal(((await f.admin.rpc('maintenance.status')).meta.backups as unknown[]).length, 0); assert.equal((await f.owner.rpc('files.list')).meta.ok, true); }
    finally { rmdirSync(path); renameSync(path + '-saved', path); }
  });
  await run('隔离恢复：新目录保留账号、内容、任务偏移、授权及审计检查点', async f => {
    const bytes = Buffer.from('恢复内容'), id = await f.upload(bytes), pending = await f.upload(Buffer.alloc(23), f.owner, false);
    const deliveryId = String((await f.owner.rpc('deliveries.create', { fileId: id, recipient: 'reader' })).meta.deliveryId);
    const result = await f.admin.rpc('maintenance.backup'), source = join(f.backupRoot, String(result.meta.id)), manifest = await f.verifyBackup(source), target = join(root, 'restored-' + crypto.randomUUID());
    await f.restoreBackup(source, target, manifest.checkpoint); const store = new Store(target);
    try { assert.deepEqual(store.get('SELECT hash FROM users WHERE id=?', f.ids.owner), f.app.store.get('SELECT hash FROM users WHERE id=?', f.ids.owner)); assert.equal(store.get('SELECT offset FROM transfers WHERE id=?', pending)!.offset, 23); assert.equal(store.get('SELECT revoked FROM deliveries WHERE id=?', deliveryId)!.revoked, 0); assert.equal(verifyAudit(store.all('SELECT * FROM audit ORDER BY seq'), manifest.checkpoint).ok, true); assert.equal(digest(readFileSync(join(target, 'objects', id))), digest(bytes)); } finally { store.close(); }
    const restored = createApp({ ...f.config, root: target }); restored.server.listen(0, '127.0.0.1'); await once(restored.server, 'listening');
    try {
      const connect = async (name: string) => { const ws = new WebSocket(`wss://127.0.0.1:${(restored.server.address() as { port: number }).port}/ws`, { ca, headers: { Origin: f.config.origin } }); await once(ws, 'open'); const p = new Peer(ws); await p.rpc('auth.password', { name, password: pass }); return p; };
      const owner = await connect('owner'), reader = await connect('reader');
      assert.equal((await owner.rpc('upload.init', { transferId: pending, name: '维护样本.bin', size: 23, sha256: digest(Buffer.alloc(23)) })).meta.offset, 23);
      await owner.rpc('upload.finish', { transferId: pending });
      assert.equal(digest((await reader.rpc('download.chunk', { fileId: id, deliveryId, offset: 0 })).payload), digest(bytes));
    } finally { await restored.close(); }
    await assert.rejects(f.restoreBackup(source, target), /EEXIST/);
  });
  await run('恢复拒绝：损坏内容、伪造路径和独立检查点不匹配均不创建目标', async f => {
    const id = await f.upload(Buffer.from('content')), result = await f.admin.rpc('maintenance.backup'), source = join(f.backupRoot, String(result.meta.id)), target = join(root, 'invalid-' + crypto.randomUUID());
    await assert.rejects(f.restoreBackup(source, target, { count: 1, head: 'f'.repeat(64) }), /AUDIT_INTEGRITY_FAILURE/); assert.equal(existsSync(target), false);
    const manifest = await f.verifyBackup(source), index = manifest.entries.findIndex(entry => entry.path === 'objects/' + id) + 1, blob = join(source, 'sealed', String(index).padStart(6, '0') + '.bin'), original = readFileSync(blob), changed = Buffer.from(original); changed[0] ^= 1; writeFileSync(blob, changed);
    await assert.rejects(f.restoreBackup(source, target), /BACKUP_AUTH_FAILED/); assert.equal(existsSync(target), false); writeFileSync(blob, original);
    manifest.entries[0].path = '../escape'; const header = newBackupHeader(manifest.id, manifest.created, await readBackupKeys(f.keyFile)), cipher = new BackupCipher(header, await readBackupKeys(f.keyFile));
    try { writeFileSync(join(source, 'manifest.json'), JSON.stringify({ ...header, bytes: manifest.storedBytes, sealed: cipher.seal(0, 'manifest', Buffer.from(JSON.stringify(manifest))).toString('base64') })); } finally { cipher.dispose(); }
    await assert.rejects(f.verifyBackup(source), /BACKUP_INVALID/);
  });
  await run('恢复中断：标记未完成的目录拒绝作为业务存储启动', async f => {
    const target = mkdtempSync(join(root, 'interrupted-')); writeFileSync(join(target, '.restore-incomplete'), '{}'); assert.throws(() => new Store(target), /RESTORE_INCOMPLETE/);
    await assert.rejects(createBackup(f.app.store, join(f.config.root, 'nested'), { quota: 1024 ** 3, count: 3, minFree: 0, pending: 0 }), /BACKUP_PATH_UNSAFE/);
  });
  await run('恢复写入失败：隔离目录保留未完成标记，原存储和备份不变', async f => {
    const id = await f.upload(Buffer.from('original')), result = await f.admin.rpc('maintenance.backup'), source = join(f.backupRoot, String(result.meta.id)), target = join(root, 'restore-failure-' + crypto.randomUUID());
    const original = fsPromises.open; fsPromises.open = async (...args) => { const handle = await original(...args); if (String(args[0]) === join(target, 'objects', id)) handle.writeFile = async () => { throw Object.assign(new Error('write failed'), { code: 'ENOSPC' }); }; return handle; }; syncBuiltinESMExports();
    try { await assert.rejects(f.restoreBackup(source, target), /write failed/); assert.ok(existsSync(join(target, '.restore-incomplete'))); assert.throws(() => new Store(target), /RESTORE_INCOMPLETE/); }
    finally { fsPromises.open = original; syncBuiltinESMExports(); }
    assert.equal(readFileSync(join(f.config.root, 'objects', id), 'utf8'), 'original'); await f.verifyBackup(source);
  });
  await run('写入故障：短写可补全，零写入与 sync 失败均不推进确认偏移', async f => {
    const bytes = Buffer.alloc(37), original = fsPromises.open;
    for (const mode of ['short', 'zero', 'sync', 'enospc']) {
      const id = String((await f.owner.rpc('upload.init', { name: mode, size: bytes.length, sha256: digest(bytes) })).meta.id);
      fsPromises.open = async (...args) => { const h = await original(...args); if (String(args[0]) === join(f.config.root, 'staging', id) && args[1] === 'r+') { const write = h.write.bind(h); if (mode === 'short') h.write = (async (buffer: any, offset: any, length: any, position: any) => write(buffer, offset, Math.min(3, length), position)) as typeof h.write; if (mode === 'zero') h.write = (async () => ({ bytesWritten: 0, buffer: bytes })) as unknown as typeof h.write; if (mode === 'enospc') h.write = (async () => { throw Object.assign(new Error('disk full'), { code: 'ENOSPC' }); }) as typeof h.write; if (mode === 'sync') h.sync = async () => { throw Object.assign(new Error('disk full'), { code: 'ENOSPC' }); }; } return h; }; syncBuiltinESMExports();
      try { if (mode === 'short') assert.equal((await f.owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes)).meta.offset, bytes.length); else { await assert.rejects(f.owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes), /WRITE_FAILED|INTERNAL_ERROR/); assert.equal(f.app.store.get('SELECT offset FROM transfers WHERE id=?', id)!.offset, 0); } }
      finally { fsPromises.open = original; syncBuiltinESMExports(); }
    }
  });
  await run('版本 3 迁移：既有数据行和审计不改写，旧任务按原创建时间判定', async f => {
    const id = await f.upload(Buffer.alloc(13), f.owner, false); f.app.store.db.exec('DROP TABLE mfa_settings; DROP TABLE mfa_recovery; DROP TABLE mfa_sessions; DROP TABLE mfa_attempts; DROP TABLE transfer_activity; PRAGMA user_version=3;');
    const before = JSON.stringify(f.app.store.all('SELECT * FROM transfers')); const anchor = f.app.store.checkpoint(); await f.restart();
    assert.equal(f.app.store.get('PRAGMA user_version')!.user_version, 6); assert.equal(JSON.stringify(f.app.store.all('SELECT * FROM transfers')), before); assert.equal(verifyAudit(f.app.store.all('SELECT * FROM audit ORDER BY seq'), anchor).ok, true); assert.ok(f.app.store.get('SELECT id FROM transfers WHERE id=?', id));
  });
  return results;
}
