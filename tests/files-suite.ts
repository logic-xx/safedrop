import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmdirSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { WebSocket } from 'ws';
import { createTestApp as createApp, scanFixtureFile, type Config } from './test-scanner.ts';
import { DATABASE_VERSION, digest, verifyAudit } from '../server/store.ts';
import { certificates } from '../scripts/certificates.ts';
import { Peer, type Result } from './suite.ts';
import { CHUNK, decode } from '../shared/protocol.ts';

export async function runFileSuite(onResult?: (r: Result) => void) {
  mkdirSync('tmp', { recursive: true }); const root = mkdtempSync(resolve('tmp/files-'));
  certificates(join(root, 'tls'));
  const ca = readFileSync(join(root, 'tls/ca.crt')), tls = { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) };
  const pass = randomBytes(24).toString('base64url'), results: Result[] = [];
  async function fixture(options: Partial<Config>) {
    const config = { root: mkdtempSync(join(root, 'data-')), origin: 'https://localhost', tls, loginLimit: 1000, normalRate: 64 * CHUNK, quota: 4 * CHUNK, maxFile: 4 * CHUNK, ...options };
    let app = createApp(config);
    const uid = await app.store.addUser('owner', pass); await app.store.addUser('other', pass); await app.store.addUser('admin', pass, 'admin');
    const start = async () => { app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening'); }; await start();
    const connect = async () => {
      const ws = new WebSocket(`wss://127.0.0.1:${(app.server.address() as { port: number }).port}/ws`, { ca, rejectUnauthorized: true, headers: { Origin: config.origin } });
      await once(ws, 'open'); return new Peer(ws);
    };
    const login = async (name = 'owner') => { const p = await connect(); await p.rpc('auth.password', { name, password: pass }); return p; };
    const owner = await login(), other = await login('other'), admin = await login('admin');
    const init = async (bytes: Buffer, name = '原文件.bin', peer = owner) => String((await peer.rpc('upload.init', { name, size: bytes.length, sha256: digest(bytes) })).meta.id);
    const upload = async (bytes: Buffer, name = '原文件.bin', peer = owner) => { const id = await init(bytes, name, peer); for (let offset = 0; offset < bytes.length; offset += CHUNK) await peer.rpc('upload.chunk', { transferId: id, offset }, bytes.subarray(offset, offset + CHUNK)); await peer.rpc('upload.finish', { transferId: id }); return id; };
    const usage = async (peer = owner) => (await peer.rpc('storage.usage')).meta;
    return { config, uid, get app() { return app; }, owner, other, admin, connect, login, init, upload, usage,
      async restart() { await app.close(); app = createApp(config); await start(); },
      async close() { assert.equal(verifyAudit(app.store.all('SELECT * FROM audit ORDER BY seq')).ok, true); assert.equal(JSON.stringify(app.store.all('SELECT * FROM audit')).includes(pass), false); await app.close(); }
    };
  }
  type Fixture = Awaited<ReturnType<typeof fixture>>;
  async function run(name: string, fn: (f: Fixture) => Promise<void>, detail: string, options: Partial<Config> = {}) {
    const at = performance.now(); let f: Fixture | undefined, failure: unknown;
    try { f = await fixture(options); await fn(f); } catch (e) { failure = e; }
    finally { if (f) try { await f.close(); } catch (e) { failure ??= e; } }
    const result = { name, ok: !failure, ms: Math.round(performance.now() - at), detail: failure instanceof Error ? failure.message : failure ? String(failure) : detail };
    results.push(result); onResult?.(result);
  }
  await run('文件权限：匿名、其他账号及管理员不能改名、删除或取消他人任务', async f => {
    const fileId = await f.upload(Buffer.from('owner-data')), transferId = await f.init(Buffer.from('pending')), anon = await f.connect();
    for (const [op, data] of [['files.rename', { fileId, name: '越权.bin' }], ['files.delete', { fileId }], ['upload.cancel', { transferId }]] as const) {
      await assert.rejects(anon.rpc(op, data), /AUTH_REQUIRED/);
      for (const p of [f.other, f.admin]) await assert.rejects(p.rpc(op, data), /NOT_FOUND/);
    }
    await assert.rejects(anon.rpc('storage.usage'), /AUTH_REQUIRED/);
    assert.equal((await f.other.rpc('storage.usage', { userId: f.uid })).meta.used, 0);
    assert.equal((await f.usage()).used, 10); assert.equal((await f.usage()).reserved, 7);
  }, '新增业务操作逐条核对所有权，管理员角色不扩大文件权限，配额只能查看本人。');
  await run('一级文件夹：创建、移动、越权拒绝和续传交付', async f => {
    const bytes = randomBytes(CHUNK + 17);
    const fileId = await f.upload(bytes);
    await scanFixtureFile(f.app, fileId);
    const original = (await f.owner.rpc('files.list')).meta.files as Record<string, any>[];
    assert.equal(original.find(file => file.id === fileId)?.folderId, null);
    const beforeUsage = await f.usage();
    const delivery = (await f.owner.rpc('deliveries.create', { fileId, recipient: 'other' })).meta.deliveryId;
    const anon = await f.connect();
    await assert.rejects(anon.rpc('folders.list'), /AUTH_REQUIRED/);
    await assert.rejects(anon.rpc('folders.create', { name: 'private' }), /AUTH_REQUIRED/);
    await assert.rejects(anon.rpc('files.move', { fileId, folderId: null }), /AUTH_REQUIRED/);
    await assert.rejects(f.owner.rpc('folders.create', { name: ' ../越界 ' }), /INVALID_FILENAME/);
    await assert.rejects(f.owner.rpc('folders.create', { name: '文'.repeat(80) }), /INVALID_FOLDER_NAME/);
    const created = (await f.owner.rpc('folders.create', { name: ' 实验资料 ' })).meta.folder as { id: string; name: string };
    assert.equal(created.name, '实验资料');
    await assert.rejects(f.owner.rpc('folders.create', { name: '实验资料' }), /FOLDER_NAME_EXISTS/);
    const otherFolder = (await f.other.rpc('folders.create', { name: '实验资料' })).meta.folder as { id: string };
    assert.notEqual(otherFolder.id, created.id);
    assert.deepEqual((await f.owner.rpc('folders.list')).meta.folders, [created]);
    assert.deepEqual((await f.other.rpc('folders.list')).meta.folders, [otherFolder]);
    assert.deepEqual((await f.admin.rpc('folders.list')).meta.folders, []);
    await assert.rejects(f.owner.rpc('files.move', { fileId, folderId: otherFolder.id }), /NOT_FOUND/);
    await assert.rejects(f.other.rpc('files.move', { fileId, folderId: otherFolder.id }), /NOT_FOUND/);
    await assert.rejects(f.admin.rpc('files.move', { fileId, folderId: null }), /NOT_FOUND/);
    const otherFile = await f.upload(Buffer.alloc(0), '其他文件.bin', f.other);
    await assert.rejects(f.other.rpc('files.move', { fileId: otherFile, folderId: created.id }), /NOT_FOUND/);
    for (let i = 0; i < 2; i++) await f.owner.rpc('files.move', { fileId, folderId: created.id });
    const after = (await f.owner.rpc('files.list')).meta.files as Record<string, any>[];
    assert.deepEqual(after, original.map(file => ({ ...file, folderId: created.id })));
    assert.deepEqual(await f.usage(), beforeUsage);
    const resume = { fileId, offset: CHUNK, prefixHash: digest(bytes.subarray(0, CHUNK)) };
    await f.owner.rpc('download.init', resume);
    await f.other.rpc('download.init', { ...resume, deliveryId: delivery });
    const chunk = await f.other.rpc('download.chunk', { fileId, deliveryId: delivery, offset: CHUNK });
    assert.deepEqual(Buffer.from(chunk.payload), bytes.subarray(CHUNK));
    const moves = f.app.store.all("SELECT event FROM audit WHERE json_extract(event,'$.action')='files.move' AND json_extract(event,'$.result')='allowed'");
    assert.equal(moves.length, 1);
    await f.restart();
    const owner = await f.login();
    assert.deepEqual((await owner.rpc('folders.list')).meta.folders, [created]);
    assert.deepEqual((await owner.rpc('files.list')).meta.files, after);
    await owner.rpc('files.move', { fileId, folderId: null });
    assert.deepEqual((await owner.rpc('files.list')).meta.files, original);
    await owner.rpc('files.move', { fileId, folderId: created.id });
    await owner.rpc('files.delete', { fileId });
    assert.equal(f.app.store.get('SELECT folderId FROM file_folders WHERE fileId=?', fileId), undefined);
    assert.deepEqual(await owner.rpc('folders.list').then(r => r.meta.folders), [created]);
  }, '文件夹与文件均按本人授权。移动保留对象、扫描结果、续传前缀和接收授权，重启后保留归属，删除文件清理归属关系。');
  await run('SQLite 7 迁移：既有文件仍在根目录，审计与传输保持一致', async f => {
    const bytes = Buffer.from('version 7 file');
    const fileId = await f.upload(bytes);
    await scanFixtureFile(f.app, fileId);
    const file = f.app.store.get('SELECT * FROM files WHERE id=?', fileId);
    const anchors = f.app.store.checkpoint();
    f.app.store.db.exec('DROP TABLE file_folders; DROP TABLE folders; PRAGMA user_version=7;');
    await f.restart();
    assert.equal(f.app.store.get('PRAGMA user_version')!.user_version, DATABASE_VERSION);
    assert.deepEqual(f.app.store.get('SELECT * FROM files WHERE id=?', fileId), file);
    assert.equal(verifyAudit(f.app.store.all('SELECT * FROM audit ORDER BY seq'), anchors).ok, true);
    const owner = await f.login();
    assert.deepEqual((await owner.rpc('folders.list')).meta.folders, []);
    const [row] = (await owner.rpc('files.list')).meta.files as Record<string, any>[];
    assert.equal(row?.folderId, null);
    assert.equal(row?.scan.state, 'clean');
    assert.deepEqual(Buffer.from((await owner.rpc('download.chunk', { fileId, offset: 0 })).payload), bytes);
  }, '迁移只添加目录相关表；既有文件行、对象字节、扫描状态与审计前缀均可复核。');
  await run('配额：已用、完整预留与可用值来自服务端并准确转换', async f => {
    const bytes = randomBytes(CHUNK + 19); let u = await f.usage(); assert.equal(u.used, 0); assert.equal(u.reserved, 0); assert.equal(u.available, 4 * CHUNK);
    const id = await f.init(bytes); u = await f.usage(); assert.equal(u.reserved, bytes.length); assert.equal(u.available, 4 * CHUNK - bytes.length);
    await f.owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes.subarray(0, CHUNK)); assert.equal((await f.usage()).reserved, bytes.length);
    await f.owner.rpc('upload.chunk', { transferId: id, offset: CHUNK }, bytes.subarray(CHUNK)); await f.owner.rpc('upload.finish', { transferId: id });
    u = await f.usage(); assert.equal(u.used, bytes.length); assert.equal(u.reserved, 0); assert.equal(u.fileCount, 1); assert.equal(u.transferCount, 0);
  }, '上传过程中按整文件大小预留；完成时在事务中从预留转换成已用，不重复计费。');
  await run('配额用尽：跨连接并发预留不能超额，清理后才恢复空间', async f => {
    const another = await f.login(), bytes = randomBytes(3 * CHUNK);
    const outcomes = await Promise.allSettled([f.init(bytes), f.init(bytes, '另一个.bin', another)]);
    assert.equal(outcomes.filter(r => r.status === 'fulfilled').length, 1);
    assert.match(String((outcomes.find(r => r.status === 'rejected') as PromiseRejectedResult).reason), /STORAGE_QUOTA/);
    const id = String((outcomes.find(r => r.status === 'fulfilled') as PromiseFulfilledResult<string>).value);
    assert.equal((await f.usage()).reserved, 3 * CHUNK); await f.owner.rpc('upload.cancel', { transferId: id });
    assert.equal((await f.usage()).available, 4 * CHUNK); await f.init(bytes);
  }, '两个连接同时申请超出剩余额度的总空间，只接受一个；成功取消后才能重新预留。');
  await run('数量限制：未完成上传也占用最终文件数量预算', async f => {
    f.app.store.transaction(() => { for (let i = 0; i < 999; i++) f.app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', 'count-' + i, f.uid, '空文件-' + i, 0, digest(''), 1); });
    const id = await f.init(Buffer.alloc(0)); await assert.rejects(f.init(Buffer.alloc(0), '额外.bin'), /FILE_COUNT_LIMIT/);
    await f.owner.rpc('upload.finish', { transferId: id }); assert.equal((await f.usage()).fileCount, 1000);
  }, '已完成文件和预留任务合计最多 1000，不能通过并发 finish 突破数量边界。');
  await run('重命名：中文名称保留标识、内容、摘要、时间和配额', async f => {
    const bytes = randomBytes(CHUNK + 7), fileId = await f.upload(bytes), before = f.app.store.get('SELECT * FROM files WHERE id=?', fileId)!, usage = await f.usage();
    const file = (await f.owner.rpc('files.rename', { fileId, name: '新的中文资料.bin' })).meta.file as Record<string, any>;
    assert.equal(file.id, fileId); assert.equal(file.name, '新的中文资料.bin'); assert.equal(file.sha256, before.sha256); assert.equal(file.created, before.created);
    assert.deepEqual(readFileSync(join(f.config.root, 'objects', fileId)), bytes); assert.deepEqual(await f.usage(), usage);
    assert.equal((await f.owner.rpc('download.init', { fileId, offset: CHUNK, prefixHash: digest(bytes.subarray(0, CHUNK)) })).meta.name, file.name);
    assert.deepEqual(Buffer.from((await f.owner.rpc('download.chunk', { fileId, offset: CHUNK })).payload), bytes.subarray(CHUNK));
  }, '只更新文件显示名；现有标识与正确前缀仍能续传，内容不复制、不重新计存储。');
  await run('重命名输入：目录穿越、控制字符、空名与超长名被拒绝', async f => {
    const fileId = await f.upload(Buffer.alloc(0));
    for (const name of ['', '.', '..', '../escape', 'a\\b', 'c:drive', 'a\0b', '\n', '   ', 'x'.repeat(181), null, 17]) await assert.rejects(f.owner.rpc('files.rename', { fileId, name }), /INVALID_FILENAME|INVALID_INPUT/);
    const name = 'quote\'"安全文件.bin'; await f.owner.rpc('files.rename', { fileId, name }); assert.equal(f.app.store.get('SELECT name FROM files WHERE id=?', fileId)!.name, name);
  }, '改名与上传共用文件名验证，参数化 SQL 正确处理引号，名称由 Vue 文本转义。');
  await run('重命名并发：带宽等待中的下载继续读取同一对象', async f => {
    const bytes = randomBytes(4096), fileId = await f.upload(bytes), down = await f.login();
    let begin!: () => void, release!: () => void; const started = new Promise<void>(r => begin = r), gate = new Promise<void>(r => release = r), take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.take = async (...args) => { begin(); await gate; return take(...args); };
    const pending = down.rpc('download.chunk', { fileId, offset: 0 }); void pending.catch(() => {}); await started;
    try { await f.owner.rpc('files.rename', { fileId, name: '下载中改名.bin' }); } finally { release(); }
    assert.equal(digest((await pending).payload), digest(bytes));
  }, '改名不撤销已经开始的下载，也不改变不可变文件版本。');
  await run('永久删除：磁盘清理完成后释放已用空间，重复请求不再扣减', async f => {
    const bytes = randomBytes(101), fileId = await f.upload(bytes); await f.owner.rpc('files.delete', { fileId });
    assert.equal(existsSync(join(f.config.root, 'objects', fileId)), false); assert.equal((await f.usage()).used, 0); assert.equal((await f.usage()).available, 4 * CHUNK);
    await assert.rejects(f.owner.rpc('files.delete', { fileId }), /NOT_FOUND/); await assert.rejects(f.owner.rpc('download.init', { fileId }), /NOT_FOUND/);
    await assert.rejects(f.owner.rpc('download.chunk', { fileId, offset: 0 }), /NOT_FOUND/); assert.equal(f.app.store.all('SELECT * FROM deletions').length, 0);
  }, '成功只在 unlink 和元数据事务结束后返回；后续下载、续传及重复删除均被拒绝。');
  await run('删除失败：真实磁盘错误保留记录、占用与删除意图，支持重试', async f => {
    const bytes = randomBytes(137), fileId = await f.upload(bytes), path = join(f.config.root, 'objects', fileId), saved = path + '.saved';
    renameSync(path, saved); mkdirSync(path);
    await assert.rejects(f.owner.rpc('files.delete', { fileId }), /DELETE_FAILED/);
    assert.equal((await f.usage()).used, bytes.length); assert.equal((await f.usage()).available, 4 * CHUNK - bytes.length);
    assert.equal(((await f.owner.rpc('files.list')).meta.files as Record<string, any>[])[0].deleting, 1);
    await assert.rejects(f.owner.rpc('download.init', { fileId }), /FILE_DELETING/); await assert.rejects(f.owner.rpc('files.rename', { fileId, name: '绕过.bin' }), /FILE_DELETING/);
    rmdirSync(path); renameSync(saved, path); await f.owner.rpc('files.delete', { fileId }); assert.equal((await f.usage()).used, 0);
  }, '用目录替换私有测试对象制造真实 unlink 错误；失败不释放空间、不重新开放下载，恢复存储后可重试。');
  await run('取消失败：暂存与遗留对象都确认清理后才能释放预留', async f => {
    const bytes = randomBytes(89), id = await f.init(bytes), path = join(f.config.root, 'objects', id);
    mkdirSync(path); await assert.rejects(f.owner.rpc('upload.cancel', { transferId: id }), /DELETE_FAILED/);
    assert.equal((await f.usage()).reserved, bytes.length); assert.equal(existsSync(join(f.config.root, 'staging', id)), false);
    await assert.rejects(f.owner.rpc('upload.init', { transferId: id, name: '原文件.bin', size: bytes.length, sha256: digest(bytes) }), /TRANSFER_CANCELING/);
    await assert.rejects(f.owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes), /TRANSFER_CANCELING/); await assert.rejects(f.owner.rpc('upload.finish', { transferId: id }), /TRANSFER_CANCELING/);
    rmdirSync(path); writeFileSync(path, bytes); await f.owner.rpc('upload.cancel', { transferId: id });
    assert.equal(existsSync(path), false); assert.equal((await f.usage()).reserved, 0);
  }, '覆盖 finish 崩溃后遗留最终对象的情况；部分清理成功也不提前释放完整预留。');
  await run('删除竞争：取消同一文件多个连接的带宽等待且不发送后续内容', async f => {
    const bytes = randomBytes(CHUNK), fileId = await f.upload(bytes), peers = await Promise.all([f.login(), f.login()]);
    f.app.bw.next.set(f.uid, performance.now() + 5000);
    let count = 0, begin!: () => void, received = 0; const started = new Promise<void>(r => begin = r), take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.take = async (...args) => { if (++count === 2) begin(); return take(...args); };
    for (const p of peers) p.ws.on('message', bytes => { received += decode(Buffer.from(bytes as Buffer)).payload.length; });
    const denied = peers.map(p => assert.rejects(p.rpc('download.chunk', { fileId, offset: 0 }), /FILE_DELETING|NOT_FOUND/));
    await started; const at = performance.now(); await f.owner.rpc('files.delete', { fileId }); await Promise.all(denied);
    assert.ok(performance.now() - at < 1500); assert.equal(received, 0); assert.equal((await f.usage()).used, 0);
    assert.equal((await f.other.rpc('ping')).meta.ok, true);
  }, '删除打断五秒真实带宽等待，两个连接均无内容返回；其他用户连接不受影响。');
  await run('写入失败：未确认字节不前移偏移，也不释放任务预留', async f => {
    const bytes = randomBytes(51), id = await f.init(bytes), path = join(f.config.root, 'staging', id), saved = path + '.saved';
    renameSync(path, saved); mkdirSync(path); await assert.rejects(f.owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes), /INTERNAL_ERROR|WRITE_FAILED/);
    assert.equal(f.app.store.get('SELECT offset FROM transfers WHERE id=?', id)!.offset, 0); assert.equal((await f.usage()).reserved, bytes.length);
    rmdirSync(path); renameSync(saved, path); await f.owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes); await f.owner.rpc('upload.finish', { transferId: id });
    assert.equal((await f.usage()).used, bytes.length);
  }, '真实文件写入错误后仍从原确认偏移重试，完成后摘要与空间统计正确。');
  await run('暂存创建失败：保留完整预留并暴露可重试清理任务', async f => {
    const bytes = randomBytes(29), path = join(f.config.root, 'staging'), saved = path + '.saved';
    renameSync(path, saved); writeFileSync(path, 'blocked');
    await assert.rejects(f.init(bytes), /UPLOAD_PREPARE_FAILED/); assert.equal((await f.usage()).reserved, bytes.length);
    const task = ((await f.owner.rpc('transfers.list')).meta.transfers as Record<string, any>[])[0]; assert.equal(task.deleting, 1);
    unlinkSync(path); renameSync(saved, path); await f.owner.rpc('upload.cancel', { transferId: task.id }); assert.equal((await f.usage()).reserved, 0);
  }, '初始文件创建失败不假定磁盘为空；显示取消待重试，确认清理后才释放预留。');
  await run('初始化与取消竞争：暂存创建完成前不能取消并留下未计费对象', async f => {
    const controller = await f.login(), bytes = randomBytes(37), original = fsPromises.open;
    let begin!: () => void, release!: () => void; const started = new Promise<void>(r => begin = r), gate = new Promise<void>(r => release = r);
    fsPromises.open = async (...args) => { if (args[1] === 'wx' && String(args[0]).startsWith(join(f.config.root, 'staging'))) { begin(); await gate; } return original(...args); };
    syncBuiltinESMExports();
    const pending = f.init(bytes); void pending.catch(() => {});
    try {
      await Promise.race([started, new Promise<never>((_, reject) => { const timer = setTimeout(() => reject(new Error('Preparation hook was not reached')), 3000); timer.unref(); })]);
      const id = f.app.store.get('SELECT id FROM transfers WHERE userId=?', f.uid)!.id;
      await assert.rejects(controller.rpc('upload.cancel', { transferId: id }), /TRANSFER_BUSY/); assert.equal((await f.usage(controller)).reserved, bytes.length);
    } finally { release(); fsPromises.open = original; syncBuiltinESMExports(); }
    const id = await pending; assert.equal(existsSync(join(f.config.root, 'staging', id)), true);
    await controller.rpc('upload.cancel', { transferId: id }); assert.equal((await f.usage()).reserved, 0); assert.equal(existsSync(join(f.config.root, 'staging', id)), false);
  }, '以可释放的文件创建屏障验证真实双连接请求：初始化同样持有任务锁，取消不能抢先释放预留。');
  await run('取消与写入竞争：忙任务不会先释放配额，暂停后可重试取消', async f => {
    const bytes = randomBytes(23), id = await f.init(bytes), sender = await f.login();
    let begin!: () => void, release!: () => void; const started = new Promise<void>(r => begin = r), gate = new Promise<void>(r => release = r), take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.take = async (...args) => { begin(); await gate; return take(...args); };
    const pending = sender.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes); void pending.catch(() => {}); await started;
    try { await assert.rejects(f.owner.rpc('upload.cancel', { transferId: id }), /TRANSFER_BUSY/); assert.equal((await f.usage()).reserved, bytes.length); } finally { release(); }
    await pending; await f.owner.rpc('upload.cancel', { transferId: id }); assert.equal((await f.usage()).reserved, 0);
  }, '上传互斥锁同时保护取消、分块和发布，冲突返回忙状态且不改变记录。');
  await run('完成与取消竞争：只发生一次状态转换，无文件或配额重复', async f => {
    const bytes = randomBytes(31), id = await f.init(bytes), second = await f.login(); await f.owner.rpc('upload.chunk', { transferId: id, offset: 0 }, bytes);
    const outcomes = await Promise.allSettled([f.owner.rpc('upload.finish', { transferId: id }), second.rpc('upload.cancel', { transferId: id })]);
    assert.equal(outcomes.filter(r => r.status === 'fulfilled').length, 1); const u = await f.usage(); assert.equal(u.reserved, 0);
    assert.equal(u.used, f.app.store.get('SELECT id FROM files WHERE id=?', id) ? bytes.length : 0);
    assert.equal(existsSync(join(f.config.root, 'objects', id)), u.used !== 0);
  }, '并发 finish/cancel 不会在取消后发布对象，也不会遗留未计费的最终对象。');
  await run('删除崩溃窗口：磁盘已删除但事务失败，重启后仍占用直到重试', async f => {
    const bytes = randomBytes(47), fileId = await f.upload(bytes), original = f.app.store.run; let fail = true;
    f.app.store.run = function(sql, ...args) { if (fail && sql === 'DELETE FROM files WHERE id=? AND userId=?') { fail = false; throw new Error('simulated database failure'); } return original.call(this, sql, ...args); };
    await assert.rejects(f.owner.rpc('files.delete', { fileId }), /INTERNAL_ERROR/);
    assert.equal(existsSync(join(f.config.root, 'objects', fileId)), false); assert.equal((await f.usage()).used, bytes.length);
    const anchor = f.app.store.checkpoint(); await f.restart(); const owner = await f.login();
    assert.equal((await f.usage(owner)).used, bytes.length); await assert.rejects(owner.rpc('download.init', { fileId }), /FILE_DELETING/);
    await owner.rpc('files.delete', { fileId }); assert.equal((await f.usage(owner)).used, 0);
    assert.equal(verifyAudit(f.app.store.all('SELECT * FROM audit ORDER BY seq'), anchor).ok, true);
  }, '持久化删除意图跨重启保留；ENOENT 只在已接受的清理中视为完成，事务成功后才释放占用。');
  await run('兼容迁移：账号策略版数据增量升级，保留文件、任务和邀请', async f => {
    const bytes = randomBytes(73), fileId = await f.upload(bytes), transferId = await f.init(bytes, '续传.bin');
    await f.owner.rpc('upload.chunk', { transferId, offset: 0 }, bytes.subarray(0, 17));
    const invite = (await f.admin.rpc('invitations.create', { hours: 1 })).meta, anchor = f.app.store.checkpoint();
    // Version 1 has exactly these unchanged tables and no deletion table.
    f.app.store.db.exec('DROP TABLE mfa_settings; DROP TABLE mfa_recovery; DROP TABLE mfa_sessions; DROP TABLE mfa_attempts; DROP TABLE transfer_activity; DROP TABLE deliveries; DROP TABLE deletions; PRAGMA user_version=1;');
    await f.restart(); const owner = await f.login(), admin = await f.login('admin');
    assert.equal(f.app.store.get('PRAGMA user_version')!.user_version, DATABASE_VERSION); assert.equal((await f.usage(owner)).used, bytes.length); assert.equal((await f.usage(owner)).reserved, bytes.length);
    assert.equal(digest((await owner.rpc('download.chunk', { fileId, offset: 0 })).payload), digest(bytes));
    assert.equal((await owner.rpc('upload.init', { transferId, name: '续传.bin', size: bytes.length, sha256: digest(bytes) })).meta.offset, 17);
    assert.equal(f.app.store.get('SELECT id FROM invitations WHERE id=?', invite.id)!.id, invite.id);
    assert.equal((await admin.rpc('audit.verify', { checkpoint: anchor })).meta.ok, true);
  }, '从真实版本 1 表结构增量升级，新增删除意图与交付授权表；原口令、邀请、文件内容、任务偏移和审计检查点保留。');
  return results;
}
