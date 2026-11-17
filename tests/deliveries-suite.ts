import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, readdirSync, renameSync, rmdirSync } from 'node:fs';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { execFileSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { WebSocket } from 'ws';
import { createApp } from '../server/app.ts';
import { digest, verifyAudit } from '../server/store.ts';
import { certificates } from '../scripts/certificates.ts';
import { Peer, type Result } from './suite.ts';
import { CHUNK, decode, type Metadata } from '../shared/protocol.ts';

export async function runDeliverySuite(onResult?: (r: Result) => void) {
  mkdirSync('tmp', { recursive: true }); const root = mkdtempSync(resolve('tmp/deliveries-')); certificates(join(root, 'tls'));
  const ca = readFileSync(join(root, 'tls/ca.crt')), tls = { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) }, pass = randomBytes(24).toString('base64url');
  const results: Result[] = [];
  async function fixture() {
    const config = { root: mkdtempSync(join(root, 'data-')), origin: 'https://localhost', tls, loginLimit: 1000, normalRate: 64 * CHUNK, vipRate: 128 * CHUNK };
    let app = createApp(config); const ids: Record<string, string> = {};
    for (const name of ['owner', 'reader', 'stranger', 'second', 'admin']) ids[name] = await app.store.addUser(name, pass, name === 'admin' ? 'admin' : 'user');
    const start = async () => { app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening'); }; await start();
    const connect = async () => { const ws = new WebSocket(`wss://127.0.0.1:${(app.server.address() as { port: number }).port}/ws`, { ca, rejectUnauthorized: true, headers: { Origin: config.origin } }); await once(ws, 'open'); return new Peer(ws); };
    const login = async (name: string) => { const p = await connect(); await p.rpc('auth.password', { name, password: pass }); return p; };
    const owner = await login('owner'), reader = await login('reader'), stranger = await login('stranger'), admin = await login('admin');
    const bytes = randomBytes(CHUNK + 79), fileId = crypto.randomUUID(); writeFileSync(join(config.root, 'objects', fileId), bytes);
    app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', fileId, ids.owner, '交付资料.bin', bytes.length, digest(bytes), Date.now());
    const send = async (recipient = 'reader', peer = owner) => String((await peer.rpc('deliveries.create', { fileId, recipient })).meta.deliveryId);
    return { config, ids, bytes, fileId, owner, reader, stranger, admin, connect, login, send, get app() { return app; },
      async restart() { await app.close(); app = createApp(config); await start(); },
      async close() { assert.equal(verifyAudit(app.store.all('SELECT * FROM audit ORDER BY seq')).ok, true); assert.equal(JSON.stringify(app.store.all('SELECT * FROM audit')).includes(pass), false); await app.close(); }
    };
  }
  type Fixture = Awaited<ReturnType<typeof fixture>>;
  async function run(name: string, fn: (f: Fixture) => Promise<void>) {
    const at = performance.now(); let f: Fixture | undefined, failure: unknown;
    try { f = await fixture(); await fn(f); } catch (e) { failure = e; }
    finally { if (f) try { await f.close(); } catch (e) { failure ??= e; } }
    const result = { name, ok: !failure, ms: Math.round(performance.now() - at), detail: failure instanceof Error ? failure.message : failure ? String(failure) : '真实 TLS/WSS 请求及数据库、内容、授权状态断言通过。' };
    results.push(result); onResult?.(result);
  }
  const list = async (p: Peer, op = 'deliveries.received', offset = 0) => (await p.rpc(op, { offset })).meta.deliveries as Record<string, any>[];
  await run('交付权限：匿名与非所有者不能核对账号或发送他人文件', async f => {
    const anon = await f.connect();
    for (const op of ['deliveries.prepare', 'deliveries.create']) {
      await assert.rejects(anon.rpc(op, { fileId: f.fileId, recipient: 'reader' }), /AUTH_REQUIRED/);
      for (const p of [f.reader, f.stranger, f.admin]) await assert.rejects(p.rpc(op, { fileId: f.fileId, recipient: 'reader', ownerId: f.ids.owner }), /NOT_FOUND/);
    }
    for (const op of ['deliveries.received', 'deliveries.sent', 'deliveries.revoke']) await assert.rejects(anon.rpc(op, { deliveryId: 'unknown' }), /AUTH_REQUIRED/);
    const transfer = (await f.owner.rpc('upload.init', { name: '未完成.bin', size: 1, sha256: digest('x') })).meta.id;
    await assert.rejects(f.owner.rpc('deliveries.create', { fileId: transfer, recipient: 'reader' }), /NOT_FOUND/);
  });
  await run('接收账号：精确匹配，拒绝不存在、停用、自己和非法输入', async f => {
    assert.deepEqual((await f.owner.rpc('deliveries.prepare', { fileId: f.fileId, recipient: 'reader' })).meta.recipient, { name: 'reader' });
    await f.admin.rpc('users.disable', { userId: f.ids.second });
    for (const recipient of ['owner', 'missing', 'second', 'Reader', "' OR 1=1 --", '../reader']) await assert.rejects(f.owner.rpc('deliveries.create', { fileId: f.fileId, recipient }), /RECIPIENT_UNAVAILABLE/);
    const prepared = await f.owner.rpc('deliveries.prepare', { fileId: f.fileId, recipient: 'stranger' }); assert.ok(prepared.meta.recipient);
    await f.admin.rpc('users.disable', { userId: f.ids.stranger }); await assert.rejects(f.send('stranger'), /RECIPIENT_UNAVAILABLE/);
    assert.equal(f.app.store.all('SELECT * FROM deliveries').length, 0);
  });
  await run('正常交付：收发列表、跨块 SHA-256 与正确前缀续传', async f => {
    const deliveryId = await f.send(), received = await list(f.reader), sent = await list(f.owner, 'deliveries.sent');
    assert.equal(received.length, 1); assert.equal(received[0].id, f.fileId); assert.equal(received[0].deliveryId, deliveryId); assert.equal(received[0].sender, 'owner'); assert.equal(sent[0].recipient, 'reader');
    const access = { fileId: f.fileId, deliveryId }; const meta = (await f.reader.rpc('download.init', access)).meta; assert.equal(meta.name, '交付资料.bin'); assert.equal('userId' in meta, false);
    const parts = []; for (let offset = 0; offset < f.bytes.length; offset += CHUNK) parts.push((await f.reader.rpc('download.chunk', { ...access, offset })).payload);
    assert.equal(digest(Buffer.concat(parts)), digest(f.bytes));
    await f.reader.rpc('download.init', { ...access, offset: CHUNK, prefixHash: digest(f.bytes.subarray(0, CHUNK)) });
    await assert.rejects(f.reader.rpc('download.init', { ...access, offset: CHUNK, prefixHash: digest('wrong') }), /PREFIX_MISMATCH/);
  });
  await run('逐块授权：第三人和管理员知道文件与授权标识也不能读取', async f => {
    const deliveryId = await f.send();
    for (const p of [f.stranger, f.admin]) {
      assert.equal((await list(p)).length, 0); assert.equal((await list(p, 'deliveries.sent')).length, 0);
      for (const op of ['download.init', 'download.chunk']) {
        await assert.rejects(p.rpc(op, { fileId: f.fileId, deliveryId, offset: 0 }), /NOT_FOUND/);
        await assert.rejects(p.rpc(op, { fileId: f.fileId, offset: 0 }), /NOT_FOUND/);
      }
    }
    await assert.rejects(f.reader.rpc('download.init', { fileId: f.fileId }), /NOT_FOUND/);
    await assert.rejects(f.reader.rpc('download.chunk', { fileId: f.fileId, deliveryId: crypto.randomUUID(), offset: 0 }), /NOT_FOUND/);
    assert.equal(((await f.reader.rpc('files.list')).meta.files as unknown[]).length, 0);
  });
  await run('只读边界：接收者不能修改、删除、撤销他人授权或转授权', async f => {
    const deliveryId = await f.send();
    for (const [op, data] of [['files.rename', { fileId: f.fileId, name: '被篡改.bin' }], ['files.delete', { fileId: f.fileId }], ['deliveries.create', { fileId: f.fileId, recipient: 'stranger', deliveryId }], ['deliveries.revoke', { deliveryId }], ['upload.finish', { transferId: f.fileId }]] as const) await assert.rejects(f.reader.rpc(op, data), /NOT_FOUND/);
    await assert.rejects(f.admin.rpc('deliveries.revoke', { deliveryId }), /NOT_FOUND/);
    assert.equal(f.app.store.get('SELECT userId FROM files WHERE id=?', f.fileId)!.userId, f.ids.owner);
  });
  await run('幂等与并发：同一接收者只创建一个有效授权，不重复计存储', async f => {
    const otherOwner = await f.login('owner'), before = (await f.owner.rpc('storage.usage')).meta;
    const responses = await Promise.all([f.owner, otherOwner].map(p => p.rpc('deliveries.create', { fileId: f.fileId, recipient: 'reader' })));
    assert.equal(responses[0].meta.deliveryId, responses[1].meta.deliveryId); assert.equal(responses.filter(r => r.meta.created).length, 1);
    await f.send('stranger'); await f.send('second'); assert.equal(f.app.store.all('SELECT * FROM deliveries WHERE revoked=0').length, 3);
    assert.deepEqual((await f.owner.rpc('storage.usage')).meta, before); assert.equal((await f.reader.rpc('storage.usage')).meta.used, 0); assert.equal(readdirSync(join(f.config.root, 'objects')).length, 1);
  });
  await run('撤销与重新发送：旧标识失效，新授权不会恢复旧下载权限', async f => {
    const old = await f.send(); await f.owner.rpc('deliveries.revoke', { deliveryId: old }); await f.owner.rpc('deliveries.revoke', { deliveryId: old });
    assert.equal((await list(f.reader)).length, 0); assert.equal((await list(f.owner, 'deliveries.sent'))[0].reason, 'revoked');
    const current = await f.send(); assert.notEqual(current, old);
    for (const op of ['download.init', 'download.chunk']) await assert.rejects(f.reader.rpc(op, { fileId: f.fileId, deliveryId: old, offset: 0 }), /DELIVERY_UNAVAILABLE/);
    assert.equal((await f.reader.rpc('download.chunk', { fileId: f.fileId, deliveryId: current, offset: 0 })).payload.length, CHUNK);
    assert.equal((await f.owner.rpc('download.chunk', { fileId: f.fileId, offset: 0 })).payload.length, CHUNK);
  });
  await run('下载中撤销：两个接收会话的带宽等待取消，其他接收授权不受影响', async f => {
    const deliveryId = await f.send(), secondId = await f.send('stranger'), reader2 = await f.login('reader');
    f.app.bw.next.set(f.ids.reader, performance.now() + 5000);
    let count = 0, begin!: () => void, received = 0; const started = new Promise<void>(r => begin = r), take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.take = async (...args) => { if (++count === 2) begin(); return take(...args); };
    for (const p of [f.reader, reader2]) p.ws.on('message', data => { received += decode(Buffer.from(data as Buffer)).payload.length; });
    const rejected = [f.reader, reader2].map(p => assert.rejects(p.rpc('download.chunk', { fileId: f.fileId, deliveryId, offset: 0 }), /DELIVERY_UNAVAILABLE/));
    await started; const at = performance.now(); await f.owner.rpc('deliveries.revoke', { deliveryId }); await Promise.all(rejected);
    assert.ok(performance.now() - at < 1500); assert.equal(received, 0);
    assert.equal((await f.stranger.rpc('download.chunk', { fileId: f.fileId, deliveryId: secondId, offset: 0 })).payload.length, CHUNK);
  });
  await run('读取后撤销：已读入服务端缓冲的数据也不能在撤销后发出', async f => {
    const deliveryId = await f.send(), original = fsPromises.open, run = f.app.store.run;
    let begin!: () => void, release!: () => void, revoked!: () => void;
    const started = new Promise<void>(r => begin = r), gate = new Promise<void>(r => release = r), ended = new Promise<void>(r => revoked = r);
    fsPromises.open = async (...args) => {
      const h = await original(...args);
      if (String(args[0]) === join(f.config.root, 'objects', f.fileId) && args[1] === 'r') {
        const read = h.read.bind(h); h.read = (async (...args: any[]) => { const result = await (read as any)(...args); begin(); await gate; return result; }) as typeof h.read;
      }
      return h;
    }; syncBuiltinESMExports();
    f.app.store.run = function(sql, ...args) { const result = run.call(this, sql, ...args); if (sql.startsWith('UPDATE deliveries SET revoked=1')) revoked(); return result; };
    const denied = assert.rejects(f.reader.rpc('download.chunk', { fileId: f.fileId, deliveryId, offset: 0 }), /DELIVERY_UNAVAILABLE/);
    try { await started; const revoke = f.owner.rpc('deliveries.revoke', { deliveryId }); await ended; release(); await revoke; await denied; }
    finally { release(); fsPromises.open = original; syncBuiltinESMExports(); f.app.store.run = run; }
  });
  await run('重命名：收到列表使用当前名称，授权及内容保持不变', async f => {
    const deliveryId = await f.send(); await f.owner.rpc('files.rename', { fileId: f.fileId, name: '改名后的交付资料.bin' });
    assert.equal((await list(f.reader))[0].name, '改名后的交付资料.bin'); assert.equal((await list(f.owner, 'deliveries.sent'))[0].name, '改名后的交付资料.bin');
    const info = (await f.reader.rpc('download.init', { fileId: f.fileId, deliveryId, offset: CHUNK, prefixHash: digest(f.bytes.subarray(0, CHUNK)) })).meta;
    assert.equal(info.sha256, digest(f.bytes)); assert.equal(info.name, '改名后的交付资料.bin');
  });
  await run('源文件删除：原授权永久失效，等待下载取消且不重复占用配额', async f => {
    const deliveryId = await f.send(); f.app.bw.next.set(f.ids.reader, performance.now() + 5000);
    let begin!: () => void; const started = new Promise<void>(r => begin = r), take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.take = async (...args) => { begin(); return take(...args); };
    const denied = assert.rejects(f.reader.rpc('download.chunk', { fileId: f.fileId, deliveryId, offset: 0 }), /DELIVERY_UNAVAILABLE/);
    const path = join(f.config.root, 'objects', f.fileId), saved = path + '.saved'; renameSync(path, saved); mkdirSync(path);
    await started; await assert.rejects(f.owner.rpc('files.delete', { fileId: f.fileId }), /DELETE_FAILED/); await denied;
    assert.equal((await f.owner.rpc('storage.usage')).meta.used, f.bytes.length); assert.equal((await list(f.reader)).length, 0);
    rmdirSync(path); renameSync(saved, path); await f.owner.rpc('files.delete', { fileId: f.fileId });
    assert.equal((await list(f.reader)).length, 0); assert.equal((await list(f.owner, 'deliveries.sent'))[0].reason, 'file-deleted');
    await assert.rejects(f.reader.rpc('download.init', { fileId: f.fileId, deliveryId }), /DELIVERY_UNAVAILABLE/); assert.equal((await f.owner.rpc('storage.usage')).meta.used, 0);
  });
  await run('账号停用：发送者或接收者停用均终止相应授权和等待下载', async f => {
    for (const who of ['reader', 'owner']) {
      const recipient = who === 'reader' ? f.reader : f.stranger, name = who === 'reader' ? 'reader' : 'stranger', deliveryId = await f.send(name);
      f.app.bw.next.set(f.ids[name], performance.now() + 5000);
      let begin!: () => void; const started = new Promise<void>(r => begin = r), take = f.app.bw.take.bind(f.app.bw);
      f.app.bw.take = async (...args) => { begin(); return take(...args); };
      const denied = assert.rejects(recipient.rpc('download.chunk', { fileId: f.fileId, deliveryId, offset: 0 }), /DELIVERY_UNAVAILABLE|CLOSED/);
      await started; await f.admin.rpc('users.disable', { userId: f.ids[who] }); await denied;
      assert.equal(f.app.store.get('SELECT reason FROM deliveries WHERE id=?', deliveryId)!.reason, 'account-disabled');
    }
    assert.equal((await list(f.stranger)).length, 0); assert.equal(f.app.store.get('SELECT size FROM files WHERE id=?', f.fileId)!.size, f.bytes.length);
  });
  await run('审计隔离：发送、下载开始与撤销对双方可见，对无关用户不可见', async f => {
    const deliveryId = await f.send(); await f.reader.rpc('download.chunk', { fileId: f.fileId, deliveryId, offset: 0 }); await f.owner.rpc('deliveries.revoke', { deliveryId });
    for (const p of [f.owner, f.reader]) {
      const events = (await p.rpc('events.list')).meta.events as Record<string, any>[];
      for (const action of ['deliveries.create', 'deliveries.download', 'deliveries.revoke']) assert.equal(events.some(e => e.action === action && e.detail.deliveryId === deliveryId), true);
    }
    const events = (await f.stranger.rpc('events.list')).meta.events as Record<string, any>[]; assert.equal(events.some(e => e.detail.deliveryId === deliveryId), false);
    const rows = f.app.store.all('SELECT * FROM audit').map(r => JSON.parse(r.event)); const e = rows.find(e => e.action === 'deliveries.download'); assert.equal(e.detail.sender, 'owner'); assert.equal(e.detail.recipient, 'reader'); assert.equal('read' in e.detail, false);
  });
  await run('接收者带宽：收件下载计入接收账号的共享预算', async f => {
    const deliveryId = await f.send(), called: string[] = [], take = f.app.bw.take.bind(f.app.bw);
    f.app.bw.take = async (...args) => { called.push(args[0]); return take(...args); };
    await f.reader.rpc('download.chunk', { fileId: f.fileId, deliveryId, offset: 0 }); assert.deepEqual(called, [f.ids.reader]);
    assert.equal((await f.reader.rpc('storage.usage')).meta.used, 0); assert.equal((await f.owner.rpc('storage.usage')).meta.used, f.bytes.length);
  });
  await run('分页与额度：收发列表有界且互相隔离，授权上限不可绕过', async f => {
    f.app.store.transaction(() => { for (let i = 0; i < 13; i++) {
      const fid = crypto.randomUUID(); f.app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', fid, f.ids.owner, '分页-' + i, 0, digest(''), i);
      f.app.store.run('INSERT INTO deliveries(id,fileId,ownerId,recipientId,name,created) VALUES(?,?,?,?,?,?)', crypto.randomUUID(), fid, f.ids.owner, f.ids.reader, '分页-' + i, i);
    } });
    assert.equal((await list(f.reader)).length, 12); assert.equal((await list(f.reader, 'deliveries.received', 12)).length, 1); assert.equal((await list(f.owner, 'deliveries.sent')).length, 12); assert.equal((await list(f.stranger)).length, 0);
    f.app.store.transaction(() => { for (let i = 13; i < 1000; i++) f.app.store.run('INSERT INTO deliveries(id,fileId,ownerId,recipientId,name,created) VALUES(?,?,?,?,?,?)', crypto.randomUUID(), 'history-' + i, f.ids.second, f.ids.reader, '占位', i); });
    await assert.rejects(f.send(), /DELIVERY_LIMIT/); assert.equal(f.app.store.get('SELECT COUNT(*) AS n FROM deliveries WHERE revoked=0')!.n, 1000);
  });
  await run('投递频率：重复核对和发送受账号聚合限制', async f => {
    const p2 = await f.login('owner');
    for (let i = 0; i < 30; i++) await (i % 2 ? p2 : f.owner).rpc('deliveries.prepare', { fileId: f.fileId, recipient: 'reader' });
    await assert.rejects(f.send(), /RATE_LIMITED/); assert.equal((await f.reader.rpc('ping')).meta.ok, true);
  });
  await run('重启持久化：有效和已撤销授权、名称、检查点与配额保留', async f => {
    const active = await f.send(), revoked = await f.send('stranger'); await f.owner.rpc('deliveries.revoke', { deliveryId: revoked });
    await f.owner.rpc('files.rename', { fileId: f.fileId, name: '重启保留.bin' }); const quota = (await f.owner.rpc('storage.usage')).meta, anchor = f.app.store.checkpoint();
    await f.restart(); const owner = await f.login('owner'), reader = await f.login('reader'), stranger = await f.login('stranger');
    assert.equal((await list(reader))[0].deliveryId, active); assert.equal((await list(reader))[0].name, '重启保留.bin');
    assert.deepEqual((await owner.rpc('storage.usage')).meta, quota); await assert.rejects(stranger.rpc('download.init', { fileId: f.fileId, deliveryId: revoked }), /DELIVERY_UNAVAILABLE/);
    assert.equal((await reader.rpc('download.chunk', { fileId: f.fileId, deliveryId: active, offset: 0 })).payload.length, CHUNK); assert.equal(verifyAudit(f.app.store.all('SELECT * FROM audit ORDER BY seq'), anchor).ok, true);
  });
  await run('版本 2 升级：原表指纹、删除意图、邀请和文件任务均保持', async f => {
    const transferId = (await f.owner.rpc('upload.init', { name: '待清理.bin', size: 37, sha256: digest(Buffer.alloc(37)) })).meta.id;
    f.app.store.run("INSERT INTO deletions VALUES(?,'transfers',?,?)", transferId, f.ids.owner, Date.now());
    await f.admin.rpc('invitations.create', { hours: 1 }); f.app.store.db.exec('DROP TABLE transfer_activity; DROP TABLE deliveries; PRAGMA user_version=2;');
    const snapshot = () => JSON.parse(execFileSync(process.execPath, [resolve('scripts/data-snapshot.mjs')], { env: { ...process.env, DATA_DIR: f.config.root }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
    const before = snapshot(); await f.restart(); const after = snapshot();
    for (const [table, records] of Object.entries(before.tables)) for (const [id, hash] of Object.entries(records as Record<string, string>)) assert.equal(after.tables[table][id], hash);
    assert.equal(f.app.store.get('PRAGMA user_version')!.user_version, 4); assert.equal(digest(readFileSync(join(f.config.root, 'objects', f.fileId))), digest(f.bytes));
  });
  return results;
}
