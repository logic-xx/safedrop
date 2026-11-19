import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { once } from 'node:events';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { WebSocket } from 'ws';
import { createTestApp as createApp, scanFixtureFile } from './test-scanner.ts';
import { setTimeout as pause } from 'node:timers/promises';
import { digest, verifyAudit, type Row } from '../server/store.ts';
import { encode, decode, CHUNK, MAX_FRAME, type Metadata, type Frame } from '../shared/protocol.ts';
import { certificates } from '../scripts/certificates.ts';

export class Peer {
  seq = 0; pending = new Map<number, { yes: (f: Frame) => void; no: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  constructor(public ws: WebSocket, private waitForScan = true) {
    ws.on('message', data => { const f = decode(Buffer.from(data as Buffer)); const p = this.pending.get(f.requestId); if (p) { clearTimeout(p.timer); this.pending.delete(f.requestId); f.meta.ok ? p.yes(f) : p.no(new Error(String(f.meta.code))); } });
    ws.on('error', () => {});
    ws.on('close', () => { for (const p of this.pending.values()) { clearTimeout(p.timer); p.no(new Error('CLOSED')); } this.pending.clear(); });
  }
  async rpc(op: string, meta: Metadata = {}, payload?: Uint8Array): Promise<Frame> {
    const n = ++this.seq;
    const frame = await new Promise<Frame>((yes, no) => { const timer = setTimeout(() => { this.pending.delete(n); no(new Error('TIMEOUT')); }, 6000); this.pending.set(n, { yes, no, timer }); this.ws.send(encode(1, n, { op, ...meta }, payload)); });
    if (op === 'upload.finish' && this.waitForScan) {
      for (let i = 0; i < 200; i++) { const result = await this.rpc('files.scan.status', { fileId: frame.meta.fileId }); if (!['pending','scanning'].includes(String((result.meta.scan as Row).state))) return frame; await pause(10); }
      throw Error('CONTROLLED_UPLOAD_SCAN_TIMEOUT');
    }
    return frame;
  }
}
export interface Result { name: string; ok: boolean; ms: number; detail: string }
export async function runSuite(onResult?: (r: Result) => void) {
  mkdirSync(resolve('tmp'), { recursive: true }); const root = mkdtempSync(resolve('tmp/security-'));
  certificates(join(root, 'tls')); const ca = readFileSync(join(root, 'tls/ca.crt'));
  const config = { root: join(root, 'data'), origin: 'https://localhost', tls: { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) }, maxFile: 16 * 1024 ** 2, quota: 32 * 1024 ** 2, loginLimit: 12 };
  let app = createApp(config), port = 0; const peers: Peer[] = [], results: Result[] = [];
  const start = async () => { app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening'); port = (app.server.address() as { port: number }).port; };
  const connect = async (origin = config.origin, trusted = true) => {
    const ws = new WebSocket(`wss://127.0.0.1:${port}/ws`, { ca: trusted ? ca : undefined, headers: { Origin: origin }, handshakeTimeout: 3000 });
    await once(ws, 'open'); const p = new Peer(ws); peers.push(p); return p;
  };
  const pass = randomBytes(18).toString('base64url');
  const run = async (name: string, fn: () => Promise<void | string> | void, detail: string) => { const at = performance.now(); let result: Result; try { const evidence = await fn(); result = { name, ok: true, ms: Math.round(performance.now() - at), detail: evidence ?? detail }; } catch (e) { result = { name, ok: false, ms: Math.round(performance.now() - at), detail: e instanceof Error ? e.message : String(e) }; } results.push(result); onResult?.(result); };
  try {
    await app.store.addUser('admin', pass, 'admin', 'vip'); await app.store.addUser('alice', pass); await app.store.addUser('bob', pass, 'user', 'vip'); await start();
    await run('TLS：拒绝不可信 CA', async () => { await assert.rejects(connect(config.origin, false)); }, '客户端开启标准证书校验，未信任本地 CA 时 TLS 握手失败。');
    await run('WebSocket：拒绝非允许来源', async () => { await assert.rejects(connect('https://attacker.invalid')); }, '错误 Origin 的握手被拒绝。');
    let alice = await connect(), bob = await connect(), admin = await connect();
    await run('认证：未登录不能列出文件', async () => { await assert.rejects(alice.rpc('files.list'), /AUTH_REQUIRED/); }, '服务端拒绝未经认证的业务消息。');
    await run('认证：SQL 注入不能绕过登录', async () => { await assert.rejects(alice.rpc('auth.password', { name: "' OR 1=1 --", password: pass }), /INVALID_CREDENTIALS/); }, '含 SQL 注入语句的用户名按普通参数处理。');
    await alice.rpc('auth.password', { name: 'alice', password: pass }); await bob.rpc('auth.password', { name: 'bob', password: pass }); await admin.rpc('auth.password', { name: 'admin', password: pass });
    const content = randomBytes(CHUNK + 37), sha = digest(content); let transferId = '', fileId = '';
    await run('文件路径：拒绝目录穿越文件名', async () => { await assert.rejects(alice.rpc('upload.init', { name: '../escape.txt', size: 0, sha256: digest('') }), /INVALID_FILENAME/); }, '显示文件名不可包含路径分隔符，物理路径由服务器生成。');
    await run('配额：拒绝超限文件', async () => { await assert.rejects(alice.rpc('upload.init', { name: 'huge.bin', size: 17 * 1024 ** 2, sha256: sha }), /INVALID_INTEGER/); }, '在分配磁盘前验证文件大小上限。');
    await run('上传：确认偏移与重复块幂等', async () => {
      transferId = String((await alice.rpc('upload.init', { name: '中文资料.bin', size: content.length, sha256: sha })).meta.id);
      assert.equal((await alice.rpc('upload.chunk', { transferId, offset: 0 }, content.subarray(0, CHUNK))).meta.offset, CHUNK);
      assert.equal((await alice.rpc('upload.chunk', { transferId, offset: 0 }, content.subarray(0, CHUNK))).meta.offset, CHUNK);
      await assert.rejects(alice.rpc('upload.chunk', { transferId, offset: 0 }, Buffer.alloc(CHUNK)), /CHUNK_CONFLICT/);
    }, '相同块重复发送不重复追加；同偏移不同内容被拒绝。');
    await run('隔离：其他用户不能续写上传任务', async () => { await assert.rejects(bob.rpc('upload.chunk', { transferId, offset: CHUNK }, content.subarray(CHUNK)), /NOT_FOUND/); }, '任务标识已知也不能越过账号所有权检查。');
    await run('状态机：错误偏移和提前完成被拒绝', async () => { await assert.rejects(alice.rpc('upload.chunk', { transferId, offset: CHUNK + 1 }, content.subarray(CHUNK + 1)), /INVALID_OFFSET/); await assert.rejects(alice.rpc('upload.finish', { transferId }), /INCOMPLETE_FILE/); }, '接收状态与确认位置均由服务器验证。');
    await run('续传：服务端重启后恢复持久化偏移', async () => {
      await app.close(); app = createApp(config); await start(); alice = await connect(); bob = await connect(); admin = await connect();
      await alice.rpc('auth.password', { name: 'alice', password: pass }); await bob.rpc('auth.password', { name: 'bob', password: pass }); await admin.rpc('auth.password', { name: 'admin', password: pass });
      const t = await alice.rpc('upload.init', { transferId, name: '中文资料.bin', size: content.length, sha256: sha }); assert.equal(t.meta.offset, CHUNK);
      await alice.rpc('upload.chunk', { transferId, offset: CHUNK }, content.subarray(CHUNK)); fileId = String((await alice.rpc('upload.finish', { transferId })).meta.fileId);
    }, '重启服务后重新认证，从已同步确认的偏移继续并完成完整文件校验。');
    await run('完成确认：重发不会重复发布文件', async () => { assert.equal((await alice.rpc('upload.finish', { transferId })).meta.fileId, fileId); }, '完成请求可安全重试。');
    await run('下载：跨块文件 SHA-256 一致', async () => { const parts = []; for (let offset = 0; offset < content.length; offset += CHUNK) parts.push((await alice.rpc('download.chunk', { fileId, offset })).payload); assert.equal(digest(Buffer.concat(parts)), sha); }, '中文文件名与跨块二进制数据完整恢复。');
    await run('下载续传：验证前缀再接受偏移', async () => { await assert.rejects(alice.rpc('download.init', { fileId, offset: CHUNK, prefixHash: digest('wrong') }), /PREFIX_MISMATCH/); const r = await alice.rpc('download.init', { fileId, offset: CHUNK, prefixHash: digest(content.subarray(0, CHUNK)) }); assert.equal(r.meta.sha256, sha); }, '错误本地前缀被拒绝；正确前缀可从指定位置恢复。');
    await run('隔离：其他用户不能下载文件', async () => { await assert.rejects(bob.rpc('download.chunk', { fileId, offset: 0 }), /NOT_FOUND/); assert.equal(((await bob.rpc('files.list')).meta.files as Row[]).length, 0); }, '列表与下载接口同时实施用户隔离。');
    await run('完整性：错误整文件摘要不能发布', async () => { const t = String((await alice.rpc('upload.init', { name: 'bad.bin', size: 1, sha256: digest('different') })).meta.id); await alice.rpc('upload.chunk', { transferId: t, offset: 0 }, new Uint8Array([1])); await assert.rejects(alice.rpc('upload.finish', { transferId: t }), /HASH_MISMATCH/); await alice.rpc('upload.cancel', { transferId: t }); }, '只在大小和摘要均正确后发布文件。');
    await run('边界：空文件可以传输并校验', async () => { const t = String((await alice.rpc('upload.init', { name: '空文件.txt', size: 0, sha256: digest('') })).meta.id); const r = await alice.rpc('upload.finish', { transferId: t }); assert.equal(r.meta.sha256, digest('')); }, '零字节文件使用标准空内容摘要。');
    let keyId = ''; const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    await run('公钥：绑定要求重新验证口令', async () => { const jwk = pair.publicKey.export({ format: 'jwk' }); await assert.rejects(alice.rpc('keys.enroll', { jwk, label: 'test', password: 'wrong' }), /INVALID_CREDENTIALS/); keyId = String((await alice.rpc('keys.enroll', { jwk, label: 'test', password: pass })).meta.keyId); }, '不能通过未重新认证的请求替换身份公钥。');
    await run('公钥：签名认证成功，挑战不能重复使用', async () => { const p = await connect(); const challenge = String((await p.rpc('auth.challenge', { name: 'alice', keyId })).meta.message); const signature = sign('sha256', Buffer.from(challenge), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64'); assert.equal(((await p.rpc('auth.prove', { signature })).meta.user as Row).name, 'alice'); await assert.rejects(p.rpc('auth.prove', { signature }), /CHALLENGE_INVALID/); }, '标准 P-256 签名验签，挑战原子消费。');
    await run('公钥：错误签名不能认证', async () => { const p = await connect(); await p.rpc('auth.challenge', { name: 'alice', keyId }); await assert.rejects(p.rpc('auth.prove', { signature: randomBytes(64).toString('base64') }), /INVALID_SIGNATURE/); p.ws.close(); }, '错误私钥或伪造签名不能建立会话。');
    await run('会话：撤销后连接关闭且无法继续业务', async () => { const p = await connect(); const auth = await p.rpc('auth.password', { name: 'alice', password: pass }); const closed = once(p.ws, 'close'); await alice.rpc('sessions.revoke', { sessionId: auth.meta.session }); await closed; assert.equal(p.ws.readyState, WebSocket.CLOSED); await assert.rejects(bob.rpc('sessions.revoke', { sessionId: (await alice.rpc('sessions.list')).meta.current }), /NOT_FOUND/); }, '撤销指定会话，服务端关闭对应长连接；其他用户不能撤销。');
    await run('权限：普通用户不能导出全局审计日志', async () => { await assert.rejects(alice.rpc('audit.page'), /FORBIDDEN/); }, '安全中心与审计导出实施独立角色权限。');
    await run('审计：检测改写及独立检查点不匹配', async () => {
      const rows = app.store.all('SELECT * FROM audit ORDER BY seq'), anchor = app.store.checkpoint(); assert.equal(verifyAudit(rows, anchor).ok, true);
      const changed = structuredClone(rows); changed[1].event += ' '; assert.equal(verifyAudit(changed, anchor).ok, false);
      const rewritten = structuredClone(rows); rewritten[1].event += ' '; for (let i = 1; i < rewritten.length; i++) { rewritten[i].prev = rewritten[i - 1].hash; rewritten[i].hash = digest(rewritten[i].prev + rewritten[i].event); }
      assert.equal(verifyAudit(rewritten).ok, true); assert.equal(verifyAudit(rewritten, anchor).ok, false); assert.equal(verifyAudit(rows.slice(0, -1), anchor).ok, false);
      assert.equal((await admin.rpc('audit.verify', { checkpoint: anchor })).meta.ok, true);
    }, '局部修改、整链重算、尾部截断均有相应检查；重算检测依赖独立可信检查点。');
    await run('协议：畸形报文关闭连接，服务仍可用', async () => { const p = await connect(); const closed = once(p.ws, 'close'); p.ws.send(Buffer.from([1, 2, 3])); await closed; assert.equal((await alice.rpc('ping')).meta.ok, true); }, '错误协议头仅影响违规连接。');
    await run('协议：超大报文被拒绝', async () => { const p = await connect(); const closed = once(p.ws, 'close'); p.ws.send(Buffer.alloc(MAX_FRAME + 1)); await closed; assert.equal((await admin.rpc('ping')).meta.ok, true); }, 'WebSocket 消息上限在业务解析前生效。');
    await run('连接：文件完成后复用原有长连接', async () => { const a = await alice.rpc('hello'); await alice.rpc('files.list'); const b = await alice.rpc('hello'); assert.equal(a.meta.connection, b.meta.connection); }, '多种业务请求前后连接标识保持不变。');
    await run('并发：多个上传与下载同时进行', async () => {
      await Promise.all([0, 1, 2].map(async n => { const data = randomBytes(4096 + n); const t = String((await alice.rpc('upload.init', { name: `parallel-${n}.bin`, size: data.length, sha256: digest(data) })).meta.id); await alice.rpc('upload.chunk', { transferId: t, offset: 0 }, data); await alice.rpc('upload.finish', { transferId: t }); }).concat([(async () => { assert.equal((await alice.rpc('download.chunk', { fileId, offset: 0 })).payload.length, CHUNK); })()]));
    }, '同一 WSS 连接交错处理三个文件上传与一个下载，任务互不混淆。');
    await run('带宽：VIP 差异及跨连接账号聚合限速', async () => {
      const normalId = await app.store.addUser('speed-normal', pass), vipId = await app.store.addUser('speed-vip', pass, 'user', 'vip');
      const payload = randomBytes(2 * 1024 ** 2), sha = digest(payload), nf = crypto.randomUUID(), vf = crypto.randomUUID();
      for (const [fid, uid] of [[nf, normalId], [vf, vipId]]) { await writeFile(join(config.root, 'objects', fid), payload); app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)', fid, uid, 'speed.bin', payload.length, sha, Date.now()); await scanFixtureFile(app, fid); }
      const p1 = await connect(), p2 = await connect(), pv = await connect();
      await p1.rpc('auth.password', { name: 'speed-normal', password: pass }); await p2.rpc('auth.password', { name: 'speed-normal', password: pass }); await pv.rpc('auth.password', { name: 'speed-vip', password: pass });
      const start = performance.now(); await Promise.all([p1, p2].map(async p => { for (let i = 0; i < 4; i++) assert.equal((await p.rpc('download.chunk', { fileId: nf, offset: i * CHUNK })).payload.length, CHUNK); })); const normalMs = performance.now() - start;
      const vs = performance.now(); for (let i = 0; i < 8; i++) assert.equal((await pv.rpc('download.chunk', { fileId: vf, offset: i * CHUNK })).payload.length, CHUNK); const vipMs = performance.now() - vs;
      assert.ok(normalMs >= 1500, `normal ${normalMs}`); assert.ok(vipMs < normalMs * .75, `VIP ${vipMs}, normal ${normalMs}`);
      return `实际传输各 2 MiB：普通账号双连接合计 ${Math.round(normalMs)} ms，VIP ${Math.round(vipMs)} ms。包含首块突发额度，仅为本机短样本。`;
    }, '');
    await run('反滥用：连续认证失败触发限流', async () => { const p = await connect(); let limited = false; for (let i = 0; i < 14; i++) try { await p.rpc('auth.password', { name: 'alice', password: 'wrong' }); } catch (e) { if ((e as Error).message === 'RATE_LIMITED') { limited = true; break; } } assert.equal(limited, true); p.ws.close(); }, '受控连续失败请求被限流，未对外部系统发起流量。');
  } finally { await app.close(); }
  return { created: new Date().toISOString(), node: process.version, platform: `${process.platform}/${process.arch}`, passed: results.filter(r => r.ok).length, results };
}
