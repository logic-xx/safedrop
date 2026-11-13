import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { request } from 'node:https';
import { join, resolve } from 'node:path';
import { setTimeout as pause } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';
import { CHUNK, encode, decode, type Frame, type Metadata } from '../shared/protocol.ts';
import { digest, type Checkpoint } from '../server/store.ts';

type Account = { name: string; password: string };
type State = { seed: string; name: string; sha256: string; fileId: string; transferId: string; checkpoint: Checkpoint };
export interface ContainerCheckOptions { origin: string; ca: Buffer; accounts: Account[]; statePath: string; phase: 'seed' | 'resume' }

class Peer {
  seq = 0;
  pending = new Map<number, { resolve: (frame: Frame) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  constructor(public ws: WebSocket) {
    ws.on('error', () => {});
    ws.on('message', data => {
      try {
        const frame = decode(new Uint8Array(data as Buffer)), pending = this.pending.get(frame.requestId);
        if (!pending) return;
        clearTimeout(pending.timer); this.pending.delete(frame.requestId);
        if (frame.meta.ok) pending.resolve(frame); else pending.reject(new Error(String(frame.meta.code)));
      } catch (error) { this.close(error instanceof Error ? error : new Error('INVALID_RESPONSE')); }
    });
    ws.on('close', () => this.close(new Error('CONNECTION_CLOSED')));
  }
  rpc(op: string, meta: Metadata = {}, payload?: Uint8Array) {
    const requestId = ++this.seq;
    return new Promise<Frame>((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(requestId); reject(new Error('RPC_TIMEOUT')); }, 10000);
      this.pending.set(requestId, { resolve, reject, timer });
      this.ws.send(encode(1, requestId, { op, ...meta }, payload));
    });
  }
  close(error = new Error('CHECK_FINISHED')) {
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(error); }
    this.pending.clear(); this.ws.terminate();
  }
}

function payload(seed: string) {
  const pattern = Buffer.from(seed, 'hex'), bytes = Buffer.alloc(CHUNK * 2 + 37);
  for (let i = 0; i < bytes.length; i++) bytes[i] = pattern[i % pattern.length] ^ (i & 255);
  return bytes;
}

export async function checkContainer(options: ContainerCheckOptions) {
  const { origin, ca, accounts, statePath, phase } = options, peers: Peer[] = [], checks: string[] = [];
  const target = new URL(origin);
  assert.equal(target.protocol, 'https:'); assert.equal(target.hostname, 'localhost');
  const get = (path: string, servername = 'localhost') => new Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: target.port || 443, servername, ca, path, headers: { Host: target.host }, timeout: 2000, rejectUnauthorized: true }, res => {
      let body = ''; res.on('data', data => { body += data; });
      res.on('error', reject); res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('timeout', () => req.destroy(new Error('HTTPS_TIMEOUT'))); req.on('error', reject); req.end();
  });
  const connect = async (requestOrigin = origin) => {
    const connectionOptions = { ca, servername: 'localhost', rejectUnauthorized: true, headers: { Origin: requestOrigin, Host: target.host }, handshakeTimeout: 3000 };
    const ws = new WebSocket(`wss://127.0.0.1:${target.port || 443}/ws`, connectionOptions);
    try { await once(ws, 'open'); } catch (error) { ws.on('error', () => {}); ws.terminate(); throw error; }
    const peer = new Peer(ws); peers.push(peer); return peer;
  };
  const login = async (name: string) => {
    const account = accounts.find(account => account.name === name); assert.ok(account, `Missing generated account: ${name}`);
    const peer = await connect(); await peer.rpc('auth.password', { name, password: account.password }); return peer;
  };
  const download = async (peer: Peer, fileId: string) => {
    const info = (await peer.rpc('download.init', { fileId, offset: 0 })).meta, blocks: Buffer[] = [];
    for (let offset = 0; offset < Number(info.size);) {
      const frame = await peer.rpc('download.chunk', { fileId, offset });
      assert.equal(frame.meta.offset, offset); assert.ok(frame.payload.length > 0);
      offset += frame.payload.length; assert.equal(frame.meta.next, offset); blocks.push(Buffer.from(frame.payload));
    }
    return digest(Buffer.concat(blocks));
  };
  const finish = async (peer: Peer, transferId: string, bytes: Buffer, start = 0) => {
    for (let offset = start; offset < bytes.length; offset += CHUNK) {
      const block = bytes.subarray(offset, offset + CHUNK), frame = await peer.rpc('upload.chunk', { transferId, offset }, block);
      assert.equal(frame.meta.offset, offset + block.length);
    }
    return String((await peer.rpc('upload.finish', { transferId })).meta.fileId);
  };
  try {
    let ready = false;
    for (let i = 0; i < 40; i++) {
      try { const health = await get('/health'); ready = health.status === 200 && JSON.parse(health.body).protocol === 'SFT/1'; if (ready) break; } catch { /* Wait for the gateway and backend. */ }
      await pause(500);
    }
    assert.ok(ready, 'HTTPS health endpoint did not become ready');
    const page = await get('/'); assert.equal(page.status, 200); assert.match(page.body, /SafeDrop/);
    assert.match(String(page.headers['content-security-policy']), /frame-ancestors 'none'/);
    assert.match(String(page.headers['strict-transport-security']), /max-age=31536000/);
    assert.equal(page.headers['x-content-type-options'], 'nosniff');
    await assert.rejects(get('/health', 'wrong-host.invalid'));
    checks.push('HTTPS certificate/hostname validation, Vue page and security headers');
    await assert.rejects(connect('https://attacker.invalid'));
    const peer = await connect(); await assert.rejects(peer.rpc('files.list'), /AUTH_REQUIRED/);
    const alice = accounts.find(account => account.name === 'alice'); assert.ok(alice);
    await peer.rpc('auth.password', { name: alice.name, password: alice.password });
    checks.push('WSS origin filtering and authentication');
    const connection = (await peer.rpc('hello')).meta.connection;
    if (phase === 'seed') {
      const seed = randomBytes(32).toString('hex'), bytes = payload(seed), sha256 = digest(bytes), name = `container-check-${seed.slice(0, 12)}`;
      const complete = await peer.rpc('upload.init', { name: name + '.bin', size: bytes.length, sha256 });
      const fileId = await finish(peer, String(complete.meta.id), bytes);
      assert.equal(await download(peer, fileId), sha256);
      const bob = await login('bob'); await assert.rejects(bob.rpc('download.init', { fileId, offset: 0 }), /NOT_FOUND/);
      const partial = await peer.rpc('upload.init', { name: name + '-resume.bin', size: bytes.length, sha256 });
      assert.equal((await peer.rpc('upload.chunk', { transferId: partial.meta.id, offset: 0 }, bytes.subarray(0, CHUNK))).meta.offset, CHUNK);
      const admin = await login('admin'), checkpoint = (await admin.rpc('audit.page')).meta.checkpoint as unknown as Checkpoint;
      const state: State = { seed, name, sha256, fileId, transferId: String(partial.meta.id), checkpoint };
      writeFileSync(statePath, JSON.stringify(state, null, 2));
      checks.push('Upload/download SHA-256 and cross-user access denial', 'Persistent partial upload and independent audit checkpoint prepared');
    } else {
      const state: State = JSON.parse(readFileSync(statePath, 'utf8')), bytes = payload(state.seed);
      assert.equal((await peer.rpc('files.list')).meta.files instanceof Array, true);
      assert.equal(await download(peer, state.fileId), state.sha256);
      const resumed = await peer.rpc('upload.init', { transferId: state.transferId, name: state.name + '-resume.bin', size: bytes.length, sha256: state.sha256 });
      assert.equal(resumed.meta.offset, CHUNK, 'Confirmed upload offset was not preserved');
      const fileId = await finish(peer, state.transferId, bytes, CHUNK);
      assert.equal(await download(peer, fileId), state.sha256);
      const admin = await login('admin'); assert.equal((await admin.rpc('audit.verify', { checkpoint: state.checkpoint })).meta.ok, true);
      checks.push('Generated accounts and completed file survive restart', 'Partial upload resumes at the durable offset; final SHA-256 matches', 'Audit history matches the checkpoint saved before restart');
    }
    assert.equal((await peer.rpc('hello')).meta.connection, connection);
    checks.push('The WSS connection is reused across file operations');
    return { phase, ok: true, checks };
  } finally { for (const peer of peers) peer.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [phase, directory, origin = 'https://localhost:18443'] = process.argv.slice(2);
  assert.ok(phase === 'seed' || phase === 'resume', 'Expected seed or resume'); assert.ok(directory, 'Expected a private runtime directory');
  const result = await checkContainer({ phase, origin, ca: readFileSync(join(directory, 'ca.crt')), accounts: JSON.parse(readFileSync(join(directory, 'accounts.json'), 'utf8')), statePath: join(directory, 'state.json') });
  mkdirSync('reports', { recursive: true }); writeFileSync(`reports/container-${phase}.json`, JSON.stringify({ created: new Date().toISOString(), ...result }, null, 2));
  for (const check of result.checks) console.log('PASS ' + check);
}
