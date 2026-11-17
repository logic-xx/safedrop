import assert from 'node:assert/strict';
import { randomBytes, generateKeyPairSync, sign } from 'node:crypto';
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
type AccountState = { userId: string; name: string; password: string; token: string; keyId: string };
type State = { seed: string; name: string; sha256: string; fileId: string; transferId: string; checkpoint: Checkpoint; account: AccountState; quota: Metadata };
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
  const get = (path: string, servername = 'localhost') => new Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; hstsCount: number; body: string }>((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: target.port || 443, servername, ca, path, headers: { Host: target.host }, timeout: 2000, rejectUnauthorized: true }, res => {
      let body = ''; res.on('data', data => { body += data; });
      res.on('error', reject); res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, hstsCount: res.rawHeaders.filter((name, index) => index % 2 === 0 && name.toLowerCase() === 'strict-transport-security').length, body }));
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
  const findUser = async (admin: Peer, name: string) => {
    for (let offset = 0; offset <= 10000; offset += 12) {
      const users = (await admin.rpc('users.list', { offset })).meta.users as Array<{ id: string; name: string; disabled: number }>;
      const user = users.find(u => u.name === name); if (user) return user; if (users.length < 12) break;
    }
    throw new Error('Account check user not found');
  };
  const fileManagementCheck = async (owner: Peer, outsider: Peer, suffix: string) => {
    const before = (await owner.rpc('storage.usage')).meta, bytes = randomBytes(73), name = 'file-check-' + suffix;
    const transferId = String((await owner.rpc('upload.init', { name: name + '.bin', size: bytes.length, sha256: digest(bytes) })).meta.id);
    assert.equal((await owner.rpc('storage.usage')).meta.reserved, Number(before.reserved) + bytes.length);
    const fileId = await finish(owner, transferId, bytes), renamed = name + '-改名.bin';
    const file = (await owner.rpc('files.rename', { fileId, name: renamed })).meta.file as Record<string, unknown>;
    assert.equal(file.id, fileId); assert.equal(file.name, renamed); assert.equal(file.sha256, digest(bytes));
    assert.equal((await owner.rpc('download.init', { fileId, offset: 17, prefixHash: digest(bytes.subarray(0, 17)) })).meta.name, renamed);
    assert.equal(digest((await owner.rpc('download.chunk', { fileId, offset: 17 })).payload), digest(bytes.subarray(17)));
    await assert.rejects(outsider.rpc('files.rename', { fileId, name: 'forbidden.bin' }), /NOT_FOUND/);
    await assert.rejects(outsider.rpc('files.delete', { fileId }), /NOT_FOUND/);
    assert.equal((await owner.rpc('storage.usage')).meta.used, Number(before.used) + bytes.length);
    await owner.rpc('files.delete', { fileId }); await assert.rejects(owner.rpc('download.init', { fileId }), /NOT_FOUND/);
    const partial = String((await owner.rpc('upload.init', { name: name + '-cancel.bin', size: bytes.length, sha256: digest(bytes) })).meta.id);
    await owner.rpc('upload.chunk', { transferId: partial, offset: 0 }, bytes.subarray(0, 17));
    await owner.rpc('upload.cancel', { transferId: partial });
    assert.deepEqual((await owner.rpc('storage.usage')).meta, before);
    checks.push('Rename preserves file identity/content and resumability; cross-user/admin mutations are denied', 'Permanent deletion and partial-upload cancellation restore exact server quota values');
  };
  const accountCheck = async (admin: Peer, suffix: string): Promise<AccountState> => {
    const policy = String((await admin.rpc('hello')).meta.registration); assert.ok(['invitation', 'closed'].includes(policy), 'Account policy module is missing');
    const name = 'check-' + suffix, password = randomBytes(24).toString('base64url'), oldPassword = randomBytes(24).toString('base64url');
    if (policy === 'closed') await admin.rpc('registration.set', { mode: 'invitation' });
    try {
      const token = String((await admin.rpc('invitations.create', { hours: 1 })).meta.token), peer = await connect();
      await peer.rpc('auth.register', { token, name, password: oldPassword });
      await assert.rejects(peer.rpc('auth.register', { token, name: name + '-replay', password: oldPassword }), /INVITATION_INVALID/);
      await peer.rpc('auth.password', { name, password: oldPassword });
      await assert.rejects(peer.rpc('users.disable', { userId: 'unknown' }), /FORBIDDEN/);
      const closed = once(peer.ws, 'close'); await peer.rpc('account.password', { password: oldPassword, newPassword: password }); await closed;
      const active = await connect(); await assert.rejects(active.rpc('auth.password', { name, password: oldPassword }), /INVALID_CREDENTIALS/);
      await active.rpc('auth.password', { name, password });
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const keyId = String((await active.rpc('keys.enroll', { password, label: 'container-account-check', jwk: pair.publicKey.export({ format: 'jwk' }) })).meta.keyId);
      await fileManagementCheck(active, admin, suffix);
      const keyed = await connect(), challenge = String((await keyed.rpc('auth.challenge', { name, keyId })).meta.message);
      await keyed.rpc('auth.prove', { signature: sign('sha256', Buffer.from(challenge), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64') });
      const user = await findUser(admin, name), closures = [active, keyed].map(p => once(p.ws, 'close'));
      await admin.rpc('users.disable', { userId: user.id }); await Promise.all(closures);
      const denied = await connect(); await assert.rejects(denied.rpc('auth.password', { name, password }), /INVALID_CREDENTIALS/);
      await assert.rejects(denied.rpc('auth.challenge', { name, keyId }), /INVALID_CREDENTIALS/);
      checks.push('Invitation registration/replay denial, ordinary-user admin denial, password rotation and all-session revocation', 'Disabled account rejects password/public-key authentication and closes both session types');
      return { userId: user.id, name, password, token, keyId };
    } finally { if (policy === 'closed') await admin.rpc('registration.set', { mode: 'closed' }); }
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
    assert.equal(page.hstsCount, 1, 'Expected exactly one HSTS response header');
    assert.equal(page.headers['strict-transport-security'], 'max-age=31536000', 'Expected a single valid HSTS policy');
    assert.equal(page.headers['x-content-type-options'], 'nosniff');
    await assert.rejects(get('/health', 'wrong-host.invalid'));
    checks.push('HTTPS certificate/hostname validation, Vue page and security headers (single HSTS policy)');
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
      await peer.rpc('files.rename', { fileId, name: name + '-renamed.bin' });
      assert.equal(await download(peer, fileId), sha256);
      const bob = await login('bob'); await assert.rejects(bob.rpc('download.init', { fileId, offset: 0 }), /NOT_FOUND/);
      const partial = await peer.rpc('upload.init', { name: name + '-resume.bin', size: bytes.length, sha256 });
      assert.equal((await peer.rpc('upload.chunk', { transferId: partial.meta.id, offset: 0 }, bytes.subarray(0, CHUNK))).meta.offset, CHUNK);
      const admin = await login('admin'), account = await accountCheck(admin, seed.slice(0, 12)), checkpoint = (await admin.rpc('audit.page')).meta.checkpoint as unknown as Checkpoint;
      // This ignored, private state contains only disposable check credentials, never print it.
      const quota = (await peer.rpc('storage.usage')).meta;
      const state: State = { seed, name, sha256, fileId, transferId: String(partial.meta.id), checkpoint, account, quota };
      writeFileSync(statePath, JSON.stringify(state, null, 2));
      checks.push('Upload/download SHA-256 and cross-user access denial', 'Persistent partial upload and independent audit checkpoint prepared');
    } else {
      const state: State = JSON.parse(readFileSync(statePath, 'utf8')), bytes = payload(state.seed);
      assert.equal((await peer.rpc('files.list')).meta.files instanceof Array, true);
      assert.deepEqual((await peer.rpc('storage.usage')).meta, state.quota);
      assert.equal(await download(peer, state.fileId), state.sha256);
      assert.equal((await peer.rpc('download.init', { fileId: state.fileId })).meta.name, state.name + '-renamed.bin');
      const resumed = await peer.rpc('upload.init', { transferId: state.transferId, name: state.name + '-resume.bin', size: bytes.length, sha256: state.sha256 });
      assert.equal(resumed.meta.offset, CHUNK, 'Confirmed upload offset was not preserved');
      const fileId = await finish(peer, state.transferId, bytes, CHUNK);
      const quota = (await peer.rpc('storage.usage')).meta;
      assert.equal(quota.used, Number(state.quota.used) + bytes.length); assert.equal(quota.reserved, Number(state.quota.reserved) - bytes.length); assert.equal(quota.available, state.quota.available);
      assert.equal(await download(peer, fileId), state.sha256);
      const admin = await login('admin'); assert.equal((await admin.rpc('audit.verify', { checkpoint: state.checkpoint })).meta.ok, true);
      const account = state.account; assert.ok(account, 'Expected version 3 account check state');
      const user = await findUser(admin, account.name); assert.equal(user.id, account.userId); assert.equal(user.disabled, 1);
      const denied = await connect(); await assert.rejects(denied.rpc('auth.password', { name: account.name, password: account.password }), /INVALID_CREDENTIALS/);
      await assert.rejects(denied.rpc('auth.challenge', { name: account.name, keyId: account.keyId }), /INVALID_CREDENTIALS/);
      if ((await admin.rpc('hello')).meta.registration === 'invitation') await assert.rejects(denied.rpc('auth.register', { token: account.token, name: account.name + '-again', password: account.password }), /INVITATION_INVALID/);
      checks.push('Disabled account, deleted key and consumed invitation stay invalid across restart');
      checks.push('Generated accounts, completed file, renamed filename and quota values survive restart', 'Partial upload resumes at the durable offset; final SHA-256 matches', 'Audit history matches the checkpoint saved before restart');
    }
    assert.equal((await peer.rpc('hello')).meta.connection, connection);
    checks.push('The WSS connection is reused across file operations');
    return { version: 4, phase, ok: true, checks };
  } finally { for (const peer of peers) peer.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [phase, directory, origin = 'https://localhost:18443'] = process.argv.slice(2);
  assert.ok(phase === 'seed' || phase === 'resume', 'Expected seed or resume'); assert.ok(directory, 'Expected a private runtime directory');
  const result = await checkContainer({ phase, origin, ca: readFileSync(join(directory, 'ca.crt')), accounts: JSON.parse(readFileSync(join(directory, 'accounts.json'), 'utf8')), statePath: join(directory, 'state.json') });
  mkdirSync('reports', { recursive: true }); writeFileSync(`reports/container-${phase}.json`, JSON.stringify({ created: new Date().toISOString(), ...result }, null, 2));
  for (const check of result.checks) console.log('PASS ' + check);
}
