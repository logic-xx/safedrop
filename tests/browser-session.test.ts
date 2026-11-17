import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionRequests } from '../web/session-requests.ts';
import { encode, decode, type Frame } from '../shared/protocol.ts';
import { Client } from '../web/client.ts';

test('a delayed file chunk cannot be sent after switching accounts', async () => {
  let current = 'alice-session', calls = 0, finishRead!: (bytes: Uint8Array) => void;
  const fileRead = new Promise<Uint8Array>(resolve => { finishRead = resolve; });
  const guarded = sessionRequests({ async rpc() { calls++; return decode(encode(2, 1, { ok: true })); } }, current, () => current);
  const upload = (async () => { const bytes = await fileRead; return guarded.rpc('upload.chunk', { transferId: 'alice-transfer', offset: 0 }, bytes); })();
  current = 'bob-session'; finishRead(new Uint8Array([1, 2, 3]));
  await assert.rejects(upload, /TASK_SESSION_CHANGED/); assert.equal(calls, 0);
});

test('an old login response is discarded after logout and new login', async () => {
  let current = 'alice-session', finishResponse!: (frame: Frame) => void;
  const pendingResponse = new Promise<Frame>(resolve => { finishResponse = resolve; });
  const guarded = sessionRequests({ rpc: async () => pendingResponse }, current, () => current);
  const response = guarded.rpc('files.list');
  current = ''; current = 'bob-session';
  finishResponse(decode(encode(2, 1, { ok: true, files: [{ name: 'alice-private.txt' }] })));
  await assert.rejects(response, /TASK_SESSION_CHANGED/);
});

test('revoked tasks stay stopped even if the same user logs in again', async () => {
  let current = 'alice-session-1', calls = 0;
  const guarded = sessionRequests({ async rpc() { calls++; return decode(encode(2, 1, { ok: true })); } }, current, () => current);
  assert.equal((await guarded.rpc('ping')).meta.ok, true);
  current = ''; await assert.rejects(guarded.rpc('upload.init'), /TASK_SESSION_CHANGED/);
  current = 'alice-session-2'; await assert.rejects(guarded.rpc('upload.chunk'), /TASK_SESSION_CHANGED/);
  assert.equal(calls, 1);
});

test('a late socket close or response cannot affect a new login connection', async () => {
  class Socket {
    static OPEN = 1;
    static instances: Socket[] = [];
    readyState = 0; binaryType = ''; sent: Uint8Array[] = [];
    onopen?: () => void; onclose?: (event: { code: number }) => void; onerror?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor(_url: string) { Socket.instances.push(this); }
    open() { this.readyState = 1; this.onopen?.(); }
    send(bytes: Uint8Array) { this.sent.push(bytes); }
    close(_code?: number) { this.readyState = 2; }
    finishClose() { this.readyState = 3; this.onclose?.({ code: 1000 }); }
    respond(frame: Uint8Array) { this.onmessage?.({ data: new Uint8Array(frame).buffer }); }
  }
  const oldLocation = Object.getOwnPropertyDescriptor(globalThis, 'location');
  const oldSocket = Object.getOwnPropertyDescriptor(globalThis, 'WebSocket');
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { protocol: 'https:', host: 'localhost:18443' } });
  Object.defineProperty(globalThis, 'WebSocket', { configurable: true, value: Socket });
  const client = new Client(); let lost = 0; client.onLost = () => { lost++; };
  try {
    const first = client.connect(), previous = Socket.instances[0]; previous.open(); await first;
    const staleRequest = client.rpc('files.list'); await Promise.resolve();
    const rejected = assert.rejects(staleRequest, /CONNECTION_CLOSED/); client.disconnect(); await rejected;
    const next = client.connect(), current = Socket.instances[1]; current.open(); await next;
    const pending = client.rpc('ping'); await Promise.resolve();
    const requestId = decode(current.sent[0]).requestId;
    previous.finishClose(); previous.respond(encode(2, requestId, { ok: true, account: 'alice' }));
    assert.equal(lost, 1); assert.equal(client.ws, current);
    current.respond(encode(2, requestId, { ok: true, account: 'bob' }));
    assert.equal((await pending).meta.account, 'bob');
  } finally {
    client.stop();
    if (oldLocation) Object.defineProperty(globalThis, 'location', oldLocation); else Reflect.deleteProperty(globalThis, 'location');
    if (oldSocket) Object.defineProperty(globalThis, 'WebSocket', oldSocket); else Reflect.deleteProperty(globalThis, 'WebSocket');
  }
});
