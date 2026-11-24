import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { get } from 'node:https';
import { setTimeout as pause } from 'node:timers/promises';
import { WebSocket } from 'ws';
import { CHUNK, decode, encode } from '../shared/protocol.ts';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

async function health(origin, ca) {
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        const request = get(`${origin}/health`, { ca, timeout: 2000 }, response => {
          const chunks = [];
          response.on('data', chunk => chunks.push(chunk));
          response.on('error', reject);
          response.on('end', () => {
            try {
              assert.equal(response.statusCode, 200);
              assert.deepEqual(JSON.parse(Buffer.concat(chunks)), { status: 'ok', protocol: 'SFT/1' });
              resolve();
            } catch (error) { reject(error); }
          });
        });
        request.on('timeout', () => request.destroy(new Error('HTTPS health check timed out')));
        request.on('error', reject);
      });
      return;
    } catch (error) {
      if (attempt === 29) throw error;
      await pause(500);
    }
  }
}

export async function probeOfflineImages({ origin, ca, password }) {
  await health(origin, ca);
  const ws = new WebSocket(`${origin.replace('https:', 'wss:')}/ws`, {
    ca, rejectUnauthorized: true, origin, handshakeTimeout: 5000,
  });
  ws.on('error', () => {});
  let sequence = 0;
  function rpc(op, meta = {}, data) {
    const requestId = ++sequence;
    return new Promise((resolve, reject) => {
      function finish(error, reply) {
        clearTimeout(timer);
        ws.off('message', receive);
        ws.off('close', closed);
        if (error) reject(error); else resolve(reply);
      }
      function receive(bytes) {
        try {
          const reply = decode(bytes);
          assert.equal(reply.type, 2);
          assert.equal(reply.requestId, requestId);
          if (reply.meta.ok !== true) throw new Error(`${op}: ${reply.meta.code}`);
          finish(null, reply);
        } catch (error) { finish(error); }
      }
      const closed = () => finish(new Error(`Connection closed during ${op}`));
      const timer = setTimeout(() => finish(new Error(`Timed out during ${op}`)), 10000);
      ws.once('close', closed);
      ws.on('message', receive);
      ws.send(encode(1, requestId, { op, ...meta }, data), error => { if (error) finish(error); });
    });
  }

  try {
    await once(ws, 'open');
    await rpc('auth.password', { name: 'alice', password });
    const bytes = Buffer.alloc(CHUNK + 37, 'SafeDrop offline distribution harmless verification sample.\n');
    const hash = sha256(bytes);
    const started = await rpc('upload.init', { name: 'offline-verification.txt', size: bytes.length, sha256: hash });
    const transferId = started.meta.id;
    assert.equal(started.meta.offset, 0);
    for (let offset = 0; offset < bytes.length; offset += CHUNK) {
      const part = bytes.subarray(offset, offset + CHUNK);
      const ack = await rpc('upload.chunk', { transferId, offset }, part);
      assert.equal(ack.meta.offset, offset + part.length);
    }
    const published = await rpc('upload.finish', { transferId });
    assert.equal(published.meta.sha256, hash);
    const fileId = published.meta.fileId;
    const deadline = Date.now() + 100000;
    let scan;
    do {
      scan = (await rpc('files.scan.status', { fileId })).meta.scan;
      if (scan.state === 'clean') break;
      assert.ok(['pending', 'scanning'].includes(scan.state), `Scan did not pass: ${scan.state} ${scan.code}`);
      await pause(500);
    } while (Date.now() < deadline);
    assert.equal(scan.state, 'clean', 'Timed out waiting for the real scan result');

    const info = (await rpc('download.init', { fileId })).meta;
    assert.equal(info.size, bytes.length);
    assert.equal(info.sha256, hash);
    const parts = [];
    for (let offset = 0; offset < bytes.length; offset += CHUNK) {
      const reply = await rpc('download.chunk', { fileId, offset });
      const next = Math.min(offset + CHUNK, bytes.length);
      assert.equal(reply.meta.offset, offset);
      assert.equal(reply.meta.next, next);
      assert.equal(reply.meta.eof, next === bytes.length);
      parts.push(Buffer.from(reply.payload));
    }
    assert.deepEqual(Buffer.concat(parts), bytes);
    await rpc('auth.logout');
    return { https: 200, wss: 'SFT/1', uploadedBytes: bytes.length, scan: 'clean', downloadedBytes: bytes.length, sha256: hash };
  } finally {
    ws.terminate();
  }
}
