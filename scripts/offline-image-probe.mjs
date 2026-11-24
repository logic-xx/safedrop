import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rmdir, unlink, writeFile } from 'node:fs/promises';
import { get } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

export async function probeOfflineImages({ origin, ca, password, stale = false }) {
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
      if (!['pending', 'scanning'].includes(scan.state)) break;
      await pause(500);
    } while (Date.now() < deadline);
    if (stale) {
      assert.equal(scan.state, 'error');
      assert.equal(scan.code, 'SCAN_DATABASE_STALE');
      await assert.rejects(rpc('download.init', { fileId }), { message: 'download.init: FILE_SCAN_REQUIRED' });
      await assert.rejects(rpc('deliveries.create', { fileId, recipient: 'bob' }), { message: 'deliveries.create: FILE_SCAN_REQUIRED' });
      await rpc('auth.logout');
      return { https: 200, wss: 'SFT/1', uploadedBytes: bytes.length, scan: scan.code, download: 'denied', delivery: 'denied' };
    }
    assert.equal(scan.state, 'clean', `Scan did not pass: ${scan.state} ${scan.code}`);

    const folder = (await rpc('folders.create', { name: 'SafeDrop review folder' })).meta.folder;
    assert.deepEqual((await rpc('folders.list')).meta.folders, [folder]);
    assert.equal((await rpc('files.move', { fileId, folderId: folder.id })).meta.folderId, folder.id);
    const moved = (await rpc('files.list')).meta.files.find(file => file.id === fileId);
    assert.equal(moved.folderId, folder.id);
    assert.equal(moved.scan.state, 'clean');
    assert.equal(moved.sha256, hash);
    const info = (await rpc('download.init', { fileId, receipt: true })).meta;
    assert.equal(info.size, bytes.length);
    assert.equal(info.sha256, hash);
    assert.equal(typeof info.downloadId, 'string');
    const receipt = { downloadId: info.downloadId, size: bytes.length, sha256: hash, saveMode: 'file' };
    await assert.rejects(rpc('download.finish', receipt), { message: 'download.finish: INCOMPLETE_FILE' });
    const parts = [];
    for (let offset = 0; offset < bytes.length; offset += CHUNK) {
      const reply = await rpc('download.chunk', { fileId, offset, downloadId: info.downloadId });
      const next = Math.min(offset + CHUNK, bytes.length);
      assert.equal(reply.meta.offset, offset);
      assert.equal(reply.meta.next, next);
      assert.equal(reply.meta.eof, next === bytes.length);
      parts.push(Buffer.from(reply.payload));
    }
    const downloaded = Buffer.concat(parts);
    assert.deepEqual(downloaded, bytes);
    assert.equal(sha256(downloaded), hash);
    const downloadDirectory = await mkdtemp(join(tmpdir(), 'safedrop-download-'));
    const savedPath = join(downloadDirectory, 'offline-verification.txt');
    try {
      await writeFile(savedPath, downloaded, { flag: 'wx' });
      assert.equal(sha256(await readFile(savedPath)), hash);
      for (let attempt = 0; attempt < 2; attempt++) assert.equal((await rpc('download.finish', receipt)).meta.received, true);
    } finally {
      await unlink(savedPath).catch(error => { if (error.code !== 'ENOENT') throw error; });
      await rmdir(downloadDirectory);
    }
    const events = (await rpc('events.list')).meta.events.filter(event =>
      event.action === 'download.finish' && event.result === 'allowed' && event.detail.fileId === fileId);
    assert.equal(events.length, 1);
    assert.equal(events[0].detail.saveMode, 'file');
    assert.equal(events[0].detail.sha256, hash);
    assert.equal((await rpc('files.move', { fileId, folderId: null })).meta.folderId, null);
    assert.equal((await rpc('files.list')).meta.files.find(file => file.id === fileId).folderId, null);
    await rpc('auth.logout');
    return { https: 200, wss: 'SFT/1', uploadedBytes: bytes.length, scan: 'clean', engine: scan.engine, downloadedBytes: downloaded.length, sha256: hash, folderMove: 'into-folder-and-back', receipt: { replayAcknowledged: true, auditRecords: events.length, localSha256Matched: true } };
  } finally {
    ws.terminate();
  }
}
