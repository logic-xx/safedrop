import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { WebSocket } from 'ws';
import { createApp } from '../server/app.ts';
import { CHUNK, MAX_META } from '../shared/protocol.ts';
import { certificates } from '../scripts/certificates.ts';
import { Peer } from './suite.ts';

test('admin reports use bounded JSON payloads above the metadata limit', { timeout: 30000 }, async () => {
  mkdirSync('tmp', { recursive: true }); const root = mkdtempSync(resolve('tmp/report-')); certificates(join(root, 'tls'));
  const reportPath = join(root, 'report.json'), password = randomBytes(24).toString('base64url');
  const app = createApp({ root: join(root, 'data'), origin: 'https://localhost', reportPath,
    tls: { cert: readFileSync(join(root, 'tls/server.crt')), key: readFileSync(join(root, 'tls/server.key')) } });
  try {
    await app.store.addUser('admin', password, 'admin'); await app.store.addUser('reader', password);
    app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening');
    const connect = async () => {
      const ws = new WebSocket(`wss://127.0.0.1:${(app.server.address() as { port: number }).port}/ws`, {
        ca: readFileSync(join(root, 'tls/ca.crt')), rejectUnauthorized: true, headers: { Origin: 'https://localhost' }
      });
      await once(ws, 'open'); return new Peer(ws);
    };
    const admin = await connect(), reader = await connect();
    await assert.rejects(admin.rpc('report.latest'), /AUTH_REQUIRED/);
    await admin.rpc('auth.password', { name: 'admin', password }); await reader.rpc('auth.password', { name: 'reader', password });
    assert.equal((await admin.rpc('report.latest')).meta.report, null);
    const report = { created: new Date().toISOString(), passed: 109, results: Array.from({ length: 109 }, (_, i) => ({ name: `场景 ${i}`, ok: true, detail: '全局预算、维护及隔离恢复验证。'.repeat(5) })) };
    writeFileSync(reportPath, JSON.stringify(report)); assert.ok(readFileSync(reportPath).length > MAX_META);
    await assert.rejects(reader.rpc('report.latest'), /FORBIDDEN/);
    const response = await admin.rpc('report.latest');
    assert.equal(response.meta.reportEncoding, 'json'); assert.ok(Buffer.byteLength(JSON.stringify(response.meta)) < MAX_META);
    assert.deepEqual(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(response.payload)), report);
    const boundary = JSON.stringify({ padding: '' }); writeFileSync(reportPath, JSON.stringify({ padding: 'x'.repeat(CHUNK - boundary.length) }));
    assert.equal((await admin.rpc('report.latest')).payload.length, CHUNK);
    writeFileSync(reportPath, Buffer.alloc(CHUNK + 1)); await assert.rejects(admin.rpc('report.latest'), /REPORT_TOO_LARGE/);
    assert.equal((await admin.rpc('ping')).meta.ok, true);
  } finally { await app.close(); }
});
