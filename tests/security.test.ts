import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSuite } from './suite.ts';
import { encode, decode } from '../shared/protocol.ts';
import { Bandwidth } from '../server/limits.ts';
import { webcrypto, createPublicKey, verify, createHash } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
test('browser crypto algorithms interoperate with server verification', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const message = new TextEncoder().encode('SFT/1 认证互操作');
  const jwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, message);
  assert.equal(verify('sha256', message, { key: createPublicKey({ key: { ...jwk }, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, new Uint8Array(sig)), true);
  assert.equal(Buffer.from(sha256(message)).toString('hex'), createHash('sha256').update(message).digest('hex'));
});
test('protocol rejects declared lengths that exceed the frame', () => { const b = encode(1, 1, { op: 'ping' }); new DataView(b.buffer).setUint32(20, 999); assert.throws(() => decode(b)); });
test('bandwidth reservations aggregate across tasks of the same user', async () => {
  const b = new Bandwidth(1000, 4000), signal = new AbortController().signal, at = performance.now();
  await Promise.all([b.take('same', 'normal', 100, signal), b.take('same', 'normal', 100, signal), b.take('same', 'normal', 100, signal)]);
  assert.ok(performance.now() - at >= 175); const independent = performance.now(); await b.take('another', 'normal', 100, signal); assert.ok(performance.now() - independent < 100);
});
test('real TLS/WebSocket security and transfer integration suite', { timeout: 90000 }, async t => { const report = await runSuite(r => t.diagnostic(`${r.ok ? 'PASS' : 'FAIL'} ${r.name}: ${r.detail}`)); assert.equal(report.passed, report.results.length); });
