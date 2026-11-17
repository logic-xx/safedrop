import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDeliverySuite } from './deliveries-suite.ts';
test('controlled delivery permissions, revocation, concurrency and migration', { timeout: 90000 }, async t => {
  const results = await runDeliverySuite(r => t.diagnostic(`${r.ok ? 'PASS' : 'FAIL'} ${r.name}: ${r.detail}`));
  assert.equal(results.filter(r => r.ok).length, results.length);
});
