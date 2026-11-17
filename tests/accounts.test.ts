import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runAccountSuite } from './accounts-suite.ts';
test('account policy, invitation concurrency, revocation and legacy migration', { timeout: 90000 }, async t => {
  const results = await runAccountSuite(r => t.diagnostic(`${r.ok ? 'PASS' : 'FAIL'} ${r.name}: ${r.detail}`));
  assert.equal(results.filter(r => r.ok).length, results.length);
});
