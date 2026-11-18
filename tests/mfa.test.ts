import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runMfaSuite } from './mfa-suite.ts';

test('administrator MFA, recovery boundaries, replay protection and persistence', { timeout: 120000 }, async t => {
  const results = await runMfaSuite(r => t.diagnostic(`${r.ok ? 'PASS' : 'FAIL'} ${r.name}: ${r.detail}`));
  assert.equal(results.filter(r => r.ok).length, results.length);
});
