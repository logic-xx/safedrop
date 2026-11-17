import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runMaintenanceSuite } from './maintenance-suite.ts';
test('global resource budgets, safe maintenance, consistent backup and isolated restore', { timeout: 120000 }, async t => {
  const results = await runMaintenanceSuite(r => t.diagnostic(`${r.ok ? 'PASS' : 'FAIL'} ${r.name}: ${r.detail}`));
  assert.equal(results.filter(r => r.ok).length, results.length);
});
