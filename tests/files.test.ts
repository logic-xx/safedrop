import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runFileSuite } from './files-suite.ts';
test('file management, quota accounting, failure recovery and concurrent access', { timeout: 90000 }, async t => {
  const results = await runFileSuite(r => t.diagnostic(`${r.ok ? 'PASS' : 'FAIL'} ${r.name}: ${r.detail}`));
  assert.equal(results.filter(r => r.ok).length, results.length);
});
