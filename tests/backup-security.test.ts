import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runBackupEncryptionSuite } from './backup-encryption-suite.ts';
test('Encrypted backup API, key lifecycle, retained data and legacy compatibility', { timeout: 120000 }, async t => {
  const results = await runBackupEncryptionSuite(result => t.diagnostic(`${result.ok ? 'PASS' : 'FAIL'} ${result.name}: ${result.detail}`));
  assert.equal(results.length, 8); assert.equal(results.filter(result => result.ok).length, results.length);
});
