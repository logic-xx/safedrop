import { test } from 'node:test';
import assert from 'node:assert/strict';
import { downloadReference, downloadAccess } from '../web/download-reference.ts';
test('received download requests and checkpoints bind to the exact delivery; owner keys stay compatible', () => {
  const owner = { id: 'same-file' }, old = { id: 'same-file', deliveryId: 'old-grant' }, current = { id: 'same-file', deliveryId: 'new-grant' };
  assert.equal(downloadReference(owner), 'same-file'); assert.notEqual(downloadReference(old), downloadReference(current)); assert.notEqual(downloadReference(owner), downloadReference(old));
  assert.deepEqual(downloadAccess(owner), { fileId: 'same-file' }); assert.deepEqual(downloadAccess(current), { fileId: 'same-file', deliveryId: 'new-grant' });
});
