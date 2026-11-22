import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runEventsSuite } from './events-suite.ts';

test('real TLS/WSS event ranges, visibility, snapshot pagination and response budgets', {timeout:60000},async t=>{
  const results=await runEventsSuite(r=>t.diagnostic(`${r.ok?'PASS':'FAIL'} ${r.name}: ${r.detail}`));
  assert.equal(results.length,7);assert.equal(results.filter(r=>r.ok).length,results.length);
});
