import {test} from 'node:test';
import assert from 'node:assert/strict';
import {runFileScanSuite} from './scans-suite.ts';
test('File scanning state and quarantine policy over real TLS/WSS with a controlled engine',{timeout:60000},async()=>{const results=await runFileScanSuite();assert.equal(results.length,21);assert.deepEqual(results.filter(r=>!r.ok),[]);});
