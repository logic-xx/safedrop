import {writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
// Official release digest; no credentials, package repositories or floating versions.
const expected='fff17fb1f8917d1ea1308c9736dabe376077458aba000a5dadcce7193a8c538c';
const response=await fetch('https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.5/clamav-1.5.5.linux.x86_64.deb',{signal:AbortSignal.timeout(300000)});
assert.equal(response.ok,true,'CLAMAV_VENDOR_DOWNLOAD_FAILED');const bytes=Buffer.from(await response.arrayBuffer());
assert.equal(createHash('sha256').update(bytes).digest('hex'),expected,'CLAMAV_VENDOR_HASH_MISMATCH');await writeFile('/vendor.deb',bytes);
