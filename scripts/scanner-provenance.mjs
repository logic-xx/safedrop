// Runs inside the scanner image. ASCII-only for Windows PowerShell 5.1 stdin.
import {readFile,readlink,lstat,readdir} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
const manifest=JSON.parse(await readFile('/scanner/vendor-manifest.json','utf8'));
assert.equal(process.platform+'/'+process.arch,manifest.platform);
const files=[],symlinks=[];
for(const expected of manifest.files){
 assert.equal((await lstat(expected.path)).isFile(),true,'VENDOR_FILE_NOT_REGULAR');
 const hash=createHash('sha256');for await(const chunk of createReadStream(expected.path))hash.update(chunk);
 const sha256=hash.digest('hex');assert.equal(sha256,expected.sha256,'VENDOR_BINARY_HASH_MISMATCH:'+expected.path);files.push({path:expected.path,sha256});
}
for(const expected of manifest.symlinks){assert.equal((await lstat(expected.path)).isSymbolicLink(),true);const target=await readlink(expected.path);assert.equal(target,expected.target,'VENDOR_LIBRARY_LINK_MISMATCH');symlinks.push({path:expected.path,target});}
const expectedLibraries=[...files,...symlinks].map(f=>f.path).filter(p=>p.startsWith('/usr/local/lib/')).map(p=>p.slice('/usr/local/lib/'.length)).sort();
assert.deepEqual((await readdir('/usr/local/lib')).sort(),expectedLibraries,'UNEXPECTED_VENDOR_LIBRARY');
const engine=execFileSync('/usr/local/sbin/clamd',['--config-file=/scanner/clamd.conf','--version'],{encoding:'utf8'}).trim();
assert.ok(engine.startsWith('ClamAV '+manifest.version+'/'),'VENDOR_VERSION_MISMATCH');
console.log(JSON.stringify({ok:true,platform:process.platform+'/'+process.arch,engine,archiveSha256:manifest.archive.sha256,manifestSha256:createHash('sha256').update(JSON.stringify(manifest)).digest('hex'),files,symlinks}));
