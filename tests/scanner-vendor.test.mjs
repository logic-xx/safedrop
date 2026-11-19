import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {mkdir,mkdtemp,writeFile,readFile,access,stat,symlink} from 'node:fs/promises';
import {setTimeout as pause} from 'node:timers/promises';
import {resolve,join} from 'node:path';
import {createHash} from 'node:crypto';
import {prepareVendor} from '../scripts/prepare-scanner-vendor.mjs';
import {downloadVendor,verifyVendor} from '../deploy/scanner/vendor-artifact.mjs';
const expected=bytes=>({bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),url:'http://127.0.0.1/fixture'});
const root=async()=>{await mkdir('tmp',{recursive:true});return mkdtemp(resolve('tmp/scanner-vendor-'));};
test('Vendor cache reuses a verified public source and then avoids all network; rejects unknown context files',async()=>{
 const dir=await root(),source=join(dir,'source.deb'),context=join(dir,'context'),bytes=Buffer.from('controlled public package fixture');await writeFile(source,bytes);const e=expected(bytes),downloadOptions={fetcher:()=>{throw Error('NETWORK_MUST_NOT_BE_USED');}};
 assert.equal((await prepareVendor(context,{source,expected:e,downloadOptions})).from,'existing-local-package');assert.deepEqual(await readFile(join(context,'vendor.deb')),bytes);assert.equal((await prepareVendor(context,{expected:e,downloadOptions})).from,'cache');
 const interrupted=join(dir,'interrupted');await mkdir(interrupted);await writeFile(join(interrupted,'vendor.deb.partial'),'old incomplete public download');await prepareVendor(interrupted,{source,expected:e,downloadOptions});assert.deepEqual(await readFile(join(interrupted,'vendor.deb')),bytes);await assert.rejects(access(join(interrupted,'vendor.deb.partial')));
 await writeFile(join(interrupted,'vendor.deb.partial'),'unexpected leftover');await assert.rejects(prepareVendor(interrupted,{expected:e}),/VENDOR_CONTEXT_NOT_READY/);
 await writeFile(join(context,'accounts.json'),'private context must never be exposed');await assert.rejects(prepareVendor(context,{expected:e}),/UNEXPECTED_VENDOR_CONTEXT_FILE/);
});
test('Vendor download resumes a real interrupted HTTP response with validated Range and final digest',async()=>{
 const dir=await root(),target=join(dir,'vendor.deb'),bytes=Buffer.alloc(128*1024,41),e=expected(bytes);let calls=0,range;
 const server=createServer((req,res)=>{calls++;if(calls===1){res.writeHead(200,{'content-length':bytes.length});res.write(bytes.subarray(0,32768));void(async()=>{for(let i=0;i<200;i++){if(await stat(target+'.partial').then(s=>s.size>0,()=>false))break;await pause(10);}res.destroy();})();}else{range=req.headers.range;const offset=Number(/^bytes=(\d+)-$/.exec(range??'')?.[1]);if(!(offset>0)){res.writeHead(416).end();return;}res.writeHead(206,{'content-range':`bytes ${offset}-${bytes.length-1}/${bytes.length}`});res.end(bytes.subarray(offset));}});server.listen(0,'127.0.0.1');await once(server,'listening');e.url=`http://127.0.0.1:${server.address().port}/fixture`;
 try{await downloadVendor(target,e,{timeoutMs:5000,attempts:2});assert.equal(calls,2);assert.match(range,/^bytes=\d+-$/);assert.deepEqual(await readFile(target),bytes);await assert.rejects(access(target+'.partial'));}finally{server.closeAllConnections();await new Promise(yes=>server.close(yes));}
});
test('Vendor tampering, malformed Range and wrong bytes never publish a ready archive',async()=>{
 const dir=await root(),target=join(dir,'vendor.deb'),bytes=Buffer.from('expected bytes'),e=expected(bytes);await writeFile(target+'.partial',bytes.subarray(0,2));
 await assert.rejects(downloadVendor(target,e,{attempts:1,fetcher:async()=>new Response(bytes.subarray(2),{status:206,headers:{'content-range':`bytes 0-${bytes.length-1}/${bytes.length}`}})}),/RANGE_MISMATCH/);await assert.rejects(access(target));
 const other=join(dir,'other.deb');await assert.rejects(downloadVendor(other,e,{attempts:1,fetcher:async()=>new Response(Buffer.alloc(bytes.length))}),/HASH_MISMATCH/);await assert.rejects(access(other));
 const restarted=join(dir,'restarted.deb');await writeFile(restarted+'.partial',bytes.subarray(0,2));await downloadVendor(restarted,e,{attempts:1,fetcher:async()=>new Response(bytes)});assert.deepEqual(await readFile(restarted),bytes);
 const context=join(dir,'context');await mkdir(context);await writeFile(join(context,'vendor.deb'),Buffer.alloc(bytes.length));await assert.rejects(prepareVendor(context,{expected:e}),/HASH_MISMATCH/);await assert.rejects(verifyVendor(target+'.partial',e),/SIZE_MISMATCH/);
 if(process.platform==='linux'){const link=join(dir,'linked.deb');await symlink(target+'.partial',link);await assert.rejects(verifyVendor(link,e),/NOT_REGULAR/);const linkedContext=join(dir,'linked-context');await mkdir(linkedContext);await symlink(target+'.partial',join(linkedContext,'.dockerignore'));await assert.rejects(prepareVendor(linkedContext,{expected:e}),/VENDOR_IGNORE_NOT_REGULAR/);}
});
test('Vendor network timeouts have bounded retries and preserve the verified archive requirement',async()=>{
 const dir=await root(),target=join(dir,'vendor.deb'),e=expected(Buffer.from('fixture'));let calls=0;
 const keepAlive=setInterval(()=>{},1000);
 try{await assert.rejects(downloadVendor(target,e,{attempts:2,timeoutMs:20,fetcher:async(_url,{signal})=>{calls++;return new Promise((_yes,no)=>signal.addEventListener('abort',()=>no(signal.reason),{once:true}));}}),/timeout/i);assert.equal(calls,2);await assert.rejects(access(target));}finally{clearInterval(keepAlive);}
});
