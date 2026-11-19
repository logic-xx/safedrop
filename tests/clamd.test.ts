import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer,type Socket} from 'node:net';
import {once} from 'node:events';
import {mkdir,mkdtemp,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {ClamdEngine,clamdVersion} from '../server/clamd.ts';
import {digest} from '../server/store.ts';
const ctime=(time=Date.now())=>new Date(time).toUTCString().replace(/^(\w+), (\d+) (\w+) (\d+) (.*) GMT$/,'$1 $3 $2 $5 $4');
const version=()=>`ClamAV 1.5.5/30000/${ctime()}`;
async function daemon(verdict:string|null='stream: OK',engine=version()){
 const sockets=new Set<Socket>(),streams:Buffer[]=[];
 const server=createServer(socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));let input=Buffer.alloc(0),stream=false;const chunks:Buffer[]=[];
  socket.on('data',raw=>{input=Buffer.concat([input,raw]);if(!stream){const end=input.indexOf(0);if(end<0)return;const command=input.subarray(0,end).toString();input=input.subarray(end+1);if(command==='zVERSION'){socket.end(engine+'\0');return;}assert.equal(command,'zINSTREAM');stream=true;}
   while(input.length>=4){const size=input.readUInt32BE(0);if(input.length<4+size)return;const chunk=input.subarray(4,4+size);input=input.subarray(4+size);if(size===0){streams.push(Buffer.concat(chunks));if(verdict!==null){const reply=Buffer.from(verdict+'\0');socket.write(reply.subarray(0,3));setImmediate(()=>socket.end(reply.subarray(3)));}return;}chunks.push(chunk);}
  });
 });server.listen(0,'127.0.0.1');await once(server,'listening');
 return {streams,port:(server.address() as {port:number}).port,async close(){for(const socket of sockets)socket.destroy();await new Promise<void>(yes=>server.close(()=>yes()));}};
}
async function source(bytes=Buffer.alloc(0)) {await mkdir('tmp',{recursive:true});const root=await mkdtemp(resolve('tmp/clamd-transport-')),path=join(root,'sample.bin');await writeFile(path,bytes);return {path,size:bytes.length,sha256:digest(bytes)};}
test('ClamD protocol simulator: streams exact bytes, empty and multi-chunk objects; only exact OK passes',async()=>{
 for(const bytes of [Buffer.alloc(0),Buffer.alloc(200003,19)]){const d=await daemon();try{const input=await source(bytes),engine=new ClamdEngine({host:'127.0.0.1',port:d.port});const result=await engine.scan(input,new AbortController().signal);assert.equal(result.state,'clean');assert.equal(result.sha256,input.sha256);assert.equal(result.bytes,bytes.length);assert.deepEqual(d.streams,[bytes]);}finally{await d.close();}}
});
test('ClamD protocol simulator: threat, limits and encrypted content remain blocked',async()=>{
 for(const [reply,state,code] of [['stream: Test-Threat FOUND','quarantined',undefined],['stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND','error','SCAN_LIMIT'],['stream: Heuristics.Encrypted.Zip FOUND','error','SCAN_ENCRYPTED']] as const){const d=await daemon(reply);try{const result=await new ClamdEngine({host:'127.0.0.1',port:d.port}).scan(await source(Buffer.from('fixture')),new AbortController().signal);assert.equal(result.state,state);assert.equal(result.code,code);}finally{await d.close();}}
});
test('ClamD protocol simulator: malformed responses, timeout, abort, source mismatch and size never pass',async()=>{
 for(const reply of ['OK','stream: OK extra','stream: OK\0extra','x'.repeat(2000)]){const d=await daemon(reply);try{await assert.rejects(new ClamdEngine({host:'127.0.0.1',port:d.port}).scan(await source(),new AbortController().signal),/SCAN_ENGINE_INVALID/);}finally{await d.close();}}
 const d=await daemon(null);try{await assert.rejects(new ClamdEngine({host:'127.0.0.1',port:d.port,timeoutMs:100}).scan(await source(),new AbortController().signal),/SCAN_TIMEOUT/);const abort=new AbortController();const task=new ClamdEngine({host:'127.0.0.1',port:d.port}).scan(await source(),abort.signal);setTimeout(()=>abort.abort(),50);await assert.rejects(task,/SCAN_INTERRUPTED/);}finally{await d.close();}
 const good=await daemon();try{const input=await source(Buffer.from('actual'));await assert.rejects(new ClamdEngine({host:'127.0.0.1',port:good.port}).scan({...input,sha256:digest('different')},new AbortController().signal),/SCAN_SOURCE_CHANGED/);await assert.rejects(new ClamdEngine({host:'127.0.0.1',port:good.port,maxBytes:1}).scan(input,new AbortController().signal),/SCAN_LIMIT/);}finally{await good.close();}
});
test('ClamD version policy rejects unpatched engine, absent/stale/future signatures and unsafe configuration',()=>{
 const now=Date.now(),age=72*3600000;assert.equal(clamdVersion(version(),age,now),version());
 for(const invalid of ['ClamAV 1.5.5','ClamAV 1.5.4/30000/'+ctime(now),'ClamAV 1.5.5/30000/'+ctime(now-age-1000),'ClamAV 1.5.5/30000/'+ctime(now+7200000)])assert.throws(()=>clamdVersion(invalid,age,now),/SCAN_ENGINE_INVALID|SCAN_ENGINE_OUTDATED|SCAN_DATABASE_STALE/);
 for(const options of [{host:''},{host:'localhost',port:0},{host:'localhost',timeoutMs:0},{host:'localhost',maxDatabaseAgeMs:0},{host:'localhost',maxBytes:0}])assert.throws(()=>new ClamdEngine(options),/SCAN_CONFIGURATION_INVALID/);
});
