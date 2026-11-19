import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createConnection} from 'node:net';
import {ClamdEngine} from '../server/clamd.ts';
import {digest} from '../server/store.ts';
import {eicarSample,zipSample,encryptedBenignZip} from './scan-samples.mjs';

const configured=Boolean(process.env.CLAMD_REAL_HOST&&process.env.CLAMD_REAL_PORT);
test('Real ClamAV 1.5.5 and official signatures: clean, EICAR, archive, encrypted and recursion limit',{skip:!configured,timeout:120000},async()=>{
 const host=process.env.CLAMD_REAL_HOST,port=Number(process.env.CLAMD_REAL_PORT),engine=new ClamdEngine({host,port});
 await mkdir('tmp',{recursive:true});const root=await mkdtemp(resolve('tmp/scanner-real-')),checks=[];
 const scanFile=async(bytes,name)=>{const path=join(root,name);await writeFile(path,bytes);return engine.scan({path,size:bytes.length,sha256:digest(bytes)},new AbortController().signal);};
 const stream=bytes=>new Promise((yes,no)=>{const socket=createConnection({host,port});let reply='';const timer=setTimeout(()=>{socket.destroy();no(Error('REAL_SCAN_TIMEOUT'));},90000);socket.on('error',error=>{clearTimeout(timer);no(error);});socket.on('connect',()=>{const length=Buffer.alloc(4);length.writeUInt32BE(bytes.length);socket.write(Buffer.concat([Buffer.from('zINSTREAM\0'),length,bytes,Buffer.alloc(4)]));});socket.on('data',chunk=>{reply+=chunk.toString();if(reply.length>1024){clearTimeout(timer);socket.destroy();no(Error('REAL_SCAN_INVALID'));}else if(reply.includes('\0')){clearTimeout(timer);socket.destroy();yes(reply.replace(/\0$/,''));}});});
 const clean=await scanFile(Buffer.from('SafeDrop harmless real scanner test\n'),'clean.txt');assert.equal(clean.state,'clean');checks.push('harmless source file passes the production stream client');
 assert.equal((await scanFile(Buffer.alloc(0),'empty.txt')).state,'clean');checks.push('zero byte source passes with its exact hash');
 const threat=await stream(eicarSample());assert.match(threat,/^stream: .+ FOUND$/);checks.push('memory-only EICAR is detected by the actual engine');
 assert.match(await stream(zipSample(eicarSample())),/^stream: .+ FOUND$/);checks.push('archived memory-only EICAR is detected');
 const encrypted=await scanFile(encryptedBenignZip(),'encrypted.zip');assert.equal(encrypted.state,'error');assert.equal(encrypted.code,'SCAN_ENCRYPTED');checks.push('a genuine encrypted archive of harmless text cannot be marked clean');
 let nested=Buffer.from('SafeDrop harmless nested archive fixture\n');for(let depth=0;depth<20;depth++)nested=zipSample(nested,depth?'nested.zip':'innocuous.txt');
 const limited=await scanFile(nested,'nested.zip');assert.equal(limited.state,'error');assert.equal(limited.code,'SCAN_LIMIT');checks.push('small deeply nested harmless archives exceed the actual recursion policy');
 if(process.env.CLAMD_REAL_REPORT)await writeFile(process.env.CLAMD_REAL_REPORT,JSON.stringify({created:new Date().toISOString(),ok:true,scope:'actual local ClamAV and official signatures; direct engine detection, not container API acceptance',engine:clean.engine,checks,threat,encrypted:encrypted.code,limit:limited.code,persistentEicarSourceCreated:false,daemonMayUsePrivateTemporaryFiles:true,originalDataChanged:false},null,2));
});
