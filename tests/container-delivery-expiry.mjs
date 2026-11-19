// ASCII stdin probe for the compiled runtime; only fresh temporary data is changed.
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {once} from 'node:events';
import {randomBytes,randomUUID} from 'node:crypto';
import {setTimeout as pause} from 'node:timers/promises';
import {WebSocket} from 'ws';
import {createApp} from './build/server/app.js';
import {ClamdEngine} from './build/server/clamd.js';
import {digest,Store} from './build/server/store.js';
import {verifyBackup,restoreBackup} from './build/server/backup.js';
import {changeBackupKeys} from './build/server/backup-keys.js';
import {encode,decode} from './build/shared/protocol.js';

const root=mkdtempSync(join(process.env.DELIVERY_PROBE_TMP??tmpdir(),'safedrop-expiry-'));
const password=randomBytes(24).toString('base64url'),checks=[];
let clock;
const config={root:join(root,'data'),origin:'http://localhost',scanner:new ClamdEngine({host:process.env.CLAMD_HOST??'scanner',port:Number(process.env.CLAMD_PORT??3310)}),deliveryClock:()=>clock??Date.now(),normalRate:64*1024**2,storage:{minFree:0,backupCount:10}};
let app=createApp(config);
const start=async()=>{app.server.listen(0,'127.0.0.1');await once(app.server,'listening');};
const login=async name=>{
 const ws=new WebSocket(`ws://127.0.0.1:${app.server.address().port}/ws`,{headers:{Origin:config.origin}});await once(ws,'open');ws.on('error',()=>{});let seq=0;
 const rpc=(op,meta={},payload)=>new Promise((yes,no)=>{const id=++seq,timer=setTimeout(()=>{ws.off('message',received);no(Error('EXPIRY_RPC_TIMEOUT:'+op));},8000);const received=raw=>{const f=decode(raw);if(f.requestId!==id)return;clearTimeout(timer);ws.off('message',received);f.meta.ok?yes(f):no(Error(op+':'+f.meta.code));};ws.on('message',received);ws.send(encode(1,id,{op,...meta},payload));});
 await rpc('auth.password',{name,password});return {rpc,ws};
};
try{
 await start();const ids={};for(const name of ['expiry-owner','expiry-reader','expiry-other','expiry-admin'])ids[name]=await app.store.addUser(name,password,name==='expiry-admin'?'admin':'user');
 let owner=await login('expiry-owner'),reader=await login('expiry-reader'),other=await login('expiry-other'),admin=await login('expiry-admin');
 const bytes=Buffer.from('SafeDrop harmless delivery expiry runtime probe.\n'),fileId=randomUUID();writeFileSync(join(config.root,'objects',fileId),bytes);
 app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)',fileId,ids['expiry-owner'],'expiry-probe.txt',bytes.length,digest(bytes),Date.now());await owner.rpc('files.scan',{fileId});
 for(let n=0;n<400&&app.scans.status(app.store.get('SELECT * FROM files WHERE id=?',fileId)).state!=='clean';n++)await pause(25);
 const verdict=app.scans.status(app.store.get('SELECT * FROM files WHERE id=?',fileId));assert.equal(verdict.state,'clean');assert.match(verdict.engine,/^ClamAV 1\.5\.5\//);
 const send=async(recipient='expiry-reader',hours=1)=>(await owner.rpc('deliveries.create',{fileId,recipient,hours})).meta;
 clock=Date.now();const old=await send();assert.equal(old.expires,clock+3600000);assert.deepEqual(Buffer.from((await reader.rpc('download.chunk',{fileId,deliveryId:old.deliveryId,offset:0})).payload),bytes);
 assert.equal((await send('expiry-reader',720)).expires,old.expires);await assert.rejects(owner.rpc('deliveries.create',{fileId,recipient:'expiry-other',hours:0}),/INVALID_DELIVERY_EXPIRY/);
 checks.push('finite server-derived deadlines and idempotent sends do not extend existing access');
 clock=old.expires;for(const [op,meta]of [['download.init',{}],['download.init',{offset:1,prefixHash:digest(bytes.subarray(0,1))}],['download.chunk',{offset:0}],['files.scan.status',{}]])await assert.rejects(reader.rpc(op,{fileId,deliveryId:old.deliveryId,...meta}),/DELIVERY_EXPIRED/);
 await assert.rejects(other.rpc('download.init',{fileId,deliveryId:old.deliveryId}),/NOT_FOUND/);assert.equal((await owner.rpc('download.chunk',{fileId,offset:0})).payload.length,bytes.length);
 checks.push('exact expiry denies initialization, resume, chunks and scan details while ownership stays valid');
 await send();clock=undefined;const waiting=await send();app.store.run('UPDATE deliveries SET expires=? WHERE id=?',Date.now()+500,waiting.deliveryId);app.bw.next.set(ids['expiry-reader'],performance.now()+5000);
 let entered=false,payload=0;const take=app.bw.take.bind(app.bw);app.bw.take=async(...args)=>{entered=true;return take(...args);};reader.ws.on('message',raw=>{payload+=decode(raw).payload.length;});
 const at=performance.now();await assert.rejects(reader.rpc('download.chunk',{fileId,deliveryId:waiting.deliveryId,offset:0}),/DELIVERY_EXPIRED/);assert.equal(entered,true);assert.ok(performance.now()-at<2500);assert.equal(payload,0);app.bw.take=take;app.bw.next.clear();
 checks.push('real deadline timer cancels bandwidth waiting without sending buffered content');
 const active=await send();assert.notEqual(active.deliveryId,waiting.deliveryId);await assert.rejects(reader.rpc('download.init',{fileId,deliveryId:old.deliveryId}),/DELIVERY_EXPIRED/);await assert.rejects(reader.rpc('download.init',{fileId,deliveryId:waiting.deliveryId}),/DELIVERY_EXPIRED/);
 const legacy=await send('expiry-other');app.store.run('UPDATE deliveries SET expires=0 WHERE id=?',legacy.deliveryId);
 assert.equal((await owner.rpc('storage.usage')).meta.used,bytes.length);assert.equal((await reader.rpc('storage.usage')).meta.used,0);
 checks.push('resend uses a new identity, preserves expired grants and charges the owner only once');
 const saved=app.store.all('SELECT * FROM deliveries ORDER BY id');await app.close();app=createApp(config);await start();owner=await login('expiry-owner');reader=await login('expiry-reader');other=await login('expiry-other');admin=await login('expiry-admin');
 assert.deepEqual(app.store.all('SELECT * FROM deliveries ORDER BY id'),saved);assert.equal((await reader.rpc('download.chunk',{fileId,deliveryId:active.deliveryId,offset:0})).payload.length,bytes.length);assert.equal((await other.rpc('download.chunk',{fileId,deliveryId:legacy.deliveryId,offset:0})).payload.length,bytes.length);await assert.rejects(reader.rpc('download.init',{fileId,deliveryId:old.deliveryId}),/DELIVERY_EXPIRED/);
 checks.push('restart retains finite and legacy deadlines and cannot revive expired grants');
 const events=(await reader.rpc('events.list')).meta.events;assert.ok(events.some(e=>e.action==='deliveries.expire'&&e.detail.deliveryId===old.deliveryId));assert.ok(!(await other.rpc('events.list')).meta.events.some(e=>e.detail.deliveryId===old.deliveryId));
 checks.push('expiry events remain visible only to participants and administrators');
 await changeBackupKeys(config.root+'.backup-keys');const backup=(await admin.rpc('maintenance.backup')).meta,source=config.root+'.backups/'+backup.id,access={keyFile:config.root+'.backup-keys'},manifest=await verifyBackup(source,undefined,access),target=join(root,'restored');await restoreBackup(source,target,manifest.checkpoint,access);
 const restored=new Store(target);try{assert.equal(restored.get('PRAGMA user_version').user_version,7);assert.deepEqual(restored.all('SELECT * FROM deliveries ORDER BY id'),app.store.all('SELECT * FROM deliveries ORDER BY id'));}finally{restored.close();}
 await app.close();app=createApp({...config,root:target});await start();reader=await login('expiry-reader');other=await login('expiry-other');await assert.rejects(reader.rpc('download.init',{fileId,deliveryId:old.deliveryId}),/DELIVERY_EXPIRED/);assert.equal((await reader.rpc('download.chunk',{fileId,deliveryId:active.deliveryId,offset:0})).payload.length,bytes.length);assert.equal((await other.rpc('download.chunk',{fileId,deliveryId:legacy.deliveryId,offset:0})).payload.length,bytes.length);
 checks.push('encrypted backup and fresh-directory restore preserve exact expiry and authorization behavior');
 console.log(JSON.stringify({ok:true,version:1,node:process.version,platform:process.platform,databaseVersion:7,scope:'compiled final runtime, real scanner and isolated temporary accounts',checks,realScanner:true,strictDeadline:true,waitCancelled:true,restart:true,legacy:true,resend:true,encryptedBackupRestore:true,originalAccountsChanged:false,originalDataChanged:false}));
}finally{await app.close();}
