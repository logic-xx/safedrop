// Dedicated loopback fixture. Resume with BROWSER_EXPIRY_ROOT; existing samples are preserved.
import {mkdirSync,mkdtempSync,writeFileSync,readFileSync,existsSync} from 'node:fs';
import {resolve,join,sep} from 'node:path';
import {randomBytes,randomUUID} from 'node:crypto';
import {setTimeout as pause} from 'node:timers/promises';
import {createApp} from '../server/app.ts';
import {ClamdEngine} from '../server/clamd.ts';
import {digest,need} from '../server/store.ts';
mkdirSync('tmp',{recursive:true});
const root=process.env.BROWSER_EXPIRY_ROOT?resolve(process.env.BROWSER_EXPIRY_ROOT):mkdtempSync(resolve('tmp/browser-expiry-'));
need(root.startsWith(resolve('tmp')+sep)&&root.startsWith(resolve('tmp/browser-expiry-')),'FIXTURE_ROOT_INVALID');
const port=Number(process.env.BROWSER_EXPIRY_PORT??1604),origin=`http://localhost:${port}`,marker=join(root,'simulate-expiry');
const app=createApp({root,origin,scanner:new ClamdEngine({host:process.env.CLAMD_REAL_HOST??'127.0.0.1',port:Number(process.env.CLAMD_REAL_PORT??3429)}),deliveryClock:()=>Date.now()+(existsSync(marker)?2*3600000:0),storage:{minFree:0}});
const fixtureFile=join(root,'fixture.json');
if(!existsSync(fixtureFile)){
 const password=randomBytes(24).toString('base64url'),owner=await app.store.addUser('expiry-owner',password),reader=await app.store.addUser('expiry-reader',password);
 await app.store.addUser('expiry-admin',password,'admin');writeFileSync(join(root,'credentials.json'),JSON.stringify({password}),{mode:0o600,flag:'wx'});
 const samples:Record<string,string>={};
 for(const [key,name,size]of [['timed','09-到期测试.txt',48],['legacy','09-旧授权样本.txt',64],['fresh','09-新期限样本.txt',80]] as const){
  const id=randomUUID(),bytes=Buffer.alloc(size,'SafeDrop harmless expiry UI sample. ');writeFileSync(join(root,'objects',id),bytes);app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)',id,owner,name,size,digest(bytes),Date.now());samples[key]=id;app.scans.enqueue(app.store.get('SELECT * FROM files WHERE id=?',id)!);
 }
 app.scans.wake();
 for(let n=0;n<400&&!Object.values(samples).every(id=>app.scans.status(app.store.get('SELECT * FROM files WHERE id=?',id)!).state==='clean');n++)await pause(25);
 need(Object.values(samples).every(id=>app.scans.status(app.store.get('SELECT * FROM files WHERE id=?',id)!).state==='clean'),'REAL_SCANNER_FIXTURE_NOT_READY');
 const grants:Record<string,string>={};for(const key of ['timed','legacy']){const file=app.store.get('SELECT * FROM files WHERE id=?',samples[key])!,id=randomUUID(),created=Date.now();app.store.run('INSERT INTO deliveries(id,fileId,ownerId,recipientId,name,created,expires) VALUES(?,?,?,?,?,?,?)',id,file.id,owner,reader,file.name,created,key==='timed'?created+3600000:0);grants[key]=id;}
 writeFileSync(fixtureFile,JSON.stringify({root,origin,port,created:new Date().toISOString(),samples,grants,clockMarker:'simulate-expiry adds two hours only to this fixture delivery clock; no system clock changes'},null,2),{flag:'wx'});
}else need(JSON.parse(readFileSync(fixtureFile,'utf8')).origin===origin,'FIXTURE_ORIGIN_MISMATCH');
app.server.listen(port,'127.0.0.1',()=>console.log(JSON.stringify({fixture:root,origin,scope:'temporary accounts, real harmless scans; expiry clock simulation is fixture-only'})));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>void app.close().then(()=>process.exit(0)));
