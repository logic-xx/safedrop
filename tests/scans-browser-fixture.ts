// Dedicated loopback UI fixture. Reuse its printed root with BROWSER_SCAN_ROOT after interruption.
// The quarantine row is controlled UI evidence; real threat detection is tested separately.
import {mkdirSync,mkdtempSync,writeFileSync,readFileSync,existsSync} from 'node:fs';
import {resolve,join,sep} from 'node:path';
import {randomBytes,randomUUID} from 'node:crypto';
import {setTimeout as pause} from 'node:timers/promises';
import {createApp} from '../server/app.ts';
import {ClamdEngine,type ScanEngine} from '../server/clamd.ts';
import {digest,need} from '../server/store.ts';
import {changeBackupKeys} from '../server/backup-keys.ts';
import {encryptedBenignZip} from './scan-samples.mjs';
mkdirSync('tmp',{recursive:true});
const root=process.env.BROWSER_SCAN_ROOT?resolve(process.env.BROWSER_SCAN_ROOT):mkdtempSync(resolve('tmp/browser-scan-'));
need(root.startsWith(resolve('tmp')+sep)&&root.startsWith(resolve('tmp/browser-scan-')),'FIXTURE_ROOT_INVALID');
const port=Number(process.env.BROWSER_SCAN_PORT??1603),origin=`http://localhost:${port}`,marker=join(root,'simulate-engine-offline');
const engine=new ClamdEngine({host:process.env.CLAMD_REAL_HOST??'127.0.0.1',port:Number(process.env.CLAMD_REAL_PORT??3429)}),offline=new ClamdEngine({host:'127.0.0.1',port:1,timeoutMs:1000});
const scanner:ScanEngine={async scan(input,signal){await pause(3000,undefined,{signal});return (existsSync(marker)?offline:engine).scan(input,signal);}};
const app=createApp({root,origin,scanner,storage:{minFree:0},normalRate:4*1024**2});
const fixtureFile=join(root,'fixture.json');
if(!existsSync(fixtureFile)){
 const password=randomBytes(24).toString('base64url'),owner=await app.store.addUser('scan-owner',password),reader=await app.store.addUser('scan-reader',password);
 await app.store.addUser('scan-admin',password,'admin');
 writeFileSync(join(root,'credentials.json'),JSON.stringify({password}),{mode:0o600,flag:'wx'});
 const file=(name:string,bytes:Buffer)=>{const id=randomUUID();writeFileSync(join(root,'objects',id),bytes);app.store.run('INSERT INTO files VALUES(?,?,?,?,?,?)',id,owner,name,bytes.length,digest(bytes),Date.now());return app.store.get('SELECT * FROM files WHERE id=?',id)!;};
 const legacy=file('03-旧文件待扫描.txt',Buffer.from('SafeDrop harmless legacy UI sample.\n'));
 const encrypted=file('03-加密无害压缩包.zip',encryptedBenignZip());
 const quarantine=file('03-隔离状态夹具（受控）.txt',Buffer.from('Harmless controlled quarantine UI state, not an engine detection.\n'));
 const retry=file('03-引擎连接重试.txt',Buffer.from('Harmless connection-failure retry UI sample.\n'));
 app.store.run("INSERT INTO file_scans(fileId,sha256,size,state,generation,requested,checked,engine,signature) VALUES(?,?,?,'quarantined',?,?,?,'TEST_ONLY_CONTROLLED_UI_STATE','Controlled UI fixture')",quarantine.id,quarantine.sha256,quarantine.size,randomUUID(),Date.now(),Date.now());
 app.scans.enqueue(encrypted);app.scans.wake();
 const grants=[legacy,quarantine].map(f=>{const id=randomUUID();app.store.run('INSERT INTO deliveries(id,fileId,ownerId,recipientId,name,created) VALUES(?,?,?,?,?,?)',id,f.id,owner,reader,f.name,Date.now());return id;});
 await changeBackupKeys(root+'.backup-keys');
 writeFileSync(fixtureFile,JSON.stringify({root,origin,port,created:new Date().toISOString(),samples:{legacy:legacy.id,encrypted:encrypted.id,quarantine:quarantine.id,retry:retry.id},grants,quarantineEvidence:'controlled UI state only; not real engine detection'},null,2),{flag:'wx'});
}else need(JSON.parse(readFileSync(fixtureFile,'utf8')).origin===origin,'FIXTURE_ORIGIN_MISMATCH');
app.server.listen(port,'127.0.0.1',()=>console.log(JSON.stringify({fixture:root,origin,scope:'temporary accounts; real engine except explicitly controlled quarantine row'})));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>void app.close().then(()=>process.exit(0)));
