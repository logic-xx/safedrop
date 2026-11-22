// Display-only synthetic audit events. No real malware, file reads or production data.
// Uses the final compiled application. Resume the same data via BROWSER_EVENTS_ROOT.
import {mkdirSync,mkdtempSync,writeFileSync,readFileSync,existsSync} from 'node:fs';
import {resolve,join,sep} from 'node:path';
import {randomBytes} from 'node:crypto';
import {createApp} from '../build/server/app.js';
import {digest,need} from '../build/server/store.js';
mkdirSync('tmp',{recursive:true});
const root=process.env.BROWSER_EVENTS_ROOT?resolve(process.env.BROWSER_EVENTS_ROOT):mkdtempSync(resolve('tmp/browser-events-'));
need(root.startsWith(resolve('tmp/browser-events-'))&&root.startsWith(resolve('tmp')+sep),'FIXTURE_ROOT_INVALID');
const port=Number(process.env.BROWSER_EVENTS_PORT??1605),origin=`http://localhost:${port}`;
const app=createApp({root,origin,storage:{minFree:0}}),fixturePath=join(root,'fixture.json');
if(!existsSync(fixturePath)){
  const password=randomBytes(24).toString('base64url'),reader=await app.store.addUser('events-reader',password);
  await app.store.addUser('events-admin',password,'admin');await app.store.addUser('events-other',password);
  writeFileSync(join(root,'credentials.json'),JSON.stringify({password}),{flag:'wx',mode:0o600});
  const now=Date.now(),base=now-23*3600000;
  const append=(time,user,action,result,detail)=>{const last=app.store.checkpoint(),event=JSON.stringify({time:new Date(time).toISOString(),user,action,result,detail});app.store.run('INSERT INTO audit VALUES(?,?,?,?)',last.count+1,event,last.head,digest(last.head+event));app.store.auditBytes+=Buffer.byteLength(event)+128;};
  for(let i=0;i<90;i++){
    const time=base+i*10*60000;
    if(i%15===0)append(time,'system','files.scan','denied',{ownerId:reader,fileId:'ui-example-'+i,state:'quarantined',code:'SYNTHETIC_UI_EXAMPLE'});
    else if(i%7===0)append(time,'events-reader','auth.password','denied',{code:'INVALID_CREDENTIALS'});
    else if(i%9===0)append(time,'system','deliveries.expire','allowed',{recipientId:reader,fileId:'ui-example-'+i,deliveryId:'ui-grant-'+i,expires:time});
    else append(time,'events-reader','upload.finish','allowed',{fileId:'ui-example-'+i,size:4096,name:i===89?'<img src=x onerror=alert(1)>.txt':'时间线界面样本.txt'});
  }
  for(let i=0;i<330;i++)append(now-60000+i,'events-other','auth.login','allowed',{method:'password'});
  writeFileSync(fixturePath,JSON.stringify({origin,root,created:new Date().toISOString(),syntheticEvents:420,readerEvents:90,scope:'display-only audit fixture; no sample objects, scans or delivery grants created'},null,2),{flag:'wx'});
}else need(JSON.parse(readFileSync(fixturePath,'utf8')).origin===origin,'FIXTURE_ORIGIN_MISMATCH');
app.server.listen(port,'127.0.0.1',()=>console.log(JSON.stringify({origin,root,compiled:true,syntheticEvents:true})));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>void app.close().then(()=>process.exit(0)));
