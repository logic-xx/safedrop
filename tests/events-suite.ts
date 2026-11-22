import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { WebSocket } from 'ws';
import { createTestApp as createApp } from './test-scanner.ts';
import { certificates } from '../scripts/certificates.ts';
import { digest, verifyAudit, type Row } from '../server/store.ts';
import { Peer, type Result } from './suite.ts';

export async function runEventsSuite(onResult?: (r: Result) => void) {
  mkdirSync('tmp',{recursive:true});const root=mkdtempSync(resolve('tmp/events-'));certificates(join(root,'tls'));
  const password=randomBytes(24).toString('base64url'),origin='https://localhost';
  const app=createApp({root:join(root,'data'),origin,tls:{cert:readFileSync(join(root,'tls/server.crt')),key:readFileSync(join(root,'tls/server.key'))}});
  const results:Result[]=[];
  const run=async(name:string,fn:()=>Promise<void>)=>{const at=performance.now();let failure:unknown;try{await fn();}catch(e){failure=e;}const r={name,ok:!failure,ms:Math.round(performance.now()-at),detail:failure instanceof Error?failure.message:failure?String(failure):'真实 TLS/WSS、完整范围统计、游标分页、可见性与不可变审计断言通过。'};results.push(r);onResult?.(r);};
  const seed=(time:number,user:string,action='auth.login',result='allowed',detail:Row={})=>{const last=app.store.checkpoint(),event=JSON.stringify({time:new Date(time).toISOString(),user,action,result,detail});app.store.run('INSERT INTO audit VALUES(?,?,?,?)',last.count+1,event,last.head,digest(last.head+event));app.store.auditBytes+=Buffer.byteLength(event)+128;return last.count+1;};
  const base=Date.UTC(2020,0,1),span=3600000;
  const query=(peer:Peer,slot:number,extra:Row={})=>peer.rpc('events.query',{from:base+slot*span,to:base+(slot+1)*span,...extra}).then(r=>r.meta as Row);
  try{
    const ids:Row={};for(const name of ['owner','reader','stranger','admin'])ids[name]=await app.store.addUser(name,password,name==='admin'?'admin':'user');
    app.server.listen(0,'127.0.0.1');await once(app.server,'listening');
    const connect=async(name?:string)=>{const ws=new WebSocket(`wss://127.0.0.1:${(app.server.address() as {port:number}).port}/ws`,{ca:readFileSync(join(root,'tls/ca.crt')),rejectUnauthorized:true,headers:{Origin:origin}});await once(ws,'open');const peer=new Peer(ws);if(name)await peer.rpc('auth.password',{name,password});return peer;};
    const owner=await connect('owner'),reader=await connect('reader'),stranger=await connect('stranger'),admin=await connect('admin');
    await run('事件查询：认证及精确半开时间边界，相同时刻按审计序号稳定排序',async()=>{
      const anonymous=await connect();await assert.rejects(query(anonymous,0),/AUTH_REQUIRED/);anonymous.ws.close();
      seed(base-1,'owner');const first=seed(base,'owner'),second=seed(base,'owner');seed(base+span-1,'owner','files.scan','denied',{state:'quarantined',ownerId:ids.owner});seed(base+span,'owner');
      const page=await query(owner,0);assert.deepEqual(page.events.map((e:Row)=>e.seq),[second+1,second,first]);assert.equal(page.total,3);assert.equal(page.denied,1);assert.equal(page.quarantined,1);assert.equal(page.buckets.reduce((n:number,b:Row)=>n+b.total,0),3);assert.equal(page.buckets[0].total,2);assert.equal(page.buckets.at(-1).total,1);assert.equal(page.nextBefore,null);
    });
    await run('事件查询：超过原 300 条截断仍可见本人及扫描/交付参与记录，第三方不可见',async()=>{
      const at=base+span+1,expected:number[]=[];
      expected.push(seed(at,'owner'));
      for(const action of ['files.scan.begin','files.scan'])expected.push(seed(at,'system',action,'allowed',{ownerId:ids.owner}));
      for(const action of ['deliveries.create','deliveries.revoke','deliveries.download','deliveries.expire'])expected.push(seed(at,'system',action,'allowed',{recipientId:ids.owner}));
      seed(at,'system','maintenance.backup','allowed',{ownerId:ids.owner});seed(at,'system','deliveries.create','allowed',{recipientId:ids.stranger});
      for(let i=0;i<330;i++)seed(at,'reader');
      const page=await query(owner,1,{from:at,role:'admin',userId:ids.reader,ownerId:ids.reader});assert.equal(page.total,expected.length);assert.deepEqual(page.events.map((e:Row)=>e.seq),expected.reverse());
      const unrelated=await query(stranger,1,{from:at});assert.equal(unrelated.total,1);assert.equal(unrelated.events[0].detail.recipientId,ids.stranger);
      assert.equal((await query(admin,1,{from:at})).total,339);
      const recent=(await owner.rpc('events.list')).meta.events as Row[];assert.ok(recent.some(e=>e.seq===expected[0]));assert.ok(recent.every(e=>e.user==='owner'||e.detail.ownerId===ids.owner||e.detail.recipientId===ids.owner));
    });
    await run('事件查询：固定快照与序号游标跨多页无重复遗漏，期间新写入不混入统计',async()=>{
      const at=base+2*span+1,ids:number[]=[];for(let i=0;i<53;i++)ids.push(seed(at,'owner'));
      let page=await query(owner,2,{limit:7}),snapshot=page.snapshot;const seen:number[]=[];
      seed(at,'owner');
      for(;;){assert.equal(page.total,53);assert.equal(page.snapshot,snapshot);seen.push(...page.events.map((e:Row)=>e.seq));if(!page.nextBefore)break;page=await query(owner,2,{limit:7,before:page.nextBefore,snapshot});}
      assert.deepEqual(seen,ids.reverse());assert.equal(new Set(seen).size,53);assert.equal((await query(owner,2)).total,54);
    });
    await run('事件查询：空范围不暴露无关记录的数量、序号或分布',async()=>{
      seed(base+3*span+1,'reader');const page=await query(owner,3,{snapshot:Number.MAX_SAFE_INTEGER});assert.equal(page.total,0);assert.equal(page.denied,0);assert.equal(page.snapshot,0);assert.deepEqual(page.events,[]);assert.equal(page.nextBefore,null);assert.ok(page.buckets.every((b:Row)=>b.total===0));
    });
    await run('事件查询：大详情与多字节名称保持有界分页，显示投影不改变原审计链',async()=>{
      const at=base+4*span+1,ids:number[]=[];
      for(let i=0;i<28;i++)ids.push(seed(at,'owner','files.rename','allowed',{name:'界'.repeat(1000),oldName:'名'.repeat(1000),fileId:'id-'+i,engine:'引擎'.repeat(1000),signature:'描述'.repeat(1000),hidden:'not exported',nested:{value:'not exported'}}));
      const anchor=app.store.checkpoint();let page=await query(owner,4,{limit:50});const snapshot=page.snapshot,seen:number[]=[];
      for(;;){assert.ok(Buffer.byteLength(JSON.stringify(page))<12*1024);assert.ok(page.events.length>0);for(const e of page.events){assert.equal(e.detailTruncated,true);assert.equal(e.detail.hidden,undefined);assert.equal(e.detail.nested,undefined);assert.ok(e.detail.name.length<=256);seen.push(e.seq);}if(!page.nextBefore)break;page=await query(owner,4,{limit:50,before:page.nextBefore,snapshot});}
      assert.deepEqual(seen,ids.reverse());assert.deepEqual(app.store.checkpoint(),anchor);assert.equal(verifyAudit(app.store.all('SELECT * FROM audit ORDER BY seq'),anchor).ok,true);
    });
    await run('事件查询：非法时段、参数类型及不完整游标拒绝，连接继续可用',async()=>{
      const bad=[{from:'0'},{to:null},{from:-1},{from:base,to:base},{from:base,to:base+32*86400000},{limit:0},{limit:51},{limit:1.5},{snapshot:'1'},{before:0,snapshot:1},{before:1},{before:'1',snapshot:1}];
      for(const input of bad)await assert.rejects(query(owner,5,input),/INVALID_(INTEGER|EVENT_RANGE|EVENT_CURSOR)/);
      assert.equal((await owner.rpc('ping')).meta.ok,true);
    });
    await run('事件查询：多连接共享账号查询限额，不影响其他账号读取',async()=>{
      const other=await connect('reader');
      for(let i=0;i<60;i++)await query(i%2?other:reader,6);
      await assert.rejects(query(other,6),/RATE_LIMITED/);assert.equal((await query(stranger,6)).total,0);other.ws.close();
    });
  }finally{assert.equal(verifyAudit(app.store.all('SELECT * FROM audit ORDER BY seq')).ok,true);await app.close();}
  return results;
}
