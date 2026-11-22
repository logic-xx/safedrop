import {test} from 'node:test';
import assert from 'node:assert/strict';
import { eventTitle,eventStatus,eventObject,groupEventBuckets,eventRange,localDateInput,exactEventTime,type SecurityEvent } from '../web/events-model.ts';
const row=(action:string,result='allowed',detail:SecurityEvent['detail']={}):SecurityEvent=>({seq:1,time:'2026-11-22T01:00:00.000Z',user:'owner',action,result,detail});
test('event labels separate expected expiry, denied access and genuine quarantine; unknown actions stay visible',()=>{
  assert.deepEqual(eventStatus(row('deliveries.expire')),{label:'已到期',tone:'neutral'});
  assert.equal(eventStatus(row('auth.password','denied')).tone,'denied');
  assert.equal(eventStatus(row('files.scan','denied',{state:'error'})).tone,'denied');
  assert.equal(eventStatus(row('files.scan','denied',{state:'quarantined'})).tone,'threat');
  assert.equal(eventTitle(row('files.scan','allowed',{state:'clean'})),'文件扫描通过');
  assert.equal(eventTitle(row('future.action')),'future.action');assert.equal(eventObject(row('auth.login')),'—');
});
test('responsive event overview preserves every count and exact interval boundaries',()=>{
  const bins=Array.from({length:24},(_,i)=>({from:i*100,to:(i+1)*100,total:i,denied:i%3,quarantined:i%2}));
  for(const maximum of [1,4,12,24]){const groups=groupEventBuckets(bins,maximum);assert.ok(groups.length<=maximum);assert.equal(groups[0].from,0);assert.equal(groups.at(-1)!.to,2400);for(const key of ['total','denied','quarantined'] as const)assert.equal(groups.reduce((n,b)=>n+b[key],0),bins.reduce((n,b)=>n+b[key],0));}
});
test('custom local-time range rejects invalid dates and oversized/reversed windows without UTC conversion',()=>{
  const from='2026-11-22T09:00',to='2026-11-22T10:00',range=eventRange(from,to);assert.equal(localDateInput(range.from),from);assert.equal(range.to-range.from,3600000);
  for(const [a,b]of [['2026-02-31T09:00',to],[from,from],[to,from],[from,'2027-01-01T10:00'],['',to]])assert.throws(()=>eventRange(a,b));
});
test('event details include calendar date and whole time as well as milliseconds',()=>{
  const value=new Date('2026-11-22T09:12:34.567').toISOString();
  assert.match(exactEventTime(value),/2026.*11.*22.*09:12:34\.567/);
});
