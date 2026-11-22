<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue';
import type { Frame, Metadata } from '../shared/protocol.ts';
import { human } from './client.ts';
import { eventTitle, eventStatus, eventObject, groupEventBuckets, localDateInput, eventRange, exactEventTime, type EventBucket, type EventPage, type SecurityEvent } from './events-model.ts';

const props=defineProps<{ rpc:(op:string,meta?:Metadata)=>Promise<Frame>; admin:boolean }>();
const DAY=86400000, latest=()=>Math.ceil((Date.now()+1)/60000)*60000;
const range=ref({from:latest()-DAY,to:latest()}),fromInput=ref(localDateInput(range.value.from)),toInput=ref(localDateInput(range.value.to)),preset=ref('24');
const page=ref<EventPage>(),busy=ref(false),error=ref(''),selected=ref<SecurityEvent>(),before=ref<number>(),backStack=ref<(number|undefined)[]>([]),zoomStack=ref<{from:number;to:number}[]>([]);
const overview=ref<HTMLElement>(),details=ref<HTMLElement>(),maximumBins=ref(24);
let live=true,request=0,observer:ResizeObserver|undefined,origin:HTMLElement|undefined,pointer:{x:number;y:number}|undefined,skipClickUntil=0;
const zone=Intl.DateTimeFormat().resolvedOptions().timeZone;
const stamp=(n:number|string)=>new Date(n).toLocaleString('zh-CN',{hour12:false});
const precise=exactEventTime;
const short=(n:number)=>new Date(n).toLocaleTimeString('zh-CN',{hour12:false,hour:'2-digit',minute:'2-digit'});
const rowTime=(n:string)=>new Date(n).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
const groups=computed(()=>groupEventBuckets(page.value?.buckets??[],maximumBins.value));
const peak=computed(()=>Math.max(1,...groups.value.map(b=>b.total)));
const duration=computed(()=>range.value.to-range.value.from);
const ticks=computed(()=>Array.from({length:5},(_,i)=>short(range.value.from+duration.value*i/4)));
const ordinary=(b:EventBucket)=>Math.max(0,b.total-b.denied),rejected=(b:EventBucket)=>Math.max(0,b.denied-b.quarantined);
const fieldNames:Record<string,string>={code:'原因代码',fileId:'文件标识',transferId:'上传标识',deliveryId:'交付标识',state:'扫描状态',size:'大小（字节）',offset:'偏移（字节）',expires:'授权期限',sender:'发送者',recipient:'接收者',ownerId:'所有者标识',recipientId:'接收者标识',method:'认证方式',name:'文件名',oldName:'原文件名',engine:'扫描引擎',signature:'签名版本',encrypted:'已加密',backupId:'备份标识',bytes:'大小（字节）',keyId:'密钥标识',sessions:'会话处理',keys:'公钥处理'};
async function load(cursor?:number,history:(number|undefined)[]=[],snapshot?:number) {
  const token=++request,rpc=props.rpc,query={...range.value,limit:24,...(cursor===undefined?{}:{before:cursor}),...(snapshot===undefined?{}:{snapshot})};
  busy.value=true;error.value='';selected.value=undefined;
  try {
    const result=await rpc('events.query',query);
    if(!live||token!==request)return;
    page.value=result.meta as unknown as EventPage;before.value=cursor;backStack.value=history;
  }catch(e){if(live&&token===request){page.value=undefined;before.value=undefined;backStack.value=[];error.value=human(e);}}
  finally{if(live&&token===request)busy.value=false;}
}
async function refresh(){page.value=undefined;await load();}
function setRange(next:{from:number;to:number}){range.value=next;fromInput.value=localDateInput(next.from);toInput.value=localDateInput(next.to);preset.value='custom';void refresh();}
function choosePreset(){if(preset.value==='custom')return;zoomStack.value=[];const to=latest();const hours=Number(preset.value);setRange({from:to-hours*3600000,to});preset.value=String(hours);}
function apply(){try{const next=eventRange(fromInput.value,toInput.value);zoomStack.value=[];setRange(next);}catch(e){error.value=e instanceof Error?e.message:'时间范围无效。';}}
function pan(direction:number){const span=duration.value,from=Math.max(0,Math.min(latest()-span,range.value.from+direction*Math.ceil(span/2)));zoomStack.value=[];setRange({from,to:from+span});}
function zoom(size:number){const span=Math.min(31*DAY,Math.max(60000,size));zoomStack.value.push({...range.value});setRange({from:Math.max(0,range.value.to-span),to:range.value.to});}
function focusBucket(bucket:EventBucket){if(performance.now()<skipClickUntil||busy.value||duration.value<=60000)return;zoomStack.value.push({...range.value});const to=Math.min(range.value.to,Math.max(bucket.to,bucket.from+60000)),from=Math.max(range.value.from,to-Math.max(60000,bucket.to-bucket.from));setRange({from,to});}
function backZoom(){const previous=zoomStack.value.pop();if(previous)setRange(previous);}
function nextPage(){if(page.value?.nextBefore!=null)void load(page.value.nextBefore,[...backStack.value,before.value],page.value.snapshot);}
function previousPage(){if(backStack.value.length){const history=[...backStack.value],cursor=history.pop();void load(cursor,history,page.value?.snapshot);}}
async function pick(event:SecurityEvent,trigger:Event){selected.value=event;origin=trigger.currentTarget as HTMLElement;await nextTick();details.value?.focus();}
async function closeDetails(){selected.value=undefined;await nextTick();if(origin?.isConnected)origin.focus();}
function swipe(event:PointerEvent){if(!pointer)return;const dx=event.clientX-pointer.x,dy=event.clientY-pointer.y;pointer=undefined;if(!busy.value&&Math.abs(dx)>48&&Math.abs(dy)<32){skipClickUntil=performance.now()+350;pan(dx>0?-1:1);}}
onMounted(()=>{
  observer=new ResizeObserver(entries=>{const width=entries[0].contentRect.width;let limit=width<420?4:width<700?12:24;if(matchMedia('(pointer: coarse)').matches)limit=Math.min(limit,Math.max(1,Math.floor(width/44)));maximumBins.value=limit;});
  if(overview.value)observer.observe(overview.value);void load();
});
onUnmounted(()=>{live=false;request++;observer?.disconnect();});
defineExpose({refresh});
</script>

<template>
  <section class="card event-explorer" aria-labelledby="events-heading" :aria-busy="busy">
    <header class="card-heading"><div><h3 id="events-heading">安全事件</h3><p>{{ admin?'管理员 · 全部用户的可见记录':'仅本人及参与的事件' }} · {{ zone }}</p></div><button class="secondary small" :disabled="busy" @click="refresh">刷新事件</button></header>
    <div class="events-toolbar">
      <label>时间范围<select v-model="preset" :disabled="busy" @change="choosePreset"><option value="1">最近 1 小时</option><option value="24">最近 24 小时</option><option value="168">最近 7 天</option><option value="custom">自定义</option></select></label>
      <label>开始时间<input v-model="fromInput" type="datetime-local" :disabled="busy"></label><label>结束时间<input v-model="toInput" type="datetime-local" :disabled="busy"></label><button class="secondary small" :disabled="busy" @click="apply">应用时间</button>
    </div>
    <p v-if="error" class="events-error" role="alert">{{ error }}</p>
    <div class="events-overview">
      <div class="range-heading"><strong>{{ stamp(range.from) }} — {{ stamp(range.to) }}</strong><span class="events-muted">结束时间不包含在范围内</span></div>
      <div class="range-controls"><div class="range-buttons"><button class="secondary small" :disabled="busy || range.from < duration/2" @click="pan(-1)">← 更早</button><button class="secondary small" :disabled="busy || range.to >= latest()" @click="pan(1)">更晚 →</button><button class="secondary small" :disabled="busy || duration <= 60000" @click="zoom(duration/2)">放大</button><button class="secondary small" :disabled="busy || duration >= 31*DAY" @click="zoom(duration*2)">缩小</button><button v-if="zoomStack.length" class="link" :disabled="busy" @click="backZoom">返回上一范围</button></div><div class="events-legend"><span><i class="legend-normal"></i>已记录</span><span><i class="legend-denied"></i>已拒绝</span><span><i class="legend-threat"></i>威胁隔离</span></div></div>
      <div ref="overview" class="event-bins" :style="{gridTemplateColumns:`repeat(${groups.length || 1},minmax(0,1fr))`}" role="group" aria-label="时间分布，点击时段放大或左右滑动" @pointerdown="pointer={x:$event.clientX,y:$event.clientY}" @pointerup="swipe" @pointercancel="pointer=undefined">
        <button v-for="bucket in groups" :key="bucket.from" type="button" class="event-bin" :disabled="busy || duration <= 60000" :aria-label="`${stamp(bucket.from)} 至 ${stamp(bucket.to)}，${bucket.total} 条，拒绝 ${bucket.denied} 条，其中威胁隔离 ${bucket.quarantined} 条`" :title="`${short(bucket.from)}—${short(bucket.to)} · ${bucket.total} 条`" @click="focusBucket(bucket)"><span class="bin-count">{{ bucket.total || '' }}</span><span class="bar-space"><span class="bar-stack" :style="{height:`${bucket.total/peak*64}px`}"><i class="segment-threat" :style="{flex:bucket.quarantined}"></i><i class="segment-denied" :style="{flex:rejected(bucket)}"></i><i class="segment-normal" :style="{flex:ordinary(bucket)}"></i></span></span></button>
        <span v-if="!groups.length" class="overview-placeholder">{{ busy?'正在查询完整时段…':'暂无时间分布' }}</span>
      </div>
      <div class="event-ticks" aria-hidden="true"><span v-for="(tick,i) in ticks" :key="i">{{ tick }}</span></div>
      <p class="events-help">横轴为时间，柱高为事件数量。点选时段放大，可左右滑动；统计覆盖所选时段全部可见记录。</p>
    </div>
    <div class="event-summary" role="status"><span v-if="busy">正在查询…</span><span v-else-if="page">当前范围 {{ page.total }} 条 · 拒绝 {{ page.denied }} 条（含威胁隔离 {{ page.quarantined }} 条）</span><span v-else>查询尚未完成</span><span v-if="page" class="events-muted">按审计序号从新到旧 · 刷新后更新记录边界</span></div>
    <div class="events-layout" :class="{'has-detail':selected}">
      <div class="event-list-area">
        <table v-if="page?.events.length" class="events-table"><thead><tr><th>时间</th><th>事件</th><th class="actor-column">账号</th><th class="object-column">对象</th><th class="result-column">结果</th></tr></thead><tbody><tr v-for="event in page.events" :key="event.seq" :class="{'is-selected':selected?.seq===event.seq}"><td class="time-column"><time :datetime="event.time">{{ rowTime(event.time) }}</time></td><td class="title-column"><button class="event-pick" :disabled="busy" :aria-expanded="selected?.seq===event.seq" @click="pick(event,$event)">{{ eventTitle(event) }}</button><small class="mobile-context">{{ event.user }} · {{ eventObject(event) }}</small><small class="mobile-status" :class="eventStatus(event).tone">{{ eventStatus(event).label }}</small></td><td class="actor-column">{{ event.user }}</td><td class="object-column">{{ eventObject(event) }}</td><td class="result-column"><span class="event-status" :class="eventStatus(event).tone">{{ eventStatus(event).label }}</span></td></tr></tbody></table>
        <div v-else class="empty">{{ busy?'正在读取事件…':error?'本次查询未成功，请调整范围或重试。':'所选时段没有可见事件' }}</div>
        <nav class="event-pagination" aria-label="安全事件分页"><button class="secondary small" :disabled="busy || !backStack.length" @click="previousPage">上一页</button><span class="events-muted">第 {{ backStack.length+1 }} 页 · 本页 {{ page?.events.length ?? 0 }} 条</span><button class="secondary small" :disabled="busy || page?.nextBefore == null" @click="nextPage">下一页</button></nav>
      </div>
      <aside v-if="selected" ref="details" class="event-details" role="region" aria-labelledby="event-detail-heading" tabindex="-1" @keydown.esc="closeDetails"><div class="detail-heading"><h4 id="event-detail-heading">事件详情</h4><button class="secondary small" aria-label="关闭事件详情" @click="closeDetails">关闭</button></div><strong>{{ eventTitle(selected) }}</strong><span class="event-status" :class="eventStatus(selected).tone">{{ eventStatus(selected).label }}</span><dl><dt>准确时间（{{ zone }}）</dt><dd>{{ precise(selected.time) }}</dd><dt>审计序号</dt><dd>#{{ selected.seq }}</dd><dt>账号</dt><dd>{{ selected.user }}</dd><dt>原始动作</dt><dd><code>{{ selected.action }}</code></dd><template v-for="(value,key) in selected.detail" :key="key"><dt>{{ fieldNames[key] ?? key }}</dt><dd>{{ key==='expires' && typeof value==='number' && value>0 ? stamp(value) : value }}</dd></template></dl><p v-if="selected.detailTruncated" class="events-help">显示详情已节选，原始审计记录保持完整。</p><p class="events-help">事件视图不替代审计链校验。拒绝不等于攻击；下载开始不表示已完整收到文件。</p></aside>
    </div>
  </section>
</template>

<style scoped>
.event-explorer{font-size:13px;color:#34483f;overflow:visible}.event-explorer .card-heading{border-radius:11px 11px 0 0;flex-wrap:wrap}.card-heading p{margin:6px 0 0;font-size:11px;color:#65776e}.events-toolbar{padding:18px 22px;display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;border-bottom:1px solid #e8ede9}.events-toolbar label{display:grid;gap:6px;font-size:11px;color:#5b6c63;min-width:0}.events-toolbar input,.events-toolbar select{padding:8px 9px;min-height:35px;font:12px system-ui;color:#354b40;border:1px solid #dce5de;border-radius:6px;background:white;min-width:0}.events-error{margin:0;padding:12px 22px;background:#fff3ea;color:#8e4a28;overflow-wrap:anywhere}.events-overview{padding:18px 22px 12px}.range-heading,.range-controls,.range-buttons,.events-legend,.event-summary{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.range-heading strong{font-size:12px;font-weight:500}.range-controls{margin:14px 0 8px}.range-buttons{justify-content:flex-start;gap:7px}.range-buttons button{font-size:11px}.events-muted,.events-help{font-size:11px;color:#62756a;line-height:1.7}.events-legend{gap:12px;font-size:11px;color:#5c6e63}.events-legend span{display:flex;align-items:center;gap:5px}.events-legend i{display:inline-block;width:8px;height:8px;border-radius:2px}.legend-normal,.segment-normal{background:#819b8a}.legend-denied,.segment-denied{background:#bd8245}.legend-threat,.segment-threat{background:#b6534b}.event-bins{min-height:100px;display:grid;gap:3px;align-items:end;touch-action:pan-y;user-select:none;border-bottom:1px solid #dce5de}.event-bin{min-width:0;padding:0 3px;background:transparent;border:0;display:grid;gap:5px;color:#485c50;min-height:98px;border-radius:4px 4px 0 0}.event-bin:hover:not(:disabled){background:#edf5ef}.event-bin:focus-visible{outline:2px solid #277d5e;outline-offset:2px}.bin-count{font-size:10px;font-variant-numeric:tabular-nums;align-self:end}.bar-space{height:68px;display:flex;align-items:flex-end;justify-content:center}.bar-stack{display:flex;flex-direction:column;width:100%;max-width:32px;min-width:2px}.bar-stack i{display:block;min-height:0;flex-basis:0;flex-shrink:0}.overview-placeholder{padding:24px;font-size:12px;color:#61756b;align-self:center}.event-ticks{display:flex;justify-content:space-between;gap:5px;padding-top:7px;color:#61756b;font-size:10px;font-variant-numeric:tabular-nums}.events-help{margin:9px 0 0}.event-summary{padding:12px 22px;background:#f6f9f7;border-top:1px solid #e7ede8;border-bottom:1px solid #e7ede8;font-size:12px}.events-layout{display:grid;min-width:0}.events-layout.has-detail{grid-template-columns:minmax(0,1fr) 300px}.event-list-area{min-width:0}.events-table{white-space:normal;table-layout:fixed;width:100%;text-align:left}.events-table th{font-size:10px;padding:12px 14px;color:#64746a}.events-table td{padding:9px 14px;color:#42584a;font-size:12px;overflow-wrap:anywhere;vertical-align:middle}.events-table th:first-child{width:132px}.events-table th:nth-child(3){width:83px}.events-table th:nth-child(4){width:140px}.events-table th:last-child{width:93px}.events-table tr.is-selected{background:#edf6f0}.event-pick{padding:7px 0;text-align:left;font:12px/1.6 system-ui;color:#1e6c50;background:none;border:0;overflow-wrap:anywhere}.event-pick:focus-visible{outline:2px solid #277d5e;outline-offset:3px}.time-column{font-variant-numeric:tabular-nums;color:#62756b!important;font-size:10px!important}.event-status{display:inline-block;font-size:11px;line-height:1.6;color:#5c7062}.event-status.denied,.mobile-status.denied{color:#955a24}.event-status.threat,.mobile-status.threat{color:#a03d37}.event-pagination{padding:15px 18px;display:flex;align-items:center;justify-content:space-between;gap:8px;border-top:1px solid #e8ede9}.event-pagination button{font-size:11px}.mobile-context,.mobile-status{display:none}.event-details{padding:16px;background:#f7faf8;border-left:1px solid #e0e8e2;min-width:0;overflow-wrap:anywhere;border-radius:0 0 11px 0}.event-details:focus-visible{outline:2px solid #277d5e;outline-offset:-2px}.detail-heading{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:15px}.detail-heading h4{font-size:13px;margin:0}.event-details>strong{display:block;font-size:13px;font-weight:500;margin-bottom:6px}.event-details dl{margin:16px 0 0}.event-details dt{font-size:10px;color:#64776b;margin-top:13px}.event-details dd{font-size:12px;margin:4px 0 0;color:#3d5344;white-space:pre-wrap;overflow-wrap:anywhere}.event-details code{font-size:11px}.has-detail .object-column{display:none}.event-details .events-help{margin-top:18px}
@media(max-width:1150px){.events-layout.has-detail{grid-template-columns:1fr}.event-details{border-left:0;border-top:1px solid #dfe7e1;border-radius:0 0 11px 11px}.has-detail .object-column{display:table-cell}.event-details dl{display:grid;grid-template-columns:130px minmax(0,1fr);gap:9px 15px}.event-details dt,.event-details dd{margin:0}}
@media(max-width:650px){.events-toolbar,.events-overview{padding:16px}.events-toolbar label{flex:1 1 170px}.events-toolbar input,.events-toolbar select{width:100%;font-size:16px}.event-summary{padding:12px 16px}.events-table,.events-table tbody{display:block}.events-table thead{display:none}.events-table tr{display:grid;grid-template-columns:80px minmax(0,1fr);padding:7px 14px;border-bottom:1px solid #e8ede9;gap:10px}.events-table td{padding:4px 0;border:0}.events-table .actor-column,.events-table .object-column,.events-table .result-column{display:none}.event-pick{min-height:38px}.mobile-context,.mobile-status{display:block;font-size:10px;line-height:1.7;color:#617469;margin-top:3px}.range-heading{align-items:flex-start}.events-legend{margin-top:3px}.event-details dl{grid-template-columns:1fr;gap:4px}.event-details dd{margin-bottom:9px}.event-pagination{flex-wrap:wrap}.events-help{font-size:11px}}
.event-pagination{flex-direction:row}
@media(max-width:650px){.events-toolbar label{flex-basis:100%}}
@media(prefers-reduced-motion:no-preference){.bar-stack{transition:height .16s ease}}
</style>
