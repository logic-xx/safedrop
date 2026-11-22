export interface SecurityEvent { seq: number; time: string; user: string; action: string; result: string; detail: Record<string,string|number|boolean>; detailTruncated?: boolean }
export interface EventBucket { from: number; to: number; total: number; denied: number; quarantined: number }
export interface EventPage { events: SecurityEvent[]; from: number; to: number; snapshot: number; total: number; denied: number; quarantined: number; buckets: EventBucket[]; nextBefore: number|null }
export function exactEventTime(value:string) { return new Date(value).toLocaleString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false,fractionalSecondDigits:3}); }
const names: Record<string,string> = {
  'auth.login':'登录成功','auth.password':'口令身份验证','auth.proof':'公钥身份验证','auth.logout':'退出登录',
  'auth.mfa':'双因素身份验证','auth.register':'邀请注册','account.password':'修改口令','users.password':'修改口令',
  'password.change':'修改口令','users.disable':'停用账号','users.register':'账号注册',
  'keys.enroll':'绑定本机公钥','keys.revoke':'撤销公钥','sessions.revoke':'撤销会话',
  'invitations.create':'创建邀请','invitations.revoke':'撤销邀请','registration.set':'修改注册策略',
  'upload.init':'准备上传','upload.finish':'上传完成','upload.chunk':'上传分块','upload.cancel':'取消上传',
  'upload.prepare':'准备上传','download.init':'开始下载','download.chunk':'读取下载分块',
  'files.rename':'重命名文件','files.delete':'删除文件','files.delete.requested':'请求删除文件',
  'upload.cancel.requested':'请求取消上传','files.scan.request':'请求文件扫描','files.scan.begin':'开始文件扫描',
  'files.scan':'文件扫描结果','deliveries.create':'创建交付授权','deliveries.download':'开始接收下载',
  'deliveries.revoke':'撤销交付授权','deliveries.expire':'交付授权到期',
  'maintenance.backup.begin':'开始一致备份','maintenance.backup':'备份完成','maintenance.cleanup':'清理过期上传',
  'maintenance.policy':'修改维护策略','mfa.setup':'准备绑定验证器','mfa.enable':'启用双因素认证',
  'mfa.disable':'停用双因素认证','mfa.recovery':'恢复双因素访问','protocol.invalid':'无效协议请求'
};
export function eventTitle(event: SecurityEvent) {
  if(event.action==='files.scan')return event.detail.state==='clean'?'文件扫描通过':event.detail.state==='quarantined'?'检测到威胁并隔离':event.detail.state==='error'?'文件扫描未通过':names[event.action];
  return names[event.action] ?? event.action;
}
export function eventStatus(event: SecurityEvent) {
  if(event.action==='files.scan' && event.detail.state==='quarantined')return { label:'威胁已隔离', tone:'threat' };
  if(event.result==='denied')return { label:'已拒绝',tone:'denied' };
  return { label:event.action==='deliveries.expire'?'已到期':'已记录',tone:'neutral' };
}
export function eventObject(event: SecurityEvent) {
  const d=event.detail;
  if(d.name)return String(d.name);
  if(d.fileId)return '文件 · '+String(d.fileId).slice(0,12);
  if(d.transferId)return '上传 · '+String(d.transferId).slice(0,12);
  if(d.deliveryId)return '交付 · '+String(d.deliveryId).slice(0,12);
  if(d.backupId)return '备份 · '+String(d.backupId).slice(0,12);
  return '—';
}
export function groupEventBuckets(buckets: EventBucket[], maximum: number) {
  const width=Math.max(1,Math.ceil(buckets.length/Math.max(1,maximum))),groups:EventBucket[]=[];
  for(let at=0;at<buckets.length;at+=width){const parts=buckets.slice(at,at+width);groups.push({from:parts[0].from,to:parts.at(-1)!.to,total:parts.reduce((n,b)=>n+b.total,0),denied:parts.reduce((n,b)=>n+b.denied,0),quarantined:parts.reduce((n,b)=>n+b.quarantined,0)});}
  return groups;
}
export function localDateInput(ms:number) { const d=new Date(ms),pad=(n:number)=>String(n).padStart(2,'0');return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; }
export function eventRange(from:string,to:string) {
  const parse=(value:string)=>{const n=new Date(value).getTime();if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d$/.test(value)||!Number.isFinite(n)||localDateInput(n)!==value)throw Error('请输入有效的本地日期和时间。');return n;};
  const start=parse(from),end=parse(to);
  if(start<0||end<=start||end-start>31*86400000)throw Error('结束时间须晚于开始时间，范围最多为 31 天。');
  return {from:start,to:end};
}
