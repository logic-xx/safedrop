import { Store, integer, need, type Row } from './store.ts';

const DAY = 86400000, MAX_DATE = 253402300799999;
const scanActions = "'files.scan.begin','files.scan'";
const deliveryActions = "'deliveries.create','deliveries.revoke','deliveries.download','deliveries.expire','download.finish'";
const quarantined = "(json_extract(event,'$.action')='files.scan' AND json_extract(event,'$.detail.state')='quarantined')";
const fields = ['code','fileId','folderId','previousFolderId','deliveryId','transferId','state','size','offset','expires','sender','recipient','ownerId','recipientId','method','name','oldName','engine','signature','encrypted','backupId','bytes','keyId','sessions','keys','saveMode'];
function visibility(user: Row) {
  return user.role === 'admin' ? { sql:'1', args:[] } : {
    sql:`(json_extract(event,'$.user')=? OR
      (json_extract(event,'$.action') IN (${scanActions}) AND json_extract(event,'$.detail.ownerId')=?) OR
      (json_extract(event,'$.action') IN (${deliveryActions}) AND (json_extract(event,'$.detail.ownerId')=? OR json_extract(event,'$.detail.recipientId')=?)))`,
    args:[user.name,user.id,user.id,user.id]
  };
}
export function recentEvents(store: Store, user: Row) {
  const scope=visibility(user);
  const events=store.all(`SELECT seq,event FROM audit WHERE ${scope.sql} ORDER BY seq DESC LIMIT 24`,...scope.args).map(row=>({seq:row.seq,...JSON.parse(row.event)}));
  while(Buffer.byteLength(JSON.stringify({events}))>12*1024)events.pop();
  return events;
}

// This bounded display projection is separate from the immutable audit-chain export.
function displayEvent(row: Row) {
  const event = JSON.parse(row.event), detail: Row = {};
  const result: Row = { seq: row.seq, time: event.time, user: String(event.user).slice(0,180), action: String(event.action).slice(0,64), result: event.result, detail };
  for (const key of fields) {
    const value = event.detail?.[key];
    if (typeof value !== 'string' && typeof value !== 'boolean' && !(typeof value === 'number' && Number.isFinite(value))) continue;
    detail[key] = typeof value === 'string' ? value.slice(0,256) : value;
    if (typeof value === 'string' && value.length > 256) result.detailTruncated = true;
    if (Buffer.byteLength(JSON.stringify(result)) > 2048) { delete detail[key]; result.detailTruncated = true; }
  }
  return result;
}

export function queryEvents(store: Store, user: Row, input: Row) {
  const from = integer(input.from, MAX_DATE), to = integer(input.to, MAX_DATE);
  need(to > from && to - from <= 31 * DAY, 'INVALID_EVENT_RANGE');
  const limit = input.limit === undefined ? 24 : integer(input.limit, 50); need(limit > 0, 'INVALID_INTEGER');
  const before = input.before === undefined ? undefined : integer(input.before);
  need(before === undefined || before > 0 && input.snapshot !== undefined, 'INVALID_EVENT_CURSOR');
  const requestedSnapshot = input.snapshot === undefined ? undefined : integer(input.snapshot);
  const visible=visibility(user);
  const scope = `${visible.sql} AND json_extract(event,'$.time')>=? AND json_extract(event,'$.time')<?`;
  const parameters = [...visible.args, new Date(from).toISOString(), new Date(to).toISOString()];
  // Never expose a global sequence/count to an empty ordinary-user query.
  const visibleHead = store.get(`SELECT COALESCE(MAX(seq),0) AS n FROM audit WHERE ${scope}`, ...parameters)!.n as number;
  const snapshot = Math.min(requestedSnapshot ?? visibleHead, visibleHead);
  const where = `${scope} AND seq<=?`, args = [...parameters,snapshot];
  const totals = store.get(`SELECT COUNT(*) AS total,COALESCE(SUM(json_extract(event,'$.result')='denied'),0) AS denied,COALESCE(SUM(${quarantined}),0) AS quarantined FROM audit WHERE ${where}`, ...args)!;
  const width = Math.ceil((to - from) / 24), count = Math.ceil((to - from) / width);
  const buckets = Array.from({ length: count }, (_, i) => ({ from: from + i * width, to: Math.min(to,from + (i+1)*width), total: 0, denied: 0, quarantined: 0 }));
  const groups = store.all(`SELECT CAST((CAST(round(unixepoch(json_extract(event,'$.time'),'subsec')*1000) AS INTEGER)-?)/? AS INTEGER) AS bucket, COUNT(*) AS total, COALESCE(SUM(json_extract(event,'$.result')='denied'),0) AS denied, COALESCE(SUM(${quarantined}),0) AS quarantined FROM audit WHERE ${where} GROUP BY bucket`, from, width, ...args);
  for (const group of groups) {
    const bucket = buckets[group.bucket];
    if (bucket) { bucket.total = group.total; bucket.denied = group.denied; bucket.quarantined = group.quarantined; }
  }
  const rows = store.all(`SELECT seq,event FROM audit WHERE ${where}${before === undefined ? '' : ' AND seq<?'} ORDER BY seq DESC LIMIT ?`, ...args,...(before === undefined ? [] : [before]),limit+1);
  const events = rows.slice(0,limit).map(displayEvent);
  const meta: Row = { events, from, to, snapshot, total: totals.total, denied: totals.denied, quarantined: totals.quarantined, buckets, nextBefore: null };
  const cursor = () => { meta.nextBefore = rows.length > events.length && events.length ? events.at(-1)!.seq : null; };
  cursor();
  while (Buffer.byteLength(JSON.stringify({ ok: true, ...meta })) > 12 * 1024 && events.length > 1) { events.pop(); cursor(); }
  need(Buffer.byteLength(JSON.stringify({ ok: true, ...meta })) <= 12 * 1024, 'EVENT_RESPONSE_TOO_LARGE');
  return meta;
}
