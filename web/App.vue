<style scoped>
.file-buttons{flex-wrap:wrap;gap:4px 12px;min-width:145px;max-width:190px}
.file-tools{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:8px}
.file-tools button{font-size:11px}
.file-select{padding-right:0;width:1%}
.file-select input{width:16px;height:16px;margin:0;vertical-align:middle;accent-color:#218368}
</style>
<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue';
import { sha256 } from '@noble/hashes/sha2.js';
import { CHUNK } from '../shared/protocol.ts';
import { Client, human, hashBlob, hex, bindKey, loginWithKey, localGet, localPut, saveJSON } from './client.ts';
import { sessionRequests } from './session-requests.ts';
import AccountAdmin from './AccountAdmin.vue';
import FileAction from './FileAction.vue';
import SendFile from './SendFile.vue';
import DeliveryCenter from './DeliveryCenter.vue';
import Maintenance from './Maintenance.vue';
import MfaSettings from './MfaSettings.vue';
import ScanBadge from './ScanBadge.vue';
import SecurityEvents from './SecurityEvents.vue';
import { downloadReference, downloadAccess } from './download-reference.ts';
type Row = Record<string, any>;
type SavedDownload = { handle: FileSystemFileHandle; offset: number };
type Task = { key: string; owner: string; name: string; kind: 'upload' | 'download'; total: number; done: number; status: string; paused: boolean; running?: boolean; file?: File; row?: Row; error?: string; transferId?: string; resumeKey?: string; terminal?: string; directory?: FileSystemDirectoryHandle; batchFile?: SavedDownload };
const client = new Client(), connection = ref('offline'), user = ref<Row>(), session = ref(''), name = ref('admin'), password = ref(''), busy = ref(false), notice = ref('');
const secureTransport = location.protocol === 'https:';
const tab = ref('files'), files = ref<Row[]>([]), transfers = ref<Row[]>([]), sessions = ref<Row[]>([]), events = ref<Row[]>([]), keys = ref<Row[]>([]), report = ref<Row | null>(null), tasks = ref<Task[]>([]), search = ref(''), auditResult = ref(''), reauth = ref('');
const uploading = ref<HTMLInputElement>(), anchorInput = ref<HTMLInputElement>();
const preparingDownloads = ref(new Set<string>());
const selectedFiles = ref(new Set<string>()), choosingDirectory = ref(false);
const directoryPicker = (window as Window & { showDirectoryPicker?: (options: { mode: 'readwrite' }) => Promise<FileSystemDirectoryHandle> }).showDirectoryPicker;
const reservingBatchNames = new Set<string>();
const registration = ref(''), registering = ref(false), invitation = ref(''), newPassword = ref(''), confirmation = ref(''), currentPassword = ref(''), changing = ref(false);
const passwordError = ref(''), passwordFeedback = ref<HTMLElement>();
const mfaChallenge = ref(''), mfaCode = ref(''), recoveryLogin = ref(false);
const labels = computed<Row>(() => user.value?.recoveryOnly ? { security: '双因素恢复' } : ({ files: '文件工作台', deliveries: '收发文件', security: '安全中心', ...(user.value?.role === 'admin' ? { accounts: '账号与邀请', maintenance: '存储与维护' } : {}), verification: '审计与验证' }));
const accountRpc = computed(() => sessionRequests(client, session.value, () => session.value).rpc);
const accountAdmin = ref<InstanceType<typeof AccountAdmin>>(), deliveryCenter = ref<InstanceType<typeof DeliveryCenter>>(), maintenance = ref<InstanceType<typeof Maintenance>>();
const securityEvents = ref<InstanceType<typeof SecurityEvents>>();
const sending = ref<Row>();
const list = computed(() => files.value.filter(f => f.name.toLowerCase().includes(search.value.toLowerCase())));
const denied = computed(() => events.value.filter(e => e.result === 'denied').length);
const usage = ref<Row>(), fileAction = ref<{ file: Row; mode: 'rename' | 'delete' }>();
const visibleTasks = computed(() => tasks.value.filter(t => t.owner === user.value?.name));
const active = computed(() => visibleTasks.value.filter(t => t.running).length);
const batchFiles = computed(() => list.value.filter(canBatchDownload));
const selectedBatchFiles = computed(() => batchFiles.value.filter(file => selectedFiles.value.has(file.id)));
watch([search, session], () => selectedFiles.value.clear());
const size = (n: number) => n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 ** 2).toFixed(1)} MB`;
const time = (n: number | string) => new Date(n).toLocaleString('zh-CN', { hour12: false });
const percent = (t: Task) => t.total ? Math.floor(t.done / t.total * 100) : t.status === '已完成' ? 100 : 0;
const progressValue = (t: Task) => t.total ? t.done : t.status === '已完成' ? 1 : 0;
function pauseTasks() { for (const t of tasks.value) if (t.status !== '已完成') t.paused = true; }
client.onState = s => connection.value = s;
client.onLost = (reason = '') => { if (user.value) { confirmation.value = ''; invitation.value = ''; } if (['ACCOUNT_DISABLED', 'PASSWORD_CHANGED', 'SESSION_REVOKED', 'MFA_CHANGED'].includes(reason)) notice.value = human(reason); mfaChallenge.value = ''; mfaCode.value = ''; recoveryLogin.value = false; pauseTasks(); user.value = undefined; session.value = ''; tab.value = 'files'; reauth.value = ''; currentPassword.value = ''; newPassword.value = ''; passwordError.value = ''; usage.value = undefined; fileAction.value = undefined; sending.value = undefined; files.value = []; transfers.value = []; sessions.value = []; events.value = []; report.value = null; keys.value = []; };
async function attempt(fn: () => Promise<unknown>) { notice.value = ''; try { await fn(); } catch (e) { notice.value = human(e); } }
async function refresh() {
  if (!user.value || user.value.recoveryOnly) return;
  const scoped = sessionRequests(client, session.value, () => session.value), isAdmin = user.value.role === 'admin';
  const all: Row[] = []; for (let offset = 0; offset <= 1000; offset += 12) { const f = await scoped.rpc('files.list', { offset }); const page = f.meta.files as Row[]; all.push(...page); if (page.length < 12) break; } files.value = all;
  if (fileAction.value) { const current = all.find(f => f.id === fileAction.value!.file.id); if (current) fileAction.value = { ...fileAction.value, file: current }; else fileAction.value = undefined; }
  transfers.value = (await scoped.rpc('transfers.list')).meta.transfers as Row[];
  usage.value = (await scoped.rpc('storage.usage')).meta;
  const e = await scoped.rpc('events.list'); events.value = e.meta.events as Row[];
  const s = await scoped.rpc('sessions.list'); sessions.value = s.meta.sessions as Row[];
  const k = await scoped.rpc('keys.list'); keys.value = k.meta.keys as Row[];
  if (isAdmin) {
    const r = await scoped.rpc('report.latest');
    report.value = r.meta.reportEncoding === 'json' ? JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(r.payload)) : r.meta.report as Row | null;
  }
  if (tab.value === 'accounts') await accountAdmin.value?.refresh();
  if (tab.value === 'deliveries') await deliveryCenter.value?.refresh();
  if (tab.value === 'maintenance') await maintenance.value?.refresh();
}
async function refreshVisible() { await refresh(); if (tab.value === 'security') await securityEvents.value?.refresh(); }
async function login(publicKey = false) {
  busy.value = true;
  await attempt(async () => {
    const r = publicKey ? await loginWithKey(client, name.value) : await client.rpc('auth.password', { name: name.value, password: password.value }); password.value = '';
    if (r.meta.mfaRequired) { mfaChallenge.value = String(r.meta.challenge); mfaCode.value = ''; recoveryLogin.value = false; return; }
    await acceptLogin(r.meta);
  });
  busy.value = false;
}
async function acceptLogin(meta: Row) {
  user.value = meta.user as Row; session.value = String(meta.session); mfaChallenge.value = ''; mfaCode.value = ''; recoveryLogin.value = false;
  tab.value = user.value.recoveryOnly ? 'security' : 'files'; if (!user.value.recoveryOnly) { await refresh(); schedule(); }
}
async function verifyMfa() {
  busy.value = true;
  await attempt(async () => { const r = await client.rpc('auth.mfa', { challenge: mfaChallenge.value, ...(recoveryLogin.value ? { recoveryCode: mfaCode.value } : { code: mfaCode.value }) }); await acceptLogin(r.meta); });
  mfaCode.value = ''; busy.value = false;
}
async function mfaChanged(enabled: boolean) { if (!user.value) return; user.value.mfaEnabled = enabled; user.value.recoveryOnly = false; await attempt(refresh); }
async function registrationPolicy() { registration.value = String((await client.rpc('hello')).meta.registration); }
async function register() {
  busy.value = true;
  await attempt(async () => {
    if (password.value !== confirmation.value) throw new Error('两次口令不一致');
    try { await client.rpc('auth.register', { name: name.value, password: password.value, token: invitation.value }); }
    finally { password.value = ''; confirmation.value = ''; invitation.value = ''; }
    registering.value = false; notice.value = '账号已创建，请使用刚设置的口令登录。';
  });
  busy.value = false;
}
async function changePassword() {
  changing.value = true; passwordError.value = ''; notice.value = '';
  try {
    if (newPassword.value !== confirmation.value) throw new Error('两次新口令不一致，请检查后重新提交。');
    const account = user.value!.name, hasMfa = Boolean(user.value!.mfaEnabled);
    await client.rpc('account.password', { password: currentPassword.value, newPassword: newPassword.value });
    client.disconnect(); tasks.value = []; passwordError.value = ''; await localPut('key:' + account, undefined);
    notice.value = hasMfa ? '口令已修改。全部会话和旧公钥已撤销，双因素设置保留，请使用新口令加验证器验证码登录。' : '口令已修改。全部会话和已绑定公钥已撤销，请用新口令登录；需要公钥登录时请重新绑定。';
  } catch (e) {
    const wrong = e instanceof Error && e.message === 'INVALID_CREDENTIALS';
    passwordError.value = wrong ? '当前口令不正确，请重新输入当前口令。' : human(e);
    if (wrong) currentPassword.value = '';
    await nextTick(); passwordFeedback.value?.focus(); passwordFeedback.value?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } finally { changing.value = false; }
}
async function logout() { busy.value = true; pauseTasks(); try { await attempt(() => client.rpc('auth.logout')); } finally { client.disconnect(); tasks.value = []; busy.value = false; } }
async function enroll() { await attempt(async () => { await bindKey(client, user.value!.name, reauth.value); reauth.value = ''; await refresh(); notice.value = '公钥已绑定。私钥仅保存在此浏览器，不能导出。'; }); }
async function revokeKey(keyId: string) { await attempt(async () => { await client.rpc('keys.revoke', { keyId, password: reauth.value }); reauth.value = ''; await refresh(); }); }
async function revoke(sid: string) { await attempt(async () => { await client.rpc('sessions.revoke', { sessionId: sid }); if (sid !== session.value) await refresh(); }); }
function enqueue(filesToAdd: FileList | null) {
  if (!filesToAdd || !user.value) return;
  for (const file of [...filesToAdd]) { if (visibleTasks.value.some(t => t.kind === 'upload' && t.name === file.name && t.total === file.size && t.status !== '已完成' && !t.terminal)) continue; tasks.value.push({ key: crypto.randomUUID(), owner: user.value.name, name: file.name, total: file.size, done: 0, kind: 'upload', status: '等待传输', paused: false, file }); }
  if (uploading.value) uploading.value.value = ''; schedule();
}
function schedule() {
  if (!user.value || user.value.recoveryOnly) return;
  for (const task of visibleTasks.value) {
    if (active.value >= 3) break;
    if (task.terminal || task.running || task.paused || task.status !== '等待传输') continue;
    if (task.kind === 'upload') void upload(task);
    else void runDownload(task);
  }
}
async function upload(t: Task) {
  if (!t.file || !user.value || t.owner !== user.value.name) return;
  t.running = true; t.status = '计算文件摘要'; t.error = ''; const account = user.value.name;
  const scoped = sessionRequests(client, session.value, () => session.value);
  try {
    const sha = await hashBlob(t.file); if (t.paused) return; scoped.assertCurrent();
    const resumeKey = t.resumeKey = `upload:${account}:${sha}:${t.name}:${t.total}`;
    const remembered = await localGet<string>(resumeKey);
    const existing = transfers.value.find(x => x.name === t.name && x.size === t.total && x.sha256 === sha)?.id;
    let response;
    try { response = await scoped.rpc('upload.init', { name: t.name, size: t.total, sha256: sha, transferId: remembered ?? existing }); }
    catch (e) { if (e instanceof Error && e.message === 'NOT_FOUND') response = await scoped.rpc('upload.init', { name: t.name, size: t.total, sha256: sha }); else throw e; }
    const transferId = t.transferId = String(response.meta.id); await localPut(resumeKey, transferId); t.done = Number(response.meta.offset); t.status = '正在上传'; usage.value = (await scoped.rpc('storage.usage')).meta;
    while (t.done < t.total && !t.paused) {
      const data = new Uint8Array(await t.file.slice(t.done, t.done + CHUNK).arrayBuffer());
      const r = await scoped.rpc('upload.chunk', { transferId, offset: t.done }, data); t.done = Number(r.meta.offset);
    }
    if (!t.paused) { t.status = '服务端完整性校验'; await scoped.rpc('upload.finish', { transferId }); await localPut(resumeKey, undefined); t.status = '已完成'; await refresh(); }
  } catch (e) { t.error = human(e); t.paused = true; }
  finally { if (t.terminal) t.status = t.terminal; else if (t.paused) t.status = '已暂停'; t.running = false; schedule(); }
}
async function cancelPending(row: Row) {
  const scoped = sessionRequests(client, session.value, () => session.value), matching = visibleTasks.value.filter(t => t.transferId === row.id);
  for (const t of matching) t.paused = true;
  await attempt(async () => {
    try { await scoped.rpc('upload.cancel', { transferId: row.id }); }
    catch (e) { if (e instanceof Error && e.message === 'DELETE_FAILED') for (const t of matching) { t.terminal = t.status = '等待取消清理'; } await refresh(); throw e; }
    for (const t of matching) { t.terminal = t.status = '已取消'; if (t.resumeKey) await localPut(t.resumeKey, undefined); }
    await refresh();
  });
}
async function fileChanged(mode: 'rename' | 'delete', file: Row) {
  fileAction.value = undefined;
  for (const t of visibleTasks.value) if (t.kind === 'download' && t.row?.id === file.id) {
    if (mode === 'rename') { t.name = file.name; t.row = file; }
    else if (t.status !== '已完成') { t.paused = true; t.terminal = t.status = '源文件已删除'; }
  }
  await attempt(refresh);
}
async function scanFile(file: Row) {
  const scoped = sessionRequests(client, session.value, () => session.value);
  await attempt(async () => { await scoped.rpc('files.scan', { fileId: file.id }); await refresh(); notice.value = '扫描请求已登记。只有扫描通过后才能下载和交付；检测到威胁或扫描失败时，原文件和占用仍保留。'; });
}
const downloadKey = (row: Row) => downloadReference(row as { id: string; deliveryId?: string });
const downloadPreparing = (row: Row) => preparingDownloads.value.has(`${session.value}:${downloadKey(row)}`);
function unfinishedDownload(row: Row) {
  return visibleTasks.value.find(task => task.kind === 'download' && task.row && !task.terminal &&
    task.status !== '已完成' && downloadKey(task.row) === downloadKey(row));
}
function canBatchDownload(row: Row) {
  return !row.deleting && row.scan?.state === 'clean' && !downloadPreparing(row) && !unfinishedDownload(row);
}
function selectBatchFiles(checked: boolean) {
  selectedFiles.value = new Set(checked ? batchFiles.value.map(file => file.id) : []);
}
function newDownload(row: Row, directory?: FileSystemDirectoryHandle) {
  tasks.value.push({
    key: crypto.randomUUID(), owner: user.value!.name, name: row.name, kind: 'download',
    total: row.size, done: 0, row, status: '等待传输', paused: false, directory,
  });
  return tasks.value[tasks.value.length - 1];
}
async function batchDownload() {
  if (!directoryPicker || choosingDirectory.value || !selectedBatchFiles.value.length) return;
  const selected = new Set(selectedBatchFiles.value.map(file => file.id));
  const capturedSession = session.value, scoped = sessionRequests(client, capturedSession, () => session.value);
  notice.value = '';
  choosingDirectory.value = true;
  try {
    const directory = await directoryPicker.call(window, { mode: 'readwrite' });
    scoped.assertCurrent();
    const ready = files.value.filter(file => selected.has(file.id) && canBatchDownload(file));
    for (const file of ready) newDownload(file, directory);
    selectedFiles.value.clear();
    if (ready.length < selected.size) notice.value = '部分文件状态已变化，请刷新列表后重试。';
    schedule();
  } catch (error) {
    if (session.value === capturedSession && !(error instanceof DOMException && error.name === 'AbortError')) notice.value = human(error);
  } finally { choosingDirectory.value = false; }
}
async function createBatchFile(directory: FileSystemDirectoryHandle, name: string, assertCurrent: () => void) {
  const dot = name.lastIndexOf('.');
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const extension = dot > 0 ? name.slice(dot) : '';
  for (let number = 1; ; number++) {
    const candidate = number === 1 ? name : `${stem} (${number})${extension}`;
    const reservation = candidate.normalize('NFC').toLowerCase();
    if (reservingBatchNames.has(reservation)) continue;
    reservingBatchNames.add(reservation);
    try {
      await directory.getFileHandle(candidate);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'NotFoundError') {
        assertCurrent();
        return await directory.getFileHandle(candidate, { create: true });
      }
      if (!(error instanceof DOMException && error.name === 'TypeMismatchError')) throw error;
    } finally { reservingBatchNames.delete(reservation); }
  }
}
function resumeDownload(task: Task) {
  if (!task.directory) { void download(task.row!); return; }
  task.paused = false;
  task.status = '等待传输';
  schedule();
}
async function download(row: Row) {
  if (!user.value || active.value >= 3) { notice.value = '当前已有三个任务运行，请稍后重试'; return; }
  if (downloadPreparing(row)) return;
  const existing = unfinishedDownload(row);
  if (existing && (existing.running || !existing.paused)) { notice.value = '此文件已在下载队列中'; return; }
  if (existing?.directory) { resumeDownload(existing); return; }
  const cacheKey = `download:${user.value.name}:${downloadKey(row)}`;
  const capturedSession = session.value, scoped = sessionRequests(client, capturedSession, () => session.value);
  const preparationKey = `${capturedSession}:${downloadKey(row)}`; preparingDownloads.value.add(preparationKey);
  let handle: FileSystemFileHandle | undefined, saved: SavedDownload | undefined;
  try {
    saved = await localGet<SavedDownload>(cacheKey);
    scoped.assertCurrent();
    if (saved) { const permission = await (saved.handle as any).requestPermission({ mode: 'readwrite' }); if (permission === 'granted') handle = saved.handle; }
    if (!handle && 'showSaveFilePicker' in window) handle = await (window as any).showSaveFilePicker({ suggestedName: row.name });
    if (!handle && row.size > 32 * 1024 ** 2) throw new Error('大文件与断点下载请使用桌面版 Edge / Chrome');
    scoped.assertCurrent(); if (active.value >= 3) throw new Error('当前已有三个任务运行，请稍后重试');
    if (unfinishedDownload(row) !== existing) throw new Error('此文件已在下载队列中');
  } catch (e) { if (session.value === capturedSession && !(e instanceof DOMException && e.name === 'AbortError')) notice.value = human(e); return; }
  finally { preparingDownloads.value.delete(preparationKey); }
  await runDownload(existing ?? newDownload(row), handle, saved);
}
async function runDownload(t: Task, handle = t.batchFile?.handle, saved = t.batchFile) {
  const row = t.row!;
  const scoped = sessionRequests(client, session.value, () => session.value);
  const cacheKey = `download:${t.owner}:${downloadKey(row)}`;
  Object.assign(t, { done: 0, paused: false, running: true, error: '', status: '正在下载' });
  let writer: FileSystemWritableFileStream | undefined; const hash = sha256.create(), parts: BlobPart[] = []; let committed = 0;
  try {
    if (handle && saved && handle === saved.handle) {
      const local = await handle.getFile(); t.done = Math.min(saved.offset, local.size, row.size);
      for (let i = 0; i < t.done; i += CHUNK) hash.update(new Uint8Array(await local.slice(i, Math.min(i + CHUNK, t.done)).arrayBuffer()));
    }
    const info = await scoped.rpc('download.init', { ...downloadAccess(row as { id: string; deliveryId?: string }), offset: t.done, prefixHash: hex(hash.clone().digest()) });
    if (info.meta.id !== row.id || info.meta.size !== row.size || info.meta.sha256 !== row.sha256) throw new Error('HASH_MISMATCH');
    if (t.paused) return;
    if (!handle && t.directory) {
      handle = await createBatchFile(t.directory, row.name, scoped.assertCurrent);
      t.batchFile = { handle, offset: 0 };
      scoped.assertCurrent();
    }
    if (handle) { writer = await handle.createWritable({ keepExistingData: true }); await writer.truncate(t.done); await writer.seek(t.done); committed = t.done; }
    while (t.done < row.size && !t.paused) {
      const r = await scoped.rpc('download.chunk', { ...downloadAccess(row as { id: string; deliveryId?: string }), offset: t.done });
      const next = t.done + r.payload.length;
      if (r.meta.offset !== t.done || r.payload.length === 0 || next > t.total || r.meta.next !== next || r.meta.eof !== (next === t.total)) throw new Error('下载偏移校验失败');
      hash.update(r.payload); if (writer) await writer.write(new Uint8Array(r.payload).buffer); else parts.push(new Uint8Array(r.payload).buffer);
      t.done += r.payload.length;
      if (handle && writer && t.done - committed >= 4 * 1024 ** 2) { await writer.close(); writer = undefined; committed = t.done; if (t.batchFile) t.batchFile.offset = committed; await localPut(cacheKey, { handle, offset: committed }); writer = await handle.createWritable({ keepExistingData: true }); await writer.seek(t.done); }
    }
    if (!t.paused && hex(hash.digest()) !== row.sha256) throw new Error('HASH_MISMATCH');
    if (writer) { await writer.close(); writer = undefined; committed = t.done; if (t.batchFile) t.batchFile.offset = committed; await localPut(cacheKey, t.paused ? { handle, offset: committed } : undefined); }
    if (!t.paused) {
      if (!handle) { const url = URL.createObjectURL(new Blob(parts)); const a = document.createElement('a'); a.href = url; a.download = row.name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 10000); }
      t.status = '已完成';
      t.batchFile = undefined;
      t.directory = undefined;
    }
  } catch (e) {
    t.error = human(e); t.paused = true;
    if (e instanceof Error && ['NOT_FOUND', 'FILE_DELETING', 'DELIVERY_UNAVAILABLE', 'DELIVERY_EXPIRED'].includes(e.message)) { t.terminal = row.deliveryId ? e.message === 'DELIVERY_EXPIRED' ? '接收授权已到期' : '接收授权已失效' : e.message === 'NOT_FOUND' ? '源文件已删除' : '源文件待删除'; await localPut(cacheKey, undefined); }
    if (e instanceof Error && ['PREFIX_MISMATCH', 'HASH_MISMATCH'].includes(e.message)) {
      if (t.batchFile) t.batchFile.offset = 0;
      await localPut(cacheKey, undefined);
      if (writer) { await writer.abort().catch(() => {}); writer = undefined; }
    }
  }
  finally {
    if (writer) try { await writer.close(); if (handle) await localPut(cacheKey, t.terminal ? undefined : { handle, offset: t.done }); } catch { /* Keep the last committed checkpoint. */ }
    if (t.terminal) t.status = t.terminal; else if (t.paused) t.status = '已暂停'; t.running = false; schedule();
  }
}
async function verifyLogs(anchor?: unknown) { await attempt(async () => { const r = await client.rpc('audit.verify', anchor ? { checkpoint: anchor } : {}); auditResult.value = r.meta.ok ? `校验通过 · 已检查 ${r.meta.count} 条记录${anchor ? '，与独立检查点一致' : '（尚未对照独立检查点）'}` : `校验失败 · ${r.meta.reason}，记录位置 ${r.meta.at ?? '检查点'}`; }); }
async function exportLogs() { await attempt(async () => { const rows: Row[] = []; let after = 0, checkpoint: unknown; while (true) { const r = await client.rpc('audit.page', { after }); const batch = r.meta.rows as Row[]; checkpoint = r.meta.checkpoint; rows.push(...batch); if (batch.length < 8) break; after = batch[batch.length - 1].seq; } saveJSON('safedrop-audit.json', { version: 1, rows, checkpoint }); saveJSON('safedrop-checkpoint.json', checkpoint); }); }
async function loadAnchor(event: Event) { await attempt(async () => { const f = (event.target as HTMLInputElement).files?.[0]; if (f && f.size < 4096) await verifyLogs(JSON.parse(await f.text())); }); }
let poll: ReturnType<typeof setInterval>, heartbeat: ReturnType<typeof setInterval>;
onMounted(() => { void registrationPolicy().catch(e => notice.value = human(e)); poll = setInterval(() => { if (user.value && !active.value) void refresh().catch(() => {}); }, 10000); heartbeat = setInterval(() => { if (connection.value === 'online') void client.rpc('ping').catch(() => {}); }, 15000); });
onUnmounted(() => { clearInterval(poll); clearInterval(heartbeat); client.stop(); });
</script>

<template>
  <div v-if="!user" class="login-shell">
    <section class="login-story"><a class="brand"><span class="brand-icon">S</span> SafeDrop<span class="brand-tag">SECURE TRANSFER</span></a><div class="story-body"><span class="eyebrow">安全文件传输与审计</span><h1>每一次传输，<br>都有安全的依据。</h1><p>加密传输、身份验证与可追溯记录，<br>在一个工作空间里完成。</p><div class="story-line"><i></i> HTTPS / WSS <span>·</span> SFT/1 <span>·</span> SHA-256</div></div><span class="story-foot">传输可控，记录可查。</span></section>
    <section class="login-panel"><div class="login-form"><span class="eyebrow">{{ mfaChallenge ? 'VERIFY YOUR IDENTITY' : registering ? 'JOIN YOUR WORKSPACE' : 'WELCOME BACK' }}</span><h2>{{ mfaChallenge ? '完成双因素认证' : registering ? '使用邀请创建账号' : '登录安全工作空间' }}</h2><p class="muted">{{ mfaChallenge ? '第二步验证通过前，不会建立可操作文件的会话。' : registering ? '输入管理员提供的邀请，自行设置账号和口令。' : '使用你的账号，或此设备已绑定的公钥。' }}</p>
      <form v-if="registering" @submit.prevent="register"><label>邀请令牌<input v-model="invitation" autocomplete="off" maxlength="64" required></label><label>新账号<input v-model="name" autocomplete="username" pattern="[a-zA-Z0-9_-]{3,32}" minlength="3" maxlength="32" placeholder="3～32 位字母、数字、下划线或短横线" required></label><label>设置口令<input v-model="password" type="password" autocomplete="new-password" minlength="12" maxlength="256" placeholder="12～256 个字符" required></label><label>再次输入口令<input v-model="confirmation" type="password" autocomplete="new-password" minlength="12" maxlength="256" required></label><button class="primary full" :disabled="busy">{{ busy ? '正在创建…' : '创建账号' }}</button></form>
      <form v-else-if="mfaChallenge" @submit.prevent="verifyMfa">
        <p class="notice">口令已验证。{{ recoveryLogin ? '恢复码仅用于重新绑定验证器，不能直接进入管理功能。' : '请使用验证器中尚未使用的六位验证码完成登录。' }}</p>
        <label>{{ recoveryLogin ? '一次性恢复码' : '验证器验证码' }}<input v-model="mfaCode" :type="recoveryLogin ? 'password' : 'text'" :inputmode="recoveryLogin ? 'text' : 'numeric'" :autocomplete="recoveryLogin ? 'off' : 'one-time-code'" :maxlength="recoveryLogin ? 64 : 6" :pattern="recoveryLogin ? undefined : '[0-9]{6}'" required :placeholder="recoveryLogin ? '完整输入一份未使用的恢复码' : '六位数字'"></label>
        <button class="primary full" :disabled="busy || !mfaCode">{{ busy ? '正在验证…' : recoveryLogin ? '验证恢复码并重新绑定' : '验证验证码并登录' }}</button>
        <button type="button" class="link full" :disabled="busy" @click="recoveryLogin = !recoveryLogin; mfaCode = ''; notice = ''">{{ recoveryLogin ? '改用验证器验证码' : '无法使用验证器，改用恢复码' }}</button>
        <button type="button" class="secondary full" :disabled="busy" @click="client.disconnect(); notice = ''">取消并返回口令登录</button>
      </form>
      <form v-else @submit.prevent="login()"><label>账号<input v-model="name" autocomplete="username" maxlength="64" required placeholder="输入账号"></label><label>口令<input v-model="password" type="password" autocomplete="current-password" maxlength="256" placeholder="输入口令"></label><button class="primary full" :disabled="busy || !password">{{ busy ? '正在验证…' : '验证身份并登录 →' }}</button></form>
      <button v-if="!registering && !mfaChallenge" class="secondary full" :disabled="busy" @click="login(true)">使用本机公钥登录</button><button v-if="!mfaChallenge" class="link full" :disabled="busy" @click="attempt(async () => { await registrationPolicy(); if (registering) registering = false; else if (registration === 'invitation') registering = true; else notice = '当前已关闭自助注册，请联系管理员'; password = ''; confirmation = ''; invitation = ''; })">{{ registering ? '返回登录' : '使用邀请注册' }}</button>
      <div v-if="notice" class="notice" role="alert">{{ notice }}</div><div class="login-hint"><i :class="connection === 'online' ? 'dot' : 'dot gray'"></i>{{ connection === 'online' ? (secureTransport ? '安全通道已连接' : '本地界面测试连接') : '等待安全连接' }}<small>默认邀请注册；管理员可关闭自助注册。首次绑定公钥需要验证口令。</small></div></div></section>
  </div>
  <div v-else class="app-shell">
    <aside class="sidebar"><a class="brand"><span class="brand-icon">S</span>SafeDrop</a><div class="workspace-label">安全文件工作空间</div><nav><button v-for="(label, key) in labels" :key="key" :class="{ selected: tab === key }" @click="tab = String(key)"><span>{{ key === 'files' ? '▤' : key === 'security' ? '◈' : key === 'deliveries' ? '↔' : '✓' }}</span>{{ label }}<b v-if="key === 'files' && active">{{ active }}</b></button></nav><div class="sidebar-bottom"><div class="secure-mark"><i class="dot"></i>{{ secureTransport ? 'SFT/1 安全通道' : 'SFT/1 本地界面测试' }}<small>文件完成后保持连接</small></div><div class="profile"><span class="avatar">{{ user.name[0].toUpperCase() }}</span><div>{{ user.name }}<small>{{ user.role === 'admin' ? '管理员' : '个人空间' }} · {{ user.tier === 'vip' ? 'VIP' : '标准' }}</small></div><button class="logout" title="退出登录" @click="logout">↗</button></div></div></aside>
    <main><header class="topbar"><span>工作空间 <span class="crumb">/</span> {{ labels[tab] }}</span><span class="connection"><i :class="connection === 'online' ? 'dot' : 'dot gray'"></i>{{ connection === 'online' ? (secureTransport ? '安全连接已建立' : '本地界面测试连接') : '连接已断开' }}</span></header><div class="page"><div class="page-heading"><div><span class="eyebrow">{{ tab === 'files' ? 'YOUR SECURE WORKSPACE' : tab === 'security' ? 'VISIBILITY & CONTROL' : tab === 'deliveries' ? 'SEND & RECEIVE' : tab === 'maintenance' ? 'STORAGE & MAINTENANCE' : tab === 'accounts' ? 'ACCOUNTS & INVITATIONS' : 'VERIFY, THEN TRUST' }}</span><h1>{{ labels[tab] }}</h1><p>{{ user.recoveryOnly ? '使用当前口令和新验证器完成重新绑定，恢复正常访问。' : tab === 'files' ? '管理文件与传输任务，每一次完成都经过完整性校验。' : tab === 'security' ? '查看真实安全事件，管理在线会话与本机身份。' : tab === 'deliveries' ? '发送自己的文件，查看收到的文件并管理接收授权。' : tab === 'maintenance' ? '查看资源预算，维护未完成上传与受保护备份。' : tab === 'accounts' ? '控制注册入口，生成单次邀请并管理账号状态。' : '用可复现的测试和可校验的记录，验证安全设计。' }}</p></div><button class="secondary" @click="attempt(refreshVisible)">↻ 刷新数据</button></div><div v-if="notice" class="notice dismiss" role="status">{{ notice }}<button @click="notice = ''">×</button></div>
    <template v-if="tab === 'files'"><div class="stats"><article><span>已用空间</span><strong>{{ usage ? size(usage.used) : '—' }}</strong><p>已完成文件，含删除待重试的占用</p></article><article><span>上传预留空间</span><strong>{{ usage ? size(usage.reserved) : '—' }}</strong><p>未完成上传按完整文件大小预留</p></article><article><span>可用空间</span><strong>{{ usage ? size(usage.available) : '—' }}</strong><p>账号配额减去已用与预留空间</p></article></div><div class="quota-summary"><span>账号配额 {{ usage ? size(usage.limit) : '—' }}</span><span>我的文件 {{ usage?.fileCount ?? '—' }} 个</span><span>未完成上传 {{ usage?.transferCount ?? '—' }} 个</span><span>传输上限 {{ size(user.rate) }}/s · 双向及多会话共享</span></div><p v-if="usage?.overQuota" class="form-error">当前占用超过账号配额，请删除文件或取消未完成上传后再上传。</p>

    <section class="upload-zone" @dragover.prevent @drop.prevent="enqueue($event.dataTransfer?.files ?? null)"><div class="upload-icon">↑</div><div><h3>将文件拖到这里，开始安全传输</h3><p>支持多任务与断点续传 · 单文件最大 512 MB</p></div><button class="primary" @click="uploading?.click()">＋ 选择文件</button><input ref="uploading" hidden type="file" multiple @change="enqueue(($event.target as HTMLInputElement).files)"></section>
    <section class="card"><div class="card-heading"><h3>我的文件 <span class="count">{{ files.length }}</span></h3><div class="file-tools"><input v-model="search" class="search" placeholder="搜索文件名" aria-label="搜索文件"><button v-if="directoryPicker" type="button" class="secondary" :disabled="!selectedBatchFiles.length || choosingDirectory" @click="batchDownload">{{ choosingDirectory ? '等待选择目录…' : selectedBatchFiles.length ? `批量下载 (${selectedBatchFiles.length})` : '批量下载' }}</button></div></div><p class="report-meta">上传完成后自动进行本地安全扫描，通过后才可下载或发送。旧文件需要请求扫描；隔离或失败不会自动删除文件，也不会释放占用。</p><div class="table-scroll"><table><thead><tr><th v-if="directoryPicker" class="file-select"><input type="checkbox" aria-label="选择当前列表中可批量下载的文件" :checked="batchFiles.length > 0 && selectedBatchFiles.length === batchFiles.length" :indeterminate="selectedBatchFiles.length > 0 && selectedBatchFiles.length < batchFiles.length" :disabled="!batchFiles.length || choosingDirectory" @change="selectBatchFiles(($event.target as HTMLInputElement).checked)"></th><th>文件名称</th><th>大小</th><th>上传时间</th><th>完整性与扫描</th><th></th></tr></thead><tbody><tr v-for="f in list" :key="f.id"><td v-if="directoryPicker" class="file-select"><input type="checkbox" :checked="selectedFiles.has(f.id)" @change="($event.target as HTMLInputElement).checked ? selectedFiles.add(f.id) : selectedFiles.delete(f.id)" :aria-label="`选择 ${f.name}`" :disabled="choosingDirectory || !canBatchDownload(f)"></td><td><div class="file-name"><span class="file-icon">▤</span><div><strong>{{ f.name }}</strong><small :title="f.sha256">{{ f.sha256.slice(0, 20) }}…</small></div></div></td><td>{{ size(f.size) }}</td><td>{{ time(f.created) }}</td><td><span :class="f.deleting ? 'badge red' : 'badge'">{{ f.deleting ? '删除待重试' : '✓ SHA-256' }}</span><ScanBadge :scan="f.scan" /></td><td class="file-buttons"><button class="link" :disabled="f.deleting || f.scan?.state !== 'clean' || downloadPreparing(f)" @click="download(f)">{{ downloadPreparing(f) ? '等待文件授权…' : '下载 / 续传 ↓' }}</button><button class="link" :disabled="f.deleting || f.scan?.state !== 'clean'" @click="sending = f; fileAction = undefined">发送给用户</button><button class="link" :disabled="f.deleting || ['pending','scanning'].includes(f.scan?.state)" @click="scanFile(f)">{{ f.scan?.state === 'clean' ? '重新扫描' : f.scan?.state === 'error' || f.scan?.state === 'quarantined' ? '重试扫描' : '请求扫描' }}</button><button class="link" :disabled="f.deleting || f.scan?.state === 'scanning'" @click="sending = undefined; fileAction = { file: f, mode: 'rename' }">重命名</button><button class="link danger" @click="sending = undefined; fileAction = { file: f, mode: 'delete' }">{{ f.deleting ? '重试删除' : '删除' }}</button></td></tr><tr v-if="!list.length"><td :colspan="directoryPicker ? 6 : 5" class="empty">{{ search ? '没有匹配的文件' : '空间已准备就绪，上传第一个文件吧。' }}</td></tr></tbody></table></div></section>
    <SendFile v-if="sending" :key="sending.id" :file="sending" :rpc="accountRpc" @close="sending = undefined" />
    <FileAction v-if="fileAction" :key="fileAction.file.id + fileAction.mode" :file="fileAction.file" :mode="fileAction.mode" :rpc="accountRpc" @close="fileAction = undefined" @changed="fileChanged" @refresh="attempt(refresh)" />

    <section v-if="transfers.length" class="card"><div class="card-heading"><h3>服务端未完成上传</h3><span class="muted">取消待重试的任务仍占用预留空间</span></div><div v-for="t in transfers" :key="t.id" class="pending-row"><span>{{ t.name }}</span><small>{{ t.deleting ? '取消待重试 · ' : '' }}{{ size(t.offset) }} / {{ size(t.size) }}</small><button class="link danger" @click="cancelPending(t)">{{ t.deleting ? '重试取消清理' : '取消并清理上传' }}</button></div></section><p class="footnote">断点下载建议使用桌面版 Edge / Chrome；每 4 MB 保存检查点，暂停时保存当前位置。其他浏览器支持 32 MB 以内的普通下载。</p>
    </template>
    <section v-if="(tab === 'files' || tab === 'deliveries') && visibleTasks.length" class="card"><div class="card-heading"><h3>传输队列 <span class="count">{{ active }} 进行中</span></h3><span class="muted">最多同时运行 3 个任务</span></div><div v-for="t in visibleTasks" :key="t.key" class="task"><span class="transfer-symbol">{{ t.kind === 'upload' ? '↑' : '↓' }}</span><div class="task-body"><div class="task-title"><strong>{{ t.name }}</strong><span>{{ t.status }} · {{ percent(t) }}%</span></div><progress :value="progressValue(t)" :max="t.total || 1"></progress><small>{{ size(t.done) }} / {{ size(t.total) }}<span v-if="t.error" class="error-text"> · {{ t.error }}</span></small></div><button v-if="t.running" class="secondary small" @click="t.paused = true">暂停</button><button v-else-if="!t.terminal && t.paused && t.kind === 'upload'" class="secondary small" @click="t.paused = false; t.status = '等待传输'; schedule()">继续</button><button v-else-if="!t.terminal && t.paused && t.row" class="secondary small" :disabled="downloadPreparing(t.row)" @click="resumeDownload(t)">{{ downloadPreparing(t.row) ? '等待文件授权…' : '恢复下载' }}</button><span v-else class="badge">{{ t.status }}</span></div></section>
    <MfaSettings v-if="tab === 'security' && user.role === 'admin'" :key="session" :rpc="accountRpc" @changed="mfaChanged" />
    <template v-if="tab === 'security' && !user.recoveryOnly"><div class="stats"><article><span>在线会话</span><strong>{{ sessions.length }}</strong><p>可即时撤销指定会话</p></article><article><span>最近拒绝事件</span><strong>{{ denied }}</strong><p>基于当前可见的最近事件</p></article><article><span>已绑定公钥</span><strong>{{ keys.length }}</strong><p>标准 P-256 挑战签名</p></article></div><SecurityEvents ref="securityEvents" :rpc="accountRpc" :admin="user.role === 'admin'" /><section class="card"><div class="card-heading"><h3>在线会话</h3><span class="muted">仅管理自己的会话</span></div><div v-for="s in sessions" :key="s.id" class="session-row"><span class="session-icon">▣</span><div><strong>{{ s.agent.slice(0, 72) }}</strong><small>{{ s.ip }} · {{ time(s.created) }}</small></div><span v-if="s.id === session" class="badge">当前会话</span><button class="secondary small" @click="revoke(s.id)">{{ s.id === session ? '退出本会话' : '撤销会话' }}</button></div></section><section class="card"><div class="card-heading"><h3>修改口令</h3><span class="muted">修改后全部会话与已绑定公钥失效</span></div><form class="account-content password-form" @submit.prevent="changePassword"><div v-if="passwordError" ref="passwordFeedback" class="form-error" role="alert" tabindex="-1"><strong>口令未修改</strong><p>{{ passwordError }}</p></div><p class="muted">包括当前会话在内的传输将停止，文件和续传任务保留。请重新登录，并按需重新绑定公钥。</p><label>当前口令<input v-model="currentPassword" type="password" autocomplete="current-password" maxlength="256" required></label><label>新口令<input v-model="newPassword" type="password" autocomplete="new-password" minlength="12" maxlength="256" placeholder="12～256 个字符" required></label><label>确认新口令<input v-model="confirmation" type="password" autocomplete="new-password" minlength="12" maxlength="256" required></label><button class="primary" :disabled="changing">{{ changing ? '正在修改…' : '修改口令并退出全部会话' }}</button></form></section><section class="card"><div class="card-heading"><h3>公钥身份管理</h3><span class="muted">私钥留在浏览器内，不可导出</span></div><p v-if="user.mfaEnabled" class="account-content muted">已开启管理员双因素认证，请使用口令加验证码登录；本机公钥绑定已停用。</p><div class="key-form"><label>绑定或撤销前，请重新验证口令<input v-model="reauth" type="password" autocomplete="current-password" placeholder="输入当前账号口令"></label><button class="primary" :disabled="!reauth || user.mfaEnabled" @click="enroll">绑定本机公钥</button></div><div v-for="k in keys" :key="k.id" class="pending-row"><span>{{ k.label }}</span><small>{{ time(k.created) }}</small><button class="link danger" :disabled="!reauth" @click="revokeKey(k.id)">撤销公钥</button></div></section></template>
    <DeliveryCenter v-if="tab === 'deliveries'" ref="deliveryCenter" :key="session" :rpc="accountRpc" :download="download" :preparing="downloadPreparing" />
    <Maintenance v-if="tab === 'maintenance' && user.role === 'admin'" ref="maintenance" :key="session" :rpc="accountRpc" />
    <AccountAdmin ref="accountAdmin" v-if="tab === 'accounts' && user.role === 'admin'" :key="session" :rpc="accountRpc" />
    <template v-if="tab === 'verification'"><div v-if="user.role !== 'admin'" class="card empty">审计导出与安全验证报告由管理员查看。个人安全记录可在安全中心查看。</div><template v-else><section class="card verification-card"><div><span class="eyebrow">TAMPER-EVIDENT AUDIT</span><h2>让操作记录可以被独立检查。</h2><p>哈希链检查日志修改；独立保存的检查点帮助发现历史重写和截断。</p></div><div class="verify-actions"><button class="primary" @click="verifyLogs()">校验当前审计链</button><button class="secondary" @click="exportLogs">导出日志与检查点</button><button class="secondary" @click="anchorInput?.click()">对照已有检查点</button><input ref="anchorInput" hidden type="file" accept="application/json,.json" @change="loadAnchor"></div><div v-if="auditResult" class="notice">{{ auditResult }}</div><small class="muted">检查点应保存在服务器之外；哈希链本身不能阻止持有全部数据的攻击者整体重算。</small></section><section class="card"><div class="card-heading"><h3>自动安全验证报告</h3><span class="badge" v-if="report">{{ report.passed }} / {{ report.results.length }} 通过</span></div><template v-if="report"><div class="report-meta">运行时间 {{ time(report.created) }} · Node {{ report.node }} · {{ report.platform }}</div><div v-for="r in report.results" :key="r.name" class="test-row"><span :class="r.ok ? 'badge' : 'badge red'">{{ r.ok ? 'PASS' : 'FAIL' }}</span><div><strong>{{ r.name }}</strong><small>{{ r.detail }}</small></div><span class="muted">{{ r.ms }} ms</span></div><div class="report-meta"><button class="secondary" @click="saveJSON('safedrop-security-report.json', report)">导出验证报告</button></div></template><div v-else class="empty">尚未生成测试报告。请在本地运行验收工具后刷新。<small>验收工具独立运行，服务端不提供触发测试的公共接口。</small></div></section></template></template>
    </div><footer>SafeDrop <span>安全文件传输与审计</span><span>安全传输 · 可验证记录</span></footer></main>
  </div>
</template>
