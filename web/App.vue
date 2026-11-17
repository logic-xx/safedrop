<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { sha256 } from '@noble/hashes/sha2.js';
import { CHUNK } from '../shared/protocol.ts';
import { Client, human, hashBlob, hex, bindKey, loginWithKey, localGet, localPut, saveJSON } from './client.ts';
import { sessionRequests } from './session-requests.ts';
type Row = Record<string, any>;
type Task = { key: string; owner: string; name: string; kind: 'upload' | 'download'; total: number; done: number; status: string; paused: boolean; running?: boolean; file?: File; row?: Row; error?: string };
const client = new Client(), connection = ref('offline'), user = ref<Row>(), session = ref(''), name = ref('admin'), password = ref(''), busy = ref(false), notice = ref('');
const secureTransport = location.protocol === 'https:';
const tab = ref('files'), files = ref<Row[]>([]), transfers = ref<Row[]>([]), sessions = ref<Row[]>([]), events = ref<Row[]>([]), keys = ref<Row[]>([]), report = ref<Row | null>(null), tasks = ref<Task[]>([]), search = ref(''), auditResult = ref(''), reauth = ref('');
const uploading = ref<HTMLInputElement>(), anchorInput = ref<HTMLInputElement>();
const preparingDownloads = ref(new Set<string>());
const labels: Row = { files: '文件工作台', security: '安全中心', verification: '审计与验证' };
const list = computed(() => files.value.filter(f => f.name.toLowerCase().includes(search.value.toLowerCase())));
const denied = computed(() => events.value.filter(e => e.result === 'denied').length);
const total = computed(() => files.value.reduce((n, f) => n + f.size, 0));
const visibleTasks = computed(() => tasks.value.filter(t => t.owner === user.value?.name));
const active = computed(() => visibleTasks.value.filter(t => t.running).length);
const size = (n: number) => n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 ** 2).toFixed(1)} MB`;
const time = (n: number | string) => new Date(n).toLocaleString('zh-CN', { hour12: false });
const percent = (t: Task) => t.total ? Math.floor(t.done / t.total * 100) : t.status === '已完成' ? 100 : 0;
const progressValue = (t: Task) => t.total ? t.done : t.status === '已完成' ? 1 : 0;
function pauseTasks() { for (const t of tasks.value) if (t.status !== '已完成') t.paused = true; }
client.onState = s => connection.value = s;
client.onLost = () => { pauseTasks(); user.value = undefined; session.value = ''; reauth.value = ''; files.value = []; transfers.value = []; sessions.value = []; events.value = []; report.value = null; keys.value = []; };
async function attempt(fn: () => Promise<unknown>) { notice.value = ''; try { await fn(); } catch (e) { notice.value = human(e); } }
async function refresh() {
  if (!user.value) return;
  const scoped = sessionRequests(client, session.value, () => session.value), isAdmin = user.value.role === 'admin';
  const all: Row[] = []; for (let offset = 0; offset <= 1000; offset += 12) { const f = await scoped.rpc('files.list', { offset }); const page = f.meta.files as Row[]; all.push(...page); if (page.length < 12) break; } files.value = all;
  transfers.value = (await scoped.rpc('transfers.list')).meta.transfers as Row[];
  const e = await scoped.rpc('events.list'); events.value = e.meta.events as Row[];
  const s = await scoped.rpc('sessions.list'); sessions.value = s.meta.sessions as Row[];
  const k = await scoped.rpc('keys.list'); keys.value = k.meta.keys as Row[];
  if (isAdmin) report.value = (await scoped.rpc('report.latest')).meta.report as Row | null;
}
async function login(publicKey = false) {
  busy.value = true;
  await attempt(async () => { const r = publicKey ? await loginWithKey(client, name.value) : await client.rpc('auth.password', { name: name.value, password: password.value }); user.value = r.meta.user as Row; session.value = String(r.meta.session); password.value = ''; await refresh(); schedule(); });
  busy.value = false;
}
async function logout() { busy.value = true; pauseTasks(); try { await attempt(() => client.rpc('auth.logout')); } finally { client.disconnect(); tasks.value = []; busy.value = false; } }
async function enroll() { await attempt(async () => { await bindKey(client, user.value!.name, reauth.value); reauth.value = ''; await refresh(); notice.value = '公钥已绑定。私钥仅保存在此浏览器，不能导出。'; }); }
async function revokeKey(keyId: string) { await attempt(async () => { await client.rpc('keys.revoke', { keyId, password: reauth.value }); reauth.value = ''; await refresh(); }); }
async function revoke(sid: string) { await attempt(async () => { await client.rpc('sessions.revoke', { sessionId: sid }); if (sid !== session.value) await refresh(); }); }
function enqueue(filesToAdd: FileList | null) {
  if (!filesToAdd || !user.value) return;
  for (const file of [...filesToAdd]) { if (visibleTasks.value.some(t => t.kind === 'upload' && t.name === file.name && t.total === file.size && t.status !== '已完成')) continue; tasks.value.push({ key: crypto.randomUUID(), owner: user.value.name, name: file.name, total: file.size, done: 0, kind: 'upload', status: '等待传输', paused: false, file }); }
  if (uploading.value) uploading.value.value = ''; schedule();
}
function schedule() { for (const t of visibleTasks.value) { if (active.value >= 3) break; if (!t.running && !t.paused && t.status === '等待传输') void upload(t); } }
async function upload(t: Task) {
  if (!t.file || !user.value || t.owner !== user.value.name) return;
  t.running = true; t.status = '计算文件摘要'; t.error = ''; const account = user.value.name;
  const scoped = sessionRequests(client, session.value, () => session.value);
  try {
    const sha = await hashBlob(t.file); if (t.paused) return; scoped.assertCurrent();
    const resumeKey = `upload:${account}:${sha}:${t.name}:${t.total}`;
    const remembered = await localGet<string>(resumeKey);
    const existing = transfers.value.find(x => x.name === t.name && x.size === t.total && x.sha256 === sha)?.id;
    let response;
    try { response = await scoped.rpc('upload.init', { name: t.name, size: t.total, sha256: sha, transferId: remembered ?? existing }); }
    catch (e) { if (e instanceof Error && e.message === 'NOT_FOUND') response = await scoped.rpc('upload.init', { name: t.name, size: t.total, sha256: sha }); else throw e; }
    const transferId = String(response.meta.id); await localPut(resumeKey, transferId); t.done = Number(response.meta.offset); t.status = '正在上传';
    while (t.done < t.total && !t.paused) {
      const data = new Uint8Array(await t.file.slice(t.done, t.done + CHUNK).arrayBuffer());
      const r = await scoped.rpc('upload.chunk', { transferId, offset: t.done }, data); t.done = Number(r.meta.offset);
    }
    if (!t.paused) { t.status = '服务端完整性校验'; await scoped.rpc('upload.finish', { transferId }); await localPut(resumeKey, undefined); t.status = '已完成'; await refresh(); }
  } catch (e) { t.error = human(e); t.paused = true; }
  finally { if (t.paused) t.status = '已暂停'; t.running = false; schedule(); }
}
async function cancelPending(row: Row) { await attempt(async () => { await client.rpc('upload.cancel', { transferId: row.id }); await refresh(); }); }
function downloadPreparing(row: Row) { return preparingDownloads.value.has(`${session.value}:${row.id}`); }
async function download(row: Row) {
  if (!user.value || active.value >= 3) { notice.value = '当前已有三个任务运行，请稍后重试'; return; }
  if (downloadPreparing(row)) return;
  if (visibleTasks.value.some(t => t.running && t.kind === 'download' && t.row?.id === row.id)) { notice.value = '此文件已在下载中'; return; }
  const account = user.value.name, cacheKey = `download:${account}:${row.id}`;
  const capturedSession = session.value, scoped = sessionRequests(client, capturedSession, () => session.value);
  const preparationKey = `${capturedSession}:${row.id}`; preparingDownloads.value.add(preparationKey);
  let handle: FileSystemFileHandle | undefined, saved: { handle: FileSystemFileHandle; offset: number } | undefined;
  try {
    saved = await localGet<{ handle: FileSystemFileHandle; offset: number }>(cacheKey);
    scoped.assertCurrent();
    if (saved) { const permission = await (saved.handle as any).requestPermission({ mode: 'readwrite' }); if (permission === 'granted') handle = saved.handle; }
    if (!handle && 'showSaveFilePicker' in window) handle = await (window as any).showSaveFilePicker({ suggestedName: row.name });
    if (!handle && row.size > 32 * 1024 ** 2) throw new Error('大文件与断点下载请使用桌面版 Edge / Chrome');
    scoped.assertCurrent(); if (active.value >= 3) throw new Error('当前已有三个任务运行，请稍后重试');
    if (visibleTasks.value.some(t => t.running && t.kind === 'download' && t.row?.id === row.id)) throw new Error('此文件已在下载中');
  } catch (e) { if (session.value === capturedSession && !(e instanceof DOMException && e.name === 'AbortError')) notice.value = human(e); return; }
  finally { preparingDownloads.value.delete(preparationKey); }
  const pausedTask = visibleTasks.value.find(t => t.kind === 'download' && t.row?.id === row.id && t.paused && !t.running);
  if (pausedTask) Object.assign(pausedTask, { done: 0, paused: false, running: true, error: '', status: '正在下载' });
  else tasks.value.push({ key: crypto.randomUUID(), owner: account, name: row.name, kind: 'download', total: row.size, done: 0, paused: false, running: true, row, status: '正在下载' });
  const t = pausedTask ?? tasks.value[tasks.value.length - 1];
  let writer: FileSystemWritableFileStream | undefined; const hash = sha256.create(), parts: BlobPart[] = []; let committed = 0;
  try {
    if (handle && saved && handle === saved.handle) {
      const local = await handle.getFile(); t.done = Math.min(saved.offset, local.size, row.size);
      for (let i = 0; i < t.done; i += CHUNK) hash.update(new Uint8Array(await local.slice(i, Math.min(i + CHUNK, t.done)).arrayBuffer()));
    }
    await scoped.rpc('download.init', { fileId: row.id, offset: t.done, prefixHash: hex(hash.clone().digest()) });
    if (handle) { writer = await handle.createWritable({ keepExistingData: true }); await writer.truncate(t.done); await writer.seek(t.done); committed = t.done; }
    while (t.done < row.size && !t.paused) {
      const r = await scoped.rpc('download.chunk', { fileId: row.id, offset: t.done });
      if (r.meta.offset !== t.done || r.payload.length === 0 || r.meta.next !== t.done + r.payload.length) throw new Error('下载偏移校验失败');
      hash.update(r.payload); if (writer) await writer.write(new Uint8Array(r.payload).buffer); else parts.push(new Uint8Array(r.payload).buffer);
      t.done += r.payload.length;
      if (handle && writer && t.done - committed >= 4 * 1024 ** 2) { await writer.close(); writer = undefined; committed = t.done; await localPut(cacheKey, { handle, offset: committed }); writer = await handle.createWritable({ keepExistingData: true }); await writer.seek(t.done); }
    }
    if (!t.paused && hex(hash.digest()) !== row.sha256) throw new Error('HASH_MISMATCH');
    if (writer) { await writer.close(); writer = undefined; committed = t.done; await localPut(cacheKey, t.paused ? { handle, offset: committed } : undefined); }
    if (!t.paused) {
      if (!handle) { const url = URL.createObjectURL(new Blob(parts)); const a = document.createElement('a'); a.href = url; a.download = row.name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 10000); }
      t.status = '已完成';
    }
  } catch (e) {
    t.error = human(e); t.paused = true;
    if (e instanceof Error && ['PREFIX_MISMATCH', 'HASH_MISMATCH'].includes(e.message)) {
      await localPut(cacheKey, undefined);
      if (writer) { await writer.abort().catch(() => {}); writer = undefined; }
    }
  }
  finally {
    if (writer) try { await writer.close(); if (handle) await localPut(cacheKey, { handle, offset: t.done }); } catch { /* Keep the last committed checkpoint. */ }
    if (t.paused) t.status = '已暂停'; t.running = false; schedule();
  }
}
async function verifyLogs(anchor?: unknown) { await attempt(async () => { const r = await client.rpc('audit.verify', anchor ? { checkpoint: anchor } : {}); auditResult.value = r.meta.ok ? `校验通过 · 已检查 ${r.meta.count} 条记录${anchor ? '，与独立检查点一致' : '（尚未对照独立检查点）'}` : `校验失败 · ${r.meta.reason}，记录位置 ${r.meta.at ?? '检查点'}`; }); }
async function exportLogs() { await attempt(async () => { const rows: Row[] = []; let after = 0, checkpoint: unknown; while (true) { const r = await client.rpc('audit.page', { after }); const batch = r.meta.rows as Row[]; checkpoint = r.meta.checkpoint; rows.push(...batch); if (batch.length < 8) break; after = batch[batch.length - 1].seq; } saveJSON('safedrop-audit.json', { version: 1, rows, checkpoint }); saveJSON('safedrop-checkpoint.json', checkpoint); }); }
async function loadAnchor(event: Event) { await attempt(async () => { const f = (event.target as HTMLInputElement).files?.[0]; if (f && f.size < 4096) await verifyLogs(JSON.parse(await f.text())); }); }
let poll: ReturnType<typeof setInterval>, heartbeat: ReturnType<typeof setInterval>;
onMounted(() => { void client.connect().catch(e => notice.value = human(e)); poll = setInterval(() => { if (user.value && !active.value) void refresh().catch(() => {}); }, 10000); heartbeat = setInterval(() => { if (connection.value === 'online') void client.rpc('ping').catch(() => {}); }, 15000); });
onUnmounted(() => { clearInterval(poll); clearInterval(heartbeat); client.stop(); });
</script>

<template>
  <div v-if="!user" class="login-shell">
    <section class="login-story"><a class="brand"><span class="brand-icon">S</span> SafeDrop<span class="brand-tag">SECURE TRANSFER</span></a><div class="story-body"><span class="eyebrow">安全文件传输与审计</span><h1>每一次传输，<br>都有安全的依据。</h1><p>加密传输、身份验证与可追溯记录，<br>在一个工作空间里完成。</p><div class="story-line"><i></i> HTTPS / WSS <span>·</span> SFT/1 <span>·</span> SHA-256</div></div><span class="story-foot">传输可控，记录可查。</span></section>
    <section class="login-panel"><div class="login-form"><span class="eyebrow">WELCOME BACK</span><h2>登录安全工作空间</h2><p class="muted">使用你的账号，或此设备已绑定的公钥。</p><form @submit.prevent="login()"><label>账号<input v-model="name" autocomplete="username" maxlength="64" required placeholder="输入账号"></label><label>口令<input v-model="password" type="password" autocomplete="current-password" maxlength="256" placeholder="输入口令"></label><button class="primary full" :disabled="busy || !password">{{ busy ? '正在验证…' : '验证身份并登录 →' }}</button></form><button class="secondary full" :disabled="busy" @click="login(true)">使用本机公钥登录</button><div v-if="notice" class="notice" role="alert">{{ notice }}</div><div class="login-hint"><i :class="connection === 'online' ? 'dot' : 'dot gray'"></i>{{ connection === 'online' ? (secureTransport ? '安全通道已连接' : '本地界面测试连接') : '等待安全连接' }}<small>请使用管理员提供的账号；首次绑定公钥需要验证口令。</small></div></div></section>
  </div>
  <div v-else class="app-shell">
    <aside class="sidebar"><a class="brand"><span class="brand-icon">S</span>SafeDrop</a><div class="workspace-label">安全文件工作空间</div><nav><button v-for="(label, key) in labels" :key="key" :class="{ selected: tab === key }" @click="tab = String(key)"><span>{{ key === 'files' ? '▤' : key === 'security' ? '◈' : '✓' }}</span>{{ label }}<b v-if="key === 'files' && active">{{ active }}</b></button></nav><div class="sidebar-bottom"><div class="secure-mark"><i class="dot"></i>{{ secureTransport ? 'SFT/1 安全通道' : 'SFT/1 本地界面测试' }}<small>文件完成后保持连接</small></div><div class="profile"><span class="avatar">{{ user.name[0].toUpperCase() }}</span><div>{{ user.name }}<small>{{ user.role === 'admin' ? '管理员' : '个人空间' }} · {{ user.tier === 'vip' ? 'VIP' : '标准' }}</small></div><button class="logout" title="退出登录" @click="logout">↗</button></div></div></aside>
    <main><header class="topbar"><span>工作空间 <span class="crumb">/</span> {{ labels[tab] }}</span><span class="connection"><i :class="connection === 'online' ? 'dot' : 'dot gray'"></i>{{ connection === 'online' ? (secureTransport ? '安全连接已建立' : '本地界面测试连接') : '连接已断开' }}</span></header><div class="page"><div class="page-heading"><div><span class="eyebrow">{{ tab === 'files' ? 'YOUR SECURE WORKSPACE' : tab === 'security' ? 'VISIBILITY & CONTROL' : 'VERIFY, THEN TRUST' }}</span><h1>{{ labels[tab] }}</h1><p>{{ tab === 'files' ? '管理文件与传输任务，每一次完成都经过完整性校验。' : tab === 'security' ? '查看真实安全事件，管理在线会话与本机身份。' : '用可复现的测试和可校验的记录，验证安全设计。' }}</p></div><button class="secondary" @click="attempt(refresh)">↻ 刷新数据</button></div><div v-if="notice" class="notice dismiss" role="status">{{ notice }}<button @click="notice = ''">×</button></div>
    <template v-if="tab === 'files'"><div class="stats"><article><span>我的文件</span><strong>{{ files.length }}<small>个</small></strong><p>仅展示当前账号可访问的文件</p></article><article><span>已用存储</span><strong>{{ size(total) }}</strong><p>文件上传完成后计入统计</p></article><article><span>账号传输速率上限</span><strong>{{ size(user.rate) }}<small>/s</small></strong><p>上传与下载、多会话共享额度</p></article></div>
    <section class="upload-zone" @dragover.prevent @drop.prevent="enqueue($event.dataTransfer?.files ?? null)"><div class="upload-icon">↑</div><div><h3>将文件拖到这里，开始安全传输</h3><p>支持多任务与断点续传 · 单文件最大 512 MB</p></div><button class="primary" @click="uploading?.click()">＋ 选择文件</button><input ref="uploading" hidden type="file" multiple @change="enqueue(($event.target as HTMLInputElement).files)"></section>
    <section class="card"><div class="card-heading"><h3>我的文件 <span class="count">{{ files.length }}</span></h3><input v-model="search" class="search" placeholder="搜索文件名" aria-label="搜索文件"></div><div class="table-scroll"><table><thead><tr><th>文件名称</th><th>大小</th><th>上传时间</th><th>完整性</th><th></th></tr></thead><tbody><tr v-for="f in list" :key="f.id"><td><div class="file-name"><span class="file-icon">▤</span><div><strong>{{ f.name }}</strong><small :title="f.sha256">{{ f.sha256.slice(0, 20) }}…</small></div></div></td><td>{{ size(f.size) }}</td><td>{{ time(f.created) }}</td><td><span class="badge">✓ SHA-256</span></td><td><button class="link" :disabled="downloadPreparing(f)" @click="download(f)">{{ downloadPreparing(f) ? '等待文件授权…' : '下载 / 续传 ↓' }}</button></td></tr><tr v-if="!list.length"><td colspan="5" class="empty">{{ search ? '没有匹配的文件' : '空间已准备就绪，上传第一个文件吧。' }}</td></tr></tbody></table></div></section>
    <section v-if="visibleTasks.length" class="card"><div class="card-heading"><h3>传输队列 <span class="count">{{ active }} 进行中</span></h3><span class="muted">最多同时运行 3 个任务</span></div><div v-for="t in visibleTasks" :key="t.key" class="task"><span class="transfer-symbol">{{ t.kind === 'upload' ? '↑' : '↓' }}</span><div class="task-body"><div class="task-title"><strong>{{ t.name }}</strong><span>{{ t.status }} · {{ percent(t) }}%</span></div><progress :value="progressValue(t)" :max="t.total || 1"></progress><small>{{ size(t.done) }} / {{ size(t.total) }}<span v-if="t.error" class="error-text"> · {{ t.error }}</span></small></div><button v-if="t.running" class="secondary small" @click="t.paused = true">暂停</button><button v-else-if="t.paused && t.kind === 'upload'" class="secondary small" @click="t.paused = false; t.status = '等待传输'; schedule()">继续</button><button v-else-if="t.paused && t.row" class="secondary small" :disabled="downloadPreparing(t.row)" @click="download(t.row)">{{ downloadPreparing(t.row) ? '等待文件授权…' : '恢复下载' }}</button><span v-else class="badge">{{ t.status }}</span></div></section>
    <section v-if="transfers.length" class="card"><div class="card-heading"><h3>服务端未完成上传</h3><span class="muted">重新选择相同文件可继续</span></div><div v-for="t in transfers" :key="t.id" class="pending-row"><span>{{ t.name }}</span><small>{{ size(t.offset) }} / {{ size(t.size) }}</small><button class="link danger" @click="cancelPending(t)">取消并释放空间</button></div></section><p class="footnote">断点下载建议使用桌面版 Edge / Chrome；每 4 MB 保存检查点，暂停时保存当前位置。其他浏览器支持 32 MB 以内的普通下载。</p>
    </template>
    <template v-if="tab === 'security'"><div class="stats"><article><span>在线会话</span><strong>{{ sessions.length }}</strong><p>可即时撤销指定会话</p></article><article><span>最近拒绝事件</span><strong>{{ denied }}</strong><p>基于当前可见的最近事件</p></article><article><span>已绑定公钥</span><strong>{{ keys.length }}</strong><p>标准 P-256 挑战签名</p></article></div><section class="card"><div class="card-heading"><h3>在线会话</h3><span class="muted">仅管理自己的会话</span></div><div v-for="s in sessions" :key="s.id" class="session-row"><span class="session-icon">▣</span><div><strong>{{ s.agent.slice(0, 72) }}</strong><small>{{ s.ip }} · {{ time(s.created) }}</small></div><span v-if="s.id === session" class="badge">当前会话</span><button class="secondary small" @click="revoke(s.id)">{{ s.id === session ? '退出本会话' : '撤销会话' }}</button></div></section><section class="card"><div class="card-heading"><h3>公钥身份管理</h3><span class="muted">私钥留在浏览器内，不可导出</span></div><div class="key-form"><label>绑定或撤销前，请重新验证口令<input v-model="reauth" type="password" autocomplete="current-password" placeholder="输入当前账号口令"></label><button class="primary" :disabled="!reauth" @click="enroll">绑定本机公钥</button></div><div v-for="k in keys" :key="k.id" class="pending-row"><span>{{ k.label }}</span><small>{{ time(k.created) }}</small><button class="link danger" :disabled="!reauth" @click="revokeKey(k.id)">撤销公钥</button></div></section><section class="card"><div class="card-heading"><h3>安全事件时间线</h3><span class="muted">{{ user.role === 'admin' ? '管理员 · 全部用户' : '仅当前用户' }}</span></div><div v-for="e in events" :key="e.seq" class="event-row"><span :class="e.result === 'denied' ? 'event-dot rejected' : 'event-dot'"></span><div><strong>{{ e.action }}<span :class="e.result === 'denied' ? 'badge red' : 'badge'">{{ e.result === 'denied' ? '已拒绝' : '已允许' }}</span></strong><small>{{ e.user }} · {{ e.detail.code ?? (e.detail.size != null ? size(e.detail.size) : '操作已记录') }}</small></div><time>{{ time(e.time) }}</time></div><div v-if="!events.length" class="empty">尚无可见事件</div></section></template>
    <template v-if="tab === 'verification'"><div v-if="user.role !== 'admin'" class="card empty">审计导出与安全验证报告由管理员查看。个人安全记录可在安全中心查看。</div><template v-else><section class="card verification-card"><div><span class="eyebrow">TAMPER-EVIDENT AUDIT</span><h2>让操作记录可以被独立检查。</h2><p>哈希链检查日志修改；独立保存的检查点帮助发现历史重写和截断。</p></div><div class="verify-actions"><button class="primary" @click="verifyLogs()">校验当前审计链</button><button class="secondary" @click="exportLogs">导出日志与检查点</button><button class="secondary" @click="anchorInput?.click()">对照已有检查点</button><input ref="anchorInput" hidden type="file" accept="application/json,.json" @change="loadAnchor"></div><div v-if="auditResult" class="notice">{{ auditResult }}</div><small class="muted">检查点应保存在服务器之外；哈希链本身不能阻止持有全部数据的攻击者整体重算。</small></section><section class="card"><div class="card-heading"><h3>自动安全验证报告</h3><span class="badge" v-if="report">{{ report.passed }} / {{ report.results.length }} 通过</span></div><template v-if="report"><div class="report-meta">运行时间 {{ time(report.created) }} · Node {{ report.node }} · {{ report.platform }}</div><div v-for="r in report.results" :key="r.name" class="test-row"><span :class="r.ok ? 'badge' : 'badge red'">{{ r.ok ? 'PASS' : 'FAIL' }}</span><div><strong>{{ r.name }}</strong><small>{{ r.detail }}</small></div><span class="muted">{{ r.ms }} ms</span></div><div class="report-meta"><button class="secondary" @click="saveJSON('safedrop-security-report.json', report)">导出验证报告</button></div></template><div v-else class="empty">尚未生成测试报告。请在本地运行验收工具后刷新。<small>验收工具独立运行，服务端不提供触发测试的公共接口。</small></div></section></template></template>
    </div><footer>SafeDrop <span>安全文件传输与审计</span><span>安全传输 · 可验证记录</span></footer></main>
  </div>
</template>
