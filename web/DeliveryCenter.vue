<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue';
import { human } from './client.ts';
import type { Frame, Metadata } from '../shared/protocol.ts';
import ScanBadge from './ScanBadge.vue';
type Row = Record<string, any>;
const props = defineProps<{ rpc: (op: string, meta?: Metadata) => Promise<Frame>; download: (row: Row) => Promise<void>; preparing: (row: Row) => boolean }>();
const incoming = ref<Row[]>([]), sent = ref<Row[]>([]), inOffset = ref(0), outOffset = ref(0), busy = ref(false), notice = ref(''), target = ref<Row>(), feedback = ref<HTMLElement>(), confirmPanel = ref<HTMLElement>();
let live = true;
const time = (n: number) => new Date(n).toLocaleString('zh-CN', { hour12: false });
const size = (n: number) => n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 ** 2).toFixed(1)} MB`;
const status = (d: Row) => !d.revoked ? '授权有效' : d.reason === 'file-deleted' ? '文件删除导致失效' : d.reason === 'account-disabled' ? '账号已停用' : '已撤销';
async function refresh() {
  const received = await props.rpc('deliveries.received', { offset: inOffset.value }), outgoing = await props.rpc('deliveries.sent', { offset: outOffset.value });
  if (live) { incoming.value = received.meta.deliveries as Row[]; sent.value = outgoing.meta.deliveries as Row[]; }
}
async function action(fn: () => Promise<void>) { busy.value = true; notice.value = ''; try { await fn(); } catch (e) { if (live) { notice.value = human(e); await nextTick(); feedback.value?.focus(); feedback.value?.scrollIntoView({ behavior: 'smooth', block: 'center' }); } } finally { busy.value = false; } }
async function revoke() { if (target.value) await action(async () => { await props.rpc('deliveries.revoke', { deliveryId: target.value!.deliveryId }); target.value = undefined; await refresh(); notice.value = '接收授权已撤销，后续下载与续传已停止。'; }); }
async function choose(d: Row) { target.value = d; await nextTick(); confirmPanel.value?.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
onMounted(() => void action(refresh)); onUnmounted(() => { live = false; });
defineExpose({ refresh });
</script>
<template>
  <div v-if="notice" ref="feedback" class="notice account-notice" role="status" tabindex="-1">{{ notice }}</div>
  <section class="card"><div class="card-heading"><h3>收到的文件</h3><button class="secondary small" :disabled="busy" @click="action(refresh)">刷新收发记录</button></div>
    <p class="report-meta">文件仍属于发送者，不占用你的存储配额；下载使用你的账号带宽。授权失效后将从此列表移除。</p>
    <div class="table-scroll"><table><thead><tr><th>文件</th><th>发送者</th><th>大小</th><th>发送时间</th><th></th></tr></thead><tbody><tr v-for="f in incoming" :key="f.deliveryId"><td><div class="file-name"><span class="file-icon">↓</span><div><strong>{{ f.name }}</strong><small :title="f.sha256">{{ f.sha256.slice(0, 20) }}…</small></div></div></td><td>{{ f.sender }}</td><td>{{ size(f.size) }}</td><td>{{ time(f.sentAt) }}<ScanBadge :scan="f.scan" /></td><td><button class="link" :disabled="preparing(f) || f.scan?.state !== 'clean'" @click="download(f)">{{ preparing(f) ? '等待文件授权…' : '下载 / 续传 ↓' }}</button></td></tr></tbody></table></div><div v-if="!incoming.length" class="empty">当前没有可下载的接收文件</div>
    <div class="account-pagination"><button class="secondary small" :disabled="busy || inOffset === 0" @click="inOffset -= 12; action(refresh)">上一页收到的文件</button><button class="secondary small" :disabled="busy || incoming.length < 12" @click="inOffset += 12; action(refresh)">下一页收到的文件</button></div>
  </section>
  <section class="card"><div class="card-heading"><h3>已发送的授权</h3><span class="muted">显示授权状态，不表示对方已读</span></div>
    <div class="table-scroll"><table><thead><tr><th>文件</th><th>接收账号</th><th>发送时间</th><th>状态</th><th></th></tr></thead><tbody><tr v-for="d in sent" :key="d.deliveryId"><td class="action-filename">{{ d.name }}</td><td>{{ d.recipient }}</td><td>{{ time(d.sentAt) }}</td><td><span :class="d.revoked ? 'badge red' : 'badge'">{{ status(d) }}</span></td><td><button v-if="!d.revoked" class="link danger" :disabled="busy" @click="choose(d)">撤销授权</button></td></tr></tbody></table></div><div v-if="!sent.length" class="empty">从文件工作台选择自己的文件，即可发送给已注册账号。</div>
    <div v-if="target" ref="confirmPanel" class="account-content disable-confirm" role="region" aria-label="撤销接收授权"><p>撤销 <strong>{{ target.name }}</strong> 给 <strong>{{ target.recipient }}</strong> 的接收授权？</p><p class="muted">这会停止后续下载与续传，已经下载到对方设备上的内容无法收回。原文件仍保留。</p><div class="account-pagination"><button class="secondary danger" :disabled="busy" @click="revoke">确认撤销授权</button><button class="secondary" :disabled="busy" @click="target = undefined">取消</button></div></div>
    <div class="account-pagination"><button class="secondary small" :disabled="busy || outOffset === 0" @click="outOffset -= 12; action(refresh)">上一页已发送授权</button><button class="secondary small" :disabled="busy || sent.length < 12" @click="outOffset += 12; action(refresh)">下一页已发送授权</button></div>
  </section>
</template>
