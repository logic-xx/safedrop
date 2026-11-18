<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue';
import { human } from './client.ts';
import type { Frame, Metadata } from '../shared/protocol.ts';
type Row = Record<string, any>;
const props = defineProps<{ rpc: (op: string, meta?: Metadata) => Promise<Frame> }>();
const state = ref<Row>(), busy = ref(false), confirm = ref(''), notice = ref(''), error = ref(false), feedback = ref<HTMLElement>(); let live = true;
const size = (n: number | null) => n === null ? '无法读取' : n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KB` : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${(n / 1024 ** 3).toFixed(2)} GB`;
async function refresh() { const r = await props.rpc('maintenance.status'); if (live) state.value = r.meta; }
async function act(op?: string) {
  busy.value = true; notice.value = ''; error.value = false;
  try {
    if (op) {
      const r = await props.rpc(op, op === 'maintenance.cleanup' ? { confirm: confirm.value } : {});
      if (live) { notice.value = op === 'maintenance.cleanup' ? `本批清理完成：成功 ${r.meta.removed}，失败 ${r.meta.failed}，活动或已恢复任务跳过 ${r.meta.activeSkipped}。失败项仍保留占用，可排除故障后重试。` : `加密备份已完成并校验：${r.meta.id}。请由部署维护者分别保护备份与密钥，并演练恢复。`; confirm.value = ''; }
    }
    await refresh();
  } catch (e) { if (live) { error.value = true; notice.value = human(e); } }
  finally { busy.value = false; if (live && notice.value) { await nextTick(); feedback.value?.focus(); feedback.value?.scrollIntoView({ behavior: 'smooth', block: 'center' }); } }
}
onMounted(() => void act()); onUnmounted(() => { live = false; }); defineExpose({ refresh });
</script>
<template>
  <div v-if="notice" ref="feedback" :class="error ? 'form-error' : 'notice account-notice'" role="status" tabindex="-1">{{ notice }}</div>
  <template v-if="state">
    <section class="card"><div class="card-heading"><h3>全局资源</h3><button class="secondary small" :disabled="busy" @click="act()">刷新维护状态</button></div><div class="account-content maintenance-summary"><p>文件已用 <strong>{{ size(state.storage.used) }}</strong> · 完整上传预留 <strong>{{ size(state.storage.reserved) }}</strong> · 全局预算 <strong>{{ size(state.storage.limit) }}</strong></p><p>文件与上传任务 {{ state.storage.objects }} / {{ state.storage.objectLimit }} 项</p><p>磁盘可用 {{ size(state.storage.diskFree) }} · 最低保留 {{ size(state.storage.minFree) }} · 尚需写入的预留 {{ size(state.storage.pending) }}</p><p :class="state.storage.pressure ? 'error-text' : 'muted'">{{ state.storage.pressure ? '存储处于保护状态，新上传或后续写入可能被拒绝。请检查磁盘并清理不再需要的数据。' : '存储预算与磁盘余量正常。' }}</p><p>审计逻辑占用 {{ size(state.audit.bytes) }} / {{ size(state.audit.limit) }}</p><p class="muted">{{ state.audit.protected ? '审计容量接近上限，部分操作进入保护状态。请先归档并由部署维护者调整容量。' : '审计保留完整历史；达到容量保护阈值后限制新操作，不自动截断或重建历史。' }}</p></div></section>
    <section class="card"><div class="card-heading"><h3>过期上传清理</h3><span class="muted">{{ state.cleanupAutomatic ? '已启用后台清理' : '后台清理未启用' }}</span></div><div class="account-content"><p>距最后活动超过 {{ state.staleDays }} 天的未完成上传可被清理；本批候选最多 {{ state.expiredBatch }} 项，每次最多处理 16 项。</p><p class="muted">执行时再次检查活动时间和传输锁，跳过正在处理或已恢复的任务。只清理未完成上传，不删除已完成文件。磁盘清理失败仍保留任务及完整预留。</p><label>输入“清理过期上传”确认<input v-model="confirm" :disabled="busy" autocomplete="off" placeholder="清理过期上传"></label><button class="secondary danger" :disabled="busy || confirm !== '清理过期上传' || !state.expiredBatch" @click="act('maintenance.cleanup')">{{ busy ? '正在处理…' : '清理本批过期上传' }}</button></div></section>
    <section class="card"><div class="card-heading"><h3>一致备份</h3><span class="muted">{{ state.backups.length }} / {{ state.backupCount }} 份已完成</span></div><div class="account-content">
      <p>创建时暂时停止接收新业务，等待在途请求收尾，再加密保存数据库、文件、未完成任务及审计链段并校验。维护完成后恢复服务。</p>
      <p v-if="state.backupEncryption?.configured">新备份加密已就绪 · 当前密钥 {{ state.backupEncryption.activeKeyId }}</p>
      <p v-else class="error-text">备份密钥不可用。请由部署维护者核对密钥文件；已有加密副本时应恢复原密钥，勿重新初始化。处理后刷新维护状态。</p>
      <p class="muted">备份与密钥需分别保存在独立受保护位置。本页只显示结果，不提供备份内容或密钥下载。达到份数或容量上限时拒绝创建，不自动删除旧备份。隔离恢复和密钥轮换由部署维护者通过本机工具执行。</p>
      <button class="primary" :disabled="busy || state.busy || !state.backupEncryption?.configured || state.backups.length >= state.backupCount" @click="act('maintenance.backup')">{{ busy ? '正在处理，请等待…' : '暂停新业务并创建加密备份' }}</button>
      <div v-for="b in state.backups" :key="b.id" class="pending-row"><span class="action-filename">{{ b.id }}</span><small>{{ new Date(b.created).toLocaleString('zh-CN') }} · {{ size(b.bytes) }} · {{ b.encrypted ? '已加密' : '旧明文格式' }}<template v-if="b.encrypted"> · 密钥 {{ b.keyId }}</template></small></div>
    </div></section>
  </template>
</template>
