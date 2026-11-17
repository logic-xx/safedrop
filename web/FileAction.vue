<script setup lang="ts">
import { ref, onMounted, nextTick } from 'vue';
import { human } from './client.ts';
import type { Frame, Metadata } from '../shared/protocol.ts';
type Row = Record<string, any>;
const props = defineProps<{ file: Row; mode: 'rename' | 'delete'; rpc: (op: string, meta?: Metadata) => Promise<Frame> }>();
const emit = defineEmits<{ close: []; changed: [mode: 'rename' | 'delete', file: Row]; refresh: [] }>();
const name = ref(props.file.name), confirmation = ref(''), error = ref(''), busy = ref(false), panel = ref<HTMLElement>(), feedback = ref<HTMLElement>();
async function submit() {
  if (props.mode === 'delete' && confirmation.value !== props.file.name) return;
  busy.value = true; error.value = '';
  try {
    const r = await props.rpc(props.mode === 'rename' ? 'files.rename' : 'files.delete', { fileId: props.file.id, ...(props.mode === 'rename' ? { name: name.value } : {}) });
    emit('changed', props.mode, props.mode === 'rename' ? r.meta.file as Row : props.file);
  } catch (e) {
    error.value = human(e); emit('refresh');
    await nextTick(); feedback.value?.focus(); feedback.value?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } finally { busy.value = false; }
}
onMounted(() => { panel.value?.scrollIntoView({ behavior: 'smooth', block: 'center' }); });
</script>
<template>
  <section ref="panel" class="card file-action" role="region" :aria-label="mode === 'rename' ? '重命名文件' : '永久删除文件'">
    <div class="card-heading"><h3>{{ mode === 'rename' ? '重命名文件' : '永久删除文件' }}</h3><button class="secondary small" :disabled="busy" @click="emit('close')">关闭</button></div>
    <form class="account-content" @submit.prevent="submit">
      <p class="action-filename">{{ file.name }}</p>
      <div v-if="error" ref="feedback" class="form-error" role="alert" tabindex="-1"><strong>操作未完成</strong><p>{{ error }}</p></div>
      <template v-if="mode === 'rename'"><p class="muted">只修改文件显示名称，文件内容和下载续传位置保持不变。</p><label>新文件名<input v-model="name" maxlength="180" autocomplete="off" required></label></template>
      <template v-else><p class="danger">此操作永久删除服务器上的文件，无法恢复。正在进行的下载将停止；已经下载到设备上的内容不受影响。</p><p class="muted">磁盘清理失败时保留文件记录与空间占用，显示“删除待重试”，请重试清理。</p><label>输入完整文件名确认删除<input v-model="confirmation" autocomplete="off" :placeholder="file.name" required></label></template>
      <button class="primary" :class="{ 'delete-button': mode === 'delete' }" :disabled="busy || mode === 'delete' && confirmation !== file.name">{{ busy ? '正在处理…' : mode === 'rename' ? '保存文件名' : file.deleting ? '重试永久删除' : '确认永久删除' }}</button>
    </form>
  </section>
</template>
