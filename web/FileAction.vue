<script setup lang="ts">
import { computed, ref, onMounted, nextTick } from 'vue';
import { human } from './client.ts';
import type { Frame, Metadata } from '../shared/protocol.ts';
type Row = Record<string, any>;
type Mode = 'rename' | 'delete' | 'move';
const props = defineProps<{ file: Row; mode: Mode; folders: { id: string; name: string }[]; rpc: (op: string, meta?: Metadata) => Promise<Frame> }>();
const emit = defineEmits<{ close: []; changed: [mode: Mode, file: Row]; refresh: [] }>();
const name = ref(props.file.name), confirmation = ref(''), error = ref(''), busy = ref(false), panel = ref<HTMLElement>(), feedback = ref<HTMLElement>();
const folderId = ref<string | null>('');
const titles = { rename: '重命名文件', delete: '永久删除文件', move: '移动文件' };
const title = computed(() => titles[props.mode]);
const disabled = computed(() => busy.value || props.mode === 'delete' && confirmation.value !== props.file.name ||
  props.mode === 'move' && (folderId.value === '' || folderId.value === (props.file.folderId ?? null)));
async function submit() {
  if (disabled.value) return;
  busy.value = true; error.value = '';
  try {
    const meta: Metadata = { fileId: props.file.id };
    if (props.mode === 'rename') meta.name = name.value;
    if (props.mode === 'move') meta.folderId = folderId.value;
    const r = await props.rpc('files.' + props.mode, meta);
    emit('changed', props.mode, props.mode === 'rename' ? r.meta.file as Row : props.file);
  } catch (e) {
    error.value = human(e); emit('refresh');
    await nextTick(); feedback.value?.focus(); feedback.value?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } finally { busy.value = false; }
}
onMounted(() => { panel.value?.scrollIntoView({ behavior: 'smooth', block: 'center' }); });
</script>
<template>
  <section ref="panel" class="card file-action" role="region" :aria-label="title">
    <div class="card-heading"><h3>{{ title }}</h3><button class="secondary small" :disabled="busy" @click="emit('close')">关闭</button></div>
    <form class="account-content" @submit.prevent="submit">
      <p class="action-filename">{{ file.name }}</p>
      <div v-if="error" ref="feedback" class="form-error" role="alert" tabindex="-1"><strong>操作未完成</strong><p>{{ error }}</p></div>
      <template v-if="mode === 'rename'"><p class="muted">只修改文件显示名称，文件内容和下载续传位置保持不变。</p><label>新文件名<input v-model="name" maxlength="180" autocomplete="off" required></label></template>
      <label v-else-if="mode === 'move'">目标文件夹
        <select v-model="folderId" class="folder-select" :disabled="busy">
          <option value="" disabled>选择目标文件夹</option>
          <option v-if="file.folderId" :value="null">根目录</option>
          <option v-for="folder in folders.filter(item => item.id !== file.folderId)" :key="folder.id" :value="folder.id">{{ folder.name }}</option>
        </select>
      </label>
      <template v-else><p class="danger">此操作永久删除服务器上的文件，无法恢复。正在进行的下载将停止；已经下载到设备上的内容不受影响。</p><p class="muted">磁盘清理失败时保留文件记录与空间占用，显示“删除待重试”，请重试清理。</p><label>输入完整文件名确认删除<input v-model="confirmation" autocomplete="off" :placeholder="file.name" required></label></template>
      <button class="primary" :class="{ 'delete-button': mode === 'delete' }" :disabled="disabled">{{ busy ? '正在处理…' : mode === 'rename' ? '保存文件名' : mode === 'move' ? '移动' : file.deleting ? '重试永久删除' : '确认永久删除' }}</button>
    </form>
  </section>
</template>

<style scoped>
.folder-select{display:block;width:100%;margin-top:5px;padding:9px 12px;border:1px solid #dce5e2;border-radius:8px;background:#fff;color:#354357;font:inherit}
.folder-select:focus-visible{outline:2px solid #459c7d;outline-offset:2px}
</style>
