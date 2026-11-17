<script setup lang="ts">
import { ref, onMounted, nextTick } from 'vue';
import { human } from './client.ts';
import type { Frame, Metadata } from '../shared/protocol.ts';
type Row = Record<string, any>;
const props = defineProps<{ file: Row; rpc: (op: string, meta?: Metadata) => Promise<Frame> }>();
const emit = defineEmits<{ close: []; sent: [] }>();
const recipient = ref(''), prepared = ref(''), confirmed = ref(false), error = ref(''), success = ref(''), busy = ref(false), panel = ref<HTMLElement>(), feedback = ref<HTMLElement>();
function edited() { prepared.value = ''; confirmed.value = false; success.value = ''; }
async function act(send: boolean) {
  if (send && (!prepared.value || !confirmed.value)) return;
  busy.value = true; error.value = ''; success.value = '';
  try {
    const r = await props.rpc(send ? 'deliveries.create' : 'deliveries.prepare', { fileId: props.file.id, recipient: send ? prepared.value : recipient.value });
    if (send) { success.value = r.meta.created ? '接收授权已创建，对方可在“收发文件”中下载。' : '此账号已有有效接收授权，本次未重复创建。'; prepared.value = ''; confirmed.value = false; emit('sent'); }
    else { prepared.value = String((r.meta.recipient as Row).name); confirmed.value = false; }
  } catch (e) { error.value = human(e); await nextTick(); feedback.value?.focus(); feedback.value?.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  finally { busy.value = false; }
}
onMounted(() => panel.value?.scrollIntoView({ behavior: 'smooth', block: 'center' }));
</script>
<template>
  <section ref="panel" class="card file-action" role="region" aria-label="发送文件给用户">
    <div class="card-heading"><h3>发送文件给用户</h3><button class="secondary small" :disabled="busy" @click="emit('close')">关闭</button></div>
    <div class="account-content"><p class="action-filename">{{ file.name }}</p><p class="muted">接收者只能读取，不能修改原文件或再次授权。文件仍属于你，可随时撤销对方的下载权限。</p>
      <div v-if="error" ref="feedback" class="form-error" role="alert" tabindex="-1"><strong>未能完成发送</strong><p>{{ error }}</p></div>
      <div v-if="success" class="notice" role="status">{{ success }}</div>
      <form class="delivery-recipient" @submit.prevent="act(false)"><label>接收账号<input v-model="recipient" maxlength="32" minlength="3" pattern="[a-zA-Z0-9_-]{3,32}" autocomplete="off" placeholder="准确输入已注册账号" :disabled="busy" required @input="edited"></label><button class="secondary" :disabled="busy">核对接收账号</button></form>
      <div v-if="prepared" class="recipient-confirm"><p>将授权给账号：<strong>{{ prepared }}</strong></p><label class="check-label"><input v-model="confirmed" type="checkbox" :disabled="busy">我已核对接收账号</label><button class="primary" :disabled="busy || !confirmed" @click="act(true)">{{ busy ? '正在发送…' : '确认发送' }}</button></div>
    </div>
  </section>
</template>
