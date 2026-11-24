<script setup lang="ts">
import { nextTick, ref } from 'vue';
import type { Frame, Metadata } from '../shared/protocol.ts';
import { human } from './client.ts';

type Folder = { id: string; name: string };
const props = defineProps<{
  folders: Folder[];
  current: Folder | undefined;
  rpc: (op: string, meta?: Metadata) => Promise<Frame>;
}>();
const emit = defineEmits<{ open: [id: string | null]; created: [folder: Folder] }>();
const name = ref(''), creating = ref(false), busy = ref(false), error = ref('');
const nameInput = ref<HTMLInputElement>();

async function showForm() {
  creating.value = true;
  await nextTick();
  nameInput.value?.focus();
}
function closeForm() {
  creating.value = false;
  name.value = '';
  error.value = '';
}
async function createFolder() {
  if (busy.value || !name.value.trim()) return;
  busy.value = true;
  error.value = '';
  try {
    const response = await props.rpc('folders.create', { name: name.value });
    emit('created', response.meta.folder as Folder);
    closeForm();
  } catch (cause) {
    error.value = human(cause);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="folder-navigation">
    <nav class="folder-toolbar" aria-label="文件夹导航">
      <div class="folder-location">
        <template v-if="current">
          <button type="button" class="link" @click="emit('open', null)">根目录</button>
          <span aria-hidden="true">/</span>
          <strong aria-current="location">{{ current.name }}</strong>
        </template>
        <strong v-else aria-current="location">根目录</strong>
      </div>
      <button v-if="!current && !creating" type="button" class="secondary small" @click="showForm">新建文件夹</button>
    </nav>
    <form v-if="creating && !current" class="folder-form" @submit.prevent="createFolder">
      <label>文件夹名称
        <input ref="nameInput" v-model="name" maxlength="80" autocomplete="off" required :disabled="busy">
      </label>
      <button type="submit" class="primary small" :disabled="busy || !name.trim()">创建</button>
      <button type="button" class="link" :disabled="busy" @click="closeForm">取消</button>
      <p v-if="error" class="error-text" role="alert">{{ error }}</p>
    </form>
    <ul v-if="!current && folders.length" class="folder-list" aria-label="个人文件夹">
      <li v-for="folder in folders" :key="folder.id">
        <button type="button" class="secondary small" @click="emit('open', folder.id)">
          <span class="folder-icon" aria-hidden="true"></span>{{ folder.name }}
        </button>
      </li>
    </ul>
  </div>
</template>

<style scoped>
.folder-navigation{padding:14px 23px;border-bottom:1px solid #f0f2f5}
.folder-toolbar,.folder-location,.folder-form{display:flex;align-items:center;gap:10px}
.folder-toolbar{justify-content:space-between}
.folder-location{color:#354357;font-size:12px;min-width:0}
.folder-location strong{overflow-wrap:anywhere}
.folder-list{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 0;padding:0;list-style:none}
.folder-list li{max-width:100%}
.folder-list button{display:flex;gap:8px;align-items:center;text-align:left;overflow-wrap:anywhere;max-width:100%}
.folder-icon{position:relative;display:inline-block;flex:0 0 15px;height:11px;border:1px solid #789785;border-radius:2px}
.folder-icon:before{content:'';position:absolute;width:6px;height:3px;left:1px;top:-4px;border:1px solid #789785;border-bottom:0;border-radius:2px 2px 0 0}
.folder-form{flex-wrap:wrap;align-items:flex-end;margin-top:12px}
.folder-form label{width:min(320px,100%);font-size:11px}
.folder-form input{font-size:12px}
.folder-form p{flex-basis:100%;font-size:11px}
@media(max-width:760px){.folder-navigation{padding:12px 16px}}
</style>
