<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { human } from './client.ts';
import type { Frame, Metadata } from '../shared/protocol.ts';
const props = defineProps<{ rpc: (op: string, meta?: Metadata) => Promise<Frame> }>();
type Row = Record<string, any>;
const mode = ref(''), invites = ref<Row[]>([]), users = ref<Row[]>([]), hours = ref(24), token = ref(''), expires = ref(0), busy = ref(false), notice = ref('');
const inviteOffset = ref(0), userOffset = ref(0), target = ref<Row>(), confirmation = ref('');
let live = true;
const time = (n: number) => new Date(n).toLocaleString('zh-CN', { hour12: false });
async function refresh() {
  const i = await props.rpc('invitations.list', { offset: inviteOffset.value });
  const u = await props.rpc('users.list', { offset: userOffset.value });
  if (!live) return;
  mode.value = String(i.meta.registration); invites.value = i.meta.invitations as Row[]; users.value = u.meta.users as Row[];
}
async function action(fn: () => Promise<void>) { busy.value = true; notice.value = ''; try { await fn(); } catch (e) { if (live) notice.value = human(e); } finally { busy.value = false; } }
async function setMode() { await action(async () => { await props.rpc('registration.set', { mode: mode.value === 'invitation' ? 'closed' : 'invitation' }); token.value = ''; await refresh(); }); }
async function create() { await action(async () => { token.value = ''; const r = await props.rpc('invitations.create', { hours: hours.value }); if (!live) return; token.value = String(r.meta.token); expires.value = Number(r.meta.expires); await refresh(); }); }
async function revoke(id: string) { await action(async () => { await props.rpc('invitations.revoke', { invitationId: id }); token.value = ''; await refresh(); }); }
async function disable() { if (!target.value || confirmation.value !== target.value.name) return; await action(async () => { await props.rpc('users.disable', { userId: target.value!.id }); target.value = undefined; confirmation.value = ''; await refresh(); }); }
function status(i: Row) { return i.usedAt ? '已使用' : i.revoked ? '已撤销' : i.expires <= Date.now() ? '已到期' : '待领取'; }
onMounted(() => void action(refresh));
onUnmounted(() => { live = false; token.value = ''; });
defineExpose({ refresh });
</script>

<template>
  <div v-if="notice" class="notice account-notice" role="alert">{{ notice }}</div>
  <section class="card">
    <div class="card-heading"><h3>注册策略</h3><button class="secondary small" :disabled="busy" @click="action(refresh)">刷新账号数据</button></div>
    <div class="account-content"><p>当前策略：<strong>{{ mode === 'invitation' ? '邀请注册' : mode === 'closed' ? '已关闭自助注册' : '读取中…' }}</strong></p><p class="muted">邀请仅能使用一次。关闭后，尚未领取的邀请也不能注册；重新开启后，未到期且未撤销的邀请仍可使用。</p><button class="secondary" :disabled="busy || !mode" @click="setMode">{{ mode === 'invitation' ? '关闭自助注册' : '开启邀请注册' }}</button></div>
  </section>
  <section class="card">
    <div class="card-heading"><h3>注册邀请</h3><span class="muted">新账号自行设置口令 · 标准用户权限</span></div>
    <form class="key-form" @submit.prevent="create"><label>有效小时数（1～168）<input v-model.number="hours" type="number" min="1" max="168" required></label><button class="primary" :disabled="busy || mode !== 'invitation'">生成单次邀请</button></form>
    <div v-if="token" class="account-content invitation-secret"><p>邀请令牌仅在本次生成后展示，请通过可信渠道交给受邀者。</p><label>邀请令牌<input :value="token" readonly autocomplete="off" aria-label="生成的邀请令牌"></label><p class="muted">到期时间：{{ time(expires) }}。离开此页后不再展示；忘记令牌请撤销后重新生成。</p><button class="secondary small" @click="token = ''">隐藏令牌</button></div>
    <div class="table-scroll"><table><thead><tr><th>生成时间</th><th>到期时间</th><th>状态</th><th></th></tr></thead><tbody><tr v-for="i in invites" :key="i.id"><td>{{ time(i.created) }}</td><td>{{ time(i.expires) }}</td><td>{{ status(i) }}</td><td><button v-if="status(i) === '待领取'" class="link danger" :disabled="busy" @click="revoke(i.id)">撤销邀请</button></td></tr></tbody></table></div>
    <div v-if="!invites.length" class="empty">尚无邀请记录</div>
    <div class="account-pagination"><button class="secondary small" :disabled="busy || inviteOffset === 0" @click="inviteOffset -= 12; action(refresh)">上一页邀请</button><button class="secondary small" :disabled="busy || invites.length < 12" @click="inviteOffset += 12; action(refresh)">下一页邀请</button></div>
  </section>
  <section class="card">
    <div class="card-heading"><h3>账号管理</h3><span class="muted">管理权限不包含读取其他用户文件</span></div>
    <div class="table-scroll"><table><thead><tr><th>账号</th><th>角色</th><th>状态</th><th></th></tr></thead><tbody><tr v-for="u in users" :key="u.id"><td>{{ u.name }}</td><td>{{ u.role === 'admin' ? '管理员' : '用户' }}</td><td>{{ u.disabled ? '已停用' : '可用' }}</td><td><button v-if="!u.disabled" class="link danger" :disabled="busy" @click="target = u; confirmation = ''">停用账号</button></td></tr></tbody></table></div>
    <div v-if="target" class="account-content disable-confirm"><p>停用 <strong>{{ target.name }}</strong> 后，全部会话、等待中的传输和已绑定公钥立即失效，文件和任务继续保留。本版不提供重新启用入口。</p><label>输入目标账号以确认<input v-model="confirmation" autocomplete="off" :placeholder="target.name"></label><div class="account-pagination"><button class="secondary danger" :disabled="busy || confirmation !== target.name" @click="disable">确认停用</button><button class="secondary" :disabled="busy" @click="target = undefined; confirmation = ''">取消</button></div></div>
    <div class="account-pagination"><button class="secondary small" :disabled="busy || userOffset === 0" @click="userOffset -= 12; action(refresh)">上一页账号</button><button class="secondary small" :disabled="busy || users.length < 12" @click="userOffset += 12; action(refresh)">下一页账号</button></div>
  </section>
</template>
