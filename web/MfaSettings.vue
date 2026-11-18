<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue';
import { human } from './client.ts';
import type { Frame, Metadata } from '../shared/protocol.ts';
type Row = Record<string, any>;
const props = defineProps<{ rpc: (op: string, meta?: Metadata) => Promise<Frame> }>();
const emit = defineEmits<{ changed: [enabled: boolean] }>();
const state = ref<Row>(), setup = ref<Row>(), password = ref(''), code = ref(''), saved = ref(false), busy = ref(false), notice = ref(''), error = ref(false), recoveryCodes = ref<string[]>([]), action = ref<'disable' | 'recovery'>(), feedback = ref<HTMLElement>();
let live = true;
async function refresh() { const r = await props.rpc('mfa.status'); if (live) state.value = r.meta; }
async function act(kind: 'setup' | 'enable' | 'cancel' | 'disable' | 'recovery') {
  busy.value = true; notice.value = ''; error.value = false;
  try {
    const meta = kind === 'setup' ? { password: password.value } : kind === 'enable' ? { code: code.value, confirm: '启用双因素认证' } : kind === 'cancel' ? {} : { password: password.value, code: code.value, confirm: kind === 'disable' ? '停用双因素认证' : '更新恢复码' };
    const r = await props.rpc('mfa.' + kind, meta); if (!live) return;
    if (kind === 'setup') { setup.value = r.meta; saved.value = false; recoveryCodes.value = []; notice.value = '请在验证器中添加密钥，再输入新生成的六位验证码。'; }
    else {
      setup.value = undefined; action.value = undefined; saved.value = false;
      if (kind !== 'cancel') {
        recoveryCodes.value = r.meta.recoveryCodes as string[] ?? [];
        notice.value = kind === 'disable' ? '双因素认证已停用。其他会话和旧公钥已撤销。' : kind === 'enable' ? '双因素认证已启用。请立即安全保存这十份一次性恢复码，离开后无法再次查看。' : '恢复码已更新，旧恢复码及其他会话已失效。请安全保存新恢复码。';
        emit('changed', Boolean(r.meta.enabled));
      } else notice.value = '本次绑定已取消，原认证方式保持。';
    }
    await refresh();
  } catch (e) { if (live) { error.value = true; notice.value = human(e); } }
  finally {
    password.value = ''; code.value = ''; busy.value = false;
    if (live && notice.value) { await nextTick(); feedback.value?.focus(); feedback.value?.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  }
}
async function copySecret() { try { await navigator.clipboard.writeText(String(setup.value?.secret)); notice.value = '绑定密钥已复制，请仅粘贴到自己的验证器。'; } catch { notice.value = '无法访问剪贴板，可选中密钥后手动复制。'; } }
onMounted(() => void refresh().catch(e => { error.value = true; notice.value = human(e); }));
onUnmounted(() => { live = false; setup.value = undefined; recoveryCodes.value = []; password.value = ''; code.value = ''; });
defineExpose({ refresh });
</script>
<template>
  <section class="card">
    <div class="card-heading"><h3>管理员双因素认证</h3><span v-if="state" :class="state.enabled ? 'badge' : 'muted'">{{ state.enabled ? '已启用' : '尚未启用' }}</span></div>
    <div class="account-content mfa-content">
      <div v-if="notice" ref="feedback" :class="error ? 'form-error' : 'notice'" role="status" tabindex="-1">{{ notice }}</div>
      <p v-if="state?.recoveryOnly" class="form-error">当前为恢复会话，仅可重新绑定验证器。完成新验证码验证后，才恢复文件与管理功能；恢复码不会直接关闭双因素认证。</p>
      <p v-else class="muted">启用后使用口令加验证器验证码登录，原公钥不能替代此流程。验证码每 30 秒更新，用过的验证码不能再次使用。</p>
      <div v-if="recoveryCodes.length" class="mfa-recovery">
        <strong>一次性恢复码 · 仅本次展示</strong><p>与口令分开保管，不要放入截图、聊天或代码仓库。每份只能使用一次，恢复登录只允许重新绑定验证器。</p>
        <div class="recovery-grid"><code v-for="item in recoveryCodes" :key="item">{{ item }}</code></div>
        <button class="secondary" @click="recoveryCodes = []">我已安全保存，隐藏恢复码</button>
      </div>
      <template v-if="state">
        <form v-if="setup" class="password-form" @submit.prevent="act('enable')">
          <p class="notice">验证器是独立的手机或桌面动态口令应用，不是本页的验证码输入框。请先在验证器中添加账号，把绑定密钥填入验证器；本页只填写它生成的六位数字。</p>
          <p>在验证器中选择“手动输入密钥”：服务为 SafeDrop，账号为 {{ setup.account }}，类型为基于时间的六位验证码。绑定将在五分钟后失效。</p>
          <label>绑定密钥<input :value="setup.secret" type="password" readonly autocomplete="off" spellcheck="false"></label><button type="button" class="secondary" @click="copySecret">复制绑定密钥</button>
          <label>新验证器验证码<input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" minlength="6" required placeholder="六位数字"></label>
          <label class="mfa-confirm"><input v-model="saved" type="checkbox">我已将密钥添加到自己的验证器，确认启用双因素认证</label>
          <div class="mfa-actions"><button class="primary" :disabled="busy || !saved || code.length !== 6">确认启用双因素认证</button><button type="button" class="secondary" :disabled="busy" @click="act('cancel')">取消本次绑定</button></div>
        </form>
        <form v-else-if="!state.enabled || state.recoveryOnly" class="password-form" @submit.prevent="act('setup')">
          <p v-if="!state.enabled">升级不会自动启用。准备好验证器后，再验证当前口令并开始绑定。</p>
          <label>双因素设置的当前口令<input v-model="password" type="password" autocomplete="current-password" maxlength="256" required></label>
          <button class="primary" :disabled="busy || !password">{{ state.recoveryOnly ? '重新绑定验证器' : '开始绑定验证器' }}</button>
        </form>
        <template v-else>
          <p>剩余一次性恢复码 {{ state.recoveryRemaining }} 份。遗失验证器时，请退出后通过口令和一份未使用的恢复码进入重新绑定流程。</p>
          <div v-if="!action" class="mfa-actions"><button class="secondary" @click="action = 'recovery'; saved = false">更新恢复码</button><button class="secondary danger" @click="action = 'disable'; saved = false">停用双因素认证</button></div>
          <form v-else class="password-form" @submit.prevent="act(action)">
            <p>{{ action === 'disable' ? '停用后将允许仅使用口令登录；其他会话和旧公钥将撤销。请确认这是你的操作。' : '更新将使全部旧恢复码及其他会话失效，请准备安全保存新恢复码。' }}</p>
            <label>双因素操作的当前口令<input v-model="password" type="password" autocomplete="current-password" maxlength="256" required></label>
            <label>未使用的验证器验证码<input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" minlength="6" required placeholder="请等待一组尚未使用的新验证码"></label>
            <label class="mfa-confirm"><input v-model="saved" type="checkbox">{{ action === 'disable' ? '我确认停用双因素认证' : '我确认使旧恢复码失效' }}</label>
            <div class="mfa-actions"><button :class="action === 'disable' ? 'secondary danger' : 'primary'" :disabled="busy || !saved || code.length !== 6">{{ action === 'disable' ? '确认停用双因素认证' : '确认更新恢复码' }}</button><button type="button" class="secondary" :disabled="busy" @click="action = undefined; password = ''; code = ''; saved = false">返回</button></div>
          </form>
        </template>
      </template>
    </div>
  </section>
</template>
<style scoped>
.mfa-content { display: grid; gap: 16px; }.mfa-content p { line-height: 1.7; }.mfa-actions { display: flex; flex-wrap: wrap; gap: 12px; }.mfa-confirm { display: flex; align-items: flex-start; gap: 10px; line-height: 1.6; }.mfa-confirm input { width: auto; margin-top: 4px; }.mfa-recovery { display: grid; gap: 14px; padding: 18px; background: #f0f7f4; border: 1px solid #cee4d9; border-radius: 10px; }.recovery-grid { display: grid; gap: 8px; overflow-wrap: anywhere; }.recovery-grid code { user-select: all; font-size: 12px; }
</style>
