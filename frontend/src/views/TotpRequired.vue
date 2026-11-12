<!-- Mandatory TOTP enrolment for roles that require it (approver/admin by default). -->
<template>
  <div class="authbox wide">
    <div class="authhead">
      <img class="authlogo" src="/logo-mark.svg" alt="" width="40" height="40">
      <h1 class="authtitle">jt-waf-mgr</h1>
    </div>
    <FlowSteps compact :title="t('guide.first.title')" :steps="firstSteps" />
    <h2><Icon name="fingerprint" /> {{ t('totp.title') }}</h2>
    <p class="alert info">{{ t('totp.required_intro') }}</p>
    <div v-if="!setup">
      <div class="actions">
        <button class="btn primary" type="button" :disabled="busy" @click="start"><Icon name="key" />{{ t('totp.setup') }}</button>
        <button class="btn ghost" type="button" @click="logout"><Icon name="logout" />{{ t('nav.logout') }}</button>
      </div>
    </div>
    <div v-else class="totpsetup">
      <p>{{ t('totp.step1') }}</p>
      <div class="field">
        <span>{{ t('totp.secret') }}</span>
        <CopyText :value="setup.secret" :display="groupBy4(setup.secret)" />
      </div>
      <details class="field">
        <summary>{{ t('totp.uri') }}</summary>
        <CopyText :value="setup.otpauth_uri" />
      </details>
      <form class="form" @submit.prevent="enable">
        <label class="field">
          <span>{{ t('totp.step2') }}</span>
          <input v-model.trim="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus>
        </label>
        <div class="actions">
          <button class="btn primary" type="submit" :disabled="busy"><Icon name="check" />{{ t('totp.enable') }}</button>
          <button class="btn ghost" type="button" @click="logout"><Icon name="logout" />{{ t('nav.logout') }}</button>
        </div>
      </form>
    </div>
    <div v-if="message" class="alert error" role="alert">{{ message }}</div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api.js'
import { state, setSession, clearSession } from '../store.js'
import { t, errText } from '../i18n.js'
import { groupBy4 } from '../util.js'
import CopyText from '../components/CopyText.vue'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'

const router = useRouter()
// First sign-in: the password step is behind (or was not needed); TOTP is required for this role.
const firstSteps = computed(() => [
  { key: 'signin', icon: 'login', label: t('guide.first.signin'), state: 'done' },
  { key: 'password', icon: 'key', label: t('guide.first.password'), state: 'done' },
  { key: 'totp', icon: 'lock', label: t('guide.first.totp'), state: 'current' },
  { key: 'start', icon: 'go', label: t('guide.first.start'), state: 'todo' },
])
const setup = ref(null)
const code = ref('')
const busy = ref(false)
const message = ref('')

async function start() {
  busy.value = true; message.value = ''
  try { setup.value = await post('/auth/totp/setup') } catch (e) { message.value = errText(e) } finally { busy.value = false }
}

async function enable() {
  busy.value = true; message.value = ''
  try {
    await post('/auth/totp/enable', { code: code.value })
    code.value = ''
    setSession(await get('/auth/me'))
    if (state.user) state.user.totp_setup_required = false
    router.replace({ name: 'overview' })
  } catch (e) {
    code.value = ''
    message.value = errText(e)
  } finally { busy.value = false }
}

async function logout() {
  try { await post('/auth/logout') } catch { /* ignore */ }
  clearSession()
  router.replace({ name: 'login' })
}
</script>

<style scoped>
.authhead { display: flex; align-items: center; gap: 10px; }
.authlogo { display: block; width: 40px; height: 40px; flex: none; }
</style>
