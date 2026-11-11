<template>
  <div :class="forced ? 'authbox' : 'card'">
    <div v-if="forced" class="authhead">
      <img class="authlogo" src="/logo-mark.svg" alt="" width="40" height="40">
      <h1 class="authtitle">jt-waf-mgr</h1>
    </div>
    <FlowSteps v-if="forced" compact :title="t('guide.first.title')" :steps="firstSteps" />
    <h2>{{ t('password.title') }}</h2>
    <p v-if="forced" class="alert info">{{ t('password.must_change') }}</p>
    <ul v-if="policyLines.length" class="plainlist small muted policy">
      <li v-for="(l, i) in policyLines" :key="i">{{ l }}</li>
    </ul>
    <form class="form" @submit.prevent="submit">
      <input type="text" name="username" autocomplete="username" :value="username" class="sr-only" tabindex="-1" readonly aria-hidden="true">
      <label class="field">
        <span>{{ t('password.current') }}</span>
        <input v-model="current" type="password" autocomplete="current-password" required maxlength="1024">
      </label>
      <label class="field">
        <span>{{ t('password.new') }}</span>
        <input v-model="next1" type="password" autocomplete="new-password" required maxlength="1024">
      </label>
      <label class="field">
        <span>{{ t('password.confirm') }}</span>
        <input v-model="next2" type="password" autocomplete="new-password" required maxlength="1024">
      </label>
      <div v-if="message" class="alert" :class="ok ? 'success' : 'error'" role="alert">{{ message }}</div>
      <div class="actions">
        <button type="submit" class="btn primary" :disabled="busy"><Icon name="key" />{{ t('password.submit') }}</button>
        <button v-if="forced" type="button" class="btn ghost" @click="logout"><Icon name="logout" />{{ t('nav.logout') }}</button>
      </div>
    </form>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { post, get } from '../api.js'
import { state, setSession, clearSession } from '../store.js'
import { t, errText } from '../i18n.js'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'

const props = defineProps({ embedded: Boolean })
const router = useRouter()
const forced = computed(() => !props.embedded)
const username = computed(() => (state.user && state.user.username) || '')
const policyLines = computed(() => {
  const p = state.meta.password_policy
  if (!p) return []
  const out = [t('policy.min_length', { n: p.min_length })]
  if (p.min_classes > 0) out.push(t('policy.min_classes', { n: p.min_classes }))
  out.push(p.history > 0 ? t('policy.history', { n: p.history }) : t('policy.not_current'))
  if (p.max_age_days > 0) out.push(t('policy.max_age', { n: p.max_age_days }))
  if (p.min_age_hours > 0) out.push(t('policy.min_age', { n: p.min_age_hours }))
  return out
})
// Where a forced password change stands in the first sign-in (must_change, then TOTP for the roles that need it).
const firstSteps = computed(() => [
  { key: 'signin', icon: 'login', label: t('guide.first.signin'), state: 'done' },
  { key: 'password', icon: 'key', label: t('guide.first.password'), state: 'current' },
  { key: 'totp', icon: 'lock', label: t('guide.first.totp'), state: state.user && state.user.totp_setup_required ? 'todo' : 'skip' },
  { key: 'start', icon: 'go', label: t('guide.first.start'), state: 'todo' },
])
const current = ref('')
const next1 = ref('')
const next2 = ref('')
const busy = ref(false)
const message = ref('')
const ok = ref(false)

async function submit() {
  message.value = ''
  ok.value = false
  if (next1.value !== next2.value) { message.value = t('password.mismatch'); return }
  busy.value = true
  try {
    await post('/auth/password', { current_password: current.value, new_password: next1.value })
    current.value = next1.value = next2.value = ''
    try { setSession(await get('/auth/me')) } catch { /* keep state */ }
    ok.value = true
    message.value = t('password.changed')
    if (forced.value) router.replace({ name: state.user && state.user.totp_setup_required ? 'setup-totp' : 'overview' })
  } catch (e) {
    if (e.code === 'password_too_recent' && e.details && e.details.retry_after) {
      message.value = t('error.password_too_recent', { hours: Math.ceil(Number(e.details.retry_after) / 3600) })
    } else {
      message.value = errText(e)
    }
  } finally {
    busy.value = false
  }
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
.policy li { display: block; border-bottom: none; padding: 1px 0; }
</style>
