<template>
  <div class="page">
    <h1>{{ t('account.title') }}</h1>
    <div class="cols2">
      <section class="card">
        <h2>{{ t('account.profile') }}</h2>
        <dl class="kv">
          <dt>{{ t('login.username') }}</dt><dd class="mono">{{ safeText(user.username) }}</dd>
          <dt>{{ t('users.role') }}</dt><dd>{{ t('role.' + user.role) }}</dd>
        </dl>
        <form class="form" @submit.prevent="saveProfile">
          <label class="field">
            <span>{{ t('users.display_name') }}</span>
            <input v-model.trim="displayName" maxlength="100">
          </label>
          <div class="field">
            <label for="acct-lang">{{ t('app.language') }}</label>
            <SelectBox id="acct-lang" v-model="language" :options="langOptions" />
          </div>
          <div v-if="profileMsg" class="alert" :class="profileOk ? 'success' : 'error'">{{ profileMsg }}</div>
          <div class="actions"><button class="btn primary" type="submit" :disabled="busy"><Icon name="save" />{{ t('common.save') }}</button></div>
        </form>
        <div v-if="pwAge" class="pwage">
          <h3 class="charthead">{{ t('chart.account.password_age') }}</h3>
          <Meter :value="pwAge.days" :max="pwAge.max" :label="t('chart.account.password_age')"
                 :text="t('chart.account.password_age_v', { days: fmtNum(pwAge.days), max: fmtNum(pwAge.max), at: fmtDate(user.password_expires_at) })" />
        </div>
      </section>

      <section class="card">
        <h2>{{ t('totp.title') }}</h2>
        <p class="muted">{{ t('totp.intro') }}</p>
        <p>
          <span class="badge" :class="user.totp_enabled ? 'b-ok' : 'b-warn'">
            {{ user.totp_enabled ? t('totp.enabled') : t('totp.disabled') }}
          </span>
        </p>

        <template v-if="!user.totp_enabled">
          <div v-if="!setup">
            <button class="btn primary" type="button" :disabled="busy" @click="startSetup"><Icon name="key" />{{ t('totp.setup') }}</button>
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
                <input v-model.trim="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
              </label>
              <div class="actions">
                <button class="btn primary" type="submit" :disabled="busy"><Icon name="check" />{{ t('totp.enable') }}</button>
                <button class="btn ghost" type="button" @click="setup = null"><Icon name="cancel" />{{ t('common.cancel') }}</button>
              </div>
            </form>
          </div>
        </template>
        <form v-else class="form" @submit.prevent="disable">
          <p class="muted">{{ t('totp.disable_intro') }}</p>
          <label class="field">
            <span>{{ t('login.password') }}</span>
            <input v-model="disPassword" type="password" autocomplete="current-password" required>
          </label>
          <label class="field">
            <span>{{ t('login.totp') }}</span>
            <input v-model.trim="disCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
          </label>
          <div class="actions"><button class="btn danger" type="submit" :disabled="busy"><Icon name="unlock" />{{ t('totp.disable') }}</button></div>
        </form>
        <div v-if="totpMsg" class="alert" :class="totpOk ? 'success' : 'error'">{{ totpMsg }}</div>
      </section>
    </div>

    <ChangePassword embedded />

    <section class="card">
      <div class="cardhead">
        <h2>{{ t('sessions.title') }}</h2>
        <button class="btn small" type="button" :disabled="busy || sessions.length < 2" @click="revokeOthers"><Icon name="logout" />{{ t('sessions.revoke_others') }}</button>
      </div>
      <ErrorBox :error="sessError" />
      <div v-if="sessMsg" class="alert success">{{ sessMsg }}</div>
      <div v-if="sessions.length > 1" class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.account.sessions') }}</h3><SegBar :parts="sessParts" :label="t('chart.account.sessions')" /></div>
      </div>
      <DataTable id="account-sessions" :columns="sessCols" :rows="sessions" :default-sort="{ key: 'last_seen', dir: -1 }" :page-size="10">
        <template #cell-created_at="{ row }">{{ fmtMinute(row.created_at) }}</template>
        <template #cell-last_seen="{ row }">{{ fmtMinute(row.last_seen) }}</template>
        <template #cell-src_ip="{ row }"><span class="mono">{{ safeText(row.src_ip, 45) }}</span></template>
        <template #cell-user_agent="{ row }"><TruncText :text="row.user_agent" :max="80" /></template>
        <template #cell-current="{ row }"><span v-if="row.current" class="badge b-ok">{{ t('sessions.current') }}</span></template>
      </DataTable>
    </section>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { state } from '../store.js'
import { get, post, patch } from '../api.js'
import { t, errText, LANGUAGES, setLang, lang } from '../i18n.js'
import { safeText, groupBy4, fmtMinute, fmtDate, fmtNum } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import TruncText from '../components/TruncText.vue'
import CopyText from '../components/CopyText.vue'
import ChangePassword from './ChangePassword.vue'
import Icon from '../components/Icon.vue'
import SelectBox from '../components/SelectBox.vue'
import DataTable from '../components/DataTable.vue'
import SegBar from '../components/charts/SegBar.vue'
import Meter from '../components/charts/Meter.vue'

const user = computed(() => state.user || {})
const displayName = ref(user.value.display_name || '')
const language = ref(user.value.language || lang.value)
const busy = ref(false)
const profileMsg = ref('')
const profileOk = ref(false)
const setup = ref(null)
const code = ref('')
const disPassword = ref('')
const disCode = ref('')
const totpMsg = ref('')
const totpOk = ref(false)

const sessions = ref([])
const sessError = ref(null)
const sessMsg = ref('')

const langOptions = computed(() => LANGUAGES.map((l) => ({ value: l.code, label: l.label })))
const sessCols = computed(() => [
  { key: 'created_at', label: t('sessions.created'), nowrap: true, text: (x) => fmtMinute(x.created_at) },
  { key: 'last_seen', label: t('sessions.last_seen'), nowrap: true, text: (x) => fmtMinute(x.last_seen) },
  { key: 'src_ip', label: t('audit.src_ip'), nowrap: true },
  { key: 'user_agent', label: t('sessions.user_agent') },
  { key: 'current', label: t('sessions.current'), value: (x) => (x.current ? t('sessions.current') : '') },
])
const sessParts = computed(() => [
  { key: 'current', label: t('sessions.current'), value: sessions.value.filter((x) => x.current).length, tone: 's1' },
  { key: 'other', label: t('chart.account.other_sessions'), value: sessions.value.filter((x) => !x.current).length, tone: 's2' },
])
// Days since the last password change against the maximum age (only when passwords expire).
const pwAge = computed(() => {
  const max = state.meta.password_policy && state.meta.password_policy.max_age_days
  const at = user.value.password_changed_at
  if (!(max > 0) || !at) return null
  const days = Math.max(0, Math.floor((Date.now() - new Date(at).getTime()) / 86400000))
  return isNaN(days) ? null : { days, max }
})

async function loadSessions() {
  sessError.value = null
  try { sessions.value = (await get('/auth/sessions')).items || [] } catch (e) { sessError.value = e }
}

async function revokeOthers() {
  if (!window.confirm(t('sessions.revoke_confirm'))) return
  busy.value = true; sessMsg.value = ''
  try {
    await post('/auth/sessions/revoke-others')
    sessMsg.value = t('sessions.revoked')
    await loadSessions()
  } catch (e) { sessError.value = e } finally { busy.value = false }
}

onMounted(loadSessions)

async function refreshMe() {
  try { const me = await get('/auth/me'); state.user = me.user; state.csrf = me.csrf_token || state.csrf } catch { /* ignore */ }
}

async function saveProfile() {
  busy.value = true; profileMsg.value = ''
  try {
    const u = await patch('/auth/me', { display_name: displayName.value, language: language.value })
    state.user = (u && u.user) || u || state.user
    setLang(language.value)
    profileOk.value = true; profileMsg.value = t('common.saved')
  } catch (e) { profileOk.value = false; profileMsg.value = errText(e) } finally { busy.value = false }
}

async function startSetup() {
  busy.value = true; totpMsg.value = ''
  try { setup.value = await post('/auth/totp/setup') } catch (e) { totpOk.value = false; totpMsg.value = errText(e) } finally { busy.value = false }
}

async function enable() {
  busy.value = true; totpMsg.value = ''
  try {
    await post('/auth/totp/enable', { code: code.value })
    setup.value = null; code.value = ''
    await refreshMe()
    totpOk.value = true; totpMsg.value = t('totp.now_enabled')
  } catch (e) { totpOk.value = false; totpMsg.value = errText(e) } finally { busy.value = false }
}

async function disable() {
  busy.value = true; totpMsg.value = ''
  try {
    await post('/auth/totp/disable', { password: disPassword.value, code: disCode.value })
    disPassword.value = ''; disCode.value = ''
    await refreshMe()
    totpOk.value = true; totpMsg.value = t('totp.now_disabled')
  } catch (e) { totpOk.value = false; totpMsg.value = errText(e) } finally { busy.value = false }
}
</script>
