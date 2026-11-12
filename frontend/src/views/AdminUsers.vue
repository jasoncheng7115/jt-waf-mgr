<!-- Local accounts: add, change role, lock / unlock, disable, expiry, sign out, reset password. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('users.title') }}</h1>
      <button class="btn small ghost" type="button" :aria-expanded="showGuide ? 'true' : 'false'" @click="toggleGuide">
        <Icon name="help" />{{ showGuide ? t('guide.hide') : t('guide.show') }}</button>
      <RouterLink class="btn small" to="/admin/users/review"><Icon name="report" />{{ t('review.open') }}</RouterLink>
    </div>
    <FlowSteps v-if="showGuide" :title="t('guide.user.title')" :steps="lifecycle" :note="t('guide.user.note')" />
    <ErrorBox :error="error" />
    <section class="card">
      <h2><Icon name="add" /> {{ t('users.add') }}</h2>
      <form class="filters inline" @submit.prevent="create">
        <label class="field"><span>{{ t('login.username') }}</span><input v-model.trim="nu.username" maxlength="64" required pattern="[A-Za-z0-9._\-]{1,64}" autocomplete="off"></label>
        <label class="field"><span>{{ t('users.display_name') }}</span><input v-model.trim="nu.display_name" maxlength="100"></label>
        <div class="field"><label for="nu-role">{{ t('users.role') }}</label>
          <SelectBox id="nu-role" v-model="nu.role" :options="roleOptions" />
        </div>
        <div class="field"><label for="nu-expires">{{ t('users.expires') }}</label><DatePicker id="nu-expires" v-model="nu.expires" :min="today" /></div>
        <div class="actions"><button class="btn primary" type="submit" :disabled="busy"><Icon name="add" />{{ t('users.create') }}</button></div>
      </form>
      <p class="muted small">{{ t('users.expires_hint') }}</p>
      <div v-if="formMsg" class="alert error">{{ formMsg }}</div>
      <div v-if="tempPw" class="alert success">
        <p>{{ t('users.temp_password', { user: tempPw.user }) }}</p>
        <CopyText :value="tempPw.password" />
        <p class="small">{{ t('users.temp_password_note') }}</p>
        <button class="btn small ghost" type="button" @click="tempPw = null"><Icon name="dismiss" />{{ t('common.dismiss') }}</button>
      </div>
      <div v-if="okMsg" class="alert success">{{ okMsg }}</div>
    </section>

    <section class="card">
      <h2><Icon name="users" /> {{ t('users.title') }} <span class="count">{{ users.length }}</span></h2>
      <div v-if="users.length" class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.users.roles') }}</h3><SegBar :parts="roleParts" :label="t('chart.users.roles')" /></div>
        <div><h3 class="charthead">{{ t('chart.users.totp') }}</h3><SegBar :parts="totpParts" :label="t('chart.users.totp')" /></div>
        <div><h3 class="charthead">{{ t('chart.users.state') }}</h3><SegBar :parts="stateParts" :label="t('chart.users.state')" /></div>
      </div>
      <DataTable id="admin-users" :columns="cols" :rows="users" row-key="username" :row-class="(u) => ({ dim: u.disabled })">
        <template #cell-username="{ row }"><span class="mono">{{ safeText(row.username, 64) }}</span><span v-if="isSelf(row)" class="chip tag">{{ t('users.you') }}</span></template>
        <template #cell-display_name="{ row }">{{ safeText(row.display_name, 100) }}</template>
        <template #cell-role="{ row }">
          <SelectBox small :model-value="row.role" :options="roleOptions" :disabled="isSelf(row) || busy" :aria-label="t('users.role_of', { user: safeText(row.username, 64) })"
                     @update:model-value="(v) => v !== row.role && update(row, { role: v })" />
        </template>
        <template #cell-totp="{ row }"><span class="badge" :class="row.totp_enabled ? 'b-ok' : 'b-warn'">{{ row.totp_enabled ? t('totp.enabled') : t('totp.disabled') }}</span></template>
        <template #cell-state="{ row }">{{ row.disabled ? t('users.disabled') : t('users.active') }}
          <span v-if="row.locked" class="badge b-blocked">{{ t('users.locked') }}</span>
          <span v-if="row.must_change_password" class="badge b-warn">{{ t('review.must_change') }}</span></template>
        <template #cell-last_login="{ row }">{{ fmtMinute(row.last_login) }}<div v-if="row.last_login_ip" class="sub mono">{{ safeText(row.last_login_ip, 45) }}</div></template>
        <template #cell-expires_at="{ row }">{{ fmtDate(row.expires_at) }}</template>
        <template #cell-dormant_at="{ row }">{{ row.disabled ? '—' : fmtDate(row.dormant_at) }}</template>
        <template #cell-created_at="{ row }">{{ fmtDate(row.created_at) }}</template>
        <template #cell-actions="{ row }"><div class="rowbtns">
          <button v-if="row.locked" class="btn small" type="button" :disabled="busy" @click="update(row, { unlock: true }, 'users.unlocked')"><Icon name="unlock" />{{ t('users.unlock') }}</button>
          <template v-if="!isSelf(row)">
            <button class="btn small" type="button" :disabled="busy" @click="update(row, { disabled: !row.disabled })">
              <Icon :name="row.disabled ? 'check' : 'block'" />{{ row.disabled ? t('users.enable') : t('users.disable') }}</button>
            <button class="btn small ghost" type="button" :disabled="busy" :aria-pressed="editing === row.username ? 'true' : 'false'" @click="toggleEdit(row)">
              <Icon name="more" />{{ t('users.more') }}</button>
          </template>
        </div></template>
      </DataTable>
    </section>

    <section v-if="editUser" class="card edituser">
      <div class="cardhead">
        <h2><Icon name="user" /> <span class="mono">{{ safeText(editUser.username, 64) }}</span></h2>
        <button class="btn small ghost" type="button" @click="editing = null"><Icon name="close" />{{ t('common.cancel') }}</button>
      </div>
      <form class="filters inline" @submit.prevent="saveExpiry(editUser)">
        <div class="field"><label for="edit-expires">{{ t('users.expires') }}</label><DatePicker id="edit-expires" v-model="editExpiry" :min="today" /></div>
        <div class="actions">
          <button class="btn small primary" type="submit" :disabled="busy"><Icon name="save" />{{ t('common.save') }}</button>
          <button class="btn small ghost" type="button" :disabled="busy || !editExpiry" @click="editExpiry = ''"><Icon name="clear" />{{ t('users.no_expiry') }}</button>
          <button class="btn small" type="button" :disabled="busy" @click="signout(editUser)"><Icon name="logout" />{{ t('users.signout') }}</button>
          <button class="btn small danger" type="button" :disabled="busy" @click="reset(editUser)"><Icon name="key" />{{ t('users.reset') }}</button>
        </div>
      </form>
      <p class="muted small">{{ t('users.password_changed', { at: fmtMinute(editUser.password_changed_at) }) }}<template v-if="editUser.password_expires_at"> · {{ t('users.password_expires', { at: fmtDate(editUser.password_expires_at) }) }}</template></p>
    </section>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { get, post, patch } from '../api.js'
import { state, ROLES } from '../store.js'
import { t, errText } from '../i18n.js'
import { safeText, fmtMinute, fmtDate, dateInputToIso, isoToDateInput } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import CopyText from '../components/CopyText.vue'
import Icon from '../components/Icon.vue'
import SelectBox from '../components/SelectBox.vue'
import DatePicker from '../components/DatePicker.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'

const users = ref([])
const settings = ref(null)
const error = ref(null)
const busy = ref(false)
const formMsg = ref('')
const okMsg = ref('')
const tempPw = ref(null)
const editing = ref(null)
const editExpiry = ref('')
const nu = reactive({ username: '', display_name: '', role: 'viewer', expires: '' })
const today = isoToDateInput(new Date().toISOString())

const GUIDE_KEY = 'jtwaf.guide.users'
const showGuide = ref(readGuide())
function readGuide() { try { return window.localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage blocked */ }
}

const roleOptions = computed(() => ROLES.map((r) => ({ value: r, label: t('role.' + r) })))
const editUser = computed(() => users.value.find((u) => u.username === editing.value) || null)

const cols = computed(() => [
  { key: 'username', label: t('login.username'), required: true },
  { key: 'display_name', label: t('users.display_name') },
  { key: 'role', label: t('users.role'), value: (u) => ROLES.indexOf(u.role), text: (u) => t('role.' + u.role) },
  { key: 'totp', label: t('totp.title'), value: (u) => (u.totp_enabled ? t('totp.enabled') : t('totp.disabled')) },
  { key: 'state', label: t('users.state'), nowrap: true,
    value: (u) => (u.disabled ? t('users.disabled') : t('users.active')) + (u.locked ? ' ' + t('users.locked') : '') + (u.must_change_password ? ' ' + t('review.must_change') : '') },
  { key: 'last_login', label: t('users.last_login'), nowrap: true, text: (u) => fmtMinute(u.last_login) + ' ' + (u.last_login_ip || '') },
  { key: 'expires_at', label: t('users.expires'), nowrap: true, text: (u) => fmtDate(u.expires_at) },
  { key: 'dormant_at', label: t('users.dormant_on'), nowrap: true, value: (u) => (u.disabled ? '' : u.dormant_at), text: (u) => (u.disabled ? '' : fmtDate(u.dormant_at)) },
  { key: 'created_at', label: t('users.created'), nowrap: true, hidden: true, text: (u) => fmtDate(u.created_at) },
  { key: 'actions', label: t('users.actions'), sortable: false, filterable: false, required: true, value: () => '' },
])

const live = computed(() => users.value.filter((u) => !u.disabled))
const roleParts = computed(() => ROLES.slice().reverse().map((r, i) => ({
  key: r, label: t('role.' + r), value: live.value.filter((u) => u.role === r).length, tone: ['s1', 's2', 's3', 'muted'][i],
})))
const totpParts = computed(() => [
  { key: 'on', label: t('totp.enabled'), value: live.value.filter((u) => u.totp_enabled).length, tone: 'good' },
  { key: 'off', label: t('totp.disabled'), value: live.value.filter((u) => !u.totp_enabled).length, tone: 'warning' },
])
const stateParts = computed(() => [
  { key: 'active', label: t('users.active'), value: live.value.filter((u) => !u.locked).length, tone: 'good' },
  { key: 'locked', label: t('users.locked'), value: live.value.filter((u) => u.locked).length, tone: 'critical' },
  { key: 'disabled', label: t('users.disabled'), value: users.value.filter((u) => u.disabled).length, tone: 'muted' },
])

// Lifecycle, with the policy numbers this page can see (meta: password policy; /settings: TOTP roles).
const lifecycle = computed(() => {
  const p = state.meta.password_policy || {}
  const roles = settings.value && Array.isArray(settings.value.require_totp_roles) ? settings.value.require_totp_roles : null
  const pwRule = p.min_length ? t('guide.user.first_pw', { n: p.min_length }) : t('guide.user.first_pw_any')
  const totpRule = roles ? (roles.length ? t('guide.user.first_totp', { roles: roles.map((r) => t('role.' + r)).join(', ') }) : t('guide.user.first_totp_none'))
    : t('guide.user.first_totp_some')
  return [
    { key: 'create', icon: 'add', label: t('guide.user.create'), desc: t('guide.user.create_d') },
    { key: 'temp', icon: 'key', label: t('guide.user.temp'), desc: t('guide.user.temp_d') },
    { key: 'first', icon: 'login', label: t('guide.user.first'), desc: pwRule + ' ' + totpRule },
    { key: 'active', icon: 'user', label: t('guide.user.active'), state: 'done',
      desc: p.max_age_days > 0 ? t('guide.user.active_d_age', { n: p.max_age_days }) : t('guide.user.active_d') },
    { key: 'locked', icon: 'lock', label: t('guide.user.locked'), desc: t('guide.user.locked_d') },
    { key: 'disabled', icon: 'block', label: t('guide.user.disabled'), state: 'skip', desc: t('guide.user.disabled_d') },
  ]
})

function isSelf(u) { return state.user && u.username === state.user.username }

async function load() {
  try { users.value = (await get('/users')).items || [] } catch (e) { error.value = e }
}
async function loadSettings() {
  try { settings.value = await get('/settings') } catch { /* the guide falls back to general wording */ }
}

async function create() {
  busy.value = true; formMsg.value = ''; tempPw.value = null; okMsg.value = ''
  try {
    const body = { username: nu.username, display_name: nu.display_name, role: nu.role }
    const exp = dateInputToIso(nu.expires)
    if (exp) body.expires_at = exp
    const r = await post('/users', body)
    tempPw.value = { user: nu.username, password: r.temporary_password }
    nu.username = ''; nu.display_name = ''; nu.role = 'viewer'; nu.expires = ''
    await load()
  } catch (e) { formMsg.value = errText(e) } finally { busy.value = false }
}

async function update(u, body, okKey) {
  busy.value = true; error.value = null; okMsg.value = ''
  try {
    await patch('/users/' + encodeURIComponent(u.username), body)
    if (okKey) okMsg.value = t(okKey, { user: u.username })
  } catch (e) { error.value = e }
  busy.value = false
  await load()
}

function toggleEdit(u) {
  if (editing.value === u.username) { editing.value = null; return }
  editing.value = u.username
  editExpiry.value = isoToDateInput(u.expires_at)
}

async function saveExpiry(u) {
  await update(u, { expires_at: dateInputToIso(editExpiry.value) }, 'users.saved')
  if (!error.value) editing.value = null
}

async function signout(u) {
  if (!window.confirm(t('users.signout_confirm', { user: u.username }))) return
  busy.value = true; error.value = null; okMsg.value = ''
  try {
    await post('/users/' + encodeURIComponent(u.username) + '/signout')
    okMsg.value = t('users.signed_out', { user: u.username })
  } catch (e) { error.value = e }
  busy.value = false
}

async function reset(u) {
  if (!window.confirm(t('users.reset_confirm', { user: u.username }))) return
  busy.value = true; error.value = null; tempPw.value = null; okMsg.value = ''
  try {
    const r = await post('/users/' + encodeURIComponent(u.username) + '/reset')
    tempPw.value = { user: u.username, password: r.temporary_password }
  } catch (e) { error.value = e }
  busy.value = false
  await load()
}

onMounted(() => { load(); loadSettings() })
</script>

<style scoped>
.rowbtns { display: flex; flex-wrap: wrap; gap: 4px; }
.edituser { border-color: var(--accent); }
</style>
