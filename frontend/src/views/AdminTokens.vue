<!-- API tokens for other systems: scopes, source networks, expiry; never approve, accounts or settings. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('tokens.title') }}</h1>
      <button class="btn small ghost" type="button" :aria-expanded="showGuide ? 'true' : 'false'" @click="toggleGuide">
        <Icon name="help" />{{ showGuide ? t('guide.hide') : t('guide.show') }}</button>
    </div>
    <p class="muted">{{ t('tokens.intro') }}</p>
    <FlowSteps v-if="showGuide" :title="t('guide.token.title')" :steps="tokenFlow" :note="t('guide.token.note')" />
    <ErrorBox :error="error" />
    <section class="card">
      <h2><Icon name="add" /> {{ t('tokens.add') }}</h2>
      <form class="form" @submit.prevent="create">
        <div class="filters inline">
          <label class="field"><span>{{ t('tokens.name') }}</span><input v-model.trim="nt.name" maxlength="64" required placeholder="jt-ipam"></label>
          <label class="field grow"><span>{{ t('tokens.allowed_cidrs') }}</span><input v-model.trim="nt.cidrs" maxlength="1000" placeholder="192.0.2.10/32, 198.51.100.0/24"></label>
          <div class="field"><label for="nt-expires">{{ t('tokens.expires_at') }}</label><DatePicker id="nt-expires" v-model="nt.expires" :min="today" /></div>
        </div>
        <fieldset class="field">
          <legend>{{ t('tokens.scopes') }}</legend>
          <label v-for="s in SCOPES" :key="s" class="check">
            <input v-model="nt.scopes" type="checkbox" :value="s"> <span class="mono">{{ s }}</span> <span class="muted small">{{ t('scope.' + s.replace(':', '_')) }}</span>
          </label>
        </fieldset>
        <p class="muted small">{{ t('tokens.cidr_hint') }}</p>
        <div v-if="formMsg" class="alert error">{{ formMsg }}</div>
        <div class="actions"><button class="btn primary" type="submit" :disabled="busy || !nt.scopes.length"><Icon name="key" />{{ t('tokens.create') }}</button></div>
      </form>
      <div v-if="secret" class="alert success">
        <p>{{ t('tokens.secret_once') }}</p>
        <CopyText :value="secret" />
        <button class="btn small ghost" type="button" @click="secret = ''"><Icon name="dismiss" />{{ t('common.dismiss') }}</button>
      </div>
    </section>
    <section class="card">
      <h2><Icon name="key" /> {{ t('tokens.title') }} <span class="count">{{ tokens.length }}</span></h2>
      <div v-if="tokens.length" class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.tokens.state') }}</h3><SegBar :parts="stateParts" :label="t('chart.tokens.state')" /></div>
        <div><h3 class="charthead">{{ t('chart.tokens.scopes') }}</h3>
          <HBars :items="scopeItems" :series="[{ key: 'n', label: t('chart.tokens.active_tokens'), tone: 's1' }]" mono /></div>
      </div>
      <DataTable id="admin-tokens" :columns="cols" :rows="tokens" :row-class="(k) => ({ dim: stateOf(k) !== 'active' })" :default-sort="{ key: 'created_at', dir: -1 }">
        <template #cell-name="{ row }">{{ safeText(row.name, 64) }}</template>
        <template #cell-id="{ row }"><span class="mono">{{ safeText(row.id, 40) }}</span></template>
        <template #cell-scopes="{ row }"><span v-for="s in row.scopes" :key="s" class="chip tag mono">{{ safeText(s, 40) }}</span></template>
        <template #cell-allowed_cidrs="{ row }"><span class="mono small">{{ (row.allowed_cidrs || []).map((c) => safeText(c, 50)).join(', ') || t('tokens.any_source') }}</span></template>
        <template #cell-expires_at="{ row }">{{ row.expires_at ? fmtShortTime(row.expires_at) : t('tokens.never') }}</template>
        <template #cell-created_at="{ row }">{{ fmtShortTime(row.created_at) }} <span class="muted small">{{ safeText(row.created_by, 64) }}</span></template>
        <template #cell-last_used_at="{ row }">{{ fmtShortTime(row.last_used_at) }}</template>
        <template #cell-state="{ row }">
          <span v-if="row.revoked" class="badge b-warn">{{ t('tokens.revoked') }}</span>
          <template v-else>
            <span v-if="stateOf(row) === 'expired'" class="badge b-warn">{{ t('tokens.expired') }}</span>
            <button class="btn small danger" type="button" :disabled="busy" @click="revoke(row)"><Icon name="delete" />{{ t('tokens.revoke') }}</button>
          </template>
        </template>
      </DataTable>
    </section>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { get, post, del } from '../api.js'
import { t, errText } from '../i18n.js'
import { safeText, fmtShortTime, isoToDateInput } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import CopyText from '../components/CopyText.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import DatePicker from '../components/DatePicker.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'

const SCOPES = ref(['status:read', 'events:read', 'rules:read', 'lookups:read', 'changes:read', 'changes:propose'])
const tokens = ref([])
const error = ref(null)
const busy = ref(false)
const formMsg = ref('')
const secret = ref('')
const nt = reactive({ name: '', cidrs: '', expires: '', scopes: [] })
const today = isoToDateInput(new Date().toISOString())

const GUIDE_KEY = 'jtwaf.guide.tokens'
const showGuide = ref(readGuide())
function readGuide() { try { return window.localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage blocked */ }
}

// What the server does with every request that carries a token (web/server.py, auth.token()).
const tokenFlow = computed(() => [
  { key: 'create', icon: 'key', label: t('guide.token.create'), desc: t('guide.token.create_d') },
  { key: 'call', icon: 'send', label: t('guide.token.call'), desc: t('guide.token.call_d') },
  { key: 'valid', icon: 'verify', label: t('guide.token.valid'), desc: t('guide.token.valid_d') },
  { key: 'source', icon: 'network', label: t('guide.token.source'), desc: t('guide.token.source_d') },
  { key: 'scope', icon: 'shield', label: t('guide.token.scope'), desc: t('guide.token.scope_d') },
  { key: 'done', icon: 'history', label: t('guide.token.done'), state: 'done', desc: t('guide.token.done_d') },
])

const cols = computed(() => [
  { key: 'name', label: t('tokens.name'), required: true },
  { key: 'id', label: 'ID', hidden: true },
  { key: 'scopes', label: t('tokens.scopes'), value: (k) => (k.scopes || []).join(' ') },
  { key: 'allowed_cidrs', label: t('tokens.allowed_cidrs'), value: (k) => (k.allowed_cidrs || []).join(' '),
    text: (k) => (k.allowed_cidrs || []).join(' ') || t('tokens.any_source') },
  { key: 'expires_at', label: t('tokens.expires_at'), nowrap: true, text: (k) => (k.expires_at ? fmtShortTime(k.expires_at) : t('tokens.never')) },
  { key: 'created_at', label: t('tokens.created'), nowrap: true, text: (k) => fmtShortTime(k.created_at) + ' ' + (k.created_by || '') },
  { key: 'last_used_at', label: t('tokens.last_used'), nowrap: true, text: (k) => fmtShortTime(k.last_used_at) },
  { key: 'state', label: t('users.state'), required: true, nowrap: true, value: (k) => t('tokens.st.' + stateOf(k)) },
])

function stateOf(k) {
  if (k.revoked) return 'revoked'
  if (k.expires_at && new Date(k.expires_at) < new Date()) return 'expired'
  return 'active'
}
const stateParts = computed(() => [
  { key: 'active', label: t('tokens.st.active'), value: tokens.value.filter((k) => stateOf(k) === 'active').length, tone: 'good' },
  { key: 'expired', label: t('tokens.st.expired'), value: tokens.value.filter((k) => stateOf(k) === 'expired').length, tone: 'warning' },
  { key: 'revoked', label: t('tokens.st.revoked'), value: tokens.value.filter((k) => stateOf(k) === 'revoked').length, tone: 'muted' },
])
const scopeItems = computed(() => SCOPES.value.map((s) => ({
  key: s, label: s, values: { n: tokens.value.filter((k) => stateOf(k) === 'active' && (k.scopes || []).includes(s)).length },
})))

async function load() {
  try {
    const r = await get('/tokens')
    tokens.value = r.items || []
    if (Array.isArray(r.scopes) && r.scopes.length) SCOPES.value = r.scopes
  } catch (e) { error.value = e }
}

function expiresIso(d) {
  if (!d) return null
  // end of the chosen day, local time
  const dt = new Date(d + 'T23:59:59')
  if (isNaN(dt)) return null
  const off = -dt.getTimezoneOffset()
  const p = (n) => String(Math.floor(Math.abs(n))).padStart(2, '0')
  return d + 'T23:59:59' + (off >= 0 ? '+' : '-') + p(off / 60) + ':' + p(off % 60)
}

async function create() {
  busy.value = true; formMsg.value = ''; secret.value = ''
  try {
    const cidrs = nt.cidrs.split(/[\s,]+/).filter(Boolean)
    const r = await post('/tokens', { name: nt.name, scopes: nt.scopes.slice(), allowed_cidrs: cidrs, expires_at: expiresIso(nt.expires) })
    secret.value = r.secret
    nt.name = ''; nt.cidrs = ''; nt.expires = ''; nt.scopes = []
    await load()
  } catch (e) { formMsg.value = errText(e) } finally { busy.value = false }
}

async function revoke(tk) {
  if (!window.confirm(t('tokens.revoke_confirm', { name: tk.name }))) return
  busy.value = true; error.value = null
  try { await del('/tokens/' + encodeURIComponent(tk.id)) } catch (e) { error.value = e }
  busy.value = false
  await load()
}

onMounted(load)
</script>
