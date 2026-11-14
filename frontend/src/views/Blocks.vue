<!-- /blocks: temporary IP blocks (an nginx deny list). Other systems add them with an API token; approvers add and
     end them here. Whether the list file is really loaded, and what it does not cover, is shown on top. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('blocks.title') }}</h1>
      <button type="button" class="btn small ghost" :disabled="loading" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
    </div>
    <p class="muted">{{ t('blocks.intro') }}</p>
    <ErrorBox :error="error" />
    <Loading v-if="loading && !data" />
    <template v-if="data">
      <div v-if="!data.enabled" class="alert info" role="status"><Icon name="info" /> {{ t('blocks.off') }}
        <RouterLink v-if="isAdmin" class="btn small" to="/admin/settings"><Icon name="settings" />{{ t('traffic.to_settings') }}</RouterLink></div>
      <div v-if="!data.included" class="alert warn" role="status">
        <Icon name="warning" /> {{ data.included_in === 'server' ? t('blocks.in_server') : t('blocks.not_included') }}
        <pre class="code small">include {{ safeText(data.file, 300) }};</pre>
        <span class="muted small">{{ t('blocks.include_hint') }}</span>
      </div>
      <div class="tiles">
        <div class="tile stat"><div class="tl"><Icon name="lock" />{{ t('blocks.active') }}</div><div class="tv">{{ fmtNum(activeCount) }}</div>
          <div class="ts"><span class="tsub">{{ t('blocks.limit', { n: fmtNum(data.limits.max_active) }) }}</span></div></div>
        <div class="tile stat"><div class="tl"><Icon name="verify" />{{ t('blocks.written') }}</div>
          <div class="tv small">{{ data.applied.at ? fmtShortTime(data.applied.at) : '—' }}</div>
          <div class="ts"><span class="badge" :class="data.in_sync ? 'b-ok' : (data.pending ? 'b-warn' : 'b-blocked')">{{ syncText }}</span></div></div>
        <div class="tile stat"><div class="tl"><Icon name="timer" />{{ t('blocks.ttl') }}</div>
          <div class="tv small">{{ dur(data.limits.default_ttl) }}</div>
          <div class="ts"><span class="tsub">{{ t('blocks.ttl_limits', { api: dur(data.limits.api_max_ttl), ui: dur(data.limits.ui_max_ttl) }) }}</span></div></div>
      </div>
      <p v-if="data.applied.ok === false" class="alert error"><Icon name="error" /> {{ safeText(data.applied.summary, 500) }}</p>

      <section v-if="canAdd && data.enabled" class="card form">
        <h2><Icon name="add" /> {{ t('blocks.add') }}</h2>
        <div class="filters">
          <label class="field"><span>{{ t('blocks.ip') }}</span><input v-model.trim="nb.ip" class="mono" maxlength="64" placeholder="203.0.113.7" spellcheck="false"></label>
          <div class="field"><label for="blk-ttl">{{ t('blocks.for') }}</label><SelectBox id="blk-ttl" v-model="nb.ttl" :options="ttlOpts" /></div>
          <label class="field grow"><span>{{ t('blocks.reason') }}</span><input v-model.trim="nb.reason" maxlength="300"></label>
        </div>
        <p class="muted small">{{ t('blocks.add_hint') }}</p>
        <p v-if="nb.ttl === 'permanent'" class="alert warn small">{{ t('blocks.permanent_hint') }}</p>
        <ErrorBox :error="addError" />
        <div class="actions"><button type="button" class="btn primary danger" :disabled="busy || !nb.ip || !nb.reason" @click="add"><Icon name="lock" />{{ t('blocks.add_btn') }}</button></div>
      </section>

      <div class="seg" role="group" :aria-label="t('blocks.state')">
        <button v-for="s in STATES" :key="s" type="button" :class="{ on: state === s }" :aria-pressed="state === s ? 'true' : 'false'" @click="state = s; load()">
          <Icon :name="STATE_ICON[s]" />{{ t('blocks.state.' + s) }}</button>
      </div>
      <DataTable id="blocks" :columns="cols" :rows="data.items" :row-key="(r) => r.id" :page-size="50">
        <template #cell-ip="{ row }"><span class="ipcell"><RouterLink class="mono" :data-ip="row.ip" :to="'/lookup/' + encodeURIComponent(row.ip.split('/')[0])">{{ safeText(row.ip, 64) }}</RouterLink>
          <GeoTag :geo="row.geo" compact /></span></template>
        <template #cell-source="{ row }"><span class="mono small">{{ safeText(row.source, 64) }}</span>
          <div class="sub">{{ safeText(row.created_by, 64) }} · {{ row.via === 'token' ? t('blocks.via_token') : row.via === 'system' ? t('blocks.via_system') : t('blocks.via_ui') }}</div></template>
        <template #cell-reason="{ row }"><TruncText :text="row.reason" :max="120" /></template>
        <template #cell-created_at="{ row }"><span class="nowrap">{{ fmtShortTime(row.created_at) }}</span></template>
        <template #cell-expires_at="{ row }"><span v-if="row.permanent" class="badge b-blocked"><Icon name="lock" />{{ t('blocks.permanent') }}</span>
          <span v-else class="nowrap">{{ fmtShortTime(row.expires_at) }}</span>
          <div v-if="row.extended" class="sub">{{ t('blocks.extended_n', { n: row.extended }) }}</div></template>
        <template #cell-state="{ row }"><span class="badge" :class="STATE_BADGE[row.state]">{{ t('blocks.state.' + row.state) }}</span>
          <div v-if="row.ended_by" class="sub">{{ safeText(row.ended_by, 64) }}</div></template>
        <template #cell-act="{ row }">
          <div v-if="row.state === 'active' && canAdd" class="rowacts">
            <button v-if="!row.permanent" type="button" class="btn tiny" @click="openExtend(row)"><Icon name="timer" />{{ t('blocks.extend') }}</button>
            <button type="button" class="btn tiny danger" @click="ending = row; note = ''; extending = null"><Icon name="unlock" />{{ t('blocks.end') }}</button>
          </div>
        </template>
      </DataTable>
      <section v-if="ending" class="card form" role="dialog" :aria-label="t('blocks.end')">
        <h2><Icon name="unlock" /> {{ t('blocks.end_title', { ip: ending.ip }) }}</h2>
        <label class="field"><span>{{ t('blocks.note') }}</span><input v-model.trim="note" maxlength="300"></label>
        <ErrorBox :error="endError" />
        <div class="actions">
          <button type="button" class="btn danger" :disabled="busy || !note" @click="end"><Icon name="unlock" />{{ t('blocks.end') }}</button>
          <button type="button" class="btn ghost" @click="ending = null"><Icon name="cancel" />{{ t('common.cancel') }}</button>
        </div>
      </section>
      <section v-if="extending" class="card form" role="dialog" :aria-label="t('blocks.extend')">
        <h2><Icon name="timer" /> {{ t('blocks.extend_title', { ip: extending.ip }) }}</h2>
        <p class="muted small">{{ t('blocks.extend_now', { at: extending.expires_at ? fmtShortTime(extending.expires_at) : '—' }) }}</p>
        <div class="filters">
          <div class="field"><label for="blk-ext">{{ t('blocks.extend_to') }}</label><SelectBox id="blk-ext" v-model="ext.ttl" :options="extOpts" /></div>
          <label class="field grow"><span>{{ t('blocks.reason') }}</span><input v-model.trim="ext.reason" maxlength="300"></label>
        </div>
        <p v-if="ext.ttl === 'permanent'" class="alert warn small">{{ t('blocks.permanent_hint') }}</p>
        <ErrorBox :error="extError" />
        <div class="actions">
          <button type="button" class="btn primary" :disabled="busy || !ext.reason" @click="extend"><Icon name="timer" />{{ t('blocks.extend') }}</button>
          <button type="button" class="btn ghost" @click="extending = null"><Icon name="cancel" />{{ t('common.cancel') }}</button>
        </div>
      </section>
      <section class="card">
        <h2><Icon name="link" /> {{ t('blocks.connect') }}</h2>
        <ol class="steps">
          <li>{{ t('blocks.connect1') }}</li>
          <li>{{ t('blocks.connect2') }} <RouterLink v-if="isAdmin" to="/admin/tokens">{{ t('nav.tokens') }}</RouterLink></li>
          <li>{{ t('blocks.connect3') }}</li>
        </ol>
        <pre class="code small">{{ f2b }}</pre>
        <p class="muted small">{{ t('blocks.connect_note') }}</p>
      </section>
      <section v-if="data.uncovered.length" class="card">
        <h2><Icon name="warning" /> {{ t('blocks.uncovered') }}</h2>
        <p class="muted small">{{ t('blocks.uncovered_hint') }}</p>
        <ul class="plain">
          <li v-for="(u, i) in data.uncovered" :key="i" class="mono small">{{ safeText(u.server, 120) }}<template v-if="u.location"> · location {{ safeText(u.location, 200) }}</template>
            <span class="muted"> ({{ shortFile(u.file) }}:{{ u.line }})</span></li>
        </ul>
      </section>
    </template>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { get, post } from '../api.js'
import { t } from '../i18n.js'
import { hasRole } from '../store.js'
import { fmtNum, fmtShortTime, safeText } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import SelectBox from '../components/SelectBox.vue'
import TruncText from '../components/TruncText.vue'
import GeoTag from '../components/GeoTag.vue'

const STATES = ['active', 'all']
const STATE_ICON = { active: 'lock', all: 'list' }
const STATE_BADGE = { active: 'b-blocked', removed: 'b-logged', expired: 'b-logged' }
const data = ref(null)
const loading = ref(false)
const error = ref(null)
const state = ref('active')
const busy = ref(false)
const addError = ref(null)
const endError = ref(null)
const ending = ref(null)
const note = ref('')
const nb = reactive({ ip: '', ttl: 86400, reason: '' })
const isAdmin = computed(() => hasRole('admin'))
const canAdd = computed(() => hasRole('approver'))
const activeCount = computed(() => (data.value.items || []).filter((r) => r.state === 'active').length)
const syncText = computed(() => (data.value.in_sync ? t('blocks.in_sync') : data.value.pending ? t('blocks.pending') : t('blocks.not_written')))

function dur(s) {
  if (!s) return '—'
  if (s % 86400 === 0) return t('blocks.days', { n: s / 86400 })
  if (s % 3600 === 0) return t('blocks.hours', { n: s / 3600 })
  return t('blocks.minutes', { n: Math.round(s / 60) })
}
// an admin may also block permanently (never a token or a rule)
const ttlOpts = computed(() => [3600, 6 * 3600, 86400, 3 * 86400, 7 * 86400, 30 * 86400]
  .filter((s) => !data.value || s <= data.value.limits.ui_max_ttl).map((s) => ({ value: s, label: dur(s) }))
  .concat(isAdmin.value ? [{ value: 'permanent', label: t('blocks.permanent') }] : []))
// a new end, counted from now: only the ones later than the current end
const extOpts = computed(() => ttlOpts.value.filter((o) => o.value === 'permanent' || !extending.value || !extending.value.expires_at
  || Date.now() + o.value * 1000 > new Date(extending.value.expires_at).getTime()))
const extending = ref(null)
const ext = reactive({ ttl: 7 * 86400, reason: '' })
const extError = ref(null)
function openExtend(row) {
  extending.value = row
  ending.value = null
  extError.value = null
  ext.reason = ''
  ext.ttl = (extOpts.value.find((o) => o.value !== 'permanent') || { value: 'permanent' }).value
}
async function extend() {
  busy.value = true
  extError.value = null
  try {
    await post('/blocks/' + extending.value.id + '/extend', { ttl: ext.ttl, reason: ext.reason })
    extending.value = null
    await load()
  } catch (e) { extError.value = e } finally { busy.value = false }
}
// a fail2ban action that blocks and unblocks through this server's API (the token is filled in by the admin)
const f2b = computed(() => ['# /etc/fail2ban/action.d/jt-waf-block.conf   (chmod 600)', '[Definition]',
  'actionban   = curl -fsS -m 10 -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \\',
  '              -d \'{"ip": "<ip>", "ttl": <bantime>, "source": "<source>", "reason": "fail2ban <name>"}\' <waf>/api/v1/blocks',
  'actionunban = curl -fsS -m 10 -X DELETE -H "Authorization: Bearer <token>" "<waf>/api/v1/blocks/<ip>?source=<source>"',
  '[Init]', 'waf    = ' + window.location.origin, 'token  = jwm_...', 'source = <host>/<name>'].join('\n'))
function shortFile(f) { return safeText(String(f || '').split('/').slice(-2).join('/'), 120) }

const cols = computed(() => [
  { key: 'ip', label: t('blocks.ip'), required: true, nowrap: true, text: (r) => r.ip + ' ' + ((r.geo && r.geo.cc) || '') },
  { key: 'source', label: t('blocks.source'), text: (r) => r.source + ' ' + r.created_by },
  { key: 'reason', label: t('blocks.reason') },
  { key: 'created_at', label: t('blocks.since'), nowrap: true, text: (r) => fmtShortTime(r.created_at) },
  { key: 'expires_at', label: t('blocks.until'), nowrap: true, value: (r) => (r.permanent ? '9999' : r.expires_at || ''),
    text: (r) => (r.permanent ? t('blocks.permanent') : fmtShortTime(r.expires_at)) },
  { key: 'state', label: t('blocks.state'), nowrap: true, text: (r) => t('blocks.state.' + r.state) },
  { key: 'act', label: '', sortable: false, required: true, text: () => '' },
])

async function load() {
  loading.value = true
  error.value = null
  try { data.value = await get('/blocks', { state: state.value }) } catch (e) { error.value = e } finally { loading.value = false }
}
async function add() {
  busy.value = true
  addError.value = null
  try {
    await post('/blocks', { ip: nb.ip, ttl: nb.ttl, reason: nb.reason })
    nb.ip = ''
    nb.reason = ''
    await load()
  } catch (e) { addError.value = e } finally { busy.value = false }
}
async function end() {
  busy.value = true
  endError.value = null
  try {
    await post('/blocks/' + ending.value.id + '/remove', { note: note.value })
    ending.value = null
    await load()
  } catch (e) { endError.value = e } finally { busy.value = false }
}
onMounted(load)
</script>

<style scoped>
.ipcell { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
.rowacts { display: flex; gap: 6px; justify-content: flex-end; flex-wrap: wrap; }
ul.plain { list-style: none; padding: 0; margin: 6px 0 0; }
ul.plain li { padding: 3px 0; }
ol.steps { margin: 6px 0 10px; padding-left: 22px; }
ol.steps li { margin: 4px 0; }
</style>
