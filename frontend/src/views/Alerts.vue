<!-- Alerts to follow up: what the event analysis or the system found that a person must look at (an attack the
     site may have answered, users hit by a false positive, an outside configuration change...). They stay open
     until an approver marks them handled with a note; open alerts are reminded through the notifications. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('alerts.title') }}</h1>
      <div class="actions">
        <RouterLink v-if="isAdmin" to="/admin/notify" class="btn small"><Icon name="notify" />{{ t('alerts.to_notify') }}</RouterLink>
        <button type="button" class="btn small ghost" :disabled="loading" @click="reload"><Icon name="refresh" />{{ t('common.refresh') }}</button>
      </div>
    </div>
    <p class="muted">{{ t('alerts.intro') }}</p>
    <ErrorBox :error="error" />
    <div class="seg" role="tablist" :aria-label="t('alerts.filter')">
      <button v-for="f in FILTERS" :key="f" type="button" role="tab" class="btn small" :class="{ primary: filter === f }"
              :aria-selected="filter === f ? 'true' : 'false'" @click="setFilter(f)">
        <Icon :name="f === 'open' ? 'bell' : f === 'handled' ? 'check' : 'list'" />{{ t('alerts.f.' + f) }}
        <span v-if="f === 'open' && counts.open" class="badge tiny b-warn">{{ counts.open }}</span></button>
    </div>

    <section v-if="sel" ref="handleEl" class="card">
      <h2><Icon name="check" /> {{ t('alerts.handle_title', { id: sel.id }) }}</h2>
      <p><b>{{ kindText(sel) }}</b> <span class="mono small">{{ safeText(sel.summary, 160) }}</span></p>
      <p v-if="sel.details.reason" class="reason">{{ safeText(sel.details.reason, 400) }}</p>
      <label class="field"><span>{{ t('alerts.note') }}</span>
        <textarea v-model="note" rows="3" maxlength="1000" class="w-lg" :placeholder="t('alerts.note_ph')"></textarea></label>
      <ErrorBox :error="handleError" />
      <div class="actions">
        <button type="button" class="btn primary" :disabled="busy" @click="handle"><Icon name="check" />{{ t('alerts.mark_handled') }}</button>
        <button type="button" class="btn ghost" :disabled="busy" @click="sel = null"><Icon name="cancel" />{{ t('common.cancel') }}</button>
      </div>
    </section>

    <section class="card">
      <h2><Icon name="bell" /> {{ t('alerts.f.' + filter) }} <span class="count">{{ items.length }}</span></h2>
      <RowTimeline v-model:window="win" :rows="items" ts-key="created_at" :series="tlSeries" />
      <DataTable id="alerts" :columns="cols" :rows="shownItems" row-key="id" :has-more="!!cursor" :loading-more="loading"
                 :default-sort="{ key: 'id', dir: -1 }" :empty="filter === 'open' ? t('alerts.none_open') : t('common.no_data')"
                 :row-class="(r) => (r.state === 'open' && r.severity === 'critical' ? 'row-crit' : null)" @more="more">
        <template #cell-created_at="{ row }"><span class="nowrap">{{ fmtShortTime(row.created_at) }}</span>
          <div v-if="row.count > 1" class="sub">{{ t('alerts.seen', { n: row.count, at: fmtShortTime(row.last_seen) }) }}</div></template>
        <template #cell-severity="{ row }"><span class="badge" :class="row.severity === 'critical' ? 'b-blocked' : 'b-warn'">{{ t('alerts.sev.' + row.severity) }}</span></template>
        <template #cell-kind="{ row }"><b>{{ kindText(row) }}</b><div class="sub">{{ t('alerts.src.' + row.source) }}</div></template>
        <template #cell-summary="{ row }"><span class="mono small breakall">{{ safeText(row.summary, 160) }}</span>
          <div v-if="row.details.reason" class="sub reason">{{ safeText(row.details.reason, 240) }}</div></template>
        <template #cell-state="{ row }"><span class="badge" :class="row.state === 'open' ? 'b-warn' : 'b-ok'">{{ t('alerts.state.' + row.state) }}</span>
          <div v-if="row.handled_by" class="sub">{{ t('alerts.handled_by', { by: safeText(row.handled_by, 40), at: fmtShortTime(row.handled_at) }) }}</div>
          <div v-if="row.note" class="sub">{{ safeText(row.note, 200) }}</div></template>
        <template #cell-actions="{ row }">
          <div class="rowacts">
            <RouterLink v-if="safeLink(row.link)" :to="safeLink(row.link)" class="btn tiny"><Icon name="go" />{{ t('alerts.open') }}</RouterLink>
            <button v-if="row.state === 'open' && canPropose && DRAFT[row.kind] && row.details.path" type="button" class="btn tiny"
                    :disabled="drafting === row.id" @click="draft(row)"><Icon :name="DRAFT[row.kind] === 'exclusion' ? 'unlock' : 'block'" />{{ t('alerts.draft_' + DRAFT[row.kind]) }}</button>
            <button v-if="row.state === 'open' && canHandle" type="button" class="btn tiny" @click="pick(row)"><Icon name="check" />{{ t('alerts.mark_handled') }}</button>
          </div>
        </template>
      </DataTable>
    </section>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'
import { get, post } from '../api.js'
import RowTimeline from '../components/RowTimeline.vue'
import { inWindow } from '../timeWindow.js'
import { t, tOr } from '../i18n.js'
import { fmtShortTime, safeText } from '../util.js'
import { hasRole, refreshAlerts } from '../store.js'
import { useRouter } from 'vue-router'
import Icon from '../components/Icon.vue'
import ErrorBox from '../components/ErrorBox.vue'
import DataTable from '../components/DataTable.vue'

const FILTERS = ['open', 'handled', 'all']
const filter = ref('open')
const items = ref([])
const win = ref(null)
const shownItems = computed(() => inWindow(items.value, 'created_at', win.value))
const tlSeries = computed(() => [{ key: 'critical', label: t('alerts.sev.critical'), tone: 'blocked', test: (r) => r.severity === 'critical' }, { key: 'warning', label: t('alerts.sev.warning'), tone: 's3', test: () => true }])
const counts = ref({ open: 0, critical: 0 })
const cursor = ref(null)
const loading = ref(false)
const error = ref(null)
const sel = ref(null)
const note = ref('')
const busy = ref(false)
const handleError = ref(null)
const handleEl = ref(null)
const isAdmin = computed(() => hasRole('admin'))
const canHandle = computed(() => hasRole('approver'))

const cols = computed(() => [
  { key: 'id', label: t('alerts.col.id'), align: 'num', hidden: true },
  { key: 'created_at', label: t('alerts.col.time'), required: true, text: (r) => fmtShortTime(r.created_at) },
  { key: 'severity', label: t('alerts.col.severity'), value: (r) => (r.severity === 'critical' ? 0 : 1), text: (r) => t('alerts.sev.' + r.severity) },
  { key: 'kind', label: t('alerts.col.kind'), value: (r) => kindText(r) },
  { key: 'summary', label: t('alerts.col.what'), value: (r) => r.summary + ' ' + (r.details.reason || '') },
  { key: 'state', label: t('alerts.col.state'), value: (r) => t('alerts.state.' + r.state) },
  { key: 'actions', label: t('alerts.col.actions'), sortable: false, filterable: false },
])
function kindText(r) { return tOr('alerts.kind.' + r.kind, r.kind) }
// an alert becomes a change: find a recent event of that site and path (paths in alerts are decoded and lower case,
// as a rule sees them) and open the change form filled from it
const DRAFT = { false_positive: 'exclusion', attack_passed: 'block', attack_in_progress: 'block' }
const canPropose = computed(() => hasRole('operator'))
const drafting = ref(null)
const router = useRouter()
function viewOf(p) { try { return decodeURIComponent(p).toLowerCase() } catch { return String(p).toLowerCase() } }
async function draft(r) {
  drafting.value = r.id
  const mode = DRAFT[r.kind]
  const host = String(r.details.host || '').split(',')[0].trim()
  const path = String(r.details.path || '').split(',')[0].trim()
  try {
    const q = { limit: 200 }
    if (host) q.host = host
    if (mode === 'exclusion') q.outcome = 'blocked'
    const res = await get('/events', q)
    const ev = (res.items || []).find((e) => viewOf(e.path || '/') === path)
    router.push(ev ? { path: '/changes/new', query: { from_event: ev.id, mode } }
      : { path: '/changes/new', query: { kind: mode === 'exclusion' ? 'exclusion' : 'confident_block' } })
  } catch (e) { error.value = e } finally { drafting.value = null }
}
// links come from the server and are paths inside this application only
function safeLink(l) { return typeof l === 'string' && /^\/[A-Za-z0-9/_-]*$/.test(l) ? l : '' }
async function load(append) {
  loading.value = true
  error.value = null
  try {
    const r = await get('/alerts', { state: filter.value === 'all' ? undefined : filter.value, limit: 100,
      cursor: append ? cursor.value : undefined })
    items.value = append ? items.value.concat(r.items) : r.items
    cursor.value = r.next_cursor
    counts.value = r.counts
  } catch (e) { error.value = e } finally { loading.value = false }
}
function more() { if (cursor.value) load(true) }
function reload() { load(false); refreshAlerts(true) }
function setFilter(f) { filter.value = f; sel.value = null; load(false) }
async function pick(r) {
  sel.value = r
  note.value = ''
  handleError.value = null
  await nextTick()
  if (handleEl.value) handleEl.value.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
async function handle() {
  busy.value = true
  handleError.value = null
  try {
    await post('/alerts/' + sel.value.id + '/handle', { note: note.value })
    sel.value = null
    reload()
  } catch (e) { handleError.value = e } finally { busy.value = false }
}
onMounted(() => load(false))
</script>

<style scoped>
.seg { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 14px; }
.sub { color: var(--muted); font-size: .85em; margin-top: 2px; }
.reason { white-space: pre-wrap; overflow-wrap: anywhere; }
.rowacts { display: flex; flex-wrap: wrap; gap: 6px; }
:deep(tr.row-crit) td:first-child { box-shadow: inset 3px 0 0 var(--blocked); }
.w-lg { width: 100%; max-width: 560px; }
</style>
