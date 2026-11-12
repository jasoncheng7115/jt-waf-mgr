<!-- Audit trail: hash-chained, append-only, anchored; filter by action / actor, verify, export. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('audit.title') }}</h1>
      <button class="btn small ghost" type="button" :aria-expanded="showGuide ? 'true' : 'false'" @click="toggleGuide">
        <Icon name="help" />{{ showGuide ? t('guide.hide') : t('guide.show') }}</button>
      <button class="btn small" type="button" :disabled="verifying" @click="verify"><Icon name="verify" />{{ verifying ? t('common.working') : t('audit.verify') }}</button>
      <button class="btn small" type="button" :disabled="exporting" @click="exportAll"><Icon name="download" />{{ exporting ? t('common.working') : t('audit.export') }}</button>
    </div>
    <p class="muted small">{{ t('audit.chain_intro') }}</p>
    <FlowSteps v-if="showGuide" :title="t('guide.audit.title')" :steps="auditFlow" :note="t('guide.audit.note')" />
    <ErrorBox :error="verifyError" />
    <ChainResult :s="chain" />
    <ErrorBox :error="exportError" />
    <div v-if="exported" class="alert info exportdone">
      <div>{{ t('audit.exported', { file: safeText(exported.file, 120) }) }}</div>
      <div class="small">SHA-256: <code class="mono breakall">{{ safeText(exported.sha256, 80) }}</code></div>
      <div class="small">{{ t('audit.verify_offline') }} <code class="mono">jt-waf-mgr audit-verify {{ safeText(exported.file, 120) }}</code></div>
    </div>
    <form class="filters inline" @submit.prevent="apply">
      <label class="field" :class="fieldClass('action')"><span>{{ t('audit.action') }}</span><input v-model.trim="f.action" maxlength="64" placeholder="login.failed"></label>
      <label class="field" :class="fieldClass('actor')"><span>{{ t('audit.actor') }}</span><input v-model.trim="f.actor" maxlength="64"></label>
      <div class="actions"><button class="btn primary" :class="{ 'needs-apply': dirty }" type="submit"><Icon name="filter" />{{ t('filter.apply') }}</button>
        <button class="btn ghost" type="button" @click="clear"><Icon name="clear" />{{ t('filter.reset') }}</button>
        <span v-if="dirty" class="applyhint" role="status"><Icon name="warning" />{{ t('filter.not_applied') }}</span></div>
    </form>
    <ErrorBox :error="error" />
    <section v-if="items.length" class="card">
      <h2><Icon name="chart" /> {{ t('chart.audit.loaded', { n: fmtNum(items.length) }) }}</h2>
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.audit.results') }}</h3><SegBar :parts="resultParts" :label="t('chart.audit.results')" /></div>
      </div>
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.audit.top_actions') }}</h3><HBars :items="topActions" :series="okSeries" mono /></div>
        <div><h3 class="charthead">{{ t('chart.audit.top_actors') }}</h3><HBars :items="topActors" :series="okSeries" mono /></div>
      </div>
    </section>
    <RowTimeline v-model:window="win" :title="t('timeline.audit')" :rows="items" ts-key="ts" :series="tlSeries" />
    <DataTable :has-more="!!cursor" :loading-more="loading" @more="load(false)" id="admin-audit" :columns="cols" :rows="shownItems" :row-class="(a) => ({ crit: isCrit(a), hl: open === a.id })" :default-sort="{ key: 'id', dir: -1 }" :page-size="50">
      <template #cell-ts="{ row }">{{ fmtTime(row.ts) }}</template>
      <template #cell-action="{ row }"><span class="mono">{{ safeText(row.action, 64) }}</span></template>
      <template #cell-action_text="{ row }">{{ actionText(row.action) }}</template>
      <template #cell-actor="{ row }">{{ safeText(row.actor, 64) }} <span class="muted small">{{ t('actor.' + (row.actor_type || 'user')) }}</span></template>
      <template #cell-src_ip="{ row }"><span class="mono">{{ safeText(row.src_ip, 45) }}</span></template>
      <template #cell-result="{ row }"><span class="badge" :class="resultClass(row)">{{ tOr('result.' + (row.result || 'ok'), row.result) }}</span></template>
      <template #cell-hash="{ row }"><HashText :value="row.hash" /></template>
      <template #cell-view="{ row }"><button type="button" class="btn tiny" :aria-label="t('audit.show_record', { id: row.id })"
                :title="t('audit.show_record', { id: row.id })" @click="toggleRow(row.id, $event)"><Icon name="show" />{{ t('audit.details') }}</button></template>
      <template #cell-details="{ row }"><TruncText :text="detailsText(row.details)" :max="300" mono /></template>
    </DataTable>
    <!-- one record, on top of the list: Escape, the close button or a click outside closes it -->
    <div v-if="openRow" class="modalback" @click.self="closeRow">
      <section ref="recEl" class="card modal recdetail" role="dialog" aria-modal="true" :aria-label="t('audit.record', { id: openRow.id })"
               tabindex="-1" @keydown.esc.stop="closeRow">
        <div class="cardhead">
          <h2><Icon name="page" /> {{ t('audit.record', { id: openRow.id }) }}</h2>
          <button class="btn small ghost" type="button" @click="closeRow"><Icon name="close" />{{ t('common.dismiss') }}</button>
        </div>
        <dl class="kv two">
          <dt>{{ t('audit.action') }}</dt><dd><span class="mono">{{ safeText(openRow.action, 64) }}</span> · {{ actionText(openRow.action) }}</dd>
          <dt>{{ t('event.time') }}</dt><dd class="mono">{{ fmtTime(openRow.ts) }}</dd>
          <dt>{{ t('audit.actor') }}</dt><dd>{{ safeText(openRow.actor, 64) }} <span class="muted small">{{ t('actor.' + (openRow.actor_type || 'user')) }}</span></dd>
          <dt>{{ t('audit.src_ip') }}</dt><dd class="mono">{{ safeText(openRow.src_ip, 45) || '—' }}</dd>
          <dt>{{ t('audit.result') }}</dt><dd><span class="badge" :class="resultClass(openRow)">{{ tOr('result.' + (openRow.result || 'ok'), openRow.result) }}</span></dd>
          <dt>ID</dt><dd class="mono">{{ openRow.id }}</dd>
          <dt>{{ t('audit.prev_hash') }}</dt><dd class="mono breakall">{{ safeText(openRow.prev_hash, 80) || '—' }}</dd>
          <dt>{{ t('audit.hash') }}</dt><dd class="mono breakall">{{ safeText(openRow.hash, 80) || '—' }}</dd>
        </dl>
        <h3 class="charthead">{{ t('audit.details') }}</h3>
        <JsonView :value="openRow.details || {}" />
      </section>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useFilterState } from '../filterState.js'
import { get, post, ApiError } from '../api.js'
import RowTimeline from '../components/RowTimeline.vue'
import { inWindow } from '../timeWindow.js'
import { t, tOr } from '../i18n.js'
import { safeText, safeMultiline, fmtTime, fmtNum, saveBlob, stamp } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import TruncText from '../components/TruncText.vue'
import JsonView from '../components/JsonView.vue'
import HashText from '../components/HashText.vue'
import ChainResult from '../components/ChainResult.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'

const route = useRoute()
const router = useRouter()
const f = reactive({ action: '', actor: '' })
const { dirty, fieldClass } = useFilterState(f, () => ({ action: typeof route.query.action === 'string' ? route.query.action : '',
  actor: typeof route.query.actor === 'string' ? route.query.actor : '' }))
const items = ref([])
const win = ref(null)
const shownItems = computed(() => inWindow(items.value, 'ts', win.value))
const tlSeries = computed(() => [{ key: 'ok', label: t('result.ok'), tone: 's1', test: (r) => (r.result || 'ok') === 'ok' }, { key: 'other', label: t('chart.audit.not_ok'), tone: 's2', test: () => true }])
const cursor = ref(null)
const loading = ref(false)
const error = ref(null)
const open = ref(null)
const chain = ref(null)
const verifying = ref(false)
const verifyError = ref(null)
const exporting = ref(false)
const exportError = ref(null)
const exported = ref(null)

const GUIDE_KEY = 'jtwaf.guide.audit'
const showGuide = ref(readGuide())
function readGuide() { try { return window.localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage blocked */ }
}

// How the trail is protected (audit.py, integrity.py, compliance.Monitor).
const auditFlow = computed(() => [
  { key: 'row', icon: 'history', label: t('guide.audit.row'), desc: t('guide.audit.row_d') },
  { key: 'chain', icon: 'link', label: t('guide.audit.chain'), desc: t('guide.audit.chain_d') },
  { key: 'anchor', icon: 'fingerprint', label: t('guide.audit.anchor'), desc: t('guide.audit.anchor_d') },
  { key: 'verify', icon: 'verify', label: t('guide.audit.verify'), desc: t('guide.audit.verify_d') },
  { key: 'alert', icon: 'alert', label: t('guide.audit.alert'), desc: t('guide.audit.alert_d') },
])

const cols = computed(() => [
  { key: 'id', label: 'ID', align: 'num', hidden: true },
  { key: 'ts', label: t('event.time'), nowrap: true, text: (a) => fmtTime(a.ts) },
  { key: 'action', label: t('audit.action'), required: true, nowrap: true },
  { key: 'action_text', label: t('audit.action_text'), value: (a) => actionText(a.action) },
  { key: 'actor', label: t('audit.actor'), nowrap: true, text: (a) => (a.actor || '') + ' ' + t('actor.' + (a.actor_type || 'user')) },
  { key: 'src_ip', label: t('audit.src_ip'), nowrap: true },
  { key: 'result', label: t('audit.result'), value: (a) => tOr('result.' + (a.result || 'ok'), a.result) },
  { key: 'hash', label: t('audit.hash'), nowrap: true, sortable: false, hidden: true },
  { key: 'view', label: t('audit.details'), sortable: false, filterable: false, text: (a) => detailsText(a.details) },
  { key: 'details', label: t('audit.details_json'), sortable: false, hidden: true, text: (a) => detailsText(a.details) },
])
// the record opens below the table: bring it into view (it is easy to miss under a long list)
const recEl = ref(null)
const flashRec = ref(false)
let opener = null
async function toggleRow(id, e) {
  opener = e && e.currentTarget
  open.value = open.value === id ? null : id
  if (open.value == null) return
  await nextTick()
  if (recEl.value) recEl.value.focus()
}
function closeRow() {
  open.value = null
  if (opener && opener.focus) opener.focus()
}
// the readable name of an audit action in the reader's language (the raw name stays in its own column)
function actionText(a) {
  const k = 'auditact.' + String(a || '')
  const v = tOr(k, '')
  return v || String(a || '').replace(/[._]/g, ' ')
}
const openRow = computed(() => items.value.find((a) => a.id === open.value) || null)

// Charts over the rows loaded so far (not the whole trail).
const okSeries = computed(() => [
  { key: 'ok', label: t('result.ok'), tone: 's1' },
  { key: 'other', label: t('chart.audit.not_ok'), tone: 's2' },
])
const resultParts = computed(() => {
  const c = {}
  for (const a of items.value) c[a.result || 'ok'] = (c[a.result || 'ok'] || 0) + 1
  const tone = { ok: 'good', denied: 'warning', outside: 'warning', failed: 'serious', error: 'critical' }
  const order = ['ok', 'denied', 'outside', 'failed', 'error']
  const keys = order.filter((k) => c[k]).concat(Object.keys(c).filter((k) => !order.includes(k)).sort())
  return keys.map((k) => ({ key: k, label: tOr('result.' + k, k), value: c[k], tone: tone[k] || 'muted' }))
})
function topBy(field) {
  const m = new Map()
  for (const a of items.value) {
    const k = safeText(a[field] || '—', 64)
    const v = m.get(k) || { ok: 0, other: 0 }
    if ((a.result || 'ok') === 'ok') v.ok++; else v.other++
    m.set(k, v)
  }
  return [...m.entries()].sort((x, y) => (y[1].ok + y[1].other) - (x[1].ok + x[1].other)).slice(0, 8)
    .map(([k, v]) => ({ key: k, label: k, values: v }))
}
const topActions = computed(() => topBy('action'))
const topActors = computed(() => topBy('actor'))

function detailsText(d) {
  if (!d || (typeof d === 'object' && !Object.keys(d).length)) return ''
  try { return JSON.stringify(d) } catch { return String(d) }
}
function detailsPretty(d) {
  try { return JSON.stringify(d || {}, null, 1) } catch { return String(d) }
}
function isCrit(a) {
  return (a.action || '').startsWith('integrity.') && !(a.action || '').endsWith('_recovered') && a.result !== 'ok'
}
function resultClass(a) {
  if (isCrit(a)) return 'b-blocked'
  if (a.result === 'ok') return 'b-ok'
  if (a.result === 'denied' || a.result === 'outside' || a.result === 'failed') return 'b-warn'
  return 'b-blocked'
}

async function verify() {
  verifying.value = true; verifyError.value = null
  try { chain.value = await post('/audit/verify') } catch (e) { verifyError.value = e } finally { verifying.value = false }
}

async function exportAll() {
  exporting.value = true; exportError.value = null; exported.value = null
  try {
    const res = await fetch('/api/v1/audit/export', { credentials: 'same-origin', cache: 'no-store' })
    if (!res.ok) {
      let err = {}
      try { err = (await res.json()).error || {} } catch { /* not JSON */ }
      throw new ApiError(res.status, err.code, err.message, err.details)
    }
    const cd = res.headers.get('Content-Disposition') || ''
    const m = /filename="([A-Za-z0-9._-]{1,120})"/.exec(cd)
    const name = m ? m[1] : 'jt-waf-mgr-audit-' + stamp() + '.ndjson'
    const blob = await res.blob()
    saveBlob(name, blob)
    exported.value = { file: name, sha256: res.headers.get('X-Content-SHA256') || '' }
  } catch (e) { exportError.value = e } finally { exporting.value = false }
}

async function load(fresh) {
  loading.value = true; error.value = null
  try {
    const p = { action: f.action, actor: f.actor, limit: 100 }
    if (!fresh && cursor.value) p.cursor = cursor.value
    const data = await get('/audit', p)
    items.value = fresh ? data.items : items.value.concat(data.items)
    cursor.value = data.next_cursor || null
  } catch (e) { error.value = e } finally { loading.value = false }
}
function apply() {
  const q = {}
  if (f.action) q.action = f.action
  if (f.actor) q.actor = f.actor
  router.push({ query: q })
}
function clear() { router.push({ query: {} }) }
watch(() => route.query, () => {
  f.action = typeof route.query.action === 'string' ? route.query.action : ''
  f.actor = typeof route.query.actor === 'string' ? route.query.actor : ''
  load(true)
}, { immediate: true })
</script>

<style scoped>
.hashcell { display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
.recdetail { scroll-margin-top: 70px; transition: box-shadow .3s; }
.recdetail.flash { box-shadow: 0 0 0 3px var(--accent); }
</style>
