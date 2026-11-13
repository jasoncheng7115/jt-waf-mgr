<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('rules.title') }}</h1>
      <button type="button" class="btn small ghost" :class="{ on: showGuide }" :aria-pressed="showGuide ? 'true' : 'false'" @click="toggleGuide"><Icon name="help" />{{ t('guide.how') }}</button>
      <RouterLink class="btn small" to="/managed"><Icon name="list" />{{ t('nav.managed') }}</RouterLink>
    </div>
    <FlowSteps v-if="showGuide" :title="t('guide.rule.title')" :steps="flow" :note="t('guide.rule.note')" />
    <form class="filters" @submit.prevent="apply">
      <div class="field" :class="fieldClass('source')"><label for="rules-f-source">{{ t('rules.source') }}</label>
        <SelectBox id="rules-f-source" v-model="f.source" :options="sourceOpts" /></div>
      <div v-if="f.source !== 'crs'" class="field" :class="fieldClass('category')"><label for="rules-f-category">{{ t('rules.category') }}</label>
        <SelectBox id="rules-f-category" v-model="f.category" :options="categoryOpts" /></div>
      <div v-else class="field" :class="fieldClass('family')"><label for="rules-f-family">{{ t('rules.family') }}</label>
        <SelectBox id="rules-f-family" v-model="f.family" :options="familyOpts" /></div>
      <div class="field" :class="fieldClass('state')"><label for="rules-f-state">{{ t('rules.state') }}</label>
        <SelectBox id="rules-f-state" v-model="f.state" :options="stateOpts" /></div>
      <label class="field grow" :class="fieldClass('q')"><span>{{ t('rules.search') }}</span><input v-model.trim="f.q" maxlength="200" :placeholder="t('rules.search_hint')"></label>
      <div class="actions filteractions">
        <button type="submit" class="btn primary" :class="{ 'needs-apply': dirty }"><Icon name="filter" />{{ t('filter.apply') }}</button>
        <span v-if="dirty" class="applyhint" role="status"><Icon name="warning" />{{ t('filter.not_applied') }}</span>
      </div>
    </form>
    <ErrorBox :error="error" />
    <Loading v-if="loading && !items.length" />
    <section v-if="summary.length" class="card">
      <h2><Icon name="chart" /> {{ t('rules.by_category_state') }}</h2>
      <p class="muted small">{{ t('rules.by_category_state_hint') }}</p>
      <div class="statetotals">
        <button v-for="s in STATES" :key="s" type="button" class="stchip" :class="['st-' + s, { on: f.state === s }]" :aria-pressed="f.state === s ? 'true' : 'false'"
                @click="pickState(s)"><Icon :name="STATE_ICON[s]" /><span class="lg" :class="'tone-' + STATE_TONE[s]"></span>{{ t('rulestate.' + s) }} <b>{{ fmtNum(totals[s]) }}</b></button>
      </div>
      <HBars :items="categoryBars" :series="stateSeries" pickable :open-label="t('filter.open')" @pick="(it) => pickGroup(it.key)" />
      <div v-if="canToggle && activeGroup" class="actions groupacts">
        <span>{{ t('toggle.group_label', { name: groupLabel(activeGroup) }) }}</span>
        <button type="button" class="btn small danger" @click="openToggle('disable', true)"><Icon name="hide" />{{ t('toggle.group_off') }}</button>
        <button type="button" class="btn small" @click="openToggle('enable', true)"><Icon name="show" />{{ t('toggle.group_on') }}</button>
      </div>
    </section>
    <!-- several rules at once: tick them, then switch them on or off as one change -->
    <div v-if="canToggle && items.length" class="selbar" role="toolbar" :aria-label="t('toggle.selection')">
      <span>{{ t('toggle.selected', { n: fmtNum(selected.size) }) }}</span>
      <button type="button" class="btn small danger" :disabled="!selected.size" @click="openToggle('disable', false)"><Icon name="hide" />{{ t('toggle.off') }}</button>
      <button type="button" class="btn small" :disabled="!selected.size" @click="openToggle('enable', false)"><Icon name="show" />{{ t('toggle.on') }}</button>
      <button type="button" class="btn small ghost" @click="selectAll"><Icon name="check" />{{ t('toggle.select_all', { n: fmtNum(selectable.length) }) }}</button>
      <button type="button" class="btn small ghost" :disabled="!selected.size" @click="selected = new Set()"><Icon name="clear" />{{ t('toggle.clear') }}</button>
    </div>
    <div v-if="done" class="alert success" role="status">{{ t('toggle.done', { id: done.change_id, ops: fmtNum(done.operations) }) }}
      <RouterLink :to="'/changes/' + done.change_id">{{ t('toggle.open_change') }}</RouterLink></div>
    <RuleToggle v-if="toggle" :key="toggle.key" :action="toggle.action" :rule-ids="toggle.ids" :group="toggle.group" :source="f.source"
                @close="toggle = null" @done="onDone" />
    <section v-if="items.length" class="card">
      <h3 class="charthead">{{ t('chart.hits_per_rule', { n: hitBars.length }) }}</h3>
      <HBars :items="hitBars" :series="hitSeries" mono />
    </section>
    <DataTable :has-more="!!cursor" :loading-more="loading" @more="load(false)" id="rules" :columns="cols" :rows="items" :row-key="(r) => r.id + ':' + r.file + ':' + r.line" :page-size="50">
      <template #cell-id="{ row }"><RouterLink class="mono" :to="'/rules/' + row.id">{{ row.id }}</RouterLink>
        <span v-if="!row.managed" class="chip tag" :title="t('rules.unmanaged_hint')">{{ t('rules.unmanaged') }}</span></template>
      <template #cell-sel="{ row }"><input v-if="row.id" type="checkbox" class="rowsel" :checked="selected.has(row.id)" :aria-label="t('toggle.pick_rule', { id: row.id })"
               @change="pickRow(row.id, $event.target.checked)"></template>
      <template #cell-state="{ row }"><span class="badge" :class="'b-' + STATE_BADGE[row.state || 'on']" :title="stateTitle(row)">{{ t('rulestate.' + (row.state || 'on')) }}</span></template>
      <template #cell-family="{ row }">{{ row.family ? tOr('family.' + row.family, row.family) : '—' }}</template>
      <template #cell-phase="{ row }"><span class="mono">{{ row.phase ?? '—' }}</span></template>
      <template #cell-disruptive="{ row }"><span class="mono">{{ safeText(row.disruptive, 20) || '—' }}</span></template>
      <template #cell-msg="{ row }">
        <div><TruncText :text="row.msg || row.comment || row.directive" :max="2000" width="min(46em, 52vw)" expand /></div>
        <div class="sub mono" :title="safeText(row.file, 500)">{{ shortFile(row.file) }}:{{ row.line }}</div>
      </template>
      <template #cell-hosts="{ row }"><span v-for="h in row.hosts || []" :key="h" class="chip host"><TruncText :text="h" :max="60" /></span><span v-if="!(row.hosts || []).length" class="muted">{{ t('rules.global') }}</span></template>
      <template #cell-provenance="{ row }"><ProvenanceTag :p="row.provenance" /></template>
      <template #cell-hits_7d="{ row }"><span class="mono">{{ fmtNum(row.hits_7d) }}</span></template>
      <template #cell-hits_30d="{ row }"><span class="mono">{{ fmtNum(row.hits_30d) }}</span></template>
      <template #cell-last_hit="{ row }">{{ row.last_hit ? fmtShortTime(row.last_hit) : '—' }}</template>
    </DataTable>

    <section class="card">
      <h2><Icon name="delete" /> {{ t('rules.removals') }} <span class="count">{{ removals.length }}</span></h2>
      <p class="muted small">{{ t('rules.removals_hint') }}</p>
      <DataTable id="rules-removals" :columns="removalCols" :rows="removals" row-key="_row">
        <template #cell-directive="{ row }"><span class="mono">{{ safeText(row.directive, 40) }}</span></template>
        <template #cell-target_ids="{ row }"><RouterLink v-for="id in row.target_ids || []" :key="id" :to="'/rules/' + id" class="idlink mono">{{ id }}</RouterLink></template>
        <template #cell-args="{ row }"><TruncText :text="row.args" :max="200" mono /></template>
        <template #cell-file="{ row }"><span class="mono" :title="safeText(row.file, 500)">{{ shortFile(row.file) }}:{{ row.line }}</span></template>
        <template #cell-comment="{ row }"><TruncText :text="row.comment" :max="200" /></template>
      </DataTable>
    </section>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useFilterState } from '../filterState.js'
import { get } from '../api.js'
import ProvenanceTag from '../components/ProvenanceTag.vue'
import { t, tOr } from '../i18n.js'
import { safeText, fmtNum, fmtShortTime } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import TruncText from '../components/TruncText.vue'
import Icon from '../components/Icon.vue'
import SelectBox from '../components/SelectBox.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import HBars from '../components/charts/HBars.vue'
import { hasRole } from '../store.js'
import RuleToggle from '../components/RuleToggle.vue'

const SOURCES = ['local', 'vhost_inline', 'crs', 'plugin', 'base', 'all']
const CATEGORIES = ['exclusion', 'confident_block', 'system', 'redaction', 'plugin_toggle', 'other']
const FAMILIES = ['protocol', 'lfi', 'rfi', 'rce', 'php', 'generic', 'xss', 'sqli', 'session', 'java', 'scanner', 'method', 'data_leak', 'other']
const STATES = ['on', 'partial', 'off', 'inactive']
const STATE_TONE = { on: 'good', partial: 'warning', off: 'blocked', inactive: 'muted' }
const STATE_BADGE = { on: 'ok', partial: 'warn', off: 'blocked', inactive: 'logged' }
const STATE_ICON = { on: 'check', partial: 'warning', off: 'hide', inactive: 'timer' }
const route = useRoute()
const router = useRouter()
const f = reactive({ source: 'local', category: '', family: '', state: '', q: '' })
const summary = ref([])
const items = ref([])
const cursor = ref(null)
const loading = ref(false)
const error = ref(null)
const removals = ref([])

const GUIDE_KEY = 'jtwaf.guide.rules'
function readFlag(k, d) { try { const v = window.localStorage.getItem(k); return v === null ? d : v === '1' } catch { return d } }
const showGuide = ref(readFlag(GUIDE_KEY, true))
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage unavailable */ }
}
const flow = computed(() => [
  { key: 'hit', label: t('guide.rule.hit'), desc: t('guide.rule.hit_d'), icon: 'shield' },
  { key: 'record', label: t('guide.rule.record'), desc: t('guide.rule.record_d'), icon: 'database' },
  { key: 'review', label: t('guide.rule.review'), desc: t('guide.rule.review_d'), icon: 'list', to: '/events' },
  { key: 'propose', label: t('guide.rule.propose'), desc: t('guide.rule.propose_d'), icon: 'add', to: hasRole('operator') ? '/changes/new' : null },
  { key: 'process', label: t('guide.rule.process'), desc: t('guide.rule.process_d'), icon: 'approve', to: '/changes' },
])

const sourceOpts = computed(() => SOURCES.map((s) => ({ value: s, label: t('source.' + s) })))
const familyOpts = computed(() => [{ value: '', label: t('filter.all_categories') }, ...FAMILIES.map((c) => ({ value: c, label: tOr('family.' + c, c) }))])
const stateOpts = computed(() => [{ value: '', label: t('rulestate.all') }, ...STATES.map((s) => ({ value: s, label: t('rulestate.' + s) }))])
const categoryOpts = computed(() => [{ value: '', label: t('filter.all_categories') }, ...CATEGORIES.map((c) => ({ value: c, label: t('category.' + c) }))])

const cols = computed(() => [
  ...(canToggle.value ? [{ key: 'sel', label: '', nowrap: true, required: true, sortable: false, text: () => '' }] : []),
  { key: 'id', label: t('rule.id'), nowrap: true, required: true, text: (r) => r.id + (r.managed ? '' : ' ' + t('rules.unmanaged')) },
  { key: 'state', label: t('rules.state'), nowrap: true, value: (r) => STATES.indexOf(r.state || 'on'), text: (r) => t('rulestate.' + (r.state || 'on')) },
  ...(f.source === 'crs' ? [{ key: 'family', label: t('rules.family'), nowrap: true, value: (r) => (r.family ? tOr('family.' + r.family, r.family) : '') }]
    : [{ key: 'category', label: t('rules.category'), nowrap: true, value: (r) => t('category.' + (r.category || 'other')) }]),
  { key: 'phase', label: t('rule.phase'), align: 'num' },
  { key: 'disruptive', label: t('rule.action') },
  { key: 'msg', label: t('rule.description'), value: (r) => r.msg || r.comment || r.directive || '', text: (r) => [r.msg, r.comment, r.directive, r.file].filter(Boolean).join(' ') },
  { key: 'hosts', label: t('rule.hosts'), text: (r) => ((r.hosts || []).length ? r.hosts.join(' ') : t('rules.global')) },
  { key: 'provenance', label: t('prov.title'), value: (r) => (r.provenance ? tOr('prov.' + r.provenance.channel, r.provenance.channel) : '') },
  { key: 'hits_7d', label: t('rule.hits_7d'), align: 'num' },
  { key: 'hits_30d', label: t('rule.hits_30d'), align: 'num' },
  { key: 'last_hit', label: t('rule.last_hit'), nowrap: true, text: (r) => (r.last_hit ? fmtShortTime(r.last_hit) : '') },
])
const removalCols = computed(() => [
  { key: 'directive', label: t('rules.directive'), nowrap: true },
  { key: 'target_ids', label: t('rules.targets') },
  { key: 'args', label: t('rules.args') },
  { key: 'file', label: t('rules.location'), nowrap: true, value: (r) => shortFile(r.file) + ':' + r.line },
  { key: 'comment', label: t('rules.comment') },
])

// rules per category (CRS: attack type) and whether they run, from the server's summary of the whole source
const stateSeries = computed(() => STATES.map((k) => ({ key: k, label: t('rulestate.' + k), tone: STATE_TONE[k] })))
const groupLabel = (k) => (f.source === 'crs' ? tOr('family.' + k, k) : t('category.' + k))
const categoryBars = computed(() => summary.value.map((c) => ({
  key: c.key, label: groupLabel(c.key), values: { on: c.on, partial: c.partial, off: c.off, inactive: c.inactive },
  sub: t('rules.group_counts', { n: fmtNum(c.on + c.partial + c.off + c.inactive), off: fmtNum(c.off + c.partial), inactive: fmtNum(c.inactive) }),
  active: (f.source === 'crs' ? f.family : f.category) === c.key,
})))
const totals = computed(() => Object.fromEntries(STATES.map((k) => [k, summary.value.reduce((a, c) => a + (c[k] || 0), 0)])))
function pickGroup(k) {
  if (f.source === 'crs') f.family = f.family === k ? '' : k
  else f.category = f.category === k ? '' : k
  apply()
}
// selecting rules and switching them (operators and up; the change is checked and approved as usual)
const canToggle = computed(() => hasRole('operator') && ['local', 'crs'].includes(f.source))
const selected = ref(new Set())
const toggle = ref(null)
const done = ref(null)
const selectable = computed(() => items.value.filter((r) => r.id).map((r) => r.id))
const activeGroup = computed(() => (f.source === 'crs' ? f.family : f.category) || '')
function pickRow(id, on) {
  const s = new Set(selected.value)
  if (on) s.add(id); else s.delete(id)
  selected.value = s
}
function selectAll() { selected.value = new Set(selectable.value) }
function openToggle(action, group) {
  done.value = null
  toggle.value = { key: Date.now(), action, ids: group ? null : [...selected.value],
    group: group ? { source: f.source, key: activeGroup.value, label: groupLabel(activeGroup.value) } : null }
}
function onDone(r) {
  done.value = r
  toggle.value = null
  selected.value = new Set()
}
function pickState(s) { f.state = f.state === s ? '' : s; apply() }
function stateTitle(r) {
  const d = r.state_detail || {}
  if (r.state === 'off') return d.managed_item ? t('rulestate.off_managed') : t('rulestate.off_where', { where: safeText(d.where, 300) })
  if (r.state === 'partial') return t('rulestate.partial_hosts', { hosts: (d.hosts || []).map((h) => (h === '*' ? t('rulestate.some_paths') : safeText(h, 100))).join(', ') })
  if (r.state === 'inactive') return t('rulestate.inactive_level', { level: d.level, pl: d.paranoia_level })
  return t('rulestate.on_hint')
}
const hitSeries = computed(() => [
  { key: 'd7', label: t('chart.last_7d'), tone: 's1' },
  { key: 'older', label: t('chart.days_8_30'), tone: 's2' },
])
const hitBars = computed(() => {
  const seen = new Set()
  return items.value.filter((r) => r.hits_30d > 0 && !seen.has(r.id) && seen.add(r.id))
    .sort((a, b) => b.hits_30d - a.hits_30d).slice(0, 15)
    .map((r) => ({ key: String(r.id), label: String(r.id) + (r.category ? ' · ' + t('category.' + r.category) : ''), sub: r.msg || r.comment || '', to: '/rules/' + r.id,
                   values: { d7: r.hits_7d || 0, older: Math.max(0, (r.hits_30d || 0) - (r.hits_7d || 0)) } }))
})

function shortFile(p) {
  const s = String(p || '')
  const i = s.lastIndexOf('/')
  return safeText(i >= 0 ? s.slice(i + 1) : s, 120)
}

const { dirty, fieldClass } = useFilterState(f, () => {
  const q = route.query
  return { source: SOURCES.includes(q.source) ? q.source : 'local', category: typeof q.category === 'string' ? q.category : '',
    family: typeof q.family === 'string' ? q.family : '', state: STATES.includes(q.state) ? q.state : '',
    q: typeof q.q === 'string' ? q.q : '' }
}, { source: 'local' })
function fromQuery() {
  const q = route.query
  f.source = SOURCES.includes(q.source) ? q.source : 'local'
  f.category = typeof q.category === 'string' ? q.category : ''
  f.family = typeof q.family === 'string' ? q.family : ''
  f.state = STATES.includes(q.state) ? q.state : ''
  f.q = typeof q.q === 'string' ? q.q : ''
}

async function load(fresh) {
  loading.value = true
  error.value = null
  try {
    const p = { source: f.source, category: f.source === 'crs' ? '' : f.category, family: f.source === 'crs' ? f.family : '', state: f.state, q: f.q, limit: 200 }
    if (!fresh && cursor.value) p.cursor = cursor.value
    const data = await get('/rules', p)
    items.value = fresh ? data.items : items.value.concat(data.items)
    if (fresh) summary.value = data.summary || []
    cursor.value = data.next_cursor || null
  } catch (e) {
    error.value = e
  } finally {
    loading.value = false
  }
}

function apply() {
  const q = {}
  if (f.source !== 'local') q.source = f.source
  if (f.category && f.source !== 'crs') q.category = f.category
  if (f.family && f.source === 'crs') q.family = f.family
  if (f.state) q.state = f.state
  if (f.q) q.q = f.q
  router.push({ query: q })
}

watch(() => route.query, () => { fromQuery(); selected.value = new Set(); toggle.value = null; load(true) }, { immediate: true })
onMounted(async () => {
  try { removals.value = (await get('/rules/removals')).items || [] } catch { removals.value = [] }
})
</script>

<style scoped>
.selbar { position: sticky; top: 60px; z-index: 5; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 0 0 10px;
  padding: 8px 12px; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; box-shadow: var(--shadow, none); }
.groupacts { margin-top: 10px; align-items: center; }
.rowsel { width: 16px; height: 16px; cursor: pointer; }
</style>
