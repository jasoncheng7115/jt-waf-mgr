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
      <div class="field" :class="fieldClass('category')"><label for="rules-f-category">{{ t('rules.category') }}</label>
        <SelectBox id="rules-f-category" v-model="f.category" :options="categoryOpts" /></div>
      <label class="field grow" :class="fieldClass('q')"><span>{{ t('rules.search') }}</span><input v-model.trim="f.q" maxlength="200" :placeholder="t('rules.search_hint')"></label>
      <div class="actions filteractions">
        <button type="submit" class="btn primary" :class="{ 'needs-apply': dirty }"><Icon name="filter" />{{ t('filter.apply') }}</button>
        <span v-if="dirty" class="applyhint" role="status"><Icon name="warning" />{{ t('filter.not_applied') }}</span>
      </div>
    </form>
    <ErrorBox :error="error" />
    <Loading v-if="loading && !items.length" />
    <section v-if="items.length" class="card">
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.rule_categories') }}</h3><HBars :items="categoryBars" /></div>
      </div>
      <h3 class="charthead">{{ t('chart.hits_per_rule', { n: hitBars.length }) }}</h3>
      <HBars :items="hitBars" :series="hitSeries" mono />
    </section>
    <DataTable :has-more="!!cursor" :loading-more="loading" @more="load(false)" id="rules" :columns="cols" :rows="items" :row-key="(r) => r.id + ':' + r.file + ':' + r.line" :page-size="50">
      <template #cell-id="{ row }"><RouterLink class="mono" :to="'/rules/' + row.id">{{ row.id }}</RouterLink>
        <span v-if="!row.managed" class="chip tag" :title="t('rules.unmanaged_hint')">{{ t('rules.unmanaged') }}</span></template>
      <template #cell-phase="{ row }"><span class="mono">{{ row.phase ?? '—' }}</span></template>
      <template #cell-disruptive="{ row }"><span class="mono">{{ safeText(row.disruptive, 20) || '—' }}</span></template>
      <template #cell-msg="{ row }">
        <div><TruncText :text="row.msg || row.comment || row.directive" :max="200" /></div>
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

const SOURCES = ['local', 'vhost_inline', 'crs', 'plugin', 'base', 'all']
const CATEGORIES = ['exclusion', 'confident_block', 'system', 'redaction', 'plugin_toggle', 'other']
const route = useRoute()
const router = useRouter()
const f = reactive({ source: 'local', category: '', q: '' })
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
const categoryOpts = computed(() => [{ value: '', label: t('filter.all_categories') }, ...CATEGORIES.map((c) => ({ value: c, label: t('category.' + c) }))])

const cols = computed(() => [
  { key: 'id', label: t('rule.id'), nowrap: true, required: true, text: (r) => r.id + (r.managed ? '' : ' ' + t('rules.unmanaged')) },
  { key: 'category', label: t('rules.category'), nowrap: true, value: (r) => t('category.' + (r.category || 'other')) },
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

// charts from the loaded rows
const categoryBars = computed(() => CATEGORIES.map((c) => ({
  key: c, label: t('category.' + c), values: { value: items.value.filter((r) => (r.category || 'other') === c).length },
  to: { path: '/rules', query: { ...route.query, category: c } },
})).filter((p) => p.values.value > 0).sort((x, y) => y.values.value - x.values.value))
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
    q: typeof q.q === 'string' ? q.q : '' }
}, { source: 'local' })
function fromQuery() {
  const q = route.query
  f.source = SOURCES.includes(q.source) ? q.source : 'local'
  f.category = typeof q.category === 'string' ? q.category : ''
  f.q = typeof q.q === 'string' ? q.q : ''
}

async function load(fresh) {
  loading.value = true
  error.value = null
  try {
    const p = { source: f.source, category: f.category, q: f.q, limit: 200 }
    if (!fresh && cursor.value) p.cursor = cursor.value
    const data = await get('/rules', p)
    items.value = fresh ? data.items : items.value.concat(data.items)
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
  if (f.category) q.category = f.category
  if (f.q) q.q = f.q
  router.push({ query: q })
}

watch(() => route.query, () => { fromQuery(); load(true) }, { immediate: true })
onMounted(async () => {
  try { removals.value = (await get('/rules/removals')).items || [] } catch { removals.value = [] }
})
</script>
