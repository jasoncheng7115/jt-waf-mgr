<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('changes.title') }}</h1>
      <button type="button" class="btn small ghost" :aria-pressed="showGuide ? 'true' : 'false'" @click="showGuide = !showGuide"><Icon name="help" />{{ t('guide.wf.toggle') }}</button>
      <RouterLink class="btn small ghost" to="/versions"><Icon name="versions" />{{ t('nav.versions') }}</RouterLink>
      <RouterLink class="btn small ghost" to="/managed"><Icon name="list" />{{ t('nav.managed') }}</RouterLink>
      <RouterLink v-if="canPropose && adopted" class="btn primary" to="/changes/new"><Icon name="add" />{{ t('changes.new') }}</RouterLink>
    </div>
    <section v-if="showGuide" class="card guide">
      <FlowSteps :title="t('guide.wf.title')" :steps="flow" :note="t('guide.wf.note')" />
      <FlowSteps :title="t('guide.apply.title')" :steps="applyFlow" :note="t('guide.apply.note')" compact />
      <h3 class="charthead">{{ t('guide.wf.states') }}</h3>
      <dl class="states">
        <template v-for="s in STATES" :key="s">
          <dt><StateBadge :state="s" /> <span class="mono muted small">{{ s }}</span></dt>
          <dd>{{ t('guide.cstate.' + s) }}</dd>
        </template>
      </dl>
    </section>
    <div v-if="adopted === false" class="alert warn">
      {{ t('changes.not_adopted') }} <RouterLink to="/managed">{{ t('changes.go_managed') }}</RouterLink>
    </div>
    <div class="seg" role="tablist">
      <button v-for="tb in TABS" :key="tb" type="button" role="tab" :aria-selected="tab === tb" :class="{ on: tab === tb }" @click="setTab(tb)">
        <Icon :name="TAB_ICON[tb]" />{{ t('changes.tab.' + tb) }}<span v-if="tb === 'pending_approval' && pending.count" class="badge tiny b-warn">{{ pending.count }}</span>
      </button>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="loading && !items.length" />
    <section v-if="items.length" class="card">
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.change.by_state') }}</h3><HBars :items="stateItems" :series="countSeries" /></div>
        <div><h3 class="charthead">{{ t('chart.change.by_kind') }}</h3><HBars :items="kindItems" :series="countSeries" /></div>
        <div><h3 class="charthead">{{ t('chart.change.by_direction') }}</h3><SegBar :parts="directionParts" :label="t('chart.change.by_direction')" /></div>
      </div>
      <p class="muted small">{{ t('chart.change.loaded', { n: fmtNum(items.length) }) }}</p>
    </section>
    <DataTable id="changes" :columns="cols" :rows="items" row-key="id" :default-sort="{ key: 'id', dir: -1 }"
               clickable @row-click="(c) => router.push('/changes/' + c.id)">
      <template #cell-id="{ row }"><RouterLink class="mono" :to="'/changes/' + row.id" @click.stop>{{ row.id }}</RouterLink></template>
      <template #cell-created_at="{ row }">{{ fmtShortTime(row.created_at) }}</template>
      <template #cell-what="{ row }">{{ t('op.' + row.op) }} · {{ t('kind.' + row.kind) }}<span v-if="row.rule_id" class="mono muted"> {{ row.rule_id }}</span></template>
      <template #cell-summary="{ row }"><TruncText :text="row.summary || ''" :max="160" />
        <div class="sub"><TruncText :text="row.reason || ''" :max="160" /></div></template>
      <template #cell-direction="{ row }"><DirectionBadge :direction="row.direction" /></template>
      <template #cell-state="{ row }"><StateBadge :state="row.state" />
        <div v-if="row.error" class="sub warn"><TruncText :text="row.error" :max="80" /></div></template>
      <template #cell-proposed_by="{ row }">{{ safeText(row.proposed_by, 64) }}<span v-if="row.proposed_via === 'api'" class="chip tag">API</span></template>
      <template #cell-updated_at="{ row }">{{ fmtShortTime(row.updated_at) }}</template>
    </DataTable>
    <LoadMore :cursor="cursor" :busy="loading" @more="load(true)" />
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { get } from '../api.js'
import { t } from '../i18n.js'
import { hasRole, pending, refreshPending } from '../store.js'
import { safeText, fmtShortTime, fmtNum } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import LoadMore from '../components/LoadMore.vue'
import TruncText from '../components/TruncText.vue'
import StateBadge from '../components/StateBadge.vue'
import DirectionBadge from '../components/DirectionBadge.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import HBars from '../components/charts/HBars.vue'
import SegBar from '../components/charts/SegBar.vue'

const TABS = ['open', 'pending_approval', 'history']
const TAB_ICON = { open: 'list', pending_approval: 'approve', history: 'history' }
// changes.py: checking -> pending_approval -> approved -> applying -> applied, plus the end states
const STATES = ['checking', 'failed', 'pending_approval', 'approved', 'applying', 'applied', 'apply_failed', 'rejected', 'cancelled', 'rolled_back']
const KINDS = ['exclusion', 'confident_block', 'redaction', 'plugin', 'raw', 'system']
const route = useRoute()
const router = useRouter()
const tab = computed(() => (TABS.includes(route.query.tab) ? route.query.tab : 'open'))
const items = ref([])
const cursor = ref(null)
const loading = ref(false)
const error = ref(null)
const adopted = ref(null)
const canPropose = computed(() => hasRole('operator'))

// guide, remembered in this browser
const GUIDE_KEY = 'jtwaf.guide.changes'
function readGuide() { try { return localStorage.getItem(GUIDE_KEY) === '1' } catch { return false } }   // collapsed until opened: the list comes first
const showGuide = ref(readGuide())
watch(showGuide, (v) => { try { localStorage.setItem(GUIDE_KEY, v ? '1' : '0') } catch { /* private mode */ } })

const flow = computed(() => [
  { key: 'propose', label: t('guide.wf.propose'), desc: t('guide.wf.propose_d'), icon: 'add', to: canPropose.value && adopted.value ? '/changes/new' : undefined },
  { key: 'static', label: t('guide.wf.static'), desc: t('guide.wf.static_d'), icon: 'code' },
  { key: 'evidence', label: t('guide.wf.evidence'), desc: t('guide.wf.evidence_d'), icon: 'search' },
  { key: 'sandbox', label: t('guide.wf.sandbox'), desc: t('guide.wf.sandbox_d'), icon: 'test' },
  { key: 'approval', label: t('guide.wf.approval'), desc: t('guide.wf.approval_d'), icon: 'approve' },
  { key: 'queue', label: t('guide.wf.queue'), desc: t('guide.wf.queue_d'), icon: 'timer' },
  { key: 'apply', label: t('guide.wf.apply'), desc: t('guide.wf.apply_d'), icon: 'server' },
  { key: 'applied', label: t('guide.wf.applied'), desc: t('guide.wf.applied_d'), icon: 'check', to: '/versions' },
])
const applyFlow = computed(() => ['request', 'drift', 'health_before', 'snapshot', 'write', 'nginx_t', 'reload', 'health_after']
  .map((k) => ({ key: k, label: t('guide.apply.' + k), desc: t('guide.apply.' + k + '_d') })))

const cols = computed(() => [
  { key: 'id', label: t('change.id'), required: true, align: 'num', value: (c) => c.id },
  { key: 'created_at', label: t('change.created'), nowrap: true, text: (c) => fmtShortTime(c.created_at) },
  { key: 'what', label: t('change.what'), nowrap: true, value: (c) => t('op.' + c.op) + ' · ' + t('kind.' + c.kind) + (c.rule_id ? ' ' + c.rule_id : '') },
  { key: 'summary', label: t('change.summary'), text: (c) => (c.summary || '') + ' ' + (c.reason || '') },
  { key: 'direction', label: t('change.direction'), value: (c) => t('direction.' + c.direction) },
  { key: 'state', label: t('change.state'), value: (c) => t('cstate.' + c.state), text: (c) => t('cstate.' + c.state) + ' ' + (c.error || '') },
  { key: 'proposed_by', label: t('change.proposed_by'), nowrap: true, text: (c) => (c.proposed_by || '') + (c.proposed_via === 'api' ? ' API' : '') },
  { key: 'updated_at', label: t('change.updated'), nowrap: true, hidden: true, text: (c) => fmtShortTime(c.updated_at) },
])

const countSeries = computed(() => [{ key: 'n', label: t('changes.title'), tone: 's1' }])
function countBy(keys, of, label) {
  return keys.map((k) => ({ key: k, label: label(k), values: { n: items.value.filter((c) => of(c) === k).length } }))
    .filter((x) => x.values.n > 0).sort((a, b) => b.values.n - a.values.n)
}
const stateItems = computed(() => countBy(STATES, (c) => c.state, (k) => t('cstate.' + k)))
const kindItems = computed(() => countBy(KINDS, (c) => c.kind, (k) => t('kind.' + k)))
const directionParts = computed(() => ['tighten', 'loosen', 'neutral'].map((d, i) => ({
  key: d, label: t('direction.' + d), value: items.value.filter((c) => c.direction === d).length, tone: ['s1', 's2', 's3'][i],
})))

function setTab(tb) { router.replace({ query: tb === 'open' ? {} : { tab: tb } }) }

async function load(more) {
  loading.value = true
  error.value = null
  try {
    const params = { limit: 100 }
    if (tab.value !== 'history') params.state = tab.value
    if (more && cursor.value) params.cursor = cursor.value
    const r = await get('/changes', params)
    items.value = more ? items.value.concat(r.items || []) : (r.items || [])
    cursor.value = r.next_cursor
  } catch (e) { error.value = e } finally { loading.value = false }
}

async function loadManaged() {
  try { adopted.value = !!(await get('/managed')).adopted } catch { adopted.value = null }
}

watch(tab, () => { items.value = []; cursor.value = null; load(false) }, { immediate: true })
loadManaged()
refreshPending(true)
</script>

<style scoped>
.guide { display: flex; flex-direction: column; gap: 12px; }
.states { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 0; align-items: baseline; }
.states dt { white-space: nowrap; }
.states dd { margin: 0; color: var(--muted); }
@media (max-width: 640px) {
  .states { grid-template-columns: 1fr; }
  .states dd { margin-bottom: 6px; }
}
</style>
