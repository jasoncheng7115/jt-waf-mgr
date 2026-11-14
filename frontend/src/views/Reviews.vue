<!-- The periodic WAF review: every few hours, what was refused (and whether anybody was refused by mistake), new
     internal hits, outside attacks that got through, what the automation did, and one line per focus site.
     Paths and addresses come from requests outsiders made: shown as text only. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('review.title') }}</h1>
      <RouterLink v-if="id" class="btn small ghost" to="/reviews"><Icon name="back" />{{ t('review.all') }}</RouterLink>
      <button v-if="isApprover" class="btn small primary" type="button" :disabled="busy" @click="runNow"><Icon name="run" />{{ busy ? t('common.working') : t('review.run_now') }}</button>
    </div>
    <p class="muted">{{ t('review.intro') }}</p>
    <ErrorBox :error="error" />

    <!-- one review -->
    <template v-if="id">
      <Loading v-if="!rv && !error" />
      <template v-if="rv">
        <section class="card" :class="rv.level === 'warning' ? 'attention' : ''">
          <div class="cardhead">
            <h2><Icon name="report" /> #{{ rv.id }} · {{ window(rv) }}</h2>
            <span class="badge" :class="rv.level === 'warning' ? 'b-warn' : 'b-ok'">{{ verdict(rv) }}</span>
          </div>
          <div class="rvtiles">
            <div class="rvtile"><span class="muted small">{{ t('review.events') }}</span><b>{{ fmtNum(rv.events) }}</b>
              <span class="muted small">{{ t('review.blocked_logged', { b: fmtNum(rv.blocked), l: fmtNum(rv.logged) }) }}</span></div>
            <div class="rvtile" :class="{ attn: rv.possible_false_blocks }"><span class="muted small">{{ t('review.suspects') }}</span><b>{{ fmtNum(rv.possible_false_blocks) }}</b>
              <span class="muted small">{{ t('review.of_groups', { n: fmtNum(rv.score_only_groups) }) }}</span></div>
            <div class="rvtile" :class="{ attn: rv.internal_new }"><span class="muted small">{{ t('review.internal_new') }}</span><b>{{ fmtNum(rv.internal_new) }}</b>
              <span class="muted small">{{ t('review.of_groups', { n: fmtNum((rv.internal || []).length) }) }}</span></div>
            <div class="rvtile"><span class="muted small">{{ t('review.not_refused') }}</span><b>{{ fmtNum(rv.outside_not_refused_groups) }}</b>
              <span class="muted small">{{ t('review.groups') }}</span></div>
            <div class="rvtile"><span class="muted small">{{ t('review.done') }}</span><b>{{ fmtNum(rv.applied) }}</b>
              <span class="muted small">{{ t('review.done_hint', { b: fmtNum(sum(rv.ip_blocks)), p: fmtNum((rv.analysis || {}).proposals || 0) }) }}</span></div>
          </div>
          <p class="small">
            <span>{{ t('review.waiting', { a: fmtNum(rv.open_alerts), c: fmtNum((rv.awaiting_approval || []).length) }) }}</span>
            <RouterLink v-if="rv.open_alerts" class="gapl" to="/alerts">{{ t('review.go_alerts') }}</RouterLink>
            <RouterLink v-if="(rv.awaiting_approval || []).length" class="gapl" to="/changes">{{ t('review.go_changes') }}</RouterLink>
          </p>
        </section>

        <section v-if="(rv.focus || []).length" class="card">
          <h2><Icon name="shield" /> {{ t('review.focus') }}</h2>
          <ul class="rvfocus">
            <li v-for="f in rv.focus" :key="f.host" :class="{ attn: f.outside_not_refused || f.s429 || (f.repeated_login || []).length }">
              <b class="mono">{{ f.host }}</b>
              <span class="gapl">{{ t('review.focus_line', { e: fmtNum(f.events), b: fmtNum(f.blocked), o: fmtNum(f.outside_not_refused), l: fmtNum(f.login_events), r: fmtNum(f.requests), x: fmtNum(f.external_requests), s: fmtNum(f.s429) }) }}</span>
              <div v-if="(f.repeated_login || []).length" class="small">{{ t('review.repeated') }}
                <span v-for="p in f.repeated_login" :key="p[0]" class="gapl"><span class="mono" :data-ip="p[0]">{{ p[0] }}</span> ×{{ p[1] }}</span></div>
            </li>
          </ul>
        </section>

        <section class="card">
          <h2><Icon name="block" /> {{ t('review.score_only') }}</h2>
          <p class="muted small">{{ t('review.score_only_hint') }}</p>
          <DataTable id="review-score" :columns="groupCols" :rows="rv.score_only || []" :row-key="(r) => r.host + r.method + r.path" :page-size="10" :empty="t('review.none')">
            <template #cell-what="{ row }"><span class="badge" :class="row.suspect ? 'b-warn' : 'b-logged'">{{ row.suspect ? t('review.suspect') : t('review.attack') }}</span></template>
            <template #cell-path="{ row }"><span class="method">{{ row.method }}</span> <TruncText :text="row.path" :max="160" mono /></template>
            <template #cell-rules="{ row }"><span class="mono small">{{ (row.rules || []).join(', ') || '—' }}</span></template>
          </DataTable>
        </section>

        <section class="card">
          <h2><Icon name="network" /> {{ t('review.internal') }}</h2>
          <p class="muted small">{{ t('review.internal_hint') }}</p>
          <DataTable id="review-internal" :columns="internalCols" :rows="rv.internal || []" :row-key="(r) => r.host + r.path" :page-size="10" :empty="t('review.none')">
            <template #cell-new="{ row }"><span v-if="row.new" class="badge b-warn">{{ t('review.new') }}</span><span v-else class="muted">—</span></template>
            <template #cell-path="{ row }"><TruncText :text="row.path" :max="160" mono /></template>
            <template #cell-rules="{ row }"><span class="mono small">{{ (row.rules || []).join(', ') || '—' }}</span></template>
          </DataTable>
        </section>

        <section class="card">
          <h2><Icon name="alert" /> {{ t('review.not_refused') }}</h2>
          <p class="muted small">{{ t('review.not_refused_hint') }}</p>
          <DataTable id="review-outside" :columns="outsideCols" :rows="rv.outside_not_refused || []" :row-key="(r) => r.host + r.path" :page-size="10" :empty="t('review.none')">
            <template #cell-path="{ row }"><TruncText :text="row.path" :max="160" mono /></template>
            <template #cell-rules="{ row }"><span class="mono small">{{ (row.rules || []).join(', ') || '—' }}</span></template>
          </DataTable>
        </section>

        <section v-if="(rv.changes || []).length || (rv.confident_by_rule || []).length" class="card">
          <h2><Icon name="change" /> {{ t('review.automation') }}</h2>
          <p class="small">{{ t('review.analysis_line', { r: fmtNum(rv.analysis.runs), e: fmtNum(rv.analysis.errors), p: fmtNum(rv.analysis.proposals) }) }}</p>
          <ul v-if="(rv.changes || []).length" class="rvlist">
            <li v-for="c in rv.changes" :key="c.id"><RouterLink :to="'/changes/' + c.id">#{{ c.id }}</RouterLink>
              <DirectionBadge class="gapl" :direction="c.direction" /> <StateBadge :state="c.state" />
              <span class="gapl">{{ c.reason }}</span></li>
          </ul>
          <p v-if="(rv.confident_by_rule || []).length" class="small">{{ t('review.confident') }}
            <span v-for="p in rv.confident_by_rule" :key="p[0]" class="gapl"><span class="mono">{{ p[0] }}</span> ×{{ fmtNum(p[1]) }}</span></p>
        </section>
      </template>
    </template>

    <!-- the list -->
    <template v-else>
      <p v-if="list && !list.enabled" class="alert info">{{ t('review.off') }}</p>
      <p v-else-if="list" class="muted small">{{ t('review.schedule', { h: list.interval_hours }) }}
        <span v-if="!(list.focus_sites || []).length">{{ t('review.no_focus') }}</span></p>
      <Loading v-if="!list && !error" />
      <section v-if="list" class="card">
        <DataTable id="review-list" :columns="cols" :rows="list.items" :default-sort="{ key: 'id', dir: -1 }" :empty="t('review.empty')" clickable @row-click="(r) => router.push('/reviews/' + r.id)">
          <template #cell-id="{ row }"><RouterLink :to="'/reviews/' + row.id">#{{ row.id }}</RouterLink></template>
          <template #cell-window="{ row }">{{ window(row) }}</template>
          <template #cell-level="{ row }"><span class="badge" :class="row.level === 'warning' ? 'b-warn' : 'b-ok'">{{ verdict(row) }}</span></template>
        </DataTable>
      </section>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api.js'
import { t } from '../i18n.js'
import { hasRole } from '../store.js'
import { fmtMinute, fmtNum } from '../util.js'
import Icon from '../components/Icon.vue'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import DataTable from '../components/DataTable.vue'
import TruncText from '../components/TruncText.vue'
import DirectionBadge from '../components/DirectionBadge.vue'
import StateBadge from '../components/StateBadge.vue'

const props = defineProps({ id: { type: String, default: null } })
const router = useRouter()
const list = ref(null)
const rv = ref(null)
const error = ref(null)
const busy = ref(false)
const isApprover = computed(() => hasRole('approver'))

const sum = (o) => Object.values(o || {}).reduce((a, b) => a + b, 0)
function window(r) {
  if (!r.since) return '—'
  return fmtMinute(r.since) + ' – ' + fmtMinute(r.until).slice(-5)
}
function attention(r) {
  return (r.possible_false_blocks || 0) + (r.internal_new || 0) +
    (r.focus || []).filter((f) => f.outside_not_refused || f.s429 || (f.repeated_login || []).length).length
}
function verdict(r) {
  const n = attention(r)
  return n ? t('review.attention', { n }) : t('review.ok')
}

const cols = computed(() => [
  { key: 'id', label: '#', align: 'num', value: (r) => r.id },
  { key: 'window', label: t('review.col.window'), value: (r) => r.since, text: (r) => window(r) },
  { key: 'level', label: t('review.col.result'), value: (r) => attention(r), text: (r) => verdict(r) },
  { key: 'events', label: t('review.events'), align: 'num' },
  { key: 'blocked', label: t('review.col.blocked'), align: 'num' },
  { key: 'possible_false_blocks', label: t('review.suspects'), align: 'num' },
  { key: 'internal_new', label: t('review.internal_new'), align: 'num' },
  { key: 'outside_not_refused_groups', label: t('review.not_refused'), align: 'num' },
  { key: 'applied', label: t('review.col.applied'), align: 'num' },
  { key: 'trigger', label: t('review.col.trigger'), hidden: true, value: (r) => t('review.trigger.' + r.trigger) },
])
const groupCols = computed(() => [
  { key: 'what', label: t('review.col.what'), value: (r) => (r.suspect ? 0 : 1) },
  { key: 'host', label: t('review.col.host') },
  { key: 'path', label: t('review.col.path'), value: (r) => r.path },
  { key: 'n', label: t('review.col.n'), align: 'num' },
  { key: 'sources', label: t('review.col.sources'), align: 'num' },
  { key: 'internal_sources', label: t('review.col.internal_sources'), align: 'num' },
  { key: 'rules', label: t('review.col.rules'), sortable: false, text: (r) => (r.rules || []).join(' ') },
])
const internalCols = computed(() => [
  { key: 'new', label: t('review.col.new'), value: (r) => (r.new ? 0 : 1) },
  { key: 'host', label: t('review.col.host') },
  { key: 'path', label: t('review.col.path') },
  { key: 'n', label: t('review.col.n'), align: 'num' },
  { key: 'sources', label: t('review.col.sources'), align: 'num' },
  { key: 'rules', label: t('review.col.rules'), sortable: false, text: (r) => (r.rules || []).join(' ') },
])
const outsideCols = computed(() => [
  { key: 'host', label: t('review.col.host') },
  { key: 'path', label: t('review.col.path') },
  { key: 'n', label: t('review.col.n'), align: 'num' },
  { key: 'sources', label: t('review.col.sources'), align: 'num' },
  { key: 'families', label: t('review.col.families'), value: (r) => (r.families || []).join(', ') },
  { key: 'rules', label: t('review.col.rules'), sortable: false, text: (r) => (r.rules || []).join(' ') },
])

async function load() {
  error.value = null
  try {
    if (props.id) { rv.value = null; rv.value = await get('/reviews/' + props.id) }
    else list.value = await get('/reviews')
  } catch (e) { error.value = e }
}
async function runNow() {
  busy.value = true
  error.value = null
  try {
    const r = await post('/reviews/run', {})
    router.push('/reviews/' + r.id)
  } catch (e) { error.value = e } finally { busy.value = false }
}
watch(() => props.id, load)
onMounted(load)
</script>

<style scoped>
.rvtiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 0 0 12px; }
.rvtile { display: flex; flex-direction: column; gap: 2px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--panel-2); }
.rvtile b { font-size: 22px; font-variant-numeric: tabular-nums; }
.rvtile.attn { border-color: var(--warn); }
.rvfocus, .rvlist { list-style: none; margin: 0; padding: 0; }
.rvfocus li, .rvlist li { padding: 6px 0; border-bottom: 1px solid var(--border); }
.rvfocus li:last-child, .rvlist li:last-child { border-bottom: 0; }
.rvfocus li.attn { box-shadow: inset 3px 0 0 var(--warn); padding-left: 8px; }
</style>
