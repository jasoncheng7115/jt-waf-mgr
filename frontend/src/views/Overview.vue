<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('overview.title') }}</h1>
      <div class="seg" role="group" :aria-label="t('overview.range')">
        <button type="button" :class="{ on: range === '24h' }" :aria-pressed="range === '24h' ? 'true' : 'false'" @click="setRange('24h')"><Icon name="timer" />{{ t('overview.range_24h') }}</button>
        <button type="button" :class="{ on: range === '7d' }" :aria-pressed="range === '7d' ? 'true' : 'false'" @click="setRange('7d')"><Icon name="calendar" />{{ t('overview.range_7d') }}</button>
      </div>
      <button type="button" class="btn small ghost" :class="{ on: showGuide }" :aria-pressed="showGuide ? 'true' : 'false'" @click="toggleGuide"><Icon name="help" />{{ t('guide.how') }}</button>
      <button type="button" class="btn small ghost" :disabled="loading" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
    </div>
    <FlowSteps v-if="showGuide" compact :title="t('guide.ev.title')" :steps="flow" :note="t('guide.ev.note')" />
    <div v-if="integrityFails.length" class="alert error integritybanner" role="alert">
      <strong>{{ t('overview.integrity_problem') }}</strong>
      {{ integrityFails.map((k) => tOr('syscheck.k.' + k, k)).join(', ') }}
      <RouterLink class="btn small" to="/admin/system"><Icon name="verify" />{{ t('nav.system') }}</RouterLink>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="loading && !data" />
    <template v-if="data">
      <div class="tiles">
        <div class="tile"><div class="tl">{{ t('overview.events') }}</div><div class="tv">{{ fmtNum(data.totals.events) }}</div></div>
        <div class="tile t-blocked"><div class="tl">{{ t('outcome.blocked') }}</div><div class="tv">{{ fmtNum(data.totals.blocked) }}</div>
          <div class="ts">{{ t('decided.confident') }} {{ fmtNum(data.totals.blocked_confident) }} · {{ t('decided.score') }} {{ fmtNum(data.totals.blocked_score) }}</div></div>
        <div class="tile"><div class="tl">{{ t('outcome.logged') }}</div><div class="tv">{{ fmtNum(data.totals.logged) }}</div></div>
        <div class="tile"><div class="tl">{{ t('origin.external') }}</div><div class="tv">{{ fmtNum(data.totals.external) }}</div></div>
        <div class="tile"><div class="tl">{{ t('origin.internal') }}</div><div class="tv">{{ fmtNum(data.totals.internal) }}</div></div>
      </div>

      <section class="card">
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.outcome_split') }}</h3><SegBar :parts="outcomeParts" :label="t('chart.outcome_split')" /></div>
          <div><h3 class="charthead">{{ t('chart.block_reason') }}</h3><SegBar :parts="reasonParts" :label="t('chart.block_reason')" /></div>
          <div><h3 class="charthead">{{ t('chart.origin_split') }}</h3><SegBar :parts="originParts" :label="t('chart.origin_split')" /></div>
        </div>
        <h3 class="charthead">{{ t('overview.timeline') }}</h3>
        <TimeBars :data="data.timeline || []" :series="outcomeSeries" :label="t('chart.timeline')" />
      </section>

      <section class="card attention">
        <div class="cardhead">
          <h2>{{ t('overview.score_only') }} <span class="count">{{ data.score_only.length }}</span></h2>
          <RouterLink class="btn small ghost" :to="{ path: '/events', query: { outcome: 'blocked', decided_by: 'score', origin: 'external', since: data.since } }"><Icon name="list" />{{ t('common.view_all') }}</RouterLink>
        </div>
        <p class="muted small">{{ t('overview.score_only_hint') }}</p>
        <EventTable table-id="overview-score-only" :items="data.score_only" :page-size="10" :empty-text="t('overview.score_only_none')" />
      </section>

      <h2 v-if="data.focus && data.focus.length" class="sectionhead"><Icon name="shield" /> {{ t('overview.focus_title') }}
        <span class="muted small">{{ t('overview.focus_hint', { n: data.focus.length }) }}</span></h2>
      <section v-if="data.focus && data.focus.length" class="focusgrid">
        <div v-for="f in data.focus" :key="f.host" class="card focus">
          <div class="cardhead">
            <h2><TruncText :text="f.host" :max="80" /></h2>
            <RouterLink class="btn small ghost" :to="{ path: '/events', query: { host: f.host, since: data.since } }"><Icon name="list" />{{ t('common.view_all') }}</RouterLink>
          </div>
          <div class="minitiles">
            <span>{{ t('overview.events') }} <b>{{ fmtNum(f.events) }}</b></span>
            <span>{{ t('outcome.blocked') }} <b>{{ fmtNum(f.blocked) }}</b></span>
            <span>{{ t('origin.external') }} <b>{{ fmtNum(f.external) }}</b></span>
            <span :class="{ warn: f.external_not_blocked > 0 }">{{ t('overview.external_not_blocked') }} <b>{{ fmtNum(f.external_not_blocked) }}</b></span>
          </div>
          <SegBar thin :parts="focusParts(f)" :label="f.host" />
          <EventTable table-id="overview-focus" :items="f.recent || []" hide-host :page-size="10" :toolbar="false" />
        </div>
      </section>

      <div class="cols2">
        <section class="card">
          <h2>{{ t('overview.by_host') }}</h2>
          <CountList :items="data.by_host" :link-for="(it) => ({ path: '/events', query: { host: it.key, since: data.since } })" />
        </section>
        <section class="card">
          <h2>{{ t('overview.by_family') }}</h2>
          <CountList :items="data.by_family" :label-for="(it) => t('family.' + it.key)" :link-for="(it) => ({ path: '/events', query: { family: it.key, since: data.since } })" />
        </section>
        <section class="card">
          <h2>{{ t('overview.by_src') }}</h2>
          <CountList :items="data.by_src" mono :link-for="(it) => ({ path: '/lookup/' + encodeURIComponent(it.key) })" />
        </section>
        <section v-if="(data.by_country || []).length" class="card">
          <h2><Icon name="globe" /> {{ t('overview.by_country') }}</h2>
          <HBars :items="countryItems" :series="outcomeSeries" />
        </section>
        <section v-if="(data.by_asn || []).length" class="card">
          <h2><Icon name="network" /> {{ t('overview.by_asn') }}</h2>
          <HBars :items="asnItems" :series="outcomeSeries" />
        </section>
        <section class="card">
          <h2>{{ t('overview.by_rule') }}</h2>
          <CountList :items="data.by_rule" mono :link-for="(it) => ({ path: '/events', query: { rule_id: it.key, since: data.since } })" />
        </section>
      </div>
      <p class="muted small">{{ t('overview.period', { since: fmtTime(data.since), until: fmtTime(data.until) }) }}</p>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { get } from '../api.js'
import { t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { fmtNum, fmtTime } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import Icon from '../components/Icon.vue'
import EventTable from '../components/EventTable.vue'
import CountList from '../components/CountList.vue'
import HBars from '../components/charts/HBars.vue'
import { countryName } from '../util.js'
import { lang } from '../i18n.js'
import TruncText from '../components/TruncText.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import TimeBars from '../components/charts/TimeBars.vue'

const route = useRoute()
const router = useRouter()
const range = ref(route.query.range === '7d' ? '7d' : '24h')
const data = ref(null)
const countryItems = computed(() => (data.value?.by_country || []).map((c) => ({
  key: c.key, label: c.key === '?' ? t('overview.geo_unknown') : countryName(c.key, lang.value) + ' (' + c.key + ')',
  sub: t('overview.geo_sources', { n: c.sources }), values: { blocked: c.blocked, logged: c.logged } })))
const asnItems = computed(() => (data.value?.by_asn || []).map((c) => ({
  key: c.key, label: c.key === '?' ? t('overview.geo_unknown') : 'AS' + c.key + ' ' + (c.label || ''),
  sub: t('overview.geo_sources', { n: c.sources }), values: { blocked: c.blocked, logged: c.logged } })))
const error = ref(null)
const loading = ref(false)
let timer = null

// guidance: the compact flow (the Events page shows it with descriptions); hidden once the user closes it
const GUIDE_KEY = 'jtwaf.guide.overview'
function readFlag(k, d) { try { const v = window.localStorage.getItem(k); return v === null ? d : v === '1' } catch { return d } }
const showGuide = ref(readFlag(GUIDE_KEY, true))
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage unavailable */ }
}
const flow = computed(() => [
  { key: 'request', label: t('guide.ev.request'), icon: 'globe' },
  { key: 'rules', label: t('guide.ev.rules'), icon: 'shield' },
  { key: 'decide', label: t('guide.ev.decide'), icon: 'block' },
  { key: 'audit', label: t('guide.ev.audit'), icon: 'page' },
  { key: 'collect', label: t('guide.ev.collect', { name: 'jt-waf-mgr' }), icon: 'database' },
  { key: 'list', label: t('guide.ev.list'), icon: 'list', to: '/events' },
])

const outcomeSeries = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
const outcomeParts = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), value: data.value.totals.blocked, tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), value: data.value.totals.logged, tone: 'logged' },
])
// blocked_confident counts confident + fallback decisions; the rest of the blocks were decided by another rule
const reasonParts = computed(() => {
  const tt = data.value.totals
  return [
    { key: 'confident', label: t('decided.confident'), value: tt.blocked_confident, tone: 's1' },
    { key: 'score', label: t('decided.score'), value: tt.blocked_score, tone: 's2' },
    { key: 'other', label: t('decided.other'), value: Math.max(0, tt.blocked - tt.blocked_confident - tt.blocked_score), tone: 's3' },
  ]
})
const originParts = computed(() => [
  { key: 'external', label: t('origin.external'), value: data.value.totals.external, tone: 's1' },
  { key: 'internal', label: t('origin.internal'), value: data.value.totals.internal, tone: 's2' },
])
function focusParts(f) {
  return [
    { key: 'blocked', label: t('outcome.blocked'), value: f.blocked, tone: 'blocked' },
    { key: 'logged', label: t('outcome.logged'), value: Math.max(0, f.events - f.blocked), tone: 'logged' },
  ]
}

async function load() {
  loading.value = true
  error.value = null
  try { data.value = await get('/overview', { range: range.value }) } catch (e) { error.value = e } finally { loading.value = false }
}
function setRange(r) {
  range.value = r
  router.replace({ query: Object.assign({}, route.query, { range: r }) })
  load()
}
// admins: one system check per page load; any "fail" item shows a banner
const integrityFails = ref([])
async function loadIntegrity() {
  if (!hasRole('admin')) return
  try {
    const r = await get('/system/check')
    integrityFails.value = (r.items || []).filter((i) => i.status === 'fail').map((i) => i.key)
  } catch { /* the banner is optional */ }
}

onMounted(() => { load(); loadIntegrity(); timer = setInterval(() => { if (!document.hidden) load() }, 60000) })
onUnmounted(() => clearInterval(timer))
</script>
