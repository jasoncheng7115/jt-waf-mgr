<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('overview.title') }}</h1>
      <button type="button" class="btn small ghost" :class="{ on: showGuide }" :aria-pressed="showGuide ? 'true' : 'false'" @click="toggleGuide"><Icon name="help" />{{ t('guide.how') }}</button>
      <button type="button" class="btn small ghost" :disabled="loading" @click="load(false)"><Icon name="refresh" />{{ t('common.refresh') }}</button>
    </div>
    <FlowSteps v-if="showGuide" compact :title="t('guide.ev.title')" :steps="flow" :note="t('guide.ev.note')" />
    <!-- one row of filters above everything they scope; every value is also in the URL -->
    <div class="ovfilters" :class="{ active: hasFilters }" role="group" :aria-label="t('overview.filter.label')">
      <div class="seg" role="group" :aria-label="t('overview.range')">
        <button type="button" :class="{ on: range === '24h' }" :aria-pressed="range === '24h' ? 'true' : 'false'" @click="setQuery({ range: '24h' })"><Icon name="timer" />{{ t('overview.range_24h') }}</button>
        <button type="button" :class="{ on: range === '7d' }" :aria-pressed="range === '7d' ? 'true' : 'false'" @click="setQuery({ range: '7d' })"><Icon name="calendar" />{{ t('overview.range_7d') }}</button>
        <button type="button" :class="{ on: range === 'custom' || showCustom }" :aria-pressed="range === 'custom' ? 'true' : 'false'"
                :aria-expanded="showCustom ? 'true' : 'false'" @click="openCustom"><Icon name="history" />{{ t('overview.range_custom') }}</button>
      </div>
      <span v-if="range === 'custom' && data" class="fchip">
        <span class="fchip-k">{{ t('overview.range') }}</span>
        <span class="fchip-v">{{ fmtShortTime(data.since) }} – {{ fmtShortTime(data.until) }}</span>
        <button type="button" class="fchip-x" :aria-label="t('overview.range_clear')" :title="t('overview.range_clear')" @click="setQuery({ range: '24h' })"><Icon name="close" /></button>
      </span>
      <div class="seg" role="group" :aria-label="t('event.origin')">
        <button v-for="o in originOpts" :key="o.value" type="button" :class="{ on: (filters.origin || '') === o.value }" :aria-pressed="(filters.origin || '') === o.value ? 'true' : 'false'"
                @click="setQuery({ origin: o.value })"><Icon :name="o.icon" />{{ o.label }}</button>
      </div>
      <div class="seg" role="group" :aria-label="t('event.outcome')">
        <button v-for="o in outcomeOpts" :key="o.value" type="button" :class="{ on: (filters.outcome || '') === o.value }" :aria-pressed="(filters.outcome || '') === o.value ? 'true' : 'false'"
                @click="setQuery({ outcome: o.value })"><Icon :name="o.icon" />{{ o.label }}</button>
      </div>
      <span v-if="chips.length" class="fchip-lead"><Icon name="filter" /> {{ t('overview.filter.active') }}</span>
      <span v-for="c in chips" :key="c.key" class="fchip">
        <span class="fchip-k">{{ c.label }}</span>
        <span class="fchip-v" :class="{ mono: c.mono }" :title="c.full">{{ c.text }}</span>
        <button type="button" class="fchip-x" :aria-label="t('overview.filter.remove', { name: c.label + ' ' + c.text })" :title="t('overview.filter.remove', { name: c.label + ' ' + c.text })"
                @click="setQuery({ [c.key]: '' })"><Icon name="close" /></button>
      </span>
      <span v-if="!chips.length" class="muted small fhint"><Icon name="info" /> {{ t('overview.filter.hint') }}</span>
      <button v-if="hasFilters" type="button" class="btn small ghost" @click="clearAll"><Icon name="clear" />{{ t('overview.filter.clear_all') }}</button>
    </div>
    <div v-if="showCustom" class="card custompanel" role="group" :aria-label="t('overview.range_custom')">
      <div class="field"><label for="ov-since">{{ t('filter.since') }}</label>
        <DatePicker id="ov-since" v-model="cust.since" mode="datetime" :presets="sincePresets" /></div>
      <div class="field"><label for="ov-until">{{ t('filter.until') }}</label>
        <DatePicker id="ov-until" v-model="cust.until" mode="datetime" :presets="untilPresets" /></div>
      <div class="actions">
        <button type="button" class="btn primary small" @click="applyCustom"><Icon name="check" />{{ t('overview.range_apply') }}</button>
        <button type="button" class="btn ghost small" @click="showCustom = false"><Icon name="cancel" />{{ t('common.cancel') }}</button>
      </div>
      <p v-if="custError" class="alert warn small">{{ custError }}</p>
      <p class="muted small">{{ t('overview.range_custom_hint', { days: 31 }) }}</p>
    </div>
    <div v-if="alertCount.open" class="alert warn integritybanner" role="status">
      <Icon name="bell" /><strong>{{ t('overview.open_alerts', { n: alertCount.open }) }}</strong>
      <span v-if="alertCount.critical">{{ t('overview.open_alerts_critical', { n: alertCount.critical }) }}</span>
      <RouterLink class="btn small" to="/alerts"><Icon name="go" />{{ t('nav.alerts') }}</RouterLink>
    </div>
    <div v-if="integrityFails.length" class="alert error integritybanner" role="alert">
      <strong>{{ t('overview.integrity_problem') }}</strong>
      {{ integrityFails.map((k) => tOr('syscheck.k.' + k, k)).join(', ') }}
      <RouterLink class="btn small" to="/admin/system"><Icon name="verify" />{{ t('nav.system') }}</RouterLink>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="loading && !data" />
    <div v-if="data" class="ovbody" :class="{ stale: dimmed }" :aria-busy="loading ? 'true' : 'false'">
      <div v-if="hasFilters" class="filteredbanner" role="status"><Icon name="filter" />
        <span>{{ t('overview.filter.banner') }}</span>
        <strong v-for="c in chips" :key="'b' + c.key" class="fb-item">{{ c.label }}: {{ c.text }}</strong>
        <template v-if="filters.origin"><strong class="fb-item">{{ t('origin.' + filters.origin) }}</strong></template>
        <template v-if="filters.outcome"><strong class="fb-item">{{ t('outcome.' + filters.outcome) }}</strong></template>
      </div>
      <div class="tiles">
        <div v-for="st in statTiles" :key="st.key" class="tile stat" :class="st.cls">
          <div class="tl"><Icon :name="st.icon" />{{ st.label }}</div>
          <div class="tv">{{ fmtNum(st.value) }}</div>
          <div class="ts"><span v-if="st.delta" class="delta" :class="st.delta.dir">{{ st.delta.text }}</span>
            <span v-if="st.sub" class="tsub">{{ st.sub }}</span></div>
          <Sparkline class="stat-spark" :values="st.series" :tone="st.tone" :label="st.label" />
        </div>
      </div>

      <section class="card">
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.outcome_split') }}</h3><SegBar :parts="outcomeParts" :label="t('chart.outcome_split')" pickable @pick="(p) => toggleFilter('outcome', p.key)" /></div>
          <div><h3 class="charthead">{{ t('chart.block_reason') }}</h3><SegBar :parts="reasonParts" :label="t('chart.block_reason')" pickable @pick="(p) => toggleFilter('decided_by', p.key)" /></div>
          <div><h3 class="charthead">{{ t('chart.origin_split') }}</h3><SegBar :parts="originParts" :label="t('chart.origin_split')" pickable @pick="(p) => toggleFilter('origin', p.key)" /></div>
        </div>
        <h3 class="charthead">{{ t('overview.timeline') }}</h3>
        <TimeBars :data="data.timeline || []" :series="outcomeSeries" :label="t('chart.timeline')" selectable
                  :bucket-seconds="data.bucket_seconds || 3600" @select="(r) => setQuery({ range: 'custom', since: r.since, until: r.until })" />
        <p class="muted small brushhint"><Icon name="info" /> {{ t('overview.brush_hint') }}</p>
      </section>

      <section class="card attention">
        <div class="cardhead">
          <h2><Icon name="alert" /> {{ t('overview.score_only') }} <span class="count">{{ data.score_only.length }}</span></h2>
          <RouterLink class="btn small ghost" :to="{ path: '/events', query: { ...filters, outcome: 'blocked', decided_by: 'score', origin: 'external', ...timeQ } }"><Icon name="list" />{{ t('common.view_all') }}</RouterLink>
        </div>
        <p class="muted small">{{ t('overview.score_only_hint') }}</p>
        <EventTable table-id="overview-score-only" :items="data.score_only" :page-size="10" :empty-text="t('overview.score_only_none')" filterable @filter="toggleFilter" />
      </section>

      <h2 v-if="data.focus && data.focus.length" class="sectionhead"><Icon name="shield" /> {{ t('overview.focus_title') }}
        <span class="muted small">{{ t('overview.focus_hint', { n: data.focus.length }) }}</span></h2>
      <section v-if="focusQuiet.length" class="card focusquiet">
        <h2><Icon name="check" /> {{ t('overview.focus_quiet', { n: focusQuiet.length }) }}</h2>
        <div class="chips"><RouterLink v-for="f in focusQuiet" :key="f.host" class="chip host" :to="{ path: '/events', query: { host: f.host } }">{{ safeText(f.host, 80) }}</RouterLink></div>
      </section>
      <section v-if="focusBusy.length" class="focuslist">
        <div v-for="f in focusBusy" :key="f.host" class="card focus">
          <div class="cardhead">
            <h2><Icon name="globe" /> <TruncText :text="f.host" :max="80" /></h2>
            <RouterLink class="btn small ghost" :to="{ path: '/events', query: { ...filters, host: f.host, ...timeQ } }"><Icon name="list" />{{ t('common.view_all') }}</RouterLink>
          </div>
          <div class="minitiles">
            <span>{{ t('overview.events') }} <b>{{ fmtNum(f.events) }}</b></span>
            <span>{{ t('outcome.blocked') }} <b>{{ fmtNum(f.blocked) }}</b></span>
            <span>{{ t('origin.external') }} <b>{{ fmtNum(f.external) }}</b></span>
            <span :class="{ warn: f.external_not_blocked > 0 }">{{ t('overview.external_not_blocked') }} <b>{{ fmtNum(f.external_not_blocked) }}</b></span>
          </div>
          <SegBar thin :parts="focusParts(f)" :label="f.host" />
          <EventTable table-id="overview-focus" :items="f.recent || []" hide-host :page-size="5" :toolbar="false" filterable @filter="toggleFilter" />
        </div>
      </section>

      <div class="cols2">
        <section class="card">
          <h2><Icon name="server" /> {{ t('overview.by_host') }}</h2>
          <CountList :items="data.by_host" pickable :active-key="filters.host" :open-label="t('filter.open_events')" :link-for="(it) => eventsLink('host', it.key)" @pick="(it) => toggleFilter('host', it.key)" />
        </section>
        <section class="card">
          <h2><Icon name="shield" /> {{ t('overview.by_family') }}</h2>
          <CountList :items="data.by_family" :label-for="(it) => t('family.' + it.key)" pickable :active-key="filters.family" :open-label="t('filter.open_events')" :link-for="(it) => eventsLink('family', it.key)" @pick="(it) => toggleFilter('family', it.key)" />
        </section>
        <section class="card">
          <h2><Icon name="network" /> {{ t('overview.by_src') }}</h2>
          <CountList :items="data.by_src" mono pickable :active-key="filters.src_ip" :open-label="t('filter.open_lookup')" :link-for="(it) => ({ path: '/lookup/' + encodeURIComponent(it.key) })" @pick="(it) => toggleFilter('src_ip', it.key)" />
        </section>
        <section v-if="(data.by_asn || []).length" class="card">
          <h2><Icon name="network" /> {{ t('overview.by_asn') }}</h2>
          <HBars :items="asnItems" :series="outcomeSeries" />
        </section>
        <section v-if="(data.by_country || []).length" class="card span2">
          <h2><Icon name="globe" /> {{ t('overview.by_country') }}</h2>
          <p class="muted small">{{ t('map.external_hint') }}</p>
          <div class="mapgrid">
            <WorldMap :items="countryItems" :series="outcomeSeries" :label="t('overview.by_country')" pickable :active-key="filters.country || null"
                      @pick="(it) => toggleFilter('country', it.key)" />
            <HBars :items="countryItems.slice(0, 15)" :series="outcomeSeries" pickable :open-label="t('filter.open_events')" @pick="(it) => toggleFilter('country', it.key)" />
          </div>
        </section>
        <section class="card span2">
          <h2><Icon name="shield" /> {{ t('overview.by_rule') }}</h2>
          <CountList :items="ruleItems" pickable :label-for="(it) => it.key + (it.family ? ' · ' + tOr('family.' + it.family, it.family) : '')" :active-key="filters.rule_id" :open-label="t('filter.open_rule')" :link-for="(it) => ({ path: '/rules/' + encodeURIComponent(it.key) })" @pick="(it) => toggleFilter('rule_id', it.key)" />
        </section>
      </div>
      <p class="muted small">{{ t('overview.period', { since: fmtTime(data.since), until: fmtTime(data.until) }) }}</p>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { get } from '../api.js'
import { t, tOr } from '../i18n.js'
import { hasRole, alertCount } from '../store.js'
import { fmtNum, fmtTime, fmtShortTime, safeText } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import Icon from '../components/Icon.vue'
import EventTable from '../components/EventTable.vue'
import CountList from '../components/CountList.vue'
import HBars from '../components/charts/HBars.vue'
import WorldMap from '../components/charts/WorldMap.vue'
import Sparkline from '../components/charts/Sparkline.vue'
import { countryName } from '../util.js'
import { lang } from '../i18n.js'
import TruncText from '../components/TruncText.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import TimeBars from '../components/charts/TimeBars.vue'
import DatePicker from '../components/DatePicker.vue'

const route = useRoute()
const router = useRouter()
const data = ref(null)

// filters live in the URL (bookmarkable, Back works); the same names as the event list
const FILTER_KEYS = ['origin', 'outcome', 'decided_by', 'host', 'src_ip', 'country', 'rule_id', 'family', 'path_prefix', 'q']
const CHIP_LABEL = { decided_by: 'event.decided_by', host: 'event.host', src_ip: 'event.source', country: 'filter.country', rule_id: 'filter.rule_id',
  family: 'event.family', path_prefix: 'filter.path_prefix', q: 'filter.q' }
const range = computed(() => (route.query.range === '7d' ? '7d'
  : route.query.range === 'custom' && typeof route.query.since === 'string' && route.query.since ? 'custom' : '24h'))
// a time window of one's own: the date pickers, or a drag across the timeline
const showCustom = ref(false)
const cust = reactive({ since: '', until: '' })
const custError = ref('')
const p2 = (n) => String(n).padStart(2, '0')
function toLocalInput(iso) {
  const d = new Date(iso)
  if (!iso || isNaN(d)) return ''
  return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()) + 'T' + p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds())
}
function ago(ms) { return toLocalInput(new Date(Date.now() - ms).toISOString()) }
const sincePresets = computed(() => [
  { key: '1h', label: t('events.preset_1h'), value: () => ago(3600e3) },
  { key: '24h', label: t('events.preset_24h'), value: () => ago(86400e3) },
  { key: '7d', label: t('events.preset_7d'), value: () => ago(7 * 86400e3) },
  { key: '30d', label: t('events.preset_30d'), value: () => ago(30 * 86400e3) },
])
const untilPresets = computed(() => [{ key: 'now', label: t('date.now'), value: () => ago(0) }])
function openCustom() {
  showCustom.value = !showCustom.value
  custError.value = ''
  if (showCustom.value) {
    cust.since = toLocalInput(data.value?.since) || ago(86400e3)
    cust.until = toLocalInput(data.value?.until) || ago(0)
  }
}
function applyCustom() {
  const a = new Date(cust.since), b = cust.until ? new Date(cust.until) : new Date()
  if (isNaN(a) || isNaN(b) || b - a < 3600e3) { custError.value = t('overview.range_bad'); return }
  if (b - a > 31 * 86400e3) { custError.value = t('overview.range_too_long', { days: 31 }); return }
  showCustom.value = false
  setQuery({ range: 'custom', since: a.toISOString(), until: b.toISOString() })
}
const timeQ = computed(() => (data.value ? { since: data.value.since, ...(data.value.range === 'custom' ? { until: data.value.until } : {}) } : {}))
const filters = computed(() => {
  const o = {}
  for (const k of FILTER_KEYS) { const v = route.query[k]; if (typeof v === 'string' && v) o[k] = v }
  return o
})
const hasFilters = computed(() => Object.keys(filters.value).length > 0)
const chips = computed(() => Object.keys(CHIP_LABEL).filter((k) => filters.value[k]).map((k) => {
  const v = filters.value[k]
  const text = k === 'family' ? tOr('family.' + v, v) : k === 'decided_by' ? tOr('decided.' + v, v) : k === 'country' ? countryName(v, lang.value) + ' (' + safeText(v, 4) + ')' : safeText(v, 60)
  return { key: k, label: t(CHIP_LABEL[k]), text, full: safeText(v, 500), mono: ['src_ip', 'rule_id', 'path_prefix', 'q'].includes(k) }
}))
const originOpts = computed(() => [
  { value: '', label: t('overview.filter.all'), icon: 'list' },
  { value: 'external', label: t('origin.external'), icon: 'globe' },
  { value: 'internal', label: t('origin.internal'), icon: 'network' },
])
const outcomeOpts = computed(() => [
  { value: '', label: t('overview.filter.all'), icon: 'list' },
  { value: 'blocked', label: t('outcome.blocked'), icon: 'block' },
  { value: 'logged', label: t('outcome.logged'), icon: 'page' },
])
function setQuery(patch) {
  const q = { ...route.query, ...patch }
  for (const k of Object.keys(q)) if (q[k] === '' || q[k] == null) delete q[k]
  if (q.range !== 'custom') { delete q.since; delete q.until }
  if (q.range === '24h') delete q.range      // the default
  const same = Object.keys(q).length === Object.keys(route.query).length && Object.keys(q).every((k) => route.query[k] === q[k])
  if (!same) router.push({ query: q })
}
function toggleFilter(key, value) {
  const v = String(value ?? '')
  setQuery({ [key]: filters.value[key] === v ? '' : v })
}
function clearAll() {
  const q = {}
  for (const k of ['range', 'since', 'until']) if (route.query[k]) q[k] = route.query[k]
  router.push({ query: q })
}
function eventsLink(key, value) { return { path: '/events', query: { ...filters.value, [key]: value, ...timeQ.value } } }
const countryItems = computed(() => (data.value?.by_country || []).map((c) => ({
  key: c.key, label: c.key === '?' ? t('overview.geo_unknown') : countryName(c.key, lang.value) + ' (' + c.key + ')',
  sub: t('overview.geo_sources', { n: c.sources }), values: { blocked: c.blocked, logged: c.logged },
  active: filters.value.country === c.key, to: c.key === '?' ? null : eventsLink('country', c.key) })))
const asnItems = computed(() => (data.value?.by_asn || []).map((c) => ({
  key: c.key, label: c.key === '?' ? t('overview.geo_unknown') : 'AS' + c.key + ' ' + (c.label || ''),
  sub: t('overview.geo_sources', { n: c.sources }), values: { blocked: c.blocked, logged: c.logged } })))
const error = ref(null)
const loading = ref(false)
const dimmed = ref(false)      // a filter / range change is loading: keep the old numbers, faded
let timer = null
let seq = 0

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

// Stat tiles: value, change against the same window just before, and the hourly trend.
function delta(cur, prev) {
  if (prev === undefined || prev === null) return null
  if (!prev) return cur ? { dir: 'up', text: t('overview.trend_new', { range: rangeLabel.value }) } : { dir: 'flat', text: t('overview.trend_same', { range: rangeLabel.value }) }
  const p = Math.round(((cur - prev) / prev) * 100)
  if (p === 0) return { dir: 'flat', text: t('overview.trend_same', { range: rangeLabel.value }) }
  return { dir: p > 0 ? 'up' : 'down', text: (p > 0 ? '▲ ' : '▼ ') + Math.abs(p) + '% ' + t('overview.trend_vs', { range: rangeLabel.value }) }
}
const rangeLabel = computed(() => (data.value && data.value.range === '7d' ? t('overview.prev_7d')
  : data.value && data.value.range === 'custom' ? t('overview.prev_custom') : t('overview.prev_24h')))
const statTiles = computed(() => {
  const d = data.value
  if (!d) return []
  const tl = d.timeline || []
  const ser = (f) => tl.map((b) => ({ t: b.t, v: f(b) }))
  const pv = d.previous || {}
  const T = d.totals
  return [
    { key: 'events', cls: 't-events', icon: 'list', label: t('overview.events'), value: T.events, tone: 's1', series: ser((b) => (b.blocked || 0) + (b.logged || 0)), delta: delta(T.events, pv.events) },
    { key: 'blocked', cls: 't-blocked', icon: 'block', label: t('outcome.blocked'), value: T.blocked, tone: 'blocked', series: ser((b) => b.blocked || 0), delta: delta(T.blocked, pv.blocked),
      sub: t('decided.confident') + ' ' + fmtNum(T.blocked_confident) + ' · ' + t('decided.score') + ' ' + fmtNum(T.blocked_score) },
    { key: 'logged', cls: 't-logged', icon: 'page', label: t('outcome.logged'), value: T.logged, tone: 'logged', series: ser((b) => b.logged || 0), delta: delta(T.logged, pv.logged) },
    { key: 'external', cls: 't-ext', icon: 'globe', label: t('origin.external'), value: T.external, tone: 'ext', series: ser((b) => b.external || 0), delta: delta(T.external, pv.external) },
    { key: 'internal', cls: 't-int', icon: 'network', label: t('origin.internal'), value: T.internal, tone: 'int', series: ser((b) => b.internal || 0), delta: delta(T.internal, pv.internal) },
  ]
})
const outcomeSeries = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
const outcomeParts = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), value: data.value.totals.blocked, tone: 'blocked', active: filters.value.outcome === 'blocked' },
  { key: 'logged', label: t('outcome.logged'), value: data.value.totals.logged, tone: 'logged', active: filters.value.outcome === 'logged' },
])
// blocked_confident counts confident + fallback decisions; the rest of the blocks were decided by another rule
// (picking a part filters decided_by: confident / score / other)
const reasonParts = computed(() => {
  const tt = data.value.totals
  const d = filters.value.decided_by
  return [
    { key: 'confident', label: t('decided.confident'), value: tt.blocked_confident, tone: 's1', active: d === 'confident' },
    { key: 'score', label: t('decided.score'), value: tt.blocked_score, tone: 's2', active: d === 'score' },
    { key: 'other', label: t('decided.other'), value: Math.max(0, tt.blocked - tt.blocked_confident - tt.blocked_score), tone: 's3', active: d === 'other' },
  ]
})
const originParts = computed(() => [
  { key: 'external', label: t('origin.external'), value: data.value.totals.external, tone: 's1', active: filters.value.origin === 'external' },
  { key: 'internal', label: t('origin.internal'), value: data.value.totals.internal, tone: 's2', active: filters.value.origin === 'internal' },
])
// focus sites with events get a card each (full width); the quiet ones share one line of chips
const focusBusy = computed(() => (data.value && data.value.focus || []).filter((f) => f.events > 0))
const focusQuiet = computed(() => (data.value && data.value.focus || []).filter((f) => !f.events))
// rule messages without the generic prefix of the site's own rules
const ruleItems = computed(() => (data.value && data.value.by_rule || []).map((it) => ({ ...it, msg: String(it.msg || '').replace(/^jt confident block:\s*/i, '') })))
function focusParts(f) {
  return [
    { key: 'blocked', label: t('outcome.blocked'), value: f.blocked, tone: 'blocked' },
    { key: 'logged', label: t('outcome.logged'), value: Math.max(0, f.events - f.blocked), tone: 'logged' },
  ]
}

// changed = the filters / range changed (fade the old render); a refresh keeps it as it is.
// Only the newest request may update the page.
async function load(changed) {
  const my = ++seq
  loading.value = true
  if (changed === true) dimmed.value = true
  error.value = null
  try {
    const tq = range.value === 'custom' ? { since: route.query.since, until: route.query.until || undefined } : {}
    const r = await get('/overview', { range: range.value, ...tq, ...filters.value })
    if (my === seq) data.value = r
  } catch (e) {
    if (my === seq) error.value = e
  } finally {
    if (my === seq) { loading.value = false; dimmed.value = false }
  }
}
const OWN_PATH = route.path
watch(() => route.fullPath, () => { if (route.path === OWN_PATH) load(true) })
// admins: one system check per page load; any "fail" item shows a banner
const integrityFails = ref([])
async function loadIntegrity() {
  if (!hasRole('admin')) return
  try {
    const r = await get('/system/check')
    integrityFails.value = (r.items || []).filter((i) => i.status === 'fail').map((i) => i.key)
  } catch { /* the banner is optional */ }
}

onMounted(() => { load(false); loadIntegrity(); timer = setInterval(() => { if (!document.hidden && !loading.value) load(false) }, 60000) })
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.custompanel { display: flex; flex-wrap: wrap; gap: 10px 16px; align-items: flex-end; margin: 0 0 12px; }
.custompanel .field { margin: 0; }
.custompanel p { flex-basis: 100%; margin: 0; }
.brushhint { margin: 4px 0 0; display: flex; gap: 5px; align-items: center; }
.ovfilters { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; padding: 8px 10px; }
.fhint { display: inline-flex; align-items: center; gap: 4px; }
.ovbody { display: flex; flex-direction: column; gap: 14px; transition: opacity .15s; }
.ovbody.stale { opacity: .5; pointer-events: none; }
</style>
