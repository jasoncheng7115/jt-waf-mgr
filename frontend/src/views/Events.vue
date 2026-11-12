<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('events.title') }}</h1>
      <button type="button" class="btn small ghost" :class="{ on: showGuide }" :aria-pressed="showGuide ? 'true' : 'false'" @click="toggleGuide"><Icon name="help" />{{ t('guide.how') }}</button>
      <button type="button" class="btn small ghost" :disabled="loading" @click="load(true)"><Icon name="refresh" />{{ t('common.refresh') }}</button>
    </div>
    <FlowSteps v-if="showGuide" :title="t('guide.ev.title')" :steps="flow" :note="t('guide.ev.note')" />
    <form class="filters" @submit.prevent="apply">
      <div class="field" :class="fieldClass('since')"><label for="ev-f-since">{{ t('filter.since') }}</label>
        <DatePicker id="ev-f-since" v-model="f.since" mode="datetime" :presets="sincePresets" /></div>
      <div class="field" :class="fieldClass('until')"><label for="ev-f-until">{{ t('filter.until') }}</label>
        <DatePicker id="ev-f-until" v-model="f.until" mode="datetime" :presets="untilPresets" /></div>
      <label class="field" :class="fieldClass('host')"><span>{{ t('event.host') }}</span><input v-model.trim="f.host" maxlength="255" :placeholder="t('filter.all_hosts')"></label>
      <label class="field" :class="fieldClass('path_prefix')"><span>{{ t('filter.path_prefix') }}</span><input v-model.trim="f.path_prefix" maxlength="500" placeholder="/"></label>
      <label class="field" :class="fieldClass('q')"><span>{{ t('filter.q') }}</span><input v-model.trim="f.q" maxlength="200"></label>
      <label class="field" :class="fieldClass('src_ip')"><span>{{ t('filter.src_ip') }}</span><input v-model.trim="f.src_ip" maxlength="64" placeholder="203.0.113.0/24"></label>
      <div class="field" :class="fieldClass('country')"><label for="ev-f-country">{{ t('filter.country') }}</label>
        <SelectBox id="ev-f-country" v-model="f.country" :options="countryOpts" searchable /></div>
      <label class="field" :class="fieldClass('rule_id')"><span>{{ t('filter.rule_id') }}</span><input v-model.trim="f.rule_id" inputmode="numeric" maxlength="9"></label>
      <div class="field" :class="fieldClass('outcome')"><label for="ev-f-outcome">{{ t('event.outcome') }}</label>
        <SelectBox id="ev-f-outcome" v-model="f.outcome" :options="outcomeOpts" /></div>
      <div class="field" :class="fieldClass('decided_by')"><label for="ev-f-decided">{{ t('event.decided_by') }}</label>
        <SelectBox id="ev-f-decided" v-model="f.decided_by" :options="deciderOpts" /></div>
      <div class="field" :class="fieldClass('origin')"><label for="ev-f-origin">{{ t('event.origin') }}</label>
        <SelectBox id="ev-f-origin" v-model="f.origin" :options="originOpts" /></div>
      <div class="field" :class="fieldClass('family')"><label for="ev-f-family">{{ t('event.family') }}</label>
        <SelectBox id="ev-f-family" v-model="f.family" :options="familyOpts" searchable /></div>
      <div class="actions filteractions">
        <button type="submit" class="btn primary" :class="{ 'needs-apply': dirty }"><Icon name="filter" />{{ t('filter.apply') }}</button>
        <button type="button" class="btn ghost" @click="reset"><Icon name="clear" />{{ t('filter.reset') }}</button>
        <span v-if="dirty" class="applyhint" role="status"><Icon name="warning" />{{ t('filter.not_applied') }}</span>
      </div>
    </form>
    <ErrorBox :error="error" />
    <section class="card">
      <EventTimeline :query="params()" @select="(r) => router.push({ query: { ...route.query, since: r.since, until: r.until } })" />
    </section>
    <Loading v-if="loading && !items.length" />
    <section v-if="items.length" class="card">
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.outcome_split') }}</h3><SegBar :parts="outcomeParts" :label="t('chart.outcome_split')" /></div>
        <div><h3 class="charthead">{{ t('chart.origin_split') }}</h3><SegBar :parts="originParts" :label="t('chart.origin_split')" /></div>
        <div v-if="blockedCount"><h3 class="charthead">{{ t('chart.block_reason') }}</h3><SegBar :parts="reasonParts" :label="t('chart.block_reason')" /></div>
      </div>
      <h3 class="charthead">{{ t('chart.families_loaded') }}</h3>
      <HBars :items="familyBars" :series="outcomeSeries" />
      <template v-if="countryItems.length">
        <h3 class="charthead">{{ t('map.loaded_title') }}</h3>
        <MapGrid :items="countryItems" :series="outcomeSeries" :label="t('map.loaded_title')" :active-key="route.query.country || null"
                 @pick="(it) => toggleFilter('country', it.key)" />
      </template>
      <p class="muted small">{{ t('chart.loaded_rows', { n: fmtNum(items.length) }) }}</p>
    </section>
    <EventTable :has-more="!!cursor" :loading-more="loading" @more="load(false)" table-id="events" :items="items" :page-size="50" filterable @filter="toggleFilter" />
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useFilterState } from '../filterState.js'
import EventTimeline from '../components/EventTimeline.vue'
import { get } from '../api.js'
import { lang, t } from '../i18n.js'
import { countryName, fmtNum } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import EventTable from '../components/EventTable.vue'
import Icon from '../components/Icon.vue'
import SelectBox from '../components/SelectBox.vue'
import DatePicker from '../components/DatePicker.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'
import MapGrid from '../components/charts/MapGrid.vue'
import CENTRE from '../components/charts/countryCentroids.js'

const KEYS = ['since', 'until', 'host', 'path_prefix', 'q', 'src_ip', 'country', 'rule_id', 'outcome', 'decided_by', 'origin', 'family']
const DECIDERS = ['confident', 'score', 'fallback', 'other']
const FAMILIES = ['protocol', 'lfi', 'rfi', 'rce', 'php', 'generic', 'xss', 'sqli', 'session', 'java', 'scanner', 'method', 'body', 'data_leak', 'local', 'other']

const route = useRoute()
const router = useRouter()
const f = reactive({})
const items = ref([])
const cursor = ref(null)
const loading = ref(false)
const error = ref(null)

const GUIDE_KEY = 'jtwaf.guide.events'
function readFlag(k, d) { try { const v = window.localStorage.getItem(k); return v === null ? d : v === '1' } catch { return d } }
const showGuide = ref(readFlag(GUIDE_KEY, true))
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage unavailable */ }
}
const flow = computed(() => [
  { key: 'request', label: t('guide.ev.request'), desc: t('guide.ev.request_d'), icon: 'globe' },
  { key: 'rules', label: t('guide.ev.rules'), desc: t('guide.ev.rules_d'), icon: 'shield', to: '/crs' },
  { key: 'decide', label: t('guide.ev.decide'), desc: t('guide.ev.decide_d'), icon: 'block' },
  { key: 'audit', label: t('guide.ev.audit'), desc: t('guide.ev.audit_d'), icon: 'page' },
  { key: 'collect', label: t('guide.ev.collect', { name: 'jt-waf-mgr' }), desc: t('guide.ev.collect_d'), icon: 'database' },
  { key: 'list', label: t('guide.ev.list'), desc: t('guide.ev.list_d'), icon: 'list', state: 'current' },
])

const outcomeOpts = computed(() => [
  { value: '', label: t('filter.all_outcomes') },
  { value: 'blocked', label: t('outcome.blocked'), icon: 'block' },
  { value: 'logged', label: t('outcome.logged'), icon: 'page' },
])
const deciderOpts = computed(() => [{ value: '', label: t('filter.all_deciders') }, ...DECIDERS.map((d) => ({ value: d, label: t('decided.' + d) }))])
const originOpts = computed(() => [
  { value: '', label: t('filter.all_sources') },
  { value: 'external', label: t('origin.external'), icon: 'globe' },
  { value: 'internal', label: t('origin.internal'), icon: 'network' },
])
const countryOpts = computed(() => [{ value: '', label: t('filter.all_countries') },
  ...Object.keys(CENTRE).map((cc) => ({ value: cc, label: countryName(cc, lang.value) + ' (' + cc + ')' }))
    .sort((a, b) => a.label.localeCompare(b.label, lang.value))])
const familyOpts = computed(() => [{ value: '', label: t('filter.all_families') }, ...FAMILIES.map((k) => ({ value: k, label: t('family.' + k) }))])

// date presets, local time "YYYY-MM-DDTHH:MM:SS"
function ago(ms) { return toLocalInput(new Date(Date.now() - ms).toISOString()) }
const sincePresets = computed(() => [
  { key: '1h', label: t('events.preset_1h'), value: () => ago(3600e3) },
  { key: '24h', label: t('events.preset_24h'), value: () => ago(86400e3) },
  { key: '7d', label: t('events.preset_7d'), value: () => ago(7 * 86400e3) },
  { key: '30d', label: t('events.preset_30d'), value: () => ago(30 * 86400e3) },
])
const untilPresets = computed(() => [{ key: 'now', label: t('date.now'), value: () => ago(0) }])

// charts: what has been loaded so far
const outcomeSeries = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
const blockedCount = computed(() => items.value.filter((e) => e.outcome === 'blocked').length)
const outcomeParts = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), value: blockedCount.value, tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), value: items.value.length - blockedCount.value, tone: 'logged' },
])
const originParts = computed(() => {
  const ext = items.value.filter((e) => e.origin !== 'internal').length
  return [
    { key: 'external', label: t('origin.external'), value: ext, tone: 's1' },
    { key: 'internal', label: t('origin.internal'), value: items.value.length - ext, tone: 's2' },
  ]
})
const reasonParts = computed(() => {
  const n = (ds) => items.value.filter((e) => e.outcome === 'blocked' && ds.includes(e.decided_by)).length
  return [
    { key: 'confident', label: t('decided.confident'), value: n(['confident']), tone: 's1' },
    { key: 'score', label: t('decided.score'), value: n(['score']), tone: 's2' },
    { key: 'fallback', label: t('decided.fallback') + ' / ' + t('decided.other'), value: n(['fallback', 'other', null]), tone: 's3' },
  ]
})
const familyBars = computed(() => {
  const m = new Map()
  for (const e of items.value) {
    for (const fam of (e.families && e.families.length ? e.families : ['other'])) {
      const c = m.get(fam) || { key: fam, label: t('family.' + fam), values: { blocked: 0, logged: 0 }, to: { path: '/events', query: { ...route.query, family: fam } } }
      c.values[e.outcome === 'blocked' ? 'blocked' : 'logged']++
      m.set(fam, c)
    }
  }
  return [...m.values()].sort((a, b) => (b.values.blocked + b.values.logged) - (a.values.blocked + a.values.logged)).slice(0, 10)
})

// external sources by country (GeoIP on each loaded event)
const countryItems = computed(() => {
  const m = new Map()
  for (const e of items.value) {
    const g = e.src_geo
    if (e.origin === 'internal' || !g || g.scope !== 'external' || !g.cc) continue
    const c = m.get(g.cc) || { key: g.cc, label: countryName(g.cc, lang.value) + ' (' + g.cc + ')', values: { blocked: 0, logged: 0 }, ips: new Set() }
    c.values[e.outcome === 'blocked' ? 'blocked' : 'logged']++
    c.ips.add(e.src_ip)
    m.set(g.cc, c)
  }
  return [...m.values()].map((c) => ({ ...c, sub: t('overview.geo_sources', { n: c.ips.size }), active: route.query.country === c.key }))
    .sort((a, b) => (b.values.blocked + b.values.logged) - (a.values.blocked + a.values.logged))
})

// URL holds RFC 3339; <input type=datetime-local> wants local "YYYY-MM-DDTHH:MM:SS".
function toLocalInput(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return ''
  const p = (n) => String(n).padStart(2, '0')
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds())
}
function toIso(local) {
  if (!local) return ''
  const d = new Date(local)
  if (isNaN(d)) return ''
  const off = -d.getTimezoneOffset()
  const sign = off >= 0 ? '+' : '-'
  const p = (n) => String(Math.floor(Math.abs(n))).padStart(2, '0')
  return toLocalInput(d.toISOString()) + sign + p(off / 60) + ':' + p(off % 60)
}

const { dirty, fieldClass } = useFilterState(f, () => {
  const o = {}
  for (const k of KEYS) {
    const v = typeof route.query[k] === 'string' ? route.query[k] : ''
    o[k] = (k === 'since' || k === 'until') ? toLocalInput(v) : v
  }
  return o
})
function fromQuery() {
  for (const k of KEYS) {
    const v = typeof route.query[k] === 'string' ? route.query[k] : ''
    f[k] = (k === 'since' || k === 'until') ? toLocalInput(v) : v
  }
}
function params() {
  const p = {}
  for (const k of KEYS) {
    const v = typeof route.query[k] === 'string' ? route.query[k] : ''
    if (v) p[k] = v
  }
  return p
}

async function load(fresh) {
  loading.value = true
  error.value = null
  try {
    const p = params()
    p.limit = 100
    if (!fresh && cursor.value) p.cursor = cursor.value
    const data = await get('/events', p)
    items.value = fresh ? data.items : items.value.concat(data.items)
    cursor.value = data.next_cursor || null
  } catch (e) {
    error.value = e
    if (fresh) { items.value = []; cursor.value = null }
  } finally {
    loading.value = false
  }
}

function apply() {
  const q = {}
  for (const k of KEYS) {
    let v = f[k]
    if (k === 'since' || k === 'until') v = toIso(v)
    if (v) q[k] = v
  }
  router.push({ query: q })
}
function reset() { router.push({ query: {} }) }
// a value clicked in the list becomes (or, when it already is, stops being) that filter
function toggleFilter(key, value) {
  const v = String(value ?? '')
  const q = { ...route.query }
  if (q[key] === v) delete q[key]
  else q[key] = v
  router.push({ query: q })
}

watch(() => route.query, () => { fromQuery(); load(true) }, { immediate: true })
</script>

<style scoped>
.field > label { font-weight: 500; }
.field > .selectbox, .field > .datepicker { width: 100%; }
.field > .datepicker :deep(.dp-btn) { flex: 1; }
</style>
