<!-- /traffic: request counts from the nginx access logs (per site and hour), next to the WAF's own numbers.
     Only numbers are kept: no address, no URL. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('traffic.title') }}</h1>
      <button type="button" class="btn small ghost" :disabled="loading" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
    </div>
    <p class="muted">{{ t('traffic.intro') }}</p>
    <ErrorBox :error="error" />
    <div v-if="data && !data.enabled" class="alert info" role="status">
      <Icon name="info" /> {{ t('traffic.disabled') }}
      <RouterLink v-if="isAdmin" class="btn small" to="/admin/settings#set-traffic"><Icon name="settings" />{{ t('traffic.to_settings') }}</RouterLink>
    </div>
    <div class="ovfilters" role="group" :aria-label="t('overview.filter.label')">
      <div class="seg" role="group" :aria-label="t('overview.range')">
        <button v-for="r in RANGES" :key="r.value" type="button" :class="{ on: range === r.value }" :aria-pressed="range === r.value ? 'true' : 'false'"
                @click="setQuery({ range: r.value })"><Icon :name="r.icon" />{{ r.label }}</button>
      </div>
      <div class="field trafhost"><label for="traf-host" class="sr-only">{{ t('traffic.site') }}</label>
        <SelectBox id="traf-host" :model-value="host" :options="hostOpts" searchable @update:model-value="(v) => setQuery({ host: v })" /></div>
    </div>
    <Loading v-if="loading && !data" />
    <template v-if="data && data.enabled">
      <div class="tiles">
        <component :is="st.to ? 'RouterLink' : 'div'" v-for="st in tiles" :key="st.key" class="tile stat" :class="[st.cls, { tilelink: st.to }]" :to="st.to">
          <div class="tl"><Icon :name="st.icon" />{{ st.label }}</div>
          <div class="tv">{{ st.text }}</div>
          <div class="ts"><span v-if="st.delta" class="delta" :class="st.delta.dir">{{ st.delta.text }}</span>
            <span v-if="st.sub" class="tsub">{{ st.sub }}</span></div>
          <Sparkline class="stat-spark" :values="st.series" :tone="st.tone" :label="st.label" />
        </component>
      </div>
      <p v-if="!data.totals.total" class="alert info"><Icon name="info" /> {{ data.polled_at ? t('traffic.no_data') : t('traffic.not_yet') }}</p>
      <section class="card">
        <h3 class="charthead">{{ t('traffic.chart_status') }}</h3>
        <TimeBars :data="data.series" :series="statusSeries" :label="t('traffic.chart_status')" :bucket-seconds="data.bucket_seconds" />
      </section>
      <section class="card">
        <h3 class="charthead">{{ t('traffic.chart_waf') }}</h3>
        <TimeBars :data="data.series" :series="wafSeries" :label="t('traffic.chart_waf')" :bucket-seconds="data.bucket_seconds" />
        <p class="muted small"><Icon name="info" /> {{ t('traffic.waf_note') }}</p>
      </section>
      <DataTable id="traffic-sites" :columns="cols" :rows="data.by_host" :row-key="(r) => r.host" :page-size="50">
        <template #cell-host="{ row }">
          <button type="button" class="linkbtn mono" :title="t('traffic.pick_site')" @click="setQuery({ host: row.host })"><Icon name="filter" /><TruncText :text="row.host" :max="80" mono /></button>
        </template>
        <template #cell-share="{ row }">{{ fmtPct(pct(row.blocked, row.total)) }}</template>
        <template #cell-bytes="{ row }">{{ fmtBytes(row.bytes || 0) }}</template>
      </DataTable>
      <p class="muted small">
        <Icon name="lock" /> {{ t('traffic.privacy') }}
        <span v-if="data.polled_at"> · {{ t('traffic.polled', { time: fmtTime(data.polled_at), n: data.files }) }}</span>
      </p>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { get } from '../api.js'
import { t } from '../i18n.js'
import { hasRole } from '../store.js'
import { fmtNum, fmtTime, fmtBytes } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import SelectBox from '../components/SelectBox.vue'
import TruncText from '../components/TruncText.vue'
import TimeBars from '../components/charts/TimeBars.vue'
import Sparkline from '../components/charts/Sparkline.vue'

const route = useRoute()
const router = useRouter()
const data = ref(null)
const loading = ref(false)
const error = ref(null)
const knownHosts = ref([])
const isAdmin = computed(() => hasRole('admin'))

const RANGES = computed(() => [
  { value: '24h', label: t('overview.range_24h'), icon: 'timer' },
  { value: '7d', label: t('overview.range_7d'), icon: 'calendar' },
  { value: '30d', label: t('traffic.range_30d'), icon: 'history' },
])
const range = computed(() => (['24h', '7d', '30d'].includes(route.query.range) ? route.query.range : '24h'))
const host = computed(() => String(route.query.host || ''))
const hostOpts = computed(() => [{ value: '', label: t('traffic.all_sites'), icon: 'server' }]
  .concat(knownHosts.value.map((h) => ({ value: h, label: h }))))

function setQuery(q) {
  router.replace({ query: Object.fromEntries(Object.entries({ ...route.query, ...q }).filter(([, v]) => v)) })
}

function pct(a, b) { return b ? (a * 100 / b) : 0 }
function fmtPct(v) { return (v >= 10 || v === 0 ? v.toFixed(0) : v.toFixed(v >= 1 ? 1 : 2)) + '%' }

// the same tiles as the overview: value, change against the same length of time just before, trend
const prevLabel = computed(() => ({ '24h': t('overview.prev_24h'), '7d': t('overview.prev_7d') }[range.value] || t('overview.prev_custom')))
function delta(cur, prev) {
  if (prev === undefined || prev === null) return null
  if (!prev) return cur ? { dir: 'up', text: t('overview.trend_new', { range: prevLabel.value }) } : { dir: 'flat', text: t('overview.trend_same', { range: prevLabel.value }) }
  const p = Math.round(((cur - prev) / prev) * 100)
  if (p === 0) return { dir: 'flat', text: t('overview.trend_same', { range: prevLabel.value }) }
  return { dir: p > 0 ? 'up' : 'down', text: (p > 0 ? '▲ ' : '▼ ') + Math.abs(p) + '% ' + t('overview.trend_vs', { range: prevLabel.value }) }
}
const tiles = computed(() => {
  const s = data.value.totals
  const pv = data.value.previous || {}
  const ser = (f) => (data.value.series || []).map((b) => ({ t: b.t, v: f(b) }))
  const evq = { range: range.value === '30d' ? '7d' : range.value }
  if (host.value) evq.host = host.value
  return [
    { key: 'total', cls: 't-events', icon: 'chart', label: t('traffic.total'), text: fmtNum(s.total), tone: 's1', series: ser((b) => b.total || 0),
      delta: delta(s.total, pv.total), sub: t('traffic.external_n', { n: fmtNum(s.external) }) },
    { key: 'blocked', cls: 't-blocked', icon: 'shield', label: t('traffic.waf_blocked'), text: fmtNum(s.blocked), tone: 'blocked', series: ser((b) => b.blocked || 0),
      delta: delta(s.blocked, pv.blocked), sub: t('traffic.share', { p: fmtPct(pct(s.blocked, s.total)) }), to: { path: '/events', query: Object.assign({ outcome: 'blocked' }, evq) } },
    { key: 's4xx', cls: 't-logged', icon: 'warn', label: t('traffic.s4xx'), text: fmtNum(s.s4xx), tone: 'logged', series: ser((b) => b.s4xx || 0),
      delta: delta(s.s4xx, pv.s4xx), sub: t('traffic.share', { p: fmtPct(pct(s.s4xx, s.total)) }) },
    { key: 's5xx', cls: 't-blocked', icon: 'error', label: t('traffic.s5xx'), text: fmtNum(s.s5xx), tone: 'blocked', series: ser((b) => b.s5xx || 0),
      delta: delta(s.s5xx, pv.s5xx), sub: t('traffic.share', { p: fmtPct(pct(s.s5xx, s.total)) }) },
    { key: 'bytes', cls: 't-ext', icon: 'send', label: t('traffic.bytes'), text: fmtBytes(s.bytes), tone: 'ext', series: ser((b) => b.bytes || 0),
      delta: delta(s.bytes, pv.bytes), sub: t('traffic.s444_429', { a: fmtNum(s.s444), b: fmtNum(s.s429) }) },
  ]
})
const statusSeries = computed(() => [
  { key: 's2xx', label: '2xx', tone: 's1' },
  { key: 's3xx', label: '3xx', tone: 's3' },
  { key: 's4xx', label: '4xx', tone: 'warning' },
  { key: 's5xx', label: '5xx', tone: 'critical' },
  { key: 'other', label: t('traffic.other_status'), tone: 'muted' },
])
const wafSeries = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
const num = (k, label) => ({ key: k, label, align: 'num', nowrap: true, value: (r) => r[k] || 0 })
const cols = computed(() => [
  { key: 'host', label: t('traffic.site'), required: true, value: (r) => r.host },
  num('total', t('traffic.total')),
  num('external', t('traffic.external')),
  num('s2xx', '2xx'), num('s3xx', '3xx'), num('s4xx', '4xx'), num('s5xx', '5xx'),
  num('s403', '403'), num('s444', '444'), num('s429', '429'),
  num('blocked', t('traffic.waf_blocked')),
  { key: 'share', label: t('traffic.block_share'), align: 'num', nowrap: true, value: (r) => pct(r.blocked, r.total), text: (r) => fmtPct(pct(r.blocked, r.total)) },
  { key: 'bytes', label: t('traffic.bytes'), align: 'num', nowrap: true, value: (r) => r.bytes || 0, text: (r) => fmtBytes(r.bytes || 0) },
])

async function load() {
  loading.value = true
  error.value = null
  try {
    const p = { range: range.value }
    if (host.value) p.host = host.value
    data.value = await get('/traffic', p)
    if (!host.value) knownHosts.value = data.value.by_host.map((r) => r.host).sort()
    else if (!knownHosts.value.includes(host.value)) knownHosts.value = [...knownHosts.value, host.value].sort()
  } catch (e) {
    error.value = e
  } finally {
    loading.value = false
  }
}
watch(() => [range.value, host.value], load, { immediate: true })
</script>
