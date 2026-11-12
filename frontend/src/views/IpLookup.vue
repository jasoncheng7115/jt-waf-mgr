<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('lookup.title') }}</h1>
      <button type="button" class="btn small ghost" :class="{ on: showGuide }" :aria-pressed="showGuide ? 'true' : 'false'" @click="toggleGuide"><Icon name="help" />{{ t('guide.how') }}</button>
    </div>
    <FlowSteps v-if="showGuide" :title="t('guide.ip.title')" :steps="flow" :note="t('guide.ip.note')" />
    <form class="filters inline" @submit.prevent="go">
      <label class="field grow"><span>{{ t('lookup.ip') }}</span><input v-model.trim="input" maxlength="64" placeholder="203.0.113.7" required></label>
      <div class="actions"><button class="btn primary" type="submit"><Icon name="search" />{{ t('lookup.submit') }}</button></div>
    </form>
    <ErrorBox :error="error" />
    <Loading v-if="loading" />
    <template v-if="data">
      <section class="card">
        <h2 class="mono">{{ safeText(data.ip, 45) }} <OriginBadge :origin="data.origin" /> <GeoTag :geo="data.geo" full />
          <span v-if="data.blocked_now" class="badge b-blocked">{{ t('lookup.blocked_now') }}</span></h2>
        <div class="tiles">
          <div class="tile"><div class="tl">{{ t('lookup.d7_events') }}</div><div class="tv">{{ fmtNum(data.d7.events) }}</div><div class="ts">{{ t('outcome.blocked') }} {{ fmtNum(data.d7.blocked) }}</div></div>
          <div class="tile"><div class="tl">{{ t('lookup.d30_events') }}</div><div class="tv">{{ fmtNum(data.d30.events) }}</div><div class="ts">{{ t('outcome.blocked') }} {{ fmtNum(data.d30.blocked) }}</div></div>
          <div class="tile"><div class="tl">{{ t('lookup.first_seen') }}</div><div class="tv small">{{ fmtTime(data.first_seen) }}</div></div>
          <div class="tile"><div class="tl">{{ t('lookup.last_seen') }}</div><div class="tv small">{{ fmtTime(data.last_seen) }}</div></div>
        </div>
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.ip_split', { period: t('lookup.d7_events') }) }}</h3><SegBar :parts="split(data.d7)" :label="t('lookup.d7_events')" /></div>
          <div><h3 class="charthead">{{ t('chart.ip_split', { period: t('lookup.d30_events') }) }}</h3><SegBar :parts="split(data.d30)" :label="t('lookup.d30_events')" /></div>
        </div>
        <div class="actions"><RouterLink class="btn small" :to="{ path: '/events', query: { src_ip: data.ip } }"><Icon name="list" />{{ t('lookup.view_events') }}</RouterLink></div>
      </section>
      <div class="cols2">
        <section class="card">
          <h2>{{ t('lookup.hosts') }} <span class="count">{{ data.hosts.length }}</span></h2>
          <HBars :items="hostBars" :series="countSeries" />
        </section>
        <section class="card">
          <h2>{{ t('lookup.rules') }} <span class="count">{{ data.rules.length }}</span></h2>
          <HBars :items="ruleBars" :series="countSeries" mono />
        </section>
      </div>
    </template>
  </div>
</template>

<script setup>
import GeoTag from '../components/GeoTag.vue'
import { ref, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { get } from '../api.js'
import { t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { safeText, fmtNum, fmtTime } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import OriginBadge from '../components/OriginBadge.vue'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'

const props = defineProps({ ip: { type: String, default: '' } })
const router = useRouter()
const input = ref(props.ip || '')
const data = ref(null)
const error = ref(null)
const loading = ref(false)

const GUIDE_KEY = 'jtwaf.guide.lookup'
function readFlag(k, d) { try { const v = window.localStorage.getItem(k); return v === null ? d : v === '1' } catch { return d } }
const showGuide = ref(readFlag(GUIDE_KEY, true))
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage unavailable */ }
}
// the investigation, with where this address stands once it has been looked up
const flow = computed(() => {
  const d = data.value
  const seen = !!(d && d.d30.events)
  const ip = d ? d.ip : ''
  const canPropose = hasRole('operator')
  return [
    { key: 'look', label: t('guide.ip.look'), desc: t('guide.ip.look_d'), icon: 'search', state: d ? 'done' : 'current' },
    { key: 'events', label: t('guide.ip.events'), desc: t('guide.ip.events_d'), icon: 'list', state: seen ? 'current' : 'todo',
      to: ip ? { path: '/events', query: { src_ip: ip } } : '/events' },
    { key: 'rules', label: t('guide.ip.rules'), desc: t('guide.ip.rules_d'), icon: 'shield', to: '/rules' },
    { key: 'fp', label: t('guide.ip.fp'), desc: t('guide.ip.fp_d'), icon: 'add',
      to: canPropose ? { path: '/changes/new', query: { kind: 'exclusion' } } : null },
    { key: 'attack', label: t('guide.ip.attack'), desc: t('guide.ip.attack_d'), icon: 'block',
      to: canPropose ? { path: '/changes/new', query: { kind: 'confident_block' } } : null },
  ]
})

const countSeries = computed(() => [{ key: 'events', label: t('chart.hits'), tone: 's1' }])
function split(p) {
  return [
    { key: 'blocked', label: t('outcome.blocked'), value: p.blocked || 0, tone: 'blocked' },
    { key: 'logged', label: t('outcome.logged'), value: Math.max(0, (p.events || 0) - (p.blocked || 0)), tone: 'logged' },
  ]
}
const hostBars = computed(() => (data.value ? data.value.hosts : []).map((h) => ({
  key: String(h.key), label: String(h.key), values: { events: h.events || 0 },
  to: { path: '/events', query: { src_ip: data.value.ip, host: h.key } },
})))
const ruleBars = computed(() => (data.value ? data.value.rules : []).map((r) => ({
  key: String(r.key), label: safeText(r.key, 12) + (r.family ? ' · ' + tOr('family.' + r.family, r.family) : ''),
  sub: r.msg ? safeText(r.msg, 120) : null, values: { events: r.events || 0 }, to: '/rules/' + encodeURIComponent(r.key),
})))

function go() {
  if (input.value) router.push('/lookup/' + encodeURIComponent(input.value))
}
async function load() {
  data.value = null
  error.value = null
  if (!props.ip) return
  input.value = props.ip
  loading.value = true
  try { data.value = await get('/lookups/ip/' + encodeURIComponent(props.ip)) } catch (e) { error.value = e } finally { loading.value = false }
}
watch(() => props.ip, load, { immediate: true })
</script>
