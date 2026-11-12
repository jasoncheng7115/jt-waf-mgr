<!-- Compliance controls computed from the live configuration (ISO 27001, Taiwan CSMA baseline, OWASP). -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('compliance.title') }}</h1>
      <button class="btn small ghost" type="button" :aria-expanded="showGuide ? 'true' : 'false'" @click="toggleGuide">
        <Icon name="help" />{{ showGuide ? t('guide.hide') : t('guide.show') }}</button>
      <button class="btn small" type="button" :disabled="!data" @click="download"><Icon name="download" />{{ t('common.download_json') }}</button>
      <button class="btn small ghost" type="button" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
    </div>
    <FlowSteps v-if="showGuide" :title="t('guide.compliance.title')" :steps="readFlow" :note="t('guide.compliance.note')" />
    <ErrorBox :error="error" />
    <Loading v-if="!data && !error" />
    <template v-if="data">
      <section class="card">
        <p>
          <template v-if="data.level">{{ t('compliance.level', { level: t('compliance.lv.' + data.level) }) }}</template>
          <template v-else>{{ t('compliance.level_unset') }}</template>
          <span class="muted small"> {{ t('compliance.level_hint') }}</span>
        </p>
        <div class="seg" role="group" :aria-label="t('compliance.filter')">
          <button v-for="f in FILTERS" :key="f" type="button" :class="{ on: filter === f }" :aria-pressed="filter === f ? 'true' : 'false'" @click="filter = f">
            <Icon :name="FILTER_ICON[f]" />{{ t('compliance.f.' + f) }} <span class="count">{{ f === 'all' ? data.controls.length : counts[f] || 0 }}</span>
          </button>
        </div>
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.compliance.status') }}</h3><SegBar :parts="statusParts" :label="t('chart.compliance.status')" /></div>
          <div><h3 class="charthead">{{ t('chart.compliance.frameworks') }}</h3><HBars :items="frameworkItems" :series="statusSeries" /></div>
        </div>
        <p class="muted small">{{ t('compliance.generated', { at: fmtMinute(data.generated_at), node: safeText(data.node_id, 60), version: safeText(data.version, 20) }) }}</p>
      </section>

      <section v-for="c in shown" :key="c.id" class="card control" :class="'st-' + c.status">
        <div class="cardhead">
          <h2><Icon name="shield" /> {{ tOr('compliance.ctl.' + c.id + '.title', c.id) }}</h2>
          <span class="badge" :class="BADGE[c.status] || 'b-logged'">{{ t('compliance.st.' + c.status) }}</span>
        </div>
        <p>{{ tOr('compliance.ctl.' + c.id + '.desc', '') }}</p>
        <div class="refs">
          <span v-for="r in c.iso" :key="'i' + r" class="chip mono" :title="'ISO/IEC 27001:2022 ' + r">ISO {{ safeText(r, 20) }}</span>
          <span v-for="r in c.tw" :key="'t' + r" class="chip" :title="t('compliance.tw_framework')">{{ tOr('compliance.tw.' + r, r) }}</span>
          <span v-for="r in c.owasp" :key="'o' + r" class="chip" :title="'OWASP Top 10:2025'">{{ safeText(r, 10) }} {{ tOr('compliance.owasp.' + r, '') }}</span>
        </div>
        <div v-if="c.needs && c.needs.length" class="needs">
          <span class="small">{{ t('compliance.needs') }}</span>
          <ul class="plainlist"><li v-for="n in c.needs" :key="n" class="mono small breakall">{{ safeText(n, 300) }}</li></ul>
        </div>
        <div v-if="c.values && Object.keys(c.values).length" class="facts">
          <div v-for="(v, k) in c.values" :key="k" class="fact">
            <div class="fact-k" :title="k">{{ tOr('compliance.val.' + k, k) }}</div>
            <div class="fact-v">
              <span v-if="typeof v === 'boolean'" class="badge" :class="v ? 'b-ok' : 'b-warn'"><Icon :name="v ? 'check' : 'warning'" /> {{ v ? t('common.yes') : t('common.no') }}</span>
              <span v-else class="mono breakall">{{ valueText(v) }}</span>
            </div>
          </div>
        </div>
      </section>
      <p v-if="!shown.length" class="empty">{{ t('common.no_data') }}</p>
      <p class="muted small">{{ t('compliance.footer') }}</p>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { get } from '../api.js'
import { t, tOr } from '../i18n.js'
import { safeText, fmtMinute, downloadText, stamp } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'

const BADGE = { met: 'b-ok', partial: 'b-warn', gap: 'b-blocked', organisational: 'b-logged' }
const CONFIG_PATH = '/etc/jt-waf-mgr/config.toml'
const FILTERS = ['all', 'gap', 'partial', 'organisational', 'met']
const FILTER_ICON = { all: 'list', gap: 'alert', partial: 'warning', organisational: 'users', met: 'check' }
const STATUS = ['met', 'partial', 'gap', 'organisational']
const TONE = { met: 'good', partial: 'warning', gap: 'critical', organisational: 'muted' }

const GUIDE_KEY = 'jtwaf.guide.compliance'
const showGuide = ref(readGuide())
function readGuide() { try { return window.localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage blocked */ }
}

const data = ref(null)
const error = ref(null)
const filter = ref('all')

const counts = computed(() => {
  const c = {}
  for (const x of (data.value && data.value.controls) || []) c[x.status] = (c[x.status] || 0) + 1
  return c
})
// How to read the page (compliance.controls()).
const readFlow = computed(() => [
  { key: 'level', icon: 'settings', label: t('guide.compliance.level'),
    desc: data.value && data.value.level ? t('guide.compliance.level_d_set', { level: t('compliance.lv.' + data.value.level) }) : t('guide.compliance.level_d_unset'),
    state: data.value ? (data.value.level ? 'done' : 'current') : 'todo' },
  { key: 'live', icon: 'search', label: t('guide.compliance.live'), desc: t('guide.compliance.live_d') },
  { key: 'status', icon: 'list', label: t('guide.compliance.status'), desc: t('guide.compliance.status_d') },
  { key: 'needs', icon: 'tool', label: t('guide.compliance.needs'), desc: t('guide.compliance.needs_d') },
  { key: 'fix', icon: 'refresh', label: t('guide.compliance.fix'), desc: t('guide.compliance.fix_d', { path: CONFIG_PATH }) },
])
const statusParts = computed(() => STATUS.map((k) => ({ key: k, label: t('compliance.st.' + k), value: counts.value[k] || 0, tone: TONE[k] })))
const statusSeries = computed(() => STATUS.map((k) => ({ key: k, label: t('compliance.st.' + k), tone: TONE[k] })))
// One bar per framework: how the controls that cite it stand.
const frameworkItems = computed(() => {
  const all = (data.value && data.value.controls) || []
  return [['iso', 'ISO/IEC 27001:2022'], ['tw', t('chart.compliance.tw')], ['owasp', 'OWASP Top 10:2025']].map(([k, label]) => {
    const values = {}
    for (const st of STATUS) values[st] = all.filter((c) => (c[k] || []).length && c.status === st).length
    return { key: k, label, values }
  })
})
const shown = computed(() => {
  const all = (data.value && data.value.controls) || []
  return filter.value === 'all' ? all : all.filter((c) => c.status === filter.value)
})

function valueText(v) {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'boolean') return v ? t('common.yes') : t('common.no')
  if (Array.isArray(v)) return v.map((x) => safeText(typeof x === 'object' ? JSON.stringify(x) : x, 100)).join(', ')
  if (typeof v === 'object') return safeText(JSON.stringify(v), 300)
  return safeText(v, 300)
}

function download() {
  downloadText('jt-waf-mgr-compliance-' + stamp() + '.json', JSON.stringify(data.value, null, 1), 'application/json')
}

async function load() {
  error.value = null
  try { data.value = await get('/compliance') } catch (e) { error.value = e }
}
onMounted(load)
</script>

<style scoped>
.facts { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(240px, 100%), 1fr)); gap: 8px; margin-top: 10px; }
.fact { border: 1px solid var(--border); border-radius: 6px; padding: 7px 10px; background: var(--panel-2); min-width: 0; }
.fact-k { color: var(--muted); font-size: 12.5px; margin-bottom: 3px; }
.fact-v { font-size: 14px; font-weight: 600; }
.fact-v .badge { font-weight: 600; }
</style>
