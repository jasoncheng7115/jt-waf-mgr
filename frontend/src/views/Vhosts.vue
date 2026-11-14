<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('vhosts.title') }}</h1>
      <span class="badge b-int"><Icon name="lock" />{{ t('rules.readonly') }}</span>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="loading" />
    <div v-if="warnings.length" class="alert warn">
      <div v-for="(w, i) in warnings" :key="i">{{ safeText(w, 500) }}</div>
    </div>
    <section v-if="items.length" class="card">
      <p class="muted small">{{ t('vhosts.summary', { total: items.length, on: count('on'), block: count('block'), off: count('off') }) }}</p>
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.waf_modes') }}</h3><SegBar :parts="modeParts" :label="t('chart.waf_modes')" /></div>
      </div>
      <div class="cols2">
        <div>
          <h3 class="charthead">{{ t('chart.site_events') }}</h3>
          <HBars :items="siteBars" :series="outcomeSeries" mono />
        </div>
        <div>
          <h3 class="charthead">{{ t('chart.bypass_per_block') }}</h3>
          <HBars :items="bypassBars" mono />
        </div>
      </div>
    </section>
    <DataTable id="vhosts" :columns="cols" :rows="items" :row-key="(v) => v.file + ':' + v.line" :page-size="50">
      <template #cell-server_names="{ row }">
        <div v-for="n in row.server_names" :key="n" class="mono"><TruncText :text="n" :max="100" /></div>
        <div class="sub mono" :title="safeText(row.file, 500)">{{ shortFile(row.file) }}:{{ row.line }} · {{ (row.listen || []).map((l) => safeText(l, 40)).join(', ') }}</div>
      </template>
      <template #cell-waf="{ row }">
        <span class="badge" :class="wafCls(row.waf)">{{ t('waf.' + (row.waf || 'unknown')) }}</span>
        <div v-if="row.inline_rule_ids && row.inline_rule_ids.length" class="sub mono">
          {{ t('vhosts.inline_rules') }}: <RouterLink v-for="id in row.inline_rule_ids" :key="id" :to="'/rules/' + id" class="idlink">{{ id }}</RouterLink>
        </div>
      </template>
      <template #cell-countries="{ row }">
        <div class="cocell">
        <div v-for="c in row.countries || []" :key="'r' + c.item_id" class="corow">
          <span class="badge" :class="!c.enabled ? 'b-logged' : c.mode === 'allow' ? 'b-ok' : 'b-blocked'">{{ t('vhosts.country_mode.' + (c.mode === 'deny' ? 'deny' : 'allow')) }}</span>
          <span v-for="cc in c.countries" :key="cc" class="mono cocode" :title="countryName(cc)">{{ cc }}</span>
          <span v-if="!c.enabled" class="muted small">{{ t('managed.disabled') }}</span>
          <RouterLink v-if="c.rule_id" :to="'/rules/' + c.rule_id" class="idlink mono small">{{ c.rule_id }}</RouterLink>
          <RouterLink v-if="canPropose" class="btn small ghost" :to="{ path: '/changes/new', query: { item: c.item_id } }"><Icon name="edit" />{{ t('managed.modify') }}</RouterLink>
        </div>
        <div v-for="c in row.country_changes || []" :key="'c' + c.change_id + '-' + (c.item_id || '')" class="corow">
          <RouterLink :to="'/changes/' + c.change_id" class="badge b-warn">{{ t('vhosts.country_pending', { id: c.change_id }) }}</RouterLink>
          <span class="small muted">{{ t('op.' + (c.op || 'add')) }}</span>
          <span v-for="cc in c.countries" :key="cc" class="mono cocode" :title="countryName(cc)">{{ cc }}</span>
        </div>
        <!-- a country rule is a ModSecurity rule: it does nothing where ModSecurity is off -->
        <p v-if="row.waf === 'off' && (row.countries || []).length" class="small warn">{{ t('vhosts.country_waf_off_rule') }}</p>
        <p v-else-if="row.waf !== 'off' && (row.countries || []).length && (row.bypass || []).length" class="small warn">
          {{ t('vhosts.country_bypass', { n: row.bypass.length }) }}</p>
        <span v-if="row.waf === 'off' && !(row.countries || []).length" class="muted small">{{ t('vhosts.country_waf_off') }}</span>
        <RouterLink v-else-if="canPropose && countryHost(row) && !(row.countries || []).length" class="btn small ghost"
                    :to="{ path: '/changes/new', query: { kind: 'country', host: countryHost(row) } }"><Icon name="add" />{{ t('vhosts.country_add') }}</RouterLink>
        <span v-else-if="!(row.countries || []).length && !(row.country_changes || []).length" class="muted">—</span>
        </div>
      </template>
      <template #cell-bypass="{ row }">
        <div v-for="b in row.bypass || []" :key="b.file + b.line" class="mono" :title="safeText(b.file, 500) + ':' + b.line"><TruncText :text="b.location" :max="120" mono /></div>
        <span v-if="!(row.bypass || []).length" class="muted">—</span>
      </template>
      <template #cell-body_limit="{ row }"><span class="mono">{{ row.body_limit ? safeText(row.body_limit, 20) : t('vhosts.default') }}</span></template>
      <template #cell-restrictions="{ row }">
        <div v-for="(r, i) in row.restrictions || []" :key="i" class="mono small"><TruncText :text="r" :max="160" mono /></div>
        <span v-if="!(row.restrictions || []).length" class="muted">—</span>
      </template>
      <template #cell-upstreams="{ row }"><div v-for="u in row.upstreams || []" :key="u" class="mono small"><TruncText :text="u" :max="100" mono /></div></template>
    </DataTable>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { get } from '../api.js'
import { t, lang } from '../i18n.js'
import { safeText } from '../util.js'
import { hasRole } from '../store.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import TruncText from '../components/TruncText.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'

const items = ref([])
const warnings = ref([])
const loading = ref(false)
const error = ref(null)
const byHost = ref([])        // /overview?range=7d by_host: the 15 busiest sites

const cols = computed(() => [
  { key: 'server_names', label: t('vhosts.server_names'), required: true, value: (v) => (v.server_names || [])[0] || '~',
    text: (v) => (v.server_names || []).join(' ') + ' ' + (v.file || '') + ' ' + (v.listen || []).join(' ') },
  { key: 'waf', label: t('vhosts.waf'), nowrap: true, value: (v) => t('waf.' + (v.waf || 'unknown')),
    text: (v) => t('waf.' + (v.waf || 'unknown')) + ' ' + (v.inline_rule_ids || []).join(' ') },
  { key: 'countries', label: t('vhosts.countries'), value: (v) => (v.countries || []).length,
    text: (v) => (v.countries || []).concat(v.country_changes || []).map((c) => t('vhosts.country_mode.' + (c.mode === 'deny' ? 'deny' : 'allow')) + ' ' + (c.countries || []).join(' ')).join(' ') },
  { key: 'bypass', label: t('vhosts.bypass'), value: (v) => (v.bypass || []).length, text: (v) => (v.bypass || []).map((b) => b.location).join(' ') },
  { key: 'body_limit', label: t('vhosts.body_limit'), text: (v) => v.body_limit || t('vhosts.default') },
  { key: 'restrictions', label: t('vhosts.restrictions'), value: (v) => (v.restrictions || []).length, text: (v) => (v.restrictions || []).join(' ') },
  { key: 'realip', label: t('vhosts.realip'), value: (v) => (v.realip ? t('common.yes') : t('common.no')) },
  { key: 'upstreams', label: t('vhosts.upstreams'), value: (v) => (v.upstreams || []).join(' ') },
])

const canPropose = computed(() => hasRole('operator'))
// country names in the interface language from the browser (as on the new change page)
const regionNames = computed(() => { try { return new Intl.DisplayNames([{ 'zh-TW': 'zh-Hant-TW', ja: 'ja', en: 'en' }[lang.value] || 'en'], { type: 'region' }) } catch { return null } })
function countryName(c) { try { return (regionNames.value && regionNames.value.of(c)) || c } catch { return c } }
// the site a new country rule is for: the first plain name of the server block (not "_" or a regular expression)
function countryHost(v) {
  return (v.server_names || []).find((n) => n && n !== '_' && !n.startsWith('~') && /^(\*\.)?[a-z0-9.-]+$/i.test(n)) || ''
}
function count(w) { return items.value.filter((v) => v.waf === w).length }
function wafCls(w) { return w === 'block' ? 'b-blocked' : w === 'on' ? 'b-ok' : w === 'off' ? 'b-warn' : 'b-int' }
function shortFile(p) {
  const s = String(p || '')
  const i = s.lastIndexOf('/')
  return safeText(i >= 0 ? s.slice(i + 1) : s, 120)
}

const modeParts = computed(() => [
  { key: 'block', label: t('waf.block'), value: count('block'), tone: 's1' },
  { key: 'on', label: t('waf.on'), value: count('on'), tone: 's2' },
  { key: 'off', label: t('waf.off'), value: count('off'), tone: 'warning' },
  { key: 'unknown', label: t('waf.unknown'), value: items.value.filter((v) => !['block', 'on', 'off'].includes(v.waf)).length, tone: 'muted' },
])
const outcomeSeries = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
const siteBars = computed(() => byHost.value.map((h) => ({
  key: String(h.key), label: String(h.key), values: { blocked: h.blocked || 0, logged: h.logged || 0 },
  to: { path: '/events', query: { host: h.key } },
})))
const bypassBars = computed(() => items.value.filter((v) => (v.bypass || []).length)
  .map((v) => ({ key: v.file + ':' + v.line, label: (v.server_names || [])[0] || shortFile(v.file), values: { value: v.bypass.length } }))
  .sort((a, b) => b.values.value - a.values.value).slice(0, 15))

onMounted(async () => {
  loading.value = true
  try {
    const data = await get('/vhosts')
    items.value = data.items || []
    warnings.value = data.warnings || []
  } catch (e) { error.value = e } finally { loading.value = false }
  try { byHost.value = (await get('/overview', { range: '7d' })).by_host || [] } catch { byHost.value = [] }
})
</script>

<style scoped>
.cocell { min-width: 230px; }
.cocell .warn { margin: 2px 0 0; }
.corow { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 6px; margin-bottom: 4px; }
.cocode { font-size: 12px; }
</style>

<style scoped>
.badge .icon { margin-right: 3px; vertical-align: -0.25em; }
</style>
