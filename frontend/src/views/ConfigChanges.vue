<!-- nginx / ModSecurity / CRS file fingerprints: every change, attributed to jt-waf-mgr or outside. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('cfgchg.title') }}</h1>
      <button class="btn small ghost" type="button" :aria-expanded="showGuide ? 'true' : 'false'" @click="toggleGuide">
        <Icon name="help" />{{ showGuide ? t('guide.hide') : t('guide.show') }}</button>
      <RouterLink v-if="id" class="btn small ghost" to="/config-changes"><Icon name="back" />{{ t('cfgchg.all') }}</RouterLink>
      <RouterLink class="btn small ghost" to="/versions"><Icon name="versions" />{{ t('nav.versions') }}</RouterLink>
    </div>
    <p class="muted">{{ t('cfgchg.intro') }}</p>
    <FlowSteps v-if="showGuide" :title="t('guide.cfgchg.title')" :steps="flow" :note="t('guide.cfgchg.note')" />
    <ErrorBox :error="error" />

    <template v-if="id">
      <Loading v-if="!snap && !error" />
      <section v-if="snap" class="card">
        <div class="cardhead">
          <h2>#{{ snap.id }} · {{ fmtMinute(snap.ts) }}</h2>
          <span class="badge" :class="CAUSE[snap.cause] || 'b-logged'">{{ tOr('cfgchg.cause.' + snap.cause, snap.cause) }}</span>
        </div>
        <p class="small">{{ t('cfgchg.digest') }}: <HashText :value="snap.digest" :len="16" /></p>
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.cfgchg.this_change') }}</h3><SegBar :parts="kindParts(snap)" :label="t('chart.cfgchg.this_change')" /></div>
        </div>
        <ChangedPaths :changes="snap.changes" />
        <h3>{{ t('cfgchg.files', { n: fileRows.length }) }}</h3>
        <DataTable id="cfgchg-files" :columns="fileCols" :rows="fileRows" row-key="path" :row-class="(r) => ({ hl: touched.has(r.path) })" :default-sort="{ key: 'path', dir: 1 }">
          <template #cell-path="{ row }"><span class="mono breakall">{{ safeText(row.path, 400) }}</span></template>
          <template #cell-touched="{ row }"><span v-if="touched.has(row.path)" class="badge b-warn">{{ t('cfgchg.touched') }}</span></template>
          <template #cell-hash="{ row }"><HashText v-if="row.hash" :value="row.hash" :len="16" /><span v-else class="badge b-warn">{{ t('cfgchg.unreadable') }}</span></template>
        </DataTable>
      </section>
    </template>

    <template v-else>
      <Loading v-if="loading && !items.length" />
      <section v-if="items.length" class="card">
        <h2>{{ t('chart.cfgchg.loaded', { n: fmtNum(items.length) }) }}</h2>
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.cfgchg.causes') }}</h3><SegBar :parts="causeParts" :label="t('chart.cfgchg.causes')" /></div>
          <div><h3 class="charthead">{{ t('chart.cfgchg.per_day') }}</h3><HBars :items="perDay" :series="causeSeries" /></div>
        </div>
      </section>
      <DataTable id="cfgchg-list" :columns="cols" :rows="items" :default-sort="{ key: 'id', dir: -1 }" :empty="t('cfgchg.none')"
                 :row-class="(c) => ({ hl: open === c.id })">
        <template #cell-id="{ row }"><RouterLink class="mono" :to="'/config-changes/' + row.id">{{ row.id }}</RouterLink></template>
        <template #cell-ts="{ row }">{{ fmtMinute(row.ts) }}</template>
        <template #cell-cause="{ row }"><span class="badge" :class="CAUSE[row.cause] || 'b-logged'">{{ tOr('cfgchg.cause.' + row.cause, row.cause) }}</span></template>
        <template #cell-paths="{ row }">
          <button v-if="n(row, 'added') + n(row, 'removed') + n(row, 'changed')" type="button" class="btn small ghost"
                  :aria-pressed="open === row.id ? 'true' : 'false'" @click="open = open === row.id ? null : row.id">
            <Icon :name="open === row.id ? 'hide' : 'show'" />{{ open === row.id ? t('cfgchg.hide_paths') : t('cfgchg.show_paths') }}</button>
        </template>
        <template #footer><LoadMore :cursor="cursor" :busy="loading" @more="load(false)" /></template>
      </DataTable>
      <section v-if="openItem" class="card">
        <div class="cardhead">
          <h2>#{{ openItem.id }} · {{ fmtMinute(openItem.ts) }}</h2>
          <button class="btn small ghost" type="button" @click="open = null"><Icon name="close" />{{ t('common.dismiss') }}</button>
        </div>
        <ChangedPaths :changes="openItem.changes" />
      </section>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, defineComponent, h } from 'vue'
import { get } from '../api.js'
import { t, tOr } from '../i18n.js'
import { safeText, fmtMinute, fmtNum, isoToDateInput } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import LoadMore from '../components/LoadMore.vue'
import HashText from '../components/HashText.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'

const props = defineProps({ id: { type: String, default: '' } })
const CAUSE = { outside: 'b-warn', 'jt-waf-mgr': 'b-int', baseline: 'b-logged' }

// Lists of added / removed / changed paths (render functions: text nodes only).
const ChangedPaths = defineComponent({
  props: { changes: { type: Object, default: () => ({}) } },
  setup(p) {
    return () => h('div', { class: 'chgpaths' }, ['added', 'removed', 'changed'].filter((k) => (p.changes[k] || []).length).map((k) =>
      h('div', { key: k }, [
        h('div', { class: 'small muted' }, t('cfgchg.' + k) + ' (' + p.changes[k].length + ')'),
        h('ul', { class: 'plainlist small' }, p.changes[k].map((x) => h('li', { class: 'mono breakall', key: x }, safeText(x, 400)))),
      ])))
  },
})

const items = ref([])
const cursor = ref(null)
const loading = ref(false)
const error = ref(null)
const open = ref(null)
const snap = ref(null)

const touched = computed(() => {
  const c = (snap.value && snap.value.changes) || {}
  return new Set([...(c.added || []), ...(c.changed || [])])
})

function n(c, k) { return ((c.changes || {})[k] || []).length }

const GUIDE_KEY = 'jtwaf.guide.cfgchg'
const showGuide = ref(readGuide())
function readGuide() { try { return window.localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage blocked */ }
}
// compliance.Monitor.check_config() / _cause()
const flow = computed(() => [
  { key: 'scan', icon: 'fingerprint', label: t('guide.cfgchg.scan'), desc: t('guide.cfgchg.scan_d') },
  { key: 'compare', icon: 'change', label: t('guide.cfgchg.compare'), desc: t('guide.cfgchg.compare_d') },
  { key: 'cause', icon: 'search', label: t('guide.cfgchg.cause'), desc: t('guide.cfgchg.cause_d') },
  { key: 'record', icon: 'history', label: t('guide.cfgchg.record'), desc: t('guide.cfgchg.record_d') },
  { key: 'warn', icon: 'warning', label: t('guide.cfgchg.warn'), desc: t('guide.cfgchg.warn_d') },
])

const CAUSES = ['outside', 'jt-waf-mgr', 'baseline']
const CAUSE_TONE = { outside: 's2', 'jt-waf-mgr': 's1', baseline: 'muted' }
const cols = computed(() => [
  { key: 'id', label: '#', align: 'num', required: true },
  { key: 'ts', label: t('event.time'), nowrap: true, text: (c) => fmtMinute(c.ts) },
  { key: 'cause', label: t('cfgchg.cause_h'), value: (c) => tOr('cfgchg.cause.' + c.cause, c.cause) },
  { key: 'added', label: t('cfgchg.added'), align: 'num', value: (c) => n(c, 'added') },
  { key: 'removed', label: t('cfgchg.removed'), align: 'num', value: (c) => n(c, 'removed') },
  { key: 'changed', label: t('cfgchg.changed'), align: 'num', value: (c) => n(c, 'changed') },
  { key: 'paths', label: t('cfgchg.path'), sortable: false, text: (c) => ['added', 'removed', 'changed'].flatMap((k) => (c.changes || {})[k] || []).join(' ') },
])
const openItem = computed(() => items.value.find((c) => c.id === open.value) || null)
const causeSeries = computed(() => CAUSES.map((k) => ({ key: k, label: tOr('cfgchg.cause.' + k, k), tone: CAUSE_TONE[k] })))
const causeParts = computed(() => CAUSES.map((k) => ({ key: k, label: tOr('cfgchg.cause.' + k, k), value: items.value.filter((c) => c.cause === k).length, tone: CAUSE_TONE[k] })))
// Snapshots per day (local date) over the loaded rows, newest first, at most 14 days that had changes.
const perDay = computed(() => {
  const m = new Map()
  for (const c of items.value) {
    const d = isoToDateInput(c.ts)
    if (!d) continue
    const v = m.get(d) || { outside: 0, 'jt-waf-mgr': 0, baseline: 0 }
    if (c.cause in v) v[c.cause]++
    m.set(d, v)
  }
  return [...m.entries()].sort((a, b) => b[0].localeCompare(a[0])).slice(0, 14).map(([d, v]) => ({ key: d, label: d, values: v }))
})
function kindParts(c) {
  return [
    { key: 'added', label: t('cfgchg.added'), value: n(c, 'added'), tone: 's1' },
    { key: 'removed', label: t('cfgchg.removed'), value: n(c, 'removed'), tone: 's2' },
    { key: 'changed', label: t('cfgchg.changed'), value: n(c, 'changed'), tone: 's3' },
  ]
}
const fileRows = computed(() => Object.entries((snap.value && snap.value.files) || {}).map(([path, hash]) => ({ path, hash })))
const fileCols = computed(() => [
  { key: 'path', label: t('cfgchg.path'), required: true },
  { key: 'touched', label: t('cfgchg.touched'), value: (r) => (touched.value.has(r.path) ? t('cfgchg.touched') : '') },
  { key: 'hash', label: 'SHA-256', sortable: false },
])

async function load(fresh) {
  loading.value = true; error.value = null
  try {
    const p = { limit: 50 }
    if (!fresh && cursor.value) p.cursor = cursor.value
    const d = await get('/config-changes', p)
    items.value = fresh ? d.items : items.value.concat(d.items)
    cursor.value = d.next_cursor || null
  } catch (e) { error.value = e } finally { loading.value = false }
}

async function loadOne() {
  snap.value = null; error.value = null
  try { snap.value = await get('/config-changes/' + encodeURIComponent(props.id)) } catch (e) { error.value = e }
}

watch(() => props.id, () => { if (props.id) loadOne(); else load(true) }, { immediate: true })
</script>
