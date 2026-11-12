<!-- Every list table: sort (click a header), filter (quick search + per-column filters), choose columns,
     paginate. Column choice, page size and sort are remembered per table (`id`) in this browser.

     columns: [{
       key,                       // row property; also the slot name: #cell-<key>="{ row, value }"
       label,                     // header text (already translated)
       value?: (row) => any,      // what sorting / filtering use (default row[key])
       text?:  (row) => string,   // what the quick search and column filter match (default String(value))
       sortable?: true, filterable?: true,
       hidden?: false,            // hidden until the user picks it
       required?: false,          // cannot be hidden
       align?: 'num' | null, nowrap?: false, class?: string,
     }]
     Rows render as plain text unless a cell slot is given (attacker-controlled data stays text). -->
<template>
  <div class="datatable">
    <div v-if="toolbar" class="dt-toolbar">
      <label class="dt-search">
        <Icon name="search" />
        <input v-model="quick" type="search" :placeholder="t('table.search')" :aria-label="t('table.search')" />
      </label>
      <button type="button" class="btn small ghost" :class="{ on: showFilters }" :aria-pressed="showFilters ? 'true' : 'false'"
              @click="showFilters = !showFilters"><Icon name="filter" />{{ t('table.filters') }}<span v-if="activeFilters" class="badge tiny b-warn">{{ activeFilters }}</span></button>
      <div class="dt-colpick">
        <button ref="colBtn" type="button" class="btn small ghost" aria-haspopup="true" :aria-expanded="colsOpen ? 'true' : 'false'"
                @click="colsOpen = !colsOpen"><Icon name="columns" />{{ t('table.columns') }}</button>
        <div v-if="colsOpen" ref="colPop" class="dt-colpop" role="group" :aria-label="t('table.columns')">
          <label v-for="c in columns" :key="c.key" class="dt-colopt" :class="{ disabled: c.required }">
            <input type="checkbox" :checked="isVisible(c)" :disabled="c.required" @change="toggleCol(c)" />
            <span>{{ c.label }}</span>
          </label>
          <button type="button" class="btn small ghost" @click="resetCols"><Icon name="refresh" />{{ t('table.reset_columns') }}</button>
        </div>
      </div>
      <button v-if="quick || activeFilters" type="button" class="btn small ghost" @click="clearFilters"><Icon name="clear" />{{ t('table.clear_filters') }}</button>
      <slot name="toolbar" />
      <span class="dt-count">{{ t('table.rows', { n: fmtNum(filtered.length) }) }}<template v-if="filtered.length !== rows.length"> / {{ fmtNum(rows.length) }}</template></span>
    </div>
    <div ref="wrap" class="tablewrap" @scroll="syncFromWrap">
      <table class="grid">
        <thead>
          <tr>
            <th v-for="c in visibleCols" :key="c.key" :class="[c.align, { sortable: c.sortable !== false }]"
                :aria-sort="sortKey === c.key ? (sortDir > 0 ? 'ascending' : 'descending') : null">
              <button v-if="c.sortable !== false" type="button" class="dt-sort" @click="sortBy(c)">
                {{ c.label }}<Icon :name="sortKey === c.key ? (sortDir > 0 ? 'sortUp' : 'sortDown') : 'sort'" class="dt-sorticon" :class="{ on: sortKey === c.key }" />
              </button>
              <template v-else>{{ c.label }}</template>
            </th>
          </tr>
          <tr v-if="showFilters" class="dt-filters">
            <th v-for="c in visibleCols" :key="c.key">
              <input v-if="c.filterable !== false" v-model="colFilter[c.key]" type="search" :aria-label="t('table.filter_column', { col: c.label })"
                     :placeholder="t('table.filter')" />
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(r, i) in pageRows" :key="keyOf(r, i)" :class="[rowClass ? rowClass(r) : null, { clickable: clickable }]"
              :tabindex="clickable ? 0 : null" @click="clickable && $emit('row-click', r, $event)"
              @keydown.enter="clickable && $emit('row-click', r, $event)">
            <td v-for="c in visibleCols" :key="c.key" :class="[c.align, c.class, { nowrap: c.nowrap }]">
              <slot :name="'cell-' + c.key" :row="r" :value="valueOf(c, r)">{{ plain(valueOf(c, r)) }}</slot>
            </td>
          </tr>
          <tr v-if="!pageRows.length"><td :colspan="visibleCols.length || 1" class="empty">{{ rows.length ? t('table.no_match') : (empty || t('common.no_data')) }}</td></tr>
        </tbody>
      </table>
    </div>
    <!-- When the table is wider than its box and its own scrollbar is below the visible screen, a copy of the
         scrollbar floats at the bottom of the window (scrolls the table, follows it). -->
    <div v-show="floatBar" ref="fbar" class="dt-floatbar" :style="floatStyle" aria-hidden="true" @scroll="syncFromBar">
      <div :style="{ width: scrollW + 'px', height: '1px' }"></div>
    </div>
    <div v-if="filtered.length > pageSize || pageSize !== defaultPageSize" class="dt-pager">
      <span class="dt-range">{{ t('table.range', { from: fmtNum(from + 1), to: fmtNum(Math.min(from + pageSize, filtered.length)), total: fmtNum(filtered.length) }) }}</span>
      <button type="button" class="btn small ghost" :disabled="page === 0" :aria-label="t('table.first')" @click="page = 0"><Icon name="prev" /><Icon name="prev" /></button>
      <button type="button" class="btn small ghost" :disabled="page === 0" @click="page--"><Icon name="prev" />{{ t('table.prev') }}</button>
      <span class="dt-page">{{ t('table.page', { n: page + 1, of: pages }) }}</span>
      <button type="button" class="btn small ghost" :disabled="page >= pages - 1" @click="page++">{{ t('table.next') }}<Icon name="next" /></button>
      <button type="button" class="btn small ghost" :disabled="page >= pages - 1" :aria-label="t('table.last')" @click="page = pages - 1"><Icon name="next" /><Icon name="next" /></button>
      <SelectBox v-model="pageSize" small :options="sizeOptions" :aria-label="t('table.page_size')" />
    </div>
    <slot name="footer" />
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { t, lang } from '../i18n.js'
import { fmtNum } from '../util.js'
import Icon from './Icon.vue'
import SelectBox from './SelectBox.vue'

const props = defineProps({
  id: { type: String, required: true },              // remembers columns / page size / sort per table
  columns: { type: Array, required: true },
  rows: { type: Array, default: () => [] },
  rowKey: { type: [String, Function], default: 'id' },
  rowClass: { type: Function, default: null },
  pageSize: { type: Number, default: 25 },
  defaultSort: { type: Object, default: null },      // { key, dir: 1 | -1 }
  empty: { type: String, default: '' },
  toolbar: { type: Boolean, default: true },
  clickable: Boolean,
})
defineEmits(['row-click'])

const STORE = 'jtwaf.table.' + props.id
function load() {
  try { return JSON.parse(window.localStorage.getItem(STORE) || '{}') || {} } catch { return {} }
}
const saved = load()
const defaultPageSize = props.pageSize
const pageSize = ref([10, 25, 50, 100, 200].includes(saved.pageSize) ? saved.pageSize : props.pageSize)
const hiddenSet = ref(Array.isArray(saved.hidden) ? saved.hidden : null)    // null = column defaults
const sortKey = ref(saved.sortKey !== undefined ? saved.sortKey : (props.defaultSort ? props.defaultSort.key : null))
const sortDir = ref(saved.sortDir === -1 || saved.sortDir === 1 ? saved.sortDir : (props.defaultSort ? props.defaultSort.dir || 1 : 1))
const quick = ref('')
const colFilter = reactive({})
const showFilters = ref(false)
const colsOpen = ref(false)
const page = ref(0)
const colBtn = ref(null), colPop = ref(null)

function persist() {
  try {
    window.localStorage.setItem(STORE, JSON.stringify({ pageSize: pageSize.value, hidden: hiddenSet.value, sortKey: sortKey.value, sortDir: sortDir.value }))
  } catch { /* storage unavailable */ }
}
watch([pageSize, hiddenSet, sortKey, sortDir], persist, { deep: true })

function isVisible(c) {
  if (c.required) return true
  return hiddenSet.value ? !hiddenSet.value.includes(c.key) : !c.hidden
}
function toggleCol(c) {
  const cur = props.columns.filter((x) => !isVisible(x)).map((x) => x.key)
  hiddenSet.value = cur.includes(c.key) ? cur.filter((k) => k !== c.key) : [...cur, c.key]
}
function resetCols() { hiddenSet.value = null }
const visibleCols = computed(() => props.columns.filter(isVisible))

function valueOf(c, r) { return c.value ? c.value(r) : r[c.key] }
function textOf(c, r) {
  if (c.text) return String(c.text(r) ?? '')
  const v = valueOf(c, r)
  if (v === null || v === undefined) return ''
  return Array.isArray(v) ? v.join(' ') : String(v)
}
function plain(v) {
  if (v === null || v === undefined || v === '') return '—'
  if (typeof v === 'number') return fmtNum(v)
  if (Array.isArray(v)) return v.join(', ')
  return String(v).slice(0, 500)
}
function keyOf(r, i) {
  const k = typeof props.rowKey === 'function' ? props.rowKey(r, i) : r[props.rowKey]
  return k === undefined || k === null ? i : k
}

const activeFilters = computed(() => Object.values(colFilter).filter((v) => v && String(v).trim()).length)
const filtered = computed(() => {
  const q = quick.value.trim().toLowerCase()
  const cf = Object.entries(colFilter).filter(([, v]) => v && String(v).trim()).map(([k, v]) => [props.columns.find((c) => c.key === k), String(v).trim().toLowerCase()]).filter(([c]) => c)
  let out = props.rows
  if (q) out = out.filter((r) => visibleCols.value.some((c) => textOf(c, r).toLowerCase().includes(q)))
  if (cf.length) out = out.filter((r) => cf.every(([c, v]) => textOf(c, r).toLowerCase().includes(v)))
  const c = props.columns.find((x) => x.key === sortKey.value)
  if (c) {
    const coll = new Intl.Collator(lang.value, { numeric: true, sensitivity: 'base' })
    const d = sortDir.value
    out = out.map((r, i) => [r, i]).sort(([a, ia], [b, ib]) => {
      const va = valueOf(c, a), vb = valueOf(c, b)
      const ea = va === null || va === undefined || va === '', eb = vb === null || vb === undefined || vb === ''
      if (ea || eb) return ea && eb ? ia - ib : ea ? 1 : -1          // empty values always last
      let r = typeof va === 'number' && typeof vb === 'number' ? va - vb
        : typeof va === 'boolean' ? Number(va) - Number(vb) : coll.compare(textOf(c, a), textOf(c, b))
      return r * d || ia - ib
    }).map(([r]) => r)
  }
  return out
})
const pages = computed(() => Math.max(1, Math.ceil(filtered.value.length / pageSize.value)))
const from = computed(() => page.value * pageSize.value)
const pageRows = computed(() => filtered.value.slice(from.value, from.value + pageSize.value))
watch([quick, colFilter, pageSize, sortKey, sortDir], () => { page.value = 0 }, { deep: true })
watch(pages, (n) => { if (page.value > n - 1) page.value = n - 1 })

function sortBy(c) {
  if (sortKey.value !== c.key) { sortKey.value = c.key; sortDir.value = 1 }
  else if (sortDir.value === 1) sortDir.value = -1
  else { sortKey.value = null; sortDir.value = 1 }
}
function clearFilters() {
  quick.value = ''
  for (const k of Object.keys(colFilter)) colFilter[k] = ''
}
const sizeOptions = computed(() => [10, 25, 50, 100, 200].map((n) => ({ value: n, label: t('table.per_page', { n }) })))

function outside(e) {
  if (colBtn.value?.contains(e.target) || colPop.value?.contains(e.target)) return
  colsOpen.value = false
}
function onKey(e) { if (e.key === 'Escape') colsOpen.value = false }
watch(colsOpen, (o) => {
  if (o) { document.addEventListener('mousedown', outside, true); document.addEventListener('keydown', onKey) }
  else { document.removeEventListener('mousedown', outside, true); document.removeEventListener('keydown', onKey) }
})
onBeforeUnmount(() => { document.removeEventListener('mousedown', outside, true); document.removeEventListener('keydown', onKey) })

// --- floating horizontal scrollbar -----------------------------------------------------------
const wrap = ref(null), fbar = ref(null)
const floatBar = ref(false)
const scrollW = ref(0)
const floatStyle = ref({})
let syncing = false
function measure() {
  const w = wrap.value
  if (!w) return
  const r = w.getBoundingClientRect()
  const overflow = w.scrollWidth > w.clientWidth + 1
  const vh = window.innerHeight
  // the table is on screen, but its bottom edge (and its own scrollbar) is below the window
  const show = overflow && r.top < vh - 40 && r.bottom > vh
  floatBar.value = show
  if (show) {
    scrollW.value = w.scrollWidth
    floatStyle.value = { left: r.left + 'px', width: r.width + 'px' }
    nextTick(() => { if (fbar.value && Math.abs(fbar.value.scrollLeft - w.scrollLeft) > 1) { syncing = true; fbar.value.scrollLeft = w.scrollLeft } })
  }
}
function syncFromWrap() {
  if (syncing) { syncing = false; return }
  if (floatBar.value && fbar.value) { syncing = true; fbar.value.scrollLeft = wrap.value.scrollLeft }
}
function syncFromBar() {
  if (syncing) { syncing = false; return }
  if (wrap.value) { syncing = true; wrap.value.scrollLeft = fbar.value.scrollLeft }
}
let ro2 = null
onMounted(() => {
  window.addEventListener('scroll', measure, { passive: true })
  window.addEventListener('resize', measure)
  if (window.ResizeObserver) { ro2 = new ResizeObserver(measure); ro2.observe(wrap.value) }
  measure()
})
onBeforeUnmount(() => {
  window.removeEventListener('scroll', measure)
  window.removeEventListener('resize', measure)
  if (ro2) ro2.disconnect()
})
watch(() => [pageRows.value.length, visibleCols.value.length, props.rows], () => nextTick(measure))
</script>
