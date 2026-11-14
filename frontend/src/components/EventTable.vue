<!-- Event list (sort / filter / columns / pages through DataTable). Attacker-controlled fields stay text.
     filterable: clicking a value emits filter(key, value) with key one of host, src_ip, origin, outcome,
     decided_by, rule_id, family (the event-list query names); the time and request still open the event. -->
<template>
  <DataTable :id="tableId" :columns="cols" :rows="items" row-key="id" :default-sort="{ key: 'ts', dir: -1 }"
             :page-size="pageSize" :toolbar="toolbar" :empty="emptyText || ''" class="events">
    <template #cell-ts="{ row }"><RouterLink :to="'/events/' + row.id">{{ fmtShortTime(row.ts) }}</RouterLink></template>
    <template #cell-outcome="{ row }">
      <button v-if="filterable" type="button" class="pickval" :title="t('filter.pick')" @click="emit('filter', 'outcome', row.redirected ? 'redirected' : row.outcome)"><OutcomeBadge :outcome="row.outcome" :decided-by="row.decided_by" :redirected="row.redirected" /><Icon name="filter" class="pv-icon" /></button>
      <OutcomeBadge v-else :outcome="row.outcome" :decided-by="row.decided_by" :redirected="row.redirected" />
    </template>
    <template #cell-host="{ row }">
      <button v-if="filterable && row.host" type="button" class="pickval" :title="t('filter.pick')" @click="emit('filter', 'host', row.host)"><TruncText :text="row.host" :max="80" /><Icon name="filter" class="pv-icon" /></button>
      <TruncText v-else :text="row.host" :max="80" />
    </template>
    <template #cell-request="{ row }">
      <RouterLink :to="'/events/' + row.id" class="reqlink">
        <span class="method">{{ safeText(row.method, 12) }}</span>
        <TruncText :text="pathWithQuery(row)" :max="300" mono />
      </RouterLink>
      <div v-if="row.message" class="sub"><TruncText :text="row.message" :max="200" /></div>
    </template>
    <template #cell-src_ip="{ row }"><span class="srcline">
      <template v-if="filterable">
        <button type="button" class="pickval mono" :title="t('filter.pick')" @click="emit('filter', 'src_ip', row.src_ip)"><span class="pv-text">{{ safeText(row.src_ip, 45) }}</span><Icon name="filter" class="pv-icon" /></button>
        <RouterLink :to="'/lookup/' + encodeURIComponent(row.src_ip)" class="openlink" :title="t('filter.open_lookup')" :aria-label="t('filter.open_lookup') + ': ' + safeText(row.src_ip, 45)"><Icon name="external" /></RouterLink>
      </template>
      <RouterLink v-else :to="'/lookup/' + encodeURIComponent(row.src_ip)" class="mono">{{ safeText(row.src_ip, 45) }}</RouterLink>
      <GeoTag :geo="row.src_geo" compact />
      <button v-if="filterable" type="button" class="pickval" :title="t('filter.pick')" @click="emit('filter', 'origin', row.origin || 'external')"><OriginBadge :origin="row.origin" /><Icon name="filter" class="pv-icon" /></button>
      <OriginBadge v-else :origin="row.origin" />
    </span></template>
    <template #cell-status="{ row }"><span class="mono">{{ row.status ?? '—' }}</span></template>
    <template #cell-rules="{ row }">
      <template v-if="filterable">
        <button v-for="f in row.families || []" :key="'f' + f" type="button" class="pickval quiet chip fam" :title="t('filter.pick')" @click="emit('filter', 'family', f)">{{ t('family.' + f) }}<Icon name="filter" class="pv-icon" /></button>
        <button v-for="r in (row.local_rule_ids || [])" :key="'l' + r" type="button" class="pickval quiet chip local mono" :title="t('filter.pick')" @click="emit('filter', 'rule_id', String(r))">{{ r }}<Icon name="filter" class="pv-icon" /></button>
        <span class="rules-ids mono"><button v-for="r in otherIds(row).shown" :key="'r' + r" type="button" class="pickval quiet ruleid" :title="t('filter.pick')" @click="emit('filter', 'rule_id', String(r))">{{ r }}<Icon name="filter" class="pv-icon" /></button><template v-if="otherIds(row).more"> +{{ otherIds(row).more }}</template></span>
      </template>
      <template v-else>
        <span v-for="f in row.families || []" :key="'f' + f" class="chip fam">{{ t('family.' + f) }}</span>
        <span v-for="r in (row.local_rule_ids || [])" :key="'l' + r" class="chip local mono">{{ r }}</span>
        <span class="rules-ids mono">{{ ruleIds(row) }}</span>
      </template>
    </template>
    <template #cell-decided_by="{ row }">
      <button v-if="filterable && row.decided_by" type="button" class="pickval" :title="t('filter.pick')" @click="emit('filter', 'decided_by', row.decided_by)"><span class="pv-text">{{ t('decided.' + row.decided_by) }}</span><Icon name="filter" class="pv-icon" /></button>
      <template v-else>{{ row.decided_by ? t('decided.' + row.decided_by) : '—' }}</template>
    </template>
    <template #cell-origin="{ row }">
      <button v-if="filterable" type="button" class="pickval" :title="t('filter.pick')" @click="emit('filter', 'origin', row.origin || 'external')"><OriginBadge :origin="row.origin" /><Icon name="filter" class="pv-icon" /></button>
      <OriginBadge v-else :origin="row.origin" />
    </template>
  </DataTable>
</template>

<script setup>
import GeoTag from './GeoTag.vue'
import { countryName } from '../util.js'
function geoText(g) { return g && g.scope === 'external' ? [g.cc, countryName(g.cc, lang.value), g.org].filter(Boolean).join(' ') : '' }
import { computed } from 'vue'
import { t, lang } from '../i18n.js'
import { fmtShortTime, fmtTime, pathWithQuery, safeText } from '../util.js'
import DataTable from './DataTable.vue'
import OutcomeBadge from './OutcomeBadge.vue'
import OriginBadge from './OriginBadge.vue'
import TruncText from './TruncText.vue'
import Icon from './Icon.vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  hideHost: Boolean,
  emptyText: String,
  tableId: { type: String, default: 'events' },   // remembers columns / sort / page size per place
  pageSize: { type: Number, default: 25 },
  toolbar: { type: Boolean, default: true },
  filterable: Boolean,     // values (site, address, origin, outcome, rule, attack type) emit filter(key, value) when clicked
})
const emit = defineEmits(['filter'])

function outcomeText(e) {
  if (e.redirected) return t('outcome.redirected')
  return e.outcome === 'blocked' ? t('outcome.blocked') + (e.decided_by ? ' ' + t('decided.' + e.decided_by) : '') : t('outcome.logged')
}
const cols = computed(() => [
  { key: 'ts', label: t('event.time'), nowrap: true, required: true, text: (e) => fmtTime(e.ts) },
  { key: 'outcome', label: t('event.outcome'), value: (e) => (e.outcome === 'blocked' ? 0 : 1) + ':' + (e.decided_by || ''), text: outcomeText },
  ...(props.hideHost ? [] : [{ key: 'host', label: t('event.host'), class: 'c-host' }]),
  { key: 'request', label: t('event.request'), class: 'c-req', value: (e) => pathWithQuery(e), text: (e) => (e.method || '') + ' ' + pathWithQuery(e) + ' ' + (e.message || '') },
  { key: 'src_ip', label: t('event.source'), nowrap: true, class: 'c-src', text: (e) => (e.src_ip || '') + ' ' + t('origin.' + (e.origin || 'external')) + ' ' + geoText(e.src_geo) },
  { key: 'status', label: t('event.status'), align: 'num' },
  { key: 'rules', label: t('event.rules'), class: 'c-rules', value: (e) => (e.rule_ids || []).join(' '),
    text: (e) => (e.families || []).map((f) => t('family.' + f)).join(' ') + ' ' + (e.rule_ids || []).join(' ') },
  { key: 'decided_by', label: t('event.decided_by'), hidden: true, text: (e) => (e.decided_by ? t('decided.' + e.decided_by) : '') },
  { key: 'origin', label: t('event.origin'), hidden: true, text: (e) => t('origin.' + (e.origin || 'external')) },
])

function otherIds(e) {
  const local = new Set(e.local_rule_ids || [])
  const ids = (e.rule_ids || []).filter((r) => !local.has(r))
  return { shown: ids.slice(0, 6), more: Math.max(0, ids.length - 6) }
}
function ruleIds(e) {
  const o = otherIds(e)
  return o.shown.join(' ') + (o.more ? ' +' + o.more : '')
}
</script>

