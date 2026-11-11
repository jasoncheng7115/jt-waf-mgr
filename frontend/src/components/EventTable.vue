<!-- Event list (sort / filter / columns / pages through DataTable). Attacker-controlled fields stay text. -->
<template>
  <DataTable :id="tableId" :columns="cols" :rows="items" row-key="id" :default-sort="{ key: 'ts', dir: -1 }"
             :page-size="pageSize" :toolbar="toolbar" :empty="emptyText || ''" class="events">
    <template #cell-ts="{ row }"><RouterLink :to="'/events/' + row.id">{{ fmtShortTime(row.ts) }}</RouterLink></template>
    <template #cell-outcome="{ row }"><OutcomeBadge :outcome="row.outcome" :decided-by="row.decided_by" /></template>
    <template #cell-host="{ row }"><TruncText :text="row.host" :max="80" /></template>
    <template #cell-request="{ row }">
      <RouterLink :to="'/events/' + row.id" class="reqlink">
        <span class="method">{{ safeText(row.method, 12) }}</span>
        <TruncText :text="pathWithQuery(row)" :max="300" mono />
      </RouterLink>
      <div v-if="row.message" class="sub"><TruncText :text="row.message" :max="200" /></div>
    </template>
    <template #cell-src_ip="{ row }">
      <RouterLink :to="'/lookup/' + encodeURIComponent(row.src_ip)" class="mono">{{ safeText(row.src_ip, 45) }}</RouterLink>
      <GeoTag :geo="row.src_geo" compact />
      <OriginBadge :origin="row.origin" />
    </template>
    <template #cell-status="{ row }"><span class="mono">{{ row.status ?? '—' }}</span></template>
    <template #cell-rules="{ row }">
      <span v-for="f in row.families || []" :key="'f' + f" class="chip fam">{{ t('family.' + f) }}</span>
      <span v-for="r in (row.local_rule_ids || [])" :key="'l' + r" class="chip local mono">{{ r }}</span>
      <span class="rules-ids mono">{{ ruleIds(row) }}</span>
    </template>
    <template #cell-decided_by="{ row }">{{ row.decided_by ? t('decided.' + row.decided_by) : '—' }}</template>
    <template #cell-origin="{ row }"><OriginBadge :origin="row.origin" /></template>
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

const props = defineProps({
  items: { type: Array, default: () => [] },
  hideHost: Boolean,
  emptyText: String,
  tableId: { type: String, default: 'events' },   // remembers columns / sort / page size per place
  pageSize: { type: Number, default: 25 },
  toolbar: { type: Boolean, default: true },
})

function outcomeText(e) {
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

function ruleIds(e) {
  const local = new Set(e.local_rule_ids || [])
  const ids = (e.rule_ids || []).filter((r) => !local.has(r))
  if (ids.length > 6) return ids.slice(0, 6).join(' ') + ' +' + (ids.length - 6)
  return ids.join(' ')
}
</script>

