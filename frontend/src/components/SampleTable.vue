<template>
  <div class="samples">
    <div class="sub">{{ title }}</div>
    <DataTable :id="tableId || 'samples-' + cols.join('-')" :columns="columns" :rows="rows" row-key="_row" :page-size="10" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'
import { safeText } from '../util.js'
import DataTable from './DataTable.vue'

const props = defineProps({ title: { type: String, default: '' }, rows: { type: Array, default: () => [] }, cols: { type: Array, default: () => [] },
  tableId: { type: String, default: '' } })
const columns = computed(() => props.cols.map((c) => ({
  key: c, label: t('evidence.col.' + c),
  value: c === 'count' ? (r) => r[c] : (r) => safeText(r[c], c === 'path' ? 300 : 120),
  align: c === 'count' ? 'num' : null,
  class: c === 'count' ? null : (c === 'path' || c === 'ua' ? 'mono breakall' : 'mono'),
})))
</script>
