<!-- A timeline of the rows a list has loaded (hours up to a week, days beyond). Drag across it to show only that
     time range in the list (v-model:window = { since, until } in ms, or null); a chip clears it. -->
<template>
  <div v-if="buckets.length" class="rowtimeline">
    <h3 class="charthead">{{ title || t('chart.timeline') }}
      <span v-if="window" class="fchip"><span class="fchip-k">{{ t('overview.range') }}</span>
        <span class="fchip-v">{{ fmtShortTime(new Date(window.since).toISOString()) }} – {{ fmtShortTime(new Date(window.until).toISOString()) }}</span>
        <button type="button" class="fchip-x" :aria-label="t('timeline.clear')" :title="t('timeline.clear')" @click="emit('update:window', null)"><Icon name="close" /></button></span>
    </h3>
    <TimeBars :data="buckets" :series="series.map(({ key, label, tone }) => ({ key, label, tone }))" :label="title || t('chart.timeline')"
              selectable :bucket-seconds="size / 1000" @select="pick" />
    <p class="muted small brushhint"><Icon name="info" /> {{ t('timeline.loaded_hint') }}</p>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'
import { fmtShortTime } from '../util.js'
import Icon from './Icon.vue'
import TimeBars from './charts/TimeBars.vue'

const props = defineProps({
  rows: { type: Array, default: () => [] },
  tsKey: { type: String, default: 'ts' },
  series: { type: Array, required: true },        // [{ key, label, tone, test: (row) => bool }]
  title: { type: String, default: '' },
  window: { type: Object, default: null },
})
const emit = defineEmits(['update:window'])
const times = computed(() => props.rows.map((r) => new Date(r[props.tsKey]).getTime()).filter((x) => !isNaN(x)))
const size = computed(() => {
  if (!times.value.length) return 3600e3
  const span = Math.max(...times.value) - Math.min(...times.value)
  return span > 7 * 86400e3 ? 86400e3 : 3600e3
})
function start(ms) {
  if (size.value === 3600e3) return Math.floor(ms / 3600e3) * 3600e3
  const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime()     // local day
}
const buckets = computed(() => {
  if (!times.value.length) return []
  const lo = start(Math.min(...times.value)), hi = start(Math.max(...times.value))
  const m = new Map()
  for (let x = lo; x <= hi; x = size.value === 3600e3 ? x + 3600e3 : start(x + 26 * 3600e3)) {
    m.set(x, Object.fromEntries(props.series.map((s) => [s.key, 0])))
    if (m.size > 800) break
  }
  for (const r of props.rows) {
    const ms = new Date(r[props.tsKey]).getTime()
    if (isNaN(ms)) continue
    const b = m.get(start(ms))
    if (!b) continue
    const s = props.series.find((x) => x.test(r)) || props.series[props.series.length - 1]
    b[s.key]++
  }
  return [...m.entries()].map(([x, v]) => ({ t: new Date(x).toISOString(), ...v }))
})
function pick(r) { emit('update:window', { since: new Date(r.since).getTime(), until: new Date(r.until).getTime() }) }
</script>

<style scoped>
.rowtimeline .charthead { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.brushhint { margin: 4px 0 0; display: flex; gap: 5px; align-items: center; }
</style>
