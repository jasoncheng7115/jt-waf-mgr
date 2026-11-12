<!-- Where requests come from: a flat world map (drawn here, no map service, no tiles) with one bubble per country,
     its area by the number of events. Hover / focus a bubble for the numbers; with `pickable` a click emits pick(item).
     items: [{ key: <ISO country code>, label, values: { <seriesKey>: n }, sub? }]   series: [{ key, label, tone }]
     Countries without a known position (or "?") are counted in the note under the map. -->
<template>
  <div class="worldmap">
    <svg class="wm-svg" :viewBox="VIEW" preserveAspectRatio="xMidYMid meet" role="img" :aria-label="ariaText">
      <rect class="wm-sea" x="0" y="0" width="360" height="180" />
      <g class="wm-grid" aria-hidden="true">
        <line v-for="x in [60, 120, 180, 240, 300]" :key="'x' + x" :x1="x" :x2="x" y1="0" y2="180" />
        <line v-for="y in [30, 60, 90, 120, 150]" :key="'y' + y" x1="0" x2="360" :y1="y" :y2="y" />
      </g>
      <path v-if="land" class="wm-land" :d="land" />
      <g class="wm-dots">
        <circle v-for="d in dots" :key="d.key" class="wm-dot" :class="['fill-' + tone, { on: d.item.key === activeKey, pick: pickable }]"
                :cx="d.x" :cy="d.y" :r="d.r" tabindex="0" :aria-label="d.aria"
                @pointermove="show($event, d)" @pointerleave="hide" @focus="show($event, d)" @blur="hide"
                @click="pickable && pick(d)" @keydown.enter.prevent="pickable && pick(d)" />
      </g>
      <g class="wm-labels" aria-hidden="true">
        <text v-for="d in labelled" :key="'l' + d.key" :x="d.x + d.r + 1.2" :y="d.y + 1.4">{{ d.key }}</text>
      </g>
    </svg>
    <p v-if="unplaced" class="muted small wm-note">{{ t('map.unplaced', { n: fmtNum(unplaced) }) }}</p>
    <ChartTip :tip="tip" />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { t } from '../../i18n.js'
import { fmtNum } from '../../util.js'
import { useTip } from './tip.js'
import ChartTip from './ChartTip.vue'
import CENTRE from './countryCentroids.js'

const props = defineProps({
  items: { type: Array, default: () => [] },
  series: { type: Array, default: () => [] },
  tone: { type: String, default: 's1' },
  pickable: Boolean,
  activeKey: { type: String, default: null },
  label: { type: String, default: '' },
  marker: Boolean,      // one place to point at (an address's location): shown even with no events
})
const emit = defineEmits(['pick'])
// latitude 84 N to 58 S: nothing to show on Antarctica, and the map stays wide
const VIEW = '0 6 360 142'
const land = ref('')
onMounted(async () => {
  try { land.value = (await import('./worldLand.js')).default } catch { land.value = '' }
})
const { tip, at, hide } = useTip()

function sum(it) { return props.series.reduce((a, s) => a + (it.values[s.key] || 0), 0) }
const placed = computed(() => props.items.filter((it) => CENTRE[String(it.key).toUpperCase()] && (props.marker || sum(it) > 0)))
const unplaced = computed(() => props.items.filter((it) => !CENTRE[String(it.key).toUpperCase()] && sum(it) > 0).length)
const dots = computed(() => {
  const max = Math.max(1, ...placed.value.map(sum))
  return placed.value
    .map((it) => {
      const [lat, lon] = CENTRE[String(it.key).toUpperCase()]
      const n = sum(it)
      return { key: String(it.key).toUpperCase(), item: it, n, x: lon + 180, y: 90 - lat, r: props.marker ? 3.5 : 1.4 + 7 * Math.sqrt(n / max),
               aria: it.label + ': ' + fmtNum(n) }
    })
    .sort((a, b) => b.n - a.n)       // biggest first, so the small ones stay on top and can be hovered
})
const labelled = computed(() => dots.value.slice(0, 5))
const ariaText = computed(() => (props.label || t('map.title')) + ': ' +
  dots.value.slice(0, 10).map((d) => d.aria).join(', '))

function show(e, d) {
  const rows = props.series.map((s) => ({ value: fmtNum(d.item.values[s.key] || 0), label: s.label, tone: s.tone }))
  if (d.item.sub) rows.push({ value: '', label: d.item.sub })
  at(e, d.item.label, rows)
}
function pick(d) { hide(); emit('pick', d.item) }
</script>

<style scoped>
.worldmap { margin: 0 0 10px; }
.wm-svg { display: block; width: 100%; height: auto; max-height: 340px; border-radius: 6px; }
.wm-sea { fill: var(--map-sea); }
.wm-grid line { stroke: var(--grid); stroke-width: .25; }
.wm-land { fill: var(--map-land); stroke: var(--map-border); stroke-width: .15; stroke-linejoin: round; }
.wm-dot { fill-opacity: .62; stroke: var(--panel); stroke-width: .5; cursor: default; outline: none; }
.wm-dot.pick { cursor: pointer; }
.wm-dot:hover, .wm-dot:focus-visible, .wm-dot.on { fill-opacity: .9; stroke: var(--text); stroke-width: .6; }
.wm-labels text { font-size: 4.2px; font-weight: 600; fill: var(--text); paint-order: stroke; stroke: var(--panel); stroke-width: .9px; }
.wm-note { margin: 4px 0 0; }
</style>
