<!-- Columns over time (one or more stacked series) with a crosshair tooltip that snaps to the nearest bucket.
     data: [{ t, <seriesKey>: n }]   series: [{ key, label, tone }] -->
<template>
  <div class="timebars">
    <svg ref="svg" :viewBox="'0 0 ' + W + ' ' + H" class="chartsvg" role="img" :aria-label="label || t('chart.timeline')"
         @pointermove="move" @pointerleave="leave">
      <line v-for="g in grid" :key="'g' + g.v" class="gridline" :x1="PADL" :x2="W" :y1="g.y" :y2="g.y" />
      <text v-for="g in grid" :key="'l' + g.v" class="axis-label" :x="PADL - 6" :y="g.y + 4" text-anchor="end">{{ fmtCompact(g.v) }}</text>
      <line class="axis" :x1="PADL" :y1="H - PADB" :x2="W" :y2="H - PADB" />
      <g v-for="(b, i) in bars" :key="i" :class="{ hot: i === hover }">
        <path v-for="s in b.segs" :key="s.key" :class="'fill-' + s.tone" :d="s.d" />
      </g>
      <line v-if="hover >= 0" class="crosshair" :x1="bars[hover].cx" :x2="bars[hover].cx" :y1="PADT" :y2="H - PADB" />
      <text v-for="tk in ticks" :key="'t' + tk.x" class="axis-label" :x="tk.x" :y="H - 6" text-anchor="middle">{{ tk.label }}</text>
    </svg>
    <div v-if="series.length > 1" class="legend">
      <span v-for="s in series" :key="s.key" class="lg-item"><span class="lg" :class="'tone-' + s.tone"></span>{{ s.label }}</span>
    </div>
    <ChartTip :tip="tip" />
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { t, lang } from '../../i18n.js'
import { fmtNum, fmtShortTime } from '../../util.js'
import { useTip } from './tip.js'
import ChartTip from './ChartTip.vue'

const props = defineProps({
  data: { type: Array, default: () => [] },
  series: { type: Array, required: true },
  label: { type: String, default: '' },
})
const W = 1000, H = 190, PADL = 48, PADB = 24, PADT = 10
const svg = ref(null)
const hover = ref(-1)
const { tip, at, hide } = useTip()

function total(d) { return props.series.reduce((s, x) => s + (d[x.key] || 0), 0) }
function niceMax(v) {
  if (v <= 4) return 4
  const p = Math.pow(10, Math.floor(Math.log10(v)))
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p
  return 10 * p
}
const maxVal = computed(() => niceMax(Math.max(1, ...props.data.map(total))))
const grid = computed(() => [0, 0.25, 0.5, 0.75, 1].map((f) => ({ v: Math.round(maxVal.value * f), y: H - PADB - f * (H - PADT - PADB) })))
const slot = computed(() => (W - PADL) / Math.max(1, props.data.length))
const bw = computed(() => Math.max(1, Math.min(24, slot.value - 2)))
function colPath(x, y0, h, w, round) {
  if (h <= 0) return ''
  const r = round ? Math.min(4, w / 2, h) : 0
  const y = y0 - h
  return 'M' + x + ',' + y0 + 'V' + (y + r) + (r ? 'Q' + x + ',' + y + ' ' + (x + r) + ',' + y + 'H' + (x + w - r) + 'Q' + (x + w) + ',' + y + ' ' + (x + w) + ',' + (y + r) : 'H' + (x + w)) + 'V' + y0 + 'Z'
}
const bars = computed(() => {
  const ih = H - PADT - PADB
  return props.data.map((d, i) => {
    const x = PADL + i * slot.value + (slot.value - bw.value) / 2
    let base = H - PADB
    const live = props.series.filter((s) => (d[s.key] || 0) > 0)
    const segs = live.map((s, k) => {
      const h = ((d[s.key] || 0) / maxVal.value) * ih
      const gap = k > 0 && h > 2 ? 2 : 0                       // 2px surface gap between stacked parts
      const p = { key: s.key, tone: s.tone, d: colPath(x, base - gap, Math.max(0, h - gap), bw.value, k === live.length - 1) }
      base -= h
      return p
    })
    return { cx: x + bw.value / 2, segs, d }
  })
})
const ticks = computed(() => {
  const n = props.data.length
  if (!n) return []
  const step = Math.max(1, Math.ceil(n / 8))
  const out = []
  for (let i = 0; i < n; i += step) {
    const dt = new Date(props.data[i].t)
    if (isNaN(dt)) continue
    const label = daily.value || n > 48 ? fmtDay(props.data[i].t) : String(dt.getHours()).padStart(2, '0') + ':00'
    out.push({ x: PADL + i * slot.value + slot.value / 2, label })
  }
  return out
})
// buckets a day or more apart are labelled by date, hourly ones by hour
const daily = computed(() => props.data.length > 1 && (new Date(props.data[1].t) - new Date(props.data[0].t)) >= 20 * 3600 * 1000)
function fmtDay(iso) {
  const d = new Date(iso)
  return isNaN(d) ? String(iso) : new Intl.DateTimeFormat(lang.value, { month: '2-digit', day: '2-digit' }).format(d)
}
function fmtCompact(v) { return v >= 10000 ? Math.round(v / 1000) + 'K' : fmtNum(v) }
function move(e) {
  if (!svg.value || !props.data.length) return
  const r = svg.value.getBoundingClientRect()
  const x = ((e.clientX - r.left) / r.width) * W
  const i = Math.min(props.data.length - 1, Math.max(0, Math.floor((x - PADL) / slot.value)))
  hover.value = i
  const d = props.data[i]
  at(e, daily.value ? fmtDay(d.t) : fmtShortTime(d.t), props.series.map((s) => ({ value: fmtNum(d[s.key] || 0), label: s.label, tone: s.tone })))
}
function leave() { hover.value = -1; hide() }
</script>
