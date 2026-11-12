<!-- Anomaly-score scale: one row per severity, each segment = one rule match worth `points`, stacked until the
     threshold is reached; a vertical line marks the threshold. Hover / focus a row for what that score does.
     rows: [{ key, label, points, count, score, tip: [{ value, label }] }]   threshold: number
     marks: [{ key, value, label }]  (extra score markers, e.g. "blocked from here" when it is not the threshold) -->
<template>
  <div class="scorescale">
    <svg class="ss-svg" :viewBox="'0 0 ' + W + ' ' + H" role="img" :aria-label="aria">
      <g v-for="tk in ticks" :key="'t' + tk">
        <line class="ss-grid" :x1="x(tk)" :x2="x(tk)" :y1="TOP - 6" :y2="H - 26" />
        <text class="ss-tick" :x="x(tk)" :y="H - 10" text-anchor="middle">{{ tk }}</text>
      </g>
      <g v-for="(r, i) in rows" :key="r.key" class="ss-row" tabindex="0" @pointermove="show($event, r)" @pointerleave="hide" @focus="show($event, r)" @blur="hide">
        <rect class="ss-hit" :x="0" :y="rowY(i) - 6" :width="W" :height="ROW" />
        <text class="ss-label" :x="LABEL - 10" :y="rowY(i) + BAR / 2 + 1" text-anchor="end">{{ r.label }}</text>
        <text class="ss-sub" :x="LABEL - 10" :y="rowY(i) + BAR / 2 + 15" text-anchor="end">{{ r.sub }}</text>
        <rect v-for="k in r.count" :key="k" class="ss-seg" :class="{ over: (k * r.points) >= threshold }"
              :x="x((k - 1) * r.points) + (k > 1 ? 1 : 0)" :y="rowY(i)" :width="Math.max(2, x(r.points) - x(0) - (k > 1 ? 2 : 1))" :height="BAR" rx="3" />
        <text class="ss-val" :x="x(r.score) + 6" :y="rowY(i) + BAR / 2 + 5">{{ r.valueText }}</text>
      </g>
      <line class="ss-thr" :x1="x(threshold)" :x2="x(threshold)" :y1="TOP - 22" :y2="H - 26" />
      <text class="ss-thrlabel" :x="x(threshold) + 5" :y="TOP - 12">{{ thresholdLabel }}</text>
      <g v-for="mk in marks" :key="mk.key">
        <line class="ss-mark" :x1="x(mk.value)" :x2="x(mk.value)" :y1="TOP - 6" :y2="H - 26" />
      </g>
    </svg>
    <ChartTip :tip="tip" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useTip } from './tip.js'
import ChartTip from './ChartTip.vue'

const props = defineProps({
  rows: { type: Array, default: () => [] },
  threshold: { type: Number, required: true },
  thresholdLabel: { type: String, default: '' },
  marks: { type: Array, default: () => [] },
  label: { type: String, default: '' },
})
const W = 560, LABEL = 128, TOP = 40, ROW = 46, BAR = 16, RIGHT = 56
const H = computed(() => TOP + props.rows.length * ROW + 30)
const max = computed(() => {
  const m = Math.max(props.threshold * 1.6, ...props.rows.map((r) => r.score + 1), ...props.marks.map((k) => k.value + 1), 4)
  const step = niceStep(m)
  return Math.ceil(m / step) * step
})
function niceStep(m) { const raw = m / 6; const p = Math.pow(10, Math.floor(Math.log10(raw))); const f = raw / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p }
const ticks = computed(() => { const s = niceStep(max.value); const out = []; for (let v = 0; v <= max.value + 1e-9; v += s) out.push(Math.round(v)); return out })
function x(v) { return LABEL + (v / max.value) * (W - LABEL - RIGHT) }
function rowY(i) { return TOP + i * ROW + 4 }
const { tip, at, hide } = useTip()
function show(e, r) { at(e, r.tipTitle || r.label, r.tip || []) }
const aria = computed(() => (props.label ? props.label + ': ' : '') + props.rows.map((r) => r.tipTitle || r.label).join('; '))
</script>

<style scoped>
.scorescale { width: 100%; }
.ss-svg { width: 100%; height: auto; display: block; overflow: visible; }
.ss-grid { stroke: var(--grid); stroke-width: 1; }
.ss-tick { fill: var(--muted); font-size: 12px; }
.ss-row { outline: none; cursor: default; }
.ss-hit { fill: transparent; }
.ss-row:hover .ss-hit, .ss-row:focus-visible .ss-hit { fill: var(--panel-2); }
.ss-row:focus-visible .ss-label { text-decoration: underline; }
.ss-label { fill: var(--text); font-size: 13.5px; font-weight: 600; }
.ss-sub { fill: var(--muted); font-size: 11.5px; }
.ss-seg { fill: var(--score); }
.ss-seg.over { fill: var(--blocked); }
.ss-val { fill: var(--text); font-size: 12.5px; font-weight: 600; }
.ss-thr { stroke: var(--text); stroke-width: 2; stroke-dasharray: 5 3; }
.ss-thrlabel { fill: var(--text); font-size: 12.5px; font-weight: 600; }
.ss-mark { stroke: var(--muted); stroke-width: 1.5; stroke-dasharray: 2 3; }
</style>
