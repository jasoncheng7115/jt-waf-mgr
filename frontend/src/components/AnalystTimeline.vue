<!-- The scheduled analysis as a timeline, redrawn as the settings change: what each run looks at (the last N hours)
     and when the next runs happen. Two scales on purpose: the window can be days while the interval is minutes, so the
     past and the future each get their own part, split at "now". -->
<template>
  <div class="atl" role="img" :aria-label="summary">
    <svg :viewBox="'0 0 ' + W + ' ' + H" class="chartsvg" width="100%">
      <!-- the window every run reads -->
      <rect class="atl-win" :x="PAD" y="22" :width="NOWX - PAD" height="26" rx="4" />
      <text class="atl-wlabel" :x="(PAD + NOWX) / 2" y="39" text-anchor="middle">{{ t('atl.window', { h: windowHours }) }}</text>
      <line v-for="tk in pastTicks" :key="'p' + tk.x" class="gridline" :x1="tk.x" :x2="tk.x" y1="18" y2="52" />
      <text v-for="tk in pastTicks" :key="'pl' + tk.x" class="axis-label" :x="tk.x" y="68" text-anchor="middle">{{ tk.label }}</text>
      <!-- now -->
      <line class="atl-now" :x1="NOWX" :x2="NOWX" y1="10" y2="56" />
      <text class="atl-nowl" :x="NOWX" y="68" text-anchor="middle">{{ t('atl.now') }}</text>
      <!-- the next runs -->
      <line class="axis" :x1="NOWX" :x2="W - PAD" y1="35" y2="35" />
      <g v-for="(r, i) in runs" :key="'r' + i">
        <circle class="atl-run" :class="{ next: i === 0 }" :cx="r.x" cy="35" r="6" />
        <text class="axis-label" :x="r.x" y="68" text-anchor="middle">{{ r.label }}</text>
      </g>
    </svg>
    <p class="muted small atl-text"><Icon name="timer" /> {{ summary }}</p>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'
import Icon from './Icon.vue'

const props = defineProps({
  windowHours: { type: Number, default: 24 },
  intervalMinutes: { type: Number, default: 180 },
  nextDue: { type: String, default: '' },
  enabled: Boolean,
})
const W = 1000, H = 76, PAD = 16
const NOWX = 640                     // the past (the window) gets the left part, the next runs the right part
const RUNS = 4

function hm(d) { return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0') }
function md(d) { return (d.getMonth() + 1) + '/' + d.getDate() }

const pastTicks = computed(() => {
  const h = Math.max(1, Number(props.windowHours) || 1)
  const step = h > 72 ? 24 : h > 24 ? 12 : h > 6 ? 3 : 1           // hours between ticks
  const now = new Date()
  const out = []
  for (let back = step; back < h; back += step) {
    const x = NOWX - (back / h) * (NOWX - PAD)
    const d = new Date(now.getTime() - back * 3600e3)
    out.push({ x, label: step >= 24 ? md(d) : (step >= 12 ? md(d) + ' ' : '') + hm(d) })
  }
  return out.length > 14 ? out.filter((_, i) => i % Math.ceil(out.length / 14) === 0) : out
})
const runs = computed(() => {
  const m = Math.max(10, Number(props.intervalMinutes) || 10)
  const first = props.nextDue ? new Date(props.nextDue) : new Date(Date.now() + m * 60e3)
  const span = (W - PAD - NOWX - 40)
  return Array.from({ length: RUNS }, (_, i) => {
    const d = new Date(first.getTime() + i * m * 60e3)
    return { x: NOWX + 40 + (i / (RUNS - 1)) * span, label: (m >= 1440 ? md(d) + ' ' : '') + hm(d) }
  })
})
const summary = computed(() => {
  const m = Math.max(10, Number(props.intervalMinutes) || 10)
  const h = Math.max(1, Number(props.windowHours) || 1)
  const perDay = Math.round(1440 / m * 10) / 10
  const overlap = Math.max(0, Math.round((1 - m / (h * 60)) * 100))
  return (props.enabled ? '' : t('atl.off') + ' ') + t('atl.summary', { m, n: perDay, h, o: overlap })
})
</script>

<style scoped>
.atl { margin: 4px 0 12px; }
.atl svg { display: block; overflow: visible; }
.atl-win { fill: color-mix(in srgb, var(--accent) 16%, transparent); stroke: var(--accent); stroke-width: 1; }
.atl-wlabel { fill: var(--text); font-size: 12px; font-weight: 600; }
.atl-now { stroke: var(--warn); stroke-width: 2; }
.atl-nowl { fill: var(--warn); font-size: 11px; font-weight: 600; }
.atl-run { fill: var(--panel); stroke: var(--accent); stroke-width: 2; }
.atl-run.next { fill: var(--accent); }
.atl-text { display: flex; gap: 6px; align-items: flex-start; margin: 2px 0 0; }
</style>
