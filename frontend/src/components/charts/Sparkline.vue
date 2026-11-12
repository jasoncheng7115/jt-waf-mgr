<!-- Small trend line for a stat tile: 2px line, a 10% area wash, the latest point marked. Hover / focus shows
     the bucket under the pointer. values: [{ t, v }] -->
<template>
  <svg ref="svg" class="sparkline" :class="'tone-line-' + tone" viewBox="0 0 120 32" preserveAspectRatio="none" role="img"
       :aria-label="label" tabindex="0" @pointermove="move" @pointerleave="leave" @focus="focusLast" @blur="leave">
    <path v-if="area" class="sl-area" :d="area" />
    <path v-if="line" class="sl-line" :d="line" vector-effect="non-scaling-stroke" />
    <line v-if="hover >= 0" class="sl-cross" :x1="xs[hover]" :x2="xs[hover]" y1="0" y2="32" vector-effect="non-scaling-stroke" />
    <ChartTip :tip="tip" />
  </svg>
</template>

<script setup>
import { computed, ref } from 'vue'
import { fmtNum, fmtShortTime } from '../../util.js'
import { useTip } from './tip.js'
import ChartTip from './ChartTip.vue'

const props = defineProps({ values: { type: Array, default: () => [] }, tone: { type: String, default: 's1' }, label: { type: String, default: '' } })
const svg = ref(null)
const hover = ref(-1)
const { tip, at, hide } = useTip()
const max = computed(() => Math.max(1, ...props.values.map((p) => p.v || 0)))
const xs = computed(() => props.values.map((_, i) => (props.values.length < 2 ? 60 : (i / (props.values.length - 1)) * 120)))
const ys = computed(() => props.values.map((p) => 30 - ((p.v || 0) / max.value) * 27))
const line = computed(() => props.values.length ? 'M' + xs.value.map((x, i) => x.toFixed(2) + ',' + ys.value[i].toFixed(2)).join(' L') : '')
const area = computed(() => props.values.length ? line.value + ' L120,32 L0,32 Z' : '')
function show(i, e) {
  hover.value = i
  const p = props.values[i]
  at(e, fmtShortTime(p.t), [{ value: fmtNum(p.v || 0), label: props.label }])
}
function move(e) {
  if (!svg.value || !props.values.length) return
  const r = svg.value.getBoundingClientRect()
  const i = Math.round(((e.clientX - r.left) / r.width) * (props.values.length - 1))
  show(Math.min(props.values.length - 1, Math.max(0, i)), e)
}
function focusLast(e) { if (props.values.length) show(props.values.length - 1, e) }
function leave() { hover.value = -1; hide() }
</script>
