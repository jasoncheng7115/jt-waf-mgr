<!-- One whole split into parts (statuses, outcomes…). Tall: 28px with the share printed inside when it fits;
     thin: 8px, no text. Legend lists the parts; every part has a hover / focus tooltip.
     parts: [{ key, label, value, tone }]  tone: good | warning | serious | critical | muted | s1 | s2 | s3 -->
<template>
  <div class="segbar" :class="{ thin }">
    <div class="sb-track" role="img" :aria-label="aria">
      <span v-for="p in shown" :key="p.key" class="sb-part" :class="'tone-' + p.tone" :style="{ flexGrow: p.value }" tabindex="0"
            @pointermove="at($event, p.label, [{ value: fmtNum(p.value) + ' (' + pct(p.value) + ')', label: '' }])" @pointerleave="hide"
            @focus="at($event, p.label, [{ value: fmtNum(p.value) + ' (' + pct(p.value) + ')', label: '' }])" @blur="hide">
        <span v-if="!thin && share(p.value) >= 0.09" class="sb-in">{{ pct(p.value) }}</span>
      </span>
      <span v-if="!total" class="sb-part tone-muted sb-zero"></span>
    </div>
    <div v-if="legend" class="legend">
      <span v-for="p in parts" :key="p.key" class="lg-item"><span class="lg" :class="'tone-' + p.tone"></span>{{ p.label }} <span class="muted">{{ fmtNum(p.value || 0) }}</span></span>
    </div>
    <ChartTip :tip="tip" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmtNum } from '../../util.js'
import { useTip } from './tip.js'
import ChartTip from './ChartTip.vue'

const props = defineProps({ parts: { type: Array, default: () => [] }, thin: Boolean, legend: { type: Boolean, default: true }, label: { type: String, default: '' } })
const { tip, at, hide } = useTip()
const total = computed(() => props.parts.reduce((s, p) => s + (p.value || 0), 0))
const shown = computed(() => props.parts.filter((p) => p.value > 0))
function share(v) { return total.value ? v / total.value : 0 }
function pct(v) { const s = share(v) * 100; return (s > 0 && s < 1 ? '<1' : Math.round(s)) + '%' }
const aria = computed(() => (props.label ? props.label + ': ' : '') + props.parts.map((p) => p.label + ' ' + fmtNum(p.value || 0)).join(', '))
</script>
