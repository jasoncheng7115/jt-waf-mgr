<!-- Ranked horizontal bars, one or more stacked series, value at the tip, hover / focus tooltip.
     items: [{ key, label, values: { <seriesKey>: n }, to? (router link), mono?, sub?, active? }]
     series: [{ key, label, tone }]   (2+ series get a legend)
     pickable: the label (and the bar: click / Enter) emits `pick(item)` instead of following `to`;
     `to` then becomes a small secondary "open" link next to the label (aria-label from openLabel). -->
<template>
  <div class="hbars">
    <div v-if="!items.length" class="empty small">{{ t('common.no_data') }}</div>
    <div v-for="it in items" :key="it.key" class="hb-row" :class="{ 'hb-on': pickable && it.active }">
      <div class="hb-label" :class="{ mono: it.mono || mono }">
        <div v-if="pickable" class="hb-line">
          <button type="button" class="pickval hb-pick" :class="{ on: it.active }" :aria-pressed="it.active ? 'true' : 'false'"
                  :title="it.active ? t('filter.unpick') : t('filter.pick')" @click="pick(it)"><span class="pv-text">{{ clip(it.label) }}</span><Icon name="filter" class="pv-icon" /></button>
          <RouterLink v-if="it.to" :to="it.to" class="openlink" :title="openLabel || t('filter.open')" :aria-label="(openLabel || t('filter.open')) + ': ' + clip(it.label, 100)"><Icon name="external" /></RouterLink>
        </div>
        <template v-else><RouterLink v-if="it.to" :to="it.to">{{ clip(it.label) }}</RouterLink><span v-else>{{ clip(it.label) }}</span></template>
        <div v-if="it.sub" class="sub">{{ clip(it.sub, 120) }}</div>
      </div>
      <div class="hb-bar" :class="{ 'hb-pickbar': pickable }" tabindex="0" @pointermove="show($event, it)" @pointerleave="hide" @focus="show($event, it)" @blur="hide"
           @click="pickable && pick(it)" @keydown.enter.prevent="pickable && pick(it)">
        <span v-for="s in series.filter((x) => (it.values[x.key] || 0) > 0)" :key="s.key" class="hb-seg" :class="'tone-' + s.tone" :style="{ width: w(it.values[s.key]) + '%' }"></span>
      </div>
      <div class="hb-num">{{ fmtNum(sum(it)) }}</div>
    </div>
    <div v-if="series.length > 1 && items.length" class="legend">
      <span v-for="s in series" :key="s.key" class="lg-item"><span class="lg" :class="'tone-' + s.tone"></span>{{ s.label }}</span>
    </div>
    <ChartTip :tip="tip" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../../i18n.js'
import { fmtNum } from '../../util.js'
import { useTip } from './tip.js'
import ChartTip from './ChartTip.vue'
import Icon from '../Icon.vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  series: { type: Array, default: () => [{ key: 'value', label: '', tone: 's1' }] },
  valueLabel: { type: String, default: '' },      // tooltip label for a single series without its own label
  mono: Boolean,
  pickable: Boolean,
  openLabel: { type: String, default: '' },
})
const emit = defineEmits(['pick'])
const { tip, at, hide } = useTip()
function sum(it) { return props.series.reduce((s, x) => s + (it.values[x.key] || 0), 0) }
const max = computed(() => Math.max(1, ...props.items.map(sum)))
function w(n) { return ((n || 0) / max.value) * 100 }
function clip(s, n = 80) { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s }
function show(e, it) {
  at(e, clip(it.label, 100), props.series.map((s) => ({ value: fmtNum(it.values[s.key] || 0), label: s.label || props.valueLabel || t('chart.count'), tone: props.series.length > 1 ? s.tone : null })))
}
function pick(it) { hide(); emit('pick', it) }
</script>
