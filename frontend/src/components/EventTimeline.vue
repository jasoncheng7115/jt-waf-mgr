<!-- Events over time for the given filters (GET /events/timeline): hours up to a week, days beyond. Drag across it
     to pick a time range (emits select { since, until }). -->
<template>
  <div class="eventtimeline">
    <h3 class="charthead">{{ title || t('chart.timeline') }}
      <span v-if="data" class="muted small">{{ fmtShortTime(data.since) }} – {{ fmtShortTime(data.until) }}</span></h3>
    <TimeBars v-if="data" :data="data.timeline" :series="series" :label="title || t('chart.timeline')" selectable
              :bucket-seconds="data.bucket_seconds" @select="(r) => emit('select', r)" />
    <p v-if="data" class="muted small brushhint"><Icon name="info" /> {{ t('overview.brush_hint') }}
      <template v-if="data.clamped"> {{ t('events.timeline_clamped', { days: data.max_days }) }}</template></p>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'
import { get } from '../api.js'
import { t } from '../i18n.js'
import { fmtShortTime } from '../util.js'
import Icon from './Icon.vue'
import TimeBars from './charts/TimeBars.vue'

const props = defineProps({ query: { type: Object, default: () => ({}) }, title: { type: String, default: '' } })
const emit = defineEmits(['select'])
const series = [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
]
const data = ref(null)
let seq = 0
async function load() {
  const my = ++seq
  try {
    const r = await get('/events/timeline', props.query)
    if (my === seq) data.value = r
  } catch { if (my === seq) data.value = null }
}
watch(() => JSON.stringify(props.query), load, { immediate: true })
</script>

<style scoped>
.eventtimeline .charthead { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
.brushhint { margin: 4px 0 0; display: flex; gap: 5px; align-items: center; flex-wrap: wrap; }
</style>
