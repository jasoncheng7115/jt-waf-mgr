<!-- A single value against its limit (disk space, retention, quota). The fill carries severity. -->
<template>
  <div class="meter" role="meter" :aria-valuenow="value" :aria-valuemin="0" :aria-valuemax="max" :aria-label="label">
    <div class="mt-track"><span class="mt-fill" :class="'tone-' + tone" :style="{ width: pct + '%' }"></span></div>
    <div class="mt-text"><span>{{ text || (Math.round(pct) + '%') }}</span></div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ value: { type: Number, default: 0 }, max: { type: Number, default: 100 }, label: { type: String, default: '' },
  text: { type: String, default: '' }, warnAt: { type: Number, default: 0.8 }, critAt: { type: Number, default: 0.95 } })
const pct = computed(() => (props.max > 0 ? Math.min(100, Math.max(0, (props.value / props.max) * 100)) : 0))
const tone = computed(() => (pct.value >= props.critAt * 100 ? 'critical' : pct.value >= props.warnAt * 100 ? 'warning' : 's1'))
</script>
