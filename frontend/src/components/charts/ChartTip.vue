<!-- Floating tooltip for charts (position: fixed, follows the pointer, flips near the right edge). -->
<template>
  <div v-if="tip.show" class="charttip" :style="style" role="status">
    <div v-if="tip.title" class="ct-title">{{ tip.title }}</div>
    <div v-for="(r, i) in tip.rows" :key="i" class="ct-row">
      <span v-if="r.tone" class="ct-key" :class="'tone-' + r.tone"></span>
      <strong class="ct-val">{{ r.value }}</strong>
      <span class="ct-lab">{{ r.label }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ tip: { type: Object, required: true } })
const style = computed(() => {
  const right = props.tip.x > window.innerWidth - 240
  return { position: 'fixed', top: Math.max(8, props.tip.y - 12) + 'px', left: (right ? props.tip.x - 12 : props.tip.x + 14) + 'px',
           transform: right ? 'translate(-100%, -100%)' : 'translateY(-100%)' }
})
</script>
