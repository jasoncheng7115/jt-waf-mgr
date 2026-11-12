<!-- Floating tooltip for charts: drawn at the end of <body> (never clipped by a card, never inheriting a chart's
     own text settings), follows the pointer, stays inside the window. tip.below: under the pointer (small charts,
     so the value label above the line stays visible). -->
<template>
  <Teleport to="body">
    <div v-if="tip.show" ref="el" class="charttip" :style="style" role="status">
      <div v-if="tip.title" class="ct-title">{{ tip.title }}</div>
      <div v-for="(r, i) in tip.rows" :key="i" class="ct-row">
        <span v-if="r.tone" class="ct-key" :class="'tone-' + r.tone"></span>
        <strong class="ct-val">{{ r.value }}</strong>
        <span class="ct-lab">{{ r.label }}</span>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
const props = defineProps({ tip: { type: Object, required: true } })
const el = ref(null)
const size = ref({ w: 180, h: 48 })
watch(() => [props.tip.show, props.tip.title, props.tip.rows], async () => {
  await nextTick()
  if (el.value) size.value = { w: el.value.offsetWidth, h: el.value.offsetHeight }
}, { deep: true })
const style = computed(() => {
  const W = window.innerWidth, H = window.innerHeight, { w, h } = size.value
  let left = props.tip.x + 14
  if (left + w > W - 8) left = props.tip.x - 14 - w
  left = Math.max(8, Math.min(left, W - w - 8))
  let top = props.tip.below ? props.tip.y + 10 : props.tip.y - 12 - h
  if (top < 8) top = props.tip.y + 18
  if (top + h > H - 8) top = Math.max(8, props.tip.y - 12 - h)
  return { position: 'fixed', top: top + 'px', left: left + 'px' }
})
</script>
