<!-- One-line text that may come from an attacker: escaped invisibles, CSS-truncated, full value in title. -->
<template>
  <span class="trunc" :class="{ mono }" :title="full">{{ shown }}</span>
</template>

<script setup>
import { computed } from 'vue'
import { safeText } from '../util.js'

const props = defineProps({ text: { default: '' }, max: { type: Number, default: 400 }, mono: { type: Boolean, default: false } })
const full = computed(() => safeText(props.text, 2000))
const shown = computed(() => safeText(props.text, props.max))
</script>
