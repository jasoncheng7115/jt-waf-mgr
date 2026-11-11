<!-- One icon by meaning (see icons.js). Decorative: the button or link next to it carries the text. -->
<template>
  <component :is="comp" v-if="comp" class="icon" width="1.15em" height="1.15em" stroke-width="1.7" aria-hidden="true" focusable="false" />
</template>

<script setup>
import { computed } from 'vue'
import { ICONS } from '../icons.js'

const props = defineProps({ name: { type: String, required: true } })
const comp = computed(() => ICONS[props.name] || null)
</script>
