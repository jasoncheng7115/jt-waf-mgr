<template>
  <pre class="code diff"><span v-for="(l, i) in lines" :key="i" class="dl" :class="l.cls">{{ l.text || ' ' }}</span></pre>
</template>

<script setup>
import { computed } from 'vue'
import { diffLines } from '../util.js'

const props = defineProps({ text: { type: String, default: '' } })
const lines = computed(() => diffLines(props.text))
</script>
