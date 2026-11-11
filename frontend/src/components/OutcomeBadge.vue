<template>
  <span class="badge" :class="cls"><Icon :name="outcome === 'blocked' ? 'block' : 'page'" />{{ label }}</span>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'
import Icon from './Icon.vue'

const props = defineProps({ outcome: String, decidedBy: { type: String, default: null } })
const cls = computed(() => {
  if (props.outcome !== 'blocked') return 'b-logged'
  if (props.decidedBy === 'score') return 'b-score'
  return 'b-blocked'
})
const label = computed(() => {
  if (props.outcome !== 'blocked') return t('outcome.logged')
  if (props.decidedBy) return t('outcome.blocked') + ' · ' + t('decided.' + props.decidedBy)
  return t('outcome.blocked')
})
</script>

<style scoped>
.badge .icon { margin-right: 3px; vertical-align: -0.25em; }
</style>
