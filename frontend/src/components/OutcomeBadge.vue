<template>
  <span class="badge" :class="cls" :title="redirected ? t('outcome.redirected_hint') : null"><Icon :name="outcome === 'blocked' ? 'block' : redirected ? 'forward' : 'page'" />{{ label }}</span>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'
import Icon from './Icon.vue'

// redirected: logged, but answered with a redirect although a refusing rule matched (nothing was served)
const props = defineProps({ outcome: String, decidedBy: { type: String, default: null }, redirected: Boolean })
const cls = computed(() => {
  if (props.redirected) return 'b-int'
  if (props.outcome !== 'blocked') return 'b-logged'
  if (props.decidedBy === 'score') return 'b-score'
  return 'b-blocked'
})
const label = computed(() => {
  if (props.redirected) return t('outcome.redirected')
  if (props.outcome !== 'blocked') return t('outcome.logged')
  if (props.decidedBy) return t('outcome.blocked') + ' · ' + t('decided.' + props.decidedBy)
  return t('outcome.blocked')
})
</script>

<style scoped>
.badge .icon { margin-right: 3px; vertical-align: -0.25em; }
</style>
