<template>
  <span class="badge" :class="cls" :title="t('direction.' + direction + '_hint')"><Icon :name="icon" />{{ t('direction.' + direction) }}</span>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'
import Icon from './Icon.vue'

const props = defineProps({ direction: { type: String, required: true } })
const cls = computed(() => ({ tighten: 'b-ext', loosen: 'b-score' }[props.direction] || 'b-logged'))
const icon = computed(() => ({ tighten: 'lock', loosen: 'unlock' }[props.direction] || 'change'))
</script>

<style scoped>
.badge .icon { margin-right: 3px; vertical-align: -0.25em; }
</style>
