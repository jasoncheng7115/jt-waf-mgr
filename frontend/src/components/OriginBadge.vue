<template>
  <span class="badge" :class="origin === 'internal' ? 'b-int' : 'b-ext'"><Icon :name="origin === 'internal' ? 'network' : 'globe'" />{{ t('origin.' + (origin || 'external')) }}</span>
</template>

<script setup>
import { t } from '../i18n.js'
import Icon from './Icon.vue'
defineProps({ origin: String })
</script>

<style scoped>
.badge .icon { margin-right: 3px; vertical-align: -0.25em; }
</style>
