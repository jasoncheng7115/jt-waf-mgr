<template>
  <div v-if="error" class="alert error" role="alert"><Icon name="alert" /> {{ errText(error) }}</div>
</template>

<script setup>
import { errText } from '../i18n.js'
import Icon from './Icon.vue'
defineProps({ error: { type: Object, default: null } })
</script>
