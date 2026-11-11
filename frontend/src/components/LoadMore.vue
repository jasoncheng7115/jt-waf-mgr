<template>
  <div v-if="cursor" class="loadmore">
    <button type="button" class="btn" :disabled="busy" @click="$emit('more')"><Icon name="expand" />{{ busy ? t('common.loading') : t('common.load_more') }}</button>
  </div>
</template>

<script setup>
import { t } from '../i18n.js'
import Icon from './Icon.vue'
defineProps({ cursor: { default: null }, busy: Boolean })
defineEmits(['more'])
</script>
