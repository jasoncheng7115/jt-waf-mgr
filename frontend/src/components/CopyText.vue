<!-- A value shown once (secret, temporary password) with a copy button. -->
<template>
  <div class="copytext">
    <code class="mono">{{ display || value }}</code>
    <button type="button" class="btn small" @click="copy"><Icon :name="copied ? 'check' : 'copy'" />{{ copied ? t('common.copied') : t('common.copy') }}</button>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { t } from '../i18n.js'
import Icon from './Icon.vue'

const props = defineProps({ value: { type: String, default: '' }, display: { type: String, default: '' } })
const copied = ref(false)
async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
    copied.value = true
    setTimeout(() => { copied.value = false }, 1500)
  } catch { /* clipboard blocked (http or permissions): user can select the text */ }
}
</script>
