<!-- A SHA-256 shown short (monospace), full value in the title, with a copy control. -->
<template>
  <span v-if="value" class="hash">
    <code class="mono" :title="full">{{ full.slice(0, len) }}</code>
    <button type="button" class="btn tiny ghost" :title="copied ? t('common.copied') : t('common.copy')" :aria-label="copied ? t('common.copied') : t('common.copy')" @click="copy"><Icon :name="copied ? 'check' : 'copy'" /></button>
  </span>
  <span v-else>—</span>
</template>

<script setup>
import { ref, computed } from 'vue'
import { t } from '../i18n.js'
import { safeText } from '../util.js'
import Icon from './Icon.vue'
const props = defineProps({ value: { type: String, default: '' }, len: { type: Number, default: 10 } })
const full = computed(() => safeText(props.value, 200))
const copied = ref(false)
async function copy() {
  try {
    await navigator.clipboard.writeText(full.value)
    copied.value = true
    setTimeout(() => { copied.value = false }, 1500)
  } catch { /* clipboard blocked: the title shows the full value */ }
}
</script>
