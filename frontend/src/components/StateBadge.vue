<template>
  <span class="badge" :class="cls">{{ t('cstate.' + state) }}</span>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'

const props = defineProps({ state: { type: String, required: true } })
const MAP = {
  checking: 'b-int', approved: 'b-int', applying: 'b-int', pending_approval: 'b-warn', failed: 'b-blocked',
  apply_failed: 'b-blocked', applied: 'b-ok', rejected: 'b-logged', cancelled: 'b-logged', rolled_back: 'b-logged',
}
const cls = computed(() => MAP[props.state] || 'b-logged')
</script>
