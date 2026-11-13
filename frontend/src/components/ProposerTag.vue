<!-- Who proposed a change: a person, an API token (with "API"), or the event analysis (a local LLM's suggestion,
     marked so nobody mistakes it for a colleague's proposal). -->
<template>
  <span v-if="by === 'analyst'" class="chip tag aitag" :title="t('change.by_analyst_hint')"><Icon name="ai" />{{ t('change.by_analyst') }}</span>
  <span v-else>{{ safeText(by, 64) }}<span v-if="via === 'api'" class="chip tag" :title="t('change.via_api_hint')">API</span>
    <span v-if="via === 'api' && (owner || ip)" class="sub apifrom">{{ fromText }}</span></span>
</template>

<script setup>
import { t } from '../i18n.js'
import { safeText } from '../util.js'
import Icon from './Icon.vue'

import { computed } from 'vue'

const props = defineProps({ by: { type: String, default: '' }, via: { type: String, default: '' }, owner: { type: String, default: '' },
  ip: { type: String, default: '' } })
// an API token's change: whose token it is and the machine that called
const fromText = computed(() => [props.owner ? t('change.token_owner', { owner: safeText(props.owner, 64) }) : '',
  props.ip ? t('change.from_ip', { ip: safeText(props.ip, 45) }) : ''].filter(Boolean).join(' · '))
</script>

<style scoped>
.apifrom { display: block; color: var(--muted); font-size: 12px; white-space: nowrap; }
/* the AI tag: dark violet on a pale violet tint in light mode, light violet on a deep tint in dark mode (both well over
   4.5:1) */
.aitag { display: inline-flex; align-items: center; gap: 4px; background: #ede9fe; color: #5b21b6;
  border-color: #c4b5fd; font-weight: 600; }
:global([data-theme="dark"]) .aitag { background: #2e1065; color: #ddd6fe; border-color: #6d28d9; }
@media (prefers-color-scheme: dark) {
  :global(:root:not([data-theme="light"])) .aitag { background: #2e1065; color: #ddd6fe; border-color: #6d28d9; }
}
</style>
