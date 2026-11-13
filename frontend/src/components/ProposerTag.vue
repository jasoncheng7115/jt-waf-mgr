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
.aitag { display: inline-flex; align-items: center; gap: 4px; background: color-mix(in srgb, #7c3aed 14%, var(--panel)); color: #6d28d9;
  border-color: color-mix(in srgb, #7c3aed 40%, var(--border)); font-weight: 600; }
:global([data-theme="dark"]) .apifrom { display: block; color: var(--muted); font-size: 12px; white-space: nowrap; }
.aitag { color: #c4b5fd; }
</style>
