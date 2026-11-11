<!-- Result of an audit hash chain verification (POST /audit/verify, system check). -->
<template>
  <div v-if="s" class="alert" :class="s.ok ? 'success' : 'error'" role="status">
    <Icon :name="s.ok ? 'verify' : 'alert'" />
    <template v-if="s.ok">
      {{ t('chain.intact', { rows: fmtNum(s.rows) }) }}
      <template v-if="s.last_anchor"> {{ t('chain.last_anchor', { at: fmtMinute(s.last_anchor.at), id: s.last_anchor.id }) }}</template>
      <template v-else> {{ t('chain.no_anchor') }}</template>
    </template>
    <template v-else>
      <strong>{{ t('chain.broken') }}</strong>
      <span v-if="s.reason"> {{ tOr('chain.reason.' + s.reason, s.reason) }}</span>
      <span v-if="s.bad_id"> {{ t('chain.bad_id', { id: s.bad_id }) }}</span>
      <ul v-if="s.anchor_problems && s.anchor_problems.length" class="plainlist small">
        <li v-for="(p, i) in s.anchor_problems" :key="i">{{ tOr('chain.reason.' + p.reason, p.reason) }}<template v-if="p.id"> · #{{ p.id }}</template><template v-if="p.at"> · {{ fmtMinute(p.at) }}</template></li>
      </ul>
    </template>
    <div class="small">{{ t('chain.checked_at', { at: fmtMinute(s.checked_at) }) }}</div>
  </div>
</template>

<script setup>
import { t, tOr } from '../i18n.js'
import { fmtNum, fmtMinute } from '../util.js'
import Icon from './Icon.vue'
defineProps({ s: { type: Object, default: null } })
</script>
