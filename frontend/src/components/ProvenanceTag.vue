<!-- Where a rule comes from and who keeps it up to date (GET /rules, /rules/{id}: provenance). -->
<template>
  <span v-if="p" class="prov">
    <span class="badge" :class="CLS[p.channel] || 'b-logged'"><Icon :name="ICON[p.channel] || 'page'" />{{ tOr('prov.' + p.channel, p.channel) }}</span>
    <span v-if="detail" class="small muted">{{ detail }}</span>
    <RouterLink v-if="p.change_id" :to="'/changes/' + p.change_id" class="small">{{ t('prov.change', { id: p.change_id }) }}</RouterLink>
  </span>
</template>

<script setup>
import { computed } from 'vue'
import { t, tOr } from '../i18n.js'
import { safeText } from '../util.js'
import Icon from './Icon.vue'

const props = defineProps({ p: { type: Object, default: null } })
const CLS = { crs: 'b-int', plugin: 'b-int', adopted: 'b-logged', person: 'b-ok', token: 'b-ok', analyst: 'b-warn', change: 'b-ok',
  managed: 'b-ok', vhost: 'b-logged', site_file: 'b-logged', base: 'b-logged' }
const ICON = { crs: 'shield', plugin: 'tool', adopted: 'adopt', person: 'user', token: 'key', analyst: 'timer', change: 'change',
  managed: 'change', vhost: 'server', site_file: 'page', base: 'settings' }
const detail = computed(() => {
  const p = props.p
  if (!p) return ''
  const parts = []
  if (p.channel === 'crs' && p.version) parts.push('v' + safeText(p.version, 20))
  if (p.channel === 'plugin' && p.name) parts.push(safeText(p.name, 60))
  if (['crs', 'plugin', 'site_file'].includes(p.channel)) parts.push(p.automation ? t('prov.auto') : t('prov.by_hand'))
  if (['person', 'token'].includes(p.channel) && p.by) parts.push(safeText(p.by, 60))
  return parts.join(' · ')
})
</script>

<style scoped>
.prov { display: inline-flex; flex-wrap: wrap; gap: 3px 6px; align-items: center; }
.prov .badge { display: inline-flex; align-items: center; gap: 3px; }
.prov .badge .icon { width: 13px; height: 13px; }
</style>
