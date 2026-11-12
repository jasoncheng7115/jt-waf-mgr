<!-- Where the program, its configuration, data and records are (admin; from /settings). -->
<template>
  <section v-if="paths" class="card">
    <h2><Icon name="database" /> {{ t('paths.title') }}</h2>
    <div class="pathgrid">
      <template v-for="k in KEYS" :key="k">
        <div v-if="paths[k]" class="pathrow">
          <div class="pathlabel">{{ t('paths.' + k) }}</div>
          <CopyText :value="String(paths[k])" />
        </div>
      </template>
    </div>
  </section>
</template>

<script setup>
import { t } from '../i18n.js'
import Icon from './Icon.vue'
import CopyText from './CopyText.vue'

defineProps({ paths: { type: Object, default: null } })
const KEYS = ['program', 'command', 'config', 'data_dir', 'database', 'backups', 'audit_anchors', 'modsecurity_audit_log',
  'syslog', 'service_log', 'managed_rules', 'nginx_conf', 'geoip', 'spool', 'apply_state', 'sandbox']
</script>

<style scoped>
.pathgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(560px, 100%), 1fr)); column-gap: 28px; }
.pathrow { display: grid; grid-template-columns: minmax(8em, 13em) minmax(0, 1fr); gap: 12px; align-items: center;
  padding: 7px 0; border-bottom: 1px solid var(--border); }
.pathlabel { color: var(--muted); font-size: 13.5px; line-height: 1.35; }
.pathrow :deep(.copytext) { align-items: center; }
.pathrow :deep(.copytext code) { padding: 4px 8px; font-size: 13.5px; }
@media (max-width: 760px) { .pathrow { grid-template-columns: minmax(0, 1fr); gap: 4px; } }
</style>
