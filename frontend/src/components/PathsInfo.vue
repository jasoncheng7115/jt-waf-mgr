<!-- Where the program, its configuration, data and records are (admin; from /settings). -->
<template>
  <section v-if="paths" class="card">
    <h2><Icon name="database" /> {{ t('paths.title') }}</h2>
    <dl class="kv two">
      <template v-for="k in KEYS" :key="k">
        <template v-if="paths[k]">
          <dt>{{ t('paths.' + k) }}</dt>
          <dd><CopyText :value="String(paths[k])" /></dd>
        </template>
      </template>
    </dl>
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
