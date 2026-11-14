<!-- /status: collector health and versions. -->
<template>
  <section class="card">
    <h2><Icon name="info" /> {{ t('status.title') }}</h2>
    <ErrorBox :error="error" />
    <dl v-if="s" class="kv two">
      <dt>{{ t('status.version') }}</dt><dd class="mono">{{ safeText(s.version, 30) }}</dd>
      <dt>{{ t('status.node') }}</dt><dd class="mono">{{ safeText(s.node_id, 60) }}</dd>
      <dt>{{ t('crs.engine_mode') }}</dt><dd class="mono">{{ safeText(s.engine_mode, 30) || '—' }}</dd>
      <dt>{{ t('status.external_threshold_block') }}</dt><dd>{{ s.external_threshold_block ? t('common.yes') : t('common.no') }}</dd>
      <dt>{{ t('status.nginx') }}</dt><dd class="mono">{{ s.nginx && s.nginx.version ? safeText(s.nginx.version, 30) : '—' }}
        <span v-if="s.nginx && s.nginx.module_mismatch === true" class="badge b-blocked">{{ t('status.module_mismatch') }}</span></dd>
      <template v-if="s.collector">
        <dt>{{ t('status.collector') }}</dt>
        <dd><span class="badge" :class="s.collector.running ? 'b-ok' : 'b-blocked'">{{ s.collector.running ? t('status.running') : t('status.stopped') }}</span>
          <span class="mono small breakall gapl">{{ safeText(s.collector.audit_log, 300) }}</span></dd>
        <dt>{{ t('status.last_event') }}</dt><dd>{{ fmtTime(s.collector.last_event_at) }}</dd>
        <dt>{{ t('status.lag') }}</dt><dd class="mono">{{ s.collector.lag_seconds ?? '—' }}</dd>
        <dt>{{ t('status.events_total') }}</dt><dd class="mono">{{ fmtNum(s.collector.events_total) }}</dd>
        <dt>{{ t('status.parse_errors') }}</dt><dd class="mono" :class="{ warn: s.collector.parse_errors > 0 }">{{ fmtNum(s.collector.parse_errors) }}</dd>
        <dt>{{ t('status.oversized') }}</dt><dd class="mono" :class="{ warn: s.collector.oversized > 0 }">{{ fmtNum(s.collector.oversized) }}</dd>
      </template>
    </dl>
  </section>
</template>

<script setup>
import Icon from './Icon.vue'
import { ref, onMounted } from 'vue'
import { get } from '../api.js'
import { t } from '../i18n.js'
import { safeText, fmtNum, fmtTime } from '../util.js'
import ErrorBox from './ErrorBox.vue'

const s = ref(null)
const error = ref(null)
onMounted(async () => {
  try { s.value = await get('/status') } catch (e) { error.value = e }
})
</script>
