<!-- GeoIP databases: what is installed, when it was built, the last update, and "update now".
     The web service only queues the request; a separate sandboxed unit downloads and verifies. -->
<template>
  <section class="card">
    <h2><Icon name="globe" /> {{ t('geoip.title') }}</h2>
    <FlowSteps compact :steps="steps" :note="t('geoip.how_note')" />
    <ErrorBox :error="error" />
    <template v-if="st">
      <p v-if="!st.configured" class="alert info">{{ t('geoip.not_configured', { file: '/etc/jt-waf-mgr/config.toml', key: '/etc/jt-waf-mgr/maxmind-license.key' }) }}</p>
      <DataTable id="geoip-editions" :columns="cols" :rows="st.editions" row-key="edition" :toolbar="false">
        <template #cell-present="{ row }"><span class="badge" :class="row.present ? 'b-ok' : 'b-warn'">{{ row.present ? t('geoip.present') : t('geoip.missing') }}</span></template>
        <template #cell-size="{ row }">{{ row.size ? fmtBytes(row.size) : '—' }}</template>
        <template #cell-built_at="{ row }">{{ fmtDate(row.built_at) }}</template>
        <template #cell-last_error="{ row }"><span v-if="row.last_error" class="small warn">{{ safeText(row.last_error, 200) }}</span><span v-else>—</span></template>
      </DataTable>
      <p class="muted small">{{ t('geoip.last_run', { at: st.last_run ? fmtMinute(st.last_run) : '—', days: st.update_days }) }}
        <span v-if="st.last_ok === false" class="badge b-blocked">{{ t('geoip.last_failed') }}</span>
        <span v-if="st.requested" class="badge b-warn">{{ t('geoip.queued') }}</span></p>
      <div class="actions">
        <button type="button" class="btn small" :disabled="busy || !st.configured || st.requested" @click="update"><Icon name="download" />{{ t('geoip.update_now') }}</button>
        <button type="button" class="btn small ghost" :disabled="busy" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
      </div>
    </template>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { get, post } from '../api.js'
import { t } from '../i18n.js'
import { fmtBytes, fmtDate, fmtMinute, safeText } from '../util.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'
import DataTable from './DataTable.vue'
import FlowSteps from './FlowSteps.vue'

const st = ref(null)
const error = ref(null)
const busy = ref(false)
const cols = computed(() => [
  { key: 'edition', label: t('geoip.edition'), required: true },
  { key: 'present', label: t('geoip.state'), value: (r) => r.present },
  { key: 'built_at', label: t('geoip.built'), nowrap: true },
  { key: 'size', label: t('geoip.size'), align: 'num' },
  { key: 'last_error', label: t('geoip.error'), sortable: false },
])
const steps = computed(() => [
  { key: 'key', icon: 'key', label: t('geoip.step_key'), state: st.value ? (st.value.configured ? 'done' : 'current') : 'todo' },
  { key: 'dl', icon: 'download', label: t('geoip.step_download') },
  { key: 'verify', icon: 'verify', label: t('geoip.step_verify') },
  { key: 'use', icon: 'globe', label: t('geoip.step_use'), state: st.value && st.value.editions.some((e) => e.present) ? 'done' : 'todo' },
])
async function load() {
  error.value = null
  try { st.value = await get('/geoip') } catch (e) { error.value = e }
}
async function update() {
  busy.value = true
  try { st.value = await post('/geoip/update') } catch (e) { error.value = e } finally { busy.value = false }
}
onMounted(load)
</script>
