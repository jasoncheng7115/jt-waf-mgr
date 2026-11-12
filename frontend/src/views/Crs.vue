<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('crs.title') }}</h1>
      <button type="button" class="btn small ghost" :class="{ on: showGuide }" :aria-pressed="showGuide ? 'true' : 'false'" @click="toggleGuide"><Icon name="help" />{{ t('guide.how') }}</button>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="!crs && !error" />
    <template v-if="crs">
      <div v-if="crs.warnings && crs.warnings.length" class="alert warn">
        <div v-for="(w, i) in crs.warnings" :key="i">{{ safeText(w, 500) }}</div>
      </div>
      <FlowSteps v-if="showGuide" :title="t('guide.crs.title')" :steps="flow" />
      <div v-if="wafModel" class="alert wafeffective">
        <span><Icon name="info" /> {{ t('waf.crs_effective', { mode: wafModel.engine.global, ext: wafMode(wafModel.summary.external), int: wafMode(wafModel.summary.internal) }) }}</span>
        <RouterLink class="btn small" to="/waf"><Icon name="go" />{{ t('waf.crs_link') }}</RouterLink>
      </div>
      <div class="tiles">
        <div class="tile"><div class="tl">{{ t('crs.version') }}</div><div class="tv">{{ safeText(crs.version, 20) || '—' }}</div></div>
        <div class="tile"><div class="tl">{{ t('crs.engine_mode') }}</div><div class="tv small">{{ safeText(crs.engine_mode, 30) || '—' }}</div>
          <div v-if="wafModel" class="ts"><RouterLink to="/waf">{{ t('waf.lane.external') }}{{ t('waf.sum.colon') }}{{ wafMode(wafModel.summary.external) }}</RouterLink></div></div>
        <div class="tile"><div class="tl">{{ t('crs.paranoia_level') }}</div><div class="tv">{{ crs.blocking_paranoia_level ?? crs.paranoia_level ?? '—' }}</div>
          <div class="ts">{{ t('crs.detection_paranoia') }} {{ crs.detection_paranoia_level ?? '—' }}</div></div>
        <div class="tile"><div class="tl">{{ t('crs.thresholds') }}</div><div class="tv">{{ crs.inbound_threshold ?? '—' }} / {{ crs.outbound_threshold ?? '—' }}</div>
          <div class="ts">{{ t('crs.inbound_outbound') }}</div></div>
        <div class="tile"><div class="tl">{{ t('crs.rules') }}</div><div class="tv">{{ fmtNum(crs.rule_count) }}</div><div class="ts">{{ t('crs.rule_files', { n: fmtNum(crs.rule_files) }) }}</div></div>
      </div>
      <section class="card">
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.paranoia_blocking') }}</h3>
            <Meter :value="blockingPl" :max="4" :warn-at="2" :crit-at="2" :label="t('chart.paranoia_blocking')" :text="t('chart.level_of', { n: blockingPl, max: 4 })" /></div>
          <div><h3 class="charthead">{{ t('chart.paranoia_detection') }}</h3>
            <Meter :value="detectionPl" :max="4" :warn-at="2" :crit-at="2" :label="t('chart.paranoia_detection')" :text="t('chart.level_of', { n: detectionPl, max: 4 })" /></div>
        </div>
      </section>
      <div class="cols2">
        <section class="card">
          <h2>{{ t('crs.engine') }}</h2>
          <dl class="kv">
            <dt>{{ t('crs.path') }}</dt><dd class="mono breakall">{{ safeText(crs.path, 300) }}</dd>
            <dt>{{ t('crs.setup_file') }}</dt><dd class="mono breakall">{{ safeText(crs.setup_file, 300) }}</dd>
            <dt>{{ t('crs.request_body_access') }}</dt><dd>{{ crs.request_body_access ? t('common.yes') : t('common.no') }}</dd>
            <dt>{{ t('crs.request_body_limit') }}</dt><dd class="mono">{{ crs.request_body_limit ? fmtBytes(crs.request_body_limit) : '—' }}
              <template v-if="crs.request_body_limit_action">({{ safeText(crs.request_body_limit_action, 30) }})</template></dd>
            <dt>{{ t('crs.pcre_match_limit') }}</dt><dd class="mono">{{ crs.pcre_match_limit ?? '—' }}</dd>
          </dl>
        </section>
        <section class="card">
          <h2>{{ t('crs.audit') }}</h2>
          <dl v-if="crs.audit" class="kv">
            <dt>{{ t('crs.audit_engine') }}</dt><dd class="mono">{{ safeText(crs.audit.engine, 30) || '—' }}</dd>
            <dt>{{ t('crs.audit_parts') }}</dt><dd class="mono">{{ safeText(crs.audit.parts, 30) || '—' }}</dd>
            <dt>{{ t('crs.audit_format') }}</dt><dd class="mono">{{ safeText(crs.audit.format, 30) || '—' }}</dd>
            <dt>{{ t('crs.audit_log') }}</dt><dd class="mono breakall">{{ safeText(crs.audit.log, 300) || '—' }}</dd>
            <dt>{{ t('crs.audit_relevant_status') }}</dt><dd class="mono">{{ safeText(crs.audit.relevant_status, 60) || '—' }}</dd>
          </dl>
        </section>
      </div>
      <section class="card">
        <h2>{{ t('crs.plugins') }} <span class="count">{{ (crs.plugins || []).length }}</span></h2>
        <ul class="plainlist">
          <li v-for="p in crs.plugins || []" :key="p.name">
            <span class="mono">{{ safeText(p.name, 120) }}</span>
            <span class="muted small mono">{{ (p.files || []).map((f) => safeText(f, 120)).join(', ') }}</span>
          </li>
          <li v-if="!(crs.plugins || []).length" class="empty small">{{ t('common.no_data') }}</li>
        </ul>
      </section>
      <StatusCard />
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { get } from '../api.js'
import { t } from '../i18n.js'
import { safeText, fmtNum, fmtBytes } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import StatusCard from '../components/StatusCard.vue'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'
import Meter from '../components/charts/Meter.vue'

const crs = ref(null)
const error = ref(null)

const blockingPl = computed(() => Number(crs.value.blocking_paranoia_level ?? crs.value.paranoia_level ?? 1) || 1)
const detectionPl = computed(() => Number(crs.value.detection_paranoia_level ?? blockingPl.value) || blockingPl.value)

const GUIDE_KEY = 'jtwaf.guide.crs'
function readFlag(k, d) { try { const v = window.localStorage.getItem(k); return v === null ? d : v === '1' } catch { return d } }
const showGuide = ref(readFlag(GUIDE_KEY, true))
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage unavailable */ }
}
const flow = computed(() => [
  { key: 'pl', label: t('guide.crs.pl', { n: blockingPl.value }), desc: t('guide.crs.pl_d'), icon: 'settings' },
  { key: 'points', label: t('guide.crs.points'), desc: t('guide.crs.points_d'), icon: 'add' },
  { key: 'compare', label: t('guide.crs.compare'), desc: t('guide.crs.compare_d', { n: crs.value.inbound_threshold ?? 5 }), icon: 'chart', to: '/rules/949110' },
  { key: 'result', label: t('guide.crs.result'), desc: t('guide.crs.result_d'), icon: 'block' },
  { key: 'events', label: t('guide.ev.list'), desc: t('guide.ev.list_d'), icon: 'list', to: '/events' },
])
// the effective behaviour (site rules can block while the global engine only logs): from /waf/model
const wafModel = ref(null)
function wafMode(sm) {
  if (!sm) return '—'
  return sm.min_block_score !== null && sm.mode !== 'off' ? t('waf.mode.blocking', { n: sm.min_block_score }) : t('waf.mode.' + sm.mode)
}
onMounted(() => { get('/waf/model').then((m) => { wafModel.value = m }).catch(() => { /* the page works without it */ }) })
onMounted(async () => {
  try { crs.value = await get('/crs') } catch (e) { error.value = e }
})
</script>

<style scoped>
.wafeffective { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; border: 1px solid var(--border-strong); background: var(--panel-2); color: var(--text); }
</style>
