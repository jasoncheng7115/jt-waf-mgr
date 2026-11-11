<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('event.detail_title') }} <span class="muted mono">#{{ safeText(id, 20) }}</span></h1>
      <RouterLink class="btn small ghost" :to="{ path: '/events' }"><Icon name="back" />{{ t('common.back') }}</RouterLink>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="!ev && !error" />
    <template v-if="ev">
      <FlowSteps :title="t('guide.evd.title')" :steps="flow" />
      <section class="card">
        <div class="reqline">
          <OutcomeBadge :outcome="ev.outcome" :decided-by="ev.decided_by" />
          <span class="method">{{ safeText(ev.method, 12) }}</span>
          <span class="mono breakall">{{ safeText(ev.host, 255) }}{{ safeText(pathWithQuery(ev), 4000) }}</span>
        </div>
        <dl class="kv two">
          <dt>{{ t('event.time') }}</dt><dd>{{ fmtTime(ev.ts) }}</dd>
          <dt>{{ t('event.status') }}</dt><dd class="mono">{{ ev.status }}</dd>
          <dt>{{ t('event.source') }}</dt>
          <dd><span class="mono">{{ safeText(ev.src_ip, 45) }}</span><template v-if="ev.client_port">:<span class="mono">{{ ev.client_port }}</span></template> <OriginBadge :origin="ev.origin" /> <GeoTag :geo="ev.src_geo" full /></dd>
          <dt>{{ t('event.host') }}</dt><dd class="mono breakall">{{ safeText(ev.host, 255) }}<template v-if="ev.server_port">:{{ ev.server_port }}</template></dd>
          <dt>{{ t('event.decided_by') }}</dt><dd>{{ ev.decided_by ? t('decided.' + ev.decided_by) : '—' }}</dd>
          <dt>{{ t('event.engine') }}</dt><dd class="mono">{{ safeText(ev.engine, 40) || '—' }}</dd>
          <dt>{{ t('event.anomaly_score') }}</dt><dd class="mono">{{ ev.anomaly_score === null || ev.anomaly_score === undefined ? '—' : ev.anomaly_score }}</dd>
          <dt>{{ t('event.http_version') }}</dt><dd class="mono">{{ safeText(ev.http_version, 10) || '—' }}</dd>
          <dt>{{ t('event.unique_id') }}</dt><dd class="mono breakall">{{ safeText(ev.unique_id, 300) }}</dd>
          <dt>{{ t('event.family') }}</dt>
          <dd><span v-for="fm in ev.families || []" :key="fm" class="chip fam">{{ t('family.' + fm) }}</span><template v-if="!(ev.families || []).length">—</template></dd>
        </dl>
        <p class="muted small">{{ t('event.redacted_note') }}</p>
        <div class="actions">
          <RouterLink class="btn small" :to="{ path: '/events', query: { src_ip: ev.src_ip } }"><Icon name="filter" />{{ t('event.same_ip') }}</RouterLink>
          <RouterLink class="btn small" :to="{ path: '/events', query: { host: ev.host } }"><Icon name="globe" />{{ t('event.same_host') }}</RouterLink>
          <RouterLink v-if="mainRule" class="btn small" :to="{ path: '/events', query: { rule_id: mainRule } }"><Icon name="shield" />{{ t('event.same_rule', { id: mainRule }) }}</RouterLink>
          <RouterLink class="btn small" :to="'/lookup/' + encodeURIComponent(ev.src_ip)"><Icon name="search" />{{ t('event.ip_lookup') }}</RouterLink>
        </div>
        <div v-if="canPropose" class="actions">
          <RouterLink class="btn small primary" :to="{ path: '/changes/new', query: { from_event: ev.id, mode: 'exclusion' } }"><Icon name="add" />{{ t('event.create_exclusion') }}</RouterLink>
          <RouterLink class="btn small" :to="{ path: '/changes/new', query: { from_event: ev.id, mode: 'block' } }"><Icon name="block" />{{ t('event.create_block') }}</RouterLink>
          <span class="muted small">{{ t('event.create_hint') }}</span>
        </div>
      </section>

      <section class="card">
        <h2>{{ t('event.matches') }} <span class="count">{{ (ev.matches || []).length }}</span></h2>
        <div v-if="ev.truncated" class="alert info">{{ t('event.truncated') }}</div>
        <div v-if="(ev.matches || []).length" class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.match_severity') }}</h3><SegBar :parts="severityParts" :label="t('chart.match_severity')" /></div>
        </div>
        <DataTable id="event-matches" :columns="matchCols" :rows="ev.matches || []" row-key="_row" :row-class="(m) => ({ localrule: m.local })">
          <template #cell-rule_id="{ row }">
            <RouterLink class="mono" :to="'/rules/' + row.rule_id">{{ row.rule_id }}</RouterLink>
            <div v-if="row.family" class="sub"><span class="chip fam">{{ t('family.' + row.family) }}</span></div>
          </template>
          <template #cell-message="{ row }">
            <div>{{ safeText(row.message, 500) }}</div>
            <div v-if="row.tags && row.tags.length" class="sub">
              <span v-for="tg in row.tags" :key="tg" class="chip tag">{{ safeText(tg, 60) }}</span>
            </div>
            <div v-if="row.file" class="sub mono" :title="safeText(row.file, 500)">{{ shortFile(row.file) }}<template v-if="row.line">:{{ row.line }}</template></div>
          </template>
          <template #cell-data="{ row }"><pre class="data">{{ safeMultiline(row.data) }}</pre></template>
        </DataTable>
      </section>
    </template>
  </div>
</template>

<script setup>
import GeoTag from '../components/GeoTag.vue'
import { ref, computed, watch } from 'vue'
import { get } from '../api.js'
import { hasRole } from '../store.js'
import { t } from '../i18n.js'
import { safeText, safeMultiline, fmtTime, pathWithQuery } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import OutcomeBadge from '../components/OutcomeBadge.vue'
import OriginBadge from '../components/OriginBadge.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'

const props = defineProps({ id: { type: String, required: true } })
const ev = ref(null)
const canPropose = computed(() => hasRole('operator'))
const error = ref(null)

const SCORING = new Set([949110, 959100, 980170, 980130, 980140, 980145, 980150])
const mainRule = computed(() => {
  if (!ev.value) return null
  const ids = (ev.value.local_rule_ids && ev.value.local_rule_ids.length) ? ev.value.local_rule_ids : (ev.value.rule_ids || [])
  return ids.find((r) => !SCORING.has(r)) || ids[0] || null
})

const SEVERITIES = [['CRITICAL', 'critical'], ['ERROR', 'serious'], ['WARNING', 'warning'], ['NOTICE', 's1']]
const SEV_ORDER = { EMERGENCY: 0, ALERT: 1, CRITICAL: 2, ERROR: 3, WARNING: 4, NOTICE: 5, INFO: 6, DEBUG: 7 }
const matchCols = computed(() => [
  { key: 'rule_id', label: t('rule.id'), nowrap: true, required: true, text: (m) => m.rule_id + ' ' + (m.family ? t('family.' + m.family) : '') },
  { key: 'severity', label: t('rule.severity'), nowrap: true, value: (m) => SEV_ORDER[m.severity] ?? 9, text: (m) => m.severity || '' },
  { key: 'message', label: t('rule.message'), text: (m) => [m.message, ...(m.tags || []), m.file || ''].join(' ') },
  { key: 'data', label: t('event.matched_data'), sortable: false },
])
const severityParts = computed(() => {
  const ms = ev.value.matches || []
  const known = new Set(SEVERITIES.map((s) => s[0]))
  const parts = SEVERITIES.map(([k, tone]) => ({ key: k, label: k.toLowerCase(), value: ms.filter((m) => m.severity === k).length, tone }))
  const rest = ms.filter((m) => !known.has(m.severity)).length
  if (rest) parts.push({ key: 'none', label: t('chart.no_severity'), value: rest, tone: 'muted' })
  return parts.filter((p) => p.value > 0)
})

// where this event stands: what happened (done) and the operator's next step
const flow = computed(() => {
  const e = ev.value
  const score = e.anomaly_score === null || e.anomaly_score === undefined ? '—' : e.anomaly_score
  const blocked = e.outcome === 'blocked'
  return [
    { key: 'src', label: t('guide.evd.source', { ip: safeText(e.src_ip, 45) }), desc: t('origin.' + (e.origin || 'external')) + ' · ' + safeText(e.host, 80), icon: 'globe', state: 'done' },
    { key: 'matched', label: t('guide.evd.matched', { n: (e.matches || []).length }), desc: (e.families || []).map((f) => t('family.' + f)).join(', '), icon: 'shield', state: 'done' },
    { key: 'score', label: t('guide.evd.score', { n: score }), icon: 'chart', state: 'done' },
    { key: 'result', label: t(blocked ? 'guide.evd.blocked' : 'guide.evd.logged', { status: e.status ?? '—' }),
      desc: e.decided_by ? t('event.decided_by') + ': ' + t('decided.' + e.decided_by) : '', icon: blocked ? 'block' : 'page', state: 'done' },
    { key: 'decide', label: t('guide.evd.decide'), desc: t('guide.evd.decide_d'), icon: 'help', state: 'current' },
  ]
})

function shortFile(f) {
  const s = String(f || '')
  const i = s.lastIndexOf('/')
  return safeText(i >= 0 ? s.slice(i + 1) : s, 120)
}

async function load() {
  ev.value = null
  error.value = null
  try { ev.value = await get('/events/' + encodeURIComponent(props.id)) } catch (e) { error.value = e }
}
watch(() => props.id, load, { immediate: true })
</script>
