<template>
  <div class="checks">
    <div v-if="!checks || !Object.keys(checks).length" class="muted">{{ t('checks.not_run') }}</div>
    <template v-else>
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.checks.summary') }}</h3><SegBar :parts="summaryParts" :label="t('chart.checks.summary')" /></div>
        <div v-if="evParts"><h3 class="charthead">{{ evParts.title }}</h3><SegBar :parts="evParts.parts" :label="evParts.title" /></div>
        <div v-if="sbParts"><h3 class="charthead">{{ sbParts.title }}</h3><SegBar :parts="sbParts.parts" :label="sbParts.title" /></div>
      </div>
      <!-- static -->
      <div class="checkrow">
        <span class="badge" :class="okCls(checks.static)">{{ okText(checks.static) }}</span>
        <b>{{ t('checks.static') }}</b>
        <span v-if="checks.static && !checks.static.ok" class="muted">
          {{ tOr('change.reason.' + checks.static.error, tOr('error.' + checks.static.error, checks.static.error)) }}
          <span v-if="checks.static.details && Object.keys(checks.static.details).length" class="mono small">{{ safeText(JSON.stringify(checks.static.details), 300) }}</span>
        </span>
      </div>

      <!-- evidence -->
      <div v-if="ev" class="checkrow">
        <span class="badge" :class="ev.warning ? 'b-warn' : okCls(ev)">{{ ev.warning ? t('checks.warning') : okText(ev) }}</span>
        <b>{{ t('checks.evidence') }}</b>
        <span v-if="ev.skipped" class="muted">{{ t('checks.skipped') }}: {{ safeText(ev.skipped, 200) }}</span>
        <span v-if="ev.error" class="muted">{{ safeText(ev.error, 200) }}</span>
      </div>
      <div v-if="ev && ev.bundle" class="checkbody">
        <p class="muted small">{{ t('bundle.evidence_note') }}</p>
        <DataTable id="bundle-evidence" :columns="bundleEvCols" :rows="ev.bundle" :row-key="(r) => ev.bundle.indexOf(r)" :toolbar="false">
          <template #cell-ok="{ row }"><span class="badge" :class="okCls(row)">{{ okText(row) }}</span></template>
          <template #cell-what="{ row }">{{ t('op.' + row.op) }} · {{ t('kind.' + row.kind) }}</template>
          <template #cell-detail="{ row }"><span v-if="row.skipped" class="muted small">{{ safeText(row.skipped, 160) }}</span>
            <span v-else-if="row.scanned !== undefined" class="small">{{ t('evidence.external_success') }} {{ fmtNum(row.external_success) }} · {{ t('evidence.internal_other') }} {{ fmtNum(row.internal_other) }}</span>
            <span v-else-if="row.hits !== undefined" class="small">{{ t('evidence.rule_hits') }} {{ fmtNum(row.hits) }}</span>
            <span v-else-if="row.affected_events !== undefined" class="small">{{ t('evidence.affected_events') }} {{ fmtNum(row.affected_events) }}</span>
            <span v-if="row.error" class="muted small">{{ safeText(row.error, 160) }}</span></template>
        </DataTable>
      </div>
      <div v-if="ev && ev.scanned !== undefined" class="checkbody">
        <div class="minitiles">
          <span>{{ t('evidence.scanned') }} <b>{{ fmtNum(ev.scanned) }}</b></span>
          <span>{{ t('evidence.files') }} <b>{{ fmtNum(ev.files) }}</b></span>
          <span>{{ t('evidence.external_hits') }} <b>{{ fmtNum(ev.external_hits) }}</b></span>
          <span :class="{ warn: ev.external_success }">{{ t('evidence.external_success') }} <b>{{ fmtNum(ev.external_success) }}</b></span>
          <span :class="{ warn: ev.internal_other }">{{ t('evidence.internal_other') }} <b>{{ fmtNum(ev.internal_other) }}</b></span>
          <span>{{ t('evidence.internal_known') }} <b>{{ fmtNum(ev.internal_known) }}</b></span>
        </div>
        <div v-if="ev.complete === false" class="alert warn">{{ t('evidence.incomplete') }}</div>
        <p class="muted small">{{ t('evidence.block_rule') }}</p>
        <SampleTable v-if="(ev.external_success_samples || []).length" :title="t('evidence.external_success_samples')" :rows="ev.external_success_samples" :cols="['host', 'status', 'path', 'ua', 'count']" />
        <SampleTable v-if="(ev.internal_samples || []).length" :title="t('evidence.internal_samples')" :rows="ev.internal_samples" :cols="['host', 'status', 'ip', 'path', 'count']" />
        <SampleTable v-if="(ev.external_samples || []).length" :title="t('evidence.external_samples')" :rows="ev.external_samples" :cols="['host', 'status', 'path', 'count']" />
        <div v-if="(ev.sites || []).length" class="sub">{{ t('evidence.sites') }}:
          <span v-for="s in ev.sites" :key="s.host" class="chip host">{{ safeText(s.host, 80) }} {{ s.hits }}</span></div>
      </div>
      <div v-if="ev && ev.affected_events !== undefined" class="checkbody">
        <div class="minitiles">
          <span>{{ t('evidence.days', { n: ev.days }) }}</span>
          <span>{{ t('evidence.affected_events') }} <b>{{ fmtNum(ev.affected_events) }}</b></span>
          <span>{{ t('evidence.external') }} <b>{{ fmtNum(ev.external) }}</b></span>
          <span :class="{ warn: ev.external_attack_like }">{{ t('evidence.external_attack_like') }} <b>{{ fmtNum(ev.external_attack_like) }}</b></span>
        </div>
        <div v-if="ev.warning" class="alert warn">{{ t('evidence.attack_like_warning') }}</div>
        <ul v-if="(ev.attack_like_samples || []).length" class="plainlist small">
          <li v-for="s in ev.attack_like_samples" :key="s.id">
            <RouterLink :to="'/events/' + s.id" class="mono">#{{ s.id }}</RouterLink>
            <span class="mono breakall">{{ safeText(s.host, 100) }}{{ safeText(s.path, 200) }}</span>
            <span>{{ t('outcome.' + s.outcome) }} · <span class="mono">{{ (s.rules || []).join(', ') }}</span></span>
          </li>
        </ul>
      </div>
      <div v-if="ev && ev.hits !== undefined" class="checkbody minitiles">
        <span>{{ t('evidence.days', { n: ev.days }) }}</span>
        <span>{{ t('evidence.rule_hits') }} <b>{{ fmtNum(ev.hits) }}</b></span>
        <span>{{ t('evidence.rule_blocked') }} <b>{{ fmtNum(ev.blocked) }}</b></span>
      </div>

      <!-- sandbox -->
      <div v-if="sb" class="checkrow">
        <span class="badge" :class="okCls(sb)">{{ okText(sb) }}</span>
        <b>{{ t('checks.sandbox') }}</b>
        <span v-if="sb.skipped" class="muted">{{ t('checks.skipped') }}: {{ safeText(sb.skipped, 200) }}</span>
        <span v-if="sb.error" class="muted">{{ tOr('sandbox.error.' + sb.error, sb.error) }}</span>
      </div>
      <pre v-if="sb && sb.message" class="code small">{{ safeMultiline(sb.message) }}</pre>
      <div v-if="sb && sb.cases !== undefined" class="checkbody">
        <div class="minitiles">
          <span>{{ t('sandbox.cases') }} <b>{{ fmtNum(sb.cases) }}</b></span>
          <span :class="{ warn: sb.failed }">{{ t('sandbox.failed') }} <b>{{ fmtNum(sb.failed) }}</b></span>
          <span>{{ t('sandbox.regression_checked') }} <b>{{ fmtNum(sb.regression_checked) }}</b></span>
        </div>
        <DataTable v-if="(sb.results || []).length" id="sandbox-results" :columns="resultCols" :rows="sb.results" :row-key="(r) => sb.results.indexOf(r)">
          <template #cell-ok="{ row }"><span class="badge" :class="row.ok ? 'b-ok' : 'b-blocked'">{{ row.ok ? t('checks.ok') : t('checks.failed') }}</span></template>
          <template #cell-source="{ row }"><OriginBadge :origin="row.source" /></template>
          <template #cell-request="{ row }"><span class="mono breakall"><span class="method">{{ safeText(row.method, 10) }}</span> {{ safeText(row.host, 120) }}{{ safeText(row.path, 300) }}</span>
            <div v-if="row.note" class="sub warn">{{ safeText(row.note, 200) }}</div></template>
          <template #cell-expect="{ row }"><span class="mono">{{ row.expect === 'not403' ? t('sandbox.not403') : row.expect }}</span></template>
          <template #cell-status="{ row }"><span class="mono">{{ safeText(row.status, 40) }}</span></template>
          <template #cell-rules="{ row }"><span class="mono small">{{ (row.rules || []).join(', ') || '—' }}</span></template>
        </DataTable>
      </div>
      <div v-if="sb && sb.requests !== undefined" class="checkbody">
        <div class="minitiles">
          <span>{{ t('sandbox.equiv_requests') }} <b>{{ fmtNum(sb.requests) }}</b></span>
          <span>{{ t('sandbox.blocked_before') }} <b>{{ fmtNum(sb.blocked_before) }}</b></span>
          <span :class="{ warn: (sb.differences || []).length }">{{ t('sandbox.differences') }} <b>{{ fmtNum((sb.differences || []).length) }}</b></span>
          <template v-if="sb.blocked_after !== undefined">
            <span>{{ t('sandbox.blocked_after') }} <b>{{ fmtNum(sb.blocked_after) }}</b></span>
            <span :class="{ warn: sb.newly_blocked }">{{ t('sandbox.newly_blocked') }} <b>{{ fmtNum(sb.newly_blocked) }}</b></span>
            <span :class="{ warn: sb.no_longer_blocked }">{{ t('sandbox.no_longer_blocked') }} <b>{{ fmtNum(sb.no_longer_blocked) }}</b></span>
          </template>
        </div>
        <ul v-if="(sb.differences || []).length" class="plainlist small">
          <li v-for="(d, i) in sb.differences" :key="i">
            <span class="mono breakall">{{ safeText(d.request.method, 10) }} {{ safeText(d.request.host, 100) }}{{ safeText(d.request.path, 300) }}</span>
            <span class="mono">{{ safeText(JSON.stringify(d.before), 120) }} → {{ safeText(JSON.stringify(d.after), 120) }}</span>
          </li>
        </ul>
      </div>
      <div v-if="checks.finished_at" class="sub">{{ t('checks.finished_at') }} {{ fmtTime(checks.finished_at) }}</div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t, tOr } from '../i18n.js'
import { safeText, safeMultiline, fmtNum, fmtTime } from '../util.js'
import OriginBadge from './OriginBadge.vue'
import SampleTable from './SampleTable.vue'
import DataTable from './DataTable.vue'
import SegBar from './charts/SegBar.vue'
const bundleEvCols = computed(() => [
  { key: 'rule_id', label: t('wizard.rule_id'), align: 'num' },
  { key: 'what', label: t('change.what'), value: (r) => r.op + ' ' + r.kind },
  { key: 'ok', label: t('checks.evidence'), value: (r) => (r.ok ? 1 : 0) },
  { key: 'detail', label: t('bundle.detail'), sortable: false },
])

const props = defineProps({ checks: { type: Object, default: null } })
const ev = computed(() => props.checks && props.checks.evidence)
const sb = computed(() => props.checks && props.checks.sandbox)

const resultCols = computed(() => [
  { key: 'ok', label: t('checks.sandbox'), value: (r) => (r.ok ? t('checks.ok') : t('checks.failed')) },
  { key: 'origin', label: t('sandbox.origin'), nowrap: true, value: (r) => tOr('sandbox.origin.' + r.origin, r.origin) },
  { key: 'source', label: t('tests.source'), value: (r) => t('origin.' + (r.source === 'internal' ? 'internal' : 'external')) },
  { key: 'request', label: t('tests.request'), required: true, value: (r) => (r.host || '') + (r.path || ''), text: (r) => (r.method || '') + ' ' + (r.host || '') + (r.path || '') + ' ' + (r.note || '') },
  { key: 'expect', label: t('tests.expect'), value: (r) => String(r.expect) },
  { key: 'status', label: t('sandbox.status'), value: (r) => String(r.status) },
  { key: 'rules', label: t('sandbox.rules'), value: (r) => (r.rules || []).join(', ') },
])

// result of one check: ok | warn | fail | skip
function verdict(c) {
  if (!c) return null
  if (c.skipped) return 'skip'
  if (!c.ok) return 'fail'
  return c.warning ? 'warn' : 'ok'
}
const summaryParts = computed(() => {
  const v = [verdict(props.checks.static), verdict(ev.value), verdict(sb.value)].filter(Boolean)
  const n = (x) => v.filter((y) => y === x).length
  return [
    { key: 'ok', label: t('checks.ok'), value: n('ok'), tone: 'good' },
    { key: 'warn', label: t('checks.warning'), value: n('warn'), tone: 'warning' },
    { key: 'fail', label: t('checks.failed'), value: n('fail'), tone: 'critical' },
    { key: 'skip', label: t('checks.skipped'), value: n('skip'), tone: 'muted' },
  ]
})
const evParts = computed(() => {
  const e = ev.value
  if (!e) return null
  if (e.scanned !== undefined) {
    return { title: t('chart.checks.matches'), parts: [
      { key: 'ext', label: t('chart.ev.external_other'), value: Math.max(0, (e.external_hits || 0) - (e.external_success || 0)), tone: 's1' },
      { key: 'ok', label: t('evidence.external_success'), value: e.external_success || 0, tone: 'critical' },
      { key: 'int', label: t('evidence.internal_other'), value: e.internal_other || 0, tone: 'warning' },
      { key: 'known', label: t('evidence.internal_known'), value: e.internal_known || 0, tone: 'muted' },
    ] }
  }
  if (e.affected_events !== undefined) {
    return { title: t('chart.checks.affected'), parts: [
      { key: 'attack', label: t('evidence.external_attack_like'), value: e.external_attack_like || 0, tone: 'warning' },
      { key: 'ext', label: t('chart.ev.external_plain'), value: Math.max(0, (e.external || 0) - (e.external_attack_like || 0)), tone: 's1' },
      { key: 'int', label: t('chart.ev.internal'), value: Math.max(0, (e.affected_events || 0) - (e.external || 0)), tone: 's2' },
    ] }
  }
  if (e.hits !== undefined) {
    return { title: t('chart.checks.hits'), parts: [
      { key: 'blocked', label: t('outcome.blocked'), value: e.blocked || 0, tone: 'blocked' },
      { key: 'other', label: t('chart.ev.not_blocked'), value: Math.max(0, (e.hits || 0) - (e.blocked || 0)), tone: 'logged' },
    ] }
  }
  return null
})
const sbParts = computed(() => {
  const s = sb.value
  if (!s) return null
  if (s.cases !== undefined) {
    return { title: t('chart.checks.cases'), parts: [
      { key: 'ok', label: t('checks.ok'), value: Math.max(0, s.cases - (s.failed || 0)), tone: 'good' },
      { key: 'fail', label: t('checks.failed'), value: s.failed || 0, tone: 'critical' },
    ] }
  }
  // the API lists at most 50 differences: beyond that the split would be wrong, so no chart
  if (s.requests !== undefined && (s.differences || []).length < 50) {
    const d = (s.differences || []).length
    return { title: t('chart.checks.replayed'), parts: [
      { key: 'same', label: t('chart.ev.same'), value: Math.max(0, s.requests - d), tone: 'good' },
      { key: 'diff', label: t('sandbox.differences'), value: d, tone: 'critical' },
    ] }
  }
  return null
})

function okCls(c) {
  if (!c) return 'b-logged'
  if (c.skipped) return 'b-logged'
  return c.ok ? 'b-ok' : 'b-blocked'
}
function okText(c) {
  if (!c) return '—'
  if (c.skipped) return t('checks.skipped')
  return c.ok ? t('checks.ok') : t('checks.failed')
}
</script>
