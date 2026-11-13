<!-- Scheduled event analysis with the local LLM: how it works, status, runs, and one run in detail.
     Paths, hosts, rule messages, the model's reasons and reply are attacker / model controlled: text only. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('analysis.title') }}</h1>
      <button type="button" class="btn small ghost" :aria-pressed="showGuide ? 'true' : 'false'" @click="showGuide = !showGuide"><Icon name="help" />{{ t('guide.wf.toggle') }}</button>
      <button type="button" class="btn small ghost" :disabled="loading" @click="reload"><Icon name="refresh" />{{ t('common.refresh') }}</button>
      <RouterLink class="btn small ghost" to="/changes"><Icon name="change" />{{ t('nav.changes') }}</RouterLink>
    </div>
    <p class="muted">{{ t('analysis.intro') }}</p>
    <div class="alert info aidisclaimer" role="note"><Icon name="info" /> {{ t('analysis.disclaimer') }}</div>
    <section v-if="showGuide" class="card">
      <FlowSteps :title="t('guide.analysis.title')" :steps="guideSteps" :note="t('guide.analysis.note')" />
    </section>
    <ErrorBox :error="error" />
    <Loading v-if="!st && !error" />

    <section v-if="st" class="card">
      <h2><Icon name="info" /> {{ t('analysis.status') }}</h2>
      <div v-if="!st.ready" class="alert warn">
        <Icon name="warning" /> {{ tOr('analysis.why.' + st.not_ready_reason, st.not_ready_reason) }}
        {{ isAdmin ? t('analysis.settings_hint_admin') : t('analysis.settings_hint') }}
      </div>
      <dl class="kv two">
        <dt>{{ t('analysis.enabled') }}</dt>
        <dd><span class="badge" :class="st.enabled ? 'b-ok' : 'b-logged'">{{ st.enabled ? t('analysis.on') : t('analysis.off') }}</span></dd>
        <dt>{{ t('analysis.llm') }}</dt>
        <dd><span class="badge" :class="st.llm_enabled ? 'b-ok' : 'b-logged'">{{ st.llm_enabled ? t('analysis.on') : t('analysis.off') }}</span>
          <span class="badge" :class="st.configured ? 'b-ok' : 'b-warn'">{{ st.configured ? t('analysis.configured') : t('analysis.not_configured') }}</span></dd>
        <dt>{{ t('analysis.model') }}</dt><dd class="mono">{{ safeText(st.model, 120) || '—' }}</dd>
        <dt>{{ t('analysis.key') }}</dt><dd>{{ st.key_set ? t('analysis.set') : t('analysis.not_set') }}</dd>
        <dt>{{ t('analysis.schedule') }}</dt><dd>{{ t('analysis.schedule_v', { every: everyText(st.interval_minutes), w: st.window_hours }) }}</dd>
        <dt>{{ t('analysis.thresholds') }}</dt><dd>{{ t('analysis.thresholds_v', { e: st.min_events, s: st.min_sources, c: st.max_candidates }) }}</dd>
        <dt>{{ t('analysis.proposal_rules') }}</dt><dd>{{ t('analysis.proposal_rules_v', { c: st.min_confidence, m: st.max_proposals }) }}</dd>
        <dt>{{ t('analysis.next_run') }}</dt>
        <dd>{{ st.next_due ? t('analysis.next_run_v', { at: fmtMinute(st.next_due) }) : '—' }}
          <span v-if="st.running" class="badge b-int">{{ t('analysis.running') }}</span>
          <span v-else-if="st.requested" class="badge b-int">{{ t('analysis.requested') }}</span></dd>
        <dt>{{ t('analysis.last_run') }}</dt>
        <dd><template v-if="st.last_run"><RouterLink :to="'/analysis/' + st.last_run.id">{{ fmtMinute(st.last_run.started_at) }}</RouterLink>
          <span class="badge" :class="st.last_run.error ? 'b-blocked' : 'b-ok'">{{ st.last_run.error ? t('analysis.failed') : t('analysis.ok') }}</span></template>
          <template v-else>{{ t('analysis.never') }}</template></dd>
      </dl>
      <div class="actions">
        <button v-if="isAdmin" type="button" class="btn primary" :disabled="busy || !st.ready || st.running || st.requested" @click="runNow"><Icon name="run" />{{ t('analysis.run_now') }}</button>
        <RouterLink v-if="isAdmin" class="btn ghost" :to="{ path: '/admin/settings', hash: st && st.configured ? '#uiset-analyst' : '#uiset-llm' }"><Icon name="settings" />{{ t('analysis.open_settings') }}</RouterLink>
      </div>
      <div v-if="active || justDone" class="live" role="status" aria-live="polite">
        <FlowSteps compact :steps="liveSteps" />
        <p class="livetext"><Icon :name="active ? 'timer' : 'check'" /> {{ liveText }}
          <RouterLink v-if="justDone && st.last_run" :to="'/analysis/' + st.last_run.id">{{ t('analysis.live.see_result') }}</RouterLink></p>
      </div>
      <ErrorBox :error="actionError" />
    </section>

    <!-- what the analysis found, in plain words: the newest run, then the runs loaded below -->
    <section v-if="st && st.enabled && latest" class="card summarycard">
      <h2><Icon name="report" /> {{ t('analysis.summary') }}</h2>
      <p class="sumlead">
        <RouterLink :to="'/analysis/' + latest.id">{{ t('analysis.sum.run', { id: latest.id, at: fmtMinute(latest.started_at) }) }}</RouterLink><span>{{ t('analysis.sum.lead', { e: latest.events_scanned == null ? '—' : fmtNum(latest.events_scanned), h: latest.window_hours, d: durText(latest.seconds) }) }}</span>
        <span v-if="latest.error" class="badge b-blocked">{{ t('analysis.failed') }}</span></p>
      <div class="sumtiles">
        <div class="sumtile"><b>{{ fmtNum(latestProbe.length) }}</b><span>{{ t('analysis.sum.probe_cands') }}</span></div>
        <div class="sumtile"><b>{{ fmtNum(countVerdict(latestProbe, 'attack_probe')) }}</b><span>{{ t('analysis.sum.attacks') }}</span></div>
        <div class="sumtile"><b>{{ fmtNum(latestFp.length) }}</b><span>{{ t('analysis.sum.fp_cands') }}</span></div>
        <div class="sumtile"><b>{{ fmtNum(countVerdict(latestFp, 'false_positive')) }}</b><span>{{ t('analysis.sum.fps') }}</span></div>
        <div class="sumtile"><b>{{ fmtNum(latestDetail ? latestDetail.proposal_list.length : latest.proposals) }}</b><span>{{ t('analysis.sum.proposals') }}</span></div>
        <div class="sumtile" :class="{ hot: latestAlerts.length }"><b>{{ fmtNum(latestAlerts.length) }}</b><span>{{ t('analysis.sum.alerts') }}</span></div>
      </div>
      <template v-if="latestDetail">
        <ul v-if="findings.length" class="findings">
          <li v-for="f in findings" :key="f.key">
            <span class="badge" :class="f.cls">{{ f.tag }}</span>
            <span v-if="f.where" class="mono small breakall">{{ f.where }}</span>
            <RouterLink v-if="f.change" :to="'/changes/' + f.change">{{ t('analysis.proposed', { id: f.change }) }}</RouterLink>
            <div v-if="f.reason" class="sub reason">{{ f.reason }}</div>
          </li>
        </ul>
        <p v-else class="muted">{{ latestProbe.length || latestFp.length ? t('analysis.sum.nothing_found') : t('analysis.sum.no_candidates') }}</p>
      </template>
      <p v-if="runs.length > 1" class="muted small">{{ t('analysis.sum.totals', { n: runs.length, e: fmtNum(totals.events), c: fmtNum(totals.candidates), p: fmtNum(totals.proposals), a: fmtNum(totals.alerts) }) }}</p>
    </section>

    <section v-if="runs.length" class="card">
      <h2><Icon name="history" /> {{ t('analysis.runs') }} <span class="count">{{ runs.length }}</span></h2>
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.analysis.verdicts') }}</h3><SegBar :parts="verdictParts(allVerdicts)" :label="t('chart.analysis.verdicts')" /></div>
        <div><h3 class="charthead">{{ t('chart.analysis.families') }}</h3><HBars :items="familyItems(allFamilies)" :series="candSeries" /></div>
        <div class="wide"><h3 class="charthead">{{ t('chart.analysis.runs') }}</h3><TimeBars :data="runBars" :series="runSeries" :label="t('chart.analysis.runs')" /></div>
      </div>
    </section>
    <section v-else-if="st && !loading" class="card"><p class="muted">{{ t('analysis.no_runs') }}</p></section>

    <DataTable :has-more="!!cursor" :loading-more="loading" @more="more" v-if="runs.length" id="analysis-runs" :columns="runCols" :rows="runs" row-key="id" :default-sort="{ key: 'id', dir: -1 }"
               clickable :row-class="(r) => ({ active: sel && r.id === sel.id })" @row-click="(r) => router.push('/analysis/' + r.id)">
      <template #cell-id="{ row }"><RouterLink :to="'/analysis/' + row.id">#{{ row.id }}</RouterLink></template>
      <template #cell-started_at="{ row }">{{ fmtShortTime(row.started_at) }}</template>
      <template #cell-trigger="{ row }">{{ tOr('analysis.trigger.' + row.trigger, row.trigger) }}</template>
      <template #cell-model="{ row }"><span class="mono">{{ safeText(row.model, 60) }}</span></template>
      <template #cell-verdicts="{ row }"><span class="small">{{ verdictText(row.verdicts) }}</span></template>
      <template #cell-seconds="{ row }"><span class="nowrap">{{ durText(row.seconds) }}</span></template>
      <template #cell-result="{ row }"><span class="badge" :class="row.error ? 'b-blocked' : row.finished_at ? 'b-ok' : 'b-int'">{{ row.error ? t('analysis.failed') : row.finished_at ? t('analysis.ok') : t('analysis.running') }}</span>
        <div v-if="row.error" class="sub"><TruncText :text="row.error" :max="120" /></div></template>
    </DataTable>

    <section v-if="selError" class="card"><ErrorBox :error="selError" /></section>
    <template v-if="sel">
      <section ref="detailEl" class="card">
        <div class="pagehead sub-head">
          <h2><Icon name="report" /> {{ t('analysis.run_title', { id: sel.id }) }}</h2>
          <RouterLink class="btn small ghost" to="/analysis"><Icon name="close" />{{ t('common.dismiss') }}</RouterLink>
        </div>
        <p class="runfacts"><span><Icon name="list" /> {{ t('analysis.events_scanned', { n: sel.events_scanned == null ? '—' : fmtNum(sel.events_scanned), h: sel.window_hours }) }}</span>
          <span><Icon name="timer" /> {{ t('analysis.took', { d: durText(sel.seconds) }) }}</span></p>
        <p class="muted small">{{ t('analysis.run_meta', { at: fmtMinute(sel.started_at), model: safeText(sel.model, 60) || '—', secs: sel.llm_seconds ?? '—', chars: fmtNum(sel.prompt_chars || 0) }) }}
          <template v-if="sel.usage && sel.usage.prompt_tokens"> · {{ t('analysis.tokens', { p: fmtNum(sel.usage.prompt_tokens), c: fmtNum(sel.usage.completion_tokens || 0) }) }}</template></p>
        <FlowSteps compact :steps="runSteps" />
        <p v-if="sel.error" class="alert error"><Icon name="alert" /> {{ t('analysis.run_error', { error: safeText(sel.error, 300) }) }}</p>
        <p class="muted small"><Icon name="info" /> {{ t('analysis.untrusted_note') }}</p>
        <div v-if="sel.candidates.length" class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.analysis.verdicts') }}</h3><SegBar :parts="verdictParts(sel.verdicts)" :label="t('chart.analysis.verdicts')" /></div>
          <div><h3 class="charthead">{{ t('chart.analysis.outcome') }}</h3><SegBar :parts="outcomeParts" :label="t('chart.analysis.outcome')" /></div>
          <div><h3 class="charthead">{{ t('chart.analysis.families') }}</h3><HBars :items="familyItems(selFamilies)" :series="candSeries" /></div>
          <div><h3 class="charthead">{{ t('chart.analysis.sources') }}</h3><HBars :items="sourceItems" :series="sourceSeries" mono /></div>
        </div>
      </section>

      <section v-if="selAlerts.length" class="card">
        <h2><Icon name="bell" /> {{ t('analysis.alerts') }} <span class="count">{{ selAlerts.length }}</span></h2>
        <p class="muted small">{{ t('analysis.alerts_hint') }}</p>
        <ul class="plainlist alertgrid">
          <li v-for="a in selAlerts" :key="a.alert_id" class="alertline">
            <span><span class="badge" :class="a.severity === 'critical' ? 'b-blocked' : 'b-warn'">{{ t('alerts.sev.' + a.severity) }}</span></span>
            <b>{{ tOr('alerts.kind.' + a.kind, a.kind) }}</b>
            <span class="mono small">{{ a.host ? safeText(a.host, 120) : '—' }}</span>
            <span class="mono small breakall">{{ a.path ? safeText(a.path, 200) : '—' }}</span>
            <span class="al-links">
              <RouterLink v-if="a.change_id" :to="'/changes/' + a.change_id">{{ t('analysis.proposed', { id: a.change_id }) }}</RouterLink>
              <RouterLink to="/alerts">{{ t('analysis.alert_n', { id: a.alert_id }) }}</RouterLink>
            </span>
            <div v-if="a.reason" class="sub reason">{{ safeText(a.reason, 300) }}</div>
          </li>
        </ul>
      </section>

      <section v-if="fpCands.length" class="card">
        <h2><Icon name="unlock" /> {{ t('analysis.fp_candidates') }} <span class="count">{{ fpCands.length }}</span></h2>
        <p class="muted small">{{ t('analysis.fp_hint') }}</p>
        <DataTable id="analysis-fp" :columns="fpCols" :rows="fpCands" row-key="id" :default-sort="{ key: 'internal_sources', dir: -1 }">
          <template #cell-path="{ row }"><span class="mono small">{{ safeText(row.host, 100) }}</span> <TruncText :text="row.path" :max="160" mono />
            <div class="sub">{{ Object.entries(row.methods || {}).map(([m, n]) => m + ' ×' + n).join(', ') }}</div></template>
          <template #cell-rules="{ row }"><div v-for="r in row.rules" :key="r.id" class="ruleline">
            <RouterLink :to="'/rules/' + r.id" class="mono">{{ r.id }}</RouterLink> <span class="small">{{ safeText(r.msg, 80) }}</span>
            <span v-for="x in r.targets" :key="x" class="chip mono">{{ safeText(x, 60) }}</span></div></template>
          <template #cell-verdict="{ row }"><span class="badge" :class="VCLS[verdictOf(row)] || 'b-logged'">{{ t('analysis.verdict.' + verdictOf(row)) }}</span></template>
          <template #cell-confidence="{ row }"><span class="mono">{{ row.verdict && row.verdict.confidence != null ? row.verdict.confidence.toFixed(2) : '—' }}</span></template>
          <template #cell-reason="{ row }"><span class="reason">{{ safeText(row.verdict && row.verdict.reason, 220) }}</span></template>
          <template #cell-result="{ row }">
            <template v-if="row.proposal"><RouterLink :to="'/changes/' + row.proposal.change_id">{{ t('analysis.proposed_exclusion', { id: row.proposal.change_id }) }}</RouterLink>
              <div v-if="row.proposal.state" class="sub"><StateBadge :state="row.proposal.state" /></div></template>
            <span v-else-if="row.skipped" class="small">{{ skipText(row.skipped) }}</span>
            <span v-else class="muted small">{{ t('analysis.not_proposed') }}</span>
          </template>
        </DataTable>
      </section>

      <section v-if="probeCands.length" class="card">
        <h2><Icon name="list" /> {{ t('analysis.candidates') }} <span class="count">{{ probeCands.length }}</span></h2>
        <DataTable id="analysis-candidates" :columns="candCols" :rows="probeCands" row-key="id" :default-sort="{ key: 'sources', dir: -1 }">
          <template #cell-path="{ row }"><TruncText :text="row.path" :max="160" mono />
            <div v-if="row.variants && row.variants.length" class="sub">{{ t('analysis.cand.variants') }}: <span class="mono breakall">{{ row.variants.map((v) => safeText(v, 120)).join('  ') }}</span></div></template>
          <template #cell-hosts="{ row }"><span class="mono small">{{ row.hosts.map((h) => safeText(h, 80)).join(', ') }}<template v-if="row.host_count > row.hosts.length"> (+{{ row.host_count - row.hosts.length }})</template></span></template>
          <template #cell-families="{ row }"><span v-for="f in row.families" :key="f" class="chip">{{ tOr('family.' + f, f) }}</span></template>
          <template #cell-rules="{ row }"><span v-for="r in row.rules" :key="r.id" class="chip mono" :title="safeText(r.msg, 160)"><RouterLink :to="'/rules/' + r.id">{{ r.id }}</RouterLink></span></template>
          <template #cell-statuses="{ row }"><span class="mono small">{{ statusText(row.statuses) }}</span></template>
          <template #cell-verdict="{ row }"><span class="badge" :class="VCLS[verdictOf(row)] || 'b-logged'">{{ t('analysis.verdict.' + verdictOf(row)) }}</span>
            <div v-if="row.verdict && row.verdict.problem && !row.verdict.verdict" class="sub warn">{{ tOr('analysis.problem.' + row.verdict.problem, row.verdict.problem) }}</div></template>
          <template #cell-confidence="{ row }"><span class="mono">{{ row.verdict && row.verdict.confidence != null ? row.verdict.confidence.toFixed(2) : '—' }}</span></template>
          <template #cell-reason="{ row }"><span class="reason">{{ safeText(row.verdict && row.verdict.reason, 220) }}</span></template>
          <template #cell-regex="{ row }"><code v-if="row.verdict && row.verdict.regex" class="mono breakall">{{ safeText(row.verdict.regex, 210) }}</code></template>
          <template #cell-result="{ row }">
            <template v-if="row.proposal"><RouterLink :to="'/changes/' + row.proposal.change_id">{{ t('analysis.proposed', { id: row.proposal.change_id }) }}</RouterLink>
              <div v-if="row.proposal.state" class="sub"><StateBadge :state="row.proposal.state" /></div></template>
            <span v-else-if="row.skipped" class="small">{{ skipText(row.skipped) }}</span>
            <span v-else class="muted small">{{ t('analysis.not_proposed') }}</span>
          </template>
        </DataTable>
      </section>

      <section v-if="skippedBefore.length" class="card">
        <h2><Icon name="filter" /> {{ t('analysis.skipped_before') }} <span class="count">{{ skippedBefore.length }}</span></h2>
        <DataTable id="analysis-skipped" :columns="skipCols" :rows="skippedBefore" row-key="n">
          <template #cell-path="{ row }"><TruncText :text="row.path" :max="160" mono /></template>
          <template #cell-reason="{ row }">{{ skipText(row.reason) }}</template>
          <template #cell-detail="{ row }">
            <RouterLink v-if="row.change_id" :to="'/changes/' + row.change_id">#{{ row.change_id }}</RouterLink>
            <RouterLink v-else-if="row.open_change" :to="'/changes/' + row.open_change">#{{ row.open_change }}</RouterLink>
            <RouterLink v-else-if="row.rule_id" :to="'/rules/' + row.rule_id">{{ t('analysis.rule_n', { id: row.rule_id }) }}</RouterLink>
            <StateBadge v-if="row.state" :state="row.state" />
          </template>
        </DataTable>
      </section>

      <section v-if="skippedModel.length" class="card">
        <h2><Icon name="warning" /> {{ t('analysis.skipped_other') }} <span class="count">{{ skippedModel.length }}</span></h2>
        <ul class="plainlist small">
          <li v-for="s in skippedModel" :key="s.n"><span v-if="s.id" class="mono">{{ safeText(s.id, 40) }}</span> {{ skipText(s.reason) }}</li>
        </ul>
      </section>

      <section v-if="sel.reply_excerpt" class="card">
        <details>
          <summary>{{ t('analysis.reply') }}</summary>
          <pre class="code small">{{ safeMultiline(sel.reply_excerpt) }}</pre>
        </details>
      </section>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api.js'
import { t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { safeText, safeMultiline, fmtMinute, fmtShortTime, fmtNum } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import TruncText from '../components/TruncText.vue'
import StateBadge from '../components/StateBadge.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'
import TimeBars from '../components/charts/TimeBars.vue'

const props = defineProps({ id: { type: String, default: '' } })
const router = useRouter()
const isAdmin = computed(() => hasRole('admin'))
const VERDICTS = ['attack_probe', 'legitimate', 'unsure', 'false_positive', 'attack', 'invalid']
const VTONE = { attack_probe: 's2', legitimate: 's1', false_positive: 's1', attack: 's2', unsure: 's3', invalid: 'muted' }
const VCLS = { attack_probe: 'b-blocked', legitimate: 'b-ok', false_positive: 'b-int', attack: 'b-blocked', unsure: 'b-warn', invalid: 'b-logged' }

const st = ref(null)
const runs = ref([])
const cursor = ref(null)
const loading = ref(false)
const error = ref(null)
const busy = ref(false)
const queued = ref(false)
const actionError = ref(null)
const sel = ref(null)
const selError = ref(null)
const detailEl = ref(null)

const GUIDE_KEY = 'jtwaf.guide.analysis'
function readGuide() { try { return localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
const showGuide = ref(readGuide())
watch(showGuide, (v) => { try { localStorage.setItem(GUIDE_KEY, v ? '1' : '0') } catch { /* private mode */ } })

const guideSteps = computed(() => [
  { key: 'events', label: t('guide.analysis.events'), desc: t('guide.analysis.events_d'), icon: 'list', to: '/events' },
  { key: 'candidates', label: t('guide.analysis.candidates'), desc: t('guide.analysis.candidates_d'), icon: 'filter' },
  { key: 'llm', label: t('guide.analysis.llm'), desc: t('guide.analysis.llm_d'), icon: 'server' },
  { key: 'validate', label: t('guide.analysis.validate'), desc: t('guide.analysis.validate_d'), icon: 'verify' },
  { key: 'propose', label: t('guide.analysis.propose'), desc: t('guide.analysis.propose_d'), icon: 'shield' },
  { key: 'checks', label: t('guide.analysis.checks'), desc: t('guide.analysis.checks_d'), icon: 'test' },
  { key: 'approve', label: t('guide.analysis.approve'), desc: t('guide.analysis.approve_d'), icon: 'approve', to: '/changes' },
])

// where the selected run got to
const runSteps = computed(() => {
  const r = sel.value
  if (!r) return []
  const n = r.candidates.length
  const asked = n > 0
  const failed = !!r.error
  const props_ = r.proposal_list.length
  const states = r.proposal_list.map((p) => p.state)
  const checking = states.includes('checking')
  const waiting = states.some((x) => ['pending_approval', 'approved', 'applying'].includes(x))
  const s = (key, state) => ({ key, label: t('guide.analysis.' + key), icon: guideSteps.value.find((g) => g.key === key).icon, state })
  return [
    s('events', 'done'),
    s('candidates', failed && !asked ? 'fail' : 'done'),
    s('llm', !asked ? 'skip' : failed ? 'fail' : 'done'),
    s('validate', !asked || failed ? 'skip' : 'done'),
    s('propose', !asked || failed ? 'skip' : props_ ? 'done' : 'skip'),
    s('checks', props_ ? (checking ? 'current' : 'done') : 'skip'),
    s('approve', props_ ? (checking ? 'todo' : waiting ? 'current' : 'done') : 'skip'),
  ]
})

function everyText(m) {
  m = Number(m) || 0
  return m % 60 === 0 ? t('analysis.every_h', { n: m / 60 }) : t('analysis.every_m', { n: m })
}
const verdictOf = (c) => (c.verdict && c.verdict.verdict) || 'invalid'
function verdictParts(counts) {
  return VERDICTS.map((k) => ({ key: k, label: t('analysis.verdict.' + k), value: (counts && counts[k]) || 0, tone: VTONE[k] }))
}
function verdictText(v) {
  return VERDICTS.filter((k) => v && v[k]).map((k) => t('analysis.verdict.' + k) + ' ' + v[k]).join(t('common.list_sep')) || '—'
}
const candSeries = computed(() => [{ key: 'n', label: t('chart.analysis.candidates'), tone: 's1' }])
function familyItems(counts) {
  return Object.entries(counts || {}).sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([f, n]) => ({ key: f, label: tOr('family.' + f, f), values: { n } }))
}
const allVerdicts = computed(() => {
  const out = {}
  for (const r of runs.value) for (const [k, n] of Object.entries(r.verdicts || {})) out[k] = (out[k] || 0) + n
  return out
})
const allFamilies = computed(() => {
  const out = {}
  for (const r of runs.value) for (const [k, n] of Object.entries(r.families || {})) out[k] = (out[k] || 0) + n
  return out
})
const runSeries = computed(() => [
  { key: 'proposed', label: t('chart.analysis.proposed'), tone: 's1' },
  { key: 'other', label: t('chart.analysis.not_proposed'), tone: 'muted' },
])
const runBars = computed(() => [...runs.value].reverse().map((r) => ({
  t: r.started_at, proposed: r.proposals, other: Math.max(0, r.candidates - r.proposals),
})))
const selFamilies = computed(() => {
  const out = {}
  for (const c of (sel.value ? sel.value.candidates : [])) { const f = (c.families || [])[0]; if (f) out[f] = (out[f] || 0) + 1 }
  return out
})
const outcomeParts = computed(() => {
  const cs = sel.value ? sel.value.candidates : []
  const proposed = cs.filter((c) => c.proposal).length
  return [
    { key: 'proposed', label: t('chart.analysis.proposed'), value: proposed, tone: 's1' },
    { key: 'other', label: t('chart.analysis.not_proposed'), value: cs.length - proposed, tone: 'muted' },
  ]
})
const sourceSeries = computed(() => [{ key: 'sources', label: t('analysis.cand.sources'), tone: 's1' }])
const sourceItems = computed(() => [...(sel.value ? sel.value.candidates : [])].sort((a, b) => b.sources - a.sources).slice(0, 10)
  .map((c) => ({ key: c.id, label: c.path, values: { sources: c.sources } })))

const probeCands = computed(() => (sel.value ? sel.value.candidates : []).filter((c) => c.type !== 'false_positive'))
const fpCands = computed(() => (sel.value ? sel.value.candidates : []).filter((c) => c.type === 'false_positive'))
const selAlerts = computed(() => (sel.value && sel.value.alert_list) || [])
const fpCols = computed(() => [
  { key: 'path', label: t('analysis.fp.where'), required: true, text: (c) => c.host + ' ' + c.path },
  { key: 'events', label: t('analysis.fp.blocked'), align: 'num' },
  { key: 'sources', label: t('analysis.cand.sources'), align: 'num' },
  { key: 'internal_sources', label: t('analysis.fp.internal'), align: 'num' },
  { key: 'rules', label: t('analysis.fp.rules'), value: (c) => (c.rules || []).map((r) => r.id + ' ' + (r.targets || []).join(' ')).join(' ') },
  { key: 'verdict', label: t('analysis.cand.verdict'), value: (c) => t('analysis.verdict.' + verdictOf(c)) },
  { key: 'confidence', label: t('analysis.cand.confidence'), align: 'num', value: (c) => (c.verdict && c.verdict.confidence != null ? c.verdict.confidence : -1) },
  { key: 'reason', label: t('analysis.cand.reason'), value: (c) => (c.verdict && c.verdict.reason) || '' },
  { key: 'result', label: t('analysis.cand.result'), value: (c) => (c.proposal ? '0 ' + c.proposal.change_id : c.skipped ? '1 ' + c.skipped : '2') },
])
const skippedBefore = computed(() => (sel.value ? sel.value.skipped_list : []).map((s, n) => Object.assign({ n }, s))
  .filter((s) => !s.id && s.path).map((s) => (s.host ? Object.assign({}, s, { path: s.host + ' ' + s.path }) : s)))
const skippedModel = computed(() => (sel.value ? sel.value.skipped_list : []).map((s, n) => Object.assign({ n }, s))
  .filter((s) => String(s.reason || '').startsWith('model_')))
function skipText(reason) {
  const r = String(reason || '')
  if (r.startsWith('refused_')) {
    const x = r.slice(8)
    return t('analysis.skip.refused', { reason: tOr('change.reason.' + x, tOr('error.' + x, x)) })
  }
  return tOr('analysis.skip.' + r, r)
}
function durText(s) {
  if (s == null) return '—'
  return s < 60 ? t('analysis.dur_s', { s: Math.round(s) }) : t('analysis.dur_ms', { m: Math.floor(s / 60), s: Math.round(s % 60) })
}
function statusText(s) { return Object.entries(s || {}).map(([k, n]) => k + ' ×' + n).join(', ') }

const runCols = computed(() => [
  { key: 'id', label: t('analysis.col.id'), required: true, align: 'num' },
  { key: 'started_at', label: t('analysis.col.started'), nowrap: true, text: (r) => fmtShortTime(r.started_at) },
  { key: 'trigger', label: t('analysis.col.trigger'), value: (r) => tOr('analysis.trigger.' + r.trigger, r.trigger) },
  { key: 'model', label: t('analysis.model'), hidden: true },
  { key: 'events_scanned', label: t('analysis.col.events'), align: 'num', text: (r) => (r.events_scanned == null ? '—' : fmtNum(r.events_scanned)) },
  { key: 'candidates', label: t('analysis.col.candidates'), align: 'num' },
  { key: 'verdicts', label: t('analysis.col.verdicts'), value: (r) => (r.verdicts && r.verdicts.attack_probe) || 0, text: (r) => verdictText(r.verdicts) },
  { key: 'proposals', label: t('analysis.col.proposals'), align: 'num' },
  { key: 'skipped', label: t('analysis.col.skipped'), align: 'num', hidden: true },
  { key: 'seconds', label: t('analysis.col.duration'), align: 'num', text: (r) => durText(r.seconds) },
  { key: 'llm_seconds', label: t('analysis.col.seconds'), align: 'num', hidden: true },
  { key: 'result', label: t('analysis.col.result'), value: (r) => (r.error ? 'failed' : 'ok'), text: (r) => (r.error ? t('analysis.failed') + ' ' + r.error : t('analysis.ok')) },
])
const candCols = computed(() => [
  { key: 'path', label: t('analysis.cand.path'), required: true, text: (c) => c.path + ' ' + (c.variants || []).join(' ') },
  { key: 'events', label: t('analysis.cand.events'), align: 'num' },
  { key: 'sources', label: t('analysis.cand.sources'), align: 'num' },
  { key: 'hosts', label: t('analysis.cand.hosts'), value: (c) => (c.hosts || []).join(' '), hidden: true },
  { key: 'families', label: t('analysis.cand.families'), value: (c) => (c.families || []).map((f) => tOr('family.' + f, f)).join(' ') },
  { key: 'rules', label: t('analysis.cand.rules'), value: (c) => (c.rules || []).map((r) => r.id + ' ' + (r.msg || '')).join(' '), hidden: true },
  { key: 'statuses', label: t('analysis.cand.statuses'), value: (c) => statusText(c.statuses), hidden: true },
  { key: 'verdict', label: t('analysis.cand.verdict'), value: (c) => t('analysis.verdict.' + verdictOf(c)) },
  { key: 'confidence', label: t('analysis.cand.confidence'), align: 'num', value: (c) => (c.verdict && c.verdict.confidence != null ? c.verdict.confidence : -1), text: (c) => (c.verdict && c.verdict.confidence != null ? c.verdict.confidence.toFixed(2) : '') },
  { key: 'reason', label: t('analysis.cand.reason'), value: (c) => (c.verdict && c.verdict.reason) || '' },
  { key: 'regex', label: t('analysis.cand.regex'), value: (c) => (c.verdict && c.verdict.regex) || '' },
  { key: 'result', label: t('analysis.cand.result'), value: (c) => (c.proposal ? '0 ' + c.proposal.change_id : c.skipped ? '1 ' + c.skipped : '2'), text: (c) => (c.proposal ? t('analysis.proposed', { id: c.proposal.change_id }) : c.skipped ? skipText(c.skipped) : t('analysis.not_proposed')) },
])
const skipCols = computed(() => [
  { key: 'path', label: t('analysis.col.path'), required: true },
  { key: 'reason', label: t('analysis.col.reason'), value: (s) => skipText(s.reason) },
  { key: 'detail', label: t('analysis.col.detail'), value: (s) => String(s.change_id || s.open_change || s.rule_id || ''), sortable: false },
])

// while a run is asked for or running, the status is polled: the page shows each step as it happens,
// also after leaving the page and coming back
const active = computed(() => !!(st.value && (st.value.requested || st.value.running)))
const justDone = ref(false)
const tick = ref(0)
let timer = null
const LIVE = ['start', 'gather', 'llm', 'validate', 'propose', 'done']
const liveSteps = computed(() => {
  const p = st.value && st.value.progress
  const stage = active.value ? (p && st.value.running ? p.stage : 'queued') : (p ? p.stage : 'done')
  const at = stage === 'queued' ? -1 : LIVE.indexOf(stage === 'error' ? 'llm' : stage)
  const icons = { start: 'run', gather: 'list', llm: 'server', validate: 'verify', propose: 'send', done: 'check' }
  return LIVE.map((k, i) => ({ key: k, icon: icons[k], label: t('analysis.live.' + k),
    state: stage === 'error' && i === at ? 'fail' : i < at || (k === 'done' && stage === 'done') ? 'done' : i === at ? 'current' : 'todo' }))
})
const liveText = computed(() => {
  void tick.value
  const p = st.value && st.value.progress
  if (!active.value) return p && p.stage === 'error' ? t('analysis.live.failed') : t('analysis.live.finished', { c: (p && p.detail.candidates) || 0, n: (p && p.detail.proposals) || 0 })
  if (!st.value.running || !p) return t('analysis.live.queued')
  const secs = Math.max(0, Math.round((Date.now() - Date.parse(p.at)) / 1000))
  const d = p.detail || {}
  return t('analysis.live.' + p.stage + '_v', { c: d.candidates || 0, h: d.window_hours || 0, model: d.model || '', s: secs, a: d.attack || 0, l: d.llm_seconds || 0 })
})
function schedule() {
  clearTimeout(timer)
  if (active.value) timer = setTimeout(poll, 3000)
}
async function poll() {
  const was = active.value
  await loadStatus()
  tick.value++
  if (was && !active.value) {        // just finished: show the new run
    justDone.value = true
    await loadRuns(false)
  }
  schedule()
}
async function loadStatus() {
  try { st.value = await get('/analyst/status') } catch (e) { error.value = e }
  schedule()
  loadLatest()
}
// the newest run in detail, for the summary
const latestDetail = ref(null)
const latest = computed(() => (st.value && st.value.last_run) || null)
async function loadLatest() {
  const id = latest.value && latest.value.id
  if (!id || (latestDetail.value && latestDetail.value.id === id && latestDetail.value.finished_at)) return
  try { latestDetail.value = await get('/analyst/runs/' + id) } catch { latestDetail.value = null }
}
const latestCands = computed(() => (latestDetail.value ? latestDetail.value.candidates : []))
const latestProbe = computed(() => latestCands.value.filter((c) => c.type !== 'false_positive'))
const latestFp = computed(() => latestCands.value.filter((c) => c.type === 'false_positive'))
const latestAlerts = computed(() => (latestDetail.value && latestDetail.value.alert_list) || [])
function countVerdict(list, v) { return list.filter((c) => c.verdict && c.verdict.verdict === v).length }
// the model's main points: alerts first, then what was proposed, then the strongest attack verdicts not proposed
const findings = computed(() => {
  const out = []
  for (const a of latestAlerts.value.slice(0, 5)) {
    out.push({ key: 'a' + a.alert_id, tag: tOr('alerts.kind.' + a.kind, a.kind), cls: a.severity === 'critical' ? 'b-blocked' : 'b-warn',
      where: [a.host, a.path].filter(Boolean).map((x) => safeText(x, 120)).join(' '), change: a.change_id, reason: safeText(a.reason, 240) })
  }
  for (const p of (latestDetail.value ? latestDetail.value.proposal_list : []).slice(0, 8)) {
    if (out.some((x) => x.change === p.change_id)) continue
    const c = latestCands.value.find((x) => x.id === p.id)
    out.push({ key: 'p' + p.change_id, tag: p.type === 'exclusion' ? t('analysis.sum.proposed_exclusion') : t('analysis.sum.proposed_block'),
      cls: p.type === 'exclusion' ? 'b-int' : 'b-ok', where: safeText([p.host, p.path].filter(Boolean).join(' '), 200), change: p.change_id,
      reason: safeText(c && c.verdict && c.verdict.reason, 240) })
  }
  const shown = new Set(out.map((x) => x.where))
  for (const c of latestCands.value.filter((x) => x.verdict && ['attack_probe', 'false_positive'].includes(x.verdict.verdict) && !x.proposal)
    .sort((a, b) => (b.verdict.confidence || 0) - (a.verdict.confidence || 0)).slice(0, 4)) {
    const where = safeText([c.host, c.path].filter(Boolean).join(' '), 200)
    if (shown.has(where)) continue
    out.push({ key: 'c' + c.id, tag: t('analysis.verdict.' + c.verdict.verdict), cls: 'b-logged', where,
      reason: safeText(c.verdict.reason, 240) + (c.skipped ? ' · ' + skipText(c.skipped) : '') })
  }
  return out
})
const totals = computed(() => runs.value.reduce((s, r) => ({ events: s.events + (r.events_scanned || 0), candidates: s.candidates + (r.candidates || 0),
  proposals: s.proposals + (r.proposals || 0), alerts: s.alerts + (r.alerts || 0) }), { events: 0, candidates: 0, proposals: 0, alerts: 0 }))
async function loadRuns(more_) {
  loading.value = true
  try {
    const r = await get('/analyst/runs', { limit: 50, cursor: more_ ? cursor.value : undefined })
    runs.value = more_ ? runs.value.concat(r.items || []) : (r.items || [])
    cursor.value = r.next_cursor
  } catch (e) { error.value = e } finally { loading.value = false }
}
async function loadRun(id) {
  selError.value = null
  if (!id) { sel.value = null; return }
  try {
    sel.value = await get('/analyst/runs/' + encodeURIComponent(id))
    await nextTick()
    if (detailEl.value) detailEl.value.scrollIntoView({ block: 'start' })
  } catch (e) { sel.value = null; selError.value = e }
}
function more() { loadRuns(true) }
async function reload() {
  error.value = null
  await Promise.all([loadStatus(), loadRuns(false)])
  if (props.id) await loadRun(props.id)
}
async function runNow() {
  busy.value = true
  actionError.value = null
  queued.value = false
  justDone.value = false
  try { st.value = await post('/analyst/run'); queued.value = true; schedule() } catch (e) { actionError.value = e } finally { busy.value = false }
}
onUnmounted(() => clearTimeout(timer))
watch(() => props.id, (v) => loadRun(v))
onMounted(reload)
</script>

<style scoped>
.chartgrid .wide { grid-column: 1 / -1; }
.sumlead { margin: 0 0 10px; display: flex; flex-wrap: wrap; gap: 4px 0; align-items: center; }
.sumlead > .badge { margin-left: 8px; }
.sumtiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; margin-bottom: 12px; }
.sumtile { border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; background: var(--panel-2); display: flex; flex-direction: column; }
.sumtile b { font-size: 1.5em; font-variant-numeric: tabular-nums; }
.sumtile span { color: var(--muted); font-size: .88em; }
.sumtile.hot { border-color: var(--warn); background: var(--warn-bg); }
.findings { list-style: none; padding: 0; margin: 0; }
.findings li { display: flex; flex-wrap: wrap; gap: 4px 10px; align-items: baseline; padding: 7px 0; border-bottom: 1px dashed var(--border); }
.findings li:last-child { border-bottom: 0; }
.findings .sub { flex-basis: 100%; color: var(--muted); font-size: .9em; }
.runfacts { display: flex; flex-wrap: wrap; gap: 6px 18px; margin: 4px 0 6px; font-weight: 600; }
.runfacts span { display: inline-flex; align-items: center; gap: 5px; }
/* one grid for all rows (subgrid): severity, kind, site, path and links line up from row to row */
.alertgrid { display: grid; grid-template-columns: max-content max-content minmax(0, max-content) minmax(0, 1fr) max-content; column-gap: 16px; }
.alertline { grid-column: 1 / -1; display: grid; grid-template-columns: subgrid; row-gap: 2px; align-items: baseline; padding: 7px 0; border-bottom: 1px solid var(--border); text-align: left; }
.alertline .al-links { display: flex; gap: 12px; justify-content: flex-end; white-space: nowrap; }
.alertline .sub { grid-column: 1 / -1; color: var(--muted); font-size: .88em; }
@media (max-width: 760px) {
  .alertgrid { display: block; }
  .alertline { display: flex; flex-wrap: wrap; gap: 4px 10px; }
  .alertline .sub { flex-basis: 100%; }
}
.ruleline { margin: 2px 0; }
.sub-head { margin: 0; }
.live { margin-top: 12px; }
.livetext { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin: 8px 0 0; }
.sub-head h2 { margin: 0; }
.reason { white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
