<!-- How the WAF decides, drawn from the site's parsed configuration (GET /waf/model): the stages a request
     passes, what each one does for an external and an internal source, the anomaly-score scale and the site
     rules involved. Nothing about one site is written here: every number, rule id and text comes from the API. -->
<template>
  <div class="page wafmodel">
    <div class="pagehead">
      <h1><Icon name="shield" /> {{ t('waf.title') }}</h1>
      <button type="button" class="btn small ghost" :disabled="loading" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
    </div>
    <p class="muted">{{ t('waf.intro') }}</p>
    <ErrorBox :error="error" />
    <Loading v-if="!md && !error" />
    <template v-if="md">
      <!-- (4) plain-language summary -->
      <section class="card summary">
        <h2><Icon name="info" /> {{ t('waf.sum.title') }}</h2>
        <ul class="sumlist">
          <li v-for="s in sentences" :key="s.key" :class="'sum-' + s.kind">
            <span class="sumicon" :class="'eff-' + s.effect"><Icon :name="EFFECT_ICON[s.effect] || 'info'" /></span>
            <span><strong v-if="s.lead">{{ s.lead }}</strong> {{ s.text }}</span>
          </li>
        </ul>
        <p class="muted small">{{ t('waf.sum.generated', { time: fmtTime(md.generated_at) }) }}</p>
      </section>

      <div class="tiles">
        <div class="tile"><div class="tl">{{ t('waf.fact.engine_global') }}</div><div class="tv small mono">{{ safeText(md.engine.global, 30) }}</div>
          <div class="ts">{{ t('waf.fact.engine_global_d') }}</div></div>
        <div class="tile"><div class="tl">{{ t('waf.lane.external') }}</div><div class="tv small">{{ modeText(md.summary.external) }}</div></div>
        <div class="tile"><div class="tl">{{ t('waf.lane.internal') }}</div><div class="tv small">{{ modeText(md.summary.internal) }}</div></div>
        <div class="tile"><div class="tl">{{ t('waf.fact.threshold') }}</div><div class="tv">{{ md.scoring.threshold }}</div>
          <div class="ts">{{ t('waf.fact.paranoia', { n: md.crs.blocking_paranoia_level }) }}</div></div>
        <div class="tile"><div class="tl">{{ t('waf.fact.vhosts') }}</div><div class="tv">{{ fmtNum(vhOn) }} / {{ fmtNum(md.vhosts.total) }}</div>
          <div class="ts">{{ t('waf.fact.bypass', { n: fmtNum(md.vhosts.bypass_locations) }) }}</div></div>
      </div>

      <!-- (1) decision flow -->
      <section class="card">
        <div class="cardhead">
          <h2><Icon name="change" /> {{ t('waf.flow.title') }}</h2>
          <div class="lanepick" role="group" :aria-label="t('waf.flow.lanes')">
            <button v-for="o in laneOptions" :key="o.value" type="button" class="btn small ghost" :class="{ on: laneSel === o.value }"
                    :aria-pressed="laneSel === o.value ? 'true' : 'false'" @click="laneSel = o.value"><Icon :name="o.icon" />{{ o.label }}</button>
          </div>
        </div>
        <p class="muted small">{{ t('waf.flow.hint') }}</p>
        <div class="flowwrap">
          <svg class="flowsvg" :viewBox="'0 0 ' + FW + ' ' + FH" role="group" :aria-label="t('waf.flow.title')" :style="{ minWidth: Math.round(FW * (lanes.length > 1 ? 0.82 : 0.8)) + 'px', maxWidth: Math.round(FW * 1.25) + 'px' }">
            <defs>
              <marker id="waf-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" class="fl-arrowhead" />
              </marker>
            </defs>
            <foreignObject :x="0" :y="0" :width="STAGE_W" :height="HEAD">
              <div class="fl-head"><Icon name="list" />{{ t('waf.flow.stage') }}</div>
            </foreignObject>
            <foreignObject v-for="(ln, li) in lanes" :key="'h' + ln" :x="laneX(li)" :y="0" :width="LANE_W" :height="HEAD">
              <div class="fl-head lanehead"><Icon :name="ln === 'external' ? 'globe' : 'network'" />{{ t('waf.lane.' + ln) }}</div>
            </foreignObject>
            <g v-for="(s, i) in stages" :key="'a' + s.key">
              <template v-if="i < stages.length - 1">
                <path class="fl-edge" :d="vline(STAGE_W / 2, i)" marker-end="url(#waf-arrow)" />
                <path v-for="(ln, li) in lanes" :key="ln" class="fl-edge lane" :class="'eff-' + s.per_source[ln]" :d="vline(laneX(li) + LANE_W / 2, i)" marker-end="url(#waf-arrow)" />
              </template>
            </g>
            <g v-for="(s, i) in stages" :key="s.key">
              <rect v-if="sel === s.key" class="fl-selband" :x="-4" :y="rowY(i) - 4" :width="FW + 8" :height="ROW_H + 8" rx="10" />
              <foreignObject :x="0" :y="rowY(i)" :width="STAGE_W" :height="ROW_H">
                <div class="fl-box stagebox" :class="['eff-' + s.effect, { sel: sel === s.key }]" tabindex="0" role="button"
                     :aria-pressed="sel === s.key ? 'true' : 'false'" :aria-label="stageName(s) + ' — ' + effectName(s.effect)"
                     @click="sel = s.key" @keydown.enter.prevent="sel = s.key" @keydown.space.prevent="sel = s.key">
                  <span class="fl-num">{{ i + 1 }}</span>
                  <div class="fl-txt">
                    <div class="fl-name"><Icon :name="STAGE_ICON[s.key] || 'info'" />{{ stageName(s) }}</div>
                    <div class="fl-sub">{{ stageSub(s) }}</div>
                  </div>
                </div>
              </foreignObject>
              <foreignObject v-for="(ln, li) in lanes" :key="ln" :x="laneX(li)" :y="rowY(i)" :width="LANE_W" :height="ROW_H">
                <div class="fl-box cell" :class="['eff-' + s.per_source[ln], { sel: sel === s.key }]" @click="sel = s.key">
                  <div class="fl-name"><Icon :name="EFFECT_ICON[s.per_source[ln]] || 'info'" />{{ cellText(s, ln) }}</div>
                  <div class="fl-sub">{{ cellSub(s, ln) }}</div>
                </div>
              </foreignObject>
            </g>
          </svg>
        </div>
        <div class="legend flowlegend">
          <span v-for="e in LEGEND" :key="e" class="lg-item"><span class="lgbox" :class="'eff-' + e"><Icon :name="EFFECT_ICON[e]" /></span>{{ effectName(e) }}</span>
        </div>
        <div v-if="current" class="flowdesc" role="status">
          <h3><Icon :name="STAGE_ICON[current.key] || 'info'" /> {{ stageName(current) }}
            <span class="badge tiny" :class="'bd-' + current.effect"><Icon :name="EFFECT_ICON[current.effect] || 'info'" />{{ effectName(current.effect) }}</span></h3>
          <p>{{ stageDesc(current) }}</p>
          <ul class="lanenotes">
            <li v-for="ln in ['external', 'internal']" :key="ln">
              <strong>{{ t('waf.lane.' + ln) }}{{ t('waf.sum.colon') }}</strong> {{ (current.per_source_all[ln] || [current.per_source[ln]]).map(effectName).join(' / ') }}<template v-if="laneNote(current, ln)"> — {{ laneNote(current, ln) }}</template>
            </li>
          </ul>
          <dl v-if="details.length" class="kv">
            <template v-for="d in details" :key="d.k"><dt>{{ d.k }}</dt>
              <dd v-if="d.chips" class="detchips"><span v-for="c in d.chips" :key="c" class="chip mono">{{ c }}</span></dd>
              <dd v-else-if="d.lines" class="detlines">
                <div v-for="(ln, i) in d.lines" :key="i" class="detline"><span class="mono dl-host">{{ ln[0] }}</span><span class="mono dl-op">{{ ln[1] }}</span><span class="mono dl-path">{{ ln[2] }}</span></div>
              </dd>
              <dd v-else :class="{ mono: d.mono }">{{ d.v }}</dd></template>
          </dl>
          <div v-if="current.rule_ids.length" class="idchips">
            <RouterLink v-for="id in current.rule_ids.slice(0, 40)" :key="id" class="chip mono" :to="'/rules/' + id">{{ id }}</RouterLink>
            <span v-if="current.rule_ids.length > 40" class="muted small">{{ t('waf.more', { n: current.rule_ids.length - 40 }) }}</span>
          </div>
          <div class="descbtns">
            <button v-if="stageRuleCount(current)" type="button" class="btn small" @click="showStageRules(current)"><Icon name="filter" />{{ t('waf.flow.show_rules') }}</button>
            <RouterLink v-if="STAGE_LINK[current.key]" class="btn small ghost" :to="STAGE_LINK[current.key]"><Icon name="go" />{{ t('guide.open_page') }}</RouterLink>
          </div>
        </div>
      </section>

      <!-- (2) scoring chart -->
      <section class="card">
        <h2><Icon name="chart" /> {{ t('waf.score.title') }}</h2>
        <p class="muted small">{{ t('waf.score.hint', { n: md.scoring.threshold }) }}</p>
        <div class="scorelayout">
          <div class="scol">
            <h3 class="charthead">{{ t('waf.score.scale') }}</h3>
            <ScoreScale :rows="scoreRows" :threshold="md.scoring.threshold" :threshold-label="t('waf.score.threshold_line', { n: md.scoring.threshold })"
                        :marks="scoreMarks" :label="t('waf.score.scale')" />
            <div class="legend">
              <span class="lg-item"><span class="lg sw-score"></span>{{ t('waf.score.legend_below') }}</span>
              <span class="lg-item"><span class="lg sw-over"></span>{{ t('waf.score.legend_reach') }}</span>
              <span class="lg-item"><span class="lg sw-thr"></span>{{ t('waf.score.legend_threshold') }}</span>
            </div>
            <h3 class="subhead">{{ t('waf.score.examples') }}</h3>
            <ul class="examples">
              <li v-for="e in examples" :key="e.key">
                <span class="mono exscore">{{ e.title }}</span>
                <span class="exouts">
                  <span v-for="ln in ['external', 'internal']" :key="ln" class="badge tiny" :class="'bd-' + resEffect(e.outcome[ln])"><Icon :name="EFFECT_ICON[resEffect(e.outcome[ln])]" />{{ t('waf.lane.' + ln) }}{{ t('waf.sum.colon') }}{{ resText(e.outcome[ln]) }}</span>
                </span>
              </li>
            </ul>
          </div>
          <div class="scol">
            <h3 class="charthead">{{ t('waf.score.levels') }}</h3>
            <HBars :items="levelBars" :value-label="t('waf.score.rules')" />
            <p class="muted small">{{ t('waf.score.levels_note') }}</p>
            <h3 class="charthead">{{ t('waf.chart.rules_by_stage') }}</h3>
            <HBars :items="stageBars" :value-label="t('waf.score.rules')" pickable :open-label="t('waf.flow.show_rules')" @pick="(it) => showStageRules({ key: it.key })" />
          </div>
        </div>
        <h3 class="charthead">{{ t('waf.chart.vhosts') }}</h3>
        <SegBar :parts="vhostParts" :label="t('waf.chart.vhosts')" />
      </section>

      <!-- (3) the rules involved -->
      <section ref="tableCard" class="card">
        <h2><Icon name="list" /> {{ t('waf.table.title') }} <span class="count">{{ fmtNum(md.rules.length) }}</span></h2>
        <p class="muted small">{{ t('waf.table.hint') }}</p>
        <div v-if="stageFilter" class="filterbar">
          <span class="chip">{{ stageName({ key: stageFilter }) }}</span>
          <button type="button" class="btn small ghost" @click="stageFilter = ''"><Icon name="clear" />{{ t('table.clear_filters') }}</button>
        </div>
        <DataTable id="waf-model-rules" :columns="cols" :rows="tableRows" row-key="rk" :default-sort="{ key: 'order', dir: 1 }">
          <template #cell-id="{ row }">
            <RouterLink v-if="row.id !== null" class="mono" :to="'/rules/' + row.id">{{ row.id }}</RouterLink>
            <span v-else class="mono muted">{{ safeText(row.directive, 40) }}</span>
          </template>
          <template #cell-stage="{ row }"><span class="nowrap"><Icon :name="STAGE_ICON[row.stage] || 'info'" /> {{ stageName({ key: row.stage }) }}</span></template>
          <template #cell-role="{ row }">{{ t('waf.role.' + row.role) }}</template>
          <template #cell-external="{ row }"><span class="badge tiny" :class="'bd-' + row.effect.external"><Icon :name="EFFECT_ICON[row.effect.external] || 'info'" />{{ effectName(row.effect.external) }}</span></template>
          <template #cell-internal="{ row }"><span class="badge tiny" :class="'bd-' + row.effect.internal"><Icon :name="EFFECT_ICON[row.effect.internal] || 'info'" />{{ effectName(row.effect.internal) }}</span></template>
          <template #cell-cond="{ row }"><span class="small">{{ row.cond }}</span></template>
          <template #cell-acts="{ row }"><span class="mono small">{{ row.acts }}</span></template>
          <template #cell-msg="{ row }">
            <span>{{ safeText(row.msg, 200) }}</span>
            <span v-if="row.weakens && row.weakens.length" class="badge tiny bd-loosens"><Icon name="warning" />{{ t('waf.table.weakens', { ids: row.weakens.join(', ') }) }}</span>
          </template>
        </DataTable>
      </section>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, nextTick } from 'vue'
import { get } from '../api.js'
import { t } from '../i18n.js'
import { safeText, fmtNum, fmtTime } from '../util.js'
import Icon from '../components/Icon.vue'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import DataTable from '../components/DataTable.vue'
import HBars from '../components/charts/HBars.vue'
import SegBar from '../components/charts/SegBar.vue'
import ScoreScale from '../components/charts/ScoreScale.vue'

const md = ref(null)
const error = ref(null)
const loading = ref(false)
const sel = ref('crs_eval')
const stageFilter = ref('')
const tableCard = ref(null)

const EFFECT_ICON = { blocks: 'block', logs: 'show', scores: 'chart', loosens: 'unlock', not_inspected: 'hide', info: 'settings',
  not_reached: 'forward', not_applicable: 'dismiss', removed: 'delete' }
const LEGEND = ['blocks', 'scores', 'logs', 'loosens', 'not_inspected', 'not_applicable']
const STAGE_ICON = { not_inspected: 'hide', exclusions: 'unlock', confident: 'block', site_scoring: 'add', crs_detect: 'search',
  crs_eval: 'chart', engine: 'settings', threshold_block: 'shield', fallback: 'block', deny_rules: 'alert', settings: 'settings',
  other: 'help', outcome: 'check' }
const STAGE_LINK = { not_inspected: '/vhosts', exclusions: '/rules', confident: '/rules', crs_detect: '/crs', crs_eval: '/crs',
  engine: '/crs', other: '/rules' }

// layout of the flow diagram
const GAP = 18, HEAD = 40, ROW_GAP = 20
const narrow = (() => { try { return window.matchMedia('(max-width: 700px)').matches } catch { return false } })()
const laneSel = ref(narrow ? 'external' : 'both')
const laneOptions = computed(() => [
  { value: 'both', label: t('waf.flow.both'), icon: 'columns' },
  { value: 'external', label: t('waf.lane.external'), icon: 'globe' },
  { value: 'internal', label: t('waf.lane.internal'), icon: 'network' },
])
const lanes = computed(() => laneSel.value === 'both' ? ['external', 'internal'] : [laneSel.value])
// one lane: narrower boxes so the diagram fits a phone without scrolling
const STAGE_W = computed(() => lanes.value.length > 1 ? 300 : 210)
const LANE_W = computed(() => lanes.value.length > 1 ? 220 : 170)
const ROW_H = computed(() => lanes.value.length > 1 ? 62 : 72)
const stages = computed(() => md.value ? md.value.stages : [])
const FW = computed(() => STAGE_W.value + lanes.value.length * (LANE_W.value + GAP))
const FH = computed(() => HEAD + stages.value.length * (ROW_H.value + ROW_GAP))
function laneX(i) { return STAGE_W.value + GAP + i * (LANE_W.value + GAP) }
function rowY(i) { return HEAD + 8 + i * (ROW_H.value + ROW_GAP) }
function vline(xc, i) { return 'M' + xc + ',' + (rowY(i) + ROW_H.value) + ' L' + xc + ',' + (rowY(i + 1) - 2) }

const current = computed(() => stages.value.find((s) => s.key === sel.value) || stages.value[0])

function effectName(e) { return t('waf.effect.' + e) }
function stageName(s) { return t('waf.stage.' + s.key) }
function ids(list, n = 6) { list = list || []; return list.slice(0, n).join(', ') + (list.length > n ? ' …' : '') }
const T = computed(() => md.value.scoring.threshold)

function modeText(sm) {
  if (!sm) return '—'
  if (sm.mode === 'blocking') return t('waf.mode.blocking', { n: sm.min_block_score })
  if (sm.mode === 'partial') return sm.min_block_score !== null ? t('waf.mode.blocking', { n: sm.min_block_score }) : t('waf.mode.partial')
  return t('waf.mode.' + sm.mode)
}

function stageSub(s) {
  const d = s.data || {}
  switch (s.key) {
    case 'not_inspected': return t('waf.sub.not_inspected', { v: (d.servers || []).length, l: (d.locations || []).length })
    case 'exclusions': return t('waf.sub.exclusions', { n: d.runtime || 0, c: d.config_time || 0, p: (d.plugins || []).length })
    case 'crs_detect': return t('waf.sub.crs_detect', { pl: md.value.crs.blocking_paranoia_level, n: fmtNum(s.count) })
    case 'crs_eval': return t('waf.sub.crs_eval', { n: T.value, ids: ids(s.rule_ids, 3) || '—' })
    case 'engine': return t('waf.sub.engine', { mode: md.value.engine.global, n: md.value.engine.contexts.length - 1 })
    case 'outcome': return t('waf.sub.outcome')
    default: return t('waf.sub.rules', { n: s.count, ids: ids(s.rule_ids, 3) })
  }
}

function cellText(s, ln) {
  if (s.key === 'outcome') return modeText(md.value.summary[ln])
  const all = s.per_source_all[ln] || [s.per_source[ln]]
  return effectName(all[0])
}
function cellSub(s, ln) {
  const all = s.per_source_all[ln] || [s.per_source[ln]]
  if (s.key === 'outcome') {
    const sm = md.value.summary[ln]
    return sm.over_by ? t('waf.cell.by', { id: sm.over_by }) : ''
  }
  if (s.key === 'engine' && (s.data.enabled_by[ln] || []).length) return t('waf.cell.switched', { ids: ids(s.data.enabled_by[ln], 3) })
  if (all.length > 1) return t('waf.cell.or', { e: all.slice(1).map(effectName).join(' / ') })
  const e = s.per_source[ln]
  if (e === 'not_applicable') return t('waf.cell.na_' + ln)
  if (e === 'not_reached') return t('waf.cell.not_reached')
  return ''
}

function stageDesc(s) {
  return t('waf.stage.' + s.key + '.desc', { n: T.value, mode: md.value.engine.global })
}
function laneNote(s, ln) {
  const all = s.per_source_all[ln] || [s.per_source[ln]]
  if (s.key === 'outcome') return summaryText(ln)
  if (s.key === 'engine' && (s.data.enabled_by[ln] || []).length) return t('waf.note.switched', { ids: ids(s.data.enabled_by[ln], 10) })
  if (s.key === 'crs_eval' && all.includes('blocks') && all.includes('logs')) return t('waf.note.eval_mixed', { ids: ids(md.value.stages.find((x) => x.key === 'engine').data.enabled_by[ln], 10) })
  if (all[0] === 'logs') return t('waf.note.logs', { mode: md.value.engine.global })
  if (all[0] === 'not_applicable') return t('waf.note.not_applicable')
  if (all[0] === 'not_reached') return t('waf.note.not_reached')
  return ''
}
const details = computed(() => {
  const s = current.value
  if (!s) return []
  const d = s.data || {}
  const out = []
  if (s.key === 'not_inspected') {
    if ((d.servers || []).length) out.push({ k: t('waf.det.servers_off'), chips: [...new Set(d.servers.map((x) => safeText(x.server, 100)))].sort() })
    if ((d.locations || []).length) {
      // "~ ^/path" -> modifier and pattern in their own columns, one location per line
      out.push({ k: t('waf.det.locations_off'), lines: d.locations.map((x) => {
        const m = /^(=|~\*|~|\^~)?\s*(.*)$/.exec(String(x.location || ''))
        return [safeText(x.server, 100), (m && m[1]) || '', safeText(m ? m[2] : x.location, 160)]
      }).sort((a, b) => a[0].localeCompare(b[0]) || a[2].localeCompare(b[2])) })
    }
  } else if (s.key === 'exclusions') {
    out.push({ k: t('waf.det.runtime'), v: fmtNum(d.runtime || 0) })
    out.push({ k: t('waf.det.config_time'), v: fmtNum(d.config_time || 0) })
    if ((d.plugins || []).length) out.push({ k: t('waf.det.plugins'), v: d.plugins.map((p) => safeText(p, 80)).join(', '), mono: true })
    if ((d.weakens || []).length) out.push({ k: t('waf.det.weakens'), v: d.weakens.join(', '), mono: true })
  } else if (s.key === 'crs_detect') {
    const p = d.points || {}
    out.push({ k: t('waf.det.points'), v: ['critical', 'error', 'warning', 'notice'].map((k) => t('waf.sev.' + k) + ' ' + p[k]).join(' · ') })
    out.push({ k: t('waf.det.paranoia'), v: t('waf.det.paranoia_v', { b: md.value.crs.blocking_paranoia_level, d: md.value.crs.detection_paranoia_level }) })
    if (d.removed) out.push({ k: t('waf.det.removed'), v: fmtNum(d.removed) })
  } else if (s.key === 'crs_eval') {
    out.push({ k: t('waf.det.threshold'), v: String(d.threshold) })
    for (const o of d.overrides || []) out.push({ k: t('waf.det.override', { id: o.id }), v: Object.entries(o.set || {}).map(([k, v]) => t('waf.det.dir_' + k) + ' ' + v).join(', ') + (o.servers.length ? ' · ' + o.servers.join(', ') : '') })
  } else if (s.key === 'engine') {
    for (const c of d.contexts || []) {
      out.push({ k: c.default ? t('waf.det.ctx_default', { mode: c.engine }) : t('waf.det.ctx', { mode: c.engine }),
        v: c.servers.length ? c.servers.map((x) => safeText(x, 100)).join(', ') : '—', mono: true })
    }
  } else if (d.by_source) {
    out.push({ k: t('waf.det.by_source'), v: Object.entries(d.by_source).map(([k, v]) => t('waf.applies.' + k) + ' ' + v).join(' · ') })
  } else if (d.by_role) {
    out.push({ k: t('waf.det.by_role'), v: Object.entries(d.by_role).map(([k, v]) => t('waf.role.' + k) + ' ' + v).join(' · ') })
  }
  return out
})

// --- summary sentences -------------------------------------------------------------------------
function summaryText(ln) {
  const sm = md.value.summary[ln]
  const parts = []
  if (sm.mode === 'off') return t('waf.sum.off')
  if (sm.min_block_score !== null) {
    let p = t('waf.sum.blocked_score', { n: sm.min_block_score, by: sm.over_by ?? '—' })
    if ((sm.over_enabled_by || []).length) p += t('waf.sum.enabled_by', { ids: ids(sm.over_enabled_by, 5) })
    parts.push(p)
  }
  if (sm.confident_applies > 0 && sm.confident_blocked > 0) parts.push(t('waf.sum.confident', { n: sm.confident_blocked }))
  if (sm.min_block_score !== null) {
    parts.push(t('waf.sum.below', { n: sm.min_block_score }))
  } else if (sm.min_flag_score !== null) {
    parts.push(t('waf.sum.logged_only', { n: sm.min_flag_score }))
  } else {
    parts.push(t('waf.sum.never'))
  }
  return parts.join(t('waf.sum.sep'))
}
const vhOn = computed(() => (md.value.vhosts.on || 0) + (md.value.vhosts.block || 0))
const sentences = computed(() => {
  const m = md.value
  const out = []
  for (const ln of ['external', 'internal']) {
    out.push({ key: ln, kind: 'main', effect: { blocking: 'blocks', partial: 'blocks', logging: 'logs', off: 'not_inspected' }[m.summary[ln].mode],
      lead: t('waf.sum.' + ln) + t('waf.sum.colon'), text: summaryText(ln) })
  }
  for (const c of m.engine.contexts) {
    if (c.default || !c.servers.length) continue
    const o = c.outcomes
    out.push({ key: 'ctx-' + c.key, kind: 'note', effect: 'info', lead: '',
      text: t('waf.sum.context', { n: c.servers.length, mode: c.engine, names: c.servers.slice(0, 5).join(', ') + (c.servers.length > 5 ? ' …' : ''),
        ext: modeText(o.external), int: modeText(o.internal) }) })
  }
  const ni = m.stages.find((s) => s.key === 'not_inspected')
  if (ni && ((ni.data.servers || []).length || (ni.data.locations || []).length)) {
    out.push({ key: 'ni', kind: 'note', effect: 'not_inspected', lead: '', text: t('waf.sum.not_inspected', { v: ni.data.servers.length, l: ni.data.locations.length }) })
  }
  const ex = m.stages.find((s) => s.key === 'exclusions')
  if (ex && (ex.data.weakens || []).length) {
    const who = m.rules.filter((r) => (r.weakens || []).length).map((r) => (r.id ?? r.directive) + ' → ' + r.weakens.join(', '))
    out.push({ key: 'weak', kind: 'warn', effect: 'loosens', lead: '', text: t('waf.sum.weakens', { list: who.slice(0, 6).join('; ') + (who.length > 6 ? ' …' : '') }) })
  }
  for (const f of m.facts) {
    if (f.key === 'source_list_mismatch') out.push({ key: f.key, kind: 'warn', effect: 'info', lead: '', text: t('waf.sum.mismatch', { n: f.value, ids: ids(f.ids, 8) }) })
    if (f.key === 'unclassified') out.push({ key: f.key, kind: 'note', effect: 'info', lead: '', text: t('waf.sum.unclassified', { n: f.value, ids: ids(f.ids, 8) }) })
  }
  return out
})

// --- scoring chart -----------------------------------------------------------------------------
function resEffect(r) { return !r ? 'info' : r.result === 'blocked' ? 'blocks' : r.result === 'logged' ? 'logs' : r.result === 'not_inspected' ? 'not_inspected' : r.result === 'allowed' ? 'loosens' : 'not_reached' }
function resText(r) {
  if (!r) return '—'
  if (r.result === 'blocked') return r.by ? t('waf.res.blocked_by', { id: r.by }) : t('waf.res.blocked')
  return t('waf.res.' + r.result)
}
const examples = computed(() => (md.value ? md.value.scoring.examples : []).map((e) => ({
  ...e, key: e.severity + '-' + e.count,
  title: t('waf.score.example', { k: e.count, sev: t('waf.sev.' + e.severity), n: e.score }),
})))
const scoreRows = computed(() => {
  const sc = md.value.scoring
  return ['critical', 'error', 'warning', 'notice'].filter((s) => sc.points[s] > 0).map((s) => {
    const p = sc.points[s]
    const ex = sc.examples.filter((e) => e.severity === s).sort((a, b) => b.count - a.count)[0]
    const count = ex ? ex.count : 1
    const score = count * p
    const tip = ex ? ['external', 'internal'].map((ln) => ({ value: resText(ex.outcome[ln]), label: t('waf.lane.' + ln) })) : []
    return { key: s, label: t('waf.sev.' + s), sub: t('waf.score.points_each', { n: p }), points: p, count, score,
      valueText: '= ' + score, tipTitle: t('waf.score.example', { k: count, sev: t('waf.sev.' + s), n: score }), tip }
  })
})
const scoreMarks = computed(() => {
  const sc = md.value.scoring
  return ['external', 'internal'].filter((ln) => sc.min_block_score[ln] !== null && sc.min_block_score[ln] !== sc.threshold)
    .map((ln) => ({ key: ln, value: sc.min_block_score[ln], label: t('waf.lane.' + ln) }))
})
const levelBars = computed(() => md.value.scoring.levels.map((lv) => ({
  key: 'pl' + lv.level, label: t('waf.score.level', { n: lv.level }) + ' · ' + t('waf.level.' + lv.state),
  values: { value: lv.total },
  sub: ['critical', 'error', 'warning', 'notice'].map((k) => t('waf.sev.' + k) + ' ' + lv.counts[k]).join(' · '),
})))
const vhostParts = computed(() => {
  const v = md.value.vhosts
  return [
    { key: 'on', label: t('waf.vh.on', { mode: md.value.engine.global }), value: v.on || 0, tone: 'logged' },
    { key: 'block', label: t('waf.vh.block'), value: v.block || 0, tone: 'blocked' },
    { key: 'off', label: t('waf.vh.off'), value: (v.off || 0) + (v.unknown || 0), tone: 'muted' },
  ]
})
const stageBars = computed(() => md.value.stages.filter((s) => stageRuleCount(s)).map((s) => ({
  key: s.key, label: stageName(s), values: { value: stageRuleCount(s) }, active: stageFilter.value === s.key,
})))
function stageRuleCount(s) { return md.value.rules.filter((r) => r.stage === s.key).length }
async function showStageRules(s) {
  stageFilter.value = stageFilter.value === s.key ? '' : s.key
  await nextTick()
  try { tableCard.value && tableCard.value.scrollIntoView({ behavior: 'smooth', block: 'start' }) } catch { /* old browser */ }
}

// --- table -------------------------------------------------------------------------------------
function condText(c) {
  switch (c.type) {
    case 'always': return t('waf.cond.always')
    case 'source': return c.applies === 'external' ? t('waf.cond.external') : c.applies === 'internal' ? t('waf.cond.internal') : 'REMOTE_ADDR ' + safeText(c.text, 80)
    case 'score': return t('waf.cond.score', { op: { ge: '≥', gt: '>', eq: '=', lt: '<', le: '≤' }[c.op] || c.op,
      n: c.value === 'threshold' ? T.value + ' (' + t('waf.cond.threshold') + ')' : String(c.value) })
    case 'flag': return 'tx.' + safeText(c.name, 40) + ' = ' + c.value
    case 'host': return (c.negated ? '!' : '') + 'Host ' + safeText(c.host, 80)
    case 'request': return (c.negated ? '!' : '') + safeText(c.variable, 60) + ' ' + safeText(c.operator, 20) + (c.pattern ? ' ' + safeText(c.pattern, 50) : '')
    default: return c.type
  }
}
const order = { not_inspected: 0, exclusions: 1, confident: 2, site_scoring: 3, deny_rules: 4, crs_detect: 5, crs_eval: 6, threshold_block: 7, fallback: 8, settings: 9, other: 10 }
const tableRows = computed(() => md.value.rules.filter((r) => !stageFilter.value || r.stage === stageFilter.value).map((r, i) => ({
  ...r, rk: r.id !== null ? 'r' + r.id + '-' + r.file + ':' + r.line : r.key,
  order: String(order[r.stage] ?? 11).padStart(2, '0') + String(r.phase).padStart(2, '0') + String(i).padStart(5, '0'),
  cond: r.id === null ? safeText(r.directive, 40) + ' ' + (r.target_ids || []).join(', ') + ' ' + safeText(r.args, 120)
    : (r.conditions || []).map(condText).join(' · '),
  acts: (r.actions || []).map((a) => safeText(a, 80)).join(', '),
})))
const cols = computed(() => [
  { key: 'id', label: t('waf.table.id'), value: (r) => r.id ?? -1, text: (r) => String(r.id ?? r.directive), required: true, nowrap: true },
  { key: 'order', label: t('waf.table.order'), hidden: true, value: (r) => r.order, text: (r) => r.order },
  { key: 'stage', label: t('waf.table.stage'), value: (r) => order[r.stage] ?? 11, text: (r) => stageName({ key: r.stage }), filterable: true },
  { key: 'phase', label: t('waf.table.phase'), align: 'num', value: (r) => r.phase },
  { key: 'role', label: t('waf.table.role'), value: (r) => r.role, text: (r) => t('waf.role.' + r.role), filterable: true, hidden: true },
  { key: 'external', label: t('waf.lane.external'), value: (r) => r.effect.external, text: (r) => effectName(r.effect.external), filterable: true },
  { key: 'internal', label: t('waf.lane.internal'), value: (r) => r.effect.internal, text: (r) => effectName(r.effect.internal), filterable: true },
  { key: 'cond', label: t('waf.table.condition'), value: (r) => r.cond },
  { key: 'acts', label: t('waf.table.actions'), value: (r) => r.acts, hidden: true },
  { key: 'msg', label: t('waf.table.msg'), value: (r) => r.msg },
  { key: 'hosts', label: t('waf.table.hosts'), value: (r) => (r.hosts || []).join(', '), hidden: true },
  { key: 'file', label: t('waf.table.file'), value: (r) => r.file + ':' + r.line, hidden: true },
])

async function load() {
  loading.value = true
  error.value = null
  try { md.value = await get('/waf/model') } catch (e) { error.value = e } finally { loading.value = false }
}
onMounted(load)
</script>

<style scoped>
.scorelayout { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr); gap: 8px 32px; align-items: start; margin-bottom: 8px; }
.scol > .charthead:not(:first-child), .scol > .subhead { margin-top: 18px; }
.examples li { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 12px; }
.exouts { display: inline-flex; flex-wrap: wrap; gap: 6px; }
.detchips { display: flex; flex-wrap: wrap; gap: 6px; }
.detlines { display: grid; gap: 2px; }
.detline { display: grid; grid-template-columns: minmax(10em, max-content) 2.2em minmax(0, 1fr); gap: 10px; padding: 3px 0;
  border-bottom: 1px dashed var(--border); }
.detline:last-child { border-bottom: 0; }
.dl-op { color: var(--muted); text-align: center; }
.dl-path { overflow-wrap: anywhere; }
@media (max-width: 1000px) { .scorelayout { grid-template-columns: minmax(0, 1fr); } }
@media (max-width: 640px) { .detline { grid-template-columns: minmax(0, 1fr); gap: 0; } .dl-op { text-align: left; } }
.cardhead { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; }
.cardhead h2 { margin: 0; }
.lanepick { display: flex; flex-wrap: wrap; gap: 4px; }
.summary h2 { display: flex; gap: 6px; align-items: center; }
.sumlist { list-style: none; margin: 0 0 8px; padding: 0; display: grid; gap: 8px; }
.sumlist li { display: flex; gap: 10px; align-items: flex-start; line-height: 1.5; }
.sumlist li.sum-main { font-size: 1.05em; }
.sumlist li.sum-warn { color: var(--warn); }
.sumicon { flex: none; display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 6px; border: 1.5px solid var(--border-strong); background: var(--panel-2); }
.flowwrap { overflow-x: auto; }
.flowsvg { width: 100%; height: auto; display: block; margin: 0 auto; }
.fl-head { height: 100%; display: flex; align-items: center; gap: 6px; font-weight: 700; color: var(--text); padding: 0 4px; box-sizing: border-box; }
.fl-head.lanehead { justify-content: center; border-bottom: 2px solid var(--border-strong); }
.fl-box { box-sizing: border-box; height: 100%; border-radius: 8px; border: 1.5px solid var(--border-strong); background: var(--panel); color: var(--text);
  display: flex; gap: 8px; align-items: center; padding: 6px 10px; cursor: pointer; overflow: hidden; outline: none; }
.fl-box.stagebox { border-left-width: 6px; }
.fl-box.cell { flex-direction: column; align-items: flex-start; justify-content: center; gap: 2px; }
.fl-box:hover, .fl-box:focus-visible { border-color: var(--accent); }
.fl-box.stagebox:focus-visible { box-shadow: 0 0 0 3px var(--accent); }
.fl-box.sel { border-color: var(--accent); }
.fl-num { flex: none; width: 22px; height: 22px; border-radius: 50%; background: var(--panel-2); border: 1px solid var(--border-strong); font-size: 12px; font-weight: 700; display: inline-flex; align-items: center; justify-content: center; }
.fl-txt { min-width: 0; }
.fl-name { font-weight: 600; font-size: 14.5px; display: flex; gap: 6px; align-items: center; line-height: 1.25; }
.fl-sub { font-size: 12px; color: var(--muted); line-height: 1.3; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; }
.fl-selband { fill: var(--panel-2); stroke: var(--accent); stroke-width: 1; stroke-dasharray: 4 3; }
.fl-edge { fill: none; stroke: var(--muted); stroke-width: 1.5; }
.fl-edge.lane.eff-blocks { stroke: var(--blocked); stroke-dasharray: 3 3; }
.fl-arrowhead { fill: var(--muted); }

/* effect colours: always next to an icon and a text */
.stagebox.eff-blocks, .lgbox.eff-blocks { border-left-color: var(--blocked); }
.stagebox.eff-scores { border-left-color: var(--score); }
.stagebox.eff-logs { border-left-color: var(--logged); }
.stagebox.eff-loosens { border-left-color: var(--ok); }
.stagebox.eff-not_inspected { border-left-color: var(--muted); border-style: dashed; }
.stagebox.eff-info { border-left-color: var(--border-strong); }
.cell.eff-blocks { background: var(--blocked-bg); border-color: var(--blocked); }
.cell.eff-blocks .fl-name { color: var(--blocked); }
.cell.eff-scores { background: var(--score-bg); border-color: var(--score); }
.cell.eff-logs { background: var(--logged-bg); border-color: var(--logged); }
.cell.eff-loosens { background: var(--ok-bg); border-color: var(--ok); }
.cell.eff-not_inspected { background: var(--panel-2); border-style: dashed; }
.cell.eff-not_applicable, .cell.eff-not_reached { background: var(--panel); border-style: dotted; color: var(--muted); }
.cell.eff-not_applicable .fl-name, .cell.eff-not_reached .fl-name { font-weight: 500; }
.flowlegend { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px 14px; }
.legend { flex-wrap: wrap; }
.lgbox { display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 20px; border-radius: 4px; border: 1.5px solid var(--border-strong); margin-right: 4px; }
.lgbox.eff-blocks { background: var(--blocked-bg); border-color: var(--blocked); color: var(--blocked); }
.lgbox.eff-scores { background: var(--score-bg); border-color: var(--score); }
.lgbox.eff-logs { background: var(--logged-bg); border-color: var(--logged); }
.lgbox.eff-loosens { background: var(--ok-bg); border-color: var(--ok); }
.lgbox.eff-not_inspected { border-style: dashed; }
.lgbox.eff-not_applicable { border-style: dotted; }
.sumicon.eff-blocks { border-color: var(--blocked); background: var(--blocked-bg); color: var(--blocked); }
.sumicon.eff-logs { border-color: var(--logged); background: var(--logged-bg); }
.sumicon.eff-loosens { border-color: var(--ok); background: var(--ok-bg); }
.sumicon.eff-not_inspected { border-style: dashed; }

.badge[class*="bd-"] { display: inline-flex; gap: 4px; align-items: center; }
.bd-blocks { color: var(--blocked); background: var(--blocked-bg); }
.bd-scores { color: var(--text); background: var(--score-bg); }
.bd-logs { color: var(--text); background: var(--logged-bg); }
.bd-loosens { color: var(--ok); background: var(--ok-bg); }
.bd-not_inspected, .bd-info, .bd-not_applicable, .bd-not_reached, .bd-removed { color: var(--muted); background: var(--panel-2); }

.flowdesc { margin-top: 10px; padding: 10px 12px; border-left: 3px solid var(--accent); background: var(--panel-2); border-radius: 0 6px 6px 0; }
.flowdesc h3 { margin: 0 0 4px; font-size: 15px; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.flowdesc p { margin: 0 0 6px; white-space: pre-line; }
.lanenotes { margin: 0 0 6px; padding-left: 18px; }
.idchips { display: flex; flex-wrap: wrap; gap: 4px; margin: 6px 0; }
.descbtns { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.subhead { font-size: 15px; margin: 14px 0 6px; }
.examples { list-style: none; padding: 0; margin: 0 0 12px; display: grid; gap: 6px; }
.examples li { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.exscore { min-width: 13em; }
.sw-score { background: var(--score); }
.sw-over { background: var(--blocked); }
.sw-thr { background: transparent; border-top: 2px dashed var(--text); height: 0; width: 16px; }
.filterbar { display: flex; gap: 6px; align-items: center; margin-bottom: 6px; }
@media (max-width: 700px) {
  .exscore { min-width: 0; width: 100%; }
}
</style>
