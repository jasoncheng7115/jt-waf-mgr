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
      <!-- OWASP CRS versions: what is in use, the newest release, a downloaded and verified one -->
      <section v-if="upd" class="card crsupd">
        <h2><Icon name="download" /> {{ t('crsupd.title') }}</h2>
        <div class="crshead">
          <div class="crsver">
            <span class="muted small">{{ t('crsupd.in_use') }}</span>
            <b class="v">{{ upd.location ? upd.location.version || '—' : t('crsupd.none') }}</b>
            <span v-if="st.state" class="badge" :class="STATE_CLS[st.state] || 'b-logged'">{{ tOr('crsupd.state.' + st.state, st.state) }}</span>
          </div>
          <div class="crscheck">
            <span class="muted small">{{ t('crsupd.checked') }} · {{ st.checked_at ? fmtMinute(st.checked_at) : t('crsupd.never_checked') }}</span>
            <button v-if="isAdmin" type="button" class="btn small" :disabled="busy || !upd.manage" @click="checkNow"><Icon name="refresh" />{{ t('crsupd.check_now') }}</button>
          </div>
        </div>
        <p v-if="checkMsg" class="muted small" role="status">{{ checkMsg }}</p>
        <dl class="kv crskv">
          <template v-if="upd.location"><dt>{{ t('crsupd.location') }}</dt>
            <dd class="mono small breakall">{{ safeText(upd.location.path, 200) }}<template v-if="upd.location.link"><span class="muted"> → </span>{{ safeText(upd.location.target, 200) }}</template></dd></template>
          <template v-if="upd.versions.length"><dt>{{ t('crsupd.on_disk') }}</dt>
            <dd class="chips"><span v-for="v in upd.versions" :key="v" class="chip mono" :class="{ cur: upd.location && v === upd.location.version }">{{ v }}<span v-if="upd.location && v === upd.location.version" class="muted small gapl">{{ t('crsupd.current') }}</span></span></dd></template>
          <dt class="sw">{{ t('crsupd.managed') }}</dt><dd>
            <label v-if="isAdmin" class="switch"><input type="checkbox" :checked="upd.manage" :disabled="busy" @change="setManage($event.target.checked)">
              <span class="knob" aria-hidden="true"></span><span>{{ upd.manage ? t('uiset.on') : t('uiset.off') }}</span></label>
            <span v-else>{{ upd.manage ? t('uiset.on') : t('uiset.off') }}</span>
            <div class="muted small">{{ t('crsupd.managed_hint', { n: upd.wait_days }) }}</div></dd>
          <template v-if="st.candidate"><dt>{{ t('crsupd.newest') }}</dt><dd>{{ st.candidate.version }}<div class="muted small">{{ t('crsupd.published', { at: fmtMinute(st.candidate.published_at), ready: fmtMinute(st.candidate.ready_at) }) }}</div></dd></template>
          <template v-if="st.staged"><dt>{{ t('crsupd.staged') }}</dt><dd><b>{{ st.staged.version }}</b><div class="muted small">{{ t('crsupd.staged_hint', { at: fmtMinute(st.staged.verified_at), n: st.staged.files }) }}</div></dd></template>
          <template v-if="st.newer_major"><dt>{{ t('crsupd.major') }}</dt><dd>{{ t('crsupd.major_hint', { v: st.newer_major }) }}</dd></template>
        </dl>
        <p v-if="upd.manage && upd.external_updater" class="alert warn">{{ t('crsupd.external', { path: safeText(upd.external_updater, 200) }) }}</p>
        <p v-if="upd.location && !upd.location.link" class="alert info">{{ t('crsupd.not_link') }}</p>
        <p v-if="st.state === 'error'" class="alert error">{{ safeText(st.error, 300) }}</p>
        <!-- switching: a change (sandbox comparison of both versions, a person approves, the root program switches) -->
        <div v-if="canPropose && switchTargets.length" class="crsswitch">
          <label class="field"><span>{{ t('crsupd.reason') }}</span>
            <textarea v-model="reason" rows="2" maxlength="2000" class="w-lg" :placeholder="t('crsupd.reason_hint')"></textarea></label>
          <div class="actions">
            <button v-for="x in switchTargets" :key="x.mode + x.version" type="button" class="btn small" :class="{ primary: x.mode !== 'rollback' }"
                    :disabled="busy || reason.trim().length < 5" @click="propose(x)">
              <Icon :name="x.mode === 'rollback' ? 'rollback' : 'test'" />{{ t({ install: 'crsupd.propose', rollback: 'crsupd.rollback', first_install: 'crsupd.propose_first' }[x.mode], { v: x.version }) }}</button>
          </div>
          <p class="muted small">{{ t('crsupd.switch_hint') }}</p>
        </div>
        <div v-if="proposed" class="alert success" role="status">{{ t('crsupd.proposed', { id: proposed }) }}
          <RouterLink :to="'/changes/' + proposed">{{ t('toggle.open_change') }}</RouterLink></div>
        <ErrorBox :error="updError" />
      </section>
      <section v-if="families.length" class="card">
        <h2><Icon name="shield" /> {{ t('crs.rules_by_family') }}</h2>
        <p class="muted small">{{ t('crs.rules_by_family_hint') }}</p>
        <div class="statetotals">
          <RouterLink v-for="s in STATES" :key="s" class="stchip" :to="{ path: '/rules', query: { source: 'crs', state: s } }">
            <Icon :name="STATE_ICON[s]" /><span class="lg" :class="'tone-' + STATE_TONE[s]"></span>{{ t('rulestate.' + s) }} <b>{{ fmtNum(totals[s]) }}</b></RouterLink>
        </div>
        <HBars :items="familyBars" :series="stateSeries" pickable :open-label="t('filter.open')"
               @pick="(it) => router.push({ path: '/rules', query: { source: 'crs', family: it.key } })" />
      </section>
      <div class="cols2">
        <section class="card">
          <h2><Icon name="settings" /> {{ t('crs.engine') }}</h2>
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
          <h2><Icon name="page" /> {{ t('crs.audit') }}</h2>
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
        <h2><Icon name="tool" /> {{ t('crs.plugins') }} <span class="count">{{ (crs.plugins || []).length }}</span></h2>
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
import { get, patch, post } from '../api.js'
import { t } from '../i18n.js'
import { safeText, fmtNum, fmtBytes, fmtMinute } from '../util.js'
import { hasRole } from '../store.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import StatusCard from '../components/StatusCard.vue'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'
import Meter from '../components/charts/Meter.vue'
import HBars from '../components/charts/HBars.vue'
import { useRouter } from 'vue-router'
import { tOr } from '../i18n.js'

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
// CRS rules per attack type, and whether they run (the rules list's summary for the CRS source)
const router = useRouter()
const STATES = ['on', 'partial', 'off', 'inactive']
const STATE_TONE = { on: 'good', partial: 'warning', off: 'blocked', inactive: 'muted' }
const STATE_ICON = { on: 'check', partial: 'warning', off: 'hide', inactive: 'timer' }
const families = ref([])
const stateSeries = computed(() => STATES.map((k) => ({ key: k, label: t('rulestate.' + k), tone: STATE_TONE[k] })))
const familyBars = computed(() => families.value.map((c) => ({
  key: c.key, label: tOr('family.' + c.key, c.key), values: { on: c.on, partial: c.partial, off: c.off, inactive: c.inactive },
  sub: t('rules.group_counts', { n: fmtNum(c.on + c.partial + c.off + c.inactive), off: fmtNum(c.off + c.partial), inactive: fmtNum(c.inactive) }),
})))
const totals = computed(() => Object.fromEntries(STATES.map((k) => [k, families.value.reduce((a, c) => a + (c[k] || 0), 0)])))
// CRS versions and updates
const upd = ref(null)
const st = computed(() => (upd.value && upd.value.status) || {})
const busy = ref(false)
const updError = ref(null)
const checkMsg = ref('')
const isAdmin = computed(() => hasRole('admin'))
const canPropose = computed(() => hasRole('approver'))
const reason = ref('')
const proposed = ref(null)
// what the CRS can switch to: the staged release, and the other versions kept on the host
const switchTargets = computed(() => {
  if (!upd.value) return []
  if (!upd.value.location) {      // no CRS yet: a verified release can be installed for the first time
    return st.value.staged ? [{ mode: 'first_install', version: st.value.staged.version }] : []
  }
  const cur = upd.value.location.version
  const out = []
  if (st.value.staged && st.value.staged.version !== cur) out.push({ mode: 'install', version: st.value.staged.version })
  for (const v of upd.value.versions || []) if (v !== cur && !out.some((x) => x.version === v)) out.push({ mode: 'rollback', version: v })
  return out
})
async function propose(x) {
  busy.value = true
  updError.value = null
  proposed.value = null
  try {
    const r = await post('/crs/updates/propose', { mode: x.mode, version: x.version, reason: reason.value.trim() })
    proposed.value = r.change_id
    reason.value = ''
  } catch (e) { updError.value = e } finally { busy.value = false }
}
const STATE_CLS = { current: 'b-ok', ready: 'b-warn', waiting: 'b-int', error: 'b-blocked', off: 'b-logged' }
async function loadUpd() { try { upd.value = await get('/crs/updates') } catch (e) { updError.value = e } }
async function setManage(on) {
  busy.value = true
  updError.value = null
  try { await patch('/settings/ui', { 'crs.manage': on }); await loadUpd() } catch (e) { updError.value = e } finally { busy.value = false }
}
async function checkNow() {
  busy.value = true
  updError.value = null
  try { await post('/crs/updates/check', {}); checkMsg.value = t('crsupd.check_requested'); setTimeout(loadUpd, 8000) } catch (e) { updError.value = e } finally { busy.value = false }
}
onMounted(loadUpd)
onMounted(() => { get('/rules', { source: 'crs', limit: 1 }).then((r) => { families.value = r.summary || [] }).catch(() => { /* optional */ }) })
onMounted(async () => {
  try { crs.value = await get('/crs') } catch (e) { error.value = e }
})
</script>

<style scoped>
.crsupd .kv dd > div { margin-top: 4px; }
.crshead { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px 16px; padding: 12px 14px; margin-bottom: 14px; border: 1px solid var(--border); border-radius: 10px; background: var(--panel-2); }
.crsver { display: flex; align-items: center; gap: 10px; }
.crsver .v { font-size: 22px; font-variant-numeric: tabular-nums; }
.crscheck { display: flex; align-items: center; gap: 12px; }
.crskv { row-gap: 12px; align-items: start; }
.crskv dt.sw { padding-top: 2px; }
.crskv dd.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.crskv .chip { display: inline-flex; align-items: center; padding: 2px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 13px; }
.crskv .chip.cur { border-color: var(--accent); }
.wafeffective { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; border: 1px solid var(--border-strong); background: var(--panel-2); color: var(--text); }
</style>
