<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('change.title') }} <span class="muted mono">#{{ safeText(id, 20) }}</span></h1>
      <RouterLink class="btn small ghost" to="/changes"><Icon name="back" />{{ t('common.back') }}</RouterLink>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="!c && !error" />
    <template v-if="c">
      <section class="card guide">
        <FlowSteps :title="t('guide.detail.title')" :steps="steps" />
        <FlowSteps v-if="applySteps" :title="t('guide.detail.apply_title', { v: ver.version })" :steps="applySteps"
                   :note="applyNote" compact />
      </section>
      <section class="card">
        <div class="reqline">
          <StateBadge :state="c.state" />
          <DirectionBadge :direction="c.direction" />
          <b>{{ t('op.' + c.op) }} · {{ t('kind.' + c.kind) }}</b>
          <span class="mono breakall">{{ safeText(c.summary, 300) }}</span>
        </div>
        <div v-if="busyStates.includes(c.state)" class="alert info">{{ t('change.in_progress.' + c.state) }}</div>
        <div v-if="c.error" class="alert error">{{ safeText(c.error, 2000) }}</div>
        <dl class="kv two">
          <dt>{{ t('change.proposed_by') }}</dt><dd>{{ safeText(c.proposed_by, 64) }}<span v-if="c.proposed_via === 'api'" class="chip tag">API</span></dd>
          <dt>{{ t('change.created') }}</dt><dd>{{ fmtTime(c.created_at) }}</dd>
          <dt>{{ t('wizard.rule_id') }}</dt><dd class="mono"><RouterLink v-if="c.rule_id" :to="'/rules/' + c.rule_id">{{ c.rule_id }}</RouterLink><template v-else>—</template></dd>
          <dt>{{ t('change.updated') }}</dt><dd>{{ fmtTime(c.updated_at) }}</dd>
          <dt>{{ t('change.base_version') }}</dt><dd class="mono">{{ c.base_version ?? '—' }}</dd>
          <dt>{{ t('change.applied_version') }}</dt><dd class="mono"><RouterLink v-if="c.applied_version" to="/versions">{{ c.applied_version }}</RouterLink><template v-else>—</template></dd>
        </dl>
        <h2>{{ t('change.reason') }}</h2>
        <pre class="code">{{ safeMultiline(c.reason) }}</pre>
        <div v-if="c.evidence_override" class="alert warn">{{ t('change.evidence_override') }}: {{ safeText(c.evidence_override, 2000) }}</div>
      </section>

      <!-- actions -->
      <section v-if="canApprove || canReject || canCancel || canRecheck" class="card form">
        <h2>{{ t('change.actions') }}</h2>
        <p v-if="c.direction !== 'tighten' && c.state === 'pending_approval'" class="muted small">{{ t('wizard.loosen_note') }}</p>
        <p v-if="own && canApprove" class="alert info">{{ t('change.own_note') }}</p>
        <div class="filters inline">
          <label class="field grow"><span>{{ t('change.note') }}</span>
            <input v-model="note" maxlength="2000" :placeholder="t('change.note_ph')"></label>
          <label v-if="canApprove && own && c.direction !== 'tighten'" class="field"><span>{{ t('change.totp') }}</span>
            <input v-model.trim="totp" inputmode="numeric" autocomplete="one-time-code" maxlength="7" class="mono" placeholder="123456"></label>
        </div>
        <label v-if="canRecheck" class="field"><span>{{ t('change.override') }}</span>
          <textarea v-model="override" rows="2" maxlength="2000" :placeholder="t('change.override_ph')"></textarea></label>
        <ErrorBox :error="actionError" />
        <div class="actions">
          <button v-if="canApprove" type="button" class="btn primary" :disabled="busy" @click="act('approve', { note, totp })"><Icon name="approve" />{{ t('change.approve') }}</button>
          <button v-if="canReject" type="button" class="btn danger" :disabled="busy || !note.trim()" :title="t('change.note_required')" @click="act('reject', { note })"><Icon name="reject" />{{ t('change.reject') }}</button>
          <button v-if="canRecheck" type="button" class="btn" :disabled="busy" @click="act('recheck', { evidence_override: override })"><Icon name="refresh" />{{ t('change.recheck') }}</button>
          <button v-if="canCancel" type="button" class="btn ghost" :disabled="busy" @click="act('cancel', {})"><Icon name="cancel" />{{ t('change.cancel') }}</button>
        </div>
      </section>

      <section v-if="c.rule_text" class="card">
        <h2>{{ t('rule.text') }}</h2>
        <pre class="code">{{ safeMultiline(c.rule_text) }}</pre>
      </section>

      <section v-if="c.diff && Object.keys(c.diff).length" class="card">
        <h2>{{ t('change.diff') }}</h2>
        <div v-for="(d, f) in c.diff" :key="f" class="diffblock">
          <div class="sub">{{ t('placement.' + f) }}</div>
          <DiffView :text="d" />
        </div>
      </section>

      <section class="card">
        <h2>{{ t('change.checks') }}</h2>
        <ChangeChecks :checks="c.checks" />
      </section>

      <section v-if="(c.tests || []).length" class="card">
        <h2>{{ t('wizard.tests') }}</h2>
        <TestCases :model-value="c.tests" disabled />
      </section>

      <section class="card">
        <h2>{{ t('change.timeline') }}</h2>
        <ul class="timeline">
          <li v-for="(l, i) in c.log || []" :key="i">
            <span class="ts">{{ fmtTime(l.ts) }}</span>
            <b>{{ tOr('clog.' + l.action, l.action) }}</b>
            <span class="muted">{{ safeText(l.actor, 64) }}</span>
            <div v-if="l.note" class="sub breakall">{{ safeText(l.note, 2000) }}</div>
          </li>
        </ul>
      </section>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, onUnmounted } from 'vue'
import { get, post } from '../api.js'
import { t, tOr } from '../i18n.js'
import { state, hasRole, refreshPending } from '../store.js'
import { safeText, safeMultiline, fmtTime } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import StateBadge from '../components/StateBadge.vue'
import DirectionBadge from '../components/DirectionBadge.vue'
import DiffView from '../components/DiffView.vue'
import ChangeChecks from '../components/ChangeChecks.vue'
import TestCases from '../components/TestCases.vue'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'

const props = defineProps({ id: { type: String, required: true } })
const c = ref(null)
const error = ref(null)
const actionError = ref(null)
const busy = ref(false)
const note = ref('')
const totp = ref('')
const override = ref('')
const busyStates = ['checking', 'approved', 'applying']
let timer = null

const own = computed(() => c.value && state.user && c.value.proposed_by === state.user.username && c.value.proposed_via === 'user')
const ownOrAdmin = computed(() => own.value || hasRole('admin'))
const canApprove = computed(() => c.value && c.value.state === 'pending_approval' && hasRole('approver') &&
  (c.value.op !== 'adopt' || hasRole('admin')))
const canReject = computed(() => c.value && c.value.state === 'pending_approval' && hasRole('approver'))
const canCancel = computed(() => c.value && ['checking', 'pending_approval'].includes(c.value.state) &&
  hasRole('operator') && ownOrAdmin.value)
const canRecheck = computed(() => c.value && ['failed', 'pending_approval'].includes(c.value.state) &&
  hasRole('operator') && ownOrAdmin.value && !['adopt', 'rollback'].includes(c.value.op))

// --- where the change stands (changes.py states, apply.py steps) ---------------------------
const lastLog = (actions) => ((c.value && c.value.log) || []).filter((l) => actions.includes(l.action)).pop()
function checkStep(key, r, x, rest) {
  if (x.op === 'rollback') return { state: 'skip', desc: t('guide.detail.not_needed') }
  if (x.state === 'checking') return key === 'static' ? { state: 'current', desc: t('guide.detail.running') } : { state: 'todo' }
  if (!r) return { state: rest }
  if (!r.ok) {
    if (key === 'evidence' && x.evidence_override) return { state: 'done', desc: t('guide.detail.overridden') }
    return { state: 'fail', desc: t('checks.failed') + (r.skipped ? ': ' + safeText(r.skipped, 100) : '') }
  }
  if (r.skipped) return { state: 'skip', desc: t('checks.skipped') + ': ' + safeText(r.skipped, 100) }
  return { state: 'done', desc: r.warning ? t('guide.detail.review') : t('checks.ok') }
}
const steps = computed(() => {
  const x = c.value
  if (!x) return []
  const st = x.state
  const ch = x.checks || {}
  const rest = ['rejected', 'cancelled'].includes(st) ? 'skip' : 'todo'
  const past = ['approved', 'applying', 'applied', 'apply_failed', 'rolled_back']
  const who = (l) => safeText(l ? l.actor : '', 64)
  let approval
  if (x.op === 'rollback') approval = { state: 'skip', desc: t('guide.detail.not_needed') }
  else if (st === 'pending_approval') approval = { state: 'current', desc: t(x.op === 'adopt' ? 'guide.detail.waiting_admin' : 'guide.detail.waiting') }
  else if (st === 'rejected') approval = { state: 'fail', desc: t('guide.detail.rejected_by', { who: who(lastLog(['rejected'])) }) }
  else if (st === 'cancelled') approval = { state: 'skip', desc: t('guide.detail.cancelled_by', { who: who(lastLog(['cancelled'])) }) }
  else if (past.includes(st)) {
    const l = lastLog(['approved', 'auto_approved'])
    approval = { state: 'done', desc: l && l.action === 'auto_approved' ? t('guide.detail.auto_approved') : (l ? t('guide.detail.approved_by', { who: who(l) }) : '') }
  } else approval = { state: rest }
  const queue = st === 'approved' ? { state: 'current', desc: t('guide.detail.queued') }
    : (['applying', 'applied', 'apply_failed', 'rolled_back'].includes(st) ? { state: 'done' } : { state: rest })
  const apply = st === 'applying' ? { state: 'current', desc: t('guide.detail.applying') }
    : st === 'apply_failed' ? { state: 'fail', desc: t('guide.detail.restored') }
      : ['applied', 'rolled_back'].includes(st) ? { state: 'done' } : { state: rest }
  const applied = st === 'applied' ? { state: 'done', desc: t('guide.detail.version', { v: x.applied_version }) }
    : st === 'rolled_back' ? { state: 'done', desc: t('guide.detail.rolled_back') }
      : st === 'apply_failed' ? { state: 'skip' } : { state: rest }
  const by = t('guide.detail.by', { who: safeText(x.proposed_by, 64) }) + (x.proposed_via === 'api' ? ' (API)' : '')
  return [
    { key: 'propose', label: t('guide.wf.propose'), icon: 'add', state: 'done', desc: by },
    { key: 'static', label: t('guide.wf.static'), icon: 'code', ...checkStep('static', ch.static, x, rest) },
    { key: 'evidence', label: t('guide.wf.evidence'), icon: 'search', ...checkStep('evidence', ch.evidence, x, rest) },
    { key: 'sandbox', label: t('guide.wf.sandbox'), icon: 'test', ...checkStep('sandbox', ch.sandbox, x, rest) },
    { key: 'approval', label: t('guide.wf.approval'), icon: 'approve', ...approval },
    { key: 'queue', label: t('guide.wf.queue'), icon: 'timer', ...queue },
    { key: 'apply', label: t('guide.wf.apply'), icon: 'server', ...apply },
    { key: 'applied', label: t('guide.wf.applied'), icon: 'check', to: ['applied', 'rolled_back'].includes(st) ? '/versions' : undefined, ...applied },
  ]
})

// the version this change produced (GET /versions), for the apply program's own steps
const ver = ref(null)
const APPLY_STEPS = ['request', 'drift', 'health_before', 'snapshot', 'write', 'nginx_t', 'reload', 'health_after']
const STEP_OF = { request: 'request', validate: 'request', preflight: 'request', drift: 'drift', nginx_t: 'nginx_t', reload: 'reload', health: 'health_after' }
const applySteps = computed(() => {
  const v = ver.value
  if (!v || v.state === 'pending') return null
  const failAt = v.state === 'failed' ? APPLY_STEPS.indexOf(STEP_OF[v.step] || '') : -2
  return APPLY_STEPS.map((k, i) => ({
    key: k, label: t('guide.apply.' + k),
    state: failAt === -2 ? 'done' : failAt === -1 ? 'todo' : i < failAt ? 'done' : i === failAt ? 'fail' : 'skip',
  }))
})
const applyNote = computed(() => {
  const v = ver.value
  if (!v || v.state !== 'failed') return ''
  return STEP_OF[v.step] ? tOr('apply_step.' + v.step, v.step) : t('guide.detail.internal')
})
async function loadVersion() {
  const x = c.value
  if (!x || !['applied', 'apply_failed', 'rolled_back'].includes(x.state)) { ver.value = null; return }
  if (ver.value && ver.value.change_id === x.id) return
  try {
    const items = (await get('/versions', { limit: 200 })).items || []
    ver.value = items.find((v) => v.change_id === x.id) || null
  } catch { ver.value = null }
}

async function load(quiet) {
  if (!quiet) { c.value = null; error.value = null; ver.value = null }
  try {
    c.value = await get('/changes/' + encodeURIComponent(props.id))
    error.value = null
  } catch (e) { if (!quiet) error.value = e }
  loadVersion()
  schedule()
}
function schedule() {
  clearTimeout(timer)
  if (c.value && busyStates.includes(c.value.state)) timer = setTimeout(() => load(true), 5000)
}
async function act(action, body) {
  busy.value = true
  actionError.value = null
  try {
    c.value = await post('/changes/' + encodeURIComponent(props.id) + '/' + action, body)
    note.value = ''
    totp.value = ''
    override.value = ''
    refreshPending(true)
    schedule()
  } catch (e) { actionError.value = e } finally { busy.value = false }
}
watch(() => props.id, () => load(false), { immediate: true })
onUnmounted(() => clearTimeout(timer))
</script>

<style scoped>
.guide { display: flex; flex-direction: column; gap: 12px; }
</style>
