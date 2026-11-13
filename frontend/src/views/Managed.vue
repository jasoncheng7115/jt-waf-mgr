<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('managed.title') }}</h1>
      <button type="button" class="btn small ghost" :aria-pressed="showGuide ? 'true' : 'false'" @click="showGuide = !showGuide"><Icon name="help" />{{ t('guide.wf.toggle') }}</button>
      <RouterLink class="btn small ghost" to="/versions"><Icon name="versions" />{{ t('nav.versions') }}</RouterLink>
      <RouterLink class="btn small ghost" to="/rules"><Icon name="shield" />{{ t('nav.rules') }}</RouterLink>
      <RouterLink v-if="m && m.adopted && canPropose" class="btn primary" to="/changes/new"><Icon name="add" />{{ t('changes.new') }}</RouterLink>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="!m && !error" />
    <RulesFileTransfer v-if="m" :adopted="!!m.adopted" />
    <template v-if="m">
      <div v-if="m.drift" class="alert error">{{ t('managed.drift_now') }}
        <ul class="plainlist small">
          <li v-for="(f, k) in m.files" :key="k"><span class="mono">{{ safeText(f.path, 300) }}</span>
            <span v-if="f.drift" class="badge b-blocked">{{ t('managed.changed_on_disk') }}</span></li>
        </ul>
        <div v-if="canRestore && m.current_version" class="driftfix">
          <label class="field"><span>{{ t('managed.restore_note') }}</span>
            <input v-model="restoreNote" maxlength="500" :placeholder="t('managed.restore_note_ph')" /></label>
          <button type="button" class="btn small danger" :disabled="restoring || restoreNote.trim().length < 10" @click="restore">
            <Icon name="rollback" />{{ t('managed.restore_files', { v: m.current_version }) }}</button>
        </div>
      </div>

      <section v-if="showGuide || m.drift" class="card guide">
        <FlowSteps v-if="showGuide" :title="t('guide.adopt.title')" :steps="adoptSteps" />
        <div v-if="showGuide || m.drift" class="drift">
          <h3 class="charthead"><Icon name="warning" />{{ t('guide.adopt.drift_title') }}</h3>
          <p class="small">{{ t('guide.adopt.drift_what') }}</p>
          <p class="small">{{ t('guide.adopt.drift_fix') }}</p>
        </div>
      </section>

      <!-- not adopted -->
      <section v-if="!m.adopted" class="card form">
        <h2><Icon name="adopt" /> {{ t('managed.not_adopted_title') }}</h2>
        <p>{{ t('managed.not_adopted_intro', { dir: m.dir }) }}</p>
        <div v-if="m.import && m.import.error" class="alert error">{{ safeText(m.import.error, 300) }}</div>
        <template v-if="m.import && m.import.sources">
          <dl class="kv">
            <template v-for="(s, k) in m.import.sources" :key="k">
              <dt>{{ t('placement.' + k) }}</dt><dd class="mono breakall">{{ safeText(s.path, 300) }} → {{ safeText(m.files[k] && m.files[k].path, 300) }}</dd>
            </template>
            <template v-for="x in m.import.insert || []" :key="'i' + x.placement">
              <dt>{{ t('placement.' + x.placement) }}</dt>
              <dd><span class="muted">{{ t('managed.no_site_file') }}</span>
                <span class="mono breakall">{{ t(x.where === 'before' ? 'managed.insert_before' : 'managed.insert_after', { file: safeText(x.file, 300), anchor: safeText(x.anchor, 300) }) }}</span></dd>
            </template>
            <dt>{{ t('managed.import_rules') }}</dt><dd class="mono">{{ m.import.rules }}</dd>
            <dt>{{ t('managed.import_comments') }}</dt><dd class="mono">{{ m.import.comment_blocks }}</dd>
          </dl>
          <p class="muted small">{{ t('managed.adopt_steps') }}</p>
        </template>
        <div v-if="m.adoption_change" class="actions">
          <span>{{ t('managed.adoption_change') }}</span>
          <RouterLink :to="'/changes/' + m.adoption_change.id" class="mono">#{{ m.adoption_change.id }}</RouterLink>
          <StateBadge :state="m.adoption_change.state" />
        </div>
        <div v-if="m.import && m.import.possible === false" class="alert warn">{{ t('managed.no_crs') }}
          <a :href="guideUrl" target="_blank" rel="noopener">{{ t('managed.install_guide') }}</a></div>
        <ErrorBox :error="actionError" />
        <div v-if="isAdmin" class="actions">
          <button type="button" class="btn primary" :disabled="busy || adoptionOpen || !(m.import && m.import.possible)" @click="adopt"><Icon name="adopt" />{{ t('managed.adopt') }}</button>
        </div>
        <p v-else class="muted small">{{ t('managed.adopt_admin_only') }}</p>
      </section>

      <!-- adopted -->
      <template v-else>
        <section class="card">
          <dl class="kv two">
            <dt>{{ t('managed.current_version') }}</dt><dd class="mono">{{ m.current_version ?? '—' }}</dd>
            <dt>{{ t('managed.dir') }}</dt><dd class="mono breakall">{{ safeText(m.dir, 300) }}</dd>
          </dl>
          <div v-if="rules.length" class="chartgrid">
            <div><h3 class="charthead">{{ t('chart.managed.by_category') }}</h3><HBars :items="categoryItems" :series="countSeries" /></div>
            <div>
              <h3 class="charthead">{{ t('chart.managed.by_file') }}</h3><SegBar :parts="fileParts" :label="t('chart.managed.by_file')" />
              <h3 class="charthead sub-chart">{{ t('chart.managed.by_origin') }}</h3><SegBar :parts="originParts" :label="t('chart.managed.by_origin')" />
              <h3 class="charthead sub-chart">{{ t('chart.managed.by_status') }}</h3><SegBar :parts="statusParts" :label="t('chart.managed.by_status')" />
            </div>
          </div>
          <div class="filters inline">
            <div class="field"><span><label for="managed-cat">{{ t('rules.category') }}</label></span>
              <SelectBox id="managed-cat" v-model="fcat" :options="catOptions" /></div>
            <label class="check inline-field"><input v-model="showDisabled" type="checkbox"> {{ t('managed.show_disabled') }}</label>
          </div>
        </section>

        <!-- disable / enable / delete: a change with a reason -->
        <section v-if="pendingOp" class="card">
          <form class="form" @submit.prevent="submitOp">
            <b>{{ t('op.' + pendingOp.op) }} {{ pendingOp.item.rule_id || '' }}</b>
            <p class="muted small">{{ t('managed.op_hint.' + pendingOp.op) }}</p>
            <label class="field"><span>{{ t('wizard.reason') }}</span><textarea ref="reasonBox" v-model="opReason" rows="2" maxlength="2000" required></textarea></label>
            <div class="actions">
              <button type="submit" class="btn primary" :disabled="busy || !opReason.trim()"><Icon name="send" />{{ t('wizard.submit') }}</button>
              <button type="button" class="btn ghost" @click="pendingOp = null"><Icon name="cancel" />{{ t('common.cancel') }}</button>
            </div>
          </form>
        </section>
        <ErrorBox :error="actionError" />
        <DataTable id="managed-rules" :columns="cols" :rows="shown" row-key="id" :row-class="(it) => ({ dim: !it.enabled })">
          <template #cell-rule_id="{ row }"><span class="mono nowrap"><RouterLink v-if="row.rule_id" :to="'/rules/' + row.rule_id">{{ row.rule_id }}</RouterLink><span v-else class="muted">—</span></span>
            <div class="sub">{{ t('placement.' + row.placement) }}</div></template>
          <template #cell-description="{ row }"><TruncText :text="row.msg || firstComment(row) || firstLine(row.text)" :max="200" />
            <details class="sub"><summary>{{ t('rule.text') }}</summary><RuleText :text="(row.comment ? row.comment + '\n' : '') + row.text" /></details></template>
          <template #cell-hosts="{ row }"><span v-for="hh in row.hosts || []" :key="hh" class="chip host"><TruncText :text="hh" :max="60" /></span><span v-if="!(row.hosts || []).length" class="muted">{{ t('rules.global') }}</span></template>
          <template #cell-origin="{ row }">{{ t('managed.origin_' + row.origin) }}<div v-if="row.change_id" class="sub"><RouterLink :to="'/changes/' + row.change_id">#{{ row.change_id }}</RouterLink></div></template>
          <template #cell-status="{ row }"><span class="badge" :class="row.enabled ? 'b-ok' : 'b-logged'">{{ row.enabled ? t('managed.enabled') : t('managed.disabled') }}</span></template>
          <template #cell-actions="{ row }">
            <div v-if="canPropose" class="rowactions">
              <RouterLink v-if="row.kind !== 'raw' || isAdmin" class="btn small ghost" :to="{ path: '/changes/new', query: { item: row.id } }"><Icon name="edit" />{{ t('managed.modify') }}</RouterLink>
              <button type="button" class="btn small ghost" @click="open(row, row.enabled ? 'disable' : 'enable')"><Icon :name="row.enabled ? 'hide' : 'show'" />{{ row.enabled ? t('managed.disable') : t('managed.enable') }}</button>
              <button type="button" class="btn small danger" @click="open(row, 'delete')"><Icon name="delete" />{{ t('managed.delete') }}</button>
            </div>
          </template>
        </DataTable>
      </template>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api.js'
import { t, lang } from '../i18n.js'
import { hasRole, refreshPending } from '../store.js'
import { safeText } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import TruncText from '../components/TruncText.vue'
import StateBadge from '../components/StateBadge.vue'
import RulesFileTransfer from '../components/RulesFileTransfer.vue'
import Icon from '../components/Icon.vue'
import SelectBox from '../components/SelectBox.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import RuleText from '../components/RuleText.vue'
import HBars from '../components/charts/HBars.vue'
import SegBar from '../components/charts/SegBar.vue'

const CATS = ['exclusion', 'confident_block', 'system', 'redaction', 'plugin_toggle', 'other']
const FINAL = ['applied', 'rejected', 'cancelled', 'failed', 'apply_failed', 'rolled_back']
const router = useRouter()
const m = ref(null)
const canRestore = computed(() => hasRole('approver'))
const restoreNote = ref('')
const restoring = ref(false)
async function restore() {
  if (!window.confirm(t('managed.restore_confirm'))) return
  restoring.value = true
  error.value = null
  try {
    const r = await post('/versions/' + m.value.current_version + '/rollback', { note: restoreNote.value.trim(), overwrite_drift: true })
    restoreNote.value = ''
    if (r && r.change_id) router.push('/changes/' + r.change_id)
  } catch (e) { error.value = e } finally { restoring.value = false }
}
const error = ref(null)
const actionError = ref(null)
const busy = ref(false)
const fcat = ref('')
const showDisabled = ref(true)
const pendingOp = ref(null)
const opReason = ref('')
const reasonBox = ref(null)
const isAdmin = computed(() => hasRole('admin'))
const GUIDE = 'https://github.com/jasoncheng7115/jt-waf-mgr/blob/main/docs/MODSECURITY'
const guideUrl = computed(() => GUIDE + ({ 'zh-TW': '.zh-TW', ja: '.ja' }[lang.value] || '') + '.md')
const canPropose = computed(() => hasRole('operator'))
const adoptionOpen = computed(() => !!(m.value && m.value.adoption_change && !FINAL.includes(m.value.adoption_change.state)))

const GUIDE_KEY = 'jtwaf.guide.managed'
function readGuide() { try { return localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
const showGuide = ref(readGuide())
watch(showGuide, (v) => { try { localStorage.setItem(GUIDE_KEY, v ? '1' : '0') } catch { /* private mode */ } })

// adoption progress: not adopted -> adoption change (checks, approval, apply) -> managed
const adoptSteps = computed(() => {
  const x = m.value
  const ac = x && x.adoption_change
  const st = ac ? ac.state : null
  let s
  if (x && x.adopted) s = ['done', 'done', 'done', 'done', 'done', 'done']
  else if (!ac || ['rejected', 'cancelled'].includes(st)) s = ['current', 'todo', 'todo', 'todo', 'todo', 'todo']
  else if (st === 'checking') s = ['done', 'done', 'current', 'todo', 'todo', 'todo']
  else if (st === 'failed') s = ['done', 'done', 'fail', 'todo', 'todo', 'todo']
  else if (st === 'pending_approval') s = ['done', 'done', 'done', 'current', 'todo', 'todo']
  else if (['approved', 'applying'].includes(st)) s = ['done', 'done', 'done', 'done', 'current', 'todo']
  else if (st === 'apply_failed') s = ['done', 'done', 'done', 'done', 'fail', 'todo']
  else s = ['done', 'done', 'done', 'done', 'done', 'current']
  const to = ac && !(x && x.adopted) ? '/changes/' + ac.id : undefined
  return [
    { key: 'detect', label: t('guide.adopt.detect'), desc: t('guide.adopt.detect_d'), icon: 'search' },
    { key: 'import', label: t('guide.adopt.import'), desc: t('guide.adopt.import_d'), icon: 'adopt' },
    { key: 'equiv', label: t('guide.adopt.equiv'), desc: t('guide.adopt.equiv_d'), icon: 'test', to },
    { key: 'approve', label: t('guide.adopt.approve'), desc: t('guide.adopt.approve_d'), icon: 'approve', to },
    { key: 'switch', label: t('guide.adopt.switch'), desc: t('guide.adopt.switch_d'), icon: 'server', to },
    { key: 'managed', label: t('guide.adopt.managed'), desc: t('guide.adopt.managed_d'), icon: 'verify' },
  ].map((step, i) => Object.assign(step, { state: s[i] }))
})

const rules = computed(() => (m.value && m.value.items || []).filter((it) => it.kind !== 'comment' && !it.deleted))
const shown = computed(() => rules.value
  .filter((it) => showDisabled.value || it.enabled)
  .filter((it) => !fcat.value || it.category === fcat.value))

const catOf = (it) => (CATS.includes(it.category) ? it.category : 'other')
const catOptions = computed(() => [{ value: '', label: t('filter.all_categories') }].concat(CATS.map((c) => ({ value: c, label: t('category.' + c) }))))
const cols = computed(() => [
  { key: 'rule_id', label: t('rule.id'), required: true, align: 'num', value: (it) => it.rule_id || 0, text: (it) => String(it.rule_id || '') + ' ' + t('placement.' + it.placement) },
  { key: 'category', label: t('rules.category'), nowrap: true, value: (it) => t('category.' + catOf(it)) },
  { key: 'description', label: t('rule.description'), value: (it) => it.msg || firstComment(it) || firstLine(it.text),
    text: (it) => [it.msg, it.comment, it.text].filter(Boolean).join(' ') },
  { key: 'hosts', label: t('rule.hosts'), value: (it) => (it.hosts || []).join(' ') || t('rules.global') },
  { key: 'origin', label: t('managed.origin'), nowrap: true, value: (it) => t('managed.origin_' + it.origin), text: (it) => t('managed.origin_' + it.origin) + (it.change_id ? ' #' + it.change_id : '') },
  { key: 'status', label: t('managed.status'), value: (it) => (it.enabled ? t('managed.enabled') : t('managed.disabled')) },
  { key: 'actions', label: t('common.actions'), sortable: false, filterable: false },
])

const countSeries = computed(() => [{ key: 'n', label: t('managed.title'), tone: 's1' }])
const categoryItems = computed(() => CATS.map((c) => ({ key: c, label: t('category.' + c), values: { n: rules.value.filter((it) => catOf(it) === c).length } }))
  .filter((x) => x.values.n > 0).sort((a, b) => b.values.n - a.values.n))
const fileParts = computed(() => ['before', 'after'].map((p, i) => ({
  key: p, label: t('placement.' + p), value: rules.value.filter((it) => it.placement === p).length, tone: ['s1', 's2'][i],
})))
const originParts = computed(() => ['imported', 'created'].map((o, i) => ({
  key: o, label: t('managed.origin_' + o), value: rules.value.filter((it) => it.origin === o).length, tone: ['s1', 's2'][i],
})))
const statusParts = computed(() => [
  { key: 'on', label: t('managed.enabled'), value: rules.value.filter((it) => it.enabled).length, tone: 'good' },
  { key: 'off', label: t('managed.disabled'), value: rules.value.filter((it) => !it.enabled).length, tone: 'muted' },
])

function firstLine(s) { return String(s || '').split('\n')[0] }
function firstComment(it) { return String(it.comment || '').split('\n').map((l) => l.replace(/^#\s?/, '')).filter(Boolean).pop() || '' }

async function load() {
  try { m.value = await get('/managed') } catch (e) { error.value = e }
}
async function adopt() {
  busy.value = true
  actionError.value = null
  try {
    const r = await post('/managed/adopt', {})
    refreshPending(true)
    router.push('/changes/' + r.change_id)
  } catch (e) { actionError.value = e } finally { busy.value = false }
}
async function open(item, op) {
  pendingOp.value = { item, op }
  opReason.value = ''
  actionError.value = null
  await nextTick()
  if (reasonBox.value) { reasonBox.value.scrollIntoView({ block: 'center' }); reasonBox.value.focus() }
}
async function submitOp() {
  busy.value = true
  actionError.value = null
  try {
    const it = pendingOp.value.item
    const r = await post('/changes', { op: pendingOp.value.op, kind: it.kind, item_id: it.id, reason: opReason.value, spec: {} })
    refreshPending(true)
    router.push('/changes/' + r.change_id)
  } catch (e) { actionError.value = e } finally { busy.value = false }
}
onMounted(load)
</script>

<style scoped>
.guide { display: flex; flex-direction: column; gap: 12px; }
.drift p { margin: 0 0 6px; }
.drift .charthead { display: flex; align-items: center; gap: 6px; }
.sub-chart { margin-top: 10px; }
</style>
