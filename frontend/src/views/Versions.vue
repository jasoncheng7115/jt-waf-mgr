<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('versions.title') }}</h1>
      <button type="button" class="btn small ghost" :aria-pressed="showGuide ? 'true' : 'false'" @click="showGuide = !showGuide"><Icon name="help" />{{ t('guide.wf.toggle') }}</button>
      <RouterLink class="btn small ghost" to="/changes"><Icon name="change" />{{ t('nav.changes') }}</RouterLink>
    </div>
    <p class="muted">{{ t('versions.intro') }}</p>
    <section v-if="showGuide" class="card">
      <FlowSteps :title="t('guide.versions.title')" :steps="guideSteps" :note="t('guide.versions.note')" />
    </section>
    <ErrorBox :error="error" />
    <Loading v-if="loading && !items.length" />
    <section v-if="items.length" class="card">
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.versions.by_state') }}</h3><SegBar :parts="stateParts" :label="t('chart.versions.by_state')" /></div>
        <div><h3 class="charthead">{{ t('chart.versions.by_kind') }}</h3><SegBar :parts="kindParts" :label="t('chart.versions.by_kind')" /></div>
      </div>
    </section>

    <section v-if="restoring" class="card">
      <form class="form" @submit.prevent="rollback">
        <p class="alert warn">{{ t('versions.restore_warning', { v: restoring.version }) }}</p>
        <label class="field"><span>{{ t('change.note') }}</span><textarea ref="noteBox" v-model="note" rows="2" maxlength="2000" required></textarea></label>
        <div class="actions">
          <button type="submit" class="btn primary" :disabled="busy || !note.trim()"><Icon name="rollback" />{{ t('versions.restore') }}</button>
          <button type="button" class="btn ghost" @click="restoring = null"><Icon name="cancel" />{{ t('common.cancel') }}</button>
        </div>
      </form>
    </section>
    <ErrorBox :error="actionError" />

    <RowTimeline v-model:window="win" :rows="items" ts-key="created_at" :series="tlSeries" />
    <DataTable id="versions" :columns="cols" :rows="shownItems" row-key="version" :default-sort="{ key: 'version', dir: -1 }">
      <template #cell-created_at="{ row }">{{ fmtShortTime(row.created_at) }}</template>
      <template #cell-kind="{ row }">{{ t('versions.kind_' + row.kind) }}<div v-if="row.change_id" class="sub"><RouterLink :to="'/changes/' + row.change_id">#{{ row.change_id }}</RouterLink></div></template>
      <template #cell-state="{ row }"><span class="badge" :class="VCLS[row.state] || 'b-logged'">{{ t('vstate.' + row.state) }}</span></template>
      <template #cell-result="{ row }">
        <div v-if="row.summary"><TruncText :text="row.summary" :max="200" /></div>
        <div v-if="row.step && row.step !== 'done'" class="sub warn">{{ t('versions.step') }}: {{ tOr('apply_step.' + row.step, row.step) }}</div>
        <details v-if="row.health && Object.keys(row.health).length" class="sub"><summary>{{ t('versions.health') }}</summary>
          <ul class="plainlist small"><li v-for="(hv, u) in row.health" :key="u"><span class="mono breakall">{{ safeText(u, 300) }}</span>
            <span class="mono">{{ safeText(hv[0], 30) }} → {{ safeText(hv[1], 30) }}</span></li></ul></details>
        <details v-if="row.nginx_t" class="sub"><summary>nginx -t</summary><pre class="code small">{{ safeMultiline(row.nginx_t) }}</pre></details>
      </template>
      <template #cell-actions="{ row }">
        <button v-if="canRollback && ['applied', 'superseded'].includes(row.state) && row.version !== current" type="button"
                class="btn small" @click="open(row)"><Icon name="rollback" />{{ t('versions.restore') }}</button>
        <span v-if="row.version === current" class="badge b-ok">{{ t('versions.current') }}</span>
      </template>
    </DataTable>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api.js'
import RowTimeline from '../components/RowTimeline.vue'
import { inWindow } from '../timeWindow.js'
import { t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { safeText, safeMultiline, fmtShortTime } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import TruncText from '../components/TruncText.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'

const VCLS = { applied: 'b-ok', pending: 'b-int', superseded: 'b-logged', failed: 'b-blocked' }
const router = useRouter()
const items = ref([])
const win = ref(null)
const shownItems = computed(() => inWindow(items.value, 'created_at', win.value))
const tlSeries = computed(() => [{ key: 'ok', label: t('vstate.applied'), tone: 's1', test: (r) => ['applied', 'superseded'].includes(r.state) }, { key: 'other', label: t('timeline.other'), tone: 's3', test: () => true }])
const loading = ref(false)
const error = ref(null)
const actionError = ref(null)
const busy = ref(false)
const restoring = ref(null)
const note = ref('')
const noteBox = ref(null)
const canRollback = computed(() => hasRole('approver'))
const current = computed(() => (items.value.find((v) => v.state === 'applied') || {}).version)

const GUIDE_KEY = 'jtwaf.guide.versions'
function readGuide() { try { return localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
const showGuide = ref(readGuide())
watch(showGuide, (v) => { try { localStorage.setItem(GUIDE_KEY, v ? '1' : '0') } catch { /* private mode */ } })

const guideSteps = computed(() => [
  { key: 'new', label: t('guide.versions.new'), desc: t('guide.versions.new_d'), icon: 'versions' },
  { key: 'current', label: t('guide.versions.current'), desc: t('guide.versions.current_d'), icon: 'check' },
  { key: 'restore', label: t('guide.versions.restore'), desc: t('guide.versions.restore_d'), icon: 'rollback' },
  { key: 'apply', label: t('guide.versions.apply'), desc: t('guide.versions.apply_d'), icon: 'server' },
  { key: 'after', label: t('guide.versions.after'), desc: t('guide.versions.after_d'), icon: 'history' },
])

const resultText = (v) => [v.summary, v.step && v.step !== 'done' ? tOr('apply_step.' + v.step, v.step) : '', v.nginx_t].filter(Boolean).join(' ')
const cols = computed(() => [
  { key: 'version', label: t('versions.version'), required: true, align: 'num' },
  { key: 'created_at', label: t('change.created'), nowrap: true, text: (v) => fmtShortTime(v.created_at) },
  { key: 'kind', label: t('versions.kind'), nowrap: true, value: (v) => t('versions.kind_' + v.kind), text: (v) => t('versions.kind_' + v.kind) + (v.change_id ? ' #' + v.change_id : '') },
  { key: 'state', label: t('change.state'), value: (v) => t('vstate.' + v.state) },
  { key: 'result', label: t('versions.result'), value: (v) => v.summary || '', text: resultText },
  { key: 'actions', label: t('common.actions'), sortable: false, filterable: false },
])

const stateParts = computed(() => [
  { key: 'applied', label: t('vstate.applied'), tone: 'good' },
  { key: 'superseded', label: t('vstate.superseded'), tone: 'muted' },
  { key: 'pending', label: t('vstate.pending'), tone: 's1' },
  { key: 'failed', label: t('vstate.failed'), tone: 'critical' },
].map((p) => Object.assign(p, { value: items.value.filter((v) => v.state === p.key).length })))
const kindParts = computed(() => ['change', 'adopt', 'rollback'].map((k, i) => ({
  key: k, label: t('versions.kind_' + k), value: items.value.filter((v) => v.kind === k).length, tone: ['s1', 's2', 's3'][i],
})))

async function load() {
  loading.value = true
  try { items.value = (await get('/versions', { limit: 200 })).items || [] } catch (e) { error.value = e } finally { loading.value = false }
}
async function open(v) {
  restoring.value = v
  note.value = ''
  actionError.value = null
  await nextTick()
  if (noteBox.value) { noteBox.value.scrollIntoView({ block: 'center' }); noteBox.value.focus() }
}
async function rollback() {
  busy.value = true
  actionError.value = null
  try {
    const r = await post('/versions/' + restoring.value.version + '/rollback', { note: note.value })
    router.push('/changes/' + r.change_id)
  } catch (e) { actionError.value = e } finally { busy.value = false }
}
onMounted(load)
</script>
