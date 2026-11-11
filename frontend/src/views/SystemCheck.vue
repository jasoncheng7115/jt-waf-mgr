<!-- Self-diagnosis: program integrity, audit chain, time, disk, database, backups, collector, apply. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('syscheck.title') }}</h1>
      <button class="btn small ghost" type="button" :aria-expanded="showGuide ? 'true' : 'false'" @click="toggleGuide">
        <Icon name="help" />{{ showGuide ? t('guide.hide') : t('guide.show') }}</button>
      <button class="btn small primary" type="button" :disabled="running" @click="run"><Icon name="run" />{{ running ? t('common.working') : t('syscheck.run') }}</button>
      <button class="btn small ghost" type="button" :disabled="loading" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
    </div>
    <p class="muted">{{ t('syscheck.intro') }}</p>
    <template v-if="showGuide">
      <FlowSteps :title="t('guide.audit.title')" :steps="auditFlow" :note="t('guide.audit.note')" />
      <FlowSteps :title="t('guide.release.title')" :steps="releaseFlow" :note="t('guide.release.note')" />
    </template>
    <ErrorBox :error="error" />
    <Loading v-if="loading && !data" />
    <template v-if="data">
      <p class="muted small">{{ t('syscheck.generated', { at: fmtMinute(data.generated_at) }) }}
        · <span v-for="s in ['fail', 'warn', 'ok', 'info']" :key="s" class="sumcount"><span class="badge" :class="BADGE[s]">{{ t('syscheck.status.' + s) }}</span> {{ counts[s] || 0 }}</span></p>
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.syscheck.status') }}</h3><SegBar :parts="statusParts" :label="t('chart.syscheck.status')" /></div>
      </div>
      <div class="checkgrid">
        <section v-for="it in data.items" :key="it.key" class="card checkcard" :class="'cs-' + it.status">
          <div class="cardhead">
            <h2>{{ tOr('syscheck.k.' + it.key, it.key) }}</h2>
            <span class="badge" :class="BADGE[it.status] || 'b-logged'">{{ tOr('syscheck.status.' + it.status, it.status) }}</span>
          </div>
          <p class="muted small">{{ tOr('syscheck.d.' + it.key, '') }}</p>
          <p v-if="it.key === 'program_integrity' && it.details.status === 'not_installed'" class="alert info small">{{ t('syscheck.not_installed') }}</p>
          <ChainResult v-if="it.key === 'audit_chain'" :s="it.details" />
          <div v-if="it.key === 'program_integrity' && it.details.checked" class="itemchart">
            <h3 class="charthead">{{ t('chart.syscheck.files') }}</h3>
            <SegBar :parts="fileParts(it.details)" :label="t('chart.syscheck.files')" />
          </div>
          <div v-if="it.key === 'disk' && it.details.free_mb != null && it.details.min_free_mb" class="itemchart">
            <h3 class="charthead">{{ t('chart.syscheck.disk') }}</h3>
            <HBars :items="diskItems(it.details)" :series="[{ key: 'mb', label: 'MB', tone: 's1' }]" />
          </div>
          <dl class="kv">
            <template v-for="(v, k) in shownDetails(it)" :key="k">
              <dt>{{ tOr('syscheck.f.' + k, k) }}</dt>
              <dd>
                <HashText v-if="isHash(v)" :value="v" :len="16" />
                <span v-else-if="typeof v === 'boolean'" class="badge" :class="boolClass(it.key, k, v)">{{ v ? t('common.yes') : t('common.no') }}</span>
                <span v-else-if="v === null || v === undefined || v === ''" class="muted">—</span>
                <span v-else-if="Array.isArray(v)" class="mono small breakall">{{ v.length ? v.map((x) => safeText(typeof x === 'object' ? JSON.stringify(x) : x, 300)).join(', ') : '—' }}</span>
                <span v-else-if="k === 'size'" class="mono">{{ fmtBytes(v) }}</span>
                <span v-else-if="TIME_KEYS.includes(k)" class="mono">{{ fmtMinute(v) }}</span>
                <span v-else-if="typeof v === 'object'" class="mono small breakall">{{ safeText(JSON.stringify(v), 400) }}</span>
                <span v-else class="mono breakall">{{ safeText(v, 300) }}</span>
              </dd>
            </template>
          </dl>
          <RouterLink v-if="it.key === 'config_changes'" class="btn small ghost" to="/config-changes"><Icon name="change" />{{ t('nav.config_changes') }}</RouterLink>
          <RouterLink v-if="it.key === 'audit_chain'" class="btn small ghost" to="/admin/audit"><Icon name="history" />{{ t('nav.audit') }}</RouterLink>
          <RouterLink v-if="it.key === 'accounts'" class="btn small ghost" to="/admin/users"><Icon name="users" />{{ t('nav.users') }}</RouterLink>
        </section>
      </div>
    </template>

    <section class="card">
      <div class="cardhead">
        <h2>{{ t('backup.title') }}</h2>
        <button class="btn small" type="button" :disabled="backingUp || (bk && !bk.enabled)" @click="backupNow"><Icon name="backup" />{{ backingUp ? t('common.working') : t('backup.now') }}</button>
      </div>
      <ErrorBox :error="bkError" />
      <template v-if="bk">
        <p v-if="!bk.enabled" class="alert warn">{{ t('backup.disabled') }}</p>
        <dl class="kv two">
          <dt>{{ t('backup.dir') }}</dt><dd class="mono breakall">{{ safeText(bk.dir, 300) }}</dd>
          <dt>{{ t('backup.schedule') }}</dt><dd>{{ t('backup.schedule_v', { hour: bk.hour, days: bk.keep_days }) }}</dd>
          <dt>{{ t('backup.last') }}</dt>
          <dd><template v-if="bk.last && bk.last.at">{{ fmtMinute(bk.last.at) }}
            <span class="badge" :class="bk.last.ok ? 'b-ok' : 'b-blocked'">{{ bk.last.ok ? t('result.ok') : t('result.failed') }}</span>
            <span v-if="bk.last.error" class="small warn"> {{ safeText(bk.last.error, 200) }}</span></template><span v-else class="muted">—</span></dd>
        </dl>
        <div v-if="bk.items.length > 1" class="itemchart">
          <h3 class="charthead">{{ t('chart.backup.sizes') }}</h3>
          <HBars :items="backupItems" :series="[{ key: 'kb', label: 'KB', tone: 's1' }]" />
        </div>
        <DataTable id="system-backups" :columns="bkCols" :rows="bk.items" row-key="file" :default-sort="{ key: 'at', dir: -1 }" :page-size="10">
          <template #cell-file="{ row }"><span class="mono">{{ safeText(row.file, 120) }}</span></template>
          <template #cell-at="{ row }">{{ fmtMinute(row.at) }}</template>
          <template #cell-size="{ row }"><span class="mono">{{ fmtBytes(row.size) }}</span></template>
          <template #cell-sha256="{ row }"><HashText :value="row.sha256" :len="16" /></template>
          <template #cell-verify="{ row }">
            <button class="btn small" type="button" :disabled="!!verifying[row.file]" @click="verifyBackup(row)"><Icon name="verify" />{{ t('backup.verify') }}</button>
            <template v-if="results[row.file]">
              <span class="badge" :class="results[row.file].ok ? 'b-ok' : 'b-blocked'">{{ results[row.file].ok ? t('backup.verified_ok') : t('backup.verified_bad') }}</span>
              <span v-if="!results[row.file].ok" class="small warn"> {{ t('backup.sha_ok', { v: results[row.file].sha256_ok ? t('common.yes') : t('common.no') }) }} · integrity_check: {{ safeText(results[row.file].integrity_check, 100) }}</span>
            </template>
            <span v-if="verifyErrors[row.file]" class="small warn"> {{ errText(verifyErrors[row.file]) }}</span>
          </template>
        </DataTable>
        <p class="muted small">{{ t('backup.offsite', { days: bk.keep_days }) }}</p>
        <p class="muted small">{{ t('backup.restore') }}</p>
      </template>
    </section>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { get, post } from '../api.js'
import { t, tOr, errText } from '../i18n.js'
import { safeText, fmtMinute, fmtBytes } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import HashText from '../components/HashText.vue'
import ChainResult from '../components/ChainResult.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'

const BADGE = { ok: 'b-ok', warn: 'b-warn', fail: 'b-blocked', info: 'b-logged' }
const TIME_KEYS = ['checked_at', 'last_at', 'last_read', 'last_error', 'last_outside_at']
// shown by ChainResult instead of the generic list
const HIDE = { audit_chain: ['ok', 'reason', 'bad_id', 'anchor_problems', 'last_anchor', 'checked_at'] }

const data = ref(null)
const error = ref(null)
const loading = ref(false)
const running = ref(false)
const bk = ref(null)
const bkError = ref(null)
const backingUp = ref(false)
const verifying = reactive({})
const results = reactive({})
const verifyErrors = reactive({})

const GUIDE_KEY = 'jtwaf.guide.syscheck'
const showGuide = ref(readGuide())
function readGuide() { try { return window.localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage blocked */ }
}

// Audit trail protection (audit.py, integrity.py, compliance.Monitor) -- same steps as the audit log page.
const auditFlow = computed(() => [
  { key: 'row', icon: 'history', label: t('guide.audit.row'), desc: t('guide.audit.row_d') },
  { key: 'chain', icon: 'link', label: t('guide.audit.chain'), desc: t('guide.audit.chain_d') },
  { key: 'anchor', icon: 'fingerprint', label: t('guide.audit.anchor'), desc: t('guide.audit.anchor_d') },
  { key: 'verify', icon: 'verify', label: t('guide.audit.verify'), desc: t('guide.audit.verify_d') },
  { key: 'alert', icon: 'alert', label: t('guide.audit.alert'), desc: t('guide.audit.alert_d') },
])
// Program integrity (tools/make_release.sh, install.sh, integrity.verify_program, apply.program_refusal).
const releaseFlow = computed(() => {
  const prog = data.value && (data.value.items || []).find((x) => x.key === 'program_integrity')
  const st = prog ? prog.details.status : null
  return [
    { key: 'sign', icon: 'fingerprint', label: t('guide.release.sign'), desc: t('guide.release.sign_d') },
    { key: 'install', icon: 'key', label: t('guide.release.install'), desc: t('guide.release.install_d', { key: '/etc/jt-waf-mgr/release-key.pem' }) },
    { key: 'check', icon: 'timer', label: t('guide.release.check'), desc: t('guide.release.check_d'),
      state: st === 'ok' ? 'done' : st === 'failed' ? 'fail' : 'todo' },
    { key: 'apply', icon: 'tool', label: t('guide.release.apply'), desc: t('guide.release.apply_d') },
    { key: 'refuse', icon: 'block', label: t('guide.release.refuse'), desc: t('guide.release.refuse_d'),
      state: st === 'failed' ? 'current' : 'todo' },
  ]
})

const statusParts = computed(() => [
  { key: 'ok', label: t('syscheck.status.ok'), value: counts.value.ok || 0, tone: 'good' },
  { key: 'warn', label: t('syscheck.status.warn'), value: counts.value.warn || 0, tone: 'warning' },
  { key: 'fail', label: t('syscheck.status.fail'), value: counts.value.fail || 0, tone: 'critical' },
  { key: 'info', label: t('syscheck.status.info'), value: counts.value.info || 0, tone: 'muted' },
])
function fileParts(d) {
  const changed = (d.changed || []).length, missing = (d.missing || []).length, extra = (d.extra || []).length
  return [
    { key: 'same', label: t('chart.syscheck.files_same'), value: Math.max(0, (d.checked || 0) - changed - missing), tone: 'good' },
    { key: 'changed', label: tOr('syscheck.f.changed', 'changed'), value: changed, tone: 'critical' },
    { key: 'missing', label: tOr('syscheck.f.missing', 'missing'), value: missing, tone: 'serious' },
    { key: 'extra', label: tOr('syscheck.f.extra', 'extra'), value: extra, tone: 'warning' },
  ]
}
function diskItems(d) {
  return [
    { key: 'free', label: tOr('syscheck.f.free_mb', 'free_mb'), values: { mb: d.free_mb } },
    { key: 'min', label: tOr('syscheck.f.min_free_mb', 'min_free_mb'), values: { mb: d.min_free_mb } },
  ]
}
const bkCols = computed(() => [
  { key: 'file', label: t('backup.file'), required: true },
  { key: 'at', label: t('backup.at'), nowrap: true, text: (b) => fmtMinute(b.at) },
  { key: 'size', label: t('backup.size'), align: 'num', nowrap: true, text: (b) => fmtBytes(b.size) },
  { key: 'sha256', label: 'SHA-256', sortable: false },
  { key: 'verify', label: t('backup.verify'), sortable: false, filterable: false, required: true, value: () => '' },
])
const backupItems = computed(() => ((bk.value && bk.value.items) || []).slice()
  .sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 14)
  .map((b) => ({ key: b.file, label: fmtMinute(b.at), values: { kb: Math.round((b.size || 0) / 1024) } })))

const counts = computed(() => {
  const c = {}
  for (const it of (data.value && data.value.items) || []) c[it.status] = (c[it.status] || 0) + 1
  return c
})

function shownDetails(it) {
  const hide = HIDE[it.key] || []
  const out = {}
  for (const [k, v] of Object.entries(it.details || {})) if (!hide.includes(k)) out[k] = v
  return out
}
function isHash(v) { return typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) }
function boolClass(key, k, v) {
  // true is good for most flags; for these, true means a problem
  const bad = ['drift']
  const good = bad.includes(k) ? !v : v
  return good ? 'b-ok' : 'b-warn'
}

async function load() {
  loading.value = true; error.value = null
  try { data.value = await get('/system/check') } catch (e) { error.value = e } finally { loading.value = false }
}
async function run() {
  running.value = true; error.value = null
  try { data.value = await post('/system/check') } catch (e) { error.value = e } finally { running.value = false }
}
async function loadBackups() {
  bkError.value = null
  try { bk.value = await get('/backups') } catch (e) { bkError.value = e }
}
async function backupNow() {
  backingUp.value = true; bkError.value = null
  try { await post('/backups') } catch (e) { bkError.value = e } finally { backingUp.value = false }
  await loadBackups()
}
async function verifyBackup(b) {
  verifying[b.file] = true; delete verifyErrors[b.file]; delete results[b.file]
  try { results[b.file] = await post('/backups/' + encodeURIComponent(b.file) + '/verify') } catch (e) { verifyErrors[b.file] = e } finally { verifying[b.file] = false }
}

onMounted(() => { load(); loadBackups() })
</script>
