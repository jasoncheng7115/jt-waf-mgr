<!-- Download the managed rules files (current, a version, or the site's original before adoption) and,
     for admins, upload a rules file: it is compared rule by rule and turned into ordinary proposals,
     each of which still goes through the checks, the sandbox and approval. Nothing is written directly. -->
<template>
  <section class="card">
    <h2><Icon name="page" /> {{ t('rulesfile.title') }}</h2>
    <div class="actions">
      <button v-for="p in ['before', 'after']" :key="p" type="button" class="btn small" :disabled="busy" @click="download(p)">
        <Icon name="download" />{{ t('rulesfile.download_' + p) }}<template v-if="version"> (v{{ version }})</template></button>
    </div>
    <p class="muted small">{{ adopted ? t('rulesfile.download_hint') : t('rulesfile.download_hint_site') }}</p>

    <template v-if="adopted && canUpload">
      <h3 class="charthead"><Icon name="upload" /> {{ t('rulesfile.upload_title') }}</h3>
      <FlowSteps compact :steps="steps" :note="t('rulesfile.upload_note')" />
      <div class="uploadrow">
        <div class="field"><label :for="id + '-pl'">{{ t('rulesfile.placement') }}</label>
          <SelectBox :id="id + '-pl'" v-model="placement" :options="[{ value: 'before', label: t('rulesfile.before') }, { value: 'after', label: t('rulesfile.after') }]" /></div>
        <div class="field"><span>{{ t('rulesfile.file') }}</span>
          <label class="btn small filepick"><Icon name="upload" />{{ fileName || t('rulesfile.choose') }}
            <input type="file" accept=".conf,.txt,text/plain" class="sr-only" @change="pick" /></label></div>
        <button type="button" class="btn small" :disabled="!text || busy" @click="preview"><Icon name="search" />{{ t('rulesfile.compare') }}</button>
      </div>
      <ErrorBox :error="error" />
      <template v-if="rows">
        <SegBar :parts="parts" :label="t('rulesfile.compare')" />
        <DataTable :id="'rules-upload'" :columns="cols" :rows="rows" :row-key="(r, i) => i" :default-sort="{ key: 'status', dir: 1 }">
          <template #cell-status="{ row }"><span class="badge" :class="BADGE[row.status]">{{ t('rulesfile.st_' + row.status) }}</span>
            <div v-if="row.error" class="sub">{{ tOr('rulesfile.err_' + row.error, row.error) }}</div></template>
          <template #cell-text="{ row }"><pre class="code small ruletext">{{ clip(row.text || row.current_text) }}</pre></template>
        </DataTable>
        <label class="checkline"><input v-model="deleteMissing" type="checkbox" :disabled="!counts.missing" />
          {{ t('rulesfile.delete_missing', { n: counts.missing || 0 }) }}</label>
        <div class="field"><label :for="id + '-reason'">{{ t('change.reason') }}</label>
          <input :id="id + '-reason'" v-model="reason" maxlength="2000" /></div>
        <div class="actions">
          <button type="button" class="btn primary small" :disabled="busy || !reason.trim() || !toPropose" @click="submit">
            <Icon name="send" />{{ t('rulesfile.propose', { n: toPropose }) }}</button>
        </div>
      </template>
      <p v-if="done" class="alert ok">{{ t('rulesfile.proposed', { n: done.changes.length, skipped: done.skipped.length }) }}
        <RouterLink class="btn small" to="/changes"><Icon name="change" />{{ t('nav.changes') }}</RouterLink></p>
    </template>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue'
import { post } from '../api.js'
import { t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { saveBlob } from '../util.js'
import Icon from './Icon.vue'
import SelectBox from './SelectBox.vue'
import DataTable from './DataTable.vue'
import ErrorBox from './ErrorBox.vue'
import FlowSteps from './FlowSteps.vue'
import SegBar from './charts/SegBar.vue'

const props = defineProps({ adopted: Boolean, version: { type: Number, default: null } })
const id = 'rf-' + Math.random().toString(36).slice(2, 7)
const canUpload = computed(() => hasRole('admin'))
const BADGE = { new: 'b-ok', changed: 'b-warn', same: '', missing: 'b-warn', invalid: 'b-blocked', conflict: 'b-blocked' }
const placement = ref('before')
const text = ref('')
const fileName = ref('')
const rows = ref(null)
const counts = ref({})
const reason = ref('')
const deleteMissing = ref(false)
const busy = ref(false)
const error = ref(null)
const done = ref(null)

const cols = computed(() => [
  { key: 'rule_id', label: t('rulesfile.rule_id'), align: 'num' },
  { key: 'status', label: t('rulesfile.status'), value: (r) => ['invalid', 'conflict', 'new', 'changed', 'missing', 'same'].indexOf(r.status),
    text: (r) => t('rulesfile.st_' + r.status) },
  { key: 'text', label: t('rulesfile.rule'), sortable: false, text: (r) => r.text || r.current_text || '' },
])
const parts = computed(() => ['new', 'changed', 'missing', 'same', 'invalid', 'conflict'].map((k) => ({
  key: k, label: t('rulesfile.st_' + k), value: counts.value[k] || 0,
  tone: { new: 'good', changed: 'warning', missing: 'serious', same: 'muted', invalid: 'critical', conflict: 'critical' }[k] })))
const toPropose = computed(() => (counts.value.new || 0) + (counts.value.changed || 0) + (deleteMissing.value ? counts.value.missing || 0 : 0))
const steps = computed(() => [
  { key: 'up', icon: 'upload', label: t('rulesfile.step_upload'), state: text.value ? 'done' : 'current' },
  { key: 'cmp', icon: 'search', label: t('rulesfile.step_compare'), state: rows.value ? 'done' : (text.value ? 'current' : 'todo') },
  { key: 'prop', icon: 'send', label: t('rulesfile.step_propose'), state: done.value ? 'done' : (rows.value ? 'current' : 'todo') },
  { key: 'flow', icon: 'approve', label: t('rulesfile.step_flow') },
])
function clip(s) { s = String(s || ''); return s.length > 600 ? s.slice(0, 599) + '…' : s }

async function download(p) {
  busy.value = true
  error.value = null
  try {
    const res = await fetch('/api/v1/managed/files/' + p + (props.version ? '?version=' + props.version : ''), { credentials: 'same-origin', cache: 'no-store' })
    if (!res.ok) throw new Error(String(res.status))
    const m = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '')
    saveBlob(m ? m[1] : p + '.conf', await res.blob())
  } catch (e) { error.value = e } finally { busy.value = false }
}
function pick(e) {
  const f = e.target.files && e.target.files[0]
  rows.value = null
  done.value = null
  if (!f) return
  if (f.size > 1024 * 1024) { error.value = { code: 'invalid_file' }; return }
  fileName.value = f.name.slice(0, 80)
  f.text().then((s) => { text.value = s })
}
async function preview() {
  busy.value = true
  error.value = null
  try {
    const r = await post('/managed/import/preview', { placement: placement.value, text: text.value })
    rows.value = r.rows
    counts.value = r.counts
  } catch (e) { error.value = e } finally { busy.value = false }
}
async function submit() {
  if (!window.confirm(t('rulesfile.confirm', { n: toPropose.value }))) return
  busy.value = true
  error.value = null
  try {
    done.value = await post('/managed/import', { placement: placement.value, text: text.value, reason: reason.value.trim(), delete_missing: deleteMissing.value })
    rows.value = null
  } catch (e) { error.value = e } finally { busy.value = false }
}
</script>

<style scoped>
.uploadrow { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin: 8px 0; }
.filepick { cursor: pointer; max-width: 22em; overflow: hidden; text-overflow: ellipsis; }
.filepick:focus-within { outline: 2px solid var(--accent); }
.ruletext { margin: 0; max-height: 8em; overflow: auto; white-space: pre-wrap; word-break: break-all; }
.checkline { display: flex; gap: 8px; align-items: center; margin: 8px 0; }
</style>
