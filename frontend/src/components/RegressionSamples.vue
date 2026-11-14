<template>
  <section class="card form">
    <div class="cardhead">
      <h2><Icon name="test" /> {{ t('regr.title') }} <span class="count">{{ items.length }}</span></h2>
      <button v-if="isAdmin" type="button" class="btn small" :disabled="busy" @click="collect"><Icon name="refresh" />{{ t('regr.collect') }}</button>
    </div>
    <p class="muted small">{{ t('regr.intro') }} <template v-if="collectedAt">{{ t('regr.collected_at') }} {{ fmtTime(collectedAt) }}</template></p>
    <div v-if="msg" class="alert success">{{ msg }}</div>
    <ErrorBox :error="error" />
    <div v-if="items.length" class="chartgrid">
      <div><h3 class="charthead">{{ t('chart.regr.by_source') }}</h3><SegBar :parts="sourceParts" :label="t('chart.regr.by_source')" /></div>
      <div><h3 class="charthead">{{ t('chart.regr.by_host') }}</h3><HBars :items="hostItems" :series="hostSeries" mono /></div>
    </div>
    <form v-if="canEdit" class="filters inline" @submit.prevent="add">
      <div class="field"><span><label for="regr-method">{{ t('tests.method') }}</label></span>
        <SelectBox id="regr-method" v-model="nm.method" :options="['GET', 'POST', 'HEAD']" /></div>
      <label class="field"><span>{{ t('tests.host') }}</span><input v-model.trim="nm.host" class="mono" maxlength="255" required placeholder="app.example.com"></label>
      <label class="field grow"><span>{{ t('tests.path') }}</span><input v-model="nm.path" class="mono" maxlength="2048" required placeholder="/important/page"></label>
      <label class="field grow"><span>{{ t('regr.note') }}</span><input v-model="nm.note" maxlength="200"></label>
      <div class="actions filteractions"><button type="submit" class="btn" :disabled="busy"><Icon name="add" />{{ t('regr.add') }}</button></div>
    </form>
    <DataTable id="regression-samples" :columns="cols" :rows="items" row-key="id" :default-sort="{ key: 'host', dir: 1 }">
      <template #cell-host="{ row }"><span class="mono">{{ safeText(row.host, 120) }}</span></template>
      <template #cell-request="{ row }"><span class="mono breakall"><span class="method">{{ safeText(row.method, 8) }}</span> {{ safeText(row.path, 300) }}</span></template>
      <template #cell-note="{ row }">{{ safeText(row.note, 200) }}</template>
      <template #cell-added_at="{ row }">{{ fmtTime(row.added_at) }}</template>
      <template #cell-actions="{ row }">
        <button v-if="canEdit" type="button" class="btn small ghost danger" :disabled="busy" @click="remove(row)"><Icon name="delete" />{{ t('common.delete') }}</button>
      </template>
    </DataTable>
  </section>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { get, post, del } from '../api.js'
import { t } from '../i18n.js'
import { hasRole } from '../store.js'
import { safeText, fmtTime } from '../util.js'
import ErrorBox from './ErrorBox.vue'
import Icon from './Icon.vue'
import SelectBox from './SelectBox.vue'
import DataTable from './DataTable.vue'
import SegBar from './charts/SegBar.vue'
import HBars from './charts/HBars.vue'

const items = ref([])
const collectedAt = ref(null)
const error = ref(null)
const busy = ref(false)
const msg = ref('')
const nm = reactive({ method: 'GET', host: '', path: '/', note: '' })
const canEdit = computed(() => hasRole('operator'))
const isAdmin = computed(() => hasRole('admin'))

const kindText = (r) => (r.pinned ? t('regr.pinned') : t('regr.auto'))
const cols = computed(() => [
  { key: 'host', label: t('tests.host'), required: true },
  { key: 'request', label: t('tests.request'), value: (r) => r.path, text: (r) => r.method + ' ' + r.path },
  { key: 'source', label: t('regr.source'), value: kindText },
  { key: 'note', label: t('regr.note') },
  { key: 'added_at', label: t('change.created'), nowrap: true, hidden: true, text: (r) => fmtTime(r.added_at) },
  { key: 'actions', label: t('common.actions'), sortable: false, filterable: false },
])
const sourceParts = computed(() => [
  { key: 'pinned', label: t('regr.pinned'), value: items.value.filter((r) => r.pinned).length, tone: 's1' },
  { key: 'auto', label: t('regr.auto'), value: items.value.filter((r) => !r.pinned).length, tone: 's2' },
])
const hostSeries = computed(() => [{ key: 'n', label: t('regr.title'), tone: 's1' }])
const hostItems = computed(() => {
  const m = new Map()
  for (const r of items.value) m.set(r.host, (m.get(r.host) || 0) + 1)
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([h, n]) => ({ key: h, label: h, values: { n } }))
})

function set(r) { items.value = r.items || []; collectedAt.value = r.collected_at }
async function load() {
  try { set(await get('/regression')) } catch (e) { error.value = e }
}
async function add() {
  busy.value = true
  error.value = null
  try { set(await post('/regression', Object.assign({}, nm))); nm.path = '/'; nm.note = '' } catch (e) { error.value = e } finally { busy.value = false }
}
async function remove(r) {
  busy.value = true
  try { await del('/regression/' + r.id); await load() } catch (e) { error.value = e } finally { busy.value = false }
}
async function collect() {
  busy.value = true
  msg.value = ''
  try { await post('/regression/collect', {}); msg.value = t('regr.collect_started') } catch (e) { error.value = e } finally { busy.value = false }
}
onMounted(load)
</script>
