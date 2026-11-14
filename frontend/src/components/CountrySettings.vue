<!-- Country blocks: the switch, where the lists come from, when they were last made, the list files in use, and
     "update now". The web service only queues the request; a separate sandboxed unit downloads and checks. -->
<template>
  <UiSettings :groups="['countries']" @saved="(c) => { load(); emit('saved', c) }" />
  <section class="card">
    <h2><Icon name="globe" /> {{ t('countries.title') }}</h2>
    <FlowSteps compact :steps="steps" :note="t('countries.how_note')" />
    <ErrorBox :error="error" />
    <template v-if="st">
      <p v-if="!st.enabled" class="alert info">{{ t('countries.off') }}</p>
      <p v-else-if="!st.generated_at" class="alert warn">{{ t('countries.no_data') }}</p>
      <p v-if="st.stale" class="alert warn">{{ t('countries.stale') }}</p>
      <dl class="kv two">
        <dt>{{ t('countries.generated_at') }}</dt><dd>{{ st.generated_at ? fmtMinute(st.generated_at) : '—' }}</dd>
        <dt>{{ t('countries.count') }}</dt><dd>{{ codes.length || '—' }}</dd>
        <dt>{{ t('countries.last_run') }}</dt>
        <dd>{{ st.last_run ? fmtMinute(st.last_run) : '—' }}
          <span v-if="st.last_ok === false" class="badge b-blocked">{{ t('countries.last_failed') }}</span>
          <span v-if="st.requested" class="badge b-warn">{{ t('countries.queued') }}</span></dd>
        <dt>{{ t('countries.sets') }}</dt>
        <dd><span v-if="!st.sets.length">—</span>
          <div v-for="s in st.sets" :key="s" class="setrow">
            <span class="badge mono setbadge">{{ s }}</span>
            <span>{{ s.split('-').map(countryName).join(t('common.list_sep')) }}</span>
            <span v-if="(st.set_users || {})[s]" class="muted small gapl">{{ t('countries.set_used_by', { sites: st.set_users[s].join(t('common.list_sep')) }) }}</span>
          </div>
          <div class="muted small">{{ t('countries.sets_hint') }}</div></dd>
        <dt>{{ t('countries.applied') }}</dt>
        <dd>{{ st.applied.at ? fmtMinute(st.applied.at) : '—' }}
          <span v-if="st.applied.ok === false" class="badge b-blocked">{{ t('countries.apply_failed') }}</span>
          <span v-if="st.pending" class="badge b-warn">{{ t('countries.writing') }}</span></dd>
      </dl>
      <p v-for="(e, k) in st.last_errors" :key="k" class="small warn">{{ k }}: {{ safeText(e, 200) }}</p>
      <div v-if="regRows.length" class="coreg">
        <DataTable id="country-registries" :columns="cols" :rows="regRows" row-key="name" :toolbar="false">
          <template #cell-size="{ row }">{{ row.size ? fmtBytes(row.size) : '—' }}</template>
        </DataTable>
      </div>
      <div class="actions">
        <button type="button" class="btn" :disabled="busy || !isAdmin || st.requested" @click="update"><Icon name="download" />{{ t('countries.update_now') }}</button>
        <button type="button" class="btn ghost" :disabled="busy" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
        <RouterLink class="btn ghost" to="/changes/new?kind=country"><Icon name="add" />{{ t('countries.new_rule') }}</RouterLink>
      </div>
    </template>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { get, post } from '../api.js'
import { t, lang } from '../i18n.js'
import { hasRole } from '../store.js'
import { fmtBytes, fmtMinute, safeText } from '../util.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'
import DataTable from './DataTable.vue'
import FlowSteps from './FlowSteps.vue'
import UiSettings from './UiSettings.vue'

const emit = defineEmits(['saved'])
// country names in the interface language from the browser
const regionNames = computed(() => { try { return new Intl.DisplayNames([{ 'zh-TW': 'zh-Hant-TW', ja: 'ja', en: 'en' }[lang.value] || 'en'], { type: 'region' }) } catch { return null } })
function countryName(c) { try { return (regionNames.value && regionNames.value.of(c)) || c } catch { return c } }
const st = ref(null)
const error = ref(null)
const busy = ref(false)
const isAdmin = computed(() => hasRole('admin'))
const codes = computed(() => Object.keys((st.value && st.value.countries) || {}))
const cols = computed(() => [
  { key: 'name', label: t('countries.col.registry') },
  { key: 'ipv4', label: 'IPv4', num: true },
  { key: 'ipv6', label: 'IPv6', num: true },
  { key: 'countries', label: t('countries.col.countries'), num: true },
  { key: 'size', label: t('countries.col.size'), num: true },
])
const regRows = computed(() => Object.entries((st.value && st.value.registries) || {}).map(([name, r]) => Object.assign({ name: name.toUpperCase() }, r)))
const steps = computed(() => [
  { key: 'dl', label: t('countries.step.download'), desc: t('countries.step.download_d'), icon: 'download' },
  { key: 'check', label: t('countries.step.check'), desc: t('countries.step.check_d'), icon: 'verify' },
  { key: 'rule', label: t('countries.step.rule'), desc: t('countries.step.rule_d'), icon: 'change' },
  { key: 'write', label: t('countries.step.write'), desc: t('countries.step.write_d'), icon: 'server' },
])

async function load() {
  error.value = null
  try { st.value = await get('/countries') } catch (e) { error.value = e }
}
async function update() {
  busy.value = true
  error.value = null
  try { st.value = await post('/countries/update', {}) } catch (e) { error.value = e } finally { busy.value = false }
}
onMounted(load)
</script>

<style scoped>
.setbadge { margin: 0 6px 0 0; }
.setrow { display: flex; flex-wrap: wrap; align-items: center; gap: 2px 4px; margin-bottom: 4px; }
.coreg { margin: 12px 0 16px; }   /* the registries table: room above the buttons */
</style>
