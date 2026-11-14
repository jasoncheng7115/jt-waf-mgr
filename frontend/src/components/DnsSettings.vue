<!-- DNS check: the internal and external DNS servers (several of each), and what each one answered for every site
     name. The web service only queues "check now"; a separate sandboxed unit asks the servers. -->
<template>
  <UiSettings :groups="['dns']" @saved="(c) => { load(); emit('saved', c) }" />
  <section class="card">
    <h2><Icon name="network" /> {{ t('dns.title') }}</h2>
    <p class="muted small">{{ t('dns.intro') }}</p>
    <ErrorBox :error="error" />
    <template v-if="st">
      <p v-if="!st.enabled" class="alert info">{{ t('dns.off') }}</p>
      <p v-else-if="!st.internal_servers.length || !st.external_servers.length" class="alert warn">{{ t('dns.need_both') }}</p>
      <dl class="kv two">
        <dt>{{ t('dns.checked_at') }}</dt><dd>{{ st.checked_at ? fmtMinute(st.checked_at) : '—' }}
          <span v-if="st.requested" class="badge b-warn">{{ t('countries.queued') }}</span></dd>
        <dt>{{ t('dns.ptr') }}</dt><dd>{{ st.ptr ? t('dns.ptr_on', { n: fmtNum(st.ptr_cached) }) : t('uiset.off') }}
          <div v-if="st.ptr" class="muted small">{{ t('dns.ptr_servers', { list: (st.ptr_servers || []).join(t('common.list_sep')) || '—' }) }}</div></dd>
      </dl>
      <p v-for="(w, z) in st.wildcards" :key="z" class="alert warn small">{{ t('dns.wildcard', { zone: z }) }}</p>
      <div v-if="rows.length" class="dnstable">
        <DataTable id="dns-names" :columns="cols" :rows="rows" row-key="name" :page-size="50">
          <template #cell-name="{ row }"><span class="mono">{{ row.name }}</span></template>
          <template #cell-class="{ row }"><span class="badge" :class="CLS[row.class] || 'b-logged'">{{ t('dns.class.' + row.class) }}</span>
            <div v-if="row.public_private" class="sub warn">{{ t('dns.public_private') }}</div></template>
          <template #cell-internal="{ row }"><div v-for="(r, srv) in row.internal" :key="srv" class="small"><span class="mono muted">{{ srv }}</span> <span class="gapl">{{ answer(r) }}</span></div></template>
          <template #cell-external="{ row }"><div v-for="(r, srv) in row.external" :key="srv" class="small"><span class="mono muted">{{ srv }}</span> <span class="gapl">{{ answer(r) }}</span></div></template>
        </DataTable>
      </div>
      <div class="actions">
        <button type="button" class="btn" :disabled="busy || !isAdmin || st.requested" @click="check"><Icon name="refresh" />{{ t('dns.check_now') }}</button>
        <button type="button" class="btn ghost" :disabled="busy" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
      </div>
    </template>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { get, post } from '../api.js'
import { t } from '../i18n.js'
import { hasRole } from '../store.js'
import { fmtMinute, fmtNum } from '../util.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'
import DataTable from './DataTable.vue'
import UiSettings from './UiSettings.vue'

const emit = defineEmits(['saved'])
const st = ref(null)
const error = ref(null)
const busy = ref(false)
const isAdmin = computed(() => hasRole('admin'))
// internal DNS only: hidden but not protected by that alone (amber); public: listed; wildcard: unclear
const CLS = { internal_only: 'b-warn', public: 'b-int', wildcard: 'b-logged', not_found: 'b-logged', error: 'b-blocked' }
const rows = computed(() => Object.entries((st.value && st.value.names) || {}).map(([name, r]) => Object.assign({ name }, r)))
const cols = computed(() => [
  { key: 'name', label: t('dns.col.name'), required: true },
  { key: 'class', label: t('dns.col.class'), value: (r) => t('dns.class.' + r.class) },
  { key: 'internal', label: t('dns.col.internal'), sortable: false, text: (r) => Object.values(r.internal || {}).map(answer).join(' ') },
  { key: 'external', label: t('dns.col.external'), sortable: false, text: (r) => Object.values(r.external || {}).map(answer).join(' ') },
])
function answer(r) {
  if (!r) return '—'
  if (r.error) return t('dns.err', { e: r.error })
  const a = (r.addrs || []).concat((r.cname || []).map((c) => '→ ' + c))
  return a.length ? a.join(' ') : (r.rcode === 'NXDOMAIN' ? t('dns.nxdomain') : t('dns.empty'))
}
async function load() {
  error.value = null
  try { st.value = await get('/dns') } catch (e) { error.value = e }
}
async function check() {
  busy.value = true
  error.value = null
  try { st.value = await post('/dns/check', {}) } catch (e) { error.value = e } finally { busy.value = false }
}
onMounted(load)
</script>

<style scoped>
.dnstable { margin: 12px 0 16px; }
</style>
