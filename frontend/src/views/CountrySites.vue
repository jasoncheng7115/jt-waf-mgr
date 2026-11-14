<!-- Country limits seen from the sites: for every nginx site, which countries may reach it (or are blocked), whether
     the WAF actually runs there, what the rules refused lately, and the way to change it (always a change that a
     person approves). -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('csites.title') }}</h1>
      <RouterLink v-if="isAdmin" class="btn small ghost" to="/admin/settings#uiset-countries"><Icon name="settings" />{{ t('countries.title') }}</RouterLink>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="loading" />
    <template v-if="data">
      <p class="muted small">{{ t('csites.intro') }}</p>
      <p v-if="!data.enabled" class="alert info">{{ t('countries.off') }}
        <RouterLink v-if="isAdmin" to="/admin/settings#uiset-countries">{{ t('wizard.country_to_settings') }}</RouterLink></p>
      <p v-else-if="!data.generated_at" class="alert warn">{{ t('countries.no_data') }}</p>
      <p class="muted small">{{ t('csites.summary', { sites: data.sites.length, limited: limitedCount, at: data.generated_at ? fmtMinute(data.generated_at) : '—' }) }}</p>

      <!-- disable / enable: a change with a reason, like on the managed rules page -->
      <section v-if="pendingOp" class="card">
        <form class="form" @submit.prevent="submitOp">
          <b>{{ t('op.' + pendingOp.op) }} {{ pendingOp.rule.rule_id || '' }} · {{ pendingOp.host }}</b>
          <p class="muted small">{{ t('managed.op_hint.' + pendingOp.op) }}</p>
          <label class="field"><span>{{ t('wizard.reason') }}</span><textarea ref="reasonBox" v-model="opReason" rows="2" maxlength="2000" required></textarea></label>
          <ErrorBox :error="opError" />
          <div class="actions">
            <button type="submit" class="btn primary" :disabled="busy || !opReason.trim()"><Icon name="send" />{{ t('wizard.submit') }}</button>
            <button type="button" class="btn ghost" @click="pendingOp = null"><Icon name="cancel" />{{ t('common.cancel') }}</button>
          </div>
        </form>
      </section>

      <label class="check inline-field onlylim"><input v-model="onlyLimited" type="checkbox"> {{ t('csites.only_limited') }}</label>
      <DataTable id="country-sites" :columns="cols" :rows="shown" row-key="host" :page-size="50">
        <template #cell-host="{ row }">
          <div class="mono"><b>{{ row.host }}</b></div>
          <div v-if="row.names.length > 1" class="sub mono">{{ row.names.filter((n) => n.toLowerCase() !== row.host).join(' ') }}</div>
        </template>
        <template #cell-limit="{ row }">
          <div v-for="c in row.countries" :key="'r' + c.item_id" class="limit">
            <div class="corow">
              <span class="badge" :class="!c.enabled ? 'b-logged' : c.mode === 'allow' ? 'b-ok' : 'b-blocked'">{{ t('vhosts.country_mode.' + (c.mode === 'deny' ? 'deny' : 'allow')) }}</span>
              <span v-for="cc in c.countries" :key="cc" class="cochip"><b class="mono">{{ cc }}</b> {{ countryName(cc) }}</span>
            </div>
            <div class="sub">
              <RouterLink v-if="c.rule_id" :to="'/rules/' + c.rule_id" class="mono">{{ c.rule_id }}</RouterLink>
              <span v-if="!c.enabled" class="badge b-logged gapl">{{ t('managed.disabled') }}</span>
            </div>
          </div>
          <div v-for="c in row.country_changes" :key="'c' + c.change_id + '-' + (c.item_id || '')" class="corow">
            <RouterLink :to="'/changes/' + c.change_id" class="badge b-warn">{{ t('vhosts.country_pending', { id: c.change_id }) }}</RouterLink>
            <span class="small muted">{{ t('op.' + (c.op || 'add')) }}</span>
            <span v-for="cc in c.countries" :key="cc" class="cochip small"><b class="mono">{{ cc }}</b> {{ countryName(cc) }}</span>
          </div>
          <span v-if="!row.countries.length && !row.country_changes.length" class="muted">{{ t('csites.none') }}</span>
          <p v-if="row.uncovered && row.uncovered.length" class="small warn">{{ t('csites.names_uncovered', { names: row.uncovered.join(' ') }) }}</p>
        </template>
        <template #cell-recent="{ row }">
          <template v-if="row.recent">
            <div><b>{{ fmtNum(row.recent.refused) }}</b> <span class="muted small">{{ t('csites.recent_sources', { n: fmtNum(row.recent.sources) }) }}</span></div>
            <div v-if="row.recent.countries.length" class="sub">
              <span v-for="x in row.recent.countries" :key="x.country" class="cotop" :title="countryName(x.country)">{{ x.country }} {{ fmtNum(x.requests) }}</span>
            </div>
            <div v-if="row.recent.last_at" class="sub">{{ t('csites.last', { at: fmtMinute(row.recent.last_at) }) }}</div>
          </template>
          <span v-else class="muted">—</span>
        </template>
        <template #cell-notes="{ row }">
          <p v-if="row.waf_off" class="small warn">{{ row.countries.length ? t('vhosts.country_waf_off_rule') : t('vhosts.country_waf_off') }}</p>
          <div v-if="row.bypass.length" class="small" :class="row.countries.length ? 'warn' : 'muted'">
            {{ t('vhosts.country_bypass', { n: row.bypass.length }) }}
            <div v-for="b in row.bypass" :key="b" class="mono"><TruncText :text="b" :max="80" mono /></div>
          </div>
          <div v-if="row.restrictions.length" class="small muted">
            {{ t('csites.nginx_limits') }}
            <div v-for="(r, i) in row.restrictions" :key="i" class="mono"><TruncText :text="r" :max="100" mono /></div>
          </div>
          <span v-if="!row.waf_off && !row.bypass.length && !row.restrictions.length" class="muted">—</span>
        </template>
        <template #cell-actions="{ row }">
          <div v-if="canPropose" class="rowactions">
            <template v-for="c in row.countries" :key="'a' + c.item_id">
              <RouterLink class="btn small ghost" :to="{ path: '/changes/new', query: { item: c.item_id } }"><Icon name="edit" />{{ t('managed.modify') }}</RouterLink>
              <button type="button" class="btn small ghost" @click="open(row, c, c.enabled ? 'disable' : 'enable')"><Icon :name="c.enabled ? 'hide' : 'show'" />{{ c.enabled ? t('managed.disable') : t('managed.enable') }}</button>
            </template>
            <RouterLink v-if="!row.countries.length && !row.waf_off" class="btn small ghost"
                        :to="{ path: '/changes/new', query: { kind: 'country', host: row.host } }"><Icon name="add" />{{ t('vhosts.country_add') }}</RouterLink>
            <template v-if="!row.waf_off">
              <RouterLink v-for="n in row.uncovered || []" :key="'n' + n" class="btn small ghost"
                          :to="{ path: '/changes/new', query: { kind: 'country', host: n } }"><Icon name="add" />{{ t('vhosts.country_add') }} {{ n }}</RouterLink>
            </template>
          </div>
        </template>
      </DataTable>

      <section v-if="data.unmatched_rules.length || data.unmatched_changes.length" class="card">
        <h2><Icon name="warning" /> {{ t('csites.unmatched_title') }}</h2>
        <p class="muted small">{{ t('csites.unmatched_hint') }}</p>
        <div v-for="c in data.unmatched_rules" :key="'u' + c.item_id" class="corow">
          <span class="mono">{{ c.host && c.host.value }}</span>
          <span class="badge" :class="c.mode === 'allow' ? 'b-ok' : 'b-blocked'">{{ t('vhosts.country_mode.' + (c.mode === 'deny' ? 'deny' : 'allow')) }}</span>
          <span class="mono">{{ c.countries.join(' ') }}</span>
          <RouterLink v-if="c.rule_id" :to="'/rules/' + c.rule_id" class="mono small">{{ c.rule_id }}</RouterLink>
          <RouterLink v-if="canPropose" class="btn small ghost" :to="{ path: '/changes/new', query: { item: c.item_id } }"><Icon name="edit" />{{ t('managed.modify') }}</RouterLink>
        </div>
        <div v-for="c in data.unmatched_changes" :key="'uc' + c.change_id + '-' + (c.item_id || '')" class="corow">
          <span class="mono">{{ c.host && c.host.value }}</span>
          <RouterLink :to="'/changes/' + c.change_id" class="badge b-warn">{{ t('vhosts.country_pending', { id: c.change_id }) }}</RouterLink>
          <span class="mono">{{ c.countries.join(' ') }}</span>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api.js'
import { t, lang } from '../i18n.js'
import { hasRole, refreshPending } from '../store.js'
import { fmtMinute, fmtNum } from '../util.js'
import Icon from '../components/Icon.vue'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import DataTable from '../components/DataTable.vue'
import TruncText from '../components/TruncText.vue'

const router = useRouter()
const data = ref(null)
const loading = ref(false)
const error = ref(null)
const onlyLimited = ref(false)
const pendingOp = ref(null)
const opReason = ref('')
const opError = ref(null)
const busy = ref(false)
const reasonBox = ref(null)
const isAdmin = computed(() => hasRole('admin'))
const canPropose = computed(() => hasRole('operator'))
// country names in the interface language from the browser
const regionNames = computed(() => { try { return new Intl.DisplayNames([{ 'zh-TW': 'zh-Hant-TW', ja: 'ja', en: 'en' }[lang.value] || 'en'], { type: 'region' }) } catch { return null } })
function countryName(c) { try { return (c && c !== '??' && regionNames.value && regionNames.value.of(c)) || c } catch { return c } }

const limitedCount = computed(() => (data.value ? data.value.sites.filter((s) => s.countries.length).length : 0))
const shown = computed(() => (data.value ? data.value.sites.filter((s) => !onlyLimited.value || s.countries.length || s.country_changes.length) : []))
function limitText(s) {
  return s.countries.map((c) => t('vhosts.country_mode.' + (c.mode === 'deny' ? 'deny' : 'allow')) + ' ' + c.countries.map((x) => x + ' ' + countryName(x)).join(' ')).join('; ') || t('csites.none')
}
const cols = computed(() => [
  { key: 'host', label: t('csites.col.site'), required: true, value: (s) => s.host, text: (s) => s.names.join(' ') },
  { key: 'limit', label: t('csites.col.limit'), value: (s) => (s.countries.length ? 0 : 1) + ' ' + limitText(s), text: limitText },
  { key: 'recent', label: t('csites.col.recent'), num: true, value: (s) => (s.recent ? s.recent.refused : -1) },
  { key: 'notes', label: t('csites.col.notes'), value: (s) => (s.waf_off ? 2 : 0) + s.bypass.length,
    text: (s) => s.bypass.concat(s.restrictions).join(' ') },
  { key: 'actions', label: t('csites.col.actions'), sortable: false },
])

async function load() {
  loading.value = true
  error.value = null
  try { data.value = await get('/countries/sites') } catch (e) { error.value = e } finally { loading.value = false }
}
async function open(site, rule, op) {
  pendingOp.value = { host: site.host, rule, op }
  opReason.value = ''
  opError.value = null
  await nextTick()
  if (reasonBox.value) { reasonBox.value.scrollIntoView({ block: 'center' }); reasonBox.value.focus() }
}
async function submitOp() {
  busy.value = true
  opError.value = null
  try {
    const r = await post('/changes', { op: pendingOp.value.op, kind: 'country', item_id: pendingOp.value.rule.item_id, reason: opReason.value, spec: {} })
    refreshPending(true)
    router.push('/changes/' + r.change_id)
  } catch (e) { opError.value = e } finally { busy.value = false }
}
onMounted(load)
</script>

<style scoped>
.onlylim { margin: 4px 0 10px; }
.limit { margin-bottom: 6px; }
.corow { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 6px; margin-bottom: 4px; }
.cochip { display: inline-flex; gap: 4px; align-items: center; padding: 1px 8px; border: 1px solid var(--border); border-radius: 999px; background: var(--panel-2); font-size: 13px; }
.cotop { display: inline-block; margin-right: 8px; font-family: var(--mono, monospace); }
.rowactions { display: flex; flex-wrap: wrap; gap: 6px; }
</style>
