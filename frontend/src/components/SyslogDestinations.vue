<!-- Log servers (syslog / SIEM): up to 8 destinations, each with its own address, protocol, record format (JSON,
     CEF, LEEF, GELF, key=value), syslog header and what it receives (audit records, WAF events, alerts). The first is
     the [syslog] destination the system check and compliance look at. "Send a test" sends one sample record as
     entered (saved or not) and shows exactly what went out. Saved with PATCH /settings/ui (syslog.* and syslog.more). -->
<template>
  <section id="uiset-syslog" class="card uiset">
    <h2><Icon name="send" /> {{ t('logship.title') }}</h2>
    <p class="ghint">{{ t('logship.hint') }}</p>
    <ErrorBox :error="error" />
    <div v-for="(d, i) in dests" :key="d.key" class="dest" :class="{ off: !d.enabled }">
      <div class="dhead">
        <b>{{ i === 0 ? t('logship.main') : (d.name || t('logship.n', { n: i + 1 })) }}</b>
        <span v-if="i === 0" class="muted small">{{ t('logship.main_hint') }}</span>
        <span class="stat muted small">{{ statText(d) }}</span>
        <button v-if="i > 0" type="button" class="btn small ghost" @click="remove(i)"><Icon name="delete" />{{ t('logship.remove') }}</button>
      </div>
      <div class="dgrid">
        <label class="switch"><input v-model="d.enabled" type="checkbox"><span class="knob" aria-hidden="true"></span>
          <span>{{ d.enabled ? t('uiset.on') : t('uiset.off') }}</span></label>
        <label v-if="i > 0" class="field"><span>{{ t('logship.name') }}</span><input v-model.trim="d.name" maxlength="60" :placeholder="t('logship.name_hint')"></label>
        <label class="field grow"><span>{{ t('logship.address') }}</span>
          <input v-model.trim="d.address" class="mono" maxlength="260" spellcheck="false" placeholder="logs.example.com:514"></label>
        <div class="field"><span class="flabel">{{ t('logship.payload') }}</span>
          <SelectBox v-model="d.payload" :options="payloadOpts" /></div>
        <div v-if="!isLocal(d)" class="field"><span class="flabel">{{ t('logship.protocol') }}</span>
          <SelectBox v-model="d.protocol" :options="protoOpts" /></div>
        <div v-if="d.payload !== 'gelf'" class="field"><span class="flabel">{{ t('logship.header') }}</span>
          <SelectBox v-model="d.format" :options="headerOpts" /></div>
        <div v-if="d.payload !== 'gelf'" class="field"><span class="flabel">{{ t('logship.facility') }}</span>
          <SelectBox v-model="d.facility" :options="facilityOpts" /></div>
      </div>
      <div class="chips content" role="group" :aria-label="t('logship.content')">
        <span class="flabel">{{ t('logship.content') }}</span>
        <label v-for="c in CONTENT" :key="c" class="chipcheck" :class="{ on: d.content.includes(c) }">
          <input v-model="d.content" type="checkbox" :value="c"><Icon v-if="d.content.includes(c)" name="check" />{{ t('logship.c.' + c) }}</label>
      </div>
      <p v-if="d.payload === 'gelf' && isLocal(d)" class="alert warn small">{{ t('logship.gelf_local') }}</p>
      <p v-if="!isLocal(d) && d.protocol !== 'tls'" class="muted small">{{ t('logship.plain') }}</p>
      <div class="actions">
        <button type="button" class="btn small" :disabled="testing === i" @click="test(i, 'audit')"><Icon name="test" />{{ t('logship.test_audit') }}</button>
        <button type="button" class="btn small" :disabled="testing === i" @click="test(i, 'event')"><Icon name="test" />{{ t('logship.test_event') }}</button>
      </div>
      <div v-if="results[i]" class="teststate" :class="results[i].ok ? 'ok' : 'bad'">
        <Icon :name="results[i].ok ? 'check' : 'alert'" />{{ results[i].ok ? t('logship.test_ok') : t('logship.test_failed', { error: results[i].error || '' }) }}</div>
      <pre v-if="results[i] && results[i].sample" class="sample">{{ results[i].sample }}</pre>
    </div>
    <div class="actions">
      <button type="button" class="btn small" :disabled="dests.length >= max" @click="add"><Icon name="add" />{{ t('logship.add') }}</button>
      <span class="muted small">{{ t('logship.max', { n: max }) }}</span>
    </div>
    <ErrorBox :error="saveError" />
    <div class="actions">
      <button type="button" class="btn primary" :disabled="busy || !dirty" @click="save"><Icon name="save" />{{ t('common.save') }}</button>
      <button type="button" class="btn ghost" :disabled="busy || !dirty" @click="load"><Icon name="cancel" />{{ t('uiset.undo') }}</button>
      <span v-if="msg" class="muted small" role="status">{{ msg }}</span>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { get, patch, post } from '../api.js'
import { t } from '../i18n.js'
import { fmtNum, fmtMinute } from '../util.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'
import SelectBox from './SelectBox.vue'

const CONTENT = ['audit', 'event', 'alert']
const FACILITIES = ['kern', 'user', 'daemon', 'auth', 'syslog', 'authpriv', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
const dests = ref([])
const stats = ref([])
const max = ref(8)
const error = ref(null)
const saveError = ref(null)
const busy = ref(false)
const msg = ref('')
const testing = ref(null)
const results = reactive({})
let original = ''

const payloadOpts = computed(() => ['json', 'cef', 'leef', 'gelf', 'kv'].map((v) => ({ value: v, label: t('logship.p.' + v) })))
const protoOpts = computed(() => ['udp', 'tcp', 'tls'].map((v) => ({ value: v, label: v.toUpperCase() })))
const headerOpts = computed(() => [{ value: 'rfc3164', label: t('logship.h.rfc3164') }, { value: 'rfc5424', label: t('logship.h.rfc5424') }])
const facilityOpts = computed(() => FACILITIES.map((v) => ({ value: v, label: v })))
const dirty = computed(() => JSON.stringify(dests.value) !== original)

function isLocal(d) { return String(d.address || '').startsWith('/') }
function statText(d) {
  const x = stats.value.find((s) => s.key === d.key)
  if (!x) return ''
  const parts = [t('logship.sent', { n: fmtNum(x.sent) })]
  if (x.queued) parts.push(t('logship.queued', { n: fmtNum(x.queued) }))
  if (x.dropped) parts.push(t('logship.dropped', { n: fmtNum(x.dropped) }))
  if (x.last_error) parts.push(t('logship.last_error', { at: fmtMinute(x.last_error.at), error: x.last_error.error }))
  return parts.join(' · ')
}
async function load() {
  error.value = null
  msg.value = ''
  try {
    const [ui, st] = await Promise.all([get('/settings/ui'), get('/settings/syslog')])
    const s = ui.settings
    const v = (k, d) => (s[k] && s[k].value !== undefined && s[k].value !== null ? s[k].value : d)
    const main = { key: 'main', name: '', enabled: !!v('syslog.enabled', false), address: v('syslog.address', '/dev/log'),
      protocol: v('syslog.protocol', 'udp'), format: v('syslog.format', 'rfc3164'), facility: v('syslog.facility', 'local0'),
      payload: v('syslog.payload', 'json'), content: [...v('syslog.content', ['audit'])] }
    const more = (v('syslog.more', []) || []).map((d) => ({ key: d.id, id: d.id, name: d.name || '', enabled: d.enabled !== false,
      address: d.address, protocol: d.protocol || 'udp', format: d.format || 'rfc3164', facility: d.facility || 'local0',
      payload: d.payload || 'json', content: [...(d.content || ['audit'])] }))
    dests.value = [main, ...more]
    stats.value = st.destinations || []
    max.value = st.max || 8
    original = JSON.stringify(dests.value)
  } catch (e) { error.value = e }
}
function add() {
  let n = 2
  while (dests.value.some((d) => d.id === 'd' + n)) n++
  dests.value.push({ key: 'd' + n, id: 'd' + n, name: '', enabled: true, address: '', protocol: 'udp', format: 'rfc3164',
    facility: 'local0', payload: 'json', content: ['event'] })
}
function remove(i) { dests.value.splice(i, 1) }
async function save() {
  busy.value = true
  saveError.value = null
  msg.value = ''
  const [m, ...more] = dests.value
  try {
    const r = await patch('/settings/ui', {
      'syslog.enabled': m.enabled, 'syslog.address': m.address, 'syslog.protocol': m.protocol, 'syslog.format': m.format,
      'syslog.facility': m.facility, 'syslog.payload': m.payload, 'syslog.content': m.content,
      'syslog.more': more.map((d) => ({ id: d.id, name: d.name, enabled: d.enabled, address: d.address, protocol: d.protocol,
        format: d.format, facility: d.facility, payload: d.payload, content: d.content })) })
    msg.value = r.changed.length ? t('uiset.saved', { n: r.changed.length }) : t('uiset.nothing_changed')
    await load()
    msg.value = r.changed.length ? t('uiset.saved', { n: r.changed.length }) : t('uiset.nothing_changed')
  } catch (e) { saveError.value = e } finally { busy.value = false }
}
async function test(i, kind) {
  testing.value = i
  results[i] = null
  const d = dests.value[i]
  try {
    results[i] = await post('/settings/syslog/test', { kind, destination: { address: d.address, protocol: d.protocol,
      format: d.format, facility: d.facility, payload: d.payload, content: d.content.length ? d.content : ['audit'] } })
  } catch (e) { results[i] = { ok: false, error: (e && (e.message || e.code)) || 'error' } } finally { testing.value = null }
}
onMounted(load)
</script>

<style scoped>
.dest { border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; margin: 0 0 12px; }
.dest.off { opacity: .75; }
.dhead { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.dhead .stat { margin-left: auto; }
.dgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(190px, 100%), 1fr)); gap: 8px 12px; align-items: end; }
.dgrid .grow { grid-column: span 2; }
.flabel { display: block; font-size: 13px; color: var(--muted); margin-bottom: 3px; }
.content { margin: 10px 0 4px; align-items: center; }
.content .flabel { display: inline; margin: 0 6px 0 0; }
.chipcheck { cursor: pointer; }
.sample { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12.5px; max-height: 180px; overflow: auto; margin: 6px 0 0; }
@media (max-width: 640px) { .dgrid .grow { grid-column: auto; } }
</style>
