<!-- Which events go to which channel. An event not set here uses its default (every channel, or none). Only
     channels that are switched on and set up send anything; the others are shown dimmed. -->
<template>
  <section id="notify-events" class="card">
    <h2><Icon name="list" /> {{ t('notify.matrix.title') }}</h2>
    <p class="muted small">{{ t('notify.matrix.hint') }}</p>
    <ErrorBox :error="error" />
    <DataTable v-if="status" id="notify-matrix" :columns="cols" :rows="rows" row-key="event" :toolbar="false"
               :page-size="50" :default-sort="{ key: 'category', dir: 1 }">
      <template #cell-event="{ row }"><span class="evname"><b>{{ tOr('notify.ev.' + row.event, row.event) }}</b>
        <button type="button" class="btn tiny ghost" :title="t('notify.preview.open')" @click="openPreview(row.event, $event)"><Icon name="show" />{{ t('notify.preview.btn') }}</button></span></template>
      <template #cell-category="{ row }"><span class="chip">{{ tOr('notify.cat.' + row.category, row.category) }}</span></template>
      <template #cell-severity="{ row }"><span class="badge" :class="SEV[row.severity]">{{ tOr('notify.sev.' + row.severity, row.severity) }}</span></template>
      <template v-for="c in channels" :key="c" #[`cell-ch_${c}`]="{ row }">
        <label class="mcheck" :class="{ off: !activeOf(c) }" :title="tOr('notify.ch.' + c, c)">
          <input type="checkbox" :checked="form[row.event].includes(c)" :aria-label="tOr('notify.ev.' + row.event, row.event) + ' / ' + tOr('notify.ch.' + c, c)"
                 @change="toggle(row.event, c, $event.target.checked)"></label>
      </template>
    </DataTable>
    <!-- what one event's message looks like (example data, in the chosen language); Escape or outside click closes -->
    <div v-if="pv.event" class="modalback" @click.self="closePreview">
      <section ref="pvEl" class="card modal" role="dialog" aria-modal="true" :aria-label="t('notify.preview.title')" tabindex="-1"
               @keydown.esc.stop="closePreview">
        <div class="cardhead">
          <h2><Icon name="show" /> {{ t('notify.preview.title') }}</h2>
          <button class="btn small ghost" type="button" @click="closePreview"><Icon name="close" />{{ t('common.dismiss') }}</button>
        </div>
        <div class="pvbar">
          <span class="mono small">{{ pv.event }}</span>
          <div class="seg" role="group" :aria-label="t('uiset.notify.language')">
            <button v-for="l in PV_LANGS" :key="l.code" type="button" :class="{ on: pv.lang === l.code }" :aria-pressed="pv.lang === l.code ? 'true' : 'false'"
                    @click="loadPreview(pv.event, l.code)"><Icon name="globe" />{{ l.label }}</button>
          </div>
        </div>
        <ErrorBox :error="pv.error" />
        <div v-if="pv.data" class="pvmsg" :class="'pv-' + pv.data.severity">
          <div class="pvtitle"><span class="badge" :class="SEV[pv.data.severity]">{{ tOr('notify.sev.' + pv.data.severity, pv.data.severity) }}</span>
            <b>{{ pv.data.title }}</b></div>
          <p v-if="pv.data.text" class="pvtext">{{ pv.data.text }}</p>
          <dl v-if="pv.data.facts.length" class="kv two">
            <template v-for="(f, i) in pv.data.facts" :key="i"><dt>{{ f.label }}</dt><dd class="mono">{{ f.value }}</dd></template>
          </dl>
          <p class="muted small">{{ pv.data.link ? t('notify.preview.link', { url: pv.data.link }) : t('notify.preview.no_link') }}</p>
        </div>
        <p class="muted small"><Icon name="info" /> {{ t('notify.preview.hint') }}</p>
      </section>
    </div>
    <div class="sfoot">
      <button type="button" class="btn primary" :disabled="busy || !dirty" @click="save"><Icon name="save" />{{ t('common.save') }}</button>
      <button type="button" class="btn ghost" :disabled="busy || !dirty" @click="reset"><Icon name="cancel" />{{ t('uiset.undo') }}</button>
      <button type="button" class="btn ghost" :disabled="busy" @click="defaults"><Icon name="refresh" />{{ t('notify.matrix.defaults') }}</button>
      <span v-if="dirty" class="pending">{{ t('notify.matrix.unsaved') }}</span>
      <span v-else-if="msg" class="saved"><Icon name="check" />{{ msg }}</span>
    </div>
  </section>
</template>

<script setup>
import { computed, nextTick, reactive, ref, watch } from 'vue'
import { get, patch } from '../api.js'
import { LANGUAGES, t, tOr } from '../i18n.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'
import DataTable from './DataTable.vue'

const props = defineProps({ status: { type: Object, default: null } })
const emit = defineEmits(['saved'])
const SEV = { critical: 'b-blocked', warning: 'b-warn', info: 'b-int', success: 'b-ok' }
const CAT_ORDER = ['alerts', 'security', 'changes', 'analysis', 'system', 'accounts']
const form = reactive({})
const error = ref(null)
const busy = ref(false)
const msg = ref('')

const channels = computed(() => (props.status ? props.status.channel_list : []))
const rows = computed(() => (props.status ? props.status.events : []))
function activeOf(c) { const x = props.status && props.status.channels.find((y) => y.channel === c); return !!(x && x.active) }
const cols = computed(() => [
  { key: 'event', label: t('notify.matrix.event'), required: true, value: (r) => tOr('notify.ev.' + r.event, r.event) },
  { key: 'category', label: t('notify.matrix.category'), value: (r) => CAT_ORDER.indexOf(r.category) + ' ' + r.event, text: (r) => tOr('notify.cat.' + r.category, r.category) },
  { key: 'severity', label: t('notify.matrix.severity'), hidden: true },
  ...channels.value.map((c) => ({ key: 'ch_' + c, label: tOr('notify.ch.' + c, c), sortable: false, filterable: false, align: 'center',
    value: (r) => (form[r.event] || []).includes(c) })),
])
// preview of one event's message
const PV_LANGS = LANGUAGES
const pv = reactive({ event: '', lang: '', data: null, error: null })
const pvEl = ref(null)
let pvOpener = null
async function loadPreview(ev, lang) {
  pv.event = ev
  pv.error = null
  try {
    pv.data = await get('/notify/preview', lang ? { event: ev, lang } : { event: ev })
    pv.lang = pv.data.language
  } catch (e) { pv.error = e; pv.data = null }
}
async function openPreview(ev, e) {
  pvOpener = e && e.currentTarget
  await loadPreview(ev, '')
  await nextTick()
  if (pvEl.value) pvEl.value.focus()
}
function closePreview() {
  pv.event = ''
  pv.data = null
  if (pvOpener && pvOpener.focus) pvOpener.focus()
}
function load() {
  if (!props.status) return
  for (const e of props.status.events) form[e.event] = [...(props.status.matrix[e.event] || [])]
}
watch(() => props.status, load, { immediate: true })
const dirty = computed(() => !!props.status && props.status.events.some((e) =>
  JSON.stringify([...(form[e.event] || [])].sort()) !== JSON.stringify([...(props.status.matrix[e.event] || [])].sort())))
function toggle(ev, c, on) {
  const cur = form[ev].filter((x) => x !== c)
  form[ev] = on ? channels.value.filter((x) => cur.includes(x) || x === c) : cur
  msg.value = ''
}
function reset() { load() }
function defaults() {
  for (const e of props.status.events) form[e.event] = e.default ? [...channels.value] : []
}
async function save() {
  busy.value = true
  error.value = null
  try {
    const m = {}
    for (const e of props.status.events) m[e.event] = form[e.event]
    await patch('/settings/ui', { 'notify.matrix': m })
    msg.value = t('notify.matrix.saved')
    emit('saved')
  } catch (e) { error.value = e } finally { busy.value = false }
}
</script>

<style scoped>
.mcheck { display: inline-flex; justify-content: center; width: 100%; margin: 0; cursor: pointer; padding: 2px 0; }
.mcheck input { width: 18px; height: 18px; }
.mcheck.off { opacity: .3; filter: grayscale(1); }
.sub { color: var(--muted); font-size: .8em; }
.evname { display: inline-flex; flex-wrap: wrap; gap: 4px 8px; align-items: center; }
.pvbar { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; justify-content: space-between; margin: 4px 0 12px; }
.pvmsg { border: 1px solid var(--border); border-left: 4px solid var(--border-strong); border-radius: 8px; padding: 12px 14px;
  background: var(--panel-2); margin-bottom: 10px; }
.pvmsg.pv-critical { border-left-color: var(--st-critical); }
.pvmsg.pv-warning { border-left-color: var(--st-warning); }
.pvmsg.pv-success { border-left-color: var(--st-good); }
.pvmsg.pv-info { border-left-color: var(--accent); }
.pvtitle { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 8px; }
.pvtext { margin: 0 0 8px; white-space: pre-wrap; overflow-wrap: anywhere; }
.pvmsg dd { overflow-wrap: anywhere; }
.sfoot { display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: center; margin-top: 14px; }
.sfoot .pending { color: var(--warn); font-size: .9em; }
.sfoot .saved { color: var(--ok); font-size: .9em; display: inline-flex; gap: 4px; align-items: center; }
</style>
