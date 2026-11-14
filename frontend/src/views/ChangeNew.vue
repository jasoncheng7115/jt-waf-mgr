<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ item ? t('wizard.modify_title', { id: item.rule_id || item.id }) : t('wizard.title') }}</h1>
      <button type="button" class="btn small ghost" :aria-pressed="showGuide ? 'true' : 'false'" @click="showGuide = !showGuide"><Icon name="help" />{{ t('guide.wf.toggle') }}</button>
      <RouterLink class="btn small ghost" to="/changes"><Icon name="back" />{{ t('common.back') }}</RouterLink>
    </div>
    <section v-if="showGuide" class="card guide">
      <FlowSteps :title="t('guide.wizard.title')" :steps="wizardSteps" />
      <h3 class="charthead">{{ t('guide.wizard.templates') }}</h3>
      <dl class="tpls">
        <template v-for="k in ALL_KINDS" :key="k">
          <dt><b>{{ t('kind.' + k) }}</b> <DirectionBadge v-if="KIND_DIRECTION[k]" :direction="KIND_DIRECTION[k]" /></dt>
          <dd>{{ t('guide.wizard.tpl.' + k) }}</dd>
        </template>
      </dl>
    </section>
    <ErrorBox :error="loadError" />
    <div v-if="fromEvent" class="alert info">{{ t('wizard.from_event', { id: fromEvent.id }) }}
      <RouterLink :to="'/events/' + fromEvent.id">#{{ fromEvent.id }}</RouterLink></div>

    <section v-if="!item" class="card">
      <h2><Icon name="list" /> {{ t('wizard.kind') }}</h2>
      <div class="kindpick">
        <label v-for="k in kinds" :key="k" class="kindopt" :class="{ on: kind === k }">
          <input v-model="kind" type="radio" name="kind" :value="k">
          <span><b>{{ t('kind.' + k) }}</b><span v-if="k === 'exclusion' || k === 'confident_block'" class="badge tiny b-ok">{{ t('wizard.recommended') }}</span>
            <span class="sub">{{ t('wizard.kind_hint.' + k) }}</span></span>
        </label>
      </div>
    </section>

    <form v-if="!blocked" class="page" @submit.prevent="submit">
      <!-- exclusion -->
      <section v-if="kind === 'exclusion'" class="card form">
        <h2><Icon name="unlock" /> {{ t('kind.exclusion') }}</h2>
        <p class="muted small">{{ t('wizard.exclusion_intro') }}</p>
        <ScopeInput v-model="ex.host" :label="t('wizard.host')" placeholder="app.example.com" />
        <FieldErr :err="err('host')" />
        <ScopeInput v-model="ex.path" :modes="['any', 'exact', 'prefix', 'regex']" :label="t('wizard.path')" placeholder="/api/" />
        <FieldErr :err="err('path')" />
        <div class="filters inline">
          <div class="field"><span><label for="ex-method">{{ t('wizard.method') }}</label></span>
            <SelectBox id="ex-method" v-model="ex.method" :options="methodOptions" /></div>
          <div class="field"><span><label for="ex-source">{{ t('wizard.source') }}</label></span>
            <SelectBox id="ex-source" v-model="ex.source" :options="sourceOptions" /></div>
          <div class="field grow"><span><label for="ex-action">{{ t('wizard.action') }}</label></span>
            <SelectBox id="ex-action" v-model="ex.action" :options="actionOptions" /></div>
        </div>
        <FieldErr :err="err('method') || err('source') || err('action')" />
        <p class="muted small">{{ t('wizard.action_hint.' + ex.action) }}</p>
        <div v-if="ex.action === 'remove_tag'" class="alert error">{{ t('wizard.remove_tag_warning') }}</div>
        <div v-if="ex.action === 'score_only'" class="alert info">{{ t('wizard.score_only_explain') }}</div>
        <div class="filters inline">
          <label v-if="['remove_target_by_id', 'remove_rule'].includes(ex.action)" class="field"><span>{{ t('wizard.rule_ids') }}</span>
            <input v-model="ex.rule_ids" class="mono" maxlength="300" placeholder="930120, 942100"></label>
          <label v-if="['remove_target_by_tag', 'remove_tag'].includes(ex.action)" class="field"><span>{{ t('wizard.tag') }}</span>
            <input v-model.trim="ex.tag" class="mono" maxlength="80" placeholder="OWASP_CRS"></label>
          <label v-if="['remove_target_by_id', 'remove_target_by_tag'].includes(ex.action)" class="field grow"><span>{{ t('wizard.targets') }}</span>
            <input v-model="ex.targets" class="mono" maxlength="2000" placeholder="ARGS:redirect_uri, REQUEST_HEADERS:User-Agent"></label>
          <div v-if="ex.action === 'body_processor'" class="field"><span><label for="ex-bp">{{ t('wizard.body_processor') }}</label></span>
            <SelectBox id="ex-bp" v-model="ex.body_processor" :options="['JSON', 'XML', 'URLENCODED', 'MULTIPART']" /></div>
        </div>
        <FieldErr :err="err('rule_ids') || err('targets') || err('tag') || err('body_processor')" />
        <label v-if="ex.action === 'remove_tag'" class="check"><input v-model="ex.confirm_tag" type="checkbox"> {{ t('wizard.confirm_tag') }}</label>
      </section>

      <!-- confident block -->
      <section v-if="kind === 'confident_block'" class="card form">
        <h2><Icon name="block" /> {{ t('kind.confident_block') }}</h2>
        <p class="muted small">{{ t('wizard.block_intro') }}</p>
        <div class="filters inline">
          <div class="field"><span><label for="bl-target">{{ t('wizard.target') }}</label></span>
            <SelectBox id="bl-target" v-model="bl.target" :options="targetOptions" /></div>
          <label v-if="bl.target === 'header'" class="field"><span>{{ t('wizard.header') }}</span>
            <input v-model.trim="bl.header" class="mono" maxlength="64" placeholder="X-Middleware-Subrequest"></label>
          <label class="field grow"><span>{{ t('wizard.regex') }}</span>
            <input v-model="bl.regex" class="mono" maxlength="1000" spellcheck="false" placeholder="^/(?:wp-login\.php|xmlrpc\.php)"></label>
        </div>
        <p v-if="['path', 'uri', 'ua', 'host'].includes(bl.target)" class="muted small">{{ t('wizard.lowercase_note') }}</p>
        <FieldErr :err="err('target') || err('header') || err('regex')" />
        <label class="field"><span>{{ t('wizard.exceptions') }}</span>
          <textarea v-model="bl.exceptions" rows="2" class="mono" maxlength="5000" spellcheck="false" placeholder="^/remote\.php/dav"></textarea>
          <span class="sub">{{ t('wizard.exceptions_hint') }}</span></label>
        <FieldErr :err="err('exceptions')" />
        <ScopeInput v-model="bl.host" :label="t('wizard.host_optional')" placeholder="app.example.com" />
        <FieldErr :err="err('host')" />
        <div class="filters inline">
          <label class="field grow"><span>{{ t('wizard.msg') }}</span><input v-model="bl.msg" maxlength="100" :placeholder="t('wizard.msg_ph')"></label>
          <label class="field grow"><span>{{ t('wizard.reference') }}</span><input v-model="bl.reference" maxlength="200" placeholder="CVE-2026-0000"></label>
        </div>
        <FieldErr :err="err('msg') || err('reference')" />
        <div class="field"><span><label for="bl-source">{{ t('wizard.block_source') }}</label></span>
          <SelectBox id="bl-source" v-model="bl.source" :options="blockSourceOptions" /></div>
        <FieldErr :err="err('source')" />
        <p v-if="bl.source === 'all'" class="alert warn">{{ t('wizard.block_source_all_note') }}</p>
        <p v-else class="muted small">{{ t('wizard.external_only') }}</p>
      </section>

      <!-- country block -->
      <section v-if="kind === 'country'" class="card form">
        <h2><Icon name="globe" /> {{ t('kind.country') }}</h2>
        <p class="muted small">{{ t('wizard.country_intro') }}</p>
        <p v-if="ctry && !ctry.enabled" class="alert warn">{{ t('wizard.country_off') }}
          <RouterLink v-if="hasRole('admin')" to="/admin/settings#uiset-countries">{{ t('wizard.country_to_settings') }}</RouterLink></p>
        <p v-else-if="ctry && !countryCodes.length" class="alert warn">{{ t('wizard.country_no_data') }}</p>
        <div class="filters inline">
          <label class="field grow"><span>{{ t('wizard.country_site') }}</span>
            <input v-model.trim="co.host" class="mono" maxlength="253" spellcheck="false" placeholder="app.example.com"></label>
          <div v-if="siteOptions.length" class="field"><span><label for="co-pick">{{ t('wizard.country_pick_site') }}</label></span>
            <SelectBox id="co-pick" :model-value="''" :options="siteOptions" searchable @update:model-value="(v) => { if (v) co.host = v }" /></div>
        </div>
        <FieldErr :err="err('host')" />
        <div class="field"><span>{{ t('wizard.country_mode') }}</span>
          <div class="seg" role="group" :aria-label="t('wizard.country_mode')">
            <button v-for="m in ['allow', 'deny']" :key="m" type="button" :class="{ on: co.mode === m }" :aria-pressed="co.mode === m ? 'true' : 'false'"
                    @click="co.mode = m"><Icon :name="m === 'allow' ? 'check' : 'block'" />{{ t('wizard.country_mode_opt.' + m) }}</button>
          </div></div>
        <div class="filters inline">
          <div class="field grow"><span><label for="co-add">{{ t('wizard.country_add') }}</label></span>
            <SelectBox id="co-add" :model-value="''" :options="countryOptions" searchable @update:model-value="addCountry" /></div>
        </div>
        <div v-if="co.countries.length" class="cochips">
          <span v-for="c in co.countries" :key="c" class="cochip"><b class="mono">{{ c }}</b> {{ countryName(c) }}
            <button type="button" class="linkbtn" :aria-label="t('common.remove') + ' ' + c" @click="co.countries = co.countries.filter((x) => x !== c)"><Icon name="close" /></button></span>
        </div>
        <p v-else class="muted small">{{ t('wizard.country_none') }}</p>
        <FieldErr :err="err('countries') || err('mode')" />
        <label class="field"><span>{{ t('wizard.country_note') }}</span><input v-model="co.note" maxlength="160"></label>
        <p class="muted small"><Icon name="info" /> {{ t('wizard.country_never') }}</p>
        <p class="muted small"><Icon name="info" /> {{ t('wizard.country_limits') }}</p>
      </section>

      <!-- redaction -->
      <section v-if="kind === 'redaction'" class="card form">
        <h2><Icon name="hide" /> {{ t('kind.redaction') }}</h2>
        <p class="muted small">{{ t('wizard.redaction_intro') }}</p>
        <label class="field"><span>{{ t('wizard.fields') }}</span><input v-model="rd.fields" class="mono" maxlength="1000" placeholder="password, otp"></label>
        <FieldErr :err="err('fields')" />
        <ScopeInput v-model="rd.host" :label="t('wizard.host_optional')" placeholder="app.example.com" />
        <ScopeInput v-model="rd.path" :modes="['any', 'exact', 'prefix', 'regex']" :label="t('wizard.path_optional')" placeholder="/login" />
        <FieldErr :err="err('host') || err('path')" />
      </section>

      <!-- plugin -->
      <section v-if="kind === 'plugin'" class="card form">
        <h2><Icon name="tool" /> {{ t('kind.plugin') }}</h2>
        <p class="muted small">{{ t('wizard.plugin_intro') }}</p>
        <label class="field"><span>{{ t('wizard.plugin') }}</span><input v-model.trim="pl.plugin" class="mono" maxlength="64" placeholder="wordpress-rule-exclusions"></label>
        <FieldErr :err="err('plugin')" />
        <ScopeInput v-model="pl.host" :modes="['exact', 'regex']" :label="t('wizard.host')" placeholder="blog.example.com" />
        <FieldErr :err="err('host')" />
      </section>

      <!-- raw -->
      <section v-if="kind === 'raw'" class="card form">
        <h2><Icon name="code" /> {{ t('kind.raw') }}</h2>
        <div class="alert warn">{{ t('wizard.raw_warning') }}</div>
        <div class="field"><span><label for="rw-placement">{{ t('wizard.placement') }}</label></span>
          <SelectBox id="rw-placement" v-model="rw.placement" :options="placementOptions" /></div>
        <label v-if="!item" class="field"><span>{{ t('wizard.before_rule_id') }}</span>
          <input v-model.number="rw.before_rule_id" type="number" min="1" class="mono" placeholder="10299">
          <span class="sub">{{ t('wizard.before_rule_id_hint') }}</span></label>
        <FieldErr :err="err('before_rule_id')" />
        <label class="field"><span>{{ t('wizard.raw_text') }}</span>
          <textarea v-model="rw.text" rows="8" class="mono" maxlength="20000" spellcheck="false"></textarea></label>
        <FieldErr :err="err('text') || err('placement')" />
      </section>

      <!-- preview -->
      <section class="card">
        <div class="cardhead">
          <h2><Icon name="show" /> {{ t('wizard.preview') }}</h2>
          <span v-if="previewing" class="muted small">{{ t('common.working') }}</span>
        </div>
        <template v-if="preview && preview.ok">
          <div class="actions">
            <DirectionBadge :direction="preview.direction" />
            <span class="muted small">{{ t('wizard.rule_id') }} <b class="mono">{{ shownRuleId }}</b> · {{ t('placement.' + preview.placement) }}</span>
          </div>
          <p v-if="preview.direction !== 'tighten'" class="alert warn">{{ t('wizard.loosen_note') }}</p>
          <RuleText :text="shownRuleText" />
        </template>
        <div v-else-if="preview && !preview.ok" class="alert error">{{ previewErrText }}</div>
        <div v-else class="muted">{{ t('wizard.preview_empty') }}</div>
      </section>

      <!-- tests -->
      <section class="card">
        <h2><Icon name="test" /> {{ t('wizard.tests') }}</h2>
        <p class="muted small">{{ t('wizard.tests_hint.' + (kind === 'confident_block' ? 'block' : kind === 'country' ? 'country' : 'other')) }}</p>
        <TestCases v-model="tests" :default-host="defaultHost" />
      </section>

      <!-- reason + submit -->
      <section class="card form">
        <label class="field"><span>{{ t('wizard.reason') }}</span>
          <textarea v-model="reason" rows="3" maxlength="2000" required :placeholder="t('wizard.reason_ph')"></textarea></label>
        <ErrorBox :error="submitError" />
        <div class="actions">
          <button type="submit" class="btn primary" :disabled="busy || !reason.trim() || (preview && !preview.ok)"><Icon name="send" />{{ busy ? t('common.working') : t('wizard.submit') }}</button>
          <span class="muted small">{{ t('wizard.submit_hint') }}</span>
        </div>
      </section>
    </form>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted, onUnmounted, h } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { get, post } from '../api.js'
import { t, tOr, lang } from '../i18n.js'
import { hasRole, refreshPending } from '../store.js'
import { escapeRegex, targetsOf, SCORING_RULES } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import ScopeInput from '../components/ScopeInput.vue'
import TestCases from '../components/TestCases.vue'
import DirectionBadge from '../components/DirectionBadge.vue'
import Icon from '../components/Icon.vue'
import SelectBox from '../components/SelectBox.vue'
import FlowSteps from '../components/FlowSteps.vue'
import RuleText from '../components/RuleText.vue'

// Field error line (render function: no template compiler needed at runtime).
const FieldErr = (props) => (props.err ? h('div', { class: 'fielderr' }, props.err) : null)
FieldErr.props = ['err']

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const ACTIONS = ['remove_target_by_id', 'remove_target_by_tag', 'remove_rule', 'remove_tag', 'score_only', 'body_processor']
const ALL_KINDS = ['exclusion', 'confident_block', 'country', 'redaction', 'plugin', 'raw']
// rulegen.direction() for a new rule; an expert rule depends on its text
const KIND_DIRECTION = { exclusion: 'loosen', confident_block: 'tighten', country: 'tighten', redaction: 'loosen', plugin: 'loosen' }
const route = useRoute()
const router = useRouter()

const GUIDE_KEY = 'jtwaf.guide.change_new'
function readGuide() { try { return localStorage.getItem(GUIDE_KEY) !== '0' } catch { return true } }
const showGuide = ref(readGuide())
watch(showGuide, (v) => { try { localStorage.setItem(GUIDE_KEY, v ? '1' : '0') } catch { /* private mode */ } })

const methodOptions = computed(() => [{ value: '', label: t('wizard.any_method') }].concat(METHODS.map((m) => ({ value: m, label: m }))))
const sourceOptions = computed(() => ['all', 'internal', 'external'].map((x) => ({ value: x, label: t('wizard.source_opt.' + x) })))
const actionOptions = computed(() => ACTIONS.map((a) => ({ value: a, label: t('wizard.action_opt.' + a) })))
const targetOptions = computed(() => ['path', 'uri', 'ua', 'host', 'header'].map((x) => ({ value: x, label: t('wizard.target_opt.' + x) })))
const placementOptions = computed(() => ['before', 'after'].map((x) => ({ value: x, label: t('placement.' + x) })))

const kinds = computed(() => ['exclusion', 'confident_block', 'country', 'redaction', 'plugin'].concat(hasRole('admin') ? ['raw'] : []))
const kind = ref(['exclusion', 'confident_block', 'country', 'redaction', 'plugin', 'raw'].includes(route.query.kind) ? route.query.kind : 'exclusion')
const ex = reactive({ host: { mode: 'exact', value: '' }, path: { mode: 'any', value: '' }, method: '', source: 'all',
  action: 'remove_target_by_id', rule_ids: '', targets: '', tag: 'OWASP_CRS', confirm_tag: false, body_processor: 'JSON' })
const bl = reactive({ target: 'path', header: '', regex: '', exceptions: '', host: { mode: 'any', value: '' }, msg: '', reference: '', source: 'external' })
const blockSourceOptions = computed(() => ['external', 'all'].map((x) => ({ value: x, label: t('wizard.block_source.' + x) })))
const rd = reactive({ fields: 'password', host: { mode: 'any', value: '' }, path: { mode: 'any', value: '' } })
const pl = reactive({ plugin: '', host: { mode: 'exact', value: '' } })
const rw = reactive({ text: '', placement: 'before', before_rule_id: '' })
const co = reactive({ host: '', mode: 'allow', countries: [], note: '' })
const ctry = ref(null)          // GET /countries: whether the feature is on and which countries have lists
const sites = ref([])
const countryCodes = computed(() => Object.keys((ctry.value && ctry.value.countries) || {}).sort())
// country names in the interface language from the browser (no dictionary of 250 names to keep)
const regionNames = computed(() => {
  try { return new Intl.DisplayNames([{ 'zh-TW': 'zh-Hant-TW', ja: 'ja', en: 'en' }[lang.value] || 'en'], { type: 'region' }) } catch { return null }
})
function countryName(c) { try { return (regionNames.value && regionNames.value.of(c)) || c } catch { return c } }
const countryOptions = computed(() => countryCodes.value.filter((c) => !co.countries.includes(c))
  .map((c) => ({ value: c, label: c + '  ' + countryName(c) })).sort((a, b) => a.label.slice(4).localeCompare(b.label.slice(4))))
const siteOptions = computed(() => sites.value.map((h) => ({ value: h, label: h })))
function addCountry(c) { if (c && !co.countries.includes(c) && co.countries.length < 50) co.countries = co.countries.concat([c]).sort() }
async function loadCountries() {
  try { ctry.value = await get('/countries') } catch { ctry.value = null }
  try {
    const r = await get('/vhosts')
    const all = new Set()
    for (const v of r.items || []) for (const n of v.server_names || []) {
      const h = String(n).toLowerCase()
      if (/^[a-z0-9.-]{1,253}$/.test(h) && h.includes('.') && !h.startsWith('.')) all.add(h)
    }
    sites.value = [...all].sort()
  } catch { /* nginx not readable or not allowed: typing the site still works */ }
}
watch(kind, (k) => { if (k === 'country' && !ctry.value) loadCountries() }, { immediate: true })
const tests = ref([])
const reason = ref('')
const item = ref(null)
const fromEvent = ref(null)
const loadError = ref(null)
const submitError = ref(null)
const busy = ref(false)
const preview = ref(null)
const previewing = ref(false)
const blocked = ref(false)   // e.g. an expert rule opened by a non-admin

const list = (s) => String(s || '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)
const lines = (s) => String(s || '').split('\n').map((x) => x.trim()).filter(Boolean)
const ids = (s) => list(s).filter((x) => /^\d{1,9}$/.test(x)).map(Number)

const spec = computed(() => {
  switch (kind.value) {
    case 'exclusion': return { host: ex.host, path: ex.path, method: ex.method, source: ex.source, action: ex.action,
      rule_ids: ids(ex.rule_ids), targets: list(ex.targets), tag: ex.tag, confirm_tag: ex.confirm_tag, body_processor: ex.body_processor }
    case 'confident_block': return { target: bl.target, header: bl.header, regex: bl.regex, exceptions: lines(bl.exceptions),
      host: bl.host, msg: bl.msg, reference: bl.reference, source: bl.source }
    case 'redaction': return { fields: list(rd.fields), host: rd.host, path: rd.path }
    case 'plugin': return { plugin: pl.plugin, host: pl.host }
    case 'country': return { host: { mode: 'exact', value: co.host }, mode: co.mode, countries: co.countries, note: co.note }
    default: return Object.assign({ text: rw.text, placement: rw.placement },
      !item.value && Number.isInteger(rw.before_rule_id) && rw.before_rule_id > 0 ? { before_rule_id: rw.before_rule_id } : {})
  }
})
const defaultHost = computed(() => (kind.value === 'country' ? co.host
  : ex.host.mode === 'exact' && kind.value === 'exclusion' ? ex.host.value : (bl.host.mode === 'exact' ? bl.host.value : '')))

// guide: where the form stands
const wizardSteps = computed(() => {
  const filled = !!(preview.value && preview.value.ok)
  const reasoned = !!reason.value.trim()
  return [
    { key: 'template', label: t('guide.wizard.template'), desc: t('guide.wizard.template_d'), icon: 'list', state: 'done' },
    { key: 'scope', label: t('guide.wizard.scope'), desc: t('guide.wizard.scope_d'), icon: 'edit', state: filled ? 'done' : 'current' },
    { key: 'tests', label: t('guide.wizard.tests'), desc: t('guide.wizard.tests_d'), icon: 'test', state: filled ? (reasoned ? 'done' : 'current') : 'todo' },
    { key: 'submit', label: t('guide.wizard.submit'), desc: t('guide.wizard.submit_d'), icon: 'send', state: filled && reasoned ? 'current' : 'todo' },
    { key: 'after', label: t('guide.wizard.after'), desc: t('guide.wizard.after_d'), icon: 'approve' },
  ]
})

// --- live preview -------------------------------------------------------------------------
let timer = null
watch([kind, spec], () => {
  clearTimeout(timer)
  timer = setTimeout(runPreview, 400)
}, { deep: true })
async function runPreview() {
  previewing.value = true
  try { preview.value = await post('/changes/preview', item.value ? { kind: kind.value, spec: spec.value, item_id: item.value.id } : { kind: kind.value, spec: spec.value }) } catch (e) {
    preview.value = { ok: false, field: '', reason: e.code, details: e.details }
  } finally { previewing.value = false }
}
onUnmounted(() => clearTimeout(timer))

function reasonText(p) {
  const params = Object.assign({}, p.details || {})
  return tOr('change.reason.' + p.reason, p.reason, params)
}
function err(field) {
  const p = preview.value
  if (!p || p.ok || p.field !== field) return ''
  return reasonText(p)
}
const previewErrText = computed(() => {
  const p = preview.value
  if (!p) return ''
  return (p.field ? t('wizard.field_label', { field: tOr('wizard.field.' + p.field, p.field) }) + ' ' : '') + reasonText(p)
})
// For a modification the rule keeps its id; the preview renders with the next free one.
const shownRuleId = computed(() => (item.value && item.value.rule_id) || (preview.value && preview.value.rule_id) || '—')
const shownRuleText = computed(() => {
  const p = preview.value
  if (!p || !p.ok) return ''
  if (item.value && item.value.rule_id && p.rule_id && item.value.rule_id !== p.rule_id) {
    return p.rule_text.replace('id:' + p.rule_id + ',', 'id:' + item.value.rule_id + ',')
  }
  return p.rule_text
})

// --- prefill --------------------------------------------------------------------------------
function scopeFrom(s) { return s && s.mode ? { mode: s.mode, value: s.value || '' } : { mode: 'any', value: '' } }

function fillFromSpec(k, s) {
  kind.value = k
  if (k === 'exclusion') Object.assign(ex, { host: scopeFrom(s.host), path: scopeFrom(s.path), method: s.method || '', source: s.source || 'all',
    action: s.action || 'remove_target_by_id', rule_ids: (s.rule_ids || []).join(', '), targets: (s.targets || []).join(', '),
    tag: s.tag || 'OWASP_CRS', confirm_tag: !!s.confirm_tag, body_processor: s.body_processor || 'JSON' })
  else if (k === 'confident_block') Object.assign(bl, { target: s.target || 'path', header: s.header || '', regex: s.regex || '',
    exceptions: (s.exceptions || []).join('\n'), host: scopeFrom(s.host), msg: s.msg || '', reference: s.reference || '', source: s.source || 'external' })
  else if (k === 'redaction') Object.assign(rd, { fields: (s.fields || []).join(', '), host: scopeFrom(s.host), path: scopeFrom(s.path) })
  else if (k === 'plugin') Object.assign(pl, { plugin: s.plugin || '', host: scopeFrom(s.host) })
  else if (k === 'country') Object.assign(co, { host: (s.host && s.host.value) || '', mode: s.mode || 'allow',
    countries: (s.countries || []).slice(), note: s.note || '' })
  else Object.assign(rw, { text: s.text || '', placement: s.placement || 'before', before_rule_id: s.before_rule_id || '' })
}

async function prefillEvent(id, mode) {
  const ev = await get('/events/' + encodeURIComponent(id))
  fromEvent.value = ev
  const path = ev.path || '/'
  const full = ev.query ? path + '?' + ev.query : path
  if (mode === 'block') {
    kind.value = 'confident_block'
    Object.assign(bl, { target: 'path', regex: '^' + escapeRegex(path.toLowerCase()) + '$', host: { mode: 'any', value: '' } })
    tests.value = [{ expect: 403, source: 'external', method: ev.method || 'GET', host: ev.host, path: full }]
    reason.value = t('wizard.reason_from_event_block', { id: ev.id })
  } else {
    kind.value = 'exclusion'
    const local = new Set(ev.local_rule_ids || [])
    const rids = (ev.rule_ids || []).filter((r) => !SCORING_RULES.includes(r) && !local.has(r))
    const targets = targetsOf(ev.matches)
    Object.assign(ex, { host: { mode: 'exact', value: ev.host }, path: { mode: 'exact', value: path }, method: '',
      source: ev.origin === 'internal' ? 'internal' : 'all', action: targets.length ? 'remove_target_by_id' : 'remove_rule',
      rule_ids: rids.join(', '), targets: targets.join(', ') })
    tests.value = [{ expect: 200, source: ev.origin === 'internal' ? 'internal' : 'external', method: ev.method || 'GET',
      host: ev.host, path: full, absent_rules: rids }]
    reason.value = t('wizard.reason_from_event_exclusion', { id: ev.id })
  }
}

async function prefillItem(id) {
  const m = await get('/managed')
  const it = (m.items || []).find((x) => String(x.id) === String(id))
  if (!it) { loadError.value = { code: 'item_not_found' }; return }
  item.value = it
  fillFromSpec(it.kind, it.spec || {})
}

onMounted(async () => {
  try {
    if (route.query.item) await prefillItem(route.query.item)
    else if (route.query.from_event) await prefillEvent(route.query.from_event, route.query.mode)
    else if (kind.value === 'country' && typeof route.query.host === 'string') co.host = route.query.host.trim().toLowerCase().slice(0, 253)
  } catch (e) { loadError.value = e }
  if (kind.value === 'raw' && !hasRole('admin')) {
    if (item.value) { blocked.value = true; loadError.value = { code: 'raw_admin_only' } } else kind.value = 'exclusion'
  }
  if (!blocked.value) runPreview()
})

// --- submit ---------------------------------------------------------------------------------
async function submit() {
  busy.value = true
  submitError.value = null
  try {
    const body = { op: item.value ? 'modify' : 'add', kind: kind.value, spec: spec.value, reason: reason.value, tests: tests.value }
    if (item.value) body.item_id = item.value.id
    const r = await post('/changes', body)
    refreshPending(true)
    router.push('/changes/' + r.change_id)
  } catch (e) {
    if (e.code === 'invalid_spec' && e.details) {
      preview.value = { ok: false, field: e.details.field, reason: e.details.reason, details: e.details }
    } else {
      submitError.value = e
    }
  } finally { busy.value = false }
}
</script>

<style scoped>
.cochips { display: flex; flex-wrap: wrap; gap: 6px; }
.cochip { display: inline-flex; align-items: center; gap: 6px; padding: 3px 4px 3px 10px; border: 1px solid var(--border); border-radius: 14px;
  background: var(--panel-2); font-size: 13.5px; }
.guide { display: flex; flex-direction: column; gap: 10px; }
.tpls { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 0; align-items: baseline; }
.tpls dt { white-space: nowrap; }
.tpls dd { margin: 0; color: var(--muted); }
@media (max-width: 640px) {
  .tpls { grid-template-columns: 1fr; }
  .tpls dd { margin-bottom: 6px; }
}
</style>
