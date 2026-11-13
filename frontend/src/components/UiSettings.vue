<!-- Settings an administrator changes here (stored in the database, audited, applied at once) instead of in the
     configuration file. Secrets are write-only: the page only learns whether one is set and its last characters.
     `groups` picks which cards to show, so a card can sit next to the feature it controls. -->
<template>
  <ErrorBox :error="error" />
  <template v-if="s">
    <section v-for="g in shownGroups" :id="'uiset-' + g.key" :key="g.key" class="card form uiset" :class="{ flash: flash === 'uiset-' + g.key }">
      <h2><Icon :name="g.icon" /> {{ t('uiset.group.' + g.key) }}</h2>
      <p class="ghint">{{ t('uiset.group.' + g.key + '.hint') }}</p>
      <p v-if="g.key === 'analyst'" class="alert info aidisclaimer" role="note"><Icon name="info" /> {{ t('analysis.disclaimer') }}</p>
      <FlowSteps v-if="g.key === 'llm'" compact :steps="llmSteps" />
      <AnalystTimeline v-if="g.key === 'analyst' && s && s['analyst.window_hours']" :window-hours="Number(form['analyst.window_hours']) || 1"
                       :interval-minutes="Number(form['analyst.interval_minutes']) || 10" :next-due="(anStatus && anStatus.next_due) || ''"
                       :enabled="!!form['analyst.enabled']" />
      <div class="srows">
        <template v-for="k in g.keys" :key="k">
          <div v-if="s[k]" class="srow" :class="{ changed: isDirty(k) }">
            <div class="slabel">
              <label :for="'uiset-in-' + k">{{ t('uiset.' + k) }}</label>
              <span class="src" :class="s[k].source === 'ui' ? 'src-ui' : 'src-file'"
                    :title="s[k].source === 'ui' ? t('uiset.source_ui', { by: s[k].updated_by || '—', at: fmtMinute(s[k].updated_at) }) : t('uiset.source_file')">
                {{ s[k].source === 'ui' ? t('uiset.src_ui_short') : t('uiset.src_file_short') }}</span>
              <div v-if="hint(k)" class="shint">{{ hint(k) }}</div>
            </div>
            <div class="sctl">
              <label v-if="s[k].type === 'bool'" class="switch"><input :id="'uiset-in-' + k" v-model="form[k]" type="checkbox">
                <span class="knob" aria-hidden="true"></span><span>{{ form[k] ? t('uiset.on') : t('uiset.off') }}</span></label>
              <div v-else-if="k === 'llm.model'" class="modelrow">
                <div class="modelpick">
                  <SelectBox :id="'uiset-in-' + k" v-model="form[k]" :options="modelOptions" class="w-md" />
                  <button type="button" class="btn small" :disabled="busy.llm || !form['llm.url']" @click="saveAndTest(g)">
                    <Icon name="test" />{{ connDirty ? t('uiset.llm.save_and_test') : t('uiset.llm.test') }}</button>
                </div>
                <div v-if="llmWaiting" class="teststate info"><Icon name="timer" />{{ t('uiset.llm.waiting') }}</div>
                <div v-else-if="llmResult && llmResult.ok" class="teststate ok"><Icon name="check" />
                  {{ t('uiset.llm.ok2', { model: llmResult.model || '—', n: (llmResult.models || []).length, seconds: llmResult.seconds, at: fmtMinute(llmResult.finished_at) }) }}</div>
                <div v-else-if="llmError" class="teststate bad"><Icon name="alert" />{{ errText(llmError) }}</div>
                <div v-else-if="!modelList.length" class="teststate muted">{{ t('uiset.llm.no_list') }}</div>
              </div>
              <SelectBox v-else-if="s[k].type === 'choice'" :id="'uiset-in-' + k" v-model="form[k]" :options="choiceOptions(k)" class="w-md" />
              <div v-else-if="s[k].type === 'list' && s[k].choices" class="chips" role="group" :aria-label="t('uiset.' + k)">
                <label v-for="c in s[k].choices" :key="c" class="chipcheck" :class="{ on: (form[k] || []).includes(c) }">
                  <input v-model="form[k]" type="checkbox" :value="c"><Icon v-if="(form[k] || []).includes(c)" name="check" /><span class="mono">{{ c }}</span></label>
              </div>
              <div v-else-if="k === 'waf.focus_sites'" class="hostpickwrap">
                <textarea :id="'uiset-in-' + k" v-model="form[k]" rows="3" class="w-lg mono" spellcheck="false" maxlength="20000"></textarea>
                <!-- site names read from nginx: a click adds or removes one; typing by hand stays possible -->
                <div v-if="hostChoices.length" class="hostpick" role="group" :aria-label="t('uiset.focus.from_nginx')">
                  <div class="hp-head"><span class="muted small">{{ t('uiset.focus.from_nginx') }}</span>
                    <input v-if="hostChoices.length > 12" v-model="hostQ" type="search" class="hp-q" :placeholder="t('uiset.focus.search')" :aria-label="t('uiset.focus.search')"></div>
                  <div class="chips">
                    <button v-for="h in shownHosts" :key="h" type="button" class="chipcheck hp-chip" :class="{ on: focusSet.has(h) }"
                            :aria-pressed="focusSet.has(h) ? 'true' : 'false'" @click="toggleHost(h)"><Icon :name="focusSet.has(h) ? 'check' : 'add'" /><span class="mono">{{ h }}</span></button>
                  </div>
                  <p v-if="hostQ && !shownHosts.length" class="muted small">{{ t('common.no_data') }}</p>
                </div>
              </div>
              <textarea v-else-if="s[k].type === 'list' || MULTILINE.includes(k)" :id="'uiset-in-' + k" v-model="form[k]" rows="3"
                        class="w-lg" :class="{ mono: s[k].type === 'list' }" spellcheck="false" maxlength="20000"></textarea>
              <input v-else-if="s[k].type === 'int'" :id="'uiset-in-' + k" v-model.number="form[k]" type="number" class="w-sm" :min="s[k].min" :max="s[k].max">
              <div v-else-if="s[k].type === 'secret'" class="secret w-lg">
                <input :id="'uiset-in-' + k" v-model="form[k]" type="password" autocomplete="new-password" spellcheck="false"
                       :placeholder="s[k].set ? t('uiset.secret_set', { hint: s[k].hint }) : t('uiset.secret_unset')">
                <span v-if="s[k].set && !cleared[k] && !form[k]" class="badge b-ok">{{ t('uiset.secret_is_set') }}</span>
                <button v-if="s[k].set" type="button" class="btn small ghost" :class="{ on: cleared[k] }" @click="toggleClear(k)"><Icon name="clear" />{{ cleared[k] ? t('uiset.secret_keep') : t('uiset.secret_clear') }}</button>
              </div>
              <input v-else :id="'uiset-in-' + k" v-model="form[k]" type="text" spellcheck="false" class="w-lg" :class="{ mono: MONO.includes(k) }" :placeholder="PLACEHOLDER[k] || ''">
            </div>
          </div>
        </template>
      </div>
      <ErrorBox :error="saveError[g.key]" />
      <p v-if="badField(g.key)" class="alert warn">{{ t('uiset.bad_field', { field: badField(g.key) }) }}</p>
      <div class="sfoot">
        <button type="button" class="btn primary" :disabled="busy[g.key] || !dirty(g).length" @click="save(g)"><Icon name="save" />{{ t('common.save') }}</button>
        <button type="button" class="btn ghost" :disabled="busy[g.key] || !dirty(g).length" @click="reset(g)"><Icon name="cancel" />{{ t('uiset.undo') }}</button>
        <button v-if="g.channel" type="button" class="btn" :disabled="busy[g.key] || tests[g.channel] === 'waiting'" @click="sendTest(g)">
          <Icon name="send" />{{ dirty(g).length ? t('uiset.notify.save_and_test') : t('uiset.notify.test') }}</button>
        <span v-if="dirty(g).length" class="pending">{{ t('uiset.unsaved', { n: dirty(g).length }) }}</span>
        <span v-else-if="msg[g.key]" class="saved"><Icon name="check" />{{ msg[g.key] }}</span>
      </div>
      <div v-if="g.channel && tests[g.channel]" class="teststate" :class="TEST_CLS[tests[g.channel]]">
        <Icon :name="tests[g.channel] === 'sent' ? 'check' : tests[g.channel] === 'waiting' ? 'timer' : 'alert'" />
        {{ testText(g.channel) }}</div>
    </section>
  </template>
</template>

<script setup>
import { computed, nextTick, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { get, patch, post } from '../api.js'
import { t, tOr, errText } from '../i18n.js'
import { fmtMinute } from '../util.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'
import SelectBox from './SelectBox.vue'
import FlowSteps from './FlowSteps.vue'
import AnalystTimeline from './AnalystTimeline.vue'
import { unfold } from '../cardFold.js'

const route = useRoute()
const props = defineProps({ groups: { type: Array, default: null } })
const emit = defineEmits(['saved'])

const GROUPS = [
  { key: 'geoip', icon: 'globe', keys: ['geoip.enabled', 'geoip.account_id', 'geoip.license_key', 'geoip.editions', 'geoip.update_days'] },
  { key: 'llm', icon: 'server', keys: ['llm.url', 'llm.api_key', 'llm.model', 'llm.timeout_seconds', 'llm.enabled'] },
  { key: 'analyst', icon: 'timer', keys: ['analyst.enabled', 'analyst.rules', 'analyst.interval_minutes', 'analyst.window_hours', 'analyst.max_proposals', 'analyst.min_events', 'analyst.min_sources'] },
  { key: 'notify', icon: 'notify', keys: ['notify.enabled', 'notify.language', 'notify.base_url', 'notify.max_per_hour', 'notify.remind_hours', 'notify.report_hour'] },
  { key: 'n_email', icon: 'mail', channel: 'email', keys: ['notify.email_enabled', 'notify.smtp_host', 'notify.smtp_port', 'notify.smtp_tls', 'notify.smtp_username', 'notify.smtp_password', 'notify.smtp_from', 'notify.email_to'] },
  { key: 'n_telegram', icon: 'chat', channel: 'telegram', keys: ['notify.telegram_enabled', 'notify.telegram_token', 'notify.telegram_chat_id'] },
  { key: 'n_teams', icon: 'chat', channel: 'teams', keys: ['notify.teams_enabled', 'notify.teams_webhook'] },
  { key: 'n_slack', icon: 'chat', channel: 'slack', keys: ['notify.slack_enabled', 'notify.slack_webhook'] },
  { key: 'n_discord', icon: 'chat', channel: 'discord', keys: ['notify.discord_enabled', 'notify.discord_webhook'] },
  { key: 'n_zulip', icon: 'chat', channel: 'zulip', keys: ['notify.zulip_enabled', 'notify.zulip_site', 'notify.zulip_bot_email', 'notify.zulip_api_key', 'notify.zulip_stream', 'notify.zulip_topic'] },
  { key: 'n_nextcloud', icon: 'chat', channel: 'nextcloud', keys: ['notify.nextcloud_enabled', 'notify.nextcloud_url', 'notify.nextcloud_token', 'notify.nextcloud_secret'] },
  { key: 'n_webhook', icon: 'link', channel: 'webhook', keys: ['notify.webhook_enabled', 'notify.webhook_url', 'notify.webhook_secret', 'notify.webhook_token'] },
  { key: 'countries', icon: 'globe', keys: ['countries.enabled'] },
  { key: 'blocks', icon: 'lock', keys: ['blocks.enabled', 'blocks.protected', 'blocks.max_active', 'blocks.max_per_token', 'blocks.token_per_hour', 'blocks.default_ttl', 'blocks.api_max_ttl', 'blocks.ui_max_ttl', 'blocks.reload_seconds', 'blocks.auto_recon', 'blocks.auto_recon_paths', 'blocks.auto_recon_minutes', 'blocks.auto_recon_ttl', 'blocks.auto_recon_per_hour'] },
  { key: 'traffic', icon: 'chart', keys: ['traffic.enabled', 'traffic.logs', 'traffic.keep_days', 'traffic.alert', 'traffic.spike_factor', 'traffic.min_requests', 'traffic.error_percent'] },
  { key: 'network', icon: 'network', keys: ['managed.imported_author', 'waf.focus_sites', 'network.known_scanners', 'evidence.catch_all_hosts', 'integrity.automation_paths'] },
  { key: 'syslog', icon: 'send', keys: ['syslog.enabled', 'syslog.address', 'syslog.protocol', 'syslog.format', 'syslog.facility'] },
  { key: 'policy', icon: 'lock', keys: ['ui.login_notice', 'compliance.level', 'auth.password_max_age_days', 'auth.password_min_age_hours', 'auth.password_history', 'auth.dormant_days', 'auth.max_sessions_per_user', 'auth.lockout_threshold', 'auth.lockout_minutes'] },
]
const MULTILINE = ['ui.login_notice']
const MONO = ['syslog.address', 'geoip.account_id', 'llm.url', 'llm.model', 'notify.base_url', 'notify.smtp_host', 'notify.telegram_chat_id',
  'notify.zulip_site', 'notify.nextcloud_url', 'notify.nextcloud_token']
const PLACEHOLDER = { 'syslog.address': '/dev/log', 'llm.url': 'http://192.0.2.10:8080/v1', 'geoip.account_id': '123456', 'notify.base_url': 'https://waf.example.com',
  'notify.smtp_host': 'mail.example.com', 'notify.smtp_from': 'waf@example.com', 'notify.telegram_chat_id': '-1001234567890',
  'notify.zulip_site': 'https://chat.example.com', 'notify.zulip_bot_email': 'waf-bot@chat.example.com', 'notify.zulip_stream': 'security',
  'notify.nextcloud_url': 'https://cloud.example.com', 'notify.teams_webhook': 'https://…', 'notify.slack_webhook': 'https://hooks.slack.com/services/…',
  'notify.discord_webhook': 'https://discord.com/api/webhooks/…', 'notify.webhook_url': 'https://hooks.example.com/waf' }

const s = ref(null)
const form = reactive({})
const cleared = reactive({})
const error = ref(null)
const saveError = reactive({})
const msg = reactive({})
const busy = reactive({})
const llmResult = ref(null)
const llmError = ref(null)

const CONN = ['llm.url', 'llm.api_key', 'llm.timeout_seconds']
const connDirty = computed(() => !!s.value && CONN.some((k) => s.value[k] && isDirty(k)))
const modelList = computed(() => (llmResult.value && llmResult.value.ok && llmResult.value.models) || [])
const modelOptions = computed(() => {
  const cur = s.value && s.value['llm.model'] ? s.value['llm.model'].value : ''
  const names = [...modelList.value]
  if (cur && !names.includes(cur)) names.unshift(cur)
  const dflt = llmResult.value && llmResult.value.ok && llmResult.value.model ? llmResult.value.model : ''
  return [{ value: '', label: dflt && !cur ? t('uiset.llm.model_default_is', { model: dflt }) : t('uiset.llm.model_default') }]
    .concat(names.map((m) => ({ value: m, label: m, hint: m === cur ? t('uiset.llm.model_saved') : '' })))
})
const llmSteps = computed(() => {
  if (!s.value || !s.value['llm.url']) return []
  const conn = !!s.value['llm.url'].value && s.value['llm.api_key'].set
  const tested = !!(llmResult.value && llmResult.value.ok)
  const model = tested && !isDirty('llm.model')
  const on = !!s.value['llm.enabled'].value
  const st = (done, cur) => (done ? 'done' : cur ? 'current' : 'todo')
  return [
    { key: 'conn', icon: 'key', label: t('uiset.llm.step_conn'), state: st(conn, true) },
    { key: 'test', icon: 'test', label: t('uiset.llm.step_test'), state: st(tested, conn) },
    { key: 'model', icon: 'list', label: t('uiset.llm.step_model'), state: st(model, tested) },
    { key: 'on', icon: 'check', label: t('uiset.llm.step_on'), state: st(on && model, model) },
  ]
})
const shownGroups = computed(() => GROUPS.filter((g) => !props.groups || props.groups.includes(g.key)))

function toForm(k) {
  const it = s.value[k]
  if (it.type === 'secret') return ''
  if (it.type === 'list') return it.choices ? [...(it.value || [])] : (it.value || []).join('\n')
  return it.value === null || it.value === undefined ? (it.type === 'int' ? 0 : '') : it.value
}
function fromForm(k) {
  const it = s.value[k]
  const v = form[k]
  if (it.type === 'list' && !it.choices) return String(v || '').split('\n').map((x) => x.trim()).filter(Boolean)
  if (it.type === 'str') return String(v ?? '')
  return v
}
function isDirty(k) {
  const g = GROUPS.find((x) => x.keys.includes(k))
  return !!g && dirty(g).includes(k)
}
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b) }
function dirty(g) {
  return g.keys.filter((k) => {
    const it = s.value[k]
    if (!it) return false
    if (it.type === 'secret') return !!form[k] || !!cleared[k]
    const cur = it.value ?? (it.type === 'list' ? [] : it.type === 'int' ? 0 : '')
    return !same(fromForm(k), cur)
  })
}
function load(r) {
  s.value = r.settings
  for (const k of Object.keys(r.settings)) { form[k] = toForm(k); cleared[k] = false }
}
function reset(g) { for (const k of g.keys) if (s.value[k]) { form[k] = toForm(k); cleared[k] = false } }
function toggleClear(k) { cleared[k] = !cleared[k]; if (cleared[k]) form[k] = '' }
function choiceOptions(k) {
  return s.value[k].choices.map((c) => ({ value: c, label: c === '' ? t('uiset.choice_default') : tOr('uiset.' + k + '.' + c, c) }))
}
function hint(k) {
  const it = s.value[k]
  const lim = it.type === 'int' ? t('uiset.range', { min: it.min, max: it.max }) : ''
  const hk = 'uiset.' + k + '.hint'
  const h = t(hk) === hk ? '' : t(hk)
  return [h, lim].filter(Boolean).join(' ')
}
function badField(gk) {
  const k = saveError[gk] && saveError[gk].details && saveError[gk].details.key
  if (!k) return ''
  const item = saveError[gk].details.item
  return tOr('uiset.' + k, k) + (item ? ': ' + item : '')
}
async function save(g) {
  const keys = dirty(g)
  const body = {}
  for (const k of keys) body[k] = s.value[k].type === 'secret' ? (cleared[k] ? '' : form[k]) : fromForm(k)
  busy[g.key] = true
  saveError[g.key] = null
  msg[g.key] = ''
  try {
    const r = await patch('/settings/ui', body)
    load(r)
    msg[g.key] = r.changed.length ? t('uiset.saved', { n: r.changed.length }) : t('uiset.nothing_changed')
    if (g.key === 'llm' && r.changed.some((k) => CONN.includes(k))) llmResult.value = null   // a new server: test again
    emit('saved', r.changed)
  } catch (e) { saveError[g.key] = e } finally { busy[g.key] = false }
}
// The web service may not reach the LLM server: it asks the analysis unit and waits for its answer.
const llmWaiting = ref(false)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function saveAndTest(g) {
  if (connDirty.value) {
    await save(g)
    if (saveError[g.key]) return
  }
  await testLlm()
}
async function testLlm() {
  busy.llm = true
  llmError.value = null
  llmResult.value = null
  llmWaiting.value = true
  try {
    const { requested_at: at } = await post('/llm/test')
    const limit = Date.now() + ((s.value['llm.timeout_seconds'].value || 180) + 60) * 1000
    while (Date.now() < limit) {
      await sleep(2000)
      const r = await get('/llm/test')
      if (r.result && r.result.requested_at === at) {
        if (r.result.ok) llmResult.value = r.result
        else llmError.value = { code: 'llm_failed', details: { error: r.result.error || '', detail: r.result.detail || '' } }
        return
      }
    }
    llmError.value = { code: 'llm_no_answer', details: { unit: 'jt-waf-mgr-analyst.path' } }
  } catch (e) { llmError.value = e } finally { busy.llm = false; llmWaiting.value = false }
}
// "Send a test": the web service only queues it; the notify unit sends it and records the result
const tests = reactive({})
const testInfo = reactive({})
const TEST_CLS = { waiting: 'info', sent: 'ok', failed: 'bad', error: 'bad' }
function testText(ch) {
  const st = tests[ch]
  const d = testInfo[ch] || {}
  if (st === 'waiting') return t('uiset.notify.waiting')
  if (st === 'sent') return t('uiset.notify.sent', { at: fmtMinute(d.sent_at) })
  if (st === 'error') return errText(d.error)
  return t('uiset.notify.failed', { error: d.error || '—' })
}
async function sendTest(g) {
  if (dirty(g).length) {
    await save(g)
    if (saveError[g.key]) return
  }
  const ch = g.channel
  tests[ch] = 'waiting'
  testInfo[ch] = {}
  try {
    const r = await post('/notify/test', { channel: ch })
    const limit = Date.now() + 120000
    while (Date.now() < limit) {
      await sleep(2000)
      const d = await get('/notify/deliveries/' + r.id)
      if (!['pending', 'sending'].includes(d.status)) {
        testInfo[ch] = d
        tests[ch] = d.status === 'sent' ? 'sent' : 'failed'
        return
      }
    }
    testInfo[ch] = { error: { code: 'notify_no_answer', details: { unit: 'jt-waf-mgr-notify.path' } } }
    tests[ch] = 'error'
  } catch (e) { testInfo[ch] = { error: e }; tests[ch] = 'error' }
}
// opened with #uiset-<group> (e.g. from the analysis page): go to that card once it is drawn
const flash = ref('')
async function goToHash() {
  const h = (route.hash || '').replace(/^#/, '')
  if (!h.startsWith('uiset-') || !shownGroups.value.some((g) => 'uiset-' + g.key === h)) return
  await nextTick()
  const el = document.getElementById(h)
  if (!el) return
  unfold(el)
  el.scrollIntoView({ block: 'start' })
  flash.value = h
  setTimeout(() => { flash.value = '' }, 2500)
  pinTop(el)
}
// Cards above this one load after it (workflow settings, samples, GeoIP): while they grow, keep the card at the
// top of the window. Stops after a few seconds or as soon as the person scrolls, clicks or types.
function pinTop(el) {
  if (typeof ResizeObserver === 'undefined') return
  const stopOn = ['wheel', 'touchstart', 'pointerdown', 'keydown']
  let done = false
  const ro = new ResizeObserver(() => { if (!done) el.scrollIntoView({ block: 'start' }) })
  const stop = () => {
    if (done) return
    done = true
    ro.disconnect()
    for (const ev of stopOn) window.removeEventListener(ev, stop, true)
  }
  ro.observe(document.body)
  for (const ev of stopOn) window.addEventListener(ev, stop, { capture: true, passive: true })
  setTimeout(stop, 4000)
}
// Focus sites: the server names nginx serves, offered as one-click choices next to the text box. Only plain names fit
// the setting (no wildcards, regexes or "_").
const anStatus = ref(null)
const hostChoices = ref([])
const hostQ = ref('')
const focusSet = computed(() => new Set(String(form['waf.focus_sites'] || '').split('\n').map((x) => x.trim().toLowerCase()).filter(Boolean)))
const shownHosts = computed(() => {
  const q = hostQ.value.trim().toLowerCase()
  return q ? hostChoices.value.filter((h) => h.includes(q)) : hostChoices.value
})
function toggleHost(h) {
  const lines = String(form['waf.focus_sites'] || '').split('\n').map((x) => x.trim()).filter(Boolean)
  const i = lines.findIndex((x) => x.toLowerCase() === h)
  if (i >= 0) lines.splice(i, 1)
  else lines.push(h)
  form['waf.focus_sites'] = lines.join('\n')
}
async function loadHosts() {
  try {
    const r = await get('/vhosts')
    const names = new Set()
    for (const v of r.items || []) {
      for (const n of v.server_names || []) {
        const h = String(n).toLowerCase()
        if (/^[a-z0-9.-]{1,253}$/.test(h) && h.includes('.') && !h.startsWith('.')) names.add(h)
      }
    }
    hostChoices.value = [...names].sort()
  } catch (e) { /* nginx not readable: typing by hand still works */ }
}

onMounted(async () => {
  try { load(await get('/settings/ui')) } catch (e) { error.value = e }
  if (s.value && s.value['waf.focus_sites']) loadHosts()
  if (shownGroups.value.some((g) => g.key === 'analyst')) {
    try { anStatus.value = await get('/analyst/status') } catch (e) { /* the timeline then starts from now */ }
  }
  goToHash()
  if (shownGroups.value.some((g) => g.key === 'llm')) {
    try {
      const r = await get('/llm/test')     // the last test: its model list fills the model choice
      if (r.result && r.result.ok) llmResult.value = r.result
    } catch (e) { /* not fatal */ }
  }
})
</script>

<style scoped>
.hostpickwrap { display: flex; flex-direction: column; gap: 8px; min-width: 0; }
.hostpick { border: 1px dashed var(--border-strong); border-radius: 6px; padding: 8px 10px; max-width: 760px; }
.hp-head { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 6px; }
.hp-q { width: 14em; max-width: 100%; }
.hostpick .chips { max-height: 220px; overflow: auto; }
.hp-chip { font: inherit; cursor: pointer; }
.uiset { scroll-margin-top: 70px; transition: box-shadow .3s; }
.uiset.flash { box-shadow: 0 0 0 3px var(--accent); }
.uiset .ghint { color: var(--muted); font-size: .92em; margin: -2px 0 10px; }
.srows { border-top: 1px solid var(--border); }
.srow { display: grid; grid-template-columns: minmax(200px, 300px) minmax(0, 1fr); gap: 6px 24px; align-items: start;
  padding: 12px 8px; border-bottom: 1px solid var(--border); }
.srow.changed { background: var(--panel-2); box-shadow: inset 3px 0 0 var(--accent); }
.slabel label { font-weight: 600; }
.src { display: inline-block; margin-left: 6px; padding: 0 6px; border-radius: 9px; font-size: .75em; line-height: 1.6;
  border: 1px solid var(--border); color: var(--muted); vertical-align: 1px; cursor: help; }
.src-ui { border-color: var(--accent); color: var(--accent); }
.shint { color: var(--muted); font-size: .86em; margin-top: 3px; line-height: 1.45; }
.sctl { min-width: 0; padding-top: 2px; }
.w-sm { width: 9em; }
.w-md { max-width: 280px; }
.w-lg { width: 100%; max-width: 560px; }
.secret { display: flex; gap: 8px; align-items: center; }
.secret input { flex: 1; min-width: 0; }
.btn.on { background: var(--panel); border-color: var(--warn); color: var(--warn); font-weight: 400; }
.switch { display: inline-flex; align-items: center; gap: 10px; cursor: pointer; margin: 0; }
.switch input { position: absolute; opacity: 0; width: 1px; height: 1px; }
.switch .knob { position: relative; width: 38px; height: 22px; border-radius: 11px; background: var(--border); transition: background .15s; flex: none; }
.switch .knob::after { content: ''; position: absolute; top: 3px; left: 3px; width: 16px; height: 16px; border-radius: 50%; background: var(--panel); transition: left .15s; }
.switch input:checked + .knob { background: var(--accent); }
.switch input:checked + .knob::after { left: 19px; }
.switch input:focus-visible + .knob { outline: 2px solid var(--accent); outline-offset: 2px; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; }
.chipcheck { display: inline-flex; align-items: center; gap: 5px; padding: 4px 10px; border: 1px solid var(--border); border-radius: 16px;
  cursor: pointer; margin: 0; background: var(--panel); }
.chipcheck input { position: absolute; opacity: 0; width: 1px; height: 1px; }
.chipcheck.on { border-color: var(--accent); background: var(--panel-2); color: var(--accent); }
.chipcheck:focus-within { outline: 2px solid var(--accent); outline-offset: 1px; }
.modelrow { display: flex; flex-direction: column; gap: 10px; }
.modelpick { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.teststate { display: flex; gap: 6px; align-items: flex-start; padding: 8px 12px; border-radius: 6px; font-size: .92em; max-width: 560px; }
.teststate.ok { background: var(--ok-bg); color: var(--ok); }
.teststate.bad { background: var(--blocked-bg); color: var(--blocked); }
.teststate.info { background: var(--int-bg); color: var(--int); }
.teststate.muted { color: var(--muted); padding-left: 0; }
.uiset :deep(.flowsteps) { margin-bottom: 12px; }
.sfoot { display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: center; margin-top: 14px; }
.sfoot .pending { color: var(--warn); font-size: .9em; }
.sfoot .saved { color: var(--ok); font-size: .9em; display: inline-flex; gap: 4px; align-items: center; }
.sfoot + .teststate { margin-top: 10px; }
@media (max-width: 760px) {
  .srow { grid-template-columns: 1fr; }
}
</style>
