<template>
  <section class="card form">
    <h2><Icon name="settings" /> {{ t('wfs.title') }}</h2>
    <ErrorBox :error="error" />
    <template v-if="s">
      <div class="alert" :class="sandboxAvailable ? 'success' : 'warn'">{{ sandboxAvailable ? t('wfs.sandbox_available') : t('wfs.sandbox_unavailable') }}</div>
      <div class="srows">
        <div class="srow">
          <div class="slabel"><label for="wfs-approval.single_admin_mode">{{ t('wfs.single_admin_mode') }}</label><div class="shint">{{ t('wfs.single_admin_mode_hint') }}</div></div>
          <div class="sctl"><label class="switch"><input id="wfs-approval.single_admin_mode" v-model="s['approval.single_admin_mode']" type="checkbox"><span class="knob" aria-hidden="true"></span>
            <span>{{ s['approval.single_admin_mode'] ? t('uiset.on') : t('uiset.off') }}</span></label></div>
        </div>
        <div class="srow">
          <div class="slabel"><label for="wfs-apply.auto_tighten">{{ t('wfs.auto_tighten') }}</label><div class="shint">{{ t('wfs.auto_tighten_hint') }}</div></div>
          <div class="sctl"><label class="switch"><input id="wfs-apply.auto_tighten" v-model="s['apply.auto_tighten']" type="checkbox"><span class="knob" aria-hidden="true"></span>
            <span>{{ s['apply.auto_tighten'] ? t('uiset.on') : t('uiset.off') }}</span></label></div>
        </div>
        <div class="srow">
          <div class="slabel"><label for="wfs-apply.auto_tighten_analyst">{{ t('wfs.auto_tighten_analyst') }}</label><div class="shint">{{ t('wfs.auto_tighten_analyst_hint') }}</div></div>
          <div class="sctl"><label class="switch"><input id="wfs-apply.auto_tighten_analyst" v-model="s['apply.auto_tighten_analyst']" type="checkbox"><span class="knob" aria-hidden="true"></span>
            <span>{{ s['apply.auto_tighten_analyst'] ? t('uiset.on') : t('uiset.off') }}</span></label></div>
        </div>
        <div class="srow">
          <div class="slabel"><label for="wfs-apply.auto_tighten_daily_limit">{{ t('wfs.auto_tighten_daily_limit') }}</label></div>
          <div class="sctl"><input id="wfs-apply.auto_tighten_daily_limit" v-model.number="s['apply.auto_tighten_daily_limit']" type="number" min="0" max="10000" class="w-sm"></div>
        </div>
        <div class="srow">
          <div class="slabel"><label for="wfs-apply.wait_old_workers_seconds">{{ t('wfs.wait_old_workers_seconds') }}</label></div>
          <div class="sctl"><input id="wfs-apply.wait_old_workers_seconds" v-model.number="s['apply.wait_old_workers_seconds']" type="number" min="0" max="10000" class="w-sm"></div>
        </div>
        <div class="srow">
          <div class="slabel"><label for="wfs-sandbox">{{ t('wfs.sandbox_required') }}</label>
            <div v-if="!s['sandbox.required']" class="shint warntext">{{ t('wfs.sandbox_required_off') }}</div></div>
          <div class="sctl"><label class="switch"><input id="wfs-sandbox" v-model="s['sandbox.required']" type="checkbox"><span class="knob" aria-hidden="true"></span>
            <span>{{ s['sandbox.required'] ? t('uiset.on') : t('uiset.off') }}</span></label></div>
        </div>
        <div class="srow">
          <div class="slabel"><label for="wfs-health">{{ t('wfs.health_urls') }}</label><div class="shint">{{ t('wfs.health_urls_hint') }}</div></div>
          <div class="sctl">
            <textarea id="wfs-health" v-model="urls" rows="5" class="mono w-lg" maxlength="20000" spellcheck="false" placeholder="https://app.example.com/"></textarea>
            <!-- one address per site nginx serves (https when it listens with ssl): a click adds or removes it; typing by hand
                 stays possible -->
            <div v-if="urlChoices.length" class="hostpick" role="group" :aria-label="t('wfs.health_from_nginx')">
              <div class="hp-head"><span class="muted small">{{ t('wfs.health_from_nginx') }}</span>
                <input v-if="urlChoices.length > 12" v-model="urlQ" type="search" class="hp-q" :placeholder="t('uiset.focus.search')" :aria-label="t('uiset.focus.search')"></div>
              <div class="chips">
                <button v-for="u in shownUrls" :key="u" type="button" class="chipcheck hp-chip" :class="{ on: urlSet.has(u) }"
                        :aria-pressed="urlSet.has(u) ? 'true' : 'false'" @click="toggleUrl(u)"><Icon :name="urlSet.has(u) ? 'check' : 'add'" /><span class="mono">{{ u }}</span></button>
              </div>
              <p v-if="urlQ && !shownUrls.length" class="muted small">{{ t('common.no_data') }}</p>
            </div>
          </div>
        </div>
      </div>
      <div v-if="msg" class="alert success">{{ msg }}</div>
      <ErrorBox :error="saveError" />
      <div class="actions"><button type="button" class="btn primary" :disabled="busy" @click="save"><Icon name="save" />{{ t('common.save') }}</button></div>
    </template>
  </section>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { get, patch } from '../api.js'
import { t } from '../i18n.js'
import ErrorBox from './ErrorBox.vue'
import Icon from './Icon.vue'

const s = ref(null)
const urls = ref('')
const sandboxAvailable = ref(false)
const error = ref(null)
const saveError = ref(null)
const busy = ref(false)
const msg = ref('')

function set(r) {
  s.value = Object.assign({}, r.settings)
  urls.value = (r.settings['health.urls'] || []).join('\n')
  sandboxAvailable.value = !!r.sandbox_available
}
async function load() {
  try { set(await get('/workflow/settings')) } catch (e) { error.value = e }
}
async function save() {
  busy.value = true
  saveError.value = null
  msg.value = ''
  try {
    const body = Object.assign({}, s.value, { 'health.urls': urls.value.split('\n').map((x) => x.trim()).filter(Boolean) })
    set(await patch('/workflow/settings', body))
    msg.value = t('common.saved')
  } catch (e) { saveError.value = e } finally { busy.value = false }
}
// health check addresses offered from the sites nginx serves
const urlChoices = ref([])
const urlQ = ref('')
const urlLines = () => urls.value.split('\n').map((x) => x.trim()).filter(Boolean)
const urlSet = computed(() => new Set(urlLines()))
const shownUrls = computed(() => {
  const q = urlQ.value.trim().toLowerCase()
  return q ? urlChoices.value.filter((u) => u.includes(q)) : urlChoices.value
})
function toggleUrl(u) {
  const lines = urlLines()
  const i = lines.indexOf(u)
  if (i >= 0) lines.splice(i, 1)
  else lines.push(u)
  urls.value = lines.join('\n')
}
function siteUrls(v) {
  const out = []
  const listens = (v.listen || []).map((l) => String(l))
  const ssl = listens.find((l) => /\bssl\b/.test(l))
  const pick = ssl || listens[0] || '80'
  const m = /(?:^|:)(\d{1,5})(?:\s|$)/.exec(pick.split(/\s+/)[0]) || /^(\d{1,5})/.exec(pick)
  const port = m ? m[1] : (ssl ? '443' : '80')
  const scheme = ssl ? 'https' : 'http'
  const def = (scheme === 'https' && port === '443') || (scheme === 'http' && port === '80')
  for (const n of v.server_names || []) {
    const h = String(n).toLowerCase()
    if (/^[a-z0-9.-]{1,253}$/.test(h) && h.includes('.') && !h.startsWith('.')) out.push(scheme + '://' + h + (def ? '' : ':' + port) + '/')
  }
  return out
}
async function loadUrlChoices() {
  try {
    const r = await get('/vhosts')
    const all = new Set()
    for (const v of r.items || []) for (const u of siteUrls(v)) all.add(u)
    urlChoices.value = [...all].sort()
  } catch (e) { /* nginx not readable: typing by hand still works */ }
}
onMounted(() => { load(); loadUrlChoices() })
</script>

<style scoped>
.hostpick { border: 1px dashed var(--border-strong); border-radius: 6px; padding: 8px 10px; max-width: 760px; margin-top: 8px; }
.warntext { color: var(--warn); }
.w-sm { width: 9em; }
.w-lg { width: 100%; max-width: 760px; }
.hp-head { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 6px; }
.hp-q { width: 14em; max-width: 100%; }
.hostpick .chips { display: flex; flex-wrap: wrap; gap: 8px; max-height: 220px; overflow: auto; }
.chipcheck { display: inline-flex; align-items: center; gap: 5px; padding: 4px 10px; border: 1px solid var(--border); border-radius: 16px;
  cursor: pointer; margin: 0; background: var(--panel); font: inherit; color: var(--text); }
.chipcheck.on { border-color: var(--accent); background: var(--panel-2); color: var(--accent); }
.chipcheck:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
</style>
