<template>
  <section class="card form">
    <h2><Icon name="settings" /> {{ t('wfs.title') }}</h2>
    <ErrorBox :error="error" />
    <template v-if="s">
      <div class="alert" :class="sandboxAvailable ? 'success' : 'warn'">{{ sandboxAvailable ? t('wfs.sandbox_available') : t('wfs.sandbox_unavailable') }}</div>
      <label class="check"><input v-model="s['approval.single_admin_mode']" type="checkbox"> <b>{{ t('wfs.single_admin_mode') }}</b></label>
      <p class="muted small">{{ t('wfs.single_admin_mode_hint') }}</p>
      <label class="check"><input v-model="s['apply.auto_tighten']" type="checkbox"> <b>{{ t('wfs.auto_tighten') }}</b></label>
      <p class="muted small">{{ t('wfs.auto_tighten_hint') }}</p>
      <label class="check"><input v-model="s['apply.auto_tighten_analyst']" type="checkbox"> <b>{{ t('wfs.auto_tighten_analyst') }}</b></label>
      <p class="muted small">{{ t('wfs.auto_tighten_analyst_hint') }}</p>
      <div class="filters inline">
        <label class="field"><span>{{ t('wfs.auto_tighten_daily_limit') }}</span>
          <input v-model.number="s['apply.auto_tighten_daily_limit']" type="number" min="0" max="10000"></label>
        <label class="field"><span>{{ t('wfs.wait_old_workers_seconds') }}</span>
          <input v-model.number="s['apply.wait_old_workers_seconds']" type="number" min="0" max="10000"></label>
      </div>
      <label class="check"><input v-model="s['sandbox.required']" type="checkbox"> <b>{{ t('wfs.sandbox_required') }}</b></label>
      <p v-if="!s['sandbox.required']" class="alert warn">{{ t('wfs.sandbox_required_off') }}</p>
      <label class="field"><span>{{ t('wfs.health_urls') }}</span>
        <textarea v-model="urls" rows="5" class="mono" maxlength="20000" spellcheck="false" placeholder="https://app.example.com/"></textarea>
        <span class="sub">{{ t('wfs.health_urls_hint') }}</span></label>
      <div v-if="msg" class="alert success">{{ msg }}</div>
      <ErrorBox :error="saveError" />
      <div class="actions"><button type="button" class="btn primary" :disabled="busy" @click="save"><Icon name="save" />{{ t('common.save') }}</button></div>
    </template>
  </section>
</template>

<script setup>
import { ref, onMounted } from 'vue'
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
onMounted(load)
</script>
