<!-- Switch the selected rules, or a whole category, on or off as ONE change. Shows what it takes first (a preview
     from the server: operations, and the rules that cannot be switched here with the reason). CRS rules switched off
     need a scope: chosen sites (exclusions) or every request (an expert rule, admins only). A whole category of CRS
     rules switched off is approved by an admin with a one-time code. Emits close and done(change_id). -->
<template>
  <section class="card form ruletoggle" role="dialog" :aria-label="title">
    <h2><Icon :name="action === 'disable' ? 'hide' : 'show'" /> {{ title }}</h2>
    <p class="muted small">{{ t(action === 'disable' ? 'toggle.disable_hint' : 'toggle.enable_hint') }}</p>
    <div v-if="needsScope" class="field">
      <span class="flabel">{{ t('toggle.scope') }}</span>
      <div class="seg" role="radiogroup" :aria-label="t('toggle.scope')">
        <button type="button" role="radio" :aria-checked="scope === 'hosts' ? 'true' : 'false'" :class="{ on: scope === 'hosts' }" @click="setScope('hosts')"><Icon name="server" />{{ t('toggle.scope_hosts') }}</button>
        <button type="button" role="radio" :aria-checked="scope === 'all' ? 'true' : 'false'" :class="{ on: scope === 'all' }" :disabled="!isAdmin" @click="setScope('all')"><Icon name="warning" />{{ t('toggle.scope_all') }}</button>
      </div>
      <p v-if="!isAdmin" class="muted small">{{ t('toggle.scope_all_admin') }}</p>
      <div v-if="scope === 'hosts'" class="chips hostchips" role="group" :aria-label="t('toggle.scope_hosts')">
        <button v-for="h in hostChoices" :key="h" type="button" class="chipcheck" :class="{ on: hosts.includes(h) }" :aria-pressed="hosts.includes(h) ? 'true' : 'false'"
                @click="toggleHost(h)"><Icon :name="hosts.includes(h) ? 'check' : 'add'" /><span class="mono">{{ h }}</span></button>
        <span v-if="!hostChoices.length" class="muted small">{{ t('toggle.no_hosts') }}</span>
      </div>
      <p v-else class="alert error">{{ t('toggle.scope_all_warn') }}</p>
    </div>
    <p v-if="strict" class="alert warn">{{ t('toggle.strict_note') }}</p>
    <div v-if="plan" class="planbox">
      <b>{{ t('toggle.plan', { rules: fmtNum(plan.rule_ids.length), ops: fmtNum(plan.operations) }) }}</b>
      <details v-if="plan.skipped.length"><summary>{{ t('toggle.skipped', { n: fmtNum(plan.skipped.length) }) }}</summary>
        <ul class="plainlist small"><li v-for="x in plan.skipped.slice(0, 100)" :key="x.id"><span class="mono">{{ x.id }}</span> {{ tOr('toggle.why.' + x.reason, x.reason) }}</li></ul>
      </details>
    </div>
    <ErrorBox :error="error" />
    <label class="field"><span>{{ t('toggle.reason') }}</span>
      <textarea v-model="reason" rows="2" maxlength="1000" class="w-lg" :placeholder="t('toggle.reason_hint')"></textarea></label>
    <div class="actions">
      <button type="button" class="btn" :class="action === 'disable' ? 'danger' : 'primary'" :disabled="busy || !canSubmit" @click="submit">
        <Icon name="send" />{{ t('toggle.submit') }}</button>
      <button type="button" class="btn ghost" @click="emit('close')"><Icon name="close" />{{ t('common.cancel') }}</button>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { get, post } from '../api.js'
import { t, tOr } from '../i18n.js'
import { fmtNum } from '../util.js'
import { hasRole } from '../store.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'

const props = defineProps({
  action: { type: String, required: true },            // disable | enable
  ruleIds: { type: Array, default: null },              // the selected rules ...
  group: { type: Object, default: null },               // ... or {source, key, label}
  source: { type: String, default: 'local' },
})
const emit = defineEmits(['close', 'done'])
const isAdmin = computed(() => hasRole('admin'))
const scope = ref('hosts')
const hosts = ref([])
const hostChoices = ref([])
const reason = ref('')
const plan = ref(null)
const error = ref(null)
const busy = ref(false)
const needsScope = computed(() => props.action === 'disable' && props.source === 'crs')
const strict = computed(() => !!props.group && props.source === 'crs' && props.action === 'disable')
const title = computed(() => (props.group
  ? t(props.action === 'disable' ? 'toggle.title_group_off' : 'toggle.title_group_on', { name: props.group.label })
  : t(props.action === 'disable' ? 'toggle.title_off' : 'toggle.title_on', { n: fmtNum(props.ruleIds.length) })))
const canSubmit = computed(() => reason.value.trim().length >= 5 && plan.value && plan.value.operations > 0 &&
  (!needsScope.value || scope.value === 'all' || hosts.value.length > 0))

function body(extra) {
  const b = { action: props.action, ...extra }
  if (props.group) b.group = { source: props.group.source, key: props.group.key }
  else b.rule_ids = props.ruleIds
  if (needsScope.value) b.scope = scope.value === 'all' ? { mode: 'all' } : { mode: 'hosts', hosts: hosts.value }
  return b
}
async function preview() {
  error.value = null
  if (needsScope.value && scope.value === 'hosts' && !hosts.value.length) { plan.value = null; return }
  try { plan.value = await post('/rules/toggle', body({ preview: true })) } catch (e) { plan.value = null; error.value = e }
}
function setScope(s) { scope.value = s }
function toggleHost(h) {
  const i = hosts.value.indexOf(h)
  if (i >= 0) hosts.value.splice(i, 1)
  else hosts.value.push(h)
}
async function submit() {
  busy.value = true
  error.value = null
  try {
    const r = await post('/rules/toggle', body({ reason: reason.value.trim() }))
    emit('done', r)
  } catch (e) { error.value = e } finally { busy.value = false }
}
watch([scope, () => hosts.value.length], preview)
onMounted(async () => {
  if (needsScope.value) {
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
    } catch { /* typing is not offered: the sites come from nginx */ }
  }
  preview()
})
</script>

<style scoped>
.ruletoggle { border-left: 3px solid var(--accent); }
.flabel { display: block; font-weight: 600; margin-bottom: 4px; }
.hostchips { margin-top: 8px; max-height: 200px; overflow: auto; }
.chipcheck { font: inherit; cursor: pointer; }
.planbox { margin: 8px 0; padding: 8px 10px; border: 1px dashed var(--border-strong); border-radius: 6px; }
.planbox details { margin-top: 4px; }
</style>
