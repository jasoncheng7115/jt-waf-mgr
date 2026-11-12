<!-- Notifications (admin): channels, which events go where, and what was sent. The web service only queues
     messages; the separate jt-waf-mgr-notify unit sends them, retries failures and reminds open alerts. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('notify.title') }}</h1>
      <div class="actions">
        <RouterLink to="/alerts" class="btn small"><Icon name="bell" />{{ t('notify.to_alerts') }}</RouterLink>
        <button type="button" class="btn small ghost" :disabled="loading" @click="reload"><Icon name="refresh" />{{ t('common.refresh') }}</button>
      </div>
    </div>
    <p class="muted">{{ t('notify.intro') }}</p>
    <ErrorBox :error="error" />
    <section v-if="st" class="card">
      <h2><Icon name="info" /> {{ t('notify.status') }}</h2>
      <FlowSteps :steps="steps" />
      <dl class="kv">
        <dt>{{ t('notify.state') }}</dt>
        <dd><span class="badge" :class="st.enabled ? 'b-ok' : 'b-logged'">{{ st.enabled ? t('notify.on') : t('notify.off') }}</span></dd>
        <dt>{{ t('notify.last_run') }}</dt><dd>{{ st.last_run ? fmtMinute(st.last_run) : '—' }}</dd>
        <dt>{{ t('notify.pending') }}</dt><dd>{{ st.pending }}</dd>
      </dl>
      <div class="chlist">
        <div v-for="c in st.channels" :key="c.channel" class="chitem" :class="{ on: c.active }">
          <Icon :name="c.channel === 'email' ? 'mail' : c.channel === 'webhook' ? 'link' : 'chat'" />
          <a :href="'#uiset-n_' + c.channel" @click.prevent="go('uiset-n_' + c.channel)">{{ tOr('notify.ch.' + c.channel, c.channel) }}</a>
          <span class="badge tiny" :class="c.active ? 'b-ok' : c.configured ? 'b-warn' : 'b-logged'">{{ c.active ? t('notify.ch_active') : c.configured ? t('notify.ch_off') : t('notify.ch_unset') }}</span>
          <span v-if="c.last_24h.sent" class="small muted">{{ t('notify.sent_n', { n: c.last_24h.sent }) }}</span>
          <span v-if="c.last_24h.failed" class="small bad">{{ t('notify.failed_n', { n: c.last_24h.failed }) }}</span>
        </div>
      </div>
    </section>
    <UiSettings :groups="GROUPS" @saved="reload" />
    <NotifyMatrix :status="st" @saved="reload" />
    <section class="card">
      <h2><Icon name="history" /> {{ t('notify.deliveries') }}</h2>
      <p class="muted small">{{ t('notify.deliveries_hint') }}</p>
      <RowTimeline v-model:window="win" :rows="items" ts-key="created_at" :series="tlSeries" />
      <DataTable id="notify-deliveries" :columns="cols" :rows="shownItems" row-key="id" :has-more="!!cursor" :loading-more="loading"
                 :default-sort="{ key: 'id', dir: -1 }" :empty="t('notify.no_deliveries')" @more="more">
        <template #cell-created_at="{ row }"><span class="nowrap">{{ fmtShortTime(row.created_at) }}</span></template>
        <template #cell-event="{ row }">{{ tOr('notify.ev.' + row.event, row.event) }}<span v-if="row.test" class="badge tiny b-int">{{ t('notify.test') }}</span>
          <div v-if="refLink(row)" class="sub"><RouterLink :to="refLink(row)">{{ refText(row) }}</RouterLink></div></template>
        <template #cell-channel="{ row }">{{ tOr('notify.ch.' + row.channel, row.channel) }}</template>
        <template #cell-status="{ row }"><span class="badge" :class="STATUS[row.status] || 'b-logged'">{{ tOr('notify.st.' + row.status, row.status) }}</span></template>
        <template #cell-error="{ row }"><span class="small mono breakall">{{ errOf(row) }}</span></template>
      </DataTable>
    </section>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'
import { get } from '../api.js'
import RowTimeline from '../components/RowTimeline.vue'
import { inWindow } from '../timeWindow.js'
import { t, tOr } from '../i18n.js'
import { fmtMinute, fmtShortTime, safeText } from '../util.js'
import Icon from '../components/Icon.vue'
import ErrorBox from '../components/ErrorBox.vue'
import DataTable from '../components/DataTable.vue'
import FlowSteps from '../components/FlowSteps.vue'
import UiSettings from '../components/UiSettings.vue'
import NotifyMatrix from '../components/NotifyMatrix.vue'

const GROUPS = ['notify', 'n_email', 'n_telegram', 'n_teams', 'n_slack', 'n_discord', 'n_zulip', 'n_nextcloud', 'n_webhook']
const STATUS = { sent: 'b-ok', failed: 'b-blocked', pending: 'b-int', sending: 'b-int', suppressed: 'b-warn', skipped: 'b-logged' }
const st = ref(null)
const items = ref([])
const win = ref(null)
const shownItems = computed(() => inWindow(items.value, 'created_at', win.value))
const tlSeries = computed(() => [{ key: 'sent', label: t('notify.st.sent'), tone: 's1', test: (r) => r.status === 'sent' }, { key: 'failed', label: t('notify.st.failed'), tone: 'blocked', test: (r) => r.status === 'failed' }, { key: 'other', label: t('timeline.other'), tone: 's3', test: () => true }])
const cursor = ref(null)
const loading = ref(false)
const error = ref(null)

const steps = computed(() => {
  if (!st.value) return []
  const anySet = st.value.channels.some((c) => c.configured)
  const anyTested = items.value.some((d) => d.test && d.status === 'sent')
  const s = (done, cur) => (done ? 'done' : cur ? 'current' : 'todo')
  return [
    { key: 'ch', icon: 'chat', label: t('notify.step.channel'), state: s(anySet, true) },
    { key: 'test', icon: 'send', label: t('notify.step.test'), state: s(anyTested, anySet) },
    { key: 'ev', icon: 'list', label: t('notify.step.events'), state: s(anyTested && st.value.enabled, anyTested) },
    { key: 'on', icon: 'check', label: t('notify.step.on'), state: s(st.value.enabled && st.value.channels.some((c) => c.active), anyTested) },
  ]
})
const cols = computed(() => [
  { key: 'id', label: t('notify.col.id'), align: 'num', hidden: true },
  { key: 'created_at', label: t('notify.col.time'), required: true, text: (r) => fmtShortTime(r.created_at) },
  { key: 'event', label: t('notify.col.event'), value: (r) => tOr('notify.ev.' + r.event, r.event) },
  { key: 'channel', label: t('notify.col.channel'), value: (r) => tOr('notify.ch.' + r.channel, r.channel) },
  { key: 'status', label: t('notify.col.status'), value: (r) => tOr('notify.st.' + r.status, r.status) },
  { key: 'attempts', label: t('notify.col.attempts'), align: 'num', hidden: true },
  { key: 'error', label: t('notify.col.error'), value: (r) => errOf(r) },
  { key: 'requested_by', label: t('notify.col.by'), hidden: true },
])
function errOf(r) {
  if (!r.error) return ''
  return tOr('notify.err.' + r.error, safeText(r.error, 300))
}
function refLink(r) {
  const x = r.ref || {}
  if (x.change_id) return '/changes/' + x.change_id
  if (x.run_id) return '/analysis/' + x.run_id
  if (x.alert_id) return '/alerts'
  if (x.snapshot) return '/config-changes/' + x.snapshot
  return ''
}
function refText(r) {
  const x = r.ref || {}
  if (x.change_id) return t('notify.ref.change', { id: x.change_id })
  if (x.run_id) return t('notify.ref.run', { id: x.run_id })
  if (x.alert_id) return t('notify.ref.alert', { id: x.alert_id })
  return t('notify.ref.snapshot', { id: x.snapshot })
}
async function loadItems(append) {
  loading.value = true
  try {
    const r = await get('/notify/deliveries', { limit: 100, cursor: append ? cursor.value : undefined })
    items.value = append ? items.value.concat(r.items) : r.items
    cursor.value = r.next_cursor
  } catch (e) { error.value = e } finally { loading.value = false }
}
function more() { if (cursor.value) loadItems(true) }
async function reload() {
  try { st.value = await get('/notify/status') } catch (e) { error.value = e }
  loadItems(false)
}
async function go(id) {
  await nextTick()
  const el = document.getElementById(id)
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
onMounted(reload)
</script>

<style scoped>
.chlist { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.chitem { display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--panel); }
.chitem.on { border-color: var(--ok); }
.chitem .bad { color: var(--blocked); }
.sub { font-size: .85em; }
</style>
