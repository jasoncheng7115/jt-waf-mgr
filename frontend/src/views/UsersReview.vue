<!-- Periodic account review: every account and active API token, with the policy in force. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('review.title') }}</h1>
      <RouterLink class="btn small ghost" to="/admin/users"><Icon name="users" />{{ t('nav.users') }}</RouterLink>
      <button class="btn small" type="button" :disabled="!data" @click="csv"><Icon name="download" />{{ t('review.download_csv') }}</button>
      <button class="btn small" type="button" :disabled="!data" @click="json"><Icon name="download" />{{ t('common.download_json') }}</button>
    </div>
    <p class="muted">{{ t('review.intro') }}</p>
    <ErrorBox :error="error" />
    <Loading v-if="!data && !error" />
    <template v-if="data">
      <p class="muted small">{{ t('review.generated', { at: fmtMinute(data.generated_at), node: safeText(data.node_id, 60) }) }}</p>
      <section class="card">
        <h2>{{ t('nav.users') }} <span class="count">{{ data.users.length }}</span></h2>
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('users.role') }}</h3><SegBar :parts="roleParts" :label="t('users.role')" /></div>
          <div><h3 class="charthead">{{ t('totp.title') }}</h3><SegBar :parts="totpParts" :label="t('totp.title')" /></div>
        </div>
        <DataTable id="review-users" :columns="userCols" :rows="data.users" row-key="username" :row-class="(u) => ({ dim: u.disabled })">
          <template #cell-username="{ row }"><span class="mono">{{ safeText(row.username, 64) }}</span></template>
          <template #cell-state="{ row }">{{ row.disabled ? t('users.disabled') : t('users.active') }}
            <span v-if="row.locked" class="badge b-blocked">{{ t('users.locked') }}</span>
            <span v-if="row.must_change_password" class="badge b-warn">{{ t('review.must_change') }}</span></template>
          <template #cell-totp="{ row }"><span class="badge" :class="row.totp_enabled ? 'b-ok' : 'b-warn'">{{ row.totp_enabled ? t('totp.enabled') : t('totp.disabled') }}</span></template>
          <template #cell-last_login="{ row }">{{ fmtMinute(row.last_login) }}<div v-if="row.last_login_ip" class="sub mono">{{ safeText(row.last_login_ip, 45) }}</div></template>
          <template #cell-days_since_activity="{ row }"><span class="mono" :class="{ warn: dormantSoon(row) }">{{ row.days_since_activity }}</span></template>
          <template #cell-expires_at="{ row }">{{ fmtDate(row.expires_at) }}</template>
          <template #cell-password_changed_at="{ row }">{{ fmtDate(row.password_changed_at) }}</template>
          <template #cell-created_at="{ row }">{{ fmtDate(row.created_at) }}</template>
        </DataTable>
      </section>
      <section class="card">
        <h2>{{ t('nav.tokens') }} <span class="count">{{ data.tokens.length }}</span></h2>
        <DataTable id="review-tokens" :columns="tokenCols" :rows="data.tokens">
          <template #cell-name="{ row }">{{ safeText(row.name, 64) }} <span class="muted small mono">{{ safeText(row.id, 20) }}</span></template>
          <template #cell-scopes="{ row }"><span v-for="s in row.scopes" :key="s" class="chip mono">{{ safeText(s, 40) }}</span></template>
          <template #cell-allowed_cidrs="{ row }"><span class="mono small">{{ (row.allowed_cidrs || []).map((c) => safeText(c, 50)).join(', ') || t('tokens.any_source') }}</span></template>
          <template #cell-expires_at="{ row }">{{ row.expires_at ? fmtDate(row.expires_at) : t('tokens.never') }}</template>
          <template #cell-last_used_at="{ row }">{{ fmtMinute(row.last_used_at) }}</template>
          <template #cell-created_at="{ row }">{{ fmtDate(row.created_at) }}</template>
        </DataTable>
      </section>
      <section class="card">
        <h2>{{ t('review.policy') }}</h2>
        <dl class="kv two">
          <template v-for="(v, k) in data.policy" :key="k">
            <dt class="mono">{{ safeText(k, 60) }}</dt><dd class="mono">{{ Array.isArray(v) ? v.map((x) => safeText(x, 30)).join(', ') : safeText(v, 60) }}</dd>
          </template>
        </dl>
      </section>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { get } from '../api.js'
import { t } from '../i18n.js'
import { safeText, fmtMinute, fmtDate, toCsv, downloadText, stamp } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import SegBar from '../components/charts/SegBar.vue'

const data = ref(null)
const error = ref(null)

const userCols = computed(() => [
  { key: 'username', label: t('login.username'), required: true },
  { key: 'display_name', label: t('users.display_name') },
  { key: 'role', label: t('users.role'), value: (u) => t('role.' + u.role) },
  { key: 'state', label: t('users.state'), value: (u) => (u.disabled ? t('users.disabled') : t('users.active')) + (u.locked ? ' ' + t('users.locked') : '') },
  { key: 'totp', label: t('totp.title'), value: (u) => (u.totp_enabled ? t('totp.enabled') : t('totp.disabled')) },
  { key: 'last_login', label: t('users.last_login'), nowrap: true, text: (u) => fmtMinute(u.last_login) + ' ' + (u.last_login_ip || '') },
  { key: 'days_since_activity', label: t('review.days_inactive'), align: 'num' },
  { key: 'sessions', label: t('review.sessions'), align: 'num' },
  { key: 'expires_at', label: t('users.expires'), nowrap: true, text: (u) => fmtDate(u.expires_at) },
  { key: 'password_changed_at', label: t('review.password_changed'), nowrap: true, text: (u) => fmtDate(u.password_changed_at) },
  { key: 'created_at', label: t('users.created'), nowrap: true, hidden: true, text: (u) => fmtDate(u.created_at) },
])
const tokenCols = computed(() => [
  { key: 'name', label: t('tokens.name'), required: true, text: (k) => k.name + ' ' + k.id },
  { key: 'scopes', label: t('tokens.scopes') },
  { key: 'allowed_cidrs', label: t('tokens.allowed_cidrs') },
  { key: 'expires_at', label: t('tokens.expires_at'), nowrap: true, text: (k) => (k.expires_at ? fmtDate(k.expires_at) : t('tokens.never')) },
  { key: 'last_used_at', label: t('tokens.last_used'), nowrap: true, text: (k) => fmtMinute(k.last_used_at) },
  { key: 'created_by', label: t('review.created_by') },
  { key: 'created_at', label: t('users.created'), nowrap: true, hidden: true, text: (k) => fmtDate(k.created_at) },
])
const roleParts = computed(() => ['admin', 'approver', 'operator', 'viewer'].map((r, i) => ({
  key: r, label: t('role.' + r), value: data.value.users.filter((u) => u.role === r && !u.disabled).length, tone: ['s1', 's2', 's3', 'muted'][i],
})).filter((p) => p.value > 0))
const totpParts = computed(() => [
  { key: 'on', label: t('totp.enabled'), value: data.value.users.filter((u) => u.totp_enabled && !u.disabled).length, tone: 'good' },
  { key: 'off', label: t('totp.disabled'), value: data.value.users.filter((u) => !u.totp_enabled && !u.disabled).length, tone: 'warning' },
])

function dormantSoon(u) {
  const d = data.value && data.value.policy && data.value.policy.dormant_days
  return !u.disabled && d > 0 && u.days_since_activity >= d - 14
}

function csv() {
  const d = data.value
  const head = ['type', 'name', 'display_name', 'role', 'state', 'totp', 'last_login', 'last_login_ip', 'days_since_activity',
    'sessions', 'expires_at', 'password_changed_at', 'created_at', 'created_by', 'scopes', 'allowed_cidrs', 'last_used_at']
  const rows = d.users.map((u) => ['user', u.username, u.display_name, u.role,
    (u.disabled ? 'disabled' : 'active') + (u.locked ? ',locked' : ''), u.totp_enabled ? 'yes' : 'no', u.last_login,
    u.last_login_ip, u.days_since_activity, u.sessions, u.expires_at, u.password_changed_at, u.created_at, '', '', '', ''])
  for (const k of d.tokens) {
    rows.push(['token', k.name + ' (' + k.id + ')', '', '', k.revoked ? 'revoked' : 'active', '', '', '', '', '',
      k.expires_at, '', k.created_at, k.created_by, (k.scopes || []).join(' '), (k.allowed_cidrs || []).join(' '), k.last_used_at])
  }
  downloadText('jt-waf-mgr-account-review-' + stamp() + '.csv', toCsv(head, rows), 'text/csv;charset=utf-8', true)
}

function json() {
  downloadText('jt-waf-mgr-account-review-' + stamp() + '.json', JSON.stringify(data.value, null, 1), 'application/json')
}

onMounted(async () => {
  try { data.value = await get('/users/review') } catch (e) { error.value = e }
})
</script>
