<template>
  <div class="app" :class="{ bare: bare }">
    <header v-if="!bare" class="topbar">
      <RouterLink to="/" class="brand"><img class="brand-logo" src="/logo-mark.svg" alt="" width="26" height="26">jt-waf-mgr</RouterLink>
      <span v-if="state.meta.node_id" class="node" :title="t('app.node')">{{ safeText(state.meta.node_id) }}</span>
      <nav class="mainnav">
        <RouterLink to="/" exact-active-class="active">{{ t('nav.overview') }}</RouterLink>
        <RouterLink to="/events" active-class="active">{{ t('nav.events') }}</RouterLink>
        <RouterLink to="/rules" active-class="active">{{ t('nav.rules') }}</RouterLink>
        <RouterLink to="/changes" active-class="active">{{ t('nav.changes') }}<span v-if="pending.count" class="badge tiny b-warn" :title="t('nav.pending_approval')">{{ pending.count }}</span></RouterLink>
        <RouterLink to="/vhosts" active-class="active">{{ t('nav.vhosts') }}</RouterLink>
        <RouterLink to="/crs" active-class="active">{{ t('nav.crs') }}</RouterLink>
        <RouterLink to="/lookup" active-class="active">{{ t('nav.lookup') }}</RouterLink>
        <RouterLink v-if="isApprover" to="/config-changes" active-class="active">{{ t('nav.config_changes') }}</RouterLink>
        <RouterLink to="/guide" active-class="active"><Icon name="help" /> {{ t('nav.guide') }}</RouterLink>
        <span v-if="isAdmin" class="navsep" aria-hidden="true"></span>
        <template v-if="isAdmin">
          <RouterLink to="/admin/users" active-class="active">{{ t('nav.users') }}</RouterLink>
          <RouterLink to="/admin/tokens" active-class="active">{{ t('nav.tokens') }}</RouterLink>
          <RouterLink to="/admin/audit" active-class="active">{{ t('nav.audit') }}</RouterLink>
          <RouterLink to="/admin/system" active-class="active">{{ t('nav.system') }}</RouterLink>
          <RouterLink to="/admin/compliance" active-class="active">{{ t('nav.compliance') }}</RouterLink>
          <RouterLink to="/admin/settings" active-class="active">{{ t('nav.settings') }}</RouterLink>
        </template>
      </nav>
      <div class="topright">
        <ThemeSwitch />
        <LangSwitch />
        <RouterLink v-if="state.user" to="/account" class="userlink" :title="t('nav.account')">
          {{ safeText(state.user.display_name || state.user.username, 40) }}
          <span class="role">{{ t('role.' + state.user.role) }}</span>
        </RouterLink>
        <button v-if="state.user" type="button" class="btn small ghost" @click="logout"><Icon name="logout" />{{ t('nav.logout') }}</button>
      </div>
    </header>
    <div v-else class="bare-top"><ThemeSwitch /><LangSwitch /></div>

    <main class="content">
      <div v-if="!bare && state.lastLogin" class="alert lastlogin" :class="state.lastLogin.failed_since > 0 ? 'warn' : 'info'" role="status">
        <span v-if="state.lastLogin.at">{{ t('lastlogin.at', { at: fmtMinute(state.lastLogin.at), ip: safeText(state.lastLogin.ip || '—', 45) }) }}</span>
        <span v-else>{{ t('lastlogin.first') }}</span>
        <span v-if="state.lastLogin.failed_since > 0"> {{ t('lastlogin.failed', { n: state.lastLogin.failed_since }) }}</span>
        <button type="button" class="btn small ghost" @click="state.lastLogin = null"><Icon name="dismiss" />{{ t('common.dismiss') }}</button>
      </div>
      <RouterView />
    </main>

    <footer class="footer">
      <span>jt-waf-mgr<template v-if="state.meta.version"> v{{ safeText(state.meta.version) }}</template></span>
      <span class="dot" aria-hidden="true">·</span>
      <a v-if="sourceUrl" :href="sourceUrl" target="_blank" rel="noopener noreferrer">{{ t('footer.source') }}</a>
      <span v-else>{{ t('footer.source') }}</span>
    </footer>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { state, hasRole, clearSession, pending, refreshPending } from './store.js'
import { post } from './api.js'
import { t } from './i18n.js'
import { safeText, fmtMinute } from './util.js'
import LangSwitch from './components/LangSwitch.vue'
import ThemeSwitch from './components/ThemeSwitch.vue'
import Icon from './components/Icon.vue'

const route = useRoute()
const router = useRouter()
const bare = computed(() => !!route.meta.bare || !state.user)
const isAdmin = computed(() => hasRole('admin'))
const isApprover = computed(() => hasRole('approver'))
const sourceUrl = computed(() => {
  const u = state.meta.source_url || ''
  return /^https:\/\//i.test(u) ? u : ''
})

let timer = null
onMounted(() => { timer = setInterval(() => refreshPending(true), 60000) })
onUnmounted(() => clearInterval(timer))

async function logout() {
  try { await post('/auth/logout') } catch { /* session may already be gone */ }
  clearSession()
  router.replace({ name: 'login' })
}
</script>
