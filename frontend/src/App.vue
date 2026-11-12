<template>
  <div class="app" :class="{ bare: bare }">
    <!-- Top bar. The links stay inline while they fit (measured, so it works for every language and role);
         when not, the links that do not fit fold into one "More" (or "Admin") drop-down; when fewer than three
         fit, everything folds into the menu button.
         On phones the theme / language / account controls move into that panel too. -->
    <header v-if="!bare" ref="barEl" class="topbar" :class="'nav-l' + navLevel">
      <button v-if="navLevel === 2" ref="menuBtn" type="button" class="btn ghost navtoggle" :aria-expanded="openMenu === 'all' ? 'true' : 'false'"
              aria-controls="navpanel" :aria-label="t('nav.menu')" :title="t('nav.menu')" @click="toggleMenu('all')"><Icon :name="openMenu === 'all' ? 'close' : 'list'" /></button>
      <RouterLink to="/" class="brand"><img class="brand-logo" src="/logo-mark.svg" alt="" width="26" height="26">jt-waf-mgr</RouterLink>
      <span v-if="state.meta.node_id" class="node" :title="t('app.node')">{{ safeText(state.meta.node_id) }}</span>
      <nav ref="navEl" class="mainnav" :aria-label="t('nav.main')">
        <!-- invisible copy of the top-level entries, only for measuring their widths -->
        <div class="navmeasure" aria-hidden="true" inert>
          <div ref="m0" class="navrow">
            <span v-for="g in navGroups" :key="g.key" class="navlink" :class="{ navmorebtn: g.items }"><Icon v-if="g.items || g.inlineIcon" :name="g.icon" />{{ g.label }}<span v-if="g.badge" class="badge tiny b-warn">{{ g.badge }}</span><Icon v-if="g.items" name="expand" /></span>
          </div>
        </div>
        <template v-if="navLevel === 0">
          <template v-for="(g, gi) in navGroups" :key="g.key">
            <RouterLink v-if="g.to" :to="g.to" class="navlink" v-bind="activeProps(g)"><Icon v-if="g.inlineIcon" :name="g.icon" />{{ g.label }}</RouterLink>
            <div v-else class="navmore">
              <button :ref="(el) => { trig[g.key] = el }" type="button" class="navlink navmorebtn" :class="{ active: groupActive(g) }"
                      :aria-expanded="openMenu === 'g:' + g.key ? 'true' : 'false'" :aria-controls="'navgrp-' + g.key" @click="toggleMenu('g:' + g.key)">
                <Icon :name="g.icon" />{{ g.label }}<span v-if="g.badge" class="badge tiny b-warn" :title="g.badgeTitle">{{ g.badge }}</span><Icon :name="openMenu === 'g:' + g.key ? 'collapse' : 'expand'" /></button>
              <div v-if="openMenu === 'g:' + g.key" :id="'navgrp-' + g.key" ref="panelEl" class="navdrop" :class="{ left: gi < navGroups.length / 2 }" @keydown.esc="closeMenu(true)">
                <RouterLink v-for="l in g.items" :key="l.to" :to="l.to" class="navitem" v-bind="activeProps(l)"><Icon :name="l.icon" />{{ l.label }}<span v-if="l.badge" class="badge tiny b-warn" :title="l.badgeTitle">{{ l.badge }}</span></RouterLink>
              </div>
            </div>
          </template>
        </template>
      </nav>
      <div class="topright">
        <ThemeSwitch />
        <LangSwitch />
        <RouterLink v-if="state.user" to="/account" class="userlink" :title="t('nav.account')">
          <span class="username">{{ safeText(state.user.display_name || state.user.username, 40) }}</span>
          <span class="role">{{ t('role.' + state.user.role) }}</span>
        </RouterLink>
        <button v-if="state.user" type="button" class="btn small ghost logoutbtn" :title="t('nav.logout')" @click="logout"><Icon name="logout" /><span class="btntext">{{ t('nav.logout') }}</span></button>
      </div>
      <div v-if="openMenu === 'all'" id="navpanel" ref="panelEl" class="navpanel" @keydown.esc="closeMenu(true)">
        <section v-for="g in navGroups.filter((x) => x.items)" :key="g.key" class="np-group">
          <h2 class="np-head">{{ g.label }}</h2>
          <div class="np-links">
            <RouterLink v-for="l in g.items" :key="l.to" :to="l.to" class="navitem" v-bind="activeProps(l)"><Icon :name="l.icon" />{{ l.label }}<span v-if="l.badge" class="badge tiny b-warn" :title="l.badgeTitle">{{ l.badge }}</span></RouterLink>
          </div>
        </section>
        <section class="np-group">
          <div class="np-links">
            <RouterLink v-for="g in navGroups.filter((x) => x.to)" :key="g.key" :to="g.to" class="navitem" v-bind="activeProps(g)"><Icon :name="g.icon" />{{ g.label }}</RouterLink>
          </div>
        </section>
        <section class="np-group np-me">
          <h2 class="np-head">{{ t('nav.group_me') }}</h2>
          <div class="np-controls">
            <ThemeSwitch />
            <LangSwitch />
          </div>
          <div class="np-links">
            <RouterLink v-if="state.user" to="/account" class="navitem" active-class="active"><Icon name="user" />{{ safeText(state.user.display_name || state.user.username, 40) }}
              <span class="role">{{ t('role.' + state.user.role) }}</span></RouterLink>
            <button v-if="state.user" type="button" class="navitem" @click="logout"><Icon name="logout" />{{ t('nav.logout') }}</button>
          </div>
        </section>
      </div>
    </header>
    <div v-else class="bare-top"><ThemeSwitch /><LangSwitch /></div>

    <main class="content">
      <!-- the server was upgraded while this tab was open: the page still runs the old program until it reloads -->
      <div v-if="newVersion" class="alert info newver" role="status">
        <span>{{ t('app.new_version', { version: safeText(newVersion, 20) }) }}</span>
        <button type="button" class="btn small primary" @click="reloadPage"><Icon name="refresh" />{{ t('app.reload') }}</button>
      </div>
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
import { computed, ref, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { state, hasRole, clearSession, pending, refreshPending, alertCount, refreshAlerts } from './store.js'
import { startCardFold, relabelCardFold } from './cardFold.js'
import { get, post } from './api.js'
import { t, lang } from './i18n.js'
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

// navigation: groups (each a drop-down) and a few direct links, drawn inline when they fit, else in the menu panel
const navGroups = computed(() => [
  { key: 'overview', to: '/', label: t('nav.overview'), icon: 'chart', exact: true },
  { key: 'events', label: t('nav.g_events'), icon: 'list', badge: alertCount.open || 0, badgeTitle: t('nav.open_alerts'), items: [
    { to: '/events', label: t('nav.events_list'), icon: 'list' },
    { to: '/alerts', label: t('nav.alerts'), icon: 'bell', badge: alertCount.open || 0, badgeTitle: t('nav.open_alerts') },
    ...(isApprover.value ? [{ to: '/analysis', label: t('nav.analysis'), icon: 'timer' }] : []),
    { to: '/lookup', label: t('nav.lookup'), icon: 'search' },
  ] },
  { key: 'rules', label: t('nav.g_rules'), icon: 'shield', items: [
    { to: '/rules', label: t('nav.rules_list'), icon: 'shield' },
    { to: '/vhosts', label: t('nav.vhosts'), icon: 'server' },
    { to: '/crs', label: t('nav.crs'), icon: 'code' },
    { to: '/waf', label: t('waf.title'), icon: 'verify' },
  ] },
  { key: 'changes', label: t('nav.g_changes'), icon: 'change', badge: pending.count || 0, badgeTitle: t('nav.pending_approval'), items: [
    { to: '/changes', label: t('nav.changes_list'), icon: 'change', badge: pending.count || 0, badgeTitle: t('nav.pending_approval') },
    ...(isApprover.value ? [{ to: '/config-changes', label: t('nav.config_changes'), icon: 'history' }] : []),
  ] },
  ...(isAdmin.value ? [{ key: 'admin', label: t('nav.admin'), icon: 'settings', items: [
    { to: '/admin/users', label: t('nav.users'), icon: 'users' },
    { to: '/admin/tokens', label: t('nav.tokens'), icon: 'key' },
    { to: '/admin/audit', label: t('nav.audit'), icon: 'page' },
    { to: '/admin/system', label: t('nav.system'), icon: 'verify' },
    { to: '/admin/compliance', label: t('nav.compliance'), icon: 'report' },
    { to: '/admin/notify', label: t('nav.notify'), icon: 'notify' },
    { to: '/admin/settings', label: t('nav.settings'), icon: 'settings' },
  ] }] : []),
  { key: 'guide', to: '/guide', label: t('nav.guide'), icon: 'help', inlineIcon: true },
])
const trig = {}
function groupActive(g) { return g.items.some((l) => route.path === l.to || route.path.startsWith(l.to + '/')) }
function activeProps(l) { return l.exact ? { 'exact-active-class': 'active', 'active-class': '' } : { 'active-class': 'active' } }
// 0 = the groups inline; 2 = they do not fit (or a phone): one menu button with everything.
const navLevel = ref(0)
const openMenu = ref(null)        // null | 'g:<group>' | 'all'
const barEl = ref(null), navEl = ref(null), m0 = ref(null), menuBtn = ref(null), panelEl = ref(null)
const PHONE = '(max-width: 640px)'
function measure() {
  if (!navEl.value || !m0.value) return
  if (window.matchMedia && window.matchMedia(PHONE).matches) { setLevel(2); return }
  const gap = parseFloat(getComputedStyle(barEl.value).columnGap) || 0
  const room = navEl.value.clientWidth + (navLevel.value === 2 && menuBtn.value ? menuBtn.value.offsetWidth + gap : 0) - 2
  setLevel(m0.value.offsetWidth <= room ? 0 : 2)
}
function setLevel(n) {
  if (navLevel.value === n) return
  navLevel.value = n
  openMenu.value = null
}
let ro = null, raf = 0
function schedule() { cancelAnimationFrame(raf); raf = requestAnimationFrame(measure) }
watch([barEl, navEl, m0], ([b, n, m]) => {
  if (ro) ro.disconnect()
  if (!b || typeof ResizeObserver === 'undefined') return
  ro = new ResizeObserver(schedule)
  ro.observe(b); ro.observe(n); ro.observe(m)
  measure()
}, { flush: 'post' })
watch(lang, () => nextTick(relabelCardFold))
watch([lang, () => navGroups.value.length, () => pending.count, () => alertCount.open, () => state.meta.node_id], () => nextTick(measure))

async function toggleMenu(which) {
  if (openMenu.value === which) { closeMenu(true); return }
  openMenu.value = which
  await nextTick()
  panelOf()?.querySelector('a, button')?.focus()
}
function closeMenu(refocus) {
  const which = openMenu.value
  if (!which) return
  openMenu.value = null
  if (refocus === true) triggerOf(which)?.focus()
}
function triggerOf(which) { return which === 'all' ? menuBtn.value : trig[String(which).slice(2)] }
function panelOf() { return Array.isArray(panelEl.value) ? panelEl.value[0] : panelEl.value }
function onDocDown(e) {
  if (!openMenu.value) return
  const trigger = triggerOf(openMenu.value)
  if (panelOf()?.contains(e.target) || trigger?.contains(e.target)) return
  closeMenu(false)
}
function onDocKey(e) { if (e.key === 'Escape' && openMenu.value && !e.defaultPrevented) closeMenu(true) }
function onFocusIn(e) {
  if (!openMenu.value) return
  const trigger = triggerOf(openMenu.value)
  if (panelOf()?.contains(e.target) || trigger?.contains(e.target)) return
  closeMenu(false)
}
watch(() => route.fullPath, () => { openMenu.value = null })

// After an upgrade an open tab keeps the program it loaded; look at the server's version every few minutes and when
// the tab comes back to the front, and offer a reload when it changed.
const newVersion = ref('')
let ticks = 0
async function checkVersion() {
  try {
    const m = await get('/meta')
    if (state.meta.version && m && m.version && m.version !== state.meta.version) newVersion.value = m.version
  } catch { /* offline or signed out: try again later */ }
}
function onVisible() { if (document.visibilityState === 'visible') checkVersion() }
function reloadPage() { window.location.reload() }

let timer = null
onMounted(() => {
  timer = setInterval(() => { refreshPending(true); refreshAlerts(true); if (++ticks % 5 === 0) checkVersion() }, 60000)
  document.addEventListener('visibilitychange', onVisible)
  startCardFold()
  document.addEventListener('pointerdown', onDocDown, true)
  document.addEventListener('keydown', onDocKey)
  document.addEventListener('focusin', onFocusIn)
})
onUnmounted(() => {
  clearInterval(timer)
  document.removeEventListener('visibilitychange', onVisible)
  if (ro) ro.disconnect()
  cancelAnimationFrame(raf)
  document.removeEventListener('pointerdown', onDocDown, true)
  document.removeEventListener('keydown', onDocKey)
  document.removeEventListener('focusin', onFocusIn)
})

async function logout() {
  try { await post('/auth/logout') } catch { /* session may already be gone */ }
  clearSession()
  router.replace({ name: 'login' })
}
</script>
