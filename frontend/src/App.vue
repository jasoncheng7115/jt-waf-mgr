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
        <!-- invisible copy of the links, only for measuring their widths -->
        <div class="navmeasure" aria-hidden="true" inert>
          <div ref="m0" class="navrow">
            <span v-for="l in mainLinks" :key="l.to" class="navlink" data-g="main"><Icon v-if="l.inlineIcon" :name="l.icon" />{{ l.label }}<span v-if="l.badge" class="badge tiny b-warn">{{ l.badge }}</span></span>
            <template v-if="adminLinks.length"><span class="navsep"></span><span v-for="l in adminLinks" :key="l.to" class="navlink">{{ l.label }}</span></template>
          </div>
          <div ref="m1" class="navrow">
            <span class="navsep"></span><span class="navlink navmorebtn" data-g="more"><Icon name="more" />{{ t('nav.more') }}<Icon name="expand" /></span>
            <span class="navsep"></span><span class="navlink navmorebtn" data-g="more"><Icon name="settings" />{{ t('nav.admin') }}<Icon name="expand" /></span>
          </div>
        </div>
        <template v-if="navLevel < 2">
          <RouterLink v-for="l in inlineMain" :key="l.to" :to="l.to" class="navlink" v-bind="activeProps(l)"><Icon v-if="l.inlineIcon" :name="l.icon" />{{ l.label }}<span v-if="l.badge" class="badge tiny b-warn" :title="t('nav.pending_approval')">{{ l.badge }}</span></RouterLink>
          <template v-if="adminLinks.length || moreMain.length">
            <span class="navsep" aria-hidden="true"></span>
            <template v-if="navLevel === 0">
              <RouterLink v-for="l in adminLinks" :key="l.to" :to="l.to" class="navlink" active-class="active">{{ l.label }}</RouterLink>
            </template>
            <div v-else class="navmore">
              <button ref="moreBtn" type="button" class="navlink navmorebtn" :class="{ active: onHiddenPage }" :aria-expanded="openMenu === 'more' ? 'true' : 'false'"
                      aria-controls="navmorepop" @click="toggleMenu('more')"><Icon :name="moreMain.length ? 'more' : 'settings'" />{{ moreMain.length ? t('nav.more') : t('nav.admin') }}<Icon :name="openMenu === 'more' ? 'collapse' : 'expand'" /></button>
              <div v-if="openMenu === 'more'" id="navmorepop" ref="panelEl" class="navdrop" @keydown.esc="closeMenu(true)">
                <template v-if="moreMain.length">
                  <RouterLink v-for="l in moreMain" :key="l.to" :to="l.to" class="navitem" v-bind="activeProps(l)"><Icon :name="l.icon" />{{ l.label }}<span v-if="l.badge" class="badge tiny b-warn" :title="t('nav.pending_approval')">{{ l.badge }}</span></RouterLink>
                </template>
                <template v-if="adminLinks.length">
                  <h2 v-if="moreMain.length" class="np-head nd-head">{{ t('nav.group_admin') }}</h2>
                  <RouterLink v-for="l in adminLinks" :key="l.to" :to="l.to" class="navitem" active-class="active"><Icon :name="l.icon" />{{ l.label }}</RouterLink>
                </template>
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
        <section class="np-group">
          <h2 class="np-head">{{ t('nav.group_main') }}</h2>
          <div class="np-links">
            <RouterLink v-for="l in mainLinks" :key="l.to" :to="l.to" class="navitem" v-bind="activeProps(l)"><Icon :name="l.icon" />{{ l.label }}<span v-if="l.badge" class="badge tiny b-warn" :title="t('nav.pending_approval')">{{ l.badge }}</span></RouterLink>
          </div>
        </section>
        <section v-if="adminLinks.length" class="np-group">
          <h2 class="np-head">{{ t('nav.group_admin') }}</h2>
          <div class="np-links">
            <RouterLink v-for="l in adminLinks" :key="l.to" :to="l.to" class="navitem" active-class="active"><Icon :name="l.icon" />{{ l.label }}</RouterLink>
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
import { state, hasRole, clearSession, pending, refreshPending } from './store.js'
import { post } from './api.js'
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

// navigation: one list, drawn inline, in the admin drop-down or in the menu panel
const mainLinks = computed(() => [
  { to: '/', label: t('nav.overview'), icon: 'chart', exact: true },
  { to: '/events', label: t('nav.events'), icon: 'list' },
  { to: '/rules', label: t('nav.rules'), icon: 'shield' },
  { to: '/changes', label: t('nav.changes'), icon: 'change', badge: pending.count || 0 },
  { to: '/vhosts', label: t('nav.vhosts'), icon: 'server' },
  { to: '/crs', label: t('nav.crs'), icon: 'code' },
  { to: '/waf', label: t('waf.title'), icon: 'shield' },
  { to: '/lookup', label: t('nav.lookup'), icon: 'search' },
  ...(isApprover.value ? [{ to: '/config-changes', label: t('nav.config_changes'), icon: 'history' }] : []),
  { to: '/guide', label: t('nav.guide'), icon: 'help', inlineIcon: true },
])
const adminLinks = computed(() => (isAdmin.value ? [
  { to: '/admin/users', label: t('nav.users'), icon: 'users' },
  { to: '/admin/tokens', label: t('nav.tokens'), icon: 'key' },
  { to: '/admin/audit', label: t('nav.audit'), icon: 'page' },
  { to: '/admin/system', label: t('nav.system'), icon: 'verify' },
  { to: '/admin/compliance', label: t('nav.compliance'), icon: 'report' },
  { to: '/admin/settings', label: t('nav.settings'), icon: 'settings' },
] : []))
function activeProps(l) { return l.exact ? { 'exact-active-class': 'active', 'active-class': '' } : { 'active-class': 'active' } }
// Priority+: 0 = everything inline; 1 = the first `inlineCount` main links inline, the rest of the main
// links and all admin links in one drop-down ("More", or "Admin" when only those are folded);
// 2 = fewer than MIN_INLINE fit (or a phone): one menu button with everything.
const navLevel = ref(0)
const inlineCount = ref(99)
const MIN_INLINE = 3
const inlineMain = computed(() => (navLevel.value === 1 ? mainLinks.value.slice(0, inlineCount.value) : mainLinks.value))
const moreMain = computed(() => (navLevel.value === 1 ? mainLinks.value.slice(inlineCount.value) : []))
const onHiddenPage = computed(() => route.path.startsWith('/admin/') || moreMain.value.some((l) => l.to !== '/' && route.path.startsWith(l.to)))
const openMenu = ref(null)        // null | 'more' | 'all'
const barEl = ref(null), navEl = ref(null), m0 = ref(null), m1 = ref(null), menuBtn = ref(null), moreBtn = ref(null), panelEl = ref(null)
const PHONE = '(max-width: 640px)'
function measure() {
  if (!navEl.value || !m0.value) return
  if (window.matchMedia && window.matchMedia(PHONE).matches) { setLevel(2, 0); return }
  // the nav is the flexible middle; at level 2 the menu button (and one gap) take part of that room
  const gap = parseFloat(getComputedStyle(barEl.value).columnGap) || 0
  const room = navEl.value.clientWidth + (navLevel.value === 2 && menuBtn.value ? menuBtn.value.offsetWidth + gap : 0) - 2
  if (m0.value.offsetWidth <= room) { setLevel(0, 99); return }
  const step = parseFloat(getComputedStyle(m0.value).columnGap) || 0
  // "more" button with its separator: the wider of the two labels
  const spans = [...m1.value.children]
  const more = Math.max(spans[0].offsetWidth + spans[1].offsetWidth, spans[2].offsetWidth + spans[3].offsetWidth) + 2 * step
  let used = more, k = 0
  for (const el of m0.value.querySelectorAll('[data-g="main"]')) {
    if (used + el.offsetWidth + step > room) break
    used += el.offsetWidth + step
    k++
  }
  if (k >= mainLinks.value.length && !adminLinks.value.length) k = mainLinks.value.length
  if (k < MIN_INLINE) setLevel(2, 0)
  else setLevel(1, k)
}
function setLevel(n, k) {
  if (navLevel.value === n && inlineCount.value === k) return
  navLevel.value = n
  inlineCount.value = k
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
watch([lang, () => mainLinks.value.length, () => adminLinks.value.length, () => pending.count, () => state.meta.node_id], () => nextTick(measure))

async function toggleMenu(which) {
  if (openMenu.value === which) { closeMenu(true); return }
  openMenu.value = which
  await nextTick()
  panelEl.value?.querySelector('a, button')?.focus()
}
function closeMenu(refocus) {
  const which = openMenu.value
  if (!which) return
  openMenu.value = null
  if (refocus === true) (which === 'more' ? moreBtn.value : menuBtn.value)?.focus()
}
function onDocDown(e) {
  if (!openMenu.value) return
  const trigger = openMenu.value === 'more' ? moreBtn.value : menuBtn.value
  if (panelEl.value?.contains(e.target) || trigger?.contains(e.target)) return
  closeMenu(false)
}
function onDocKey(e) { if (e.key === 'Escape' && openMenu.value && !e.defaultPrevented) closeMenu(true) }
function onFocusIn(e) {
  if (!openMenu.value) return
  const trigger = openMenu.value === 'more' ? moreBtn.value : menuBtn.value
  if (panelEl.value?.contains(e.target) || trigger?.contains(e.target)) return
  closeMenu(false)
}
watch(() => route.fullPath, () => { openMenu.value = null })

let timer = null
onMounted(() => {
  timer = setInterval(() => refreshPending(true), 60000)
  document.addEventListener('pointerdown', onDocDown, true)
  document.addEventListener('keydown', onDocKey)
  document.addEventListener('focusin', onFocusIn)
})
onUnmounted(() => {
  clearInterval(timer)
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
