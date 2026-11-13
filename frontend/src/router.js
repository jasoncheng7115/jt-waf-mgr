import Guide from './views/Guide.vue'
import { createRouter, createWebHistory } from 'vue-router'
import { state, hasRole, refreshPending, refreshAlerts } from './store.js'

import Login from './views/Login.vue'
import ChangePassword from './views/ChangePassword.vue'
import TotpRequired from './views/TotpRequired.vue'
import Account from './views/Account.vue'
import Overview from './views/Overview.vue'
import Events from './views/Events.vue'
import EventDetail from './views/EventDetail.vue'
import IpLookup from './views/IpLookup.vue'
import Rules from './views/Rules.vue'
import RuleDetail from './views/RuleDetail.vue'
import Vhosts from './views/Vhosts.vue'
import Crs from './views/Crs.vue'
import WafModel from './views/WafModel.vue'
import AdminUsers from './views/AdminUsers.vue'
import AdminTokens from './views/AdminTokens.vue'
import AdminAudit from './views/AdminAudit.vue'
import AdminSettings from './views/AdminSettings.vue'
import Notifications from './views/Notifications.vue'
import Alerts from './views/Alerts.vue'
import Traffic from './views/Traffic.vue'
import NotFound from './views/NotFound.vue'
import Changes from './views/Changes.vue'
import ChangeNew from './views/ChangeNew.vue'
import ChangeDetail from './views/ChangeDetail.vue'
import Managed from './views/Managed.vue'
import Versions from './views/Versions.vue'
import UsersReview from './views/UsersReview.vue'
import SystemCheck from './views/SystemCheck.vue'
import ConfigChanges from './views/ConfigChanges.vue'
import Compliance from './views/Compliance.vue'
import Analysis from './views/Analysis.vue'

const routes = [
  { path: '/login', name: 'login', component: Login, meta: { public: true, bare: true } },
  { path: '/change-password', name: 'change-password', component: ChangePassword, meta: { bare: true, allowMustChange: true } },
  { path: '/setup-totp', name: 'setup-totp', component: TotpRequired, meta: { bare: true, allowTotpSetup: true } },
  { path: '/', name: 'overview', component: Overview },
  { path: '/events', name: 'events', component: Events },
  { path: '/events/:id', name: 'event', component: EventDetail, props: true },
  { path: '/lookup', name: 'lookup', component: IpLookup },
  { path: '/lookup/:ip', name: 'lookup-ip', component: IpLookup, props: true },
  { path: '/rules', name: 'rules', component: Rules },
  { path: '/rules/:id', name: 'rule', component: RuleDetail, props: true },
  { path: '/managed', name: 'managed', component: Managed },
  { path: '/changes', name: 'changes', component: Changes },
  { path: '/changes/new', name: 'change-new', component: ChangeNew, meta: { role: 'operator' } },
  { path: '/changes/:id(\\d+)', name: 'change', component: ChangeDetail, props: true },
  { path: '/versions', name: 'versions', component: Versions },
  { path: '/vhosts', name: 'vhosts', component: Vhosts },
  { path: '/crs', name: 'crs', component: Crs },
  { path: '/waf', name: 'waf', component: WafModel },
  { path: '/account', name: 'account', component: Account },
  { path: '/guide', name: 'guide', component: Guide },
  { path: '/admin/users', name: 'admin-users', component: AdminUsers, meta: { role: 'admin' } },
  { path: '/admin/users/review', name: 'users-review', component: UsersReview, meta: { role: 'admin' } },
  { path: '/admin/system', name: 'admin-system', component: SystemCheck, meta: { role: 'admin' } },
  { path: '/admin/compliance', name: 'admin-compliance', component: Compliance, meta: { role: 'admin' } },
  { path: '/analysis', name: 'analysis', component: Analysis },
  { path: '/analysis/:id(\\d+)', name: 'analysis-run', component: Analysis, props: true },
  { path: '/config-changes', name: 'config-changes', component: ConfigChanges, meta: { role: 'approver' } },
  { path: '/config-changes/:id(\\d+)', name: 'config-change', component: ConfigChanges, props: true, meta: { role: 'approver' } },
  { path: '/admin/tokens', name: 'admin-tokens', component: AdminTokens, meta: { role: 'admin' } },
  { path: '/admin/audit', name: 'admin-audit', component: AdminAudit, meta: { role: 'admin' } },
  { path: '/admin/settings', name: 'admin-settings', component: AdminSettings, meta: { role: 'admin' } },
  { path: '/admin/notify', name: 'admin-notify', component: Notifications, meta: { role: 'admin' } },
  { path: '/alerts', name: 'alerts', component: Alerts },
  { path: '/traffic', name: 'traffic', component: Traffic },
  { path: '/:pathMatch(.*)*', name: 'not-found', component: NotFound },
]

export const router = createRouter({
  history: createWebHistory('/'),
  routes,
  scrollBehavior(to, from, saved) {
    if (saved) return saved
    if (to.path === from.path) return false
    return { top: 0 }
  },
})

router.beforeEach((to) => {
  if (to.meta.public) {
    if (state.user && to.name === 'login') return { name: 'overview' }
    return true
  }
  if (!state.user) {
    return { name: 'login', query: to.fullPath !== '/' ? { next: to.fullPath } : {} }
  }
  if (state.user.must_change_password) {
    return to.meta.allowMustChange ? true : { name: 'change-password' }
  }
  if (to.meta.allowMustChange) return { name: 'overview' }
  if (state.user.totp_setup_required) {
    return to.meta.allowTotpSetup ? true : { name: 'setup-totp' }
  }
  if (to.meta.allowTotpSetup) return { name: 'overview' }
  if (to.meta.role && !hasRole(to.meta.role)) return { name: 'overview' }
  return true
})

router.afterEach((to, from) => {
  refreshPending(false)
  refreshAlerts(false)
  // the last sign-in notice stays for the landing page and one more navigation
  if (state.lastLogin && to.fullPath !== from.fullPath && !to.meta.bare) {
    state.lastLogin.navs = (state.lastLogin.navs || 0) + 1
    if (state.lastLogin.navs > 2) state.lastLogin = null
  }
})

// Only accept same-app relative paths as a post-login target (no open redirect).
export function safeNext(v) {
  if (typeof v !== 'string') return '/'
  if (!v.startsWith('/') || v.startsWith('//') || v.startsWith('/\\')) return '/'
  return v
}
