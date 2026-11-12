// Shared app state: server meta, logged-in user, CSRF token.
import { reactive } from 'vue'
import { get } from './api.js'

export const state = reactive({
  meta: { name: 'jt-waf-mgr', version: '', source_url: '', sso_enabled: false, node_id: '', login_notice: '', password_policy: null },
  // previous_login from the sign-in response: shown once, cleared on dismiss or after two navigations
  lastLogin: null,
  user: null,
  csrf: '',
  ready: false,
})

export const ROLES = ['viewer', 'operator', 'approver', 'admin']

export function hasRole(min) {
  if (!state.user) return false
  return ROLES.indexOf(state.user.role) >= ROLES.indexOf(min)
}

export function setSession(data) {
  state.user = data && data.user ? data.user : null
  state.csrf = (data && data.csrf_token) || ''
}

export function clearSession() {
  state.user = null
  state.csrf = ''
  state.lastLogin = null
}

// Number of changes waiting for approval (nav badge). Refreshed on navigation, at most every 15 s,
// and by a 60 s timer; views that change a change's state call refreshPending(true).

export const pending = reactive({ count: 0, at: 0, adopted: null })

export async function refreshPending(force) {
  if (!state.user || state.user.must_change_password || state.user.totp_setup_required) return
  const now = Date.now()
  if (!force && now - pending.at < 15000) return
  pending.at = now
  try {
    const r = await get('/changes', { state: 'pending_approval', limit: 100 })
    pending.count = (r.items || []).length
  } catch { /* keep the last value */ }
}

// Open alerts (nav badge): same rhythm as the pending changes.
export const alertCount = reactive({ open: 0, critical: 0, at: 0 })

export async function refreshAlerts(force) {
  if (!state.user || state.user.must_change_password || state.user.totp_setup_required) return
  const now = Date.now()
  if (!force && now - alertCount.at < 15000) return
  alertCount.at = now
  try {
    const r = await get('/alerts/counts')
    alertCount.open = r.open || 0
    alertCount.critical = r.critical || 0
  } catch { /* keep the last value */ }
}
