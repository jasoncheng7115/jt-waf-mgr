// Fetch wrapper for /api/v1. Same-origin cookie session; CSRF header on non-GET.
import { state, clearSession } from './store.js'

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message || code || ('HTTP ' + status))
    this.status = status
    this.code = code || 'http_' + status
    this.details = details || {}
  }
}

let onUnauthenticated = null
export function setUnauthenticatedHandler(fn) { onUnauthenticated = fn }
let onSetupRequired = null
export function setSetupRequiredHandler(fn) { onSetupRequired = fn }

function qs(params) {
  if (!params) return ''
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    u.append(k, String(v))
  }
  const s = u.toString()
  return s ? '?' + s : ''
}

export async function api(method, path, { params, body, quiet401 } = {}) {
  const headers = { Accept: 'application/json' }
  const init = { method, headers, credentials: 'same-origin', cache: 'no-store' }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  if (method !== 'GET' && method !== 'HEAD' && state.csrf) headers['X-CSRF-Token'] = state.csrf
  let res
  try {
    res = await fetch('/api/v1' + path + qs(params), init)
  } catch (e) {
    throw new ApiError(0, 'network_error', String(e && e.message || e))
  }
  if (res.status === 204) return null
  let data = null
  const ct = res.headers.get('Content-Type') || ''
  if (ct.includes('application/json')) {
    try { data = await res.json() } catch { data = null }
  }
  if (!res.ok) {
    const err = (data && data.error) || {}
    const e = new ApiError(res.status, err.code, err.message, err.details)
    if (res.status === 401 && e.code === 'not_authenticated' && !quiet401) {
      clearSession()
      if (onUnauthenticated) onUnauthenticated()
    }
    if (res.status === 403 && (e.code === 'password_change_required' || e.code === 'totp_setup_required') && onSetupRequired) {
      onSetupRequired(e.code)
    }
    throw e
  }
  return data
}

export const get = (path, params, opts) => api('GET', path, { params, ...(opts || {}) })
export const post = (path, body) => api('POST', path, { body: body || {} })
export const patch = (path, body) => api('PATCH', path, { body: body || {} })
export const del = (path) => api('DELETE', path)
