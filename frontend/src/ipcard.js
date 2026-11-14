// The card shown when the pointer rests on an address anywhere on the site (any element with data-ip): where it is,
// its PTR name (looked up by the DNS job; asked for if not known yet), whether it is blocked, and what it did in the
// last 7 days. Built from text nodes only (the values come from requests an outsider made), in the site's style.
import { get } from './api.js'
import { t } from './i18n.js'
import { fmtMinute, fmtNum } from './util.js'

const DELAY = 150
const KEEP = 60 * 1000                 // a card's data is reused for a minute
const cache = new Map()
let card = null
let cur = null
let timer = null

function box() {
  if (card) return card
  card = document.createElement('div')
  card.id = 'jt-ipcard'
  card.className = 'jt-ipcard'
  card.setAttribute('role', 'dialog')
  card.hidden = true
  card.addEventListener('pointerleave', () => hide())
  document.body.appendChild(card)
  return card
}

function el(tag, cls, text) {
  const e = document.createElement(tag)
  if (cls) e.className = cls
  if (text !== undefined && text !== null) e.textContent = String(text)
  return e
}

function row(label, value, cls) {
  const r = el('div', 'ic-row')
  r.appendChild(el('span', 'ic-k', label))
  const v = el('span', 'ic-v' + (cls ? ' ' + cls : ''))
  if (value instanceof Node) v.appendChild(value)
  else v.textContent = value
  r.appendChild(v)
  return r
}

function render(d) {
  const c = box()
  c.textContent = ''
  const head = el('div', 'ic-head')
  head.appendChild(el('span', 'ic-ip', d.ip))
  head.appendChild(el('span', 'badge ' + (d.origin === 'internal' ? 'b-int' : 'b-ext'), d.origin === 'internal' ? t('origin.internal') : t('origin.external')))
  c.appendChild(head)
  if (d.ptr) {
    if (d.ptr.pending) c.appendChild(row(t('ipcard.ptr'), t('ipcard.ptr_pending'), 'muted'))
    else if (d.ptr.name) {
      const v = el('span')
      v.appendChild(el('span', 'mono', d.ptr.name))
      v.appendChild(el('span', 'ic-note ' + (d.ptr.confirmed ? 'ok' : 'warn'), d.ptr.confirmed ? t('ipcard.ptr_confirmed') : t('ipcard.ptr_unconfirmed')))
      c.appendChild(row(t('ipcard.ptr'), v))
    } else c.appendChild(row(t('ipcard.ptr'), d.ptr.error ? t('ipcard.ptr_error') : t('ipcard.ptr_none'), 'muted'))
  }
  const g = d.geo || {}
  if (g.cc || g.country) {
    let where = (g.country || g.cc) + (g.city ? ' · ' + g.city : '')
    try { const n = new Intl.DisplayNames([document.documentElement.lang || 'en'], { type: 'region' }).of(g.cc); if (n) where = n + ' (' + g.cc + ')' + (g.city ? ' · ' + g.city : '') } catch { /* code only */ }
    c.appendChild(row(t('ipcard.where'), where))
  }
  if (g.asn || g.org) c.appendChild(row(t('ipcard.network'), (g.asn ? 'AS' + g.asn + ' ' : '') + (g.org || '')))
  if (d.blocked && d.blocked.length) {
    const b = d.blocked[0]
    c.appendChild(row(t('ipcard.blocked'), b.permanent ? t('blocks.permanent') : t('ipcard.until', { at: fmtMinute(b.until) }), 'bad'))
  }
  c.appendChild(row(t('ipcard.week'), t('ipcard.week_n', { n: fmtNum(d.d7.events), b: fmtNum(d.d7.blocked) })))
  if (d.d7.last) c.appendChild(row(t('ipcard.last'), fmtMinute(d.d7.last)))
  if (d.hosts && d.hosts.length) c.appendChild(row(t('ipcard.sites'), d.hosts.map((h) => h.key + ' ' + fmtNum(h.events)).join(' · ')))
  c.appendChild(el('div', 'ic-foot', t('ipcard.open')))
}

function place(n) {
  const c = box()
  const r = n.getBoundingClientRect()
  c.style.left = '0px'
  c.style.top = '0px'
  const w = c.offsetWidth
  const h = c.offsetHeight
  let top = r.bottom + 6
  if (top + h > window.innerHeight - 6 && r.top - 6 - h > 6) top = r.top - 6 - h
  const left = Math.max(6, Math.min(r.left, window.innerWidth - w - 6))
  c.style.left = Math.round(left + window.scrollX) + 'px'
  c.style.top = Math.round(top + window.scrollY) + 'px'
}

async function show(n, ip) {
  cur = n
  const hit = cache.get(ip)
  let d = hit && Date.now() - hit.at < KEEP ? hit.d : null
  if (!d) {
    render({ ip, origin: '', d7: { events: 0, blocked: 0 } })
    box().lastChild.textContent = t('ipcard.loading')
    box().hidden = false
    place(n)
    try { d = await get('/lookups/ip/' + encodeURIComponent(ip) + '/card') } catch { hide(); return }
    // a PTR still being looked up: kept for a few seconds only, so the next hover shows the name
    cache.set(ip, { d, at: d.ptr && d.ptr.pending ? Date.now() - KEEP + 5000 : Date.now() })
  }
  if (cur !== n) return
  render(d)
  box().hidden = false
  place(n)
}

export function hide() {
  clearTimeout(timer)
  if (card) card.hidden = true
  cur = null
}

function target(node) {
  for (let n = node; n && n !== document.body; n = n.parentElement) {
    if (n.nodeType === 1 && n.hasAttribute && n.hasAttribute('data-ip')) return n
  }
  return null
}

export function installIpCards() {
  document.addEventListener('pointerover', (e) => {
    const n = target(e.target)
    if (!n || n === cur) return
    const ip = (n.getAttribute('data-ip') || '').split('/')[0]
    if (!ip) return
    clearTimeout(timer)
    timer = setTimeout(() => { if (n.isConnected) show(n, ip) }, DELAY)
  }, true)
  document.addEventListener('pointerout', (e) => {
    const n = target(e.target)
    if (!n) return
    const to = e.relatedTarget
    if (to && (n.contains(to) || (card && card.contains(to)))) return
    clearTimeout(timer)
    if (n === cur) hide()
  }, true)
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide() }, true)
  window.addEventListener('scroll', hide, true)
}
