// One tooltip for the whole site, in the site's own style (never the browser's native one).
//
// Any element with a `title` (from any template or component) or a `data-tip` shows it here: when the pointer or
// keyboard focus reaches it, the title text moves to `data-tip` (so the browser has nothing to show) and, for an
// element with no text of its own and no aria-label, becomes its aria-label (the accessible name stays). A title that
// changes later (Vue sets the attribute again) is picked up the next time. Escape, scrolling, a click and leaving the
// element close it. The text is set as text, never as markup.
const DELAY = 250

let tip = null
let cur = null
let timer = null

function el() {
  if (tip) return tip
  tip = document.createElement('div')
  tip.id = 'jt-tip'
  tip.className = 'jt-tip'
  tip.setAttribute('role', 'tooltip')
  tip.hidden = true
  document.body.appendChild(tip)
  return tip
}

// the element that carries a tip, from the event target up (a title on an inner element wins)
function owner(node) {
  for (let n = node; n && n !== document.body; n = n.parentElement) {
    if (n.nodeType !== 1) continue
    if (n.hasAttribute('title') || n.hasAttribute('data-tip')) return n
  }
  return null
}

function take(n) {
  const t = n.getAttribute('title')
  if (t !== null) {
    n.removeAttribute('title')
    if (t.trim()) {
      n.setAttribute('data-tip', t)
      if (!n.getAttribute('aria-label') && !(n.textContent || '').trim()) n.setAttribute('aria-label', t)
    }
  }
  return n.getAttribute('data-tip') || ''
}

function place(n) {
  const t = el()
  const r = n.getBoundingClientRect()
  t.style.left = '0px'
  t.style.top = '0px'
  const w = t.offsetWidth
  const h = t.offsetHeight
  const gap = 8
  let top = r.bottom + gap
  if (top + h > window.innerHeight - 4 && r.top - gap - h > 4) top = r.top - gap - h     // no room below: above
  let left = r.left + r.width / 2 - w / 2
  left = Math.max(6, Math.min(left, window.innerWidth - w - 6))
  t.style.left = Math.round(left + window.scrollX) + 'px'
  t.style.top = Math.round(top + window.scrollY) + 'px'
}

function show(n) {
  const text = take(n)
  if (!text) return
  const t = el()
  t.textContent = text
  t.hidden = false
  cur = n
  n.setAttribute('aria-describedby', 'jt-tip')
  place(n)
}

export function hideTip() {
  clearTimeout(timer)
  if (tip) tip.hidden = true
  if (cur) cur.removeAttribute('aria-describedby')
  cur = null
}

function enter(e) {
  const n = owner(e.target)
  if (!n) return
  take(n)                       // at once, so the native tooltip never starts
  if (n === cur) return
  clearTimeout(timer)
  timer = setTimeout(() => { if (n.isConnected) show(n) }, e.type === 'focusin' ? 0 : DELAY)
}

function leave(e) {
  const n = owner(e.target)
  if (!n) return
  const to = e.relatedTarget
  if (to && n.contains(to)) return
  clearTimeout(timer)
  if (n === cur) hideTip()
}

export function installTooltips() {
  document.addEventListener('pointerover', enter, true)
  document.addEventListener('focusin', enter, true)
  document.addEventListener('pointerout', leave, true)
  document.addEventListener('focusout', leave, true)
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideTip() }, true)
  document.addEventListener('pointerdown', hideTip, true)
  window.addEventListener('scroll', hideTip, true)
  window.addEventListener('resize', hideTip)
}
