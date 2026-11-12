// Every card with a title band (`.card > h2:first-child` or `.card > .cardhead:first-child`) can be folded: a button
// at the right end of the band, or a click on the band itself (not on its own buttons / links). What is folded is
// remembered per page and card in this browser. One observer for the whole application, so every page (and every
// card added later) gets it without changes to the views.
import { t } from './i18n.js'

const STORE = 'jtwaf.fold'
const SEL = '.card > h2:first-child, .card > .cardhead:first-child'
const SVGNS = 'http://www.w3.org/2000/svg'

function load() {
  try { return JSON.parse(window.localStorage.getItem(STORE) || '{}') || {} } catch { return {} }
}
function save(m) {
  try { window.localStorage.setItem(STORE, JSON.stringify(m)) } catch { /* private window: not remembered */ }
}
// the card's id, else its title without numbers (counts change; cards that load late must not shift the keys)
function keyOf(card) {
  const h = card.querySelector(':scope > .foldable h2') || card.querySelector(':scope > .foldable')
  const title = h ? h.textContent.replace(/[\d,.\s]+/g, ' ').trim().slice(0, 80) : ''
  return window.location.pathname + '#' + (card.id || title)
}
function chevron() {
  const s = document.createElementNS(SVGNS, 'svg')
  s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('width', '18'); s.setAttribute('height', '18')
  s.setAttribute('aria-hidden', 'true'); s.setAttribute('class', 'icon')
  const p = document.createElementNS(SVGNS, 'path')
  p.setAttribute('d', 'M6 9l6 6 6-6'); p.setAttribute('fill', 'none'); p.setAttribute('stroke', 'currentColor')
  p.setAttribute('stroke-width', '1.8'); p.setAttribute('stroke-linecap', 'round'); p.setAttribute('stroke-linejoin', 'round')
  s.appendChild(p)
  return s
}
function setFolded(card, folded, remember) {
  card.classList.toggle('folded', folded)
  const b = card.querySelector(':scope > .foldable > .cardfold')
  if (b) {
    b.setAttribute('aria-expanded', folded ? 'false' : 'true')
    const label = folded ? t('card.expand') : t('card.collapse')
    b.setAttribute('aria-label', label); b.title = label
  }
  if (remember) {
    const m = load()
    const k = keyOf(card)
    if (folded) m[k] = 1; else delete m[k]
    save(m)
  }
}
function enhance(head) {
  if (head.classList.contains('foldable')) return
  const card = head.parentElement
  head.classList.add('foldable')
  const b = document.createElement('button')
  b.type = 'button'
  b.className = 'cardfold'
  b.appendChild(chevron())
  b.addEventListener('click', (e) => { e.stopPropagation(); setFolded(card, !card.classList.contains('folded'), true) })
  head.appendChild(b)
  head.addEventListener('click', (e) => {
    if (e.target.closest('button, a, input, select, textarea, label, [role="button"], .datepicker, .selectbox')) return
    if (window.getSelection && String(window.getSelection()).length) return     // selecting the title text
    setFolded(card, !card.classList.contains('folded'), true)
  })
  setFolded(card, !!load()[keyOf(card)], false)
}
let raf = 0
function scan() {
  raf = 0
  for (const h of document.querySelectorAll(SEL)) enhance(h)
}
export function startCardFold() {
  scan()
  new MutationObserver(() => { if (!raf) raf = requestAnimationFrame(scan) }).observe(document.body, { childList: true, subtree: true })
}
// opened through a link to this card (#id): show it
export function unfold(el) {
  const card = el && (el.classList.contains('card') ? el : el.closest('.card'))
  if (card && card.classList.contains('folded')) setFolded(card, false, true)
}
// the language changed: the button labels follow
export function relabelCardFold() {
  for (const c of document.querySelectorAll('.card')) {
    if (c.querySelector(':scope > .foldable > .cardfold')) setFolded(c, c.classList.contains('folded'), false)
  }
}
