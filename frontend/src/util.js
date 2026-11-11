// Helpers for showing attacker-controlled text safely (always as text, never HTML).
import { lang } from './i18n.js'

// Control, bidi and zero-width characters become visible escapes so they cannot
// hide, reorder or spoof what the operator reads.
// Built from a string with escaped code points: a literal U+2028 in the bundle would end the line.
const INVISIBLE = new RegExp('[' + [
  '\\u0000-\\u001f', '\\u007f-\\u009f', '\\u00ad', '\\u200b-\\u200f', '\\u2028', '\\u2029',
  '\\u202a-\\u202e', '\\u2060-\\u2064', '\\u2066-\\u2069', '\\ufeff', '\\ufff9-\\ufffb',
].join('') + ']', 'g')

export function safeText(v, max) {
  if (v === null || v === undefined) return ''
  let s = String(v)
  s = s.replace(INVISIBLE, (c) => {
    if (c === '\n') return '↵'
    if (c === '\t') return '⇥'
    return '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')
  })
  if (max && s.length > max) s = s.slice(0, max) + '…'
  return s
}

// Same, but keeps real newlines (for <pre> blocks such as rule text).
export function safeMultiline(v) {
  if (v === null || v === undefined) return ''
  return String(v).split('\n').map((l) => safeText(l)).join('\n')
}

function locale() {
  return lang.value === 'zh-TW' ? 'zh-TW' : lang.value === 'ja' ? 'ja-JP' : 'en-GB'
}

// Unambiguous in every language: 2026-11-10 22:45:07 (browser local time).
const p2 = (n) => String(n).padStart(2, '0')
export function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return safeText(iso)
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`
}

// 2026-11-10 22:45 (browser local time).
export function fmtMinute(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return safeText(iso)
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`
}

export function fmtDate(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return safeText(iso)
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}`
}

// <input type="date"> value (local) -> ISO end of that day in local time; '' -> null.
export function dateInputToIso(v) {
  if (!v) return null
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v)
  if (!m) return null
  return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59).toISOString()
}

// ISO -> <input type="date"> value (local).
export function isoToDateInput(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return ''
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}`
}

export function fmtShortTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return safeText(iso)
  return `${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`
}

export function fmtNum(n) {
  if (n === null || n === undefined) return '—'
  return Number(n).toLocaleString(locale())
}

export function fmtBytes(n) {
  if (n === null || n === undefined) return '—'
  const u = ['B', 'KB', 'MB', 'GB']
  let i = 0; let v = Number(n)
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return (i ? v.toFixed(1) : v) + ' ' + u[i]
}

export function pathWithQuery(e) {
  if (!e) return ''
  return e.query ? e.path + '?' + e.query : e.path
}

export function groupBy4(s) {
  return String(s || '').replace(/(.{4})/g, '$1 ').trim()
}

// --- P2 helpers -----------------------------------------------------------------------------

// A regular expression matching exactly this text (PCRE / JS compatible escaping).
export function escapeRegex(s) {
  return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, (c) => '\\' + c)
}

const VAR_RE = /\b(ARGS(?:_GET|_POST)?(?:_NAMES)?|REQUEST_COOKIES(?:_NAMES)?|REQUEST_HEADERS(?:_NAMES)?|REQUEST_FILENAME|REQUEST_BASENAME|REQUEST_URI(?:_RAW)?|REQUEST_BODY|QUERY_STRING|XML|FILES(?:_NAMES)?)(:[^\s:'"`,)\]]+)?/g

// Variable names (ARGS:q, REQUEST_HEADERS:User-Agent ...) mentioned in a match's data / match text.
export function targetsOf(matches) {
  const out = []
  for (const m of matches || []) {
    for (const s of [m.data, m.match]) {
      if (!s) continue
      for (const x of String(s).matchAll(VAR_RE)) {
        const v = x[1] + (x[2] || '')
        if (!out.includes(v) && v.length <= 140) out.push(v)
      }
    }
  }
  return out
}

export const SCORING_RULES = [949110, 959100, 980170, 980130, 980140, 980145, 949111, 959101, 980099]

// One <span> per diff line, classed by its first character.
export function diffLines(text) {
  return String(text || '').split('\n').map((l) => ({
    text: safeText(l),
    cls: l.startsWith('+++') || l.startsWith('---') ? 'dh' : l.startsWith('@@') ? 'dhunk' : l.startsWith('+') ? 'dadd' : l.startsWith('-') ? 'ddel' : '',
  }))
}

// --- compliance helpers -------------------------------------------------------------------------

// First n characters of a hash (full value goes in a title / copy control).
export function shortHash(h, n = 10) {
  return h ? String(h).slice(0, n) : '—'
}

// One CSV field: always quoted, quotes doubled, and a leading = + - @ (or tab / CR) neutralised
// with an apostrophe so a spreadsheet does not run it as a formula (CSV injection).
export function csvField(v) {
  let s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join(' ') : typeof v === 'object' ? JSON.stringify(v) : String(v)
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s
  return '"' + s.replace(/"/g, '""') + '"'
}

export function toCsv(header, rows) {
  return [header, ...rows].map((r) => r.map(csvField).join(',')).join('\r\n') + '\r\n'
}

// Save text as a file, built in the browser. bom: prefix UTF-8 BOM (Excel opens CSV correctly).
export function downloadText(name, text, type, bom) {
  const blob = new Blob([bom ? '﻿' : '', text], { type: type || 'text/plain;charset=utf-8' })
  saveBlob(name, blob)
}

export function saveBlob(name, blob) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 2000)
}

export function stamp() {
  const d = new Date()
  return `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}-${p2(d.getHours())}${p2(d.getMinutes())}`
}

// ISO 3166 country code -> name in the reader's language (Intl), the code itself when unknown.
export function countryName(code, lang) {
  if (!/^[A-Z]{2}$/.test(code || '')) return code || ''
  try { return new Intl.DisplayNames([lang], { type: 'region' }).of(code) || code } catch { return code }
}
