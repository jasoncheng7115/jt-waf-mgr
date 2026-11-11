// Minimal i18n: flat JSON dictionaries, {name} interpolation, English fallback.
// No runtime message compiler (keeps the strict CSP: no eval / new Function).
import { ref } from 'vue'
import en from './i18n/en.json'
import zhTW from './i18n/zh-TW.json'
import ja from './i18n/ja.json'

const DICTS = { en, 'zh-TW': zhTW, ja }
export const LANGUAGES = [
  { code: 'en', label: 'English' },
  { code: 'zh-TW', label: '繁體中文' },
  { code: 'ja', label: '日本語' },
]
const STORAGE_KEY = 'jtwaf.lang'

function initial() {
  try {
    const v = window.localStorage.getItem(STORAGE_KEY)
    if (v && DICTS[v]) return v
  } catch { /* storage unavailable */ }
  const nav = (navigator.language || '').toLowerCase()
  if (nav.startsWith('zh')) return 'zh-TW'
  if (nav.startsWith('ja')) return 'ja'
  return 'en'
}

export const lang = ref(initial())

export function setLang(code) {
  if (!DICTS[code]) return
  lang.value = code
  document.documentElement.lang = code
  try { window.localStorage.setItem(STORAGE_KEY, code) } catch { /* ignore */ }
}
document.documentElement.lang = lang.value

export function t(key, params) {
  const d = DICTS[lang.value] || en
  let s = d[key]
  if (s === undefined) s = en[key]
  if (s === undefined) return key
  if (params) {
    s = s.replace(/\{(\w+)\}/g, (m, k) => (params[k] === undefined || params[k] === null ? m : String(params[k])))
  }
  return s
}

// Translate with a fallback text when the key is not in the dictionary (e.g. server error codes).
export function tOr(key, fallback, params) {
  const r = t(key, params)
  return r === key ? (fallback || key) : r
}

export function errText(e) {
  if (!e) return ''
  const code = e.code || 'unknown'
  const params = Object.assign({}, e.details || {})
  return tOr('error.' + code, e.message || code, params)
}
