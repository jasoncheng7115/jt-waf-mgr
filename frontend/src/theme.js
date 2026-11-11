// Light / dark / follow the system. Per browser (localStorage); applied before the app mounts so the
// page never flashes the wrong theme.
import { ref } from 'vue'

export const THEMES = ['auto', 'light', 'dark']
const KEY = 'jtwaf.theme'

function initial() {
  try {
    const v = window.localStorage.getItem(KEY)
    if (THEMES.includes(v)) return v
  } catch { /* storage unavailable */ }
  return 'auto'
}

export const theme = ref(initial())

function apply(v) {
  const el = document.documentElement
  if (v === 'auto') el.removeAttribute('data-theme')
  else el.setAttribute('data-theme', v)
}

export function setTheme(v) {
  if (!THEMES.includes(v)) return
  theme.value = v
  apply(v)
  try { window.localStorage.setItem(KEY, v) } catch { /* ignore */ }
}

apply(theme.value)
