<!-- The site's own dropdown (never the browser's <select>): a button plus a listbox popup.
     Keyboard: Enter / Space / ArrowDown open; arrows move; Home / End; type to jump; Enter picks; Escape closes.
     options: [{ value, label, icon?, hint?, disabled? }] or plain strings. The popup is position: fixed, so
     it is never clipped by a scrolling table. -->
<template>
  <div class="selectbox" :class="[{ open, disabled, small }, $attrs.class]">
    <button ref="btn" type="button" class="sb-btn" :id="id" :disabled="disabled" :aria-label="ariaLabel || null"
            aria-haspopup="listbox" :aria-expanded="open ? 'true' : 'false'" :aria-controls="listId"
            @click.prevent.stop="toggle" @keydown="onBtnKey">
      <Icon v-if="current && current.icon" :name="current.icon" />
      <span class="sb-value" :class="{ placeholder: !current }">{{ current ? current.label : (placeholder || t('select.choose')) }}</span>
      <Icon name="expand" class="sb-caret" />
    </button>
    <div v-if="open" ref="pop" class="sb-pop" :style="popStyle" @keydown="onListKey" @click.prevent.stop>
      <input v-if="searchable" ref="search" v-model="query" class="sb-search" type="search" :placeholder="t('select.search')"
             :aria-label="t('select.search')" @keydown="onListKey" />
      <ul :id="listId" ref="list" role="listbox" tabindex="-1" :aria-activedescendant="activeId">
        <li v-for="(o, i) in shown" :id="listId + '-' + i" :key="String(o.value)" role="option"
            :aria-selected="o.value === modelValue ? 'true' : 'false'" :aria-disabled="o.disabled ? 'true' : null"
            :class="{ active: i === active, selected: o.value === modelValue, disabled: o.disabled }"
            @mousedown.prevent="pick(o)" @mousemove="active = i">
          <Icon :name="o.value === modelValue ? 'check' : (o.icon || 'check')" :class="{ invisible: o.value !== modelValue && !o.icon }" />
          <span class="sb-label">{{ o.label }}</span>
          <span v-if="o.hint" class="sb-hint">{{ o.hint }}</span>
        </li>
        <li v-if="!shown.length" class="sb-empty">{{ t('select.no_options') }}</li>
      </ul>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { t } from '../i18n.js'
import Icon from './Icon.vue'

defineOptions({ inheritAttrs: false })
const props = defineProps({
  modelValue: { default: null },
  options: { type: Array, default: () => [] },
  placeholder: { type: String, default: '' },
  ariaLabel: { type: String, default: '' },
  id: { type: String, default: null },
  disabled: Boolean,
  small: Boolean,
  searchable: { type: Boolean, default: null },   // default: on when there are more than 10 options
})
const emit = defineEmits(['update:modelValue', 'change'])

let seq = 0
const listId = 'sb-' + Math.random().toString(36).slice(2, 8) + (seq++)
const btn = ref(null), pop = ref(null), list = ref(null), search = ref(null)
const open = ref(false)
const active = ref(-1)
const query = ref('')
const popStyle = ref({})

const opts = computed(() => props.options.map((o) => (o !== null && typeof o === 'object' ? o : { value: o, label: String(o) })))
const current = computed(() => opts.value.find((o) => o.value === props.modelValue) || null)
const searchable = computed(() => (props.searchable === null ? opts.value.length > 10 : props.searchable))
const shown = computed(() => {
  const q = query.value.trim().toLowerCase()
  return q ? opts.value.filter((o) => String(o.label).toLowerCase().includes(q) || String(o.value).toLowerCase().includes(q)) : opts.value
})
const activeId = computed(() => (active.value >= 0 ? listId + '-' + active.value : null))

function place() {
  if (!btn.value) return
  const r = btn.value.getBoundingClientRect()
  const below = window.innerHeight - r.bottom
  const up = below < 240 && r.top > below
  popStyle.value = {
    position: 'fixed', left: Math.max(8, Math.min(r.left, window.innerWidth - Math.max(r.width, 180) - 8)) + 'px',
    minWidth: r.width + 'px', maxHeight: Math.max(160, Math.min(320, (up ? r.top : below) - 12)) + 'px',
    ...(up ? { bottom: (window.innerHeight - r.top + 4) + 'px' } : { top: (r.bottom + 4) + 'px' }),
  }
}

async function show() {
  if (props.disabled || open.value) return
  query.value = ''
  open.value = true
  active.value = Math.max(0, shown.value.findIndex((o) => o.value === props.modelValue))
  place()
  await nextTick()
  ;(searchable.value ? search.value : list.value)?.focus({ preventScroll: true })
  scrollActive()
  document.addEventListener('mousedown', outside, true)
  window.addEventListener('resize', hide)
  window.addEventListener('scroll', onScroll, true)
}
function hide(refocus) {
  if (!open.value) return
  open.value = false
  document.removeEventListener('mousedown', outside, true)
  window.removeEventListener('resize', hide)
  window.removeEventListener('scroll', onScroll, true)
  if (refocus === true) btn.value?.focus()
}
function toggle() { open.value ? hide(true) : show() }
function outside(e) {
  if (btn.value?.contains(e.target) || pop.value?.contains(e.target)) return
  hide()
}
function onScroll(e) { if (!pop.value?.contains(e.target)) place() }   // stay with the field
function pick(o) {
  if (!o || o.disabled) return
  if (o.value !== props.modelValue) {
    emit('update:modelValue', o.value)
    emit('change', o.value)
  }
  hide(true)
}
function move(d) {
  const n = shown.value.length
  if (!n) return
  let i = active.value
  for (let k = 0; k < n; k++) {
    i = (i + d + n) % n
    if (!shown.value[i].disabled) break
  }
  active.value = i
  scrollActive()
}
function scrollActive() {
  nextTick(() => {
    const el = list.value?.querySelector('li.active')
    el?.scrollIntoView({ block: 'nearest' })
  })
}
let typed = '', typedAt = 0
function onBtnKey(e) {
  if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) { e.preventDefault(); show() }
}
function onListKey(e) {
  if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); hide(true) }
  else if (e.key === 'Tab') hide()
  else if (e.key === 'ArrowDown') { e.preventDefault(); move(1) }
  else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1) }
  else if (e.key === 'Home') { e.preventDefault(); active.value = -1; move(1) }
  else if (e.key === 'End') { e.preventDefault(); active.value = 0; move(-1) }
  else if (e.key === 'Enter') { e.preventDefault(); pick(shown.value[active.value]) }
  else if (!searchable.value && e.key.length === 1) {
    const now = Date.now()
    typed = (now - typedAt < 700 ? typed : '') + e.key.toLowerCase()
    typedAt = now
    const i = shown.value.findIndex((o) => String(o.label).toLowerCase().startsWith(typed))
    if (i >= 0) { active.value = i; scrollActive() }
  }
}
watch(query, () => { active.value = shown.value.length ? 0 : -1 })
onBeforeUnmount(() => hide())
</script>
