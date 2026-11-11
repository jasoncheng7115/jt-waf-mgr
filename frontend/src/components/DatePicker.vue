<!-- The site's own date / date-time picker (never the browser's). Drop-in for <input type="date"> and
     <input type="datetime-local" step="1">: v-model is the same string ("YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SS",
     local time, "" when empty), so existing conversions keep working.
     Keyboard in the calendar: arrows move a day / week, PageUp / PageDown a month, Home / End the week,
     Enter picks, Escape closes. -->
<template>
  <div class="datepicker" :class="{ open, small }">
    <button ref="btn" type="button" class="dp-btn" :id="id" :disabled="disabled" :aria-label="ariaLabel || null"
            aria-haspopup="dialog" :aria-expanded="open ? 'true' : 'false'" @click.prevent.stop="toggle" @keydown.down.prevent="show">
      <Icon name="calendar" />
      <span class="dp-value" :class="{ placeholder: !modelValue }">{{ modelValue ? display : (placeholder || t('date.choose')) }}</span>
    </button>
    <button v-if="clearable && modelValue && !disabled" type="button" class="dp-clear" :title="t('date.clear')" :aria-label="t('date.clear')" @click="emitValue('')"><Icon name="close" /></button>
    <div v-if="open" ref="pop" class="dp-pop" role="dialog" :aria-label="ariaLabel || t('date.choose')" :style="popStyle" @keydown.esc.stop.prevent="hide(true)" @click.stop>
      <div v-if="presets.length" class="dp-presets">
        <button v-for="p in presets" :key="p.key" type="button" class="btn small ghost" @click="pickPreset(p)"><Icon name="timer" />{{ p.label }}</button>
      </div>
      <div class="dp-head">
        <button type="button" class="btn small ghost" :aria-label="t('date.prev_month')" :title="t('date.prev_month')" @click="shiftMonth(-1)"><Icon name="prev" /></button>
        <span class="dp-month" aria-live="polite">{{ monthLabel }}</span>
        <button type="button" class="btn small ghost" :aria-label="t('date.next_month')" :title="t('date.next_month')" @click="shiftMonth(1)"><Icon name="next" /></button>
      </div>
      <table class="dp-grid" role="grid" @keydown="onGridKey">
        <thead><tr><th v-for="w in weekdays" :key="w" scope="col">{{ w }}</th></tr></thead>
        <tbody>
          <tr v-for="(week, wi) in weeks" :key="wi">
            <td v-for="d in week" :key="d.key" role="gridcell" :aria-selected="d.selected ? 'true' : 'false'">
              <button type="button" class="dp-day" :class="{ other: !d.inMonth, today: d.today, selected: d.selected, focus: d.key === focusKey }"
                      :disabled="d.disabled" :tabindex="d.key === focusKey ? 0 : -1" :data-key="d.key" :aria-label="d.long" @click="pickDay(d)">{{ d.day }}</button>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="mode === 'datetime'" class="dp-time">
        <Icon name="timer" />
        <label class="sr-only" :for="listId + '-h'">{{ t('date.hour') }}</label>
        <input :id="listId + '-h'" v-model="hh" class="dp-tin" inputmode="numeric" maxlength="2" @change="applyTime" />:
        <label class="sr-only" :for="listId + '-m'">{{ t('date.minute') }}</label>
        <input :id="listId + '-m'" v-model="mi" class="dp-tin" inputmode="numeric" maxlength="2" @change="applyTime" />:
        <label class="sr-only" :for="listId + '-s'">{{ t('date.second') }}</label>
        <input :id="listId + '-s'" v-model="ss" class="dp-tin" inputmode="numeric" maxlength="2" @change="applyTime" />
      </div>
      <div class="dp-foot">
        <button type="button" class="btn small ghost" @click="pickToday"><Icon name="calendar" />{{ mode === 'datetime' ? t('date.now') : t('date.today') }}</button>
        <button v-if="clearable" type="button" class="btn small ghost" @click="emitValue(''); hide(true)"><Icon name="clear" />{{ t('date.clear') }}</button>
        <button type="button" class="btn small primary" @click="hide(true)"><Icon name="check" />{{ t('date.done') }}</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, ref } from 'vue'
import { t, lang } from '../i18n.js'
import Icon from './Icon.vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  mode: { type: String, default: 'date' },              // 'date' | 'datetime'
  min: { type: String, default: '' },                   // "YYYY-MM-DD"
  max: { type: String, default: '' },
  presets: { type: Array, default: () => [] },          // [{ key, label, value: () => "YYYY-MM-DD[THH:MM:SS]" }]
  id: { type: String, default: null },
  ariaLabel: { type: String, default: '' },
  placeholder: { type: String, default: '' },
  clearable: { type: Boolean, default: true },
  disabled: Boolean,
  small: Boolean,
})
const emit = defineEmits(['update:modelValue', 'change'])

const listId = 'dp-' + Math.random().toString(36).slice(2, 8)
const btn = ref(null), pop = ref(null)
const open = ref(false)
const popStyle = ref({})
const view = ref(new Date())          // first day of the month on screen
const focusKey = ref('')
const hh = ref('00'), mi = ref('00'), ss = ref('00')

const p2 = (n) => String(n).padStart(2, '0')
const keyOf = (d) => d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate())
function parse(v) {
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2}))?)?$/.exec(v || '')
  if (!m) return null
  return new Date(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0))
}
const selected = computed(() => parse(props.modelValue))
const display = computed(() => {
  const d = selected.value
  if (!d) return props.modelValue
  const opt = props.mode === 'datetime'
    ? { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }
    : { year: 'numeric', month: '2-digit', day: '2-digit', weekday: 'short' }
  return new Intl.DateTimeFormat(lang.value, opt).format(d)
})
const monthLabel = computed(() => new Intl.DateTimeFormat(lang.value, { year: 'numeric', month: 'long' }).format(view.value))
const firstDow = computed(() => (lang.value === 'en' ? 0 : 1))   // Sunday first in English, Monday otherwise
const weekdays = computed(() => {
  const f = new Intl.DateTimeFormat(lang.value, { weekday: 'narrow' })
  return Array.from({ length: 7 }, (_, i) => f.format(new Date(2024, 0, 7 + ((i + firstDow.value) % 7))))
})
const weeks = computed(() => {
  const y = view.value.getFullYear(), m = view.value.getMonth()
  const start = new Date(y, m, 1)
  start.setDate(1 - ((start.getDay() - firstDow.value + 7) % 7))
  const todayKey = keyOf(new Date())
  const selKey = selected.value ? keyOf(selected.value) : ''
  const long = new Intl.DateTimeFormat(lang.value, { dateStyle: 'full' })
  const out = []
  for (let w = 0; w < 6; w++) {
    const row = []
    for (let i = 0; i < 7; i++) {
      const d = new Date(start); d.setDate(start.getDate() + w * 7 + i)
      const k = keyOf(d)
      row.push({ key: k, day: d.getDate(), date: d, inMonth: d.getMonth() === m, today: k === todayKey, selected: k === selKey,
                 disabled: !!((props.min && k < props.min.slice(0, 10)) || (props.max && k > props.max.slice(0, 10))), long: long.format(d) })
    }
    out.push(row)
  }
  return out
})

function emitValue(v) {
  if (v !== props.modelValue) { emit('update:modelValue', v); emit('change', v) }
}
function compose(d) {
  if (props.mode !== 'datetime') return keyOf(d)
  const h = Math.min(23, Math.max(0, parseInt(hh.value, 10) || 0)), m = Math.min(59, Math.max(0, parseInt(mi.value, 10) || 0))
  const s = Math.min(59, Math.max(0, parseInt(ss.value, 10) || 0))
  hh.value = p2(h); mi.value = p2(m); ss.value = p2(s)
  return keyOf(d) + 'T' + p2(h) + ':' + p2(m) + ':' + p2(s)
}
function pickDay(d) {
  if (d.disabled) return
  emitValue(compose(d.date))
  focusKey.value = d.key
  if (!d.inMonth) view.value = new Date(d.date.getFullYear(), d.date.getMonth(), 1)
  if (props.mode !== 'datetime') hide(true)
}
function applyTime() {
  const base = selected.value || new Date()
  emitValue(compose(base))
}
function pickToday() {
  const now = new Date()
  if (props.mode === 'datetime') { hh.value = p2(now.getHours()); mi.value = p2(now.getMinutes()); ss.value = p2(now.getSeconds()) }
  emitValue(compose(now))
  view.value = new Date(now.getFullYear(), now.getMonth(), 1)
  focusKey.value = keyOf(now)
  if (props.mode !== 'datetime') hide(true)
}
function pickPreset(p) {
  const v = p.value()
  emitValue(v)
  const d = parse(v)
  if (d) { hh.value = p2(d.getHours()); mi.value = p2(d.getMinutes()); ss.value = p2(d.getSeconds()) }
  hide(true)
}
function shiftMonth(n) { view.value = new Date(view.value.getFullYear(), view.value.getMonth() + n, 1) }

function place() {
  if (!btn.value) return
  const r = btn.value.getBoundingClientRect()
  const h = pop.value ? pop.value.offsetHeight : (props.mode === 'datetime' ? 470 : 380)
  const vh = window.innerHeight
  let top = r.bottom + 4
  if (top + h > vh - 8) top = r.top - 4 - h >= 8 ? r.top - 4 - h : Math.max(8, vh - h - 8)   // flip up, else fit
  popStyle.value = { position: 'fixed', left: Math.max(8, Math.min(r.left, window.innerWidth - 300)) + 'px', top: top + 'px',
    maxHeight: (vh - 16) + 'px', overflowY: 'auto' }
}
async function show() {
  if (props.disabled || open.value) return
  const d = selected.value || new Date()
  view.value = new Date(d.getFullYear(), d.getMonth(), 1)
  focusKey.value = keyOf(d)
  hh.value = p2(selected.value ? d.getHours() : 0); mi.value = p2(selected.value ? d.getMinutes() : 0); ss.value = p2(selected.value ? d.getSeconds() : 0)
  open.value = true
  place()
  await nextTick()
  place()                                   // again with the real height
  pop.value?.querySelector('.dp-day.focus')?.focus({ preventScroll: true })
  document.addEventListener('mousedown', outside, true)
  window.addEventListener('resize', closeQuiet)
  window.addEventListener('scroll', onScroll, true)
}
function hide(refocus) {
  if (!open.value) return
  open.value = false
  document.removeEventListener('mousedown', outside, true)
  window.removeEventListener('resize', closeQuiet)
  window.removeEventListener('scroll', onScroll, true)
  if (refocus === true) btn.value?.focus()
}
function closeQuiet() { hide() }
function toggle() { open.value ? hide(true) : show() }
function outside(e) { if (!btn.value?.contains(e.target) && !pop.value?.contains(e.target)) hide() }
function onScroll(e) { if (!pop.value?.contains(e.target)) place() }   // stay with the field

async function moveFocus(days, months) {
  const cur = parse(focusKey.value) || new Date()
  const d = months ? new Date(cur.getFullYear(), cur.getMonth() + months, Math.min(cur.getDate(), 28)) : new Date(cur.getFullYear(), cur.getMonth(), cur.getDate() + days)
  focusKey.value = keyOf(d)
  if (d.getMonth() !== view.value.getMonth() || d.getFullYear() !== view.value.getFullYear()) view.value = new Date(d.getFullYear(), d.getMonth(), 1)
  await nextTick()
  pop.value?.querySelector('.dp-day.focus')?.focus({ preventScroll: true })
}
function onGridKey(e) {
  const map = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [-7, 0], ArrowDown: [7, 0], PageUp: [0, -1], PageDown: [0, 1] }
  if (map[e.key]) { e.preventDefault(); moveFocus(...map[e.key]) }
  else if (e.key === 'Home' || e.key === 'End') {
    e.preventDefault()
    const cur = parse(focusKey.value) || new Date()
    const dow = (cur.getDay() - firstDow.value + 7) % 7
    moveFocus(e.key === 'Home' ? -dow : 6 - dow, 0)
  }
}
onBeforeUnmount(() => hide())
</script>
