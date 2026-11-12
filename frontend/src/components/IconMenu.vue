<!-- One icon button that opens a small menu of choices (theme, language): keeps the top bar short.
     options: [{ value, label, icon? }]; emits change(value). Keyboard: Enter / Space / ArrowDown open,
     arrows move, Enter picks, Escape closes; a click outside closes. -->
<template>
  <div ref="root" class="iconmenu">
    <button ref="btn" type="button" class="btn small ghost im-btn" :title="title" :aria-label="title" aria-haspopup="menu"
            :aria-expanded="open ? 'true' : 'false'" @click="toggle" @keydown.down.prevent="openAt(0)">
      <Icon :name="icon" /><span v-if="text" class="im-text">{{ text }}</span>
    </button>
    <ul v-if="open" class="im-menu" role="menu" :aria-label="title" @keydown="key">
      <li v-for="(o, i) in options" :key="o.value" role="none">
        <button :ref="(el) => (items[i] = el)" type="button" role="menuitemradio" class="im-item" :class="{ on: o.value === modelValue }"
                :aria-checked="o.value === modelValue ? 'true' : 'false'" @click="pick(o)">
          <Icon :name="o.value === modelValue ? 'check' : (o.icon || 'next')" :class="{ 'im-ghost': o.value !== modelValue && !o.icon }" />{{ o.label }}
        </button>
      </li>
    </ul>
  </div>
</template>

<script setup>
import { nextTick, onBeforeUnmount, ref } from 'vue'
import Icon from './Icon.vue'

const props = defineProps({
  options: { type: Array, required: true },
  modelValue: { type: [String, Number], default: null },
  icon: { type: String, required: true },
  title: { type: String, required: true },
  text: { type: String, default: '' },
})
const emit = defineEmits(['change'])
const open = ref(false)
const root = ref(null)
const btn = ref(null)
const items = []

function outside(e) { if (root.value && !root.value.contains(e.target)) close(false) }
async function openAt(i) {
  open.value = true
  document.addEventListener('pointerdown', outside, true)
  await nextTick()
  const cur = props.options.findIndex((o) => o.value === props.modelValue)
  const el = items[i ?? Math.max(0, cur)]
  if (el) el.focus()
}
function close(focus = true) {
  open.value = false
  document.removeEventListener('pointerdown', outside, true)
  if (focus && btn.value) btn.value.focus()
}
function toggle() { if (open.value) close(); else openAt(null) }
function pick(o) { emit('change', o.value); close() }
function key(e) {
  const i = items.indexOf(document.activeElement)
  if (e.key === 'Escape') { e.preventDefault(); close() } else if (e.key === 'ArrowDown') { e.preventDefault(); (items[(i + 1) % items.length] || {}).focus?.() } else if (e.key === 'ArrowUp') { e.preventDefault(); (items[(i - 1 + items.length) % items.length] || {}).focus?.() } else if (e.key === 'Tab') close(false)
}
onBeforeUnmount(() => document.removeEventListener('pointerdown', outside, true))
</script>

<style scoped>
.iconmenu { position: relative; display: inline-block; }
.im-btn { min-width: 34px; justify-content: center; }
.im-text { margin-left: 4px; }
.im-menu { position: absolute; right: 0; top: calc(100% + 6px); z-index: 60; list-style: none; margin: 0; padding: 4px; min-width: 11em;
  background: var(--panel); border: 1px solid var(--border-strong); border-radius: 8px; box-shadow: 0 6px 20px rgba(0, 0, 0, .14); }
.im-item { display: flex; gap: 8px; align-items: center; width: 100%; padding: 6px 10px; border: 0; background: none; color: var(--text);
  border-radius: 5px; cursor: pointer; text-align: left; font: inherit; font-size: 14px; white-space: nowrap; }
.im-item:hover, .im-item:focus-visible { background: var(--panel-2); outline: none; }
.im-item.on { color: var(--accent); font-weight: 600; }
.im-ghost { visibility: hidden; }
</style>
