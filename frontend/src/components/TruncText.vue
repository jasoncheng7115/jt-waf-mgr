<!-- One-line text that may come from an attacker: escaped invisibles, CSS-truncated ("..."), full value in title.
     width: a maximum width (a table column otherwise grows to fit the text). expand: a click shows the whole text
     (wrapped) and a second click folds it again; only when the text is cut, so a click on a short text does nothing. -->
<template>
  <span ref="el" class="trunc" :class="{ mono, open, expandable: expand && (cut || open) }" :style="width ? { maxWidth: width } : null"
        :title="open ? null : full" :tabindex="expand && (cut || open) ? 0 : null" :role="expand && (cut || open) ? 'button' : null"
        :aria-expanded="expand && (cut || open) ? (open ? 'true' : 'false') : null"
        @click="toggle" @keydown.enter.prevent="toggle" @mouseenter="measure">{{ open ? full : shown }}</span>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { safeText } from '../util.js'

const props = defineProps({
  text: { default: '' },
  max: { type: Number, default: 400 },
  mono: { type: Boolean, default: false },
  width: { type: String, default: '' },
  expand: { type: Boolean, default: false },
})
const full = computed(() => safeText(props.text, 2000))
const shown = computed(() => safeText(props.text, props.max))
const el = ref(null)
const open = ref(false)
const cut = ref(false)
function measure() { if (el.value && !open.value) cut.value = el.value.scrollWidth > el.value.clientWidth + 1 || shown.value !== full.value }
function toggle(e) {
  if (!props.expand) return
  measure()
  if (!cut.value && !open.value) return
  e.stopPropagation()
  open.value = !open.value
}
onMounted(measure)
</script>
