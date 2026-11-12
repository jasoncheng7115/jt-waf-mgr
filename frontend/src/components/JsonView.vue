<!-- A JSON value, pretty-printed with syntax colours (keys, strings, numbers, true / false, null). Every piece is
     rendered as text (no v-html): the values may come from requests. -->
<template>
  <pre class="code jsonview"><template v-for="(p, i) in pieces" :key="i"><span v-if="p.c" :class="'j-' + p.c">{{ p.s }}</span><template v-else>{{ p.s }}</template></template></pre>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ value: { type: [Object, Array, String, Number, Boolean], default: null }, max: { type: Number, default: 200000 } })
// strings (a key when a colon follows), numbers, literals, punctuation
const TOKEN = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false)\b|\b(null)\b|([{}[\],])/g
const pieces = computed(() => {
  let text
  try { text = JSON.stringify(props.value, null, 2) ?? 'null' } catch { text = String(props.value) }
  if (text.length > props.max) text = text.slice(0, props.max) + '\n…'
  const out = []
  let last = 0
  for (const m of text.matchAll(TOKEN)) {
    if (m.index > last) out.push({ s: text.slice(last, m.index) })
    if (m[1]) {
      out.push({ s: m[1], c: m[2] ? 'key' : 'str' })
      if (m[2]) out.push({ s: m[2], c: 'punct' })
    } else if (m[3]) out.push({ s: m[3], c: 'num' })
    else if (m[4]) out.push({ s: m[4], c: 'bool' })
    else if (m[5]) out.push({ s: m[5], c: 'null' })
    else out.push({ s: m[6], c: 'punct' })
    last = m.index + m[0].length
  }
  if (last < text.length) out.push({ s: text.slice(last) })
  return out
})
</script>

<style scoped>
.jsonview { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; max-height: 60vh; overflow: auto; }
.j-key { color: var(--series-1); font-weight: 600; }
.j-str { color: var(--ok); }
.j-num { color: var(--score, var(--warn)); }
.j-bool { color: var(--blocked); font-weight: 600; }
.j-null { color: var(--muted); font-style: italic; }
.j-punct { color: var(--muted); }
</style>
