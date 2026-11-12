<!-- ModSecurity rule text with syntax colours, a "formatted" reading view (one action per line,
     chained rules indented) and a copy button. The original view and Copy are exact; the text is
     attacker-influenced, so it is only ever rendered as text pieces (never as HTML). -->
<template>
  <div class="ruletext">
    <div class="rt-bar">
      <div class="seg" role="group" :aria-label="t('ruletext.view')">
        <button type="button" :class="{ on: formatted }" :aria-pressed="formatted" :title="t('ruletext.formatted_hint')" @click="setFormatted(true)"><Icon name="list" />{{ t('ruletext.formatted') }}</button>
        <button type="button" :class="{ on: !formatted }" :aria-pressed="!formatted" :title="t('ruletext.raw_hint')" @click="setFormatted(false)"><Icon name="code" />{{ t('ruletext.raw') }}</button>
      </div>
      <button type="button" class="btn small ghost" :title="t('ruletext.copy_hint')" @click="copy"><Icon :name="copied ? 'check' : 'copy'" />{{ copied ? t('common.copied') : t('common.copy') }}</button>
      <span v-if="copyFailed" class="muted small" role="status">{{ t('ruletext.copy_failed') }}</span>
    </div>
    <pre ref="box" class="code rt" :class="{ nowrap: !wrap, numbered: lineNumbers }"><span v-for="(l, i) in lines" :key="i" class="rl"><span v-if="lineNumbers" class="ln" aria-hidden="true">{{ l.n ?? '' }}</span><span class="lc" :style="hang(l)"><span v-if="l.ind" class="ind">{{ safeText(l.ind) }}</span><RulePieces :pieces="l.pieces" /></span></span></pre>
  </div>
</template>

<script>
import { ref } from 'vue'

// one choice for every rule text on the page, remembered per browser
const KEY = 'jtwaf.ruletext.formatted'
let initial = true
try { initial = localStorage.getItem(KEY) !== '0' } catch { /* storage blocked: default */ }
const formattedPref = ref(initial)
</script>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'
import { safeText } from '../util.js'
import Icon from './Icon.vue'
import RulePieces from './RulePieces.vue'
import { tokenizeLines, formatLines } from './ruleTokens.js'

const props = defineProps({
  text: { type: String, default: '' },
  wrap: { type: Boolean, default: true },
  lineNumbers: { type: Boolean, default: false },
})
const formatted = formattedPref
const box = ref(null)
const copied = ref(false)
const copyFailed = ref(false)

function setFormatted(v) {
  formattedPref.value = v
  try { localStorage.setItem(KEY, v ? '1' : '0') } catch { /* storage blocked */ }
}

// The leading indentation is split off into a span that never wraps, so a long indented line
// does not break right after its indentation.
function splitIndent(l) {
  let ind = ''
  const pieces = l.pieces.slice()
  while (pieces.length) {
    const p = pieces[0]
    const m = /^[ \t]*/.exec(p.text)[0]
    ind += m
    if (m.length < p.text.length) {
      if (m) pieces[0] = { cls: p.cls, text: p.text.slice(m.length) }
      break
    }
    pieces.shift()
  }
  return { n: l.n, ind, pieces }
}

const lines = computed(() => (formatted.value
  ? formatLines(props.text)
  : tokenizeLines(props.text).map((pieces, i) => ({ n: i + 1, pieces }))).map(splitIndent))

// wrapped parts of a long line continue under its text, not at the left edge
function hang(l) {
  if (!props.wrap) return null
  const pad = Math.min(l.ind.length, 24) + 2
  return { paddingLeft: pad + 'ch', textIndent: -pad + 'ch' }
}

async function copy() {
  copyFailed.value = false
  try {
    await navigator.clipboard.writeText(props.text)
    copied.value = true
    setTimeout(() => { copied.value = false }, 1500)
  } catch {
    // clipboard blocked (plain http or permissions): show the original and select it
    setFormatted(false)
    copyFailed.value = true
    setTimeout(() => {
      try {
        const r = document.createRange()
        r.selectNodeContents(box.value)
        const sel = window.getSelection()
        sel.removeAllRanges()
        sel.addRange(r)
      } catch { /* nothing more to do */ }
    }, 0)
  }
}
</script>

<style scoped>
.ruletext { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.rt-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 10px; }
.rt-bar .seg button { display: inline-flex; align-items: center; gap: 4px; padding: 2px 10px; font-size: 13px; }
pre.rt { word-break: normal; overflow-wrap: anywhere; line-height: 1.55; }
pre.rt .rl { display: block; min-height: 1.55em; }
pre.rt .lc { display: block; }
pre.rt .ind { white-space: pre; }
pre.rt.numbered .rl { display: grid; grid-template-columns: 4ch 1fr; gap: 10px; }
pre.rt .ln { color: var(--muted); text-align: right; user-select: none; opacity: .8; }
pre.rt.nowrap { white-space: pre; overflow-wrap: normal; overflow-x: auto; }
pre.rt.nowrap .rl, pre.rt.nowrap .lc { width: max-content; min-width: 100%; }
</style>
