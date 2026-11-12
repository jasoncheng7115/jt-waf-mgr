<!-- A unified diff of rules files: added / removed lines coloured as before, and the rule text inside
     each hunk coloured like RuleText. Each hunk's old and new side is scanned as a whole so that
     continued lines keep their meaning; a hunk that starts inside a rule shows that rule's first
     lines plain until the next rule starts. -->
<template>
  <pre class="code diff"><span v-for="(l, i) in lines" :key="i" class="dl" :class="l.cls"><template v-if="l.pieces">{{ l.mark }}<RulePieces :pieces="l.pieces" /></template><template v-else>{{ l.text || ' ' }}</template></span></pre>
</template>

<script setup>
import { computed } from 'vue'
import { diffLines, safeText } from '../util.js'
import RulePieces from './RulePieces.vue'
import { tokenizeLines } from './ruleTokens.js'

const props = defineProps({ text: { type: String, default: '' } })

const HUNK = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/

const lines = computed(() => {
  const raw = String(props.text || '').split('\n')
  const out = diffLines(props.text)
  let k = 0
  while (k < raw.length) {
    const h = HUNK.exec(raw[k])
    if (!h) { k++; continue }
    let oldLeft = h[1] === undefined ? 1 : Number(h[1])
    let newLeft = h[2] === undefined ? 1 : Number(h[2])
    const oldL = []
    const newL = []
    const at = []                       // [line index, side, index on that side]
    let j = k + 1
    while (j < raw.length && (oldLeft > 0 || newLeft > 0)) {
      const l = raw[j]
      const c = l[0]
      if (c === '\\') { j++; continue }  // "\ No newline at end of file"
      const body = l.slice(1)
      if (c === '-' && oldLeft > 0) { at.push([j, 'old', oldL.length]); oldL.push(body); oldLeft-- }
      else if (c === '+' && newLeft > 0) { at.push([j, 'new', newL.length]); newL.push(body); newLeft-- }
      else if ((c === ' ' || c === undefined) && oldLeft > 0 && newLeft > 0) {
        at.push([j, 'new', newL.length]); oldL.push(body); newL.push(body); oldLeft--; newLeft--
      } else break                      // not what the header promised: leave the rest as it was
      j++
    }
    const tok = { old: tokenizeLines(oldL.join('\n')), new: tokenizeLines(newL.join('\n')) }
    for (const [li, side, n] of at) {
      const c = raw[li][0]
      out[li] = { cls: c === '+' ? 'dadd' : c === '-' ? 'ddel' : '', mark: safeText(c || ' '), pieces: tok[side][n] }
    }
    k = j
  }
  return out
})
</script>
