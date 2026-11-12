<!-- Coloured pieces of ModSecurity rule text (from ruleTokens.js), always rendered as text.
     Shared by RuleText and DiffView so both use the same palette. -->
<template><span v-for="(p, k) in pieces" :key="k" :class="p.cls ? 'k-' + p.cls : null">{{ safeText(p.text) }}</span></template>

<script setup>
import { safeText } from '../util.js'

defineProps({ pieces: { type: Array, default: () => [] } })
</script>

<style scoped>
/* Built from the theme variables, so light and dark both work. */
.k-comment { color: var(--muted); font-style: italic; }
.k-dir { color: var(--link); font-weight: 700; }
.k-var { color: var(--ext); }
.k-sel { color: var(--int); }
.k-neg, .k-op { color: var(--warn); font-weight: 700; }
.k-oparg { color: var(--ok); }
.k-act, .k-act-pass { color: var(--text); font-weight: 600; }
.k-act-deny { color: var(--blocked); font-weight: 700; }
.k-act-chain { color: var(--link); font-weight: 700; }
.k-val, .k-num { color: var(--int); }
.k-str { color: var(--ok); }
.k-id { color: var(--link); font-weight: 700; background: var(--tint-a); border-radius: 3px; box-shadow: 0 0 0 1px var(--guide-border); }
.k-macro { color: var(--ext); font-style: italic; }
.k-punct, .k-q { color: var(--muted); }
.k-cont { color: var(--muted); opacity: .75; }
</style>
