<!-- Ranked "key: blocked + logged" bars: a thin wrapper around charts/HBars with the WAF outcome series.
     items: [{ key, blocked, logged, origin?, msg? }] -->
<template>
  <HBars :items="bars" :series="series" :mono="mono" />
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'
import HBars from './charts/HBars.vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  linkFor: { type: Function, default: null },
  labelFor: { type: Function, default: null },
  mono: Boolean,
})
const series = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
const bars = computed(() => (props.items || []).map((it) => ({
  key: String(it.key),
  label: props.labelFor ? props.labelFor(it) : String(it.key ?? ''),
  values: { blocked: it.blocked || 0, logged: it.logged || 0 },
  to: props.linkFor ? props.linkFor(it) : null,
  sub: [it.origin ? t('origin.' + it.origin) : '', it.msg || ''].filter(Boolean).join(' · ') || null,
})))
</script>
