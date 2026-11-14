<!-- Ranked "key: blocked + logged" bars: a thin wrapper around charts/HBars with the WAF outcome series.
     items: [{ key, blocked, logged, origin?, msg?, geo? }]  (geo: the server's GeoIP result; country and network owner
     are shown under an external address)
     pickable: clicking a key emits `pick(item)` (the original item); linkFor then gives the secondary
     "open" link next to it (openLabel names it); activeKey marks the key that is the current filter. -->
<template>
  <HBars :items="bars" :series="series" :mono="mono" :pickable="pickable" :open-label="openLabel" :inline-sub="inlineSub" @pick="(b) => emit('pick', b.item)" />
</template>

<script setup>
import { computed } from 'vue'
import { t, lang } from '../i18n.js'
import { countryName } from '../util.js'
import HBars from './charts/HBars.vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  linkFor: { type: Function, default: null },
  labelFor: { type: Function, default: null },
  mono: Boolean,
  inlineSub: Boolean,
  pickable: Boolean,
  openLabel: { type: String, default: '' },
  activeKey: { type: [String, Number], default: null },
  ipKeys: Boolean,          // the keys are addresses: the address card shows on hover
})
const emit = defineEmits(['pick'])
const series = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
const bars = computed(() => (props.items || []).map((it) => ({
  key: String(it.key),
  label: props.labelFor ? props.labelFor(it) : String(it.key ?? ''),
  values: { blocked: it.blocked || 0, logged: it.logged || 0 },
  to: props.linkFor ? props.linkFor(it) : null,
  sub: [it.origin ? t('origin.' + it.origin) : '', geoText(it.geo), it.msg || ''].filter(Boolean).join(' · ') || null,
  active: props.activeKey != null && String(props.activeKey) === String(it.key),
  item: it,
  ip: props.ipKeys ? String(it.key) : null,
})))
function clip(s, n) { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s }
function geoText(g) {
  if (!g || g.scope !== 'external') return ''
  const cc = /^[A-Z]{2}$/.test(g.cc || '') ? g.cc : ''
  const name = cc ? (countryName(cc, lang.value) || clip(g.country || '', 40)) + ' (' + cc + ')' : ''
  return [name, g.org ? clip(g.org, 32) : ''].filter(Boolean).join(' · ')
}
</script>
