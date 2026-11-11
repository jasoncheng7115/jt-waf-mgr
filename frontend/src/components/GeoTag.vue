<!-- Where an external address is: country (named in the reader's language), city, network owner (ASN).
     Values come from the server's GeoIP lookup and are rendered as text. -->
<template>
  <span v-if="geo && geo.scope === 'external' && (geo.cc || geo.org)" class="geotag" :class="{ full }" :title="title">
    <span v-if="geo.cc" class="geo-cc mono">{{ cc }}</span>
    <span v-if="full || !compact" class="geo-name">{{ country }}<template v-if="geo.city && full">, {{ clip(geo.city, 60) }}</template></span>
    <span v-if="geo.org && (full || !compact)" class="geo-org">{{ geo.asn ? 'AS' + geo.asn + ' ' : '' }}{{ clip(geo.org, full ? 120 : 40) }}</span>
  </span>
</template>

<script setup>
import { computed } from 'vue'
import { lang } from '../i18n.js'
import { countryName } from '../util.js'

const props = defineProps({ geo: { type: Object, default: null }, compact: Boolean, full: Boolean })
const cc = computed(() => (/^[A-Z]{2}$/.test(props.geo?.cc || '') ? props.geo.cc : '??'))
const country = computed(() => countryName(props.geo?.cc, lang.value) || clip(props.geo?.country || '', 60))
const title = computed(() => [country.value, props.geo?.city, props.geo?.asn ? 'AS' + props.geo.asn : '', props.geo?.org]
  .filter(Boolean).map((x) => clip(String(x), 120)).join(' · '))
function clip(s, n) { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s }
</script>
