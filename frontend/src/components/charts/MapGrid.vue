<!-- World map with the country list beside it, one line per country (the source count on the same line). The list
     starts with the first `rows` countries, about the height of the map, so the card has no empty space under it;
     "show all" opens the rest and the map stays in view (sticky) while the list scrolls. Same props as WorldMap +
     HBars; emits pick(item). -->
<template>
  <div class="mapgrid">
    <div class="mg-map">
      <WorldMap :items="items" :series="series" :label="label" pickable :active-key="activeKey" @pick="(it) => emit('pick', it)" />
    </div>
    <div class="mg-list">
      <HBars :items="all ? items.slice(0, MAX) : items.slice(0, rows)" :series="series" pickable inline-sub :open-label="openLabel" @pick="(it) => emit('pick', it)" />
      <button v-if="items.length > rows" type="button" class="btn small ghost mg-more" :aria-expanded="all ? 'true' : 'false'" @click="all = !all">
        <Icon :name="all ? 'collapse' : 'expand'" />{{ all ? t('map.show_fewer', { n: rows }) : t('map.show_all', { n: fmtNum(Math.min(items.length, MAX)) }) }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { t } from '../../i18n.js'
import { fmtNum } from '../../util.js'
import Icon from '../Icon.vue'
import HBars from './HBars.vue'
import WorldMap from './WorldMap.vue'

defineProps({
  items: { type: Array, default: () => [] },
  series: { type: Array, default: () => [] },
  label: { type: String, default: '' },
  activeKey: { type: String, default: null },
  openLabel: { type: String, default: '' },
  rows: { type: Number, default: 10 },
})
const emit = defineEmits(['pick'])
const MAX = 50
const all = ref(false)
</script>

<style scoped>
.mg-map { position: sticky; top: 72px; }
.mg-more { margin-top: 6px; }
@media (max-width: 900px) { .mg-map { position: static; } }
</style>
