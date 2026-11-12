<!-- One whole split into parts (statuses, outcomes…). Tall: 28px with the share printed inside when it fits;
     thin: 8px, no text. Legend lists the parts; every part has a hover / focus tooltip.
     parts: [{ key, label, value, tone, active?, pickable? }]  tone: good | warning | serious | critical | muted | s1 | s2 | s3
     pickable: parts and legend entries emit `pick(part)` on click / Enter / Space (a part with pickable: false
     stays display-only); `active` marks the part that is the current filter. -->
<template>
  <div class="segbar" :class="{ thin, 'sb-pickable': pickable }">
    <div class="sb-track" :role="pickable ? 'group' : 'img'" :aria-label="aria">
      <span v-for="p in shown" :key="p.key" class="sb-part" :class="['tone-' + p.tone, { 'sb-on': canPick(p) && p.active, 'sb-pick': canPick(p) }]"
            :style="{ flexGrow: p.value }" tabindex="0"
            :role="canPick(p) ? 'button' : null" :aria-pressed="canPick(p) ? (p.active ? 'true' : 'false') : null"
            :aria-label="canPick(p) ? p.label + ' ' + fmtNum(p.value) + ' (' + pct(p.value) + ')' : null"
            @pointermove="at($event, p.label, [{ value: fmtNum(p.value) + ' (' + pct(p.value) + ')', label: '' }])" @pointerleave="hide"
            @focus="at($event, p.label, [{ value: fmtNum(p.value) + ' (' + pct(p.value) + ')', label: '' }])" @blur="hide"
            @click="pick(p)" @keydown.enter.prevent="pick(p)" @keydown.space.prevent="pick(p)">
        <span v-if="!thin && share(p.value) >= 0.09" class="sb-in">{{ pct(p.value) }}</span>
      </span>
      <span v-if="!total" class="sb-part tone-muted sb-zero"></span>
    </div>
    <div v-if="legend" class="legend">
      <template v-for="p in parts" :key="p.key">
        <button v-if="canPick(p)" type="button" class="lg-item pickval" :class="{ on: p.active }" :aria-pressed="p.active ? 'true' : 'false'"
                :title="p.active ? t('filter.unpick') : t('filter.pick')" @click="pick(p)">
          <span class="lg" :class="'tone-' + p.tone"></span><span class="pv-text">{{ p.label }}</span> <span class="muted">{{ fmtNum(p.value || 0) }}</span><Icon name="filter" class="pv-icon" />
        </button>
        <span v-else class="lg-item"><span class="lg" :class="'tone-' + p.tone"></span>{{ p.label }} <span class="muted">{{ fmtNum(p.value || 0) }}</span></span>
      </template>
    </div>
    <ChartTip :tip="tip" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../../i18n.js'
import { fmtNum } from '../../util.js'
import { useTip } from './tip.js'
import ChartTip from './ChartTip.vue'
import Icon from '../Icon.vue'

const props = defineProps({ parts: { type: Array, default: () => [] }, thin: Boolean, legend: { type: Boolean, default: true }, label: { type: String, default: '' }, pickable: Boolean })
const emit = defineEmits(['pick'])
const { tip, at, hide } = useTip()
const total = computed(() => props.parts.reduce((s, p) => s + (p.value || 0), 0))
const shown = computed(() => props.parts.filter((p) => p.value > 0))
function share(v) { return total.value ? v / total.value : 0 }
function pct(v) { const s = share(v) * 100; return (s > 0 && s < 1 ? '<1' : Math.round(s)) + '%' }
const aria = computed(() => (props.label ? props.label + ': ' : '') + props.parts.map((p) => p.label + ' ' + fmtNum(p.value || 0)).join(', '))
function canPick(p) { return props.pickable && p.pickable !== false }
function pick(p) { if (!canPick(p)) return; hide(); emit('pick', p) }
</script>
