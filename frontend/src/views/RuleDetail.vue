<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('rule.detail_title') }} <span class="mono">{{ safeText(id, 12) }}</span></h1>
      <RouterLink class="btn small ghost" to="/rules"><Icon name="back" />{{ t('common.back') }}</RouterLink>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="!rule && !error" />
    <template v-if="rule">
      <FlowSteps :title="t('guide.rule.title')" :steps="flow" :note="t('guide.rule.note')" />
      <section class="card">
        <dl class="kv two">
          <dt>{{ t('rules.directive') }}</dt><dd class="mono">{{ safeText(rule.directive, 40) }}</dd>
          <dt>{{ t('rules.source') }}</dt><dd>{{ t('source.' + (rule.source || 'local')) }}
            <span v-if="!rule.managed" class="chip tag">{{ t('rules.unmanaged') }}</span></dd>
          <dt>{{ t('rules.category') }}</dt><dd>{{ t('category.' + (rule.category || 'other')) }}</dd>
          <dt>{{ t('rule.phase') }}</dt><dd class="mono">{{ rule.phase ?? '—' }}</dd>
          <dt>{{ t('rule.action') }}</dt><dd class="mono">{{ safeText(rule.disruptive, 20) || '—' }}</dd>
          <dt>{{ t('rule.severity') }}</dt><dd>{{ safeText(rule.severity, 20) || '—' }}</dd>
          <dt>{{ t('rule.message') }}</dt><dd>{{ safeText(rule.msg, 500) || '—' }}</dd>
          <dt>{{ t('rule.hosts') }}</dt><dd><span v-for="h in rule.hosts || []" :key="h" class="chip host">{{ safeText(h, 120) }}</span><template v-if="!(rule.hosts || []).length">{{ t('rules.global') }}</template></dd>
          <dt>{{ t('rules.location') }}</dt><dd class="mono breakall">{{ safeText(rule.file, 500) }}:{{ rule.line }}</dd>
          <dt>{{ t('rule.tags') }}</dt><dd><span v-for="tg in rule.tags || []" :key="tg" class="chip tag">{{ safeText(tg, 80) }}</span><template v-if="!(rule.tags || []).length">—</template></dd>
          <dt>{{ t('rule.hits_7d') }}</dt><dd class="mono">{{ fmtNum(rule.hits_7d) }}</dd>
          <dt>{{ t('rule.hits_30d') }}</dt><dd class="mono">{{ fmtNum(rule.hits_30d) }}</dd>
          <dt>{{ t('rule.last_hit') }}</dt><dd>{{ fmtTime(rule.last_hit) }}</dd>
        </dl>
        <div class="actions">
          <RouterLink class="btn small" :to="{ path: '/events', query: { rule_id: rule.id } }"><Icon name="list" />{{ t('rule.view_events') }}</RouterLink>
          <RouterLink v-if="canPropose" class="btn small" :to="{ path: '/changes/new', query: { kind: 'exclusion' } }"><Icon name="add" />{{ t('guide.rule.propose') }}</RouterLink>
        </div>
      </section>
      <section v-if="rule.comment" class="card">
        <h2>{{ t('rules.comment') }}</h2>
        <pre class="code">{{ safeMultiline(rule.comment) }}</pre>
      </section>
      <section class="card">
        <h2>{{ t('rule.text') }}</h2>
        <pre class="code">{{ safeMultiline(rule.text) }}</pre>
      </section>
      <section class="card">
        <h2>{{ t('rule.hits_by_day') }}</h2>
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.outcome_split') }}</h3><SegBar :parts="hitParts" :label="t('chart.outcome_split')" /></div>
        </div>
        <TimeBars :data="hitsSeries" :series="outcomeSeries" :label="t('rule.hits_by_day')" />
      </section>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { get } from '../api.js'
import { t } from '../i18n.js'
import { safeText, safeMultiline, fmtNum, fmtTime } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import TimeBars from '../components/charts/TimeBars.vue'
import { hasRole } from '../store.js'

const props = defineProps({ id: { type: String, required: true } })
const rule = ref(null)
const hits = ref([])
const error = ref(null)

const canPropose = computed(() => hasRole('operator'))
const p2 = (n) => String(n).padStart(2, '0')
const dayKey = (d) => d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate())
// one column per day for the last 30 days (the API only returns days with hits)
const hitsSeries = computed(() => {
  const by = new Map(hits.value.map((h) => [h.day, h]))
  const out = []
  const d = new Date()
  d.setHours(0, 0, 0, 0)
  d.setDate(d.getDate() - 29)
  for (let i = 0; i < 30; i++) {
    const k = dayKey(d)
    const h = by.get(k)
    out.push({ t: k + 'T00:00:00', blocked: h ? h.blocked || 0 : 0, logged: h ? h.logged || 0 : 0 })
    d.setDate(d.getDate() + 1)
  }
  return out
})
const outcomeSeries = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
const hitParts = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), value: hits.value.reduce((s, h) => s + (h.blocked || 0), 0), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), value: hits.value.reduce((s, h) => s + (h.logged || 0), 0), tone: 'logged' },
])
// where this rule stands: hits seen -> review them -> maybe propose a change
const flow = computed(() => {
  const r = rule.value
  const hit = (r.hits_30d || 0) > 0
  return [
    { key: 'hit', label: t('guide.rule.hit'), desc: t('rule.hits_30d') + ': ' + fmtNum(r.hits_30d || 0), icon: 'shield', state: hit ? 'done' : 'skip' },
    { key: 'record', label: t('guide.rule.record'), desc: t('rule.last_hit') + ': ' + fmtTime(r.last_hit), icon: 'database', state: hit ? 'done' : 'skip' },
    { key: 'review', label: t('guide.rule.review'), desc: t('guide.rule.review_d'), icon: 'list', state: hit ? 'current' : 'skip',
      to: { path: '/events', query: { rule_id: r.id } } },
    { key: 'propose', label: t('guide.rule.propose'), desc: t('guide.rule.propose_d'), icon: 'add', state: hit ? 'todo' : 'skip',
      to: canPropose.value ? { path: '/changes/new', query: { kind: 'exclusion' } } : null },
    { key: 'process', label: t('guide.rule.process'), desc: t('guide.rule.process_d'), icon: 'approve', state: hit ? 'todo' : 'skip' },
  ]
})

async function load() {
  rule.value = null
  error.value = null
  hits.value = []
  try {
    rule.value = await get('/rules/' + encodeURIComponent(props.id))
    try { hits.value = (await get('/rules/' + encodeURIComponent(props.id) + '/hits', { days: 30 })).items || [] } catch { hits.value = [] }
  } catch (e) { error.value = e }
}
watch(() => props.id, load, { immediate: true })
</script>
