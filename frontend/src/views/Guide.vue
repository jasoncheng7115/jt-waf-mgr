<!-- Getting started: an interactive architecture diagram, the first steps, the change workflow and the roles. -->
<template>
  <div class="page guide">
    <div class="pagehead">
      <h1><Icon name="guide" /> {{ t('guide.title') }}</h1>
    </div>
    <p class="muted">{{ t('guide.intro') }}</p>

    <section class="card">
      <h2>{{ t('guide.arch.title') }}</h2>
      <p class="muted small">{{ t('guide.arch.hint') }}</p>
      <div class="archwrap">
        <svg class="archsvg" viewBox="0 0 1000 520" role="group" :aria-label="t('guide.arch.title')">
          <defs>
            <marker id="arch-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" class="arch-arrowhead" />
            </marker>
          </defs>
          <rect class="arch-group" x="190" y="282" width="640" height="218" rx="12" />
          <text class="arch-grouplabel" x="816" y="490" text-anchor="end">jt-waf-mgr · {{ t('guide.arch.service') }}</text>
          <path v-for="e in edges" :key="e.key" class="arch-edge" :class="{ hot: e.from === sel || e.to === sel, main: e.main }" :d="e.d" marker-end="url(#arch-arrow)" />
          <g v-for="e in edges" :key="'l' + e.key">
            <text v-if="e.label" class="arch-edgelabel" :x="e.lx" :y="e.ly" :text-anchor="e.anchor || 'middle'">{{ t(e.label) }}</text>
          </g>
          <g v-for="n in nodes" :key="n.key" class="arch-node" :class="[n.kind, { sel: sel === n.key }]" tabindex="0" role="button"
             :aria-pressed="sel === n.key ? 'true' : 'false'" :aria-label="t('guide.node.' + n.key + '.name')"
             @click="sel = n.key" @keydown.enter.prevent="sel = n.key" @keydown.space.prevent="sel = n.key">
            <rect :x="n.x" :y="n.y" :width="n.w" :height="n.h" rx="8" />
            <text class="arch-name" :x="n.x + n.w / 2" :y="n.y + (n.sub ? n.h / 2 - 3 : n.h / 2 + 5)" text-anchor="middle">{{ t('guide.node.' + n.key + '.name') }}</text>
            <text v-if="n.sub" class="arch-sub" :x="n.x + n.w / 2" :y="n.y + n.h / 2 + 15" text-anchor="middle">{{ t('guide.node.' + n.key + '.sub') }}</text>
          </g>
        </svg>
      </div>
      <div class="archdesc" role="status">
        <h3><Icon :name="current.icon" /> {{ t('guide.node.' + sel + '.name') }}</h3>
        <p>{{ t('guide.node.' + sel + '.desc') }}</p>
        <RouterLink v-if="current.to && canSee(current)" class="btn small" :to="current.to"><Icon name="go" />{{ t('guide.open_page') }}</RouterLink>
      </div>
      <div class="legend archlegend">
        <span class="lg-item"><span class="lg lg-main"></span>{{ t('guide.arch.legend_traffic') }}</span>
        <span class="lg-item"><span class="lg lg-data"></span>{{ t('guide.arch.legend_data') }}</span>
      </div>
    </section>

    <section class="card">
      <FlowSteps :title="t('guide.first.title')" :steps="firstSteps" />
    </section>

    <section class="card">
      <FlowSteps :title="t('guide.change.title')" :steps="changeSteps" :note="t('guide.change.note')" />
    </section>

    <section class="card">
      <h2>{{ t('guide.roles.title') }}</h2>
      <div class="rolegrid">
        <div v-for="r in roles" :key="r" class="rolecard" :class="{ mine: state.user && state.user.role === r }">
          <h3><Icon :name="roleIcon[r]" /> {{ t('role.' + r) }}<span v-if="state.user && state.user.role === r" class="badge tiny b-ok">{{ t('guide.roles.you') }}</span></h3>
          <p class="small">{{ t('guide.roles.' + r) }}</p>
        </div>
      </div>
      <p class="muted small">{{ t('guide.roles.note') }}</p>
    </section>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { t } from '../i18n.js'
import { state, hasRole } from '../store.js'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'

// Layout of the architecture diagram (viewBox 1000 x 520).
const nodes = [
  { key: 'clients', x: 20, y: 40, w: 170, h: 70, kind: 'ext', icon: 'globe' },
  { key: 'nginx', x: 330, y: 28, w: 300, h: 94, kind: 'core', sub: true, icon: 'shield', to: '/crs' },
  { key: 'sites', x: 790, y: 40, w: 190, h: 70, kind: 'ext', icon: 'server', to: '/vhosts' },
  { key: 'auditlog', x: 300, y: 180, w: 160, h: 64, kind: 'file', sub: true, icon: 'page' },
  { key: 'managed', x: 490, y: 180, w: 160, h: 64, kind: 'file', sub: true, icon: 'code', to: '/managed' },
  { key: 'apply', x: 690, y: 180, w: 170, h: 64, kind: 'root', sub: true, icon: 'lock' },
  { key: 'collector', x: 210, y: 320, w: 140, h: 60, kind: 'svc', icon: 'download', to: '/events' },
  { key: 'database', x: 370, y: 320, w: 140, h: 60, kind: 'svc', icon: 'database' },
  { key: 'workflow', x: 530, y: 320, w: 140, h: 60, kind: 'svc', icon: 'change', to: '/changes' },
  { key: 'webui', x: 690, y: 320, w: 120, h: 60, kind: 'svc', icon: 'page', to: '/' },
  { key: 'sandbox', x: 515, y: 410, w: 175, h: 60, kind: 'svc', sub: true, icon: 'test' },
  { key: 'monitor', x: 205, y: 410, w: 175, h: 60, kind: 'svc', sub: true, icon: 'verify', to: '/admin/system', role: 'admin' },
  { key: 'users', x: 860, y: 320, w: 120, h: 60, kind: 'ext', icon: 'users', to: '/admin/users', role: 'admin' },
  { key: 'siem', x: 20, y: 410, w: 150, h: 60, kind: 'ext', sub: true, icon: 'bell' },
]
const N = Object.fromEntries(nodes.map((n) => [n.key, n]))
function mid(k, side) {
  const n = N[k]
  return side === 'l' ? [n.x, n.y + n.h / 2] : side === 'r' ? [n.x + n.w, n.y + n.h / 2]
    : side === 't' ? [n.x + n.w / 2, n.y] : [n.x + n.w / 2, n.y + n.h]
}
function edge(key, from, fs, to, ts, opts = {}) {
  const a = opts.a || mid(from, fs), b = opts.b || mid(to, ts)
  const d = opts.d || ('M' + a[0] + ',' + a[1] + ' L' + b[0] + ',' + b[1])
  return { key, from, to, d, label: opts.label, lx: opts.lx ?? (a[0] + b[0]) / 2, ly: opts.ly ?? (a[1] + b[1]) / 2 - 6, anchor: opts.anchor, main: opts.main }
}
const edges = [
  edge('c-n', 'clients', 'r', 'nginx', 'l', { label: 'guide.edge.requests', main: true }),
  edge('n-s', 'nginx', 'r', 'sites', 'l', { label: 'guide.edge.allowed', main: true }),
  edge('n-a', 'nginx', 'b', 'auditlog', 't', { a: [380, 122], b: [380, 180], label: 'guide.edge.blocked_logged', lx: 386, ly: 156, anchor: 'start' }),
  edge('m-n', 'managed', 't', 'nginx', 'b', { a: [570, 180], b: [570, 122], label: 'guide.edge.loads', lx: 576, ly: 156, anchor: 'start' }),
  edge('ap-m', 'apply', 'l', 'managed', 'r', { label: 'guide.edge.writes' }),
  edge('ap-n', 'apply', 't', 'nginx', 'r', { d: 'M775,180 L775,92 L630,92', label: 'guide.edge.test_reload', lx: 782, ly: 140, anchor: 'start' }),
  edge('a-c', 'auditlog', 'b', 'collector', 't', { d: 'M380,244 L380,282 L280,282 L280,320', label: 'guide.edge.reads', lx: 300, ly: 274, anchor: 'start' }),
  edge('c-d', 'collector', 'r', 'database', 'l'),
  edge('w-d', 'workflow', 'l', 'database', 'r'),
  edge('u-w', 'webui', 'l', 'workflow', 'r'),
  edge('w-ap', 'workflow', 't', 'apply', 'b', { d: 'M640,320 L640,290 L775,290 L775,244', label: 'guide.edge.approved', lx: 650, ly: 284, anchor: 'start' }),
  edge('w-sb', 'workflow', 'b', 'sandbox', 't'),
  edge('us-u', 'users', 'l', 'webui', 'r', { main: true }),
  edge('mo-si', 'monitor', 'l', 'siem', 'r', { label: 'guide.edge.syslog', ly: 434 }),
  edge('d-mo', 'database', 'b', 'monitor', 'r', { d: 'M440,380 L440,440 L380,440', label: 'guide.edge.verifies', lx: 446, ly: 410, anchor: 'start' }),
]
const sel = ref('nginx')
const current = computed(() => N[sel.value])
function canSee(n) { return !n.role || hasRole(n.role) }

const firstSteps = computed(() => [
  { key: 'signin', icon: 'login', label: t('guide.first.secure'), desc: t('guide.first.signin_d'), to: '/account' },
  { key: 'check', icon: 'verify', label: t('guide.first.check'), desc: t('guide.first.check_d'), to: hasRole('admin') ? '/admin/system' : null },
  { key: 'overview', icon: 'chart', label: t('guide.first.overview'), desc: t('guide.first.overview_d'), to: '/' },
  { key: 'events', icon: 'list', label: t('guide.first.events'), desc: t('guide.first.events_d'), to: '/events' },
  { key: 'lookup', icon: 'search', label: t('guide.first.lookup'), desc: t('guide.first.lookup_d'), to: '/lookup' },
  { key: 'propose', icon: 'change', label: t('guide.first.propose'), desc: t('guide.first.propose_d'), to: '/changes/new' },
])
const changeSteps = computed(() => [
  { key: 'propose', icon: 'add', label: t('guide.change.propose'), desc: t('guide.change.propose_d') },
  { key: 'checks', icon: 'check', label: t('guide.change.checks'), desc: t('guide.change.checks_d') },
  { key: 'sandbox', icon: 'test', label: t('guide.change.sandbox'), desc: t('guide.change.sandbox_d') },
  { key: 'approve', icon: 'approve', label: t('guide.change.approve'), desc: t('guide.change.approve_d') },
  { key: 'apply', icon: 'lock', label: t('guide.change.apply'), desc: t('guide.change.apply_d') },
  { key: 'verify', icon: 'verify', label: t('guide.change.verify'), desc: t('guide.change.verify_d') },
])
const roles = ['viewer', 'operator', 'approver', 'admin']
const roleIcon = { viewer: 'show', operator: 'tool', approver: 'approve', admin: 'settings' }
</script>

<style scoped>
.archwrap { overflow-x: auto; }
.archsvg { width: 100%; min-width: 720px; height: auto; display: block; }
.arch-group { fill: var(--panel-2); stroke: var(--border-strong); stroke-dasharray: none; }
.arch-grouplabel { fill: var(--muted); font-size: 14px; font-weight: 600; }
.arch-node { cursor: pointer; outline: none; }
.arch-node rect { fill: var(--panel); stroke: var(--border-strong); stroke-width: 1.5; }
.arch-node.core rect { stroke: var(--accent); stroke-width: 2; }
.arch-node.root rect { stroke: var(--blocked); stroke-width: 2; }
.arch-node.file rect { fill: var(--code-bg); }
.arch-node.ext rect { fill: var(--panel-2); }
.arch-node:hover rect, .arch-node:focus-visible rect { stroke: var(--accent); stroke-width: 2.5; }
.arch-node.sel rect { stroke: var(--accent); stroke-width: 3; fill: var(--panel); }
.arch-name { fill: var(--text); font-size: 15px; font-weight: 600; pointer-events: none; }
.arch-sub { fill: var(--muted); font-size: 12px; pointer-events: none; }
.arch-edge { fill: none; stroke: var(--muted); stroke-width: 1.5; }
.arch-edge.main { stroke: var(--series-1); stroke-width: 2.5; }
.arch-edge.hot { stroke: var(--accent); stroke-width: 2.5; }
.arch-arrowhead { fill: var(--muted); }
.arch-edgelabel { fill: var(--muted); font-size: 11.5px; }
.archdesc { margin-top: 10px; padding: 10px 12px; border-left: 3px solid var(--accent); background: var(--panel-2); border-radius: 0 6px 6px 0; }
.archdesc h3 { margin: 0 0 4px; font-size: 15px; display: flex; gap: 6px; align-items: center; }
.archdesc p { margin: 0 0 8px; white-space: pre-line; }
.archlegend { margin-top: 8px; }
.lg-main { background: var(--series-1); height: 3px; width: 16px; }
.lg-data { background: var(--muted); height: 2px; width: 16px; }
.rolegrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-bottom: 8px; }
.rolecard { border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; background: var(--panel-2); }
.rolecard.mine { border-color: var(--accent); }
.rolecard h3 { margin: 0 0 4px; font-size: 15px; display: flex; gap: 6px; align-items: center; }
.rolecard p { margin: 0; }
</style>
