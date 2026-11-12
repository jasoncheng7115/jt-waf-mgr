<!-- Getting started: an interactive architecture diagram, the first steps, the change workflow and the roles. -->
<template>
  <div class="page guide">
    <div class="pagehead">
      <h1><Icon name="guide" /> {{ t('guide.title') }}</h1>
    </div>
    <p class="muted">{{ t('guide.intro') }}</p>
    <section class="card wafcard">
      <div><h2><Icon name="shield" /> {{ t('waf.title') }}</h2><p class="muted small">{{ t('waf.guide_link_d') }}</p></div>
      <RouterLink class="btn" to="/waf"><Icon name="go" />{{ t('waf.crs_link') }}</RouterLink>
    </section>

    <section class="card">
      <h2><Icon name="map" /> {{ t('guide.arch.title') }}</h2>
      <p class="muted small">{{ t('guide.arch.hint') }}</p>
      <div class="archwrap">
        <svg class="archsvg" viewBox="0 0 1000 625" role="group" :aria-label="t('guide.arch.title')">
          <defs>
            <marker id="arch-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" class="arch-arrowhead" />
            </marker>
          </defs>
          <rect class="arch-group" x="190" y="282" width="640" height="330" rx="12" />
          <text class="arch-grouplabel" x="816" y="600" text-anchor="end">jt-waf-mgr · {{ t('guide.arch.service') }}</text>
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
        <span class="lg-item"><span class="lg-k core"></span>{{ t('guide.arch.legend_core') }}</span>
        <span class="lg-item"><span class="lg-k svc"></span>{{ t('guide.arch.legend_svc') }}</span>
        <span class="lg-item"><span class="lg-k file"></span>{{ t('guide.arch.legend_file') }}</span>
        <span class="lg-item"><span class="lg-k root"></span>{{ t('guide.arch.legend_root') }}</span>
        <span class="lg-item"><span class="lg-k ext"></span>{{ t('guide.arch.legend_ext') }}</span>
      </div>
    </section>

    <section class="card">
      <FlowSteps :title="t('guide.first.title')" :steps="firstSteps" />
    </section>

    <section class="card">
      <FlowSteps :title="t('guide.change.title')" :steps="changeSteps" :note="t('guide.change.note')" />
    </section>

    <section class="card">
      <h2><Icon name="users" /> {{ t('guide.roles.title') }}</h2>
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
  { key: 'webui', x: 688, y: 320, w: 142, h: 60, kind: 'svc', icon: 'page', to: '/' },
  { key: 'sandbox', x: 515, y: 410, w: 175, h: 60, kind: 'svc', sub: true, icon: 'test' },
  { key: 'monitor', x: 205, y: 410, w: 175, h: 60, kind: 'svc', sub: true, icon: 'verify', to: '/admin/system', role: 'admin' },
  { key: 'users', x: 848, y: 320, w: 146, h: 60, kind: 'ext', icon: 'users', to: '/admin/users', role: 'admin' },
  { key: 'siem', x: 20, y: 410, w: 150, h: 60, kind: 'ext', sub: true, icon: 'bell' },
  { key: 'analyst', x: 370, y: 500, w: 150, h: 60, kind: 'svc', sub: true, icon: 'timer', to: '/analysis', role: 'approver' },
  { key: 'notify', x: 640, y: 500, w: 160, h: 60, kind: 'svc', sub: true, icon: 'notify', to: '/admin/notify', role: 'admin' },
  { key: 'llm', x: 20, y: 500, w: 150, h: 60, kind: 'ext', sub: true, icon: 'server' },
  { key: 'channels', x: 848, y: 500, w: 146, h: 60, kind: 'ext', sub: true, icon: 'chat' },
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
  edge('a-c', 'auditlog', 'b', 'collector', 't', { d: 'M380,244 L380,264 L280,264 L280,320', label: 'guide.edge.reads', lx: 386, ly: 259, anchor: 'start' }),
  edge('c-d', 'collector', 'r', 'database', 'l'),
  edge('w-d', 'workflow', 'l', 'database', 'r'),
  edge('u-w', 'webui', 'l', 'workflow', 'r'),
  edge('w-ap', 'workflow', 't', 'apply', 'b', { d: 'M640,320 L640,290 L775,290 L775,244', label: 'guide.edge.approved', lx: 650, ly: 284, anchor: 'start' }),
  edge('w-sb', 'workflow', 'b', 'sandbox', 't'),
  edge('us-u', 'users', 'l', 'webui', 'r', { main: true }),
  edge('mo-si', 'monitor', 'l', 'siem', 'r'),
  edge('d-mo', 'database', 'b', 'monitor', 'r', { d: 'M440,380 L440,440 L380,440', label: 'guide.edge.verifies', lx: 446, ly: 410, anchor: 'start' }),
  edge('an-d', 'analyst', 't', 'database', 'b', { d: 'M470,500 L470,380', label: 'guide.edge.proposes', lx: 464, ly: 472, anchor: 'end' }),
  edge('an-llm', 'analyst', 'l', 'llm', 'r', { label: 'guide.edge.asks' }),
  edge('d-no', 'database', 'b', 'notify', 't', { d: 'M500,380 L500,485 L720,485 L720,500', label: 'guide.edge.queue', lx: 590, ly: 498 }),
  edge('no-ch', 'notify', 'r', 'channels', 'l', { label: 'guide.edge.sends' }),
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
.archwrap { overflow-x: auto; border-radius: 8px; background: linear-gradient(180deg, var(--panel-2), var(--panel)); padding: 6px; }
.archsvg { width: 100%; min-width: 720px; height: auto; display: block; }
.arch-group { fill: var(--tint-b); stroke: var(--tint-b-line); stroke-width: 1.5; stroke-dasharray: 6 4; }
.arch-grouplabel { fill: var(--tint-b-line); font-size: 14px; font-weight: 700; }
.arch-node { cursor: pointer; outline: none; }
.arch-node rect { stroke-width: 2; filter: drop-shadow(0 1px 2px rgba(16, 24, 40, .12)); transition: stroke-width .1s; }
.arch-node.ext rect { fill: var(--tint-e); stroke: var(--tint-e-line); }
.arch-node.core rect { fill: var(--tint-a); stroke: var(--tint-a-line); stroke-width: 2.5; }
.arch-node.file rect { fill: var(--tint-d); stroke: var(--tint-d-line); }
.arch-node.root rect { fill: var(--blocked-bg); stroke: var(--blocked); stroke-width: 2.5; }
.arch-node.svc rect { fill: var(--panel); stroke: var(--tint-b-line); }
.arch-node:hover rect, .arch-node:focus-visible rect { stroke-width: 3.5; }
.arch-node.sel rect { stroke: var(--accent); stroke-width: 4; }
.arch-name { fill: var(--text); font-size: 14.5px; font-weight: 700; pointer-events: none; }
.arch-sub { fill: var(--muted); font-size: 12px; pointer-events: none; }
.arch-edge { fill: none; stroke: var(--muted); stroke-width: 1.6; }
.arch-edge.main { stroke: var(--tint-a-line); stroke-width: 3; }
.arch-edge.hot { stroke: var(--accent); stroke-width: 3; }
.arch-arrowhead { fill: var(--muted); }
.arch-edgelabel { fill: var(--text); font-size: 12px; font-weight: 600; paint-order: stroke; stroke: var(--panel); stroke-width: 4px; }
.archdesc { margin-top: 10px; padding: 10px 12px; border-left: 4px solid var(--accent); background: var(--guide-bg); border-radius: 0 6px 6px 0; }
.archdesc h3 { margin: 0 0 4px; font-size: 15px; display: flex; gap: 6px; align-items: center; color: var(--accent); }
.archdesc p { margin: 0 0 8px; white-space: pre-line; }
.archlegend { margin-top: 8px; }
.lg-main { background: var(--tint-a-line); height: 3px; width: 16px; }
.lg-data { background: var(--muted); height: 2px; width: 16px; }
.lg-k { display: inline-block; width: 14px; height: 10px; border-radius: 3px; border: 2px solid; }
.lg-k.ext { background: var(--tint-e); border-color: var(--tint-e-line); }
.lg-k.core { background: var(--tint-a); border-color: var(--tint-a-line); }
.lg-k.file { background: var(--tint-d); border-color: var(--tint-d-line); }
.lg-k.root { background: var(--blocked-bg); border-color: var(--blocked); }
.lg-k.svc { background: var(--panel); border-color: var(--tint-b-line); }
.rolegrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-bottom: 8px; }
.rolecard { border: 1px solid var(--border); border-top: 3px solid var(--tint-c-line); border-radius: 8px; padding: 10px 12px; background: var(--tint-c); }
.rolecard:nth-child(2) { border-top-color: var(--tint-b-line); background: var(--tint-b); }
.rolecard:nth-child(3) { border-top-color: var(--tint-d-line); background: var(--tint-d); }
.rolecard:nth-child(4) { border-top-color: var(--tint-a-line); background: var(--tint-a); }
.rolecard.mine { box-shadow: 0 0 0 2px var(--accent); }
.rolecard h3 { margin: 0 0 4px; font-size: 15px; display: flex; gap: 6px; align-items: center; }
.rolecard p { margin: 0; }
.wafcard { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between; }
.wafcard h2 { display: flex; gap: 6px; align-items: center; margin: 0 0 4px; }
.wafcard p { margin: 0; }
</style>
