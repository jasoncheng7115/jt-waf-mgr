"""The WAF decision model: which mechanisms exist, which block, which only log, which loosen.

Everything is derived from the parsed nginx + ModSecurity configuration (nothing about one site is
assumed). Each site rule is read for what it checks (source address, anomaly score, a TX flag set by
another rule, Host, other request parts) and what it does (deny, turn the engine on, add score, set a
flag, remove rules or targets, ...). A small abstract run of the rules in phase order then answers
"what happens to a request from outside / from the internal networks at score S, or when a confident
block rule matches" for every engine context (the global SecRuleEngine and vhosts that override it).

Simplifications (also in docs): CRS detection rules are one step that adds the score S; skipAfter /
SecMarker flow is not followed; conditions on request content are only true in the scenario that
forces that rule; outbound (response) scoring is reported, not simulated.
"""
import ipaddress
import math
import os
import re

from . import util
from .modsecconf import DISRUPTIVE, readable_host, split_actions

SEVERITIES = ('critical', 'error', 'warning', 'notice')
DEFAULT_POINTS = {'critical': 5, 'error': 4, 'warning': 3, 'notice': 2}
SEV_ALIASES = {'0': 'emergency', '1': 'alert', '2': 'critical', '3': 'error', '4': 'warning', '5': 'notice',
               'emergency': 'emergency', 'alert': 'alert', 'critical': 'critical', 'error': 'error',
               'warning': 'warning', 'notice': 'notice'}
# Display order of effects (strongest first) when several rules of a stage differ.
EFFECT_ORDER = ('blocks', 'logs', 'not_inspected', 'loosens', 'scores', 'info', 'not_reached', 'not_applicable')
LOOSEN_CTL = ('ruleremovebyid', 'ruleremovebytag', 'ruleremovebymsg', 'ruleremovetargetbyid',
              'ruleremovetargetbytag', 'ruleremovetargetbymsg')
INBOUND_SCORE_VAR = re.compile(r'^TX:(?:BLOCKING_)?(?:INBOUND_)?ANOMALY_SCORE(?:_PL\d)?$')
OUTBOUND_SCORE_VAR = re.compile(r'^TX:(?:BLOCKING_)?OUTBOUND_ANOMALY_SCORE(?:_PL\d)?$')
SITE_SOURCES = ('local', 'vhost_inline')
ROLE_STAGE = {
    'exclusion': 'exclusions', 'allow': 'exclusions', 'policy': 'exclusions', 'plugin_toggle': 'exclusions',
    'confident_block': 'confident', 'score_rule': 'site_scoring', 'score_bridge': 'site_scoring',
    'threshold_block': 'threshold_block', 'fallback_deny': 'fallback', 'deny_rule': 'deny_rules',
    'engine_off': 'not_inspected', 'threshold_override': 'settings', 'paranoia_override': 'settings',
    'body_processor': 'settings', 'engine_on': 'settings', 'other': 'other',
}
ROLE_EFFECT = {
    'exclusions': 'loosens', 'confident': 'blocks', 'site_scoring': 'scores', 'threshold_block': 'blocks',
    'fallback': 'blocks', 'deny_rules': 'blocks', 'not_inspected': 'not_inspected', 'settings': 'info',
    'other': 'info',
}


# --- reading one rule ---------------------------------------------------------------------------
def _nets(text):
    out = []
    for p in re.split(r'[,\s]+', text.strip()):
        if not p:
            continue
        try:
            out.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            return None
    return out


def _covered(net, nets):
    return any(net.version == n.version and net.subnet_of(n) for n in nets)


def _source_cond(op, internal):
    neg = op.startswith('!')
    o = op[1:] if neg else op
    m = re.match(r'@ipMatch\s+(.+)$', o.strip(), re.S)
    nets = _nets(m.group(1)) if m else None
    if nets is None:
        return {'type': 'source', 'applies': 'some', 'negated': neg, 'text': op[:200]}
    inside = all(_covered(n, internal) for n in nets)          # the list holds only internal ranges
    missing = [str(n) for n in internal if not _covered(n, nets)]
    if neg:
        applies = 'external' if inside else 'some'
    else:
        applies = 'internal' if inside else 'some'
    return {'type': 'source', 'applies': applies, 'negated': neg, 'networks': [str(n) for n in nets],
            'missing_internal': missing if inside else [], 'text': op[:200]}


def _num_or_threshold(v):
    v = v.strip()
    if re.fullmatch(r'%\{tx\.inbound_anomaly_score_threshold\}', v, re.I):
        return 'threshold'
    if re.fullmatch(r'%\{tx\.outbound_anomaly_score_threshold\}', v, re.I):
        return 'outbound_threshold'
    return int(v) if re.fullmatch(r'-?\d+', v) else None


def _condition(var, op, internal):
    v = var.strip()
    vu = v.upper()
    o = op.strip()
    if not v:
        return {'type': 'always'}
    if vu in ('REMOTE_ADDR', 'REMOTE_HOST'):
        return _source_cond(o, internal)
    if INBOUND_SCORE_VAR.match(vu) or OUTBOUND_SCORE_VAR.match(vu):
        m = re.match(r'(!?)@(ge|gt|eq|lt|le)\s+(.+)$', o)
        value = _num_or_threshold(m.group(3)) if m else None
        if m and value is not None and not m.group(1):
            return {'type': 'score', 'direction': 'outbound' if OUTBOUND_SCORE_VAR.match(vu) else 'inbound',
                    'variable': v, 'op': m.group(2), 'value': value}
    if vu.startswith('TX:') and '|' not in vu:
        m = re.match(r'@eq\s+(-?\d+)$', o)
        if m:
            return {'type': 'flag', 'name': vu[3:].lower(), 'value': int(m.group(1))}
    if vu.startswith('REQUEST_HEADERS:HOST') or vu.startswith('SERVER_NAME'):
        param = re.sub(r'^!?@\w+\s+', '', o)
        return {'type': 'host', 'negated': o.startswith('!'), 'host': readable_host(param)[:200]}
    m = re.match(r'(!?)(@\w+)?\s*(.*)$', o, re.S)
    return {'type': 'request', 'variable': v[:200], 'negated': bool(m.group(1)),
            'operator': m.group(2) or '@rx', 'pattern': (m.group(3) or '')[:160]}


def _setvar(v):
    v = v.strip().strip("'")
    m = re.match(r'(?:tx|TX)\.([A-Za-z0-9_.\-]+)=(\+|-)?(.*)$', v)
    if not m:
        return None
    return m.group(1).lower(), m.group(2), m.group(3)


def _effects(rule, points):
    """What a rule does when all its conditions hold."""
    eff = {'disruptive': None, 'allow': None, 'engine': None, 'score_add': 0, 'score_macro': None, 'flags': {},
           'removes_ids': [], 'removes_tags': [], 'removes_targets': [], 'body_access_off': False,
           'body_processor': None, 'threshold_set': {}, 'paranoia_set': {}, 'plugin_toggle': [], 'policy': [],
           'other_setvar': []}
    for k, v in rule.actions:
        if k in DISRUPTIVE and eff['disruptive'] is None:
            eff['disruptive'] = k
            if k == 'allow':
                eff['allow'] = v or 'all'
    for k, v in rule.all_actions():
        if k == 'ctl':
            name, _, val = v.partition('=')
            n = name.strip().lower()
            val = val.strip()
            if n == 'ruleengine':
                eff['engine'] = {'on': 'On', 'off': 'Off', 'detectiononly': 'DetectionOnly'}.get(val.lower(), val)
            elif n == 'ruleremovebyid':
                for p in val.split(','):
                    p = p.strip()
                    m = re.fullmatch(r'(\d+)-(\d+)', p)
                    if m:
                        eff['removes_ids'].append([int(m.group(1)), int(m.group(2))])
                    elif p.isdigit():
                        eff['removes_ids'].append(int(p))
            elif n in ('ruleremovebytag', 'ruleremovebymsg'):
                eff['removes_tags'].append(val[:120])
            elif n in LOOSEN_CTL:
                eff['removes_targets'].append(val[:160])
            elif n == 'requestbodyaccess' and val.lower() == 'off':
                eff['body_access_off'] = True
            elif n == 'requestbodyprocessor':
                eff['body_processor'] = val[:40]
        elif k == 'setvar':
            sv = _setvar(v)
            if not sv:
                continue
            name, sign, val = sv
            if re.fullmatch(r'(?:blocking_)?(?:inbound_)?anomaly_score(?:_pl\d)?', name) and sign == '+':
                m = re.fullmatch(r'%\{tx\.(\w+)_anomaly_score\}', val.strip(), re.I)
                if m and m.group(1).lower() in points:
                    eff['score_add'] += points[m.group(1).lower()]
                    eff['score_macro'] = m.group(1).lower()
                elif val.strip().isdigit():
                    eff['score_add'] += int(val)
            elif name in ('inbound_anomaly_score_threshold', 'outbound_anomaly_score_threshold'):
                if val.strip().isdigit():
                    eff['threshold_set']['inbound' if name.startswith('in') else 'outbound'] = int(val)
            elif name in ('paranoia_level', 'blocking_paranoia_level', 'detection_paranoia_level',
                          'executing_paranoia_level'):
                if val.strip().isdigit():
                    eff['paranoia_set'][name] = int(val)
            elif name.endswith('plugin_enabled'):
                eff['plugin_toggle'].append({'plugin': name[:-len('_enabled')].rstrip('-_')[:80],
                                             'enabled': val.strip() not in ('0', '')})
            elif name.startswith('allowed_') or name.startswith('restricted_') or name.startswith('arg_') \
                    or name.startswith('max_') or name.startswith('total_arg') or name.startswith('combined_file'):
                eff['policy'].append(name[:60])
            elif sign is None and re.fullmatch(r'-?\d+', val.strip()):
                eff['flags'][name] = int(val)
            else:
                eff['other_setvar'].append(name[:60])
    return eff


def _role(conds, eff, site=True):
    types = {c['type'] for c in conds}
    content = types & {'request', 'host'}
    blocking = eff['disruptive'] in ('deny', 'drop', 'redirect', 'block')
    if eff['engine'] == 'Off':
        return 'engine_off'
    if eff['removes_ids'] or eff['removes_tags'] or eff['removes_targets'] or eff['body_access_off'] \
            or eff['engine'] == 'DetectionOnly':
        return 'exclusion'
    if eff['allow']:
        return 'allow'
    inbound_score = any(c['type'] == 'score' and c['direction'] == 'inbound' for c in conds)
    if inbound_score and (blocking or eff['engine'] == 'On' or eff['flags']):
        return 'threshold_block'
    if 'flag' in types and not content and blocking:
        return 'fallback_deny'
    if 'flag' in types and not content and eff['score_add']:
        return 'score_bridge'
    if site and content and (eff['engine'] == 'On' or eff['flags'] or (blocking and 'source' in types)):
        return 'confident_block'
    if eff['score_add']:
        return 'score_rule'
    if eff['threshold_set']:
        return 'threshold_override'
    if eff['paranoia_set']:
        return 'paranoia_override'
    if eff['plugin_toggle']:
        return 'plugin_toggle'
    if eff['policy']:
        return 'policy'
    if eff['body_processor']:
        return 'body_processor'
    if blocking:
        return 'deny_rule'
    if eff['engine'] == 'On':
        return 'engine_on'
    return 'other'


def _phase(rule):
    p = rule.action('phase')
    if p is None:
        return 2
    p = p.strip("'\"")
    if p.isdigit():
        return int(p)
    return {'request': 2, 'response': 4, 'logging': 5}.get(p.lower(), 2)


def _default_disruptive(settings):
    """SecDefaultAction per phase -> disruptive action ('block' resolves to it)."""
    out = {}
    for d, val, _, _ in settings:
        if d != 'SecDefaultAction':
            continue
        acts = split_actions(val)
        ph = next((v for k, v in acts if k == 'phase'), '2')
        ph = int(ph) if ph.isdigit() else {'request': 2, 'response': 4}.get(ph, 2)
        dis = next((k for k, _ in acts if k in DISRUPTIVE), 'pass')
        out[ph] = dis
    return out


def _sev(rule):
    s = rule.action('severity')
    return SEV_ALIASES.get((s or '').strip("'\"").lower()) if s else None


def _pl(rule):
    for k, v in rule.all_actions():
        if k == 'tag':
            m = re.fullmatch(r"'?paranoia-level/(\d)'?", v.strip())
            if m:
                return int(m.group(1))
    return None


def _in_ids(rid, spec):
    for s in spec:
        if isinstance(s, list) and s[0] <= rid <= s[1]:
            return True
        if s == rid:
            return True
    return False


# --- the model ----------------------------------------------------------------------------------
class _Rule:
    __slots__ = ('r', 'id', 'phase', 'order', 'inline', 'source', 'conds', 'eff', 'role', 'msg', 'hosts',
                 'servers', 'disruptive', 'crs_eval')


def _analyse(m, cfg, points, defaults):
    internal = list(cfg.internal_networks)
    out, seen = [], set()
    for idx, r in enumerate(m.rules):
        src = m.source_of(r)
        key = (r.id, r.file, r.line, getattr(r, 'inline', False))
        if key in seen:
            continue
        seen.add(key)
        a = _Rule()
        a.r, a.id, a.phase, a.order = r, r.id, _phase(r), idx
        a.inline = bool(getattr(r, 'inline', False))
        a.source = src
        a.conds = [_condition(var, op, internal) for var, op, _ in r.parts] if r.directive == 'SecRule' \
            else [{'type': 'always'}]
        a.eff = _effects(r, points)
        dis = a.eff['disruptive']
        if dis == 'block':
            dis = defaults.get(a.phase, 'pass')
        a.disruptive = dis if dis in ('deny', 'drop', 'redirect') else None
        a.crs_eval = src == 'crs' and a.disruptive is not None and any(
            c['type'] == 'score' and c['direction'] == 'inbound' for c in a.conds)
        a.role = _role(a.conds, a.eff, src in SITE_SOURCES) if src in SITE_SOURCES or src == 'base' \
            else ('crs_eval' if a.crs_eval else src)
        a.msg = r.action('msg') or ''
        a.hosts = [c['host'] for c in a.conds if c['type'] == 'host' and not c.get('negated')]
        a.servers = []
        out.append(a)
    return out


class _Sim:
    """Abstract run of the inbound phases (1, 2) for one engine context."""

    def __init__(self, seq, engine, threshold, crs_marker):
        self.seq = seq
        self.engine = engine
        self.threshold = threshold
        self.crs_marker = crs_marker      # (phase, order) where CRS detection adds the score

    def run(self, src, score, force=()):
        st = {'engine': self.engine, 'score': 0, 'flags': {}, 'removed': [], 'T': self.threshold}
        trace = {}
        res = {'result': None, 'by': None, 'enabled_by': [], 'would_block_by': [], 'allowed_by': None}
        if self.engine == 'Off':
            res['result'] = 'not_inspected'
            return res, trace
        added = False
        skip_phase = None
        for a in self.seq:
            if not added and _seq_key(a) >= self.crs_marker:
                st['score'] += score
                added = True
            if skip_phase is not None and a.phase <= skip_phase:
                continue
            if a.id is not None and _in_ids(a.id, st['removed']):
                trace[a.id] = 'removed'
                continue
            ok = self._match(a, src, st, force)
            if ok is not True:
                if ok is False and a.id is not None and any(c['type'] == 'source' and _src_fail(c, src) for c in a.conds):
                    trace[a.id] = 'not_applicable'
                continue
            e = a.eff
            if a.id is not None:
                trace[a.id] = 'fired'
            if e['engine']:
                st['engine'] = e['engine']
                if e['engine'] == 'On' and a.id is not None:
                    res['enabled_by'].append(a.id)
                if e['engine'] == 'Off':
                    res['result'] = 'not_inspected'
                    res['by'] = a.id
                    return res, trace
            if e['score_add']:
                st['score'] += e['score_add']
            st['flags'].update(e['flags'])
            st['removed'].extend(e['removes_ids'])
            if 'inbound' in e['threshold_set']:
                st['T'] = e['threshold_set']['inbound']
            if a.disruptive:
                if st['engine'] == 'On':
                    res.update(result='blocked', by=a.id)
                    if a.id is not None:
                        trace[a.id] = 'blocked'
                    return res, trace
                res['would_block_by'].append(a.id)
                if a.id is not None:
                    trace[a.id] = 'would_block'
            elif e['allow']:
                res['allowed_by'] = a.id
                if e['allow'] == 'phase':
                    skip_phase = a.phase
                else:
                    res['result'] = 'allowed'
                    return res, trace
        if not added:
            st['score'] += score
        res['result'] = 'logged' if (res['would_block_by'] or st['score'] > 0) else 'passed'
        return res, trace

    @staticmethod
    def _match(a, src, st, force):
        unknown = False
        for c in a.conds:
            t = c['type']
            if t == 'always':
                continue
            if t == 'source':
                if c['applies'] == 'some':
                    unknown = True
                elif _src_fail(c, src):
                    return False
            elif t == 'score':
                if c['direction'] != 'inbound':
                    return False
                v = st['T'] if c['value'] == 'threshold' else c['value']
                if not isinstance(v, int):
                    return False
                s = st['score']
                if not {'ge': s >= v, 'gt': s > v, 'eq': s == v, 'lt': s < v, 'le': s <= v}[c['op']]:
                    return False
            elif t == 'flag':
                if st['flags'].get(c['name'], 0) != c['value']:
                    return False
            else:   # request content / Host: only true when this scenario forces the rule
                if a.id is None or a.id not in force:
                    unknown = True
        return None if unknown else True


def _seq_key(a):
    # a vhost's inline rules run before the http-level rules of the same phase
    return (a.phase, 0 if a.inline else 1, a.order)


def _id_spec(target_ids):
    return [x if isinstance(x, int) else [int(p) for p in str(x).split('-')] for x in target_ids]


def _blocking(b):
    return bool(b.disruptive or b.crs_eval or b.role in ('threshold_block', 'confident_block'))


def _src_fail(c, src):
    return c['type'] == 'source' and c['applies'] in ('external', 'internal') and c['applies'] != src


def _rank(effs):
    for e in EFFECT_ORDER:
        if e in effs:
            return e
    return 'not_reached'


def model(app):
    n, m = app.site.load()
    cfg = app.cfg
    crs = m.crs_status()
    T = crs['inbound_threshold']
    points, points_from = {}, {}
    for s in SEVERITIES:
        v = m.tx_setvar(900100, s + '_anomaly_score')
        if v is None:
            v = next((x for x in (m.tx_setvar(r.id, s + '_anomaly_score') for r in m.rules if r.id) if x is not None), None)
            points_from[s] = 'crs' if v is not None else 'default'
        else:
            points_from[s] = 'setup'
        points[s] = v if v is not None else DEFAULT_POINTS[s]
    defaults = _default_disruptive(m.settings)
    rules = _analyse(m, cfg, points, defaults)
    by_id = {}
    for a in rules:
        if a.id is not None:
            by_id.setdefault(a.id, a)
    # SecRuleRemoveById at configure time. Removals inside a vhost's modsecurity_rules only apply there;
    # the parser does not tell them apart, so they count as global here.
    removed_global = [x for rm in m.removals if rm['directive'] == 'SecRuleRemoveById'
                      for x in _id_spec(rm['target_ids'])]

    # --- vhosts and engine contexts --------------------------------------------------------------
    servers = n.servers()
    inline_ids = {a.id for a in rules if a.inline and a.id is not None}
    ctx_map = {}
    vh = {'total': len(servers), 'on': 0, 'block': 0, 'off': 0, 'unknown': 0, 'bypass_locations': 0}
    not_inspected = {'servers': [], 'locations': []}
    for s in servers:
        name = s['server_names'][0] if s['server_names'] else '(%s:%d)' % (os.path.basename(s['file']), s['line'])
        vh[s['waf']] = vh.get(s['waf'], 0) + 1
        if s['waf'] in ('off', 'unknown'):
            not_inspected['servers'].append({'server': name, 'waf': s['waf']})
            continue
        for b in s['bypass']:
            not_inspected['locations'].append({'server': name, 'location': b['location']})
        vh['bypass_locations'] += len(s['bypass'])
        engine = 'On' if s['waf'] == 'block' else crs['engine_mode']
        ids = tuple(sorted(i for i in s['inline_rule_ids'] if i in inline_ids))
        ctx_map.setdefault((engine, ids), []).append(name)
    gkey = (crs['engine_mode'], ())
    if gkey not in ctx_map:
        ctx_map[gkey] = []

    def seq_for(ids):
        out = []
        for a in rules:
            if a.phase > 2 or (a.id is not None and _in_ids(a.id, removed_global)):
                continue
            if a.source == 'crs' and not a.crs_eval:
                continue
            if a.source == 'plugin':
                continue
            if a.inline and a.id not in ids:
                continue
            out.append(a)
        out.sort(key=_seq_key)
        return out

    crs_detect = [a for a in rules if a.source == 'crs' and not a.crs_eval and a.phase <= 2 and _sev(a.r)]
    first_crs = min((a.order for a in crs_detect if a.phase == 2), default=None)
    first_eval = min((a.order for a in rules if a.crs_eval), default=None)
    crs_marker = (2, 1, first_crs if first_crs is not None else (first_eval if first_eval is not None else 10 ** 9))

    confident_ids = [a.id for a in rules if a.role == 'confident_block' and a.id is not None]
    contexts = []
    for (engine, ids), names in sorted(ctx_map.items(), key=lambda kv: (kv[0] != gkey, kv[0])):
        seq = seq_for(set(ids))
        thr = T
        sim = _Sim(seq, engine, thr, crs_marker)
        cands = sorted({0, max(T - 1, 0), T, T + 1} | {c['value'] + d for a in seq for c in a.conds
                                                       if c['type'] == 'score' and isinstance(c['value'], int)
                                                       for d in (0, 1)})
        cands = [c for c in cands if c >= 0]
        per = {}
        for src in ('external', 'internal'):
            below, _ = sim.run(src, max(T - 1, 0))
            over, _ = sim.run(src, T)
            conf = None
            if confident_ids:
                conf, _ = sim.run(src, 0, force=set(confident_ids))
            min_block = next((c for c in cands if sim.run(src, c)[0]['result'] == 'blocked'), None)
            min_flag = next((c for c in cands if sim.run(src, c)[0]['would_block_by'] or
                             sim.run(src, c)[0]['result'] == 'blocked'), None)
            conf_blocked = sum(1 for i in confident_ids if sim.run(src, 0, force={i})[0]['result'] == 'blocked')
            conf_applies = sum(1 for i in confident_ids if not any(_src_fail(c, src) for c in by_id[i].conds))
            per[src] = {'below': below, 'over': over, 'confident': conf, 'min_block_score': min_block,
                        'min_flag_score': min_flag,
                        'confident_blocked': conf_blocked, 'confident_total': len(confident_ids),
                        'confident_applies': conf_applies,
                        'mode': _mode(min_block, conf_blocked, conf_applies, engine)}
        contexts.append({'key': '%s:%s' % (engine, ','.join(map(str, ids))) if ids else engine,
                         'engine': engine, 'default': (engine, ids) == gkey, 'servers': names,
                         'inline_rule_ids': list(ids), 'outcomes': per, '_sim': sim})
    default_ctx = contexts[0]
    dsim = default_ctx['_sim']

    # --- per rule effect (default context) -------------------------------------------------------
    rows = []
    stage_rules = {}
    for a in rules:
        if a.source not in SITE_SOURCES and not (a.source == 'base' and a.disruptive) and not a.crs_eval:
            continue
        sim = next((c['_sim'] for c in contexts if a.id in c['inline_rule_ids']), dsim) if a.inline else dsim
        effect, effects = {}, {}
        for src in ('external', 'internal'):
            effs = set()
            if a.id is not None and _in_ids(a.id, removed_global):
                effect[src] = 'removed'
                effects[src] = ['removed']
                continue
            if a.phase > 2 or (a.inline and sim is dsim):
                # response-phase rules (and inline rules of no inspected vhost): what they do, not simulated
                effs.add(_static_effect(a))
                effect[src] = _rank(effs)
                effects[src] = [effect[src]]
                continue
            scen = [(0, {a.id}), (T, {a.id})]
            if not any(c['type'] in ('request', 'host') for c in a.conds):
                # rules driven by a flag / the score: also after a confident block matched
                scen.append((0, set(confident_ids) | {a.id}))
            for score, force in scen:
                res, trace = sim.run(src, score, force=force)
                tr = trace.get(a.id)
                if tr == 'blocked' or (res['result'] == 'blocked' and a.id in res['enabled_by']):
                    effs.add('blocks')
                elif tr == 'would_block':
                    effs.add('logs')
                elif tr == 'fired':
                    effs.add(_static_effect(a, fired=True))
                elif tr == 'not_applicable':
                    effs.add('not_applicable')
            effect[src] = _rank(effs) if effs else 'not_reached'
            real = [e for e in EFFECT_ORDER if e in effs and e not in ('not_reached', 'not_applicable')]
            effects[src] = real or [effect[src]]
        stage = 'crs_eval' if a.crs_eval else ROLE_STAGE.get(a.role, 'other')
        weakens = []
        for x in a.eff['removes_ids']:
            for b in rules:
                if b.id is not None and b is not a and _in_ids(b.id, [x]) and _blocking(b):
                    weakens.append(b.id)
        row = {'id': a.id, 'phase': a.phase, 'source': a.source, 'role': a.role, 'stage': stage,
               'msg': a.msg[:300], 'hosts': a.hosts[:10], 'conditions': a.conds[:8], 'effect': effect,
               'effects': effects,
               'actions': _action_summary(a), 'file': a.r.file, 'line': a.r.line, 'inline': a.inline,
               'weakens': sorted(set(weakens))}
        if a.inline:
            row['servers'] = [nm for c in contexts if a.id in c['inline_rule_ids'] for nm in c['servers']][:20]
        rows.append(row)
        stage_rules.setdefault(stage, []).append(row)
    removal_rows = []
    for i, rm in enumerate(m.removals):
        removal_rows.append({'id': None, 'key': 'removal-%d' % i, 'phase': 0, 'source': 'config', 'role': 'exclusion',
                             'stage': 'exclusions', 'directive': rm['directive'],
                             'target_ids': [x if isinstance(x, int) else str(x) for x in rm['target_ids']],
                             'args': (rm.get('args') or '')[:200], 'msg': '', 'hosts': [], 'conditions': [],
                             'effect': {'external': 'loosens', 'internal': 'loosens'},
                             'effects': {'external': ['loosens'], 'internal': ['loosens']}, 'file': rm['file'],
                             'line': rm['line'],
                             'weakens': sorted({b.id for b in rules if b.id is not None and _blocking(b)
                                                and rm['directive'] == 'SecRuleRemoveById'
                                                and _in_ids(b.id, _id_spec(rm['target_ids']))})})

    # --- CRS scoring numbers ----------------------------------------------------------------------
    levels = {lv: {s: 0 for s in SEVERITIES} for lv in (1, 2, 3, 4)}
    outbound = {s: 0 for s in SEVERITIES}
    removed_crs = 0
    for a in rules:
        if a.source != 'crs' or a.crs_eval or a.id is None or a.id < 910000:
            continue
        sev = _sev(a.r)
        if sev not in SEVERITIES:
            continue
        if _in_ids(a.id, removed_global):
            removed_crs += 1
            continue
        if '/RESPONSE-' in a.r.file or a.phase > 2:
            outbound[sev] += 1
            continue
        levels[min(max(_pl(a.r) or 1, 1), 4)][sev] += 1
    bpl, dpl = crs['blocking_paranoia_level'], crs['detection_paranoia_level']
    level_rows = [{'level': lv, 'counts': c, 'total': sum(c.values()),
                   'state': 'blocking' if lv <= bpl else ('detection' if lv <= dpl else 'inactive')}
                  for lv, c in sorted(levels.items())]
    examples = []
    for s in SEVERITIES:
        p = points[s]
        if p <= 0:
            continue
        need = max(1, math.ceil(T / p))
        for k in sorted({1, need}):
            sc = k * p
            examples.append({'severity': s, 'count': k, 'score': sc,
                             'outcome': {src: _brief(dsim.run(src, sc)[0]) for src in ('external', 'internal')}})
    overrides = [{'id': r['id'], 'role': r['role'], 'hosts': r['hosts'], 'servers': r.get('servers', []),
                  'set': by_id[r['id']].eff['threshold_set'] if r['id'] in by_id else {}}
                 for r in rows if r['role'] == 'threshold_override']

    # --- stages -------------------------------------------------------------------------------------
    def ids(stage):
        return [r['id'] for r in stage_rules.get(stage, []) if r['id'] is not None]

    def per_source(stage, extra=()):
        out = {}
        for src in ('external', 'internal'):
            effs = {r['effect'][src] for r in stage_rules.get(stage, [])} | set(extra)
            out[src] = _rank(effs) if effs else 'not_reached'
        return out

    def all_effects(stage):
        out = {}
        for src in ('external', 'internal'):
            effs = {e for r in stage_rules.get(stage, []) for e in r['effects'][src]}
            out[src] = [e for e in EFFECT_ORDER if e in effs] or [per_source(stage)[src]]
        return out

    def first(stage):
        rs = [by_id[i] for i in ids(stage) if i in by_id]
        return min(((a.phase, a.order) for a in rs), default=(9, 10 ** 9))

    stages = []
    ni_rules = ids('not_inspected')
    stages.append({'key': 'not_inspected', 'effect': 'not_inspected', 'phase': 0,
                   'rule_ids': ni_rules, 'count': len(not_inspected['servers']) + len(not_inspected['locations']) + len(ni_rules),
                   'per_source': {'external': 'not_inspected', 'internal': 'not_inspected'},
                   'conditions': [{'type': 'waf_off'}, {'type': 'location_off'}] + ([{'type': 'ctl_engine_off'}] if ni_rules else []),
                   'data': {'servers': not_inspected['servers'][:200], 'locations': not_inspected['locations'][:200]}, '_pos': (-1, 0)})
    mid = []
    if stage_rules.get('exclusions') or removal_rows or crs['plugins']:
        weak = sorted({w for r in stage_rules.get('exclusions', []) + removal_rows for w in r['weakens']})
        mid.append({'key': 'exclusions', 'effect': 'loosens', 'phase': 1, 'rule_ids': ids('exclusions'),
                    'count': len(ids('exclusions')) + len(removal_rows),
                    'per_source': per_source('exclusions', ['loosens'] if removal_rows else []),
                    'conditions': _typical(stage_rules.get('exclusions', [])),
                    'data': {'runtime': len(ids('exclusions')), 'config_time': len(removal_rows),
                             'plugins': [p['name'] for p in crs['plugins']], 'weakens': weak,
                             'by_role': _count(r['role'] for r in stage_rules.get('exclusions', []))},
                    '_pos': min(first('exclusions'), (1, -1) if removal_rows else (9, 10 ** 9))})
    for key in ('confident', 'site_scoring', 'threshold_block', 'fallback', 'deny_rules'):
        if stage_rules.get(key):
            rs = stage_rules[key]
            ps = per_source(key)
            mid.append({'key': key, 'effect': _rank(set(ps.values())), 'phase': min(r['phase'] for r in rs),
                        'rule_ids': ids(key), 'count': len(rs), 'per_source': ps, 'per_source_all': all_effects(key),
                        'conditions': _typical(rs), 'data': {'by_source': _count(_applies(r) for r in rs)},
                        '_pos': first(key)})
    detect_total = sum(lr['total'] for lr in level_rows if lr['state'] != 'inactive')
    mid.append({'key': 'crs_detect', 'effect': 'scores', 'phase': 2, 'rule_ids': [], 'count': detect_total,
                'per_source': {'external': 'scores', 'internal': 'scores'},
                'conditions': [{'type': 'paranoia', 'blocking': bpl, 'detection': dpl}],
                'data': {'points': points, 'levels': level_rows, 'removed': removed_crs}, '_pos': crs_marker})
    eval_rows = stage_rules.get('crs_eval', [])
    mid.append({'key': 'crs_eval', 'effect': 'blocks' if crs['engine_mode'] == 'On' else 'logs', 'phase': 2,
                'rule_ids': ids('crs_eval'), 'count': len(eval_rows),
                'per_source': per_source('crs_eval') if eval_rows else {'external': 'not_reached', 'internal': 'not_reached'},
                'per_source_all': all_effects('crs_eval'),
                'conditions': [{'type': 'score', 'direction': 'inbound', 'op': 'ge', 'value': 'threshold', 'threshold': T}],
                'data': {'threshold': T, 'overrides': overrides}, '_pos': (2, first_eval if first_eval is not None else crs_marker[1])})
    mid.sort(key=lambda s: s['_pos'])
    # the engine mode is what makes the CRS decision (and every deny) block or only log: right after it
    at = next((i for i, s in enumerate(mid) if s['key'] == 'crs_eval'), len(mid) - 1) + 1
    eng_eff = {'On': 'blocks', 'DetectionOnly': 'logs', 'Off': 'not_inspected'}.get(crs['engine_mode'], 'info')
    switched = {src: sorted({i for k in ('over', 'confident') if default_ctx['outcomes'][src][k]
                             for i in default_ctx['outcomes'][src][k]['enabled_by']}) for src in ('external', 'internal')}
    mid.insert(at, {'key': 'engine', 'effect': eng_eff, 'phase': None, 'rule_ids': [], 'count': len(contexts),
                    'per_source': {'external': eng_eff, 'internal': eng_eff},
                    'per_source_all': {src: [eng_eff] + (['blocks'] if switched[src] and eng_eff != 'blocks' else [])
                                       for src in ('external', 'internal')},
                    'conditions': [{'type': 'engine', 'mode': crs['engine_mode']}],
                    'data': {'global': crs['engine_mode'],
                             'contexts': [{'engine': c['engine'], 'servers': c['servers'][:50], 'default': c['default'],
                                           'inline_rule_ids': c['inline_rule_ids']} for c in contexts],
                             'enabled_by': switched},
                    '_pos': (2, 0)})
    stages.extend(mid)
    for key in ('settings', 'other'):
        if stage_rules.get(key):
            rs = stage_rules[key]
            stages.append({'key': key, 'effect': 'info', 'phase': min(r['phase'] for r in rs), 'rule_ids': ids(key),
                           'count': len(rs), 'per_source': per_source(key), 'conditions': _typical(rs),
                           'data': {'by_role': _count(r['role'] for r in rs)}, '_pos': (8, 0)})
    summary = {src: _summary(default_ctx['outcomes'][src]) for src in ('external', 'internal')}
    stages.append({'key': 'outcome', 'effect': 'info', 'phase': None, 'rule_ids': [], 'count': 0,
                   'per_source': {src: _mode_effect(summary[src]['mode']) for src in ('external', 'internal')},
                   'conditions': [], 'data': summary, '_pos': (9, 0)})
    for s in stages:
        s.pop('_pos', None)
        s['kind'] = s['key']
        s.setdefault('per_source_all', {src: [s['per_source'][src]] for src in ('external', 'internal')})
        real = set(s['per_source'].values()) - {'not_applicable', 'not_reached'}
        if s['key'] not in ('engine', 'outcome', 'settings', 'other') and real:
            s['effect'] = _rank(real)

    mismatch = sorted({r['id'] for r in rows for c in r['conditions']
                       if c['type'] == 'source' and c.get('missing_internal') and r['id'] is not None})
    unclassified = [r['id'] for r in rows if r['role'] == 'other' and r['id'] is not None]
    ctx_out = []
    for c in contexts:
        c = dict(c)
        c.pop('_sim')
        c['outcomes'] = {src: {k: (_brief(v) if isinstance(v, dict) and 'result' in v else v)
                               for k, v in o.items()} for src, o in c['outcomes'].items()}
        ctx_out.append(c)
    facts = [
        {'key': 'engine_global', 'value': crs['engine_mode']},
        {'key': 'effective_external', 'value': summary['external']['mode'], 'threshold': T,
         'score': summary['external']['min_block_score']},
        {'key': 'effective_internal', 'value': summary['internal']['mode'], 'threshold': T,
         'score': summary['internal']['min_block_score']},
        {'key': 'paranoia', 'value': bpl, 'detection': dpl},
        {'key': 'thresholds', 'value': T, 'outbound': crs['outbound_threshold']},
        {'key': 'vhosts_on', 'value': vh.get('on', 0) + vh.get('block', 0), 'total': vh['total']},
        {'key': 'vhosts_block', 'value': vh.get('block', 0)},
        {'key': 'vhosts_off', 'value': vh.get('off', 0) + vh.get('unknown', 0)},
        {'key': 'bypass_locations', 'value': vh['bypass_locations']},
        {'key': 'confident_rules', 'value': len(confident_ids)},
        {'key': 'exclusions', 'value': len(stage_rules.get('exclusions', [])) + len(removal_rows)},
    ]
    if mismatch:
        facts.append({'key': 'source_list_mismatch', 'value': len(mismatch), 'ids': mismatch[:50]})
    if unclassified:
        facts.append({'key': 'unclassified', 'value': len(unclassified), 'ids': unclassified[:50]})
    return {
        'generated_at': util.iso(util.now()),
        'engine': {'global': crs['engine_mode'], 'contexts': ctx_out},
        'crs': {'version': crs['version'], 'blocking_paranoia_level': bpl, 'detection_paranoia_level': dpl,
                'inbound_threshold': T, 'outbound_threshold': crs['outbound_threshold'],
                'eval_rule_ids': [a.id for a in rules if a.crs_eval], 'plugins': [p['name'] for p in crs['plugins']]},
        'scoring': {'threshold': T, 'outbound_threshold': crs['outbound_threshold'], 'points': points,
                    'points_from': points_from, 'levels': level_rows, 'outbound_counts': outbound,
                    'removed_crs_rules': removed_crs, 'examples': examples,
                    'min_block_score': {src: default_ctx['outcomes'][src]['min_block_score'] for src in ('external', 'internal')},
                    'min_flag_score': {src: default_ctx['outcomes'][src]['min_flag_score'] for src in ('external', 'internal')},
                    'threshold_overrides': overrides},
        'stages': stages,
        'rules': rows + removal_rows,
        'summary': summary,
        'facts': facts,
        'vhosts': {k: v for k, v in vh.items()},
        'internal_networks': [str(x) for x in cfg.internal_networks],
        'unclassified': unclassified,
    }


def _static_effect(a, fired=False):
    st = ROLE_STAGE.get(a.role, 'other')
    if a.crs_eval:
        return 'logs'
    e = ROLE_EFFECT.get(st, 'info')
    if a.role == 'plugin_toggle' and not any(p['enabled'] for p in a.eff['plugin_toggle']):
        return 'info'
    if st in ('confident', 'threshold_block', 'fallback') and fired:
        return 'scores' if a.eff['score_add'] and not a.disruptive else 'info'
    if st == 'deny_rules':
        return 'logs'
    return e


def _brief(res):
    return {'result': res['result'], 'by': res['by'], 'enabled_by': res['enabled_by'][:10],
            'would_block_by': [i for i in res['would_block_by'] if i is not None][:10],
            'allowed_by': res['allowed_by']}


def _mode(min_block, conf_blocked, conf_total, engine):
    if engine == 'Off':
        return 'off'
    if min_block is not None and (conf_total == 0 or conf_blocked == conf_total):
        return 'blocking'
    if min_block is not None or conf_blocked:
        return 'partial'
    return 'logging'


def _mode_effect(mode):
    return {'blocking': 'blocks', 'partial': 'blocks', 'logging': 'logs', 'off': 'not_inspected'}[mode]


def _summary(o):
    return {'mode': o['mode'], 'min_block_score': o['min_block_score'], 'min_flag_score': o['min_flag_score'],
            'over_by': o['over']['by'], 'over_result': o['over']['result'], 'over_enabled_by': o['over']['enabled_by'][:10],
            'over_would_block_by': [i for i in o['over']['would_block_by'] if i is not None][:10],
            'below_result': o['below']['result'],
            'confident_blocked': o['confident_blocked'], 'confident_total': o['confident_total'],
            'confident_applies': o['confident_applies'],
            'confident_by': o['confident']['by'] if o['confident'] else None}


def _action_summary(a):
    e = a.eff
    out = []
    if a.disruptive:
        out.append(a.disruptive)
    elif e['allow']:
        out.append('allow')
    if e['engine']:
        out.append('ctl:ruleEngine=' + e['engine'])
    if e['score_add']:
        out.append('score +%d' % e['score_add'])
    for k, v in sorted(e['flags'].items()):
        out.append('tx.%s=%d' % (k[:40], v))
    for x in e['removes_ids']:
        out.append('remove %s' % (x if isinstance(x, int) else '%d-%d' % tuple(x)))
    out.extend('remove tag %s' % x for x in e['removes_tags'][:5])
    out.extend('remove target %s' % x for x in e['removes_targets'][:5])
    if e['body_access_off']:
        out.append('requestBodyAccess=Off')
    if e['body_processor']:
        out.append('requestBodyProcessor=' + e['body_processor'])
    for k, v in e['threshold_set'].items():
        out.append('%s threshold=%d' % (k, v))
    for k, v in e['paranoia_set'].items():
        out.append('%s=%d' % (k, v))
    for p in e['plugin_toggle']:
        out.append('plugin %s %s' % (p['plugin'], 'on' if p['enabled'] else 'off'))
    out.extend('set %s' % x for x in e['policy'][:5])
    return out[:20]


def _applies(row):
    for c in row['conditions']:
        if c['type'] == 'source':
            return c['applies']
    return 'all'


def _typical(rows):
    seen, out = set(), []
    for r in rows:
        for c in r['conditions']:
            k = c['type'] + ':' + str(c.get('applies') or c.get('name') or c.get('value') or '')
            if c['type'] in ('request', 'host'):
                k = c['type']
            if k not in seen:
                seen.add(k)
                out.append({x: y for x, y in c.items() if x in ('type', 'applies', 'name', 'value', 'op', 'direction')})
    return out[:6]


def _count(xs):
    out = {}
    for x in xs:
        out[x] = out.get(x, 0) + 1
    return out
