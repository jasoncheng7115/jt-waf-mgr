"""Read-only ModSecurity v3 configuration parser: rules, removals, engine settings, CRS status."""
import glob
import os
import collections
import re

from . import util

RULE_DIRECTIVES = ('SecRule', 'SecAction')
REMOVAL_DIRECTIVES = ('SecRuleRemoveById', 'SecRuleRemoveByTag', 'SecRuleRemoveByMsg',
                      'SecRuleUpdateTargetById', 'SecRuleUpdateTargetByTag', 'SecRuleUpdateActionById')
DISRUPTIVE = ('deny', 'block', 'pass', 'allow', 'drop', 'redirect')


def logical_lines(text):
    """Joins backslash continuations. Yields (line_no, text, preceding_comments)."""
    comments = []
    buf, start = [], None
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.rstrip()
        if not buf:
            st = s.strip()
            if not st:
                comments = []
                continue
            if st.startswith('#'):
                comments.append(st.lstrip('#').strip())
                continue
            start = i
        if s.endswith('\\'):
            buf.append(s[:-1])
            continue
        buf.append(s)
        yield start, '\n'.join(buf), comments[-20:]
        buf, comments = [], []
    if buf:
        yield start, '\n'.join(buf), comments[-20:]


def split_args(s):
    """Splits a directive line into words, honouring "..." and '...' quoting."""
    out, i, n = [], 0, len(s)
    while i < n:
        while i < n and s[i] in ' \t\n\r':
            i += 1
        if i >= n:
            break
        if s[i] in '"\'':
            q, j, buf = s[i], i + 1, []
            while j < n and s[j] != q:
                if s[j] == '\\' and j + 1 < n and s[j + 1] == q:
                    buf.append(q)
                    j += 2
                    continue
                buf.append(s[j])
                j += 1
            out.append(''.join(buf))
            i = j + 1
        else:
            j = i
            while j < n and s[j] not in ' \t\n\r':
                j += 1
            out.append(s[i:j])
            i = j
    return out


def split_actions(s):
    """'id:1,phase:2,msg:\\'a, b\\',t:none' -> [('id','1'), ('phase','2'), ('msg','a, b'), ('t','none')]"""
    out, cur, q = [], [], False
    i = 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            cur.append(s[i:i + 2])
            i += 2
            continue
        if c == "'":
            q = not q
        if c == ',' and not q:
            out.append(''.join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        out.append(''.join(cur))
    res = []
    for a in out:
        a = a.strip()
        if not a:
            continue
        k, _, v = a.partition(':')
        v = v.strip()
        if len(v) >= 2 and v[0] == "'" and v[-1] == "'":
            v = v[1:-1]
        res.append((k.strip().lower(), v))
    return res


class Rule:
    def __init__(self, directive, file, line, comment, text, parts):
        self.directive = directive
        self.file = file
        self.line = line
        self.comment = comment
        self.text = text
        self.parts = parts          # list of (variables, operator, actions) for SecRule chain elements
        self.actions = parts[0][2] if parts else []
        self.id = None
        for k, v in self.actions:
            if k == 'id':
                try:
                    self.id = int(v.strip("'\""))
                except ValueError:
                    pass

    def action(self, key):
        for k, v in self.actions:
            if k == key:
                return v
        return None

    def all_actions(self):
        for _, _, acts in self.parts:
            yield from acts

    def chained(self):
        return any(k == 'chain' for k, _ in self.actions) if self.parts else False


def parse_rules_text(text, file, out_rules, out_removals, out_settings, includes):
    pending = None
    for line, s, comments in logical_lines(text):
        words = split_args(s)
        if not words:
            continue
        d = words[0]
        if d.lower() == 'include' and len(words) > 1:
            includes.append((words[1], file, line))
            continue
        if d in RULE_DIRECTIVES:
            if d == 'SecRule':
                if len(words) < 3:
                    continue
                part = (words[1], words[2], split_actions(words[3]) if len(words) > 3 else [])
            else:
                part = ('', '', split_actions(words[1]) if len(words) > 1 else [])
            if pending is not None:
                pending.parts.append(part)
                pending.text += '\n' + s
                if not any(k == 'chain' for k, _ in part[2]):
                    out_rules.append(pending)
                    pending = None
                continue
            r = Rule(d, file, line, '\n'.join(comments), s, [part])
            if r.chained():
                pending = r
            else:
                out_rules.append(r)
            continue
        if d in REMOVAL_DIRECTIVES:
            ids = []
            if d in ('SecRuleRemoveById', 'SecRuleUpdateTargetById', 'SecRuleUpdateActionById'):
                for w in (words[1:] if d == 'SecRuleRemoveById' else words[1:2]):
                    for p in w.split(','):
                        p = p.strip()
                        m = re.fullmatch(r'(\d+)-(\d+)', p)
                        if m:
                            ids.append('%s-%s' % m.groups())
                        elif p.isdigit():
                            ids.append(int(p))
            out_removals.append({'directive': d, 'target_ids': ids,
                                 'args': ' '.join(words[1:] if d.startswith('SecRuleRemove') and d != 'SecRuleRemoveById' else words[2:]),
                                 'file': file, 'line': line, 'comment': '\n'.join(comments)})
            continue
        if d.startswith('Sec') and len(words) > 1:
            out_settings.append((d, ' '.join(words[1:]), file, line))
    if pending is not None:
        out_rules.append(pending)


class ModsecConfig:
    def __init__(self, nginx, cfg):
        self.cfg = cfg
        self.nginx = nginx
        self.rules = []
        self.removals = []
        self.settings = []
        self.inline_settings = []
        self.errors = []
        self.files = {}
        self.warnings = []
        self.main_files = []
        seen_main = set()
        for path, file, line, ctx in nginx.modsec_rules_files():
            if any(c.startswith('server') for c in ctx):
                self.warnings.append('rules_file_per_vhost:%s:%d' % (file, line))
            if not os.path.isabs(path):
                path = os.path.join(nginx.prefix, path)
            if path not in seen_main:
                seen_main.add(path)
                self.main_files.append(path)
                self._load(path, 0)
        for text, file, line, ctx in nginx.inline_rules():
            rules = []
            # settings inside a vhost (e.g. SecRuleEngine On for block mode) are not global
            parse_rules_text(text, file, rules, self.removals, self.inline_settings, [])
            for r in rules:
                r.line = line
                r.inline = True
                r.context = ctx
            self.rules.extend(rules)

    def _load(self, path, depth):
        if depth > 10:
            return
        for f in sorted(glob.glob(path)) if glob.has_magic(path) else [path]:
            if f in self.files:
                continue
            try:
                with open(f, encoding='utf-8', errors='replace') as fh:
                    text = fh.read()
                self.files[f] = os.stat(f).st_mtime
            except OSError as e:
                if not glob.has_magic(path):
                    self.errors.append('%s: %s' % (f, e.strerror))
                continue
            includes = []
            parse_rules_text(text, f, self.rules, self.removals, self.settings, includes)
            for inc, _, _ in includes:
                p = inc if os.path.isabs(inc) else os.path.join(os.path.dirname(f), inc)
                self._load(p, depth + 1)

    # --- classification -----------------------------------------------------------------
    def source_of(self, r):
        if getattr(r, 'inline', False):
            return 'vhost_inline'
        f = r.file.replace('\\', '/')
        if '/rules/REQUEST-' in f or '/rules/RESPONSE-' in f or re.search(r'/crs[^/]*/rules/', f):
            return 'crs'
        if '/plugins/' in f:
            return 'plugin'
        if r.id is not None and 200000 <= r.id <= 200099 or os.path.basename(f) == 'modsecurity.conf':
            return 'base'
        if os.path.basename(f).startswith('crs-setup') or (r.id and 900000 <= r.id <= 900999):
            return 'crs'
        return 'local'

    def category_of(self, r):
        acts = list(r.all_actions())
        keys = [k for k, _ in acts]
        ctl = [v for k, v in acts if k == 'ctl']
        lo, hi = self.cfg['waf']['confident_range']
        tags = [v for k, v in acts if k == 'tag']
        if r.id is not None and (r.id in self.cfg['waf']['threshold_rule_ids'] or r.id in self.cfg['waf']['fallback_rule_ids']):
            return 'system'
        if r.id is not None and lo <= r.id <= hi or any('confident' in t for t in tags):
            return 'confident_block'
        if any(re.match(r'ruleRemove', c) for c in ctl):
            redaction = any(re.search(r';(?:ARGS|ARGS_POST|REQUEST_BODY)', c) and util.Redactor(self.cfg.sensitive).is_sensitive(
                c.split(':', 1)[-1].split(';')[-1]) for c in ctl)
            return 'redaction' if redaction else 'exclusion'
        if any('plugin_enabled' in v for k, v in acts if k == 'setvar'):
            return 'plugin_toggle'
        if any(c.startswith('requestBodyProcessor') for c in ctl) or any(
                v.startswith("'tx.allowed") or v.startswith('tx.allowed') for k, v in acts if k == 'setvar'):
            return 'system'
        if 'deny' in keys or 'drop' in keys:
            return 'confident_block' if self.source_of(r) == 'local' else 'other'
        return 'other'

    def hosts_of(self, r):
        hosts = []
        for var, op, _ in r.parts:
            v = var.upper()
            if 'REQUEST_HEADERS:HOST' in v or v.startswith('SERVER_NAME'):
                m = re.match(r'@?(\w+)\s+(.*)$', op.strip()) if op.strip().startswith('@') else None
                param = m.group(2) if m else op
                hosts.append(readable_host(param))
        return hosts

    def rule_dict(self, r):
        acts = list(r.all_actions())
        disruptive = next((k for k, _ in r.actions if k in DISRUPTIVE), None)
        phase = r.action('phase')
        try:
            phase = int(phase) if phase and phase.isdigit() else {'request': 2, 'response': 4, 'logging': 5}.get(phase, phase)
        except ValueError:
            pass
        sev = r.action('severity')
        return {'id': r.id, 'file': r.file, 'line': r.line, 'directive': r.directive,
                'phase': phase, 'disruptive': disruptive, 'msg': r.action('msg') or '',
                'tags': [v for k, v in acts if k == 'tag'][:30], 'severity': sev,
                'source': self.source_of(r), 'managed': False, 'category': self.category_of(r),
                'hosts': self.hosts_of(r), 'comment': r.comment, 'text': r.text}

    def rule_states(self):
        """rule id -> {'state', ...}: whether each loaded rule really runs.
        off: removed for every request (SecRuleRemoveById / ByTag / ByMsg); partial: removed by a ctl:ruleRemoveById /
        ByTag inside a rule (for some sites, paths or sources; 'hosts' lists the sites, '*' = not by site);
        inactive: a CRS rule above the paranoia level (CRS skips it); on: everything else. Cached per load."""
        if getattr(self, '_states', None) is not None:
            return self._states
        pl = self.tx_setvar(900000, 'blocking_paranoia_level') or self.tx_setvar(900000, 'paranoia_level') or 1
        dpl = max(pl, self.tx_setvar(900001, 'detection_paranoia_level') or pl)
        ids, ranges, tags, msgs = {}, [], [], []
        for rm in self.removals:
            where = '%s:%s' % (rm['file'], rm['line'])
            if rm['directive'] == 'SecRuleRemoveById':
                for t in rm['target_ids']:
                    if isinstance(t, int):
                        ids[t] = where
                    else:
                        lo, hi = t.split('-')
                        ranges.append((int(lo), int(hi), where))
            elif rm['directive'] in ('SecRuleRemoveByTag', 'SecRuleRemoveByMsg'):
                pat = rm['args'].strip().strip('"\'')
                (tags if rm['directive'] == 'SecRuleRemoveByTag' else msgs).append((pat, where))
        p_ids, p_tags = collections.defaultdict(set), collections.defaultdict(set)
        for r in self.rules:
            if self.source_of(r) == 'crs':
                # CRS's own mechanics (sampling 901450, the localhost exceptions 9051xx) remove "OWASP_CRS" for a
                # few internal requests: not an exclusion of the site's, or every CRS rule would look switched off
                continue
            for k, v in r.all_actions():
                if k != 'ctl':
                    continue
                m = re.match(r'ruleRemoveById\s*=\s*([\d,\s-]+)$', v)
                t = re.match(r'ruleRemoveByTag\s*=\s*(.+)$', v)
                hosts = set(self.hosts_of(r)) or {'*'}
                if m:
                    for part in m.group(1).split(','):
                        part = part.strip()
                        if re.fullmatch(r'\d+', part):
                            p_ids[int(part)] |= hosts
                        elif re.fullmatch(r'\d+-\d+', part):
                            lo, hi = map(int, part.split('-'))
                            if hi - lo <= 100000:
                                for i in range(lo, hi + 1):
                                    p_ids[i] |= hosts
                elif t:
                    p_tags[t.group(1).strip().strip('"\'')] |= hosts

        def tag_hit(pat, rtags):
            for x in rtags:
                if x == pat:
                    return True
                try:
                    if re.search(pat, x):
                        return True
                except re.error:
                    pass
            return False
        out = {}
        for r in self.rules:
            if r.id is None:
                continue
            rtags = [v for k, v in r.all_actions() if k == 'tag']
            msg = r.action('msg') or ''
            where = ids.get(r.id) or next((w for lo, hi, w in ranges if lo <= r.id <= hi), None) \
                or next((w for pat, w in tags if tag_hit(pat, rtags)), None) \
                or next((w for pat, w in msgs if pat and pat in msg), None)
            if where:
                out[r.id] = {'state': 'off', 'where': where}
                continue
            lvl = next((int(m.group(1)) for x in rtags for m in [re.match(r'paranoia-level/(\d)$', x)] if m), None)
            if self.source_of(r) == 'crs' and lvl and lvl > dpl:      # not evaluated at all: exclusions do not matter
                out[r.id] = {'state': 'inactive', 'level': lvl, 'paranoia_level': dpl}
                continue
            hosts = set(p_ids.get(r.id, ()))
            for pat, hs in p_tags.items():
                if tag_hit(pat, rtags):
                    hosts |= hs
            if hosts:
                out[r.id] = {'state': 'partial', 'hosts': sorted(hosts)[:20]}
                continue
            out[r.id] = {'state': 'on'}
        self._states = out
        return out

    def setting(self, name, default=None):
        v = default
        for d, val, _, _ in self.settings:
            if d == name:
                v = val
        return v

    def tx_setvar(self, rule_id, var):
        for r in self.rules:
            if r.id == rule_id:
                for k, v in r.all_actions():
                    if k == 'setvar':
                        m = re.match(r"'?tx\.%s=(\d+)'?$" % re.escape(var), v)
                        if m:
                            return int(m.group(1))
        return None

    def crs_status(self):
        crs_dir = None
        version = None
        rule_files = set()
        crs_rules = 0
        for r in self.rules:
            if self.source_of(r) == 'crs' and '/rules/' in r.file:
                rule_files.add(r.file)
                crs_rules += 1
                if crs_dir is None:
                    crs_dir = os.path.dirname(os.path.dirname(r.file))
            if version is None:
                ver = r.action('ver')
                if ver and ver.startswith('OWASP_CRS/'):
                    version = ver.split('/', 1)[1]
        if crs_dir:
            real = os.path.realpath(crs_dir)
            m = re.search(r'(\d+\.\d+\.\d+)', os.path.basename(real))
            if m and not version:
                version = m.group(1)
        setup = next((f for f in self.files if os.path.basename(f).startswith('crs-setup')), None)
        pl = self.tx_setvar(900000, 'blocking_paranoia_level') or self.tx_setvar(900000, 'paranoia_level') or 1
        dpl = self.tx_setvar(900001, 'detection_paranoia_level') or pl
        inbound = self.tx_setvar(900110, 'inbound_anomaly_score_threshold') or 5
        outbound = self.tx_setvar(900110, 'outbound_anomaly_score_threshold') or 4
        plugins = {}
        for f in self.files:
            if '/plugins/' in f:
                base = os.path.basename(f)
                name = re.sub(r'-(config|before|after)\.conf$', '', base)
                plugins.setdefault(name, []).append(base)
        lim = self.setting('SecRequestBodyLimit')
        return {
            'version': version, 'path': crs_dir, 'setup_file': setup,
            'paranoia_level': pl, 'blocking_paranoia_level': pl, 'detection_paranoia_level': dpl,
            'inbound_threshold': inbound, 'outbound_threshold': outbound,
            'engine_mode': self.setting('SecRuleEngine', 'DetectionOnly'),
            'request_body_access': (self.setting('SecRequestBodyAccess', 'Off') or '').lower() == 'on',
            'request_body_limit': int(lim) if lim and lim.isdigit() else None,
            'request_body_limit_action': self.setting('SecRequestBodyLimitAction'),
            'pcre_match_limit': _int(self.setting('SecPcreMatchLimit')),
            'audit': {'engine': self.setting('SecAuditEngine'), 'parts': self.setting('SecAuditLogParts'),
                      'format': self.setting('SecAuditLogFormat'), 'log': self.setting('SecAuditLog'),
                      'relevant_status': self.setting('SecAuditLogRelevantStatus')},
            'plugins': [{'name': k, 'files': sorted(v)} for k, v in sorted(plugins.items())],
            'rule_files': len(rule_files), 'rule_count': crs_rules,
            'warnings': self.status_warnings(),
        }

    def status_warnings(self):
        w = list(self.warnings)
        if (self.setting('SecAuditLogFormat') or '').upper() != 'JSON':
            w.append('audit_log_not_json')
        if (self.setting('SecAuditEngine') or '').lower() == 'off':
            w.append('audit_engine_off')
        return w

    def external_threshold_block(self):
        for r in self.rules:
            if any('BLOCKING_INBOUND_ANOMALY_SCORE' in var.upper() or 'INBOUND_ANOMALY_SCORE' in var.upper()
                   for var, _, _ in r.parts) and any(k == 'ctl' and v.lower().startswith('ruleengine=on')
                                                     for k, v in r.all_actions()):
                return True
        return False


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def readable_host(param):
    """'^app\\.example\\.com(?::[0-9]+)?$' -> 'app.example.com'; other regexes are kept as is."""
    p = param.strip()
    p = re.sub(r'\(\?::\[0-9\]\+\)\?', '', p)
    p = re.sub(r'\(\?::\\d\+\)\?', '', p)
    core = p.lstrip('^').rstrip('$')
    plain = core.replace('\\.', '.').replace('\\-', '-')
    if re.fullmatch(r'[A-Za-z0-9.-]+', plain):
        return plain.lower()
    return p
