"""Rule templates -> SecRule text, static checks, and change direction.

Every generated rule has a fixed shape, the same as the hand-written site rules it replaces:

  confident block   SecRule <target> "@rx ..." "id:N,phase:1,pass,log,...,msg:'jt confident block: ...',
                    tag:'jt-confident-block',chain"  ...  SecRule REMOTE_ADDR "!@ipMatch <internal>"
                    "t:none,setvar:tx.jt_block=1,ctl:ruleEngine=On"
                    (the system rules add the critical score so that CRS's 949110 decides, and refuse
                    what stays under the threshold)
  exclusion         a phase-1 chain on Host / path / method / source ending in ctl:ruleRemove...
  redaction         ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:<field> for each field (not inspected,
                    so never copied into the audit log)
  plugin toggle     setvar:'tx.<plugin>-plugin_enabled=1' for one Host
  raw               expert mode: SecRule text as written, checked against a forbidden list
  country           Host -> REMOTE_ADDR "!@ipMatchFromFile <rules_dir>/<SET>.data" (allow: only these countries) or
                    "@ipMatchFromFile ..." (deny) -> REMOTE_ADDR "!@ipMatch <never blocked>" -> jt_block, like a
                    confident block; the list file is written by the root program (countries.py)
"""
import ipaddress
import os
import re
import subprocess
import sys

from .modsecconf import logical_lines, split_actions, split_args

KINDS = ('exclusion', 'confident_block', 'redaction', 'plugin', 'raw', 'country')
EXCLUSION_ACTIONS = ('remove_target_by_id', 'remove_target_by_tag', 'remove_rule', 'remove_tag', 'score_only',
                     'body_processor')
BLOCK_TARGETS = {
    # target -> (variable, transformations)
    'path': ('REQUEST_FILENAME', 't:none,t:urlDecodeUni,t:normalizePath,t:lowercase'),
    'uri': ('REQUEST_URI', 't:none,t:urlDecodeUni,t:lowercase'),
    'ua': ('REQUEST_HEADERS:User-Agent', 't:none,t:lowercase'),
    'host': ('REQUEST_HEADERS:Host', 't:none,t:lowercase'),
    'header': (None, 't:none'),
}
TARGET_RE = re.compile(r'^(?:ARGS|ARGS_GET|ARGS_POST|ARGS_NAMES|ARGS_GET_NAMES|ARGS_POST_NAMES|REQUEST_COOKIES|'
                       r'REQUEST_COOKIES_NAMES|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|XML|REQUEST_BODY|REQUEST_URI|'
                       r'REQUEST_URI_RAW|REQUEST_FILENAME|REQUEST_BASENAME|FILES|FILES_NAMES|QUERY_STRING)'
                       r'(?::[A-Za-z0-9_.\-\[\]/@$^*|()?\\]{1,128})?$')
TAG_RE = re.compile(r'^[A-Za-z0-9_./\-]{1,80}$')
HEADER_RE = re.compile(r'^[A-Za-z0-9-]{1,64}$')
PLUGIN_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,63}$')
HOST_RE = re.compile(r'^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)*$')
SAFE_TEXT_RE = re.compile(r'^[^\'"\\\x00-\x1f\x7f]*$')
BENIGN = ['/', '/index.html', '/api/v1/items?page=2', '/static/app.3f9a.js', '/login',
          'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/130.0 safari/537.36',
          'app.example.com', '/images/logo.png', '/search?q=hello+world']

# Expert mode: what a raw rule may never do (SPEC 5.6), plus what the apply program refuses too.
FORBIDDEN = [
    (re.compile(r'^\s*SecRuleEngine\s+Off\b', re.I | re.M), 'SecRuleEngine Off'),
    (re.compile(r'ctl:\s*ruleEngine\s*=\s*Off', re.I), 'ctl:ruleEngine=Off'),
    (re.compile(r'\bexec\s*:', re.I), 'exec action'),
    (re.compile(r'^\s*SecAudit\w*', re.I | re.M), 'audit settings'),
    (re.compile(r'ctl:\s*auditEngine', re.I), 'ctl:auditEngine'),
    (re.compile(r'ctl:\s*auditLogParts', re.I), 'ctl:auditLogParts'),
    (re.compile(r'^\s*SecRequestBodyAccess\s+Off\b', re.I | re.M), 'SecRequestBodyAccess Off'),
    (re.compile(r'\bsetenv\s*:', re.I), 'setenv'),
    (re.compile(r'^\s*Include\b', re.I | re.M), 'Include'),
    (re.compile(r'^\s*Sec(?:DataDir|TmpDir|UploadDir|DebugLog\w*|Collection\w*|Remote\w*|ComponentSignature|'
                r'ArgumentSeparator|CookieFormat|UnicodeMapFile|PcreMatchLimit\w*|RequestBody\w*|ResponseBody\w*|'
                r'StatusEngine|ServerSignature|HttpBlKey|GeoLookupDb|GsbLookupDb|WebAppId|Default\w*)\b',
                re.I | re.M), 'engine-wide setting'),
    # @pmFromFile / @ipMatchFromFile are allowed only for a .data file in the ModSecurity configuration
    # directory (e.g. the CRS's own lists): see _data_file_ok(); every other file-reading operator is refused
    (re.compile(r'@(?!(?:pm|ipMatch)FromFile\b)\w*FromFile\b', re.I), 'operators reading files'),
    (re.compile(r'@inspectFile\b', re.I), '@inspectFile'),
]
DATA_FILE_OP = re.compile(r'@(?:pm|ipMatch)FromFile\s+([^\s"\']+)', re.I)
DATA_FILE_DIRS = ('/etc/nginx/modsec/', '/etc/modsecurity/', '/usr/share/modsecurity-crs/')


def _data_file_ok(path, cfg=None):
    """A list file the rule reads: an absolute path to a .data file below a ModSecurity configuration
    directory, no '..', no URL (@pmFromFile can fetch https:// lists — never from here)."""
    if re.fullmatch(r'[\w.-]+\.data', path) and not path.startswith('.'):
        return True          # a bare file name: next to the rule file, inside the configuration directory
    if cfg is not None:      # a country list written by the root program (countries.rules_dir, from config.toml)
        d = cfg['countries']['rules_dir'].rstrip('/') + '/'
        rest = path[len(d):] if path.startswith(d) else ''
        if re.fullmatch(r'[A-Z]{2}(?:-[A-Z]{2}){0,49}\.data', rest):
            return True
    return (path.startswith('/') and path.endswith('.data') and '..' not in path.split('/')
            and re.fullmatch(r'[\w./-]+', path) is not None and any(path.startswith(d) for d in DATA_FILE_DIRS))


ALLOWED_DIRECTIVES = ('SecRule', 'SecAction', 'SecRuleRemoveById', 'SecRuleRemoveByTag', 'SecRuleRemoveByMsg',
                      'SecRuleUpdateTargetById', 'SecRuleUpdateTargetByTag', 'SecRuleUpdateActionById', 'SecMarker')


class SpecError(ValueError):
    def __init__(self, field, code, **details):
        super().__init__('%s: %s' % (field, code))
        self.field = field
        self.code = code
        self.details = details


def _ip_list(networks):
    return ','.join(str(n) if n.prefixlen != n.max_prefixlen or n.version == 4 else str(n.network_address)
                    for n in networks)


def _regex_ok(field, rx, allow_broad=False):
    if not isinstance(rx, str) or not rx.strip():
        raise SpecError(field, 'empty')
    if len(rx) > 1000:
        raise SpecError(field, 'too_long')
    if not SAFE_TEXT_RE.match(rx.replace('\\', '').replace("'", '')) or '"' in rx or '\n' in rx:
        raise SpecError(field, 'forbidden_character')
    try:
        c = re.compile(rx)
    except re.error as e:
        raise SpecError(field, 'invalid_regex', error=str(e)[:200])
    if not allow_broad:
        if c.search('') is not None:
            raise SpecError(field, 'matches_empty')
        if sum(1 for b in BENIGN if c.search(b)) >= len(BENIGN) - 2:
            raise SpecError(field, 'too_broad')
    if redos_shape(rx):
        raise SpecError(field, 'redos_shape')
    if not redos_runtime_ok(rx):
        raise SpecError(field, 'redos_runtime')
    return rx


def redos_shape(rx):
    """Nested quantifiers and quantified alternations of quantified branches: refuse the shape."""
    s = re.sub(r'\\.', 'x', rx)                     # drop escapes
    s = re.sub(r'\[[^\]]*\]', 'x', s)               # character classes -> one char
    # a group whose body ends with a quantifier, quantified again: (a+)+ (\w*)* (x{2,})+
    if re.search(r'\([^()]*[+*}]\)\s*[+*{]', s):
        return True
    # (a|ab)* style: quantified group with alternation where a branch is itself quantified
    for m in re.finditer(r'\(([^()]*\|[^()]*)\)\s*[+*{]', s):
        if re.search(r'[+*}]', m.group(1)):
            return True
    return False


_REDOS_OK = {}     # regex -> True (passed); only passes are remembered, a failure is checked again


def redos_runtime_ok(rx, timeout=2.0):
    """Run the regex on long hostile strings in a subprocess; False if it does not finish in time."""
    if _REDOS_OK.get(rx):
        return True
    ok = _redos_run(rx, timeout)
    if ok:
        if len(_REDOS_OK) > 5000:
            _REDOS_OK.clear()
        _REDOS_OK[rx] = True
    return ok


def _redos_run(rx, timeout):
    code = ('import re,sys\nr=re.compile(sys.stdin.read())\n'
            'for s in ("a"*20000+"!", "/"*20000+"x", "%2e"*5000+"\\x00", "a/"*10000, " "*20000+"x", "0"*20000+"z"):\n'
            '    r.search(s)\n')
    try:
        p = subprocess.run([sys.executable, '-I', '-c', code], input=rx, text=True, capture_output=True, timeout=timeout)
        return p.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _text_ok(field, s, maxlen=160, required=False):
    if s is None or s == '':
        if required:
            raise SpecError(field, 'required')
        return ''
    if not isinstance(s, str) or len(s) > maxlen or not SAFE_TEXT_RE.match(s):
        raise SpecError(field, 'invalid_text', max_length=maxlen)
    return s


# the Host header as nginx accepts it for the site: "name", "name." (a trailing dot), "name:443", "name.:443". A full URL
# in the request line ("GET http://name/ HTTP/1.1") routes by that URL, but nginx gives ModSecurity the path only, so no
# ModSecurity rule can see it: a site whose country limit must hold for such requests needs the check in nginx too.
HOST_RX_FMT = r'^%s\.?(?::[0-9]*)?$'


def _host_cond(host):
    """{'mode': 'exact'|'regex'|'any', 'value': ...} -> (variable, operator, transforms) or None"""
    if not host or host.get('mode', 'any') == 'any':
        return None
    mode, v = host.get('mode'), (host.get('value') or '').strip().lower()
    if mode == 'exact':
        if not HOST_RE.match(v):
            raise SpecError('host', 'invalid_host')
        pat = re.escape(v).replace('\\*', '[^.]+') if v.startswith('*.') else re.escape(v)
        # nginx serves the site for its name with a trailing dot too ("example.com."): that form must match, or a rule
        # scoped to the site (a country limit, a block) is skipped for it
        return ('REQUEST_HEADERS:Host', '@rx ' + HOST_RX_FMT % pat.replace('\\-', '-'), 't:none,t:lowercase')
    if mode == 'regex':
        _regex_ok('host', v)
        return ('REQUEST_HEADERS:Host', '@rx ' + v, 't:none,t:lowercase')
    raise SpecError('host', 'invalid_mode')


def _path_cond(path, negate=False):
    if not path or path.get('mode', 'any') == 'any':
        return None
    mode, v = path.get('mode'), path.get('value') or ''
    if mode in ('exact', 'prefix'):
        if not v.startswith('/') or len(v) > 512 or re.search(r'[\s"\'\\\x00-\x1f\x7f]', v):
            raise SpecError('path', 'invalid_path')
        op = '@streq ' if mode == 'exact' else '@beginsWith '
        return ('REQUEST_FILENAME', ('!' if negate else '') + op + v, 't:none')
    if mode == 'regex':
        _regex_ok('path', v)
        return ('REQUEST_FILENAME', ('!' if negate else '') + '@rx ' + v, 't:none')
    raise SpecError('path', 'invalid_mode')


def _source_cond(source, internal):
    if source in (None, '', 'all'):
        return None
    if source == 'internal':
        return ('REMOTE_ADDR', '@ipMatch ' + internal, 't:none')
    if source == 'external':
        return ('REMOTE_ADDR', '!@ipMatch ' + internal, 't:none')
    raise SpecError('source', 'invalid_source')


def _chain(conds, first_actions, final_actions):
    """conds: [(var, op, transforms)], at least one. Returns SecRule text (continuation lines)."""
    lines = []
    n = len(conds)
    for i, (var, op, tr) in enumerate(conds):
        ind = '    ' * i
        acts = []
        if i == 0:
            acts.append(first_actions)
        acts.append(tr)
        if i < n - 1:
            acts.append('chain')
        else:
            if final_actions:
                acts.append(final_actions)
        a = ','.join(x for x in acts if x)
        lines.append('%sSecRule %s "%s" \\\n%s    "%s"' % (ind, var, op.replace('"', '\\"'), ind, a))
    return '\n'.join(lines)


def build(kind, spec, rule_id, cfg):
    """Returns (normalized spec, rule text, placement). Raises SpecError."""
    internal = _ip_list(cfg.internal_networks)
    if kind == 'exclusion':
        return _exclusion(spec, rule_id, cfg, internal)
    if kind == 'confident_block':
        return _confident(spec, rule_id, cfg, internal)
    if kind == 'redaction':
        return _redaction(spec, rule_id, cfg)
    if kind == 'plugin':
        return _plugin(spec, rule_id)
    if kind == 'raw':
        return _raw(spec, rule_id, cfg)
    if kind == 'country':
        return _country(spec, rule_id, cfg)
    raise SpecError('kind', 'unknown_kind')


def never_list(cfg):
    """Addresses a country rule never refuses: the internal networks, the known scanners, the trusted proxies and
    the protected list (a CDN in front of a site: its own addresses are in no country list of the site's users)."""
    nets = list(cfg.internal_networks) + list(cfg.known_scanners) + list(cfg.trusted_proxies)
    for x in cfg['blocks'].get('protected') or []:
        try:
            nets.append(ipaddress.ip_network(str(x), strict=False))
        except ValueError:
            continue
    seen, out = set(), []
    for n in nets:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _country(spec, rid, cfg):
    """One site's country limit: mode 'allow' (only these countries) or 'deny' (not these countries).
    The list file is written by the root program from the registries' data (countries.py)."""
    from .countries import DataError, set_name
    host = spec.get('host') or {}
    if host.get('mode') != 'exact':
        raise SpecError('host', 'scope_required')        # a country limit is per site, named exactly
    h = _host_cond(host)
    mode = spec.get('mode')
    if mode not in ('allow', 'deny'):
        raise SpecError('mode', 'invalid_mode')
    try:
        name = set_name(spec.get('countries') or [])
    except DataError:
        raise SpecError('countries', 'invalid_countries', limit=50)
    note = _text_ok('note', spec.get('note'), 160)
    path = os.path.join(cfg['countries']['rules_dir'], name + '.data')
    conds = [h, ('REMOTE_ADDR', ('!' if mode == 'allow' else '') + '@ipMatchFromFile ' + path, 't:none')]
    never = never_list(cfg)
    if never:
        conds.append(('REMOTE_ADDR', '!@ipMatch ' + _ip_list(never), 't:none'))
    what = ('only ' if mode == 'allow' else 'from ') + ' '.join(name.split('-')[:12]) + (' ...' if name.count('-') >= 12 else '')
    first = "id:%d,phase:1,pass,log,msg:'jt country block: %s',tag:'jt-country-block'" % (rid, what)
    text = _chain(conds, first, 'setvar:tx.jt_block=1,ctl:ruleEngine=On')
    norm = {'host': {'mode': host.get('mode'), 'value': (host.get('value') or '').strip().lower()}, 'mode': mode,
            'countries': name.split('-'), 'note': note}
    return norm, text, 'before'


def _exclusion(spec, rid, cfg, internal):
    action = spec.get('action', 'remove_target_by_id')
    if action not in EXCLUSION_ACTIONS:
        raise SpecError('action', 'invalid_action')
    host, path = _host_cond(spec.get('host')), _path_cond(spec.get('path'))
    if not host and not path:
        raise SpecError('host', 'scope_required')   # global exclusions only in expert mode
    method = (spec.get('method') or '').upper()
    if method and not re.fullmatch(r'[A-Z]{3,10}', method):
        raise SpecError('method', 'invalid_method')
    src = _source_cond(spec.get('source'), internal)
    ids = spec.get('rule_ids') or []
    if not isinstance(ids, list) or not all(isinstance(x, int) and 1 <= x <= 99999999 for x in ids) or len(ids) > 20:
        raise SpecError('rule_ids', 'invalid_rule_ids')
    targets = spec.get('targets') or []
    if not isinstance(targets, list) or len(targets) > 20 or not all(isinstance(t, str) and TARGET_RE.match(t) for t in targets):
        raise SpecError('targets', 'invalid_targets')
    tag = spec.get('tag') or ''
    ctl = []
    if action == 'remove_target_by_id':
        if not ids or not targets:
            raise SpecError('targets', 'rule_ids_and_targets_required')
        ctl = ['ctl:ruleRemoveTargetById=%d;%s' % (i, t) for i in ids for t in targets]
    elif action == 'remove_target_by_tag':
        if not TAG_RE.match(tag) or not targets:
            raise SpecError('tag', 'tag_and_targets_required')
        ctl = ['ctl:ruleRemoveTargetByTag=%s;%s' % (tag, t) for t in targets]
    elif action == 'remove_rule':
        if not ids:
            raise SpecError('rule_ids', 'required')
        ctl = ['ctl:ruleRemoveById=%d' % i for i in ids]
    elif action == 'remove_tag':
        if not TAG_RE.match(tag):
            raise SpecError('tag', 'invalid_tag')
        if not spec.get('confirm_tag'):
            raise SpecError('tag', 'confirmation_required')
        ctl = ['ctl:ruleRemoveByTag=%s' % tag]
    elif action == 'score_only':
        ctl = ['ctl:ruleRemoveById=%d' % i for i in cfg['waf']['threshold_rule_ids']]
        if not ctl:
            raise SpecError('action', 'no_threshold_rule')
    elif action == 'body_processor':
        bp = spec.get('body_processor')
        if bp not in ('JSON', 'XML', 'URLENCODED', 'MULTIPART'):
            raise SpecError('body_processor', 'invalid_body_processor')
        ctl = ['ctl:requestBodyProcessor=%s' % bp]
    conds = [c for c in (host, path) if c]
    if method:
        conds.append(('REQUEST_METHOD', '@streq ' + method, 't:none'))
    if src:
        conds.append(src)
    text = _chain(conds, 'id:%d,phase:1,pass,nolog' % rid, ','.join(ctl))
    norm = {'host': spec.get('host') or {'mode': 'any'}, 'path': spec.get('path') or {'mode': 'any'},
            'method': method, 'source': spec.get('source') or 'all', 'action': action, 'rule_ids': ids,
            'targets': targets, 'tag': tag, 'body_processor': spec.get('body_processor') or '',
            'confirm_tag': bool(spec.get('confirm_tag'))}
    return norm, text, 'before'


def _confident(spec, rid, cfg, internal):
    target = spec.get('target', 'path')
    if target not in BLOCK_TARGETS:
        raise SpecError('target', 'invalid_target')
    var, tr = BLOCK_TARGETS[target]
    if target == 'header':
        h = spec.get('header') or ''
        if not HEADER_RE.match(h):
            raise SpecError('header', 'invalid_header')
        var = 'REQUEST_HEADERS:' + h
    rx = _regex_ok('regex', spec.get('regex'))
    msg = _text_ok('msg', spec.get('msg'), 100, required=True)
    ref = _text_ok('reference', spec.get('reference'), 200)
    exc = spec.get('exceptions') or []
    if not isinstance(exc, list) or len(exc) > 10:
        raise SpecError('exceptions', 'invalid_exceptions')
    for e in exc:
        _regex_ok('exceptions', e, allow_broad=True)
    conds = [(var, '@rx ' + rx, tr)]
    if exc:
        conds.append(('REQUEST_FILENAME', '!@rx ' + '|'.join('(?:%s)' % e for e in exc), 't:none,t:urlDecodeUni,t:lowercase'))
    h = _host_cond(spec.get('host'))
    if h:
        conds.append(h)
    # source: 'external' (default) -- internal addresses are never blocked; 'all' -- internal addresses too,
    # except the known scanners (their list is written into the rule as it is at this moment)
    source = spec.get('source') or 'external'
    if source == 'external':
        conds.append(('REMOTE_ADDR', '!@ipMatch ' + internal, 't:none'))
    elif source == 'all':
        if cfg.known_scanners:
            conds.append(('REMOTE_ADDR', '!@ipMatch ' + _ip_list(cfg.known_scanners), 't:none'))
    else:
        raise SpecError('source', 'invalid_source')
    first = "id:%d,phase:1,pass,log,msg:'jt confident block: %s',tag:'jt-confident-block'" % (rid, msg)
    text = _chain(conds, first, 'setvar:tx.jt_block=1,ctl:ruleEngine=On')
    norm = {'target': target, 'header': spec.get('header') or '', 'regex': rx, 'exceptions': exc,
            'host': spec.get('host') or {'mode': 'any'}, 'msg': msg, 'reference': ref, 'source': source}
    return norm, text, 'before'


def _redaction(spec, rid, cfg):
    fields = spec.get('fields') or []
    if not isinstance(fields, list) or not fields or len(fields) > 30 or not all(
            isinstance(f, str) and re.fullmatch(r'[A-Za-z0-9_.\-\[\]]{1,64}', f) for f in fields):
        raise SpecError('fields', 'invalid_fields')
    ctl = ','.join('ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:%s' % f for f in fields)
    host, path = _host_cond(spec.get('host')), _path_cond(spec.get('path'))
    conds = [c for c in (host, path) if c]
    if conds:
        text = _chain(conds, 'id:%d,phase:1,pass,nolog' % rid, ctl)
    else:
        text = 'SecAction "id:%d,phase:1,pass,nolog,t:none,\\\n    %s"' % (rid, ',\\\n    '.join(ctl.split(',')))
    return {'fields': fields, 'host': spec.get('host') or {'mode': 'any'}, 'path': spec.get('path') or {'mode': 'any'}}, text, 'before'


def _plugin(spec, rid):
    name = spec.get('plugin') or ''
    if not PLUGIN_RE.match(name):
        raise SpecError('plugin', 'invalid_plugin')
    host = _host_cond(spec.get('host'))
    if not host:
        raise SpecError('host', 'scope_required')
    text = _chain([host], 'id:%d,phase:1,pass,nolog' % rid, "setvar:'tx.%s-plugin_enabled=1'" % name)
    return {'plugin': name, 'host': spec.get('host')}, text, 'before'


def check_raw_text(text, allow_ids=None, cfg=None):
    """Expert / imported text: only rule directives, nothing from FORBIDDEN. Returns the rule ids."""
    if not isinstance(text, str) or not text.strip():
        raise SpecError('text', 'empty')
    if len(text) > 20000 or '\x00' in text:
        raise SpecError('text', 'too_long')
    for rx, what in FORBIDDEN:
        if rx.search(text):
            raise SpecError('text', 'forbidden', what=what)
    for m in DATA_FILE_OP.finditer(text):
        if not _data_file_ok(m.group(1), cfg):
            raise SpecError('text', 'forbidden', what='operators reading files outside the ModSecurity data directories')
    ids = []
    for _, s, _ in logical_lines(text):
        words = split_args(s)
        if not words:
            continue
        if words[0] not in ALLOWED_DIRECTIVES:
            raise SpecError('text', 'directive_not_allowed', directive=words[0][:40])
        if words[0] in ('SecRule', 'SecAction'):
            acts = split_actions(words[-1]) if len(words) > (3 if words[0] == 'SecRule' else 1) else []
            for k, v in acts:
                if k == 'id':
                    try:
                        ids.append(int(v.strip("'\"")))
                    except ValueError:
                        raise SpecError('text', 'invalid_id')
                if k == 'ctl' and re.match(r'(?i)rule(?:Remove(?:ById|ByTag)|RemoveTarget\w*)=', v) and cfg is not None:
                    tgt = v.split('=', 1)[1].split(';')[0]
                    sysids = set(cfg['waf']['fallback_rule_ids']) | set(cfg['waf']['score_rule_ids'])
                    if tgt.isdigit() and int(tgt) in sysids:
                        raise SpecError('text', 'removes_system_rule', rule_id=int(tgt))
        if words[0] == 'SecRuleRemoveById' and cfg is not None:
            sysids = set(cfg['waf']['fallback_rule_ids']) | set(cfg['waf']['score_rule_ids'])
            for w in words[1:]:
                for p in w.split(','):
                    if p.strip().isdigit() and int(p) in sysids:
                        raise SpecError('text', 'removes_system_rule', rule_id=int(p))
    return ids


def _raw(spec, rid, cfg):
    text = spec.get('text') or ''
    placement = spec.get('placement', 'before')
    if placement not in ('before', 'after'):
        raise SpecError('placement', 'invalid_placement')
    ids = check_raw_text(text, cfg=cfg)
    lo, hi = cfg['waf']['local_range']
    for i in ids:
        if not lo <= i <= hi:
            raise SpecError('text', 'id_out_of_range', rule_id=i)
    if len(ids) > 1:
        raise SpecError('text', 'one_rule_per_change')
    if rid is not None and ids and ids[0] != rid:
        raise SpecError('text', 'id_mismatch', rule_id=ids[0])
    norm = {'text': text.strip('\n'), 'placement': placement}
    # where a new rule goes: at the end of its file (default), or right before another managed rule
    before = spec.get('before_rule_id')
    if before not in (None, ''):
        if not isinstance(before, int) or isinstance(before, bool) or before <= 0:
            raise SpecError('before_rule_id', 'invalid_rule_id')
        norm['before_rule_id'] = before
    return norm, text.strip('\n'), placement


def raw_direction(text):
    t = text
    loosen = re.search(r'ctl:\s*rule(?:Remove|Engine\s*=\s*(?:Off|DetectionOnly))|SecRuleRemove|SecRuleUpdateTarget|'
                       r'ctl:\s*requestBodyProcessor|plugin_enabled\s*=\s*1|\ballow\b', t, re.I)
    tighten = re.search(r'\bdeny\b|\bdrop\b|ctl:\s*ruleEngine\s*=\s*On|jt_block\s*=\s*1', t, re.I)
    return 'tighten' if tighten and not loosen else 'loosen'


def host_matches(host, h):
    """Whether a rule's host scope ({'mode': 'any'|'exact'|'regex', 'value'}) covers request host h (the
    condition _host_cond writes, in Python). A pattern Python cannot read counts as covering it."""
    host = host or {}
    mode, v = host.get('mode', 'any'), (host.get('value') or '').strip().lower()
    h = (h or '').strip().lower()
    if mode == 'any' or not mode:
        return True
    if mode == 'exact':
        pat = re.escape(v).replace('\\*', '[^.]+') if v.startswith('*.') else re.escape(v)
        return re.fullmatch(pat + r'\.?(?::[0-9]*)?', h) is not None
    try:
        return re.search(v, h) is not None
    except re.error:
        return True


def _never_in(text):
    m = re.search(r'REMOTE_ADDR "!@ipMatch ([^"]*)"', text or '')
    return set(m.group(1).split(',')) if m else set()


def country_modify_direction(old, new, old_text=None, new_text=None):
    """A changed country limit tightens only when it covers the same site the same way and refuses at least
    what it refused before: fewer allowed countries, or more blocked ones, and no address added to the ones it
    never refuses (the rule text is rebuilt with today's internal networks, scanners, proxies and protected
    list). Anything else loosens."""
    if old_text is not None and new_text is not None and not _never_in(new_text) <= _never_in(old_text):
        return 'loosen'

    def site(s):
        h = s.get('host') or {}
        return (h.get('mode') or 'any', (h.get('value') or '').strip().lower())
    if not old or not new or site(old) != site(new) or old.get('mode') != new.get('mode'):
        return 'loosen'
    a, b = set(old.get('countries') or []), set(new.get('countries') or [])
    if new.get('mode') == 'allow':
        return 'tighten' if b and b <= a else 'loosen'
    if new.get('mode') == 'deny':
        return 'tighten' if b >= a else 'loosen'
    return 'loosen'


def direction(op, kind, text=''):
    """SPEC 6.1: tightening vs loosening. Anything unclear counts as loosening."""
    tightening_kind = kind in ('confident_block', 'country') or (kind == 'raw' and raw_direction(text) == 'tighten')
    if op == 'add':
        return 'tighten' if tightening_kind else 'loosen'
    if op in ('disable', 'delete'):
        return 'loosen' if tightening_kind else 'tighten'
    if op == 'enable':
        return 'tighten' if tightening_kind else 'loosen'
    return 'loosen'   # modify
