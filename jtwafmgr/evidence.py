"""Evidence for a change (SPEC 6.2), from the nginx access logs and the event history.

Confident block: every access log line the generated rule would match, judged with the rule's own
variables and transformations (libmodsecurity v3 semantics, see below). Passes when no external
request it matches got a 2xx/3xx (outside catch-all sites) and no internal source other than the
known scanners matches (LESSONS 25). Nothing is skipped that the rule itself does not skip: a path
the rule does not exempt (WebDAV, share links) counts, so the evidence shows the harm.
Exclusion: which recorded alerts it would silence, flagging external ones that look like attacks.

How the rule sees a request (libmodsecurity v3, Transaction::processURI, ModSecurity-nginx passes
the raw request target): the fragment is cut, the whole target is %XX-decoded once
(utils::uri_decode: valid %XX only, '+' kept), REQUEST_FILENAME is that up to the first '?' of the
decoded text, REQUEST_URI is all of it (an absolute-form "scheme://host" prefix dropped). The
t: transformations then run on bytes: urlDecodeUni (%XX, %uXXXX with the low byte and the
full-width ASCII fix, '+' -> space; invalid sequences kept), normalizePath (ModSecurity's
normalize_path_inplace, not posixpath), lowercase (ASCII only). @rx is PCRE without UTF, with
DOTALL and MULTILINE. Not modelled: a SecUnicodeMapFile table for %uXXXX (the low byte is used).
"""
import collections
import glob
import gzip
import json
import re
import time

from . import rulegen, util

COMBINED = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
# The exception condition of a generated confident block (rulegen._confident): REQUEST_FILENAME
# with these transformations. tests/test_evidence_security.py checks it against the rule text.
EXCEPTION_TRANSFORMS = 't:none,t:urlDecodeUni,t:lowercase'
# Regression samples: a path becomes a "must keep working" sample only when this many distinct
# source addresses got a 2xx for it (one attacker hammering a path cannot make it one).
MIN_SAMPLE_SOURCES = 3
_SAMPLE_IP_CAP = 64
_HEX = frozenset(b'0123456789abcdefABCDEF')
_NGINX_ESC = re.compile(rb'\\x([0-9A-Fa-f]{2})')


# --- ModSecurity transformations (bytes in, bytes out) -----------------------------------------
def uri_decode(b):
    """utils::uri_decode: %XX with two valid hex digits; nothing else changes ('+' stays)."""
    if b'%' not in b:
        return b
    out, i, n = bytearray(), 0, len(b)
    while i < n:
        c = b[i]
        if c == 0x25 and i + 2 < n and b[i + 1] in _HEX and b[i + 2] in _HEX:
            out.append(int(b[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(c)
            i += 1
    return bytes(out)


def url_decode_uni(b):
    """t:urlDecodeUni (url_decode_uni.cc), without a unicode map table."""
    if b'%' not in b and b'+' not in b:
        return b
    out, i, n = bytearray(), 0, len(b)
    while i < n:
        c = b[i]
        if c == 0x25:
            if i + 1 < n and b[i + 1] in b'uU':
                if i + 5 < n and all(x in _HEX for x in b[i + 2:i + 6]):
                    d = int(b[i + 4:i + 6], 16)
                    if 0 < d < 0x5f and b[i + 2] in b'fF' and b[i + 3] in b'fF':
                        d += 0x20
                    out.append(d)
                    i += 6
                else:
                    out += b[i:i + 2]
                    i += 2
            elif i + 2 < n and b[i + 1] in _HEX and b[i + 2] in _HEX:
                out.append(int(b[i + 1:i + 3], 16))
                i += 3
            else:
                out.append(c)
                i += 1
        else:
            out.append(0x20 if c == 0x2b else c)
            i += 1
    return bytes(out)


def normalize_path(b):
    """t:normalizePath: a port of ModSecurity's normalize_path_inplace (win=0), quirks included
    (a segment ending in ".." counts as a back reference, e.g. /a../b -> /b)."""
    if b[:1] == b'/' and b'//' not in b and b'./' not in b and not b.endswith(b'.'):
        return b    # nothing the algorithm would touch
    return _normalize_path_inplace(b)


def _normalize_path_inplace(b):
    if not b:
        return b
    s = bytearray(b)
    src = dst = 0
    end = len(s) - 1
    relative = s[0] != 0x2f
    trailing = s[end] == 0x2f
    hitroot = False
    done = False
    while not done and src <= end and dst <= end:
        copy = True
        if src == end:
            done = True
        if not done and s[src + 1] != 0x2f:
            pass                                            # not the end of a segment
        elif src != end and s[src] == 0x2f:
            pass                                            # empty segment: the copy squeezes it
        elif s[src] == 0x2e:
            if dst > 0 and s[dst - 1] == 0x2e:              # back reference
                if relative and (hitroot or dst - 2 <= 0):
                    hitroot = True
                else:
                    dst -= 3
                    while dst > 0 and s[dst] != 0x2f:
                        dst -= 1
                    if dst <= 0:
                        hitroot = True
                        dst = 0
                        if not relative and src == end:
                            dst += 1
                    if done:
                        copy = False
                    else:
                        src += 1
            elif dst == 0:                                  # relative self reference
                if done:
                    copy = False
                else:
                    src += 1
            elif s[dst - 1] == 0x2f:                        # self reference
                if done:
                    copy = False
                else:
                    dst -= 1
                    src += 1
        elif dst > 0:
            hitroot = False
        if copy:
            if s[src] == 0x2f:
                while src < end and s[src + 1] == 0x2f:
                    src += 1
                if relative and dst == 0:
                    src += 1
                    continue
            s[dst] = s[src]
            dst += 1
            src += 1
    if not trailing and dst > 0 and s[dst - 1] == 0x2f:
        dst -= 1
    return bytes(s[:dst])


TRANSFORMATIONS = {'urlDecodeUni': url_decode_uni, 'normalizePath': normalize_path, 'lowercase': bytes.lower}


def transform(value, chain):
    """Applies a rule's t: list ('t:none,t:urlDecodeUni,...') in order. An unknown name is an error:
    evidence that silently skips a transformation would judge a different rule."""
    for t in chain.split(','):
        name = t.strip()[2:] if t.strip().startswith('t:') else t.strip()
        if name in ('', 'none'):
            continue
        fn = TRANSFORMATIONS.get(name)
        if fn is None:
            raise ValueError('transformation not modelled: %s' % name)
        value = fn(value)
    return value


def request_filename(raw):
    """REQUEST_FILENAME from the raw request target (bytes)."""
    dec = uri_decode(raw.split(b'#', 1)[0])
    return dec.split(b'?', 1)[0]


def request_uri(raw):
    """REQUEST_URI from the raw request target (bytes)."""
    dec = uri_decode(raw.split(b'#', 1)[0])
    if dec and dec[:1] != b'/':
        c = dec.find(b':')
        if c >= 0 and dec[c + 1:c + 3] == b'//':
            p = dec.find(b'/', c + 3)
            if p >= 0:
                return dec[p:]
    return dec


def log_bytes(s, escaped):
    """A logged value back to the bytes the server received: nginx's default log escaping writes
    unprintable bytes as \\xHH (combined format); escape=json does not."""
    b = s.encode('utf-8', 'surrogateescape')
    return _NGINX_ESC.sub(lambda m: bytes([int(m.group(1), 16)]), b) if escaped else b


class _Rx:
    """@rx: PCRE without UTF, DOTALL | MULTILINE, matched on bytes."""

    def __init__(self, pattern):
        try:
            self.c, self.bytes = re.compile(pattern.encode('utf-8'), re.S | re.M), True
        except re.error:
            self.c, self.bytes = re.compile(pattern, re.S | re.M), False

    def search(self, b):
        return self.c.search(b if self.bytes else b.decode('latin-1'))


class AccessLogs:
    def __init__(self, cfg):
        self.cfg = cfg

    def files(self):
        out = []
        for g in self.cfg['evidence']['access_logs']:
            out.extend(sorted(glob.glob(g)))
        seen, res = set(), []
        for f in out:
            if f not in seen:
                seen.add(f)
                res.append(f)
        return res

    def lines(self, deadline):
        """Yields dicts: host, method, uri, status, ip, ua, esc (values carry nginx's default \\xHH
        escaping). Stops at the deadline."""
        for f in self.files():
            host_from_name = re.sub(r'\.(?:access|combined)\.log.*$', '', f.rsplit('/', 1)[-1])
            opener = gzip.open if f.endswith('.gz') else open
            try:
                fh = opener(f, 'rt', encoding='utf-8', errors='replace')
            except OSError:
                continue
            with fh:
                for n, line in enumerate(fh):
                    if n % 5000 == 0 and time.time() > deadline:
                        return
                    if line.startswith('{'):
                        try:
                            d = json.loads(line)
                        except ValueError:
                            continue
                        req = str(d.get('request') or '')
                        parts = req.split(' ')
                        uri = parts[1] if len(parts) > 1 else str(d.get('url') or '')
                        yield {'host': str(d.get('vhost') or host_from_name).lower(), 'method': parts[0] if parts else '',
                               'uri': uri, 'status': str(d.get('http_status') or ''),
                               'ip': str(d.get('srcip') or d.get('remote_addr') or ''), 'ua': str(d.get('user_agent') or ''),
                               'esc': False}
                    else:
                        m = COMBINED.match(line)
                        if m:
                            yield {'host': host_from_name if host_from_name not in ('access', 'access.log') else '(default)',
                                   'method': m.group(2), 'uri': m.group(3), 'status': m.group(4), 'ip': m.group(1),
                                   'ua': m.group(5), 'esc': True}


class Evidence:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self.logs = AccessLogs(cfg)

    def check(self, r):
        spec = json.loads(r['spec'])
        if r['op'] == 'adopt':
            return {'ok': True, 'skipped': 'adoption keeps every rule as it is'}
        if r['kind'] == 'confident_block' and r['op'] in ('add', 'modify', 'enable'):
            return self.block_evidence(spec)
        if r['kind'] in ('exclusion', 'redaction') and r['op'] in ('add', 'modify', 'enable'):
            return self.exclusion_impact(spec)
        if r['op'] in ('disable', 'delete') and r['rule_id']:
            return self.rule_hits(r['rule_id'])
        return {'ok': True, 'skipped': 'no evidence check for this kind of change'}

    # --- confident blocks ----------------------------------------------------------------------
    @staticmethod
    def rule_view(spec):
        """What the generated rule inspects, from rulegen's own tables: a function taking a log line
        (dict) to the transformed value of the first condition, or None when the variable is not in
        the access log (headers other than User-Agent / Host)."""
        target = spec.get('target', 'path')
        var, tr = rulegen.BLOCK_TARGETS[target]
        if target == 'header':
            var = 'REQUEST_HEADERS:' + (spec.get('header') or '')
        if var == 'REQUEST_FILENAME':
            return lambda d: transform(request_filename(log_bytes(d['uri'], d['esc'])), tr)
        if var == 'REQUEST_URI':
            return lambda d: transform(request_uri(log_bytes(d['uri'], d['esc'])), tr)
        if var.lower() == 'request_headers:user-agent':
            return lambda d: transform(log_bytes(d['ua'], d['esc']), tr)
        if var.lower() == 'request_headers:host':
            return lambda d: transform(log_bytes(d['host'], False), tr)
        return None

    def block_evidence(self, spec):
        target = spec.get('target', 'path')
        if target not in rulegen.BLOCK_TARGETS:
            raise ValueError('unknown target')
        view = self.rule_view(spec)
        if view is None:
            return {'ok': True, 'skipped': 'headers other than User-Agent are not in the access log', 'complete': False}
        rx = _Rx(spec['regex'])
        exc = [_Rx(e) for e in spec.get('exceptions') or []]
        host_cond = rulegen._host_cond(spec.get('host'))
        host_rx = (_Rx(host_cond[1][len('@rx '):]), host_cond[2]) if host_cond else None
        catch_all = set(x.lower() for x in self.cfg['evidence']['catch_all_hosts'])
        deadline = time.time() + self.cfg['evidence']['max_scan_seconds']
        total = ext = 0
        ext_ok, intl, known, sites = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
        ext_examples = collections.Counter()
        complete = True
        for d in self.logs.lines(deadline):
            total += 1
            if not rx.search(view(d)):
                continue
            if exc:
                fn = transform(request_filename(log_bytes(d['uri'], d['esc'])), EXCEPTION_TRANSFORMS)
                if any(e.search(fn) for e in exc):
                    continue
            if host_rx and not host_rx[0].search(transform(log_bytes(d['host'], False), host_rx[1])):
                continue
            sites[d['host']] += 1
            shape = util.clip(d['uri'].split('?', 1)[0], 100)
            if util.ip_in(d['ip'], self.cfg.internal_networks):
                if util.ip_in(d['ip'], self.cfg.known_scanners):
                    known[d['ip']] += 1
                else:
                    intl[(d['host'], d['status'], d['ip'], shape)] += 1
            else:
                ext += 1
                ext_examples[(d['host'], d['status'], shape)] += 1
                if d['status'][:1] in '23' and d['host'] not in catch_all:
                    ext_ok[(d['host'], d['status'], shape, util.clip(d['ua'], 40))] += 1
        if time.time() > deadline:
            complete = False
        ok = complete and not ext_ok and not intl
        return {
            'ok': ok, 'complete': complete, 'scanned': total, 'files': len(self.logs.files()),
            'external_hits': ext, 'external_success': sum(ext_ok.values()), 'internal_other': sum(intl.values()),
            'internal_known': sum(known.values()),
            'sites': [{'host': k, 'hits': n} for k, n in sites.most_common(10)],
            'external_success_samples': [{'host': k[0], 'status': k[1], 'path': k[2], 'ua': k[3], 'count': n}
                                         for k, n in ext_ok.most_common(15)],
            'internal_samples': [{'host': k[0], 'status': k[1], 'ip': k[2], 'path': k[3], 'count': n}
                                 for k, n in intl.most_common(15)],
            'external_samples': [{'host': k[0], 'status': k[1], 'path': k[2], 'count': n} for k, n in ext_examples.most_common(10)],
        }

    # --- exclusions ----------------------------------------------------------------------------
    def exclusion_impact(self, spec, days=30):
        since = util.now() - days * 86400
        h, p = spec.get('host') or {}, spec.get('path') or {}
        where, args = ['ts>=?'], [since]
        if h.get('mode') == 'exact':
            where.append('host=?')
            args.append(h['value'].lower())
        rows = self.db.q('SELECT id, host, path, method, origin, outcome, rule_ids, families, decided_by FROM events WHERE '
                         + ' AND '.join(where) + ' ORDER BY id DESC LIMIT 200000', args)
        host_rx = re.compile(h['value']) if h.get('mode') == 'regex' else None
        path_ok = {
            'exact': lambda x: x == p.get('value'),
            'prefix': lambda x: x.startswith(p.get('value', '')),
            'regex': (lambda x, c=re.compile(p['value']) if p.get('mode') == 'regex' else None: bool(c.search(x))),
        }.get(p.get('mode'), lambda x: True)
        ids = set(spec.get('rule_ids') or [])
        method = spec.get('method') or ''
        src = spec.get('source') or 'all'
        n = ext = attack_like = 0
        samples = []
        for e in rows:
            if host_rx and not host_rx.search(e['host']):
                continue
            if not path_ok(e['path']) or (method and e['method'] != method) or (src != 'all' and e['origin'] != src):
                continue
            rids = {int(x) for x in e['rule_ids'].strip(',').split(',') if x}
            if ids and not rids & ids and spec.get('action') not in ('score_only', 'remove_tag', 'remove_target_by_tag',
                                                                     'body_processor'):
                continue
            n += 1
            if e['origin'] == 'external':
                ext += 1
                fams = set(x for x in e['families'].strip(',').split(',') if x)
                other = rids - ids - util.SCORING_RULES
                if e['decided_by'] in ('confident', 'fallback') or (fams & {'rce', 'php', 'java', 'sqli', 'xss', 'lfi', 'rfi'}
                                                                     and other):
                    attack_like += 1
                    if len(samples) < 10:
                        samples.append({'id': e['id'], 'host': e['host'], 'path': util.clip(e['path'], 120),
                                        'outcome': e['outcome'], 'rules': sorted(rids)[:10]})
        return {'ok': True, 'days': days, 'affected_events': n, 'external': ext, 'external_attack_like': attack_like,
                'attack_like_samples': samples, 'warning': attack_like > 0}

    def rule_hits(self, rule_id, days=30):
        r = self.db.one("SELECT COUNT(*) n, SUM(outcome='blocked') b FROM event_rules WHERE rule_id=? AND ts>=?",
                        (rule_id, util.now() - days * 86400))
        return {'ok': True, 'days': days, 'hits': r['n'] or 0, 'blocked': r['b'] or 0}

    # --- regression samples ---------------------------------------------------------------------
    @staticmethod
    def _sample_key(path):
        """A path as a rule's exception / path condition sees it (REQUEST_FILENAME, decoded, lowercase)."""
        return transform(request_filename(path.encode('utf-8', 'surrogateescape')), EXCEPTION_TRANSFORMS)

    def _paths_with_waf_events(self):
        """(host, key) of every path that had a WAF event: blocked, or any rule logged a hit."""
        rows = self.db.q("SELECT DISTINCT host, path FROM events WHERE outcome='blocked' OR rule_ids NOT IN ('', ',,')")
        return {(r['host'].lower(), self._sample_key(r['path'])) for r in rows}

    def collect_samples(self, per_host=8, seconds=600):
        """Successful GET paths per site (query strings dropped) become regression samples, ranked by
        the number of distinct sources (internal ones first; at least MIN_SAMPLE_SOURCES). Never from
        catch-all sites, known scanners, or paths that had WAF events: what an attacker requested
        often must not turn into a "this must keep working" sample."""
        catch_all = set(x.lower() for x in self.cfg['evidence']['catch_all_hosts'])
        flagged = self._paths_with_waf_events()
        # host -> path -> [all sources, internal sources, hits]
        seen = collections.defaultdict(dict)
        kinds = {}
        deadline = time.time() + seconds
        for d in self.logs.lines(deadline):
            host = d['host']
            if d['method'] != 'GET' or not d['status'].startswith('2') or host in ('', '-', '(default)', '_') \
                    or host in catch_all:
                continue
            path = d['uri'].split('?', 1)[0]
            if not path.startswith('/') or len(path) > 300 or re.search(r'[\s"\'<>\\]', path):
                continue
            ip = d['ip']
            kind = kinds.get(ip)
            if kind is None:
                kind = kinds[ip] = ('scanner' if not ip or util.ip_in(ip, self.cfg.known_scanners) else
                                    'internal' if util.ip_in(ip, self.cfg.internal_networks) else 'external')
            if kind == 'scanner':
                continue
            e = seen[host].get(path)
            if e is None:
                e = seen[host][path] = [set(), set(), 0]
            e[2] += 1
            if len(e[0]) < _SAMPLE_IP_CAP:
                e[0].add(ip)
            if kind == 'internal' and len(e[1]) < _SAMPLE_IP_CAP:
                e[1].add(ip)
        chosen = {}
        for host, paths in seen.items():
            cands = [(p, e) for p, e in paths.items()
                     if len(e[0]) >= MIN_SAMPLE_SOURCES and (host, self._sample_key(p)) not in flagged]
            if any(e[1] for _, e in cands):
                cands = [(p, e) for p, e in cands if e[1]]     # internal users exist: only what they use
            cands.sort(key=lambda x: (-len(x[1][1]), -len(x[1][0]), -x[1][2], x[0]))
            if cands:
                chosen[host] = [p for p, _ in cands[:per_host]]
        added = 0
        t = util.now()
        with self.db.tx() as c:
            c.execute('DELETE FROM regression_samples WHERE pinned=0')
            for host, paths in chosen.items():
                for path in paths:
                    added += c.execute('INSERT OR IGNORE INTO regression_samples(host, method, path, source, added_at) '
                                       "VALUES (?, 'GET', ?, 'auto', ?)", (host, path, t)).rowcount
        return {'hosts': len(chosen), 'samples': added}
