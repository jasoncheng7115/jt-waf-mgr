"""Evidence for a change (SPEC 6.2), from the nginx access logs and the event history.

Confident block: every access log line the pattern would match, with the rule's own
transformations. Passes when no external request it matches got a 2xx/3xx (outside catch-all
sites) and no internal source other than the known scanners matches (LESSONS 25).
Exclusion: which recorded alerts it would silence, flagging external ones that look like attacks.
"""
import collections
import glob
import gzip
import json
import posixpath
import re
import time
import urllib.parse

from . import util

COMBINED = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
DAV = re.compile(r'^/(?:remote|public)\.php/(?:web)?dav|^/(?:index\.php/)?s/')


def normalize_path(p):
    p = urllib.parse.unquote(p)
    keep = p.endswith('/')
    p = posixpath.normpath('/' + p.lstrip('/')) if p else '/'
    return (p + '/' if keep and p != '/' else p).lower()


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
        """Yields dicts: host, method, uri, status, ip, ua. Stops at the deadline."""
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
                               'ip': str(d.get('srcip') or d.get('remote_addr') or ''), 'ua': str(d.get('user_agent') or '')}
                    else:
                        m = COMBINED.match(line)
                        if m:
                            yield {'host': host_from_name if host_from_name not in ('access', 'access.log') else '(default)',
                                   'method': m.group(2), 'uri': m.group(3), 'status': m.group(4), 'ip': m.group(1),
                                   'ua': m.group(5)}


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
    def block_evidence(self, spec):
        rx = re.compile(spec['regex'])
        exc = [re.compile(e) for e in spec.get('exceptions') or []]
        host_rx = None
        h = spec.get('host') or {}
        if h.get('mode') == 'exact':
            host_rx = re.compile('^%s$' % re.escape(h['value'].lower()))
        elif h.get('mode') == 'regex':
            host_rx = re.compile(h['value'])
        catch_all = set(x.lower() for x in self.cfg['evidence']['catch_all_hosts'])
        target = spec['target']
        deadline = time.time() + self.cfg['evidence']['max_scan_seconds']
        total = ext = 0
        ext_ok, intl, known, sites = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
        ext_examples = collections.Counter()
        complete = True
        for d in self.logs.lines(deadline):
            total += 1
            uri = d['uri']
            path = normalize_path(uri.split('?', 1)[0])
            if target == 'path':
                val = path
            elif target == 'uri':
                val = urllib.parse.unquote(uri).lower()
            elif target == 'ua':
                val = d['ua'].lower()
            elif target == 'host':
                val = d['host']
            else:
                continue   # arbitrary headers are not in the access log
            if not rx.search(val):
                continue
            if any(e.search(path) for e in exc) or DAV.search(path):
                continue
            if host_rx and not host_rx.search(d['host']):
                continue
            sites[d['host']] += 1
            shape = util.clip(path, 100)
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
        if target == 'header':
            return {'ok': True, 'skipped': 'headers other than User-Agent are not in the access log', 'complete': False}
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
    def collect_samples(self, per_host=8, seconds=600):
        """Frequent successful GET paths per site (query strings dropped) become regression samples."""
        counts = collections.defaultdict(collections.Counter)
        deadline = time.time() + seconds
        for d in self.logs.lines(deadline):
            if d['method'] != 'GET' or not d['status'].startswith('2') or d['host'] in ('', '-', '(default)', '_'):
                continue
            path = d['uri'].split('?', 1)[0]
            if not path.startswith('/') or len(path) > 300 or re.search(r'[\s"\'<>\\]', path):
                continue
            counts[d['host']][path] += 1
        added = 0
        t = util.now()
        with self.db.tx() as c:
            c.execute('DELETE FROM regression_samples WHERE pinned=0')
            for host, ctr in counts.items():
                for path, _ in ctr.most_common(per_host):
                    added += c.execute('INSERT OR IGNORE INTO regression_samples(host, method, path, source, added_at) '
                                       "VALUES (?, 'GET', ?, 'auto', ?)", (host, path, t)).rowcount
        return {'hosts': len(counts), 'samples': added}
