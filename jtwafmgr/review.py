"""The periodic WAF review (every review.interval_hours, default 3): what the WAF did in the last hours, read from the
database only, stored as a review and sent through the notification channels.

Each review answers the questions a person used to answer by hand:
- was anybody blocked by mistake? Requests blocked by the CRS score alone (no confident rule) are where normal users
  get caught; a group with an internal source (not a known scanner) or without any attack family is a "possible
  false block" and is listed first;
- new internal hits (not known scanners): internal applications the rules misread;
- outside requests that look like attacks and were not refused: candidates for new confident blocks;
- what the automation did: event analysis, changes, IP blocks; what waits for a person (alerts, approvals);
- the focus sites (waf.focus_sites): one line each, every review, even when nothing happened -- events, refusals,
  outside requests not refused, login paths in the WAF log, answers 429 (rate limit), a source that keeps logging in.

Never kept or sent: request bodies, matched data, query strings (a password must not reach a review), header values.
Runs in the notification job (jt-waf-mgr-notify.service, every minute) or on request from the web interface.
"""
import collections
import ipaddress
import json
import re
import time

from . import util

# attack types (util.FAMILIES): a score-only block with none of them (only protocol, body or other checks) may be a
# normal request; a scanner's user agent is an attack tool, not a user
ATTACK_FAMILIES = {'rce', 'php', 'java', 'sqli', 'xss', 'lfi', 'rfi', 'generic', 'session', 'scanner'}
LOGIN_RE = re.compile(r'login|signin|sign-in|logon|authenticate|/token\b|/oauth|openid-connect|/session', re.I)
REPEATED_LOGIN = 20          # one outside source this many times on login paths in one review: worth a look
INTERVALS = (1, 2, 3, 4, 6, 8, 12, 24)
LIST_MAX = 30
NEW_LOOKBACK = 7 * 86400     # an internal hit is "new" if its site and path had none in the 7 days before


def _ids(s):
    return [int(x) for x in (s or '').split(',') if x.strip().isdigit()]


def _rules(ids):
    return [i for i in ids if i not in util.SCORING_RULES]


def _fams(s):
    return {x for x in (s or '').split(',') if x}


def _top(counter, n=6):
    return [k for k, _ in counter.most_common(n)]


class _Scanners:
    def __init__(self, nets):
        self.nets = list(nets)

    def __call__(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in self.nets)


def build(app, since, until):
    """The review of [since, until): a dict of plain values (no request content)."""
    db, cfg = app.db, app.cfg
    scanner = _Scanners(cfg.known_scanners)
    rows = db.q('SELECT id, ts, host, method, path, src_ip, origin, status, outcome, decided_by, rule_ids, families '
                'FROM events INDEXED BY events_ts WHERE ts>=? AND ts<? ORDER BY id', (since, until))
    out = {'since': util.iso(since), 'until': util.iso(until), 'hours': round((until - since) / 3600, 1),
           'events': len(rows), 'blocked': sum(1 for r in rows if r['outcome'] == 'blocked'),
           'logged': sum(1 for r in rows if r['outcome'] == 'logged'),
           'external_sources': len({r['src_ip'] for r in rows if r['origin'] == 'external'})}
    by = collections.Counter('%s/%s' % (r['outcome'], r['decided_by'] or '-') for r in rows)
    out['by_decision'] = dict(by.most_common())

    # blocked by the score alone
    g = collections.defaultdict(lambda: {'n': 0, 'src': set(), 'rules': collections.Counter(), 'origin': collections.Counter(),
                                         'fam': set(), 'internal_users': set()})
    for r in rows:
        if r['outcome'] == 'blocked' and r['decided_by'] in ('score', 'other'):
            x = g[(r['host'], r['method'], r['path'])]
            x['n'] += 1
            x['src'].add(r['src_ip'])
            x['rules'].update(_rules(_ids(r['rule_ids'])))
            x['origin'][r['origin']] += 1
            x['fam'] |= _fams(r['families'])
            if r['origin'] == 'internal' and not scanner(r['src_ip']):
                x['internal_users'].add(r['src_ip'])
    score = []
    for (h, m, p), x in g.items():
        suspect = bool(x['internal_users']) or not (x['fam'] & ATTACK_FAMILIES)
        score.append({'host': h, 'method': m, 'path': util.clip(p, 200), 'n': x['n'], 'sources': len(x['src']),
                      'internal_sources': len(x['internal_users']), 'rules': _top(x['rules']),
                      'families': sorted(x['fam'])[:6], 'suspect': suspect})
    score.sort(key=lambda s: (not s['suspect'], -s['n']))
    out['score_only'] = score[:LIST_MAX]
    out['score_only_groups'] = len(score)
    out['possible_false_blocks'] = sum(1 for s in score if s['suspect'])

    # internal hits, not known scanners
    g = collections.defaultdict(lambda: {'n': 0, 'src': set(), 'rules': collections.Counter(), 'outcome': collections.Counter()})
    for r in rows:
        if r['origin'] == 'internal' and not scanner(r['src_ip']):
            x = g[(r['host'], r['path'])]
            x['n'] += 1
            x['src'].add(r['src_ip'])
            x['rules'].update(_rules(_ids(r['rule_ids'])))
            x['outcome'][r['outcome']] += 1
    internal = []
    for (h, p), x in sorted(g.items(), key=lambda kv: -kv[1]['n'])[:LIST_MAX]:
        seen = db.one("SELECT 1 FROM events INDEXED BY events_ts WHERE ts>=? AND ts<? AND origin='internal' AND host=? AND path=? "
                      'LIMIT 1', (since - NEW_LOOKBACK, since, h, p))
        internal.append({'host': h, 'path': util.clip(p, 200), 'n': x['n'], 'sources': len(x['src']), 'rules': _top(x['rules']),
                         'outcome': dict(x['outcome']), 'new': not seen})
    out['internal'] = internal
    out['internal_new'] = sum(1 for i in internal if i['new'])

    # outside requests that look like attacks and were not refused
    g = collections.defaultdict(lambda: {'n': 0, 'src': set(), 'rules': collections.Counter(), 'status': collections.Counter(),
                                         'fam': collections.Counter()})
    for r in rows:
        fam = _fams(r['families']) & ATTACK_FAMILIES
        if r['origin'] == 'external' and r['outcome'] == 'logged' and fam:
            x = g[(r['host'], r['path'])]
            x['n'] += 1
            x['src'].add(r['src_ip'])
            x['rules'].update(_rules(_ids(r['rule_ids'])))
            x['status'][str(r['status'])] += 1
            x['fam'].update(fam)
    out['outside_not_refused'] = [{'host': h, 'path': util.clip(p, 200), 'n': x['n'], 'sources': len(x['src']),
                                   'status': dict(x['status']), 'families': _top(x['fam'], 4), 'rules': _top(x['rules'])}
                                  for (h, p), x in sorted(g.items(), key=lambda kv: -kv[1]['n'])[:LIST_MAX]]
    out['outside_not_refused_groups'] = len(g)

    lo, hi = cfg['waf']['local_range']
    cb = collections.Counter()
    for r in rows:
        if r['outcome'] == 'blocked' and r['decided_by'] in ('confident', 'fallback', 'country'):
            cb.update(i for i in _ids(r['rule_ids']) if lo <= i <= hi)
    out['confident_by_rule'] = [[k, n] for k, n in cb.most_common(15)]

    # what the automation did, what waits for a person
    runs = db.q('SELECT error, proposals FROM analyst_runs WHERE started_at>=? AND started_at<?', (since, until))
    out['analysis'] = {'runs': len(runs), 'errors': sum(1 for r in runs if r['error']),
                       'proposals': sum(len(json.loads(r['proposals'] or '[]')) for r in runs)}
    out['changes'] = [{'id': r['id'], 'op': r['op'], 'kind': r['kind'], 'direction': r['direction'], 'state': r['state'],
                       'by': r['proposed_by'], 'rule_id': r['rule_id'], 'reason': util.clip((r['reason'] or '').split('\n', 1)[0], 160)}
                      for r in db.q('SELECT id, op, kind, direction, state, proposed_by, rule_id, reason FROM changes '
                                    'WHERE updated_at>=? AND updated_at<? ORDER BY id', (since, until))][:LIST_MAX]
    out['applied'] = db.one("SELECT COUNT(*) FROM audit WHERE action='change.applied' AND ts>=? AND ts<?", (since, until))[0]
    out['ip_blocks'] = dict(collections.Counter(r['source'] for r in db.q(
        'SELECT source FROM ip_blocks WHERE created_at>=? AND created_at<?', (since, until))))
    out['open_alerts'] = db.one("SELECT COUNT(*) FROM alerts WHERE state='open'")[0]
    out['awaiting_approval'] = [r['id'] for r in db.q("SELECT id FROM changes WHERE state='pending_approval' ORDER BY id")][:50]

    # the focus sites: one line each, every time
    focus = []
    h0 = int(since // 3600 * 3600)
    for host in cfg['waf'].get('focus_sites') or []:
        f = [r for r in rows if r['host'] == host]
        ext = [r for r in f if r['origin'] == 'external']
        login = [r for r in f if LOGIN_RE.search(r['path'] or '')]
        per_src = collections.Counter(r['src_ip'] for r in login if r['origin'] == 'external')
        t = db.one('SELECT SUM(total) t, SUM(external) e, SUM(s429) n FROM traffic_hourly WHERE host=? AND hour>=? AND hour<?',
                   (host, h0, until))
        focus.append({'host': host, 'events': len(f), 'blocked': sum(1 for r in f if r['outcome'] == 'blocked'),
                      'outside_not_refused': sum(1 for r in ext if r['outcome'] == 'logged'
                                                 and _fams(r['families']) & ATTACK_FAMILIES),
                      'login_events': len(login), 'requests': (t['t'] or 0) if t else 0,
                      'external_requests': (t['e'] or 0) if t else 0, 's429': (t['n'] or 0) if t else 0,
                      'repeated_login': [[ip, n] for ip, n in per_src.most_common(3) if n >= REPEATED_LOGIN]})
    out['focus'] = focus
    attention = out['possible_false_blocks'] + out['internal_new'] + sum(
        1 for f in focus if f['outside_not_refused'] or f['repeated_login'] or f['s429'])
    out['level'] = 'warning' if attention else 'info'
    return out


def _slot(now, hours):
    """The local-time start of the review slot that contains now (slots begin at 00:00 and every `hours` after)."""
    lt = time.localtime(now)
    start = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour - lt.tm_hour % hours, 0, 0, 0, 0, -1))
    return start


def save(app, d, trigger):
    cur = app.db.x('INSERT INTO reviews(node_id, created_at, since, until, level, trigger, summary, details) '
                   'VALUES (?,?,?,?,?,?,?,?)',
                   (app.cfg['node']['id'], util.now(), util.parse_iso(d['since']), util.parse_iso(d['until']), d['level'],
                    trigger, json.dumps(summary(d), ensure_ascii=False), json.dumps(d, ensure_ascii=False)))
    return cur.lastrowid


def summary(d):
    """The numbers a list and a notification show."""
    return {k: d.get(k) for k in ('since', 'until', 'hours', 'events', 'blocked', 'logged', 'score_only_groups',
                                  'possible_false_blocks', 'internal_new', 'outside_not_refused_groups', 'applied',
                                  'open_alerts', 'level')} | {
        'awaiting_approval': len(d.get('awaiting_approval') or []),
        'ip_blocks': sum((d.get('ip_blocks') or {}).values()),
        'proposals': (d.get('analysis') or {}).get('proposals', 0),
        'suspects': [{'host': s['host'], 'method': s['method'], 'path': s['path'], 'n': s['n']}
                     for s in (d.get('score_only') or []) if s['suspect']][:5],
        'not_refused': [{'host': s['host'], 'path': s['path'], 'n': s['n'], 'families': s['families']}
                        for s in (d.get('outside_not_refused') or [])][:3],
        'focus': [{k: f[k] for k in ('host', 'events', 'blocked', 'outside_not_refused', 'login_events', 'requests', 's429',
                                     'repeated_login')} for f in d.get('focus') or []]}


def run(app, trigger='schedule', now=None, notify=True):
    """Build, store and (notify) queue one review of the last interval. Returns (id, details)."""
    from . import notify as notify_mod
    now = now or util.now()
    hours = app.cfg['review']['interval_hours']
    d = build(app, now - hours * 3600, now)
    rid = save(app, d, trigger)
    if notify and app.cfg['notify']['enabled']:
        notify_mod.enqueue(app.db, app.cfg, 'report.review', dict(summary(d), review_id=rid), severity=d['level'])
    return rid, d


def run_due(app, now=None):
    """Called every minute by the notification job: one review per slot (review.interval_hours). Returns the id or None."""
    cfg = app.cfg['review']
    if not cfg['enabled']:
        return None
    now = now or util.now()
    slot = _slot(now, cfg['interval_hours'])
    if app.db.get_meta('review.slot') == str(int(slot)):
        return None
    app.db.set_meta('review.slot', str(int(slot)))     # first: one review a slot even if building fails later
    rid, _ = run(app, 'schedule', now)
    return rid


def purge(app, now=None):
    now = now or util.now()
    app.db.x('DELETE FROM reviews WHERE created_at<?', (now - app.cfg['review']['keep_days'] * 86400,))


def listing(db, limit=100, before=None):
    args = []
    sql = 'SELECT id, created_at, trigger, summary FROM reviews'
    if before:
        sql += ' WHERE id<?'
        args.append(int(before))
    sql += ' ORDER BY id DESC LIMIT ?'
    args.append(int(limit))
    return [dict(json.loads(r['summary']), id=r['id'], created_at=util.iso(r['created_at']), trigger=r['trigger'])
            for r in db.q(sql, args)]


def get(db, rid):
    r = db.one('SELECT * FROM reviews WHERE id=?', (int(rid),))
    if not r:
        return None
    return dict(json.loads(r['details']), id=r['id'], created_at=util.iso(r['created_at']), trigger=r['trigger'])
