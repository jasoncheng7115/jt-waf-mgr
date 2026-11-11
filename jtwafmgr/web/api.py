"""REST API handlers (/api/v1). See docs/dev/ui-api.md for the JSON shapes."""
import gzip
import hashlib
import ipaddress
import json
import time

from .. import __version__, util
from ..auth import LANGUAGES, SCOPES_P1, AuthError
from ..config import ROLES
from .server import ApiError, Response, json_response

V = '/api/v1'


def _limit(req, default=100, cap=1000):
    try:
        n = int(req.query.get('limit', default))
    except ValueError:
        raise ApiError(400, 'bad_request', 'limit must be a number')
    return max(1, min(n, cap))


def _int_param(req, name):
    v = req.query.get(name)
    if v in (None, ''):
        return None
    try:
        return int(v)
    except ValueError:
        raise ApiError(400, 'bad_request', '%s must be a number' % name)


def _time_param(req, name):
    v = req.query.get(name)
    if not v:
        return None
    try:
        return util.parse_iso(v)
    except ValueError:
        raise ApiError(400, 'bad_request', '%s must be RFC 3339' % name)


def _range(req):
    r = req.query.get('range', '24h')
    if r not in ('24h', '7d'):
        raise ApiError(400, 'bad_request', 'range must be 24h or 7d')
    until = util.now()
    return r, until - (86400 if r == '24h' else 7 * 86400), until


def _ids(s):
    return [int(x) for x in s.strip(',').split(',') if x]


# GeoIP lookup for event sources (set by App; None in tools that run without it)
GEO = None


def geo(ip):
    try:
        return GEO(ip) if GEO and ip else None
    except Exception:            # never let a broken database break an event list
        return None


def event_summary(r):
    return {'id': r['id'], 'ts': util.iso(r['ts']), 'host': r['host'], 'method': r['method'], 'path': r['path'],
            'query': r['query'], 'src_ip': r['src_ip'], 'origin': r['origin'], 'status': r['status'],
            'outcome': r['outcome'], 'decided_by': r['decided_by'], 'rule_ids': _ids(r['rule_ids']),
            'families': [x for x in r['families'].strip(',').split(',') if x], 'message': r['message'],
            'local_rule_ids': _ids(r['local_rule_ids']), 'src_geo': geo(r['src_ip'])}


def event_full(r):
    e = event_summary(r)
    e.update({'unique_id': r['unique_id'], 'http_version': r['http_version'], 'engine': r['engine'],
              'client_port': r['src_port'], 'server_port': r['server_port'], 'anomaly_score': r['anomaly_score'],
              'matches': json.loads(r['matches']), 'truncated': bool(r['truncated'])})
    return e


def _user(app, r):
    return app.auth.user_public(r)


# --- public / auth -------------------------------------------------------------------------

def meta(app, req):
    a = app.cfg['auth']
    return json_response(200, {'name': 'jt-waf-mgr', 'version': __version__, 'source_url': app.cfg.source_url,
                               'sso_enabled': False, 'node_id': app.cfg['node']['id'],
                               'login_notice': app.cfg['ui']['login_notice'],
                               'password_policy': {'min_length': a['password_min_length'],
                                                   'min_classes': a['password_min_classes'],
                                                   'history': a['password_history'],
                                                   'max_age_days': a['password_max_age_days'],
                                                   'min_age_hours': a['password_min_age_hours']}})


def me(app, req):
    return json_response(200, {'user': _user(app, req.user), 'csrf_token': req.csrf})


def login(app, req):
    b = req.body()
    if not isinstance(b.get('username'), str) or not isinstance(b.get('password'), str):
        raise ApiError(400, 'bad_request')
    totp = b.get('totp') if isinstance(b.get('totp'), str) else None
    sid, csrf, row, previous = app.auth.login(b['username'], b['password'], totp, req.client_ip,
                                              req.headers.get('User-Agent'))
    resp = json_response(200, {'user': _user(app, row), 'csrf_token': csrf, 'previous_login': previous})
    resp.headers.append(req.set_cookie_header(sid))
    return resp


def logout(app, req):
    sid = req.get_cookie()
    if sid:
        s = app.auth.session(sid)
        if s:
            if req.method == 'POST':
                sent = req.headers.get('X-CSRF-Token') or ''
                if sent != s[1]:
                    raise ApiError(403, 'csrf_failed')
            app.audit.log('logout', s[0]['username'], src_ip=req.client_ip)
        app.auth.logout(sid)
    resp = Response(204)
    resp.headers.append(req.set_cookie_header('', clear=True))
    return resp


def change_password(app, req):
    b = req.body()
    from ..auth import verify_password
    if not verify_password(str(b.get('current_password') or ''), req.user['pw_hash']):
        app.audit.log('password.change', req.user['username'], src_ip=req.client_ip, result='denied')
        raise ApiError(401, 'invalid_credentials')
    app.auth.set_password(req.user['username'], str(b.get('new_password') or ''))
    # set_password dropped every session; keep this one alive by re-inserting it
    from ..auth import _sha256
    app.db.x('INSERT INTO sessions(id_hash, username, csrf, created_at, last_seen, src_ip, user_agent) '
             'VALUES (?,?,?,?,?,?,?)', (_sha256(req.sid), req.user['username'], req.csrf, util.now(), util.now(),
                                        req.client_ip, (req.headers.get('User-Agent') or '')[:200]))
    app.audit.log('password.change', req.user['username'], src_ip=req.client_ip)
    return Response(204)


def patch_me(app, req):
    b = req.body()
    u = req.user['username']
    if 'language' in b:
        if b['language'] not in LANGUAGES:
            raise ApiError(400, 'bad_request', 'unknown language')
        app.db.x('UPDATE users SET language=? WHERE username=?', (b['language'], u))
    if 'display_name' in b:
        if not isinstance(b['display_name'], str) or len(b['display_name']) > 64:
            raise ApiError(400, 'bad_request', 'display_name: up to 64 characters')
        app.db.x('UPDATE users SET display_name=? WHERE username=?', (b['display_name'].strip(), u))
    return json_response(200, {'user': _user(app, app.auth.user_row(u)), 'csrf_token': req.csrf})


def my_sessions(app, req):
    return json_response(200, {'items': app.auth.sessions_of(req.user['username'], req.sid)})


def my_sessions_revoke_others(app, req):
    n = len(app.auth.sessions_of(req.user['username'])) - 1
    app.auth.drop_sessions(req.user['username'], keep_sid=req.sid)
    app.audit.log('sessions.revoked', req.user['username'], src_ip=req.client_ip, target=req.user['username'],
                  count=max(n, 0))
    return Response(204)


def totp_setup(app, req):
    secret, uri = app.auth.totp_setup(req.user['username'])
    return json_response(200, {'secret': secret, 'otpauth_uri': uri})


def totp_enable(app, req):
    app.auth.totp_enable(req.user['username'], str(req.body().get('code') or ''))
    app.audit.log('totp.enabled', req.user['username'], src_ip=req.client_ip)
    return Response(204)


def totp_disable(app, req):
    b = req.body()
    app.auth.totp_disable(req.user['username'], str(b.get('password') or ''), str(b.get('code') or ''))
    app.audit.log('totp.disabled', req.user['username'], src_ip=req.client_ip)
    return Response(204)


# --- status / overview ---------------------------------------------------------------------

def status(app, req):
    _, m = app.site.load()
    crs = m.crs_status()
    st = app.tailer.stats if app.tailer else {}
    last = st.get('last_event_ts')
    if last is None:
        row = app.db.one('SELECT MAX(ts) FROM events')
        last = row[0] if row else None
    total = app.db.one('SELECT COUNT(*) FROM events')[0]
    return json_response(200, {
        'version': __version__, 'node_id': app.cfg['node']['id'],
        'engine_mode': crs['engine_mode'], 'external_threshold_block': m.external_threshold_block(),
        'crs': {k: crs[k] for k in ('version', 'paranoia_level', 'blocking_paranoia_level',
                                    'inbound_threshold', 'outbound_threshold')},
        'collector': {'audit_log': app.cfg['paths']['audit_log'], 'running': bool(app.tailer and st.get('error') is None),
                      'error': st.get('error'), 'last_event_at': util.iso(last),
                      'lag_seconds': int(util.now() - st['last_read']) if st.get('last_read') else None,
                      'parse_errors': st.get('parse_errors', 0), 'oversized': st.get('oversized', 0),
                      'events_total': total},
        'nginx': {'version': app.site.nginx_version(), 'module_mismatch': None},
        'managed_files_drift': None, 'last_apply': None,
    })


def _group(app, col, since, until, limit=15, extra_where='', args=()):
    rows = app.db.q(
        'SELECT %s AS k, SUM(outcome=\'blocked\') AS b, SUM(outcome=\'logged\') AS l FROM events '
        'WHERE ts>=? AND ts<? %s GROUP BY k ORDER BY COUNT(*) DESC LIMIT ?' % (col, extra_where),
        (since, until) + tuple(args) + (limit,))
    return [{'key': r['k'], 'blocked': r['b'] or 0, 'logged': r['l'] or 0} for r in rows]


def _by_rule(app, since, until, limit=15):
    rows = app.db.q(
        'SELECT rule_id, SUM(outcome=\'blocked\') AS b, SUM(outcome=\'logged\') AS l FROM event_rules '
        'WHERE ts>=? AND ts<? AND rule_id NOT IN (%s) GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT ?'
        % ','.join(str(x) for x in sorted(util.SCORING_RULES)), (since, until, limit))
    out = []
    for r in rows:
        rule = app.site.rule(r['rule_id'])
        out.append({'key': str(r['rule_id']), 'msg': (rule.action('msg') if rule else '') or '',
                    'blocked': r['b'] or 0, 'logged': r['l'] or 0})
    return out


def _by_family(app, since, until):
    counts = {}
    for r in app.db.q('SELECT families, outcome FROM events WHERE ts>=? AND ts<?', (since, until)):
        fams = [x for x in r['families'].strip(',').split(',') if x] or ['other']
        for f in fams:
            c = counts.setdefault(f, {'key': f, 'blocked': 0, 'logged': 0})
            c[r['outcome']] += 1
    return sorted(counts.values(), key=lambda c: -(c['blocked'] + c['logged']))


def overview(app, req):
    rng, since, until = _range(req)
    t = app.db.one(
        "SELECT COUNT(*) n, SUM(outcome='blocked') b, SUM(outcome='logged') l, SUM(origin='external') ext, "
        "SUM(origin='internal') int, SUM(decided_by IN ('confident','fallback')) bc, SUM(decided_by='score') bs "
        'FROM events WHERE ts>=? AND ts<?', (since, until))
    buckets = {}
    for r in app.db.q("SELECT CAST(ts/3600 AS INTEGER) h, SUM(outcome='blocked') b, SUM(outcome='logged') l "
                      'FROM events WHERE ts>=? AND ts<? GROUP BY h', (since, until)):
        buckets[r['h']] = (r['b'] or 0, r['l'] or 0)
    first, last = int(since // 3600) + 1, int(until // 3600)
    timeline = [{'t': util.iso(h * 3600), 'blocked': buckets.get(h, (0, 0))[0], 'logged': buckets.get(h, (0, 0))[1]}
                for h in range(first, last + 1)]
    src = app.db.q(
        "SELECT src_ip k, origin, SUM(outcome='blocked') b, SUM(outcome='logged') l FROM events WHERE ts>=? AND ts<? "
        'GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 15', (since, until))
    score_only = [event_summary(r) for r in app.db.q(
        "SELECT * FROM events WHERE ts>=? AND ts<? AND outcome='blocked' AND decided_by='score' AND origin='external' "
        'ORDER BY ts DESC LIMIT 50', (since, until))]
    focus = []
    for host in app.cfg['waf']['focus_sites']:
        h = host.lower()
        f = app.db.one("SELECT COUNT(*) n, SUM(outcome='blocked') b, SUM(origin='external') e, "
                       "SUM(origin='external' AND outcome='logged') enb FROM events WHERE host=? AND ts>=? AND ts<?",
                       (h, since, until))
        recent = [event_summary(r) for r in app.db.q(
            'SELECT * FROM events WHERE host=? AND ts>=? AND ts<? ORDER BY ts DESC LIMIT 10', (h, since, until))]
        focus.append({'host': h, 'events': f['n'] or 0, 'blocked': f['b'] or 0, 'external': f['e'] or 0,
                      'external_not_blocked': f['enb'] or 0, 'recent': recent})
    return json_response(200, {
        'range': rng, 'since': util.iso(since), 'until': util.iso(until),
        'totals': {'events': t['n'] or 0, 'blocked': t['b'] or 0, 'logged': t['l'] or 0, 'external': t['ext'] or 0,
                   'internal': t['int'] or 0, 'blocked_confident': t['bc'] or 0, 'blocked_score': t['bs'] or 0},
        'timeline': timeline, 'by_host': _group(app, 'host', since, until),
        'by_family': _by_family(app, since, until),
        'by_src': [{'key': r['k'], 'origin': r['origin'], 'blocked': r['b'] or 0, 'logged': r['l'] or 0, 'geo': geo(r['k'])}
                   for r in src],
        'by_rule': _by_rule(app, since, until), 'score_only': score_only, 'focus': focus,
        'by_country': _by_geo(app, since, until, 'cc'), 'by_asn': _by_geo(app, since, until, 'asn'),
    })


def _by_geo(app, since, until, field, top=15):
    """External sources grouped by country or network owner (GeoIP); [] without a GeoIP database."""
    if not GEO:
        return []
    acc = {}
    for r in app.db.q("SELECT src_ip, SUM(outcome='blocked') b, SUM(outcome='logged') l FROM events "
                      "WHERE ts>=? AND ts<? AND origin='external' GROUP BY src_ip LIMIT 20000", (since, until)):
        g = geo(r['src_ip'])
        if not g or g.get('scope') != 'external':
            continue
        k = g.get(field)
        if k is None:
            k = '?'
        a = acc.setdefault(k, {'key': str(k), 'blocked': 0, 'logged': 0, 'sources': 0,
                               'label': g.get('org') if field == 'asn' else g.get('country')})
        a['blocked'] += r['b'] or 0
        a['logged'] += r['l'] or 0
        a['sources'] += 1
    if not acc or all(k == '?' for k in acc):
        return []
    return sorted(acc.values(), key=lambda x: -(x['blocked'] + x['logged']))[:top]


# --- events --------------------------------------------------------------------------------

def _event_filters(req):
    where, args = [], []
    since, until = _time_param(req, 'since'), _time_param(req, 'until')
    if since is not None:
        where.append('ts>=?')
        args.append(since)
    if until is not None:
        where.append('ts<?')
        args.append(until)
    q = req.query
    if q.get('host'):
        where.append('host=?')
        args.append(q['host'].lower())
    if q.get('path_prefix'):
        where.append("substr(path, 1, ?)=?")
        args += [len(q['path_prefix']), q['path_prefix']]
    if q.get('q'):
        where.append("instr(path, ?)>0")
        args.append(q['q'])
    if q.get('src_ip'):
        v = q['src_ip']
        if '/' in v:
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                raise ApiError(400, 'bad_request', 'src_ip: not an address or network')
            # addresses are stored as text: pick the matching ones from the distinct set seen
            ips = [r[0] for r in req.app.db.q('SELECT DISTINCT src_ip FROM events') if util.ip_in(r[0], [net])]
            if len(ips) > 20000:
                raise ApiError(400, 'bad_request', 'src_ip: network matches too many addresses')
            where.append('src_ip IN (%s)' % ','.join('?' * len(ips)) if ips else '0')
            args += ips
        else:
            where.append('src_ip=?')
            args.append(v)
    rid = _int_param(req, 'rule_id')
    if rid is not None:
        where.append('rule_ids LIKE ?')
        args.append('%%,%d,%%' % rid)
    for key, allowed in (('outcome', ('blocked', 'logged')), ('decided_by', ('confident', 'score', 'fallback', 'other')),
                         ('origin', ('external', 'internal'))):
        if q.get(key):
            if q[key] not in allowed:
                raise ApiError(400, 'bad_request', '%s: one of %s' % (key, ', '.join(allowed)))
            where.append('%s=?' % key)
            args.append(q[key])
    if q.get('family'):
        if q['family'] not in util.FAMILIES:
            raise ApiError(400, 'bad_request', 'unknown family')
        where.append('families LIKE ?')
        args.append('%%,%s,%%' % q['family'])
    return where, args


def events(app, req):
    where, args = _event_filters(req)
    limit = _limit(req)
    cur = _int_param(req, 'cursor')
    if cur is not None:
        where.append('id<?')
        args.append(cur)
    sql = 'SELECT * FROM events' + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY id DESC LIMIT ?'
    rows = app.db.q(sql, args + [limit + 1])
    items = [event_summary(r) for r in rows[:limit]]
    return json_response(200, {'items': items, 'next_cursor': str(rows[limit - 1]['id']) if len(rows) > limit else None})


def event(app, req):
    try:
        eid = int(req.params['id'])
    except ValueError:
        raise ApiError(404, 'not_found')
    r = app.db.one('SELECT * FROM events WHERE id=?', (eid,))
    if not r:
        raise ApiError(404, 'not_found')
    return json_response(200, event_full(r))


def event_stats(app, req):
    g = req.query.get('group_by', 'host')
    since = _time_param(req, 'since') or util.now() - 86400
    until = _time_param(req, 'until') or util.now()
    if g == 'host':
        items = _group(app, 'host', since, until, 1000)
    elif g == 'src_ip':
        items = _group(app, 'src_ip', since, until, 1000)
    elif g == 'hour':
        items = [{'key': util.iso(r['k'] * 3600), 'blocked': r['b'] or 0, 'logged': r['l'] or 0} for r in app.db.q(
            "SELECT CAST(ts/3600 AS INTEGER) k, SUM(outcome='blocked') b, SUM(outcome='logged') l FROM events "
            'WHERE ts>=? AND ts<? GROUP BY k ORDER BY k', (since, until))]
    elif g == 'rule':
        items = _by_rule(app, since, until, 1000)
    elif g == 'family':
        items = _by_family(app, since, until)
    else:
        raise ApiError(400, 'bad_request', 'group_by: host, rule, src_ip, family or hour')
    return json_response(200, {'group_by': g, 'items': items})


def event_export(app, req):
    cur = _int_param(req, 'cursor') or 0
    limit = _limit(req, 1000, 5000)
    rows = app.db.q('SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?', (cur, limit))
    body = ''.join(json.dumps(event_full(r), ensure_ascii=False) + '\n' for r in rows).encode('utf-8')
    nxt = str(rows[-1]['id']) if rows else str(cur)
    headers = [('X-Next-Cursor', nxt), ('X-Content-SHA256', hashlib.sha256(body).hexdigest())]
    return Response(200, body, 'application/x-ndjson; charset=utf-8', headers)


# --- rules / vhosts / crs ------------------------------------------------------------------

def _hits(app, rid):
    t = util.now()
    r = app.db.one('SELECT SUM(ts>=?) d7, COUNT(*) d30, MAX(ts) last FROM event_rules WHERE rule_id=? AND ts>=?',
                   (t - 7 * 86400, rid, t - 30 * 86400))
    return (r['d7'] or 0), (r['d30'] or 0), util.iso(r['last'])


def rules(app, req):
    _, m = app.site.load()
    src = req.query.get('source', 'local')
    if src not in ('local', 'crs', 'plugin', 'vhost_inline', 'base', 'all'):
        raise ApiError(400, 'bad_request', 'unknown source')
    cat = req.query.get('category')
    q = (req.query.get('q') or '').lower()
    out = []
    for r in m.rules:
        d = m.rule_dict(r)
        if src != 'all' and d['source'] != src:
            continue
        if cat and d['category'] != cat:
            continue
        if q and not (q in str(d['id']) or q in d['msg'].lower() or q in d['comment'].lower()
                      or any(q in h for h in d['hosts'])):
            continue
        out.append(d)
    out.sort(key=lambda d: (d['id'] is None, d['id'] or 0))
    limit = _limit(req, 1000, 5000)
    start = _int_param(req, 'cursor') or 0
    page = out[start:start + limit]
    for d in page:
        if d['id'] is not None:
            d['hits_7d'], d['hits_30d'], d['last_hit'] = _hits(app, d['id'])
        else:
            d['hits_7d'] = d['hits_30d'] = 0
            d['last_hit'] = None
    nxt = str(start + limit) if start + limit < len(out) else None
    return json_response(200, {'items': page, 'next_cursor': nxt, 'total': len(out)})


def _rule_id(req):
    try:
        return int(req.params['id'])
    except ValueError:
        raise ApiError(404, 'not_found')


def rule(app, req):
    rid = _rule_id(req)
    r = app.site.rule(rid)
    if not r:
        raise ApiError(404, 'not_found')
    _, m = app.site.load()
    d = m.rule_dict(r)
    d['hits_7d'], d['hits_30d'], d['last_hit'] = _hits(app, rid)
    return json_response(200, d)


def rule_hits(app, req):
    rid = _rule_id(req)
    days = max(1, min(_int_param(req, 'days') or 30, 365))
    t = util.now() - days * 86400
    import datetime
    rows = app.db.q('SELECT day, SUM(CASE WHEN outcome=\'blocked\' THEN n ELSE 0 END) b, '
                    'SUM(CASE WHEN outcome=\'logged\' THEN n ELSE 0 END) l FROM stats_daily '
                    'WHERE rule_id=? AND day>=? GROUP BY day ORDER BY day',
                    (rid, datetime.date.fromtimestamp(t).isoformat()))
    return json_response(200, {'items': [{'day': r['day'], 'blocked': r['b'], 'logged': r['l']} for r in rows]})


def removals(app, req):
    _, m = app.site.load()
    return json_response(200, {'items': m.removals})


def vhosts(app, req):
    n, m = app.site.load()
    items = n.servers()
    items.sort(key=lambda s: (s['server_names'][0] if s['server_names'] else '~', s['file'], s['line']))
    return json_response(200, {'items': items, 'warnings': m.warnings + n.errors + m.errors})


def crs(app, req):
    _, m = app.site.load()
    return json_response(200, m.crs_status())


def lookup_ip(app, req):
    ip = req.params['ip']
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ApiError(400, 'bad_request', 'not an IP address')
    t = util.now()
    d7 = app.db.one("SELECT COUNT(*) n, SUM(outcome='blocked') b FROM events WHERE src_ip=? AND ts>=?", (ip, t - 7 * 86400))
    d30 = app.db.one("SELECT COUNT(*) n, SUM(outcome='blocked') b, MIN(ts) f, MAX(ts) l FROM events WHERE src_ip=? AND ts>=?",
                     (ip, t - 30 * 86400))
    hosts = app.db.q('SELECT host k, COUNT(*) n FROM events WHERE src_ip=? AND ts>=? GROUP BY host ORDER BY n DESC LIMIT 20',
                     (ip, t - 30 * 86400))
    rules_ = app.db.q('SELECT r.rule_id k, COUNT(*) n FROM event_rules r JOIN events e ON e.id=r.event_id '
                      'WHERE e.src_ip=? AND r.ts>=? AND r.rule_id NOT IN (%s) GROUP BY r.rule_id ORDER BY n DESC LIMIT 20'
                      % ','.join(str(x) for x in sorted(util.SCORING_RULES)), (ip, t - 30 * 86400))
    return json_response(200, {
        'ip': ip, 'origin': 'internal' if util.ip_in(ip, app.cfg.internal_networks) else 'external', 'geo': geo(ip),
        'd7': {'events': d7['n'] or 0, 'blocked': d7['b'] or 0}, 'd30': {'events': d30['n'] or 0, 'blocked': d30['b'] or 0},
        'first_seen': util.iso(d30['f']), 'last_seen': util.iso(d30['l']),
        'hosts': [{'key': r['k'], 'events': r['n']} for r in hosts],
        'rules': [{'key': str(r['k']), 'events': r['n']} for r in rules_], 'blocked_now': False})


# --- admin ---------------------------------------------------------------------------------

def users(app, req):
    rows = app.db.q('SELECT * FROM users ORDER BY username')
    return json_response(200, {'items': [_user(app, r) for r in rows]})


def user_create(app, req):
    b = req.body()
    if b.get('role') not in ROLES:
        raise ApiError(400, 'invalid_role')
    temp = app.auth.create_user(str(b.get('username') or ''), b['role'], str(b.get('display_name') or ''),
                                expires_at=b.get('expires_at') or None)
    name = str(b['username']).strip().lower()
    app.audit.log('user.created', req.user['username'], src_ip=req.client_ip, target=name, role=b['role'],
                  expires_at=b.get('expires_at') or None)
    return json_response(201, {'user': _user(app, app.auth.user_row(name)), 'temporary_password': temp})


def _target(app, req):
    r = app.auth.user_row(req.params['username'])
    if not r:
        raise ApiError(404, 'not_found')
    return r


def user_patch(app, req):
    r = _target(app, req)
    b = req.body()
    name = r['username']
    self_edit = name == req.user['username']
    changes = {}
    if 'display_name' in b:
        if not isinstance(b['display_name'], str) or len(b['display_name']) > 64:
            raise ApiError(400, 'bad_request')
        app.db.x('UPDATE users SET display_name=? WHERE username=?', (b['display_name'].strip(), name))
        changes['display_name'] = True
    if 'role' in b and b['role'] != r['role']:
        if b['role'] not in ROLES:
            raise ApiError(400, 'invalid_role')
        if self_edit:
            raise ApiError(400, 'cannot_modify_self')
        if r['role'] == 'admin' and app.auth.admins_active() <= 1:
            raise ApiError(400, 'last_admin')
        app.db.x('UPDATE users SET role=? WHERE username=?', (b['role'], name))
        changes['role'] = b['role']
    if 'disabled' in b and bool(b['disabled']) != bool(r['disabled']):
        if self_edit:
            raise ApiError(400, 'cannot_modify_self')
        if b['disabled'] and r['role'] == 'admin' and app.auth.admins_active() <= 1:
            raise ApiError(400, 'last_admin')
        app.auth.set_disabled(name, bool(b['disabled']))
        changes['disabled'] = bool(b['disabled'])
    if 'expires_at' in b and (b['expires_at'] or None) != util.iso(r['expires_at']):
        app.auth.set_expiry(name, b['expires_at'] or None)
        changes['expires_at'] = b['expires_at'] or None
    if b.get('unlock') and r['locked_until'] > util.now():
        app.db.x('UPDATE users SET failed_count=0, locked_until=0 WHERE username=?', (name,))
        changes['unlocked'] = True
    if changes:
        app.audit.log('user.changed', req.user['username'], src_ip=req.client_ip, target=name, **changes)
    return json_response(200, _user(app, app.auth.user_row(name)))


def user_reset(app, req):
    r = _target(app, req)
    if r['username'] == req.user['username']:
        raise ApiError(400, 'cannot_modify_self')
    temp = app.auth.reset_password(r['username'])
    app.audit.log('user.reset', req.user['username'], src_ip=req.client_ip, target=r['username'])
    return json_response(200, {'temporary_password': temp})


def user_signout(app, req):
    r = _target(app, req)
    n = len(app.auth.sessions_of(r['username']))
    app.auth.drop_sessions(r['username'])
    app.audit.log('sessions.revoked', req.user['username'], src_ip=req.client_ip, target=r['username'], count=n)
    return Response(204)


def users_review(app, req):
    """Account review (periodic access review): every account with role, state and activity."""
    t = util.now()
    items = []
    for r in app.db.q('SELECT * FROM users ORDER BY username'):
        u = _user(app, r)
        u['days_since_activity'] = int((t - (r['activity_at'] or r['created_at'])) // 86400)
        u['sessions'] = app.db.one('SELECT COUNT(*) FROM sessions WHERE username=?', (r['username'],))[0]
        items.append(u)
    toks = [app.auth.token_public(r) for r in app.db.q('SELECT * FROM tokens WHERE revoked=0 ORDER BY created_at')]
    app.audit.log('users.reviewed', req.user['username'], src_ip=req.client_ip, users=len(items), tokens=len(toks))
    return json_response(200, {'generated_at': util.iso(t), 'node_id': app.cfg['node']['id'], 'users': items,
                               'tokens': toks, 'policy': {k: app.cfg['auth'][k] for k in (
                                   'password_min_length', 'password_min_classes', 'password_history',
                                   'password_max_age_days', 'password_min_age_hours', 'dormant_days',
                                   'require_totp_roles', 'lockout_threshold', 'lockout_minutes')}})


def tokens(app, req):
    rows = app.db.q('SELECT * FROM tokens ORDER BY created_at DESC')
    return json_response(200, {'items': [app.auth.token_public(r) for r in rows], 'scopes': list(SCOPES_P1)})


def token_create(app, req):
    b = req.body()
    scopes = b.get('scopes') if isinstance(b.get('scopes'), list) else []
    cidrs = b.get('allowed_cidrs') if isinstance(b.get('allowed_cidrs'), list) else []
    tid, secret = app.auth.create_token(b.get('name'), [str(s) for s in scopes], [str(c) for c in cidrs],
                                        b.get('expires_at'), req.user['username'])
    row = app.db.one('SELECT * FROM tokens WHERE id=?', (tid,))
    app.audit.log('token.created', req.user['username'], src_ip=req.client_ip, token=row['name'],
                  token_id=tid, scopes=json.loads(row['scopes']))
    return json_response(201, {'token': app.auth.token_public(row), 'secret': secret})


def token_revoke(app, req):
    r = app.db.one('SELECT * FROM tokens WHERE id=?', (req.params['id'],))
    if not r:
        raise ApiError(404, 'not_found')
    app.db.x('UPDATE tokens SET revoked=1 WHERE id=?', (r['id'],))
    app.audit.log('token.revoked', req.user['username'], src_ip=req.client_ip, token=r['name'], token_id=r['id'])
    return Response(204)


def audit_list(app, req):
    items, nxt = app.audit.list(req.query.get('action') or None, req.query.get('actor') or None,
                                _limit(req), _int_param(req, 'cursor'))
    return json_response(200, {'items': items, 'next_cursor': nxt})


def settings(app, req):
    c = app.cfg
    return json_response(200, {
        'config_file': c.path, 'node_id': c['node']['id'],
        'internal_networks': c['network']['internal'], 'known_scanners': c['network']['known_scanners'],
        'focus_sites': c['waf']['focus_sites'], 'sensitive_fields': c['waf']['sensitive_fields'],
        'id_ranges': {'local': c['waf']['local_range'], 'confident': c['waf']['confident_range'],
                      'threshold_rule_ids': c['waf']['threshold_rule_ids'], 'fallback_rule_ids': c['waf']['fallback_rule_ids']},
        'audit_log': c['paths']['audit_log'], 'nginx_conf': c['paths']['nginx_conf'],
        'retention_days': {'events': c['retention']['events_days'], 'stats': c['retention']['stats_days']},
        'password_min_length': c['auth']['password_min_length'], 'require_totp_roles': c['auth']['require_totp_roles'],
        'session_idle_minutes': c['server']['session_idle_minutes'], 'syslog': c['syslog'],
        'account_policy': {k: c['auth'][k] for k in ('lockout_threshold', 'lockout_minutes', 'dormant_days',
                                                     'max_sessions_per_user', 'password_max_age_days',
                                                     'password_min_age_hours', 'password_history', 'password_min_classes')},
        'integrity': {k: c['integrity'][k] for k in ('anchor_minutes', 'program_check_minutes', 'config_check_minutes',
                                                     'disk_min_free_mb')},
        'geoip': {k: c['geoip'][k] for k in ('enabled', 'editions', 'update_days')},
        'compliance_level': c['compliance']['level'],
    })


def register(router):
    R = router.add
    viewer = lambda scope: ('role', 'viewer', scope)
    admin = ('admin',)
    R('GET', V + '/meta', meta, 'public')
    R('POST', V + '/auth/login', login, 'public')
    R('POST', V + '/auth/logout', logout, 'public')
    R('GET', V + '/auth/me', me, 'session')
    R('PATCH', V + '/auth/me', patch_me, 'session')
    R('POST', V + '/auth/password', change_password, 'session')
    R('GET', V + '/auth/sessions', my_sessions, 'session')
    R('POST', V + '/auth/sessions/revoke-others', my_sessions_revoke_others, 'session')
    R('POST', V + '/auth/totp/setup', totp_setup, 'session')
    R('POST', V + '/auth/totp/enable', totp_enable, 'session')
    R('POST', V + '/auth/totp/disable', totp_disable, 'session')
    R('GET', V + '/status', status, viewer('status:read'))
    R('GET', V + '/overview', overview, viewer('events:read'))
    R('GET', V + '/events', events, viewer('events:read'))
    R('GET', V + '/events/stats', event_stats, viewer('events:read'))
    R('GET', V + '/events/export', event_export, viewer('events:read'))
    R('GET', V + '/events/{id}', event, viewer('events:read'))
    R('GET', V + '/rules', rules, viewer('rules:read'))
    R('GET', V + '/rules/removals', removals, viewer('rules:read'))
    R('GET', V + '/rules/{id}', rule, viewer('rules:read'))
    R('GET', V + '/rules/{id}/hits', rule_hits, viewer('rules:read'))
    R('GET', V + '/vhosts', vhosts, viewer('rules:read'))
    R('GET', V + '/crs', crs, viewer('rules:read'))
    R('GET', V + '/lookups/ip/{ip}', lookup_ip, viewer('lookups:read'))
    R('GET', V + '/users', users, admin)
    R('POST', V + '/users', user_create, admin)
    R('PATCH', V + '/users/{username}', user_patch, admin)
    R('GET', V + '/users/review', users_review, admin)
    R('POST', V + '/users/{username}/reset', user_reset, admin)
    R('POST', V + '/users/{username}/signout', user_signout, admin)
    R('GET', V + '/tokens', tokens, admin)
    R('POST', V + '/tokens', token_create, admin)
    R('DELETE', V + '/tokens/{id}', token_revoke, admin)
    R('GET', V + '/audit', audit_list, admin)
    R('GET', V + '/settings', settings, admin)
    register_p2(router)
    register_compliance(router)


# --- P2: managed files, changes, versions -----------------------------------------------------

from ..changes import ChangeError  # noqa: E402
from ..modsecconf import parse_rules_text  # noqa: E402


def _wf(app):
    return app.workflow


def _change_error(e):
    return ApiError(e.status, e.code, e.code.replace('_', ' '), **e.details)


def _item_public(app, m, it):
    rules = []
    if it['text']:
        parse_rules_text(it['text'], app.workflow.managed.path(it['placement']), rules, [], [], [])
    cat = m.category_of(rules[0]) if rules and it['kind'] == 'raw' else it['kind']
    d = m.rule_dict(rules[0]) if rules else {}
    return {'id': it['id'], 'rule_id': it['rule_id'], 'kind': it['kind'], 'category': cat, 'placement': it['placement'],
            'position': it['position'], 'enabled': bool(it['enabled']), 'deleted': bool(it['deleted']),
            'origin': it['origin'], 'comment': it['comment'], 'text': it['text'], 'spec': json.loads(it['spec'])
            if isinstance(it['spec'], str) else it['spec'], 'msg': d.get('msg', ''), 'hosts': d.get('hosts', []),
            'created_by': it.get('created_by'), 'created_at': util.iso(it.get('created_at')),
            'updated_at': util.iso(it.get('updated_at')), 'change_id': it.get('change_id')}


def managed(app, req):
    wf = _wf(app)
    mg = wf.managed
    _, m = app.site.load()
    disk = mg.disk_state()
    cur = mg.current_version()
    out = {'adopted': disk['adopted'], 'dir': mg.dir, 'files': disk['files'], 'drift': disk['drift'],
           'current_version': cur['version'] if cur else None,
           'items': [_item_public(app, m, it) for it in mg.items() if it['kind'] != 'comment' or req.query.get('comments')]}
    if not disk['adopted']:
        try:
            items, sources = mg.import_preview()
            out['import'] = {'sources': sources, 'rules': sum(1 for i in items if i['text']),
                             'comment_blocks': sum(1 for i in items if not i['text'])}
        except OSError as e:
            out['import'] = {'error': str(e)[:200]}
        r = app.db.one("SELECT id, state FROM changes WHERE op='adopt' ORDER BY id DESC LIMIT 1")
        out['adoption_change'] = {'id': r['id'], 'state': r['state']} if r else None
    return json_response(200, out)


def managed_item(app, req):
    it = _wf(app).managed.item(_cid(req))
    if not it or it['kind'] == 'comment':
        raise ApiError(404, 'not_found')
    _, m = app.site.load()
    return json_response(200, _item_public(app, m, it))


def managed_adopt(app, req):
    try:
        cid = _wf(app).propose_adoption(req.user['username'])
    except ChangeError as e:
        raise _change_error(e)
    return json_response(202, {'change_id': cid, 'state': 'checking'})


def changes_list(app, req):
    items, nxt = _wf(app).list(req.query.get('state') or None, _limit(req), _int_param(req, 'cursor'))
    return json_response(200, {'items': items, 'next_cursor': nxt})


def change_get(app, req):
    try:
        r = _wf(app).get(int(req.params['id']))
    except (ValueError, ChangeError):
        raise ApiError(404, 'not_found')
    return json_response(200, _wf(app).public(r, full=True))


def change_create(app, req):
    b = req.body()
    actor, via = (req.user['username'], 'user') if req.user is not None else (req.token['name'], 'api')
    role = req.user['role'] if req.user is not None else None
    if via == 'user' and role == 'viewer':
        raise ApiError(403, 'forbidden')
    spec = b.get('spec') if isinstance(b.get('spec'), dict) else {}
    try:
        cid = _wf(app).propose(str(b.get('op') or 'add'), str(b.get('kind') or ''), spec, b.get('reason'), actor, via,
                               item_id=b.get('item_id') if isinstance(b.get('item_id'), int) else None,
                               tests=b.get('tests') if isinstance(b.get('tests'), list) else [], role=role)
    except ChangeError as e:
        raise _change_error(e)
    r = _wf(app).get(cid)
    return json_response(202, {'change_id': cid, 'direction': r['direction'], 'state': r['state'], 'rule_id': r['rule_id']})


def change_preview(app, req):
    """Render a template without creating anything: rule text, direction, next rule id, or the field error."""
    from .. import rulegen
    b = req.body()
    kind = str(b.get('kind') or '')
    spec = b.get('spec') if isinstance(b.get('spec'), dict) else {}
    mg = _wf(app).managed
    item = mg.item(b['item_id']) if isinstance(b.get('item_id'), int) else None
    try:
        if kind == 'raw':
            ids = rulegen.check_raw_text(spec.get('text') or '', cfg=app.cfg)
            rid = ids[0] if ids else None
        elif item is not None:
            rid = item['rule_id']   # modify keeps the rule's own id
        else:
            rid = mg.next_rule_id(kind)
        spec, text, placement = rulegen.build(kind, spec, rid, app.cfg)
    except rulegen.SpecError as e:
        return json_response(200, {'ok': False, 'field': e.field, 'reason': e.code, 'details': e.details})
    except ValueError as e:
        return json_response(200, {'ok': False, 'field': 'kind', 'reason': str(e)})
    return json_response(200, {'ok': True, 'rule_id': rid, 'rule_text': text, 'placement': placement,
                               'direction': rulegen.direction('add', kind, text)})


def _cid(req):
    try:
        return int(req.params['id'])
    except ValueError:
        raise ApiError(404, 'not_found')


def change_approve(app, req):
    b = req.body()
    try:
        _wf(app).approve(_cid(req), req.user, str(b.get('totp') or ''), str(b.get('note') or ''))
    except ChangeError as e:
        app.audit.log('change.approve_denied', req.user['username'], src_ip=req.client_ip, result='denied', reason=e.code,
                      target=req.params.get('id') or req.params.get('version'))
        raise _change_error(e)
    return json_response(200, _wf(app).public(_wf(app).get(_cid(req)), full=True))


def change_reject(app, req):
    try:
        _wf(app).reject(_cid(req), req.user, str(req.body().get('note') or ''))
    except ChangeError as e:
        app.audit.log('change.reject_denied', req.user['username'], src_ip=req.client_ip, result='denied', reason=e.code,
                      target=req.params.get('id') or req.params.get('version'))
        raise _change_error(e)
    return json_response(200, _wf(app).public(_wf(app).get(_cid(req)), full=True))


def change_cancel(app, req):
    try:
        _wf(app).cancel(_cid(req), req.user)
    except ChangeError as e:
        app.audit.log('change.cancel_denied', req.user['username'], src_ip=req.client_ip, result='denied', reason=e.code,
                      target=req.params.get('id') or req.params.get('version'))
        raise _change_error(e)
    return json_response(200, _wf(app).public(_wf(app).get(_cid(req)), full=True))


def change_recheck(app, req):
    try:
        _wf(app).recheck(_cid(req), req.user, str(req.body().get('evidence_override') or ''))
    except ChangeError as e:
        app.audit.log('change.recheck_denied', req.user['username'], src_ip=req.client_ip, result='denied', reason=e.code,
                      target=req.params.get('id') or req.params.get('version'))
        raise _change_error(e)
    return json_response(200, _wf(app).public(_wf(app).get(_cid(req)), full=True))


def versions(app, req):
    rows = app.db.q('SELECT version, created_at, change_id, kind, hashes, state, result FROM versions ORDER BY version DESC LIMIT ?',
                    (_limit(req, 50, 500),))
    out = []
    for r in rows:
        res = json.loads(r['result'] or '{}')
        out.append({'version': r['version'], 'created_at': util.iso(r['created_at']), 'change_id': r['change_id'],
                    'kind': r['kind'], 'state': r['state'], 'summary': res.get('summary'), 'step': res.get('step'),
                    'health': res.get('health'), 'nginx_t': res.get('nginx_t')})
    return json_response(200, {'items': out})


def version_rollback(app, req):
    try:
        v = int(req.params['version'])
    except ValueError:
        raise ApiError(404, 'not_found')
    try:
        b = req.body()
        cid = _wf(app).rollback(v, req.user, str(b.get('note') or ''), overwrite_drift=b.get('overwrite_drift') is True)
    except ChangeError as e:
        app.audit.log('change.rollback_denied', req.user['username'], src_ip=req.client_ip, result='denied', reason=e.code,
                      target=req.params.get('id') or req.params.get('version'))
        raise _change_error(e)
    return json_response(202, {'change_id': cid})


def workflow_settings(app, req):
    return json_response(200, {'settings': _wf(app).settings(),
                               'sandbox_available': _wf(app).sandbox.available() if _wf(app).sandbox else False})


def workflow_settings_patch(app, req):
    b = req.body()
    wf = _wf(app)
    try:
        for k, v in b.items():
            old = wf.setting(k)
            wf.set_setting(k, v, req.user['username'])
            if old != v:
                app.audit.log('settings.changed', req.user['username'], src_ip=req.client_ip, key=k, old=old, new=v)
    except ChangeError as e:
        raise _change_error(e)
    return workflow_settings(app, req)


def regression_list(app, req):
    rows = app.db.q('SELECT * FROM regression_samples ORDER BY pinned DESC, host, path LIMIT 5000')
    return json_response(200, {'items': [{'id': r['id'], 'host': r['host'], 'method': r['method'], 'path': r['path'],
                                          'source': r['source'], 'pinned': bool(r['pinned']), 'note': r['note'],
                                          'added_at': util.iso(r['added_at'])} for r in rows],
                               'collected_at': util.iso(_wf(app).managed.setting('samples.collected_at'))})


def regression_add(app, req):
    b = req.body()
    host = str(b.get('host') or '').strip().lower()
    path = str(b.get('path') or '')
    method = str(b.get('method') or 'GET').upper()
    import re as _re
    if not _re.fullmatch(r'[a-z0-9.-]{1,255}', host) or not path.startswith('/') or len(path) > 2048 or \
            _re.search(r'[\s\x00-\x1f]', path) or method not in ('GET', 'POST', 'HEAD'):
        raise ApiError(400, 'bad_request')
    app.db.x('INSERT OR REPLACE INTO regression_samples(host, method, path, source, pinned, note, added_at) '
             "VALUES (?,?,?,'user',1,?,?)", (host, method, path, str(b.get('note') or '')[:200], util.now()))
    app.audit.log('regression.added', req.user['username'], src_ip=req.client_ip, host=host, path=path[:200])
    return regression_list(app, req)


def regression_delete(app, req):
    r = app.db.one('SELECT * FROM regression_samples WHERE id=?', (_cid(req),))
    if r:
        app.db.x('DELETE FROM regression_samples WHERE id=?', (r['id'],))
        app.audit.log('regression.deleted', req.user['username'], src_ip=req.client_ip, host=r['host'],
                      path=r['path'][:200])
    return Response(204)


def regression_collect(app, req):
    import threading
    wf = _wf(app)
    wf.managed.set_setting('samples.collected_at', util.now())
    threading.Thread(target=wf.evidence.collect_samples, daemon=True).start()
    app.audit.log('regression.collect_started', req.user['username'], src_ip=req.client_ip)
    return json_response(202, {'started': True})


def register_p2(router):
    R = router.add
    viewer = lambda scope: ('role', 'viewer', scope)
    R('GET', V + '/managed', managed, viewer('rules:read'))
    R('POST', V + '/managed/adopt', managed_adopt, ('admin',))
    R('GET', V + '/managed/items/{id}', managed_item, viewer('rules:read'))
    R('GET', V + '/changes', changes_list, viewer('changes:read'))
    R('POST', V + '/changes', change_create, ('role', 'viewer', 'changes:propose'))
    R('POST', V + '/changes/preview', change_preview, ('role', 'operator', 'changes:propose'))
    R('GET', V + '/changes/{id}', change_get, viewer('changes:read'))
    R('POST', V + '/changes/{id}/approve', change_approve, ('role', 'approver', None))
    R('POST', V + '/changes/{id}/reject', change_reject, ('role', 'approver', None))
    R('POST', V + '/changes/{id}/cancel', change_cancel, ('role', 'operator', None))
    R('POST', V + '/changes/{id}/recheck', change_recheck, ('role', 'operator', None))
    R('GET', V + '/versions', versions, viewer('changes:read'))
    R('POST', V + '/versions/{version}/rollback', version_rollback, ('role', 'approver', None))
    R('GET', V + '/workflow/settings', workflow_settings, ('admin',))
    R('PATCH', V + '/workflow/settings', workflow_settings_patch, ('admin',))
    R('GET', V + '/regression', regression_list, viewer('changes:read'))
    R('POST', V + '/regression', regression_add, ('role', 'operator', None))
    R('DELETE', V + '/regression/{id}', regression_delete, ('role', 'operator', None))
    R('POST', V + '/regression/collect', regression_collect, ('admin',))


# --- compliance and integrity ------------------------------------------------------------------

from .. import compliance as _compliance  # noqa: E402


def system_check(app, req):
    return json_response(200, {'generated_at': util.iso(util.now()), 'items': _compliance.system_check(app)})


def system_check_run(app, req):
    mon = app.monitor
    mon.check_program()
    mon.check_chain(full=True)
    mon.check_config()
    mon.check_db()
    app.audit.log('system.checked', req.user['username'], src_ip=req.client_ip)
    return system_check(app, req)


def audit_verify(app, req):
    res = app.monitor.check_chain(full=True)
    app.audit.log('audit.verified', req.user['username'], src_ip=req.client_ip, result='ok' if res['ok'] else 'failed',
                  rows=res['rows'], chain_ok=res['ok'])
    return json_response(200, res)


def audit_export(app, req):
    since, until = _time_param(req, 'since'), _time_param(req, 'until')
    body, summary = _compliance.audit_export(app, since, until)
    app.audit.log('audit.exported', req.user['username'], src_ip=req.client_ip, rows=summary['rows'],
                  sha256=summary['sha256_of_lines'])
    name = 'jt-waf-mgr-audit-%s.ndjson' % time.strftime('%Y%m%d-%H%M%S')
    return Response(200, body.encode('utf-8'), 'application/x-ndjson; charset=utf-8',
                    [('Content-Disposition', 'attachment; filename="%s"' % name),
                     ('X-Content-SHA256', summary['sha256_of_lines'])])


def config_changes(app, req):
    items, nxt = app.monitor.config_changes(_limit(req, 50, 200), _int_param(req, 'cursor'))
    return json_response(200, {'items': items, 'next_cursor': nxt})


def config_change(app, req):
    try:
        sid = int(req.params['id'])
    except ValueError:
        raise ApiError(404, 'not_found')
    r = app.monitor.config_snapshot(sid)
    if not r:
        raise ApiError(404, 'not_found')
    return json_response(200, r)


def compliance_report(app, req):
    return json_response(200, _compliance.controls(app))


def backups(app, req):
    last = app.workflow.managed.setting('backup.last') or {}
    b = app.cfg['backup']
    return json_response(200, {'items': app.monitor.backups(), 'last': {k: v for k, v in last.items() if k != 'ts'},
                               'enabled': b['enabled'], 'dir': b['dir'], 'keep_days': b['keep_days'], 'hour': b['hour']})


def backup_now(app, req):
    res = app.monitor.backup(actor=req.user['username'])
    if not res['ok']:
        raise ApiError(500, 'backup_failed', 'backup failed', error=res.get('error') or '', file=res.get('file'))
    return json_response(201, {k: v for k, v in res.items() if k != 'ts'})


def backup_verify(app, req):
    res = app.monitor.verify_backup(req.params['name'])
    if res is None:
        raise ApiError(404, 'not_found')
    app.audit.log('backup.verified', req.user['username'], src_ip=req.client_ip,
                  result='ok' if res['ok'] else 'failed', file=res['file'])
    return json_response(200, res)


def geoip_status(app, req):
    return json_response(200, app.geoip.status())


def geoip_update(app, req):
    """The web service never downloads: it leaves a request file for the sandboxed updater unit."""
    try:
        app.geoip.request_update()
    except OSError as e:
        raise ApiError(500, 'geoip_request_failed', 'could not queue the update', error=e.strerror)
    app.audit.log('geoip.update_requested', req.user['username'], src_ip=req.client_ip)
    return json_response(202, app.geoip.status())


def geoip_lookup(app, req):
    ip = req.params['ip']
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ApiError(400, 'bad_request', 'not an IP address')
    return json_response(200, {'ip': ip, 'geo': geo(ip), 'available': app.geoip.available()})


def register_compliance(router):
    R = router.add
    admin = ('admin',)
    R('GET', V + '/system/check', system_check, admin)
    R('POST', V + '/system/check', system_check_run, admin)
    R('POST', V + '/audit/verify', audit_verify, admin)
    R('GET', V + '/audit/export', audit_export, admin)
    R('GET', V + '/config-changes', config_changes, ('role', 'approver', None))
    R('GET', V + '/config-changes/{id}', config_change, ('role', 'approver', None))
    R('GET', V + '/compliance', compliance_report, admin)
    R('GET', V + '/backups', backups, admin)
    R('GET', V + '/geoip', geoip_status, admin)
    R('POST', V + '/geoip/update', geoip_update, admin)
    R('GET', V + '/geoip/{ip}', geoip_lookup, ('role', 'viewer', 'lookups:read'))
    R('POST', V + '/backups', backup_now, admin)
    R('POST', V + '/backups/{name}/verify', backup_verify, admin)

