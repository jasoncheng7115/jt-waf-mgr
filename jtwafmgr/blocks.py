"""Temporary IP blocks: an nginx deny list that other systems (fail2ban on a mail host, a SOAR playbook) and
approvers fill, without the change workflow.

Why not a change: a brute-force block has to work within a minute and goes away by itself; it is data, not
configuration. Why nginx and not ModSecurity: some sites run without ModSecurity and some locations switch it off
(uploads, WebSocket); `deny` at the http{} level covers every server and location that has no allow / deny of
its own (nginx does not inherit them into a block that defines its own -- listed as not covered).

How it reaches nginx: the administrator adds once, inside http{}:
    include /etc/nginx/jt-waf-mgr/blocked-ips.conf;
The root apply program writes that file ("deny <address>;" lines, always ending in "allow all;", which is
nginx's default and shows that the file is really loaded at the http{} level), tests and reloads nginx. The web
service only queues the whole list (one request, at most once per [blocks] reload_seconds); the database is the
source of truth, so a lost file is written again.

Never blocked (checked here and again by the root program): private, loopback, link-local, multicast and
reserved addresses, the internal networks, the known scanners, the trusted proxies and the protected list
(for example a CDN in front of the sites: blocking one of its addresses would block everyone behind it).
A token blocks single addresses only, for at most api_max_ttl; an approver may block a range up to /24 (IPv4)
or /64 (IPv6) for at most ui_max_ttl. Nothing is permanent.

One active entry per (address, source): the same source sending the same address again extends it; another
source gets its own entry, and removing one source's entry leaves the others (the address stays blocked until
the last one ends).
"""
import hashlib
import ipaddress
import json
import os
import re
import threading
import time

from . import util

SOURCE_RE = re.compile(r'[\w.:@/+-]{1,64}')
STATES = ('active', 'removed', 'expired')
# never a block target: these are not addresses of someone on the internet (the documentation ranges are left
# blockable on purpose: harmless, and what the tests use)
NON_PUBLIC = [ipaddress.ip_network(n) for n in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
    '224.0.0.0/3', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '::ffff:0:0/96')]
HARD_MAX = 20000          # the root program refuses a longer list whatever the settings say
META_APPLIED = 'blocks_applied'     # {"sha": ..., "at": ..., "count": n, "ok": bool, "summary": ...}
META_PENDING = 'blocks_pending'     # {"request_id": ..., "sha": ..., "at": ...}


class BlockError(Exception):
    def __init__(self, code, status=422, **extra):
        super().__init__(code)
        self.code, self.status, self.extra = code, status, extra


def _nets(items):
    out = []
    for x in items or []:
        try:
            out.append(ipaddress.ip_network(str(x), strict=False))
        except ValueError:
            continue
    return out


def never_blocked(cfg):
    """The networks no block may touch."""
    b = cfg['blocks']
    return (list(cfg.internal_networks) + list(cfg.known_scanners) + _nets(cfg['server'].get('trusted_proxies'))
            + _nets(b.get('protected')))


def _non_public(net):
    return any(p.version == net.version and (net.subnet_of(p) or p.subnet_of(net)) for p in NON_PUBLIC)


def check_target(cfg, value, allow_range=False):
    """A normalised network string, or BlockError."""
    s = str(value or '').strip()
    if not s or len(s) > 64:
        raise BlockError('invalid_ip')
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        raise BlockError('invalid_ip')
    full = 32 if net.version == 4 else 128
    if net.prefixlen != full:
        if not allow_range:
            raise BlockError('single_address_only')
        if net.prefixlen < (24 if net.version == 4 else 64):
            raise BlockError('range_too_wide', limit='/24' if net.version == 4 else '/64')
    if _non_public(net):
        raise BlockError('not_public')
    a = net.network_address
    for p in never_blocked(cfg):
        if p.version == net.version and (net.subnet_of(p) or p.subnet_of(net)):
            raise BlockError('protected', network=str(p))
    return str(net) if net.prefixlen != full else str(a)


def public(r):
    return {'id': r['id'], 'ip': r['ip'], 'source': r['source'], 'reason': r['reason'], 'state': r['state'],
            'created_at': util.iso(r['created_at']), 'expires_at': util.iso(r['expires_at']),
            'created_by': r['created_by'], 'via': r['via'], 'extended': r['extended'],
            'ended_at': util.iso(r['ended_at']) if r['ended_at'] else None, 'ended_by': r['ended_by']}


class Blocks:
    def __init__(self, app):
        self.app = app
        self.cfg, self.db = app.cfg, app.db
        self._rate = {}          # token id -> [timestamps of adds in the last hour]
        self._lock = threading.Lock()

    # --- reading --------------------------------------------------------------------------------
    def active(self):
        return self.db.q("SELECT * FROM ip_blocks WHERE state='active' ORDER BY id")

    def listing(self, state='active', limit=500):
        if state not in STATES + ('all',):
            raise BlockError('invalid_state', 400)
        sql = 'SELECT * FROM ip_blocks' + ('' if state == 'all' else ' WHERE state=?') + ' ORDER BY id DESC LIMIT ?'
        return [public(r) for r in self.db.q(sql, ((state,) if state != 'all' else ()) + (limit,))]

    def blocked(self, ip):
        """The active entries that cover one address (an exact entry or a range containing it)."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return []
        out = []
        for r in self.active():
            n = ipaddress.ip_network(r['ip'], strict=False)
            if n.version == a.version and a in n:
                out.append(public(r))
        return out

    def desired(self):
        """The distinct networks that should be in the file, sorted."""
        nets = {ipaddress.ip_network(r['ip'], strict=False) for r in self.active()}
        return [str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)
                for n in sorted(nets, key=lambda n: (n.version, n))]

    @staticmethod
    def list_sha(entries):
        return hashlib.sha256('\n'.join(entries).encode()).hexdigest()

    # --- writing --------------------------------------------------------------------------------
    def _rate_ok(self, token_id):
        b = self.cfg['blocks']
        now = time.time()
        with self._lock:
            ts = [t for t in self._rate.get(token_id, []) if now - t < 3600]
            if len(ts) >= b['token_per_hour']:
                self._rate[token_id] = ts
                return False
            ts.append(now)
            self._rate[token_id] = ts
            return True

    def _refuse(self, actor, via, src_ip, code, **detail):
        self.app.audit.log('block.refused', actor, via if via == 'token' else 'user', src_ip, 'denied',
                           reason=code, **{k: util.clip(str(v), 200) for k, v in detail.items()})

    def add(self, ip, ttl, source, reason, actor, via='user', token_id=None, role=None, src_ip=None):
        """Block (or extend). via: 'token' (single address, api_max_ttl) or 'user' (approver; ranges, ui_max_ttl)."""
        b = self.cfg['blocks']
        if not b['enabled']:
            raise BlockError('blocks_off', 409)
        source = str(source or ('ui' if via == 'user' else '')).strip()
        reason = ' '.join(str(reason or '').split())[:300]
        try:
            if not SOURCE_RE.fullmatch(source):
                raise BlockError('invalid_source')
            if not reason:
                raise BlockError('reason_required')
            try:
                ttl = int(ttl if ttl not in (None, '') else b['default_ttl'])
            except (TypeError, ValueError):
                raise BlockError('invalid_ttl')
            top = b['api_max_ttl'] if via == 'token' else b['ui_max_ttl']
            if not b['min_ttl'] <= ttl <= top:
                raise BlockError('invalid_ttl', min=b['min_ttl'], max=top)
            net = check_target(self.cfg, ip, allow_range=via == 'user' and role in ('approver', 'admin'))
            if via == 'token' and not self._rate_ok(token_id):
                raise BlockError('rate_limited', 429, per_hour=b['token_per_hour'])
        except BlockError as e:
            self._refuse(actor, via, src_ip, e.code, ip=ip, source=source)
            raise
        now = util.now()
        exp = now + ttl
        with self.db.tx() as c:
            r = c.execute("SELECT * FROM ip_blocks WHERE state='active' AND ip=? AND source=?", (net, source)).fetchone()
            if r:
                new_exp = max(r['expires_at'], exp)
                c.execute('UPDATE ip_blocks SET expires_at=?, extended=extended+1, reason=? WHERE id=?', (new_exp, reason, r['id']))
                bid, action = r['id'], 'block.extend'
            else:
                n = c.execute("SELECT COUNT(*) FROM ip_blocks WHERE state='active'").fetchone()[0]
                if n >= b['max_active']:
                    bid = None
                elif via == 'token' and c.execute("SELECT COUNT(*) FROM ip_blocks WHERE state='active' AND token_id=?",
                                                  (token_id,)).fetchone()[0] >= b['max_per_token']:
                    bid = -1
                else:
                    cur = c.execute('INSERT INTO ip_blocks(ip, source, reason, state, created_at, expires_at, created_by, via, '
                                    "token_id) VALUES (?,?,?,'active',?,?,?,?,?)",
                                    (net, source, reason, now, exp, actor, via, token_id))
                    bid = cur.lastrowid
                action = 'block.add'
        if bid is None or bid == -1:
            code = 'too_many_blocks' if bid is None else 'too_many_for_token'
            self._refuse(actor, via, src_ip, code, ip=net, source=source)
            if bid is None:
                from . import alerts
                alerts.raise_alert(self.db, self.app.audit, 'blocks', 'other', 'warning', 'blocks_full',
                                   {'reason': 'the IP block list is full (%d); new blocks are refused' % b['max_active']})
            raise BlockError(code, 409, limit=b['max_active'] if bid is None else b['max_per_token'])
        self.app.audit.log(action, actor, via if via == 'token' else 'user', src_ip, 'ok', ip=net, source=source,
                           ttl=ttl, block_id=bid, token_id=token_id, reason=util.clip(reason, 200))
        self.sync()
        return public(self.db.one('SELECT * FROM ip_blocks WHERE id=?', (bid,)))

    def remove(self, actor, via='user', ip=None, source=None, block_id=None, token_id=None, src_ip=None, note=''):
        """End blocks early. A token ends only its own entries (by address, optionally one source); a person ends
        one entry by id (any source), with a note."""
        if via == 'token':
            try:
                net = check_target(self.cfg, ip) if ip else None
            except BlockError:
                net = str(ip or '')[:64]
            if not net:
                self._refuse(actor, via, src_ip, 'invalid_ip', ip=ip)
                raise BlockError('invalid_ip')
            sql, args = "SELECT * FROM ip_blocks WHERE state='active' AND ip=? AND token_id=?", [net, token_id]
            if source:
                sql += ' AND source=?'
                args.append(str(source))
            rows = self.db.q(sql, tuple(args))
        else:
            if not (note or '').strip():
                self._refuse(actor, via, src_ip, 'note_required', block_id=block_id)
                raise BlockError('note_required')
            rows = self.db.q("SELECT * FROM ip_blocks WHERE state='active' AND id=?", (block_id,))
        if not rows:
            self._refuse(actor, via, src_ip, 'remove_not_found', ip=ip or '', block_id=block_id or '', source=source or '')
            raise BlockError('not_found', 404)
        now = util.now()
        for r in rows:
            self.db.x("UPDATE ip_blocks SET state='removed', ended_at=?, ended_by=? WHERE id=? AND state='active'",
                      (now, actor, r['id']))
            self.app.audit.log('block.remove', actor, via if via == 'token' else 'user', src_ip, 'ok', ip=r['ip'],
                               source=r['source'], block_id=r['id'], token_id=token_id,
                               note=util.clip(' '.join(str(note or '').split()), 200))
        self.sync()
        return len(rows)

    def expire(self, now=None):
        now = now or util.now()
        rows = self.db.q("SELECT * FROM ip_blocks WHERE state='active' AND expires_at<=?", (now,))
        for r in rows:
            self.db.x("UPDATE ip_blocks SET state='expired', ended_at=?, ended_by='system' WHERE id=? AND state='active'",
                      (now, r['id']))
        if rows:
            self.app.audit.log('block.expired', 'system', 'system', None, 'ok', count=len(rows),
                               ips=[r['ip'] for r in rows[:50]])
        return len(rows)

    def purge(self, days=90):
        return self.db.x("DELETE FROM ip_blocks WHERE state!='active' AND ended_at<?", (util.now() - days * 86400,)).rowcount

    # --- to nginx -------------------------------------------------------------------------------
    def _meta(self, key):
        try:
            return json.loads(self.db.get_meta(key) or 'null')
        except ValueError:
            return None

    def sync(self, force=False):
        """Queue the whole list for the apply program when it differs from what was last written, at most once
        per reload_seconds and with one request in flight."""
        b = self.cfg['blocks']
        if not b['enabled']:
            return None
        wf = getattr(self.app, 'workflow', None)
        if wf is None:
            return None
        entries = self.desired()
        sha = self.list_sha(entries)
        applied = self._meta(META_APPLIED) or {}
        pending = self._meta(META_PENDING)
        now = time.time()
        if pending:
            if now - pending.get('at', 0) < 600:
                return None          # one in flight; its result decides what comes next
            pending = None           # lost (the apply program never answered): send again
        if not force and applied.get('sha') == sha and applied.get('ok'):
            return None
        if not force and now - (applied.get('at') or 0) < b['reload_seconds']:
            return None
        rid = 'blocks-%d' % int(now * 1000)
        wf._write_request({'request_id': rid, 'action': 'blocks', 'entries': entries, 'sha256': sha,
                           'wait_old_workers': wf.setting('apply.wait_old_workers_seconds')})
        self.db.set_meta(META_PENDING, json.dumps({'request_id': rid, 'sha': sha, 'at': now, 'count': len(entries)}))
        return rid

    def handle_result(self, res):
        pending = self._meta(META_PENDING) or {}
        if pending.get('request_id') and pending['request_id'] != res.get('request_id'):
            return
        ok = res.get('result') == 'ok'
        self.db.set_meta(META_APPLIED, json.dumps({
            'sha': res.get('sha256') if ok else (self._meta(META_APPLIED) or {}).get('sha'), 'at': time.time(),
            'count': res.get('count'), 'ok': ok, 'changed': res.get('changed'),
            'summary': util.clip(str(res.get('summary') or ''), 500)}))
        self.db.set_meta(META_PENDING, 'null')
        self.app.audit.log('block.applied' if ok else 'block.apply_failed', 'system', 'system', None, 'ok' if ok else 'error',
                           severity=None if ok else 'crit', count=res.get('count'),
                           summary=util.clip(str(res.get('summary') or ''), 300))
        if not ok:
            from . import alerts
            alerts.raise_alert(self.db, self.app.audit, 'blocks', 'apply_failed', 'critical', 'blocks_apply_failed',
                               {'reason': 'the IP block list could not be written: %s' % util.clip(str(res.get('summary')), 300)},
                               link='/blocks')

    # --- status ---------------------------------------------------------------------------------
    def status(self):
        """Whether the list file is loaded at the http{} level, and the servers / locations it does not cover."""
        path = self.cfg['blocks']['file']
        included, where, uncovered = False, None, []
        try:
            from .nginxconf import NginxConfig
            n = NginxConfig(self.cfg['paths']['nginx_conf'])
            h = n.http()
            if h is not None:
                included = any(d.file == path and d.name == 'allow' for d in h.children)
                if not included:
                    for s in h.children:
                        if s.name == 'server' and s.children and any(d.file == path for d in s.children):
                            where = 'server'
                for s in h.children:
                    if s.name != 'server' or s.children is None:
                        continue
                    name = next((d.args[0] for d in s.children if d.name == 'server_name' and d.args), '_')
                    if any(d.name in ('allow', 'deny') and d.file != path for d in s.children):
                        uncovered.append({'server': name, 'location': None, 'file': s.file, 'line': s.line})
                    for loc, d in _locations(s.children):
                        if any(c.name in ('allow', 'deny') for c in d.children):
                            uncovered.append({'server': name, 'location': loc, 'file': d.file, 'line': d.line})
        except Exception as e:      # noqa: BLE001 -- a broken nginx configuration is reported, not fatal here
            where = 'error: %s' % util.clip(str(e), 200)
        applied = self._meta(META_APPLIED) or {}
        pending = self._meta(META_PENDING)
        return {'enabled': bool(self.cfg['blocks']['enabled']), 'file': path, 'included': included,
                'included_in': 'http' if included else where, 'uncovered': uncovered[:200],
                'applied': {'at': util.iso(applied['at']) if applied.get('at') else None, 'ok': applied.get('ok'),
                            'count': applied.get('count'), 'summary': applied.get('summary')},
                'pending': bool(pending), 'in_sync': applied.get('sha') == self.list_sha(self.desired()) and bool(applied.get('ok')),
                'limits': {k: self.cfg['blocks'][k] for k in ('max_active', 'max_per_token', 'token_per_hour', 'default_ttl',
                                                              'min_ttl', 'api_max_ttl', 'ui_max_ttl', 'reload_seconds')}}

    def run(self, stop, interval=5):
        """The web service's thread: expire, write when needed (also after a restart: the database decides)."""
        last_purge = 0
        while not stop.is_set():
            try:
                if self.cfg['blocks']['enabled']:
                    self.expire()
                    self.sync()
                    if time.time() - last_purge > 86400:
                        self.purge()
                        last_purge = time.time()
            except Exception as e:      # noqa: BLE001
                print('blocks: %s' % util.clip(str(e), 300), flush=True)
            stop.wait(interval)


def _locations(children, prefix=''):
    for d in children:
        if d.name == 'location' and d.children is not None:
            loc = prefix + ' '.join(d.args)
            yield loc, d
            yield from _locations(d.children, loc + ' > ')


def render(entries, path, when=None):
    """The list file: one deny per entry, then nginx's default (allow all), which also marks the file as loaded."""
    head = ['# Generated by jt-waf-mgr -- temporary IP blocks; do not edit by hand.',
            '# Include once inside http { }:  include %s;' % path,
            '# %d entries, %s' % (len(entries), when or time.strftime('%Y-%m-%dT%H:%M:%S%z'))]
    return '\n'.join(head + ['deny %s;' % e for e in entries] + ['allow all;', ''])


def validate_entries(entries, never=()):
    """For the root program: every entry a public address or a narrow range outside the never-blocked networks."""
    if not isinstance(entries, list) or len(entries) > HARD_MAX:
        raise ValueError('entries: a list of at most %d' % HARD_MAX)
    out = []
    for e in entries:
        if not isinstance(e, str) or not re.fullmatch(r'[0-9A-Fa-f:.]{2,45}(?:/\d{1,3})?', e):
            raise ValueError('entry %r' % str(e)[:60])
        net = ipaddress.ip_network(e, strict=False)
        if net.prefixlen < (24 if net.version == 4 else 64):
            raise ValueError('entry %s: wider than /24 or /64' % e)
        a = net.network_address
        if _non_public(net):
            raise ValueError('entry %s: not a public address' % e)
        for p in never:
            if p.version == net.version and (net.subnet_of(p) or p.subnet_of(net)):
                raise ValueError('entry %s: inside the protected network %s' % (e, p))
        out.append(str(a) if net.prefixlen == net.max_prefixlen else str(net))
    return out
