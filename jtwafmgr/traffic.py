"""Request counts from the nginx access logs: how many requests each site got per hour, by status class.

The ModSecurity audit log only has the requests a rule matched; everything that passed cleanly is only in
the access logs. These counts give the WAF numbers their denominator (what share of the traffic was
blocked) and show a site whose traffic jumps or that starts answering 5xx.

Only numbers are kept: per site and hour the total, 2xx / 3xx / 4xx / 5xx, 403, 444, 429, the requests
from external addresses and the bytes sent. No address, no URL, no user agent is stored.

Reading: the live files of [traffic] logs, each from where the last pass stopped (inode + offset, kept in
the meta table in the same transaction as the counts, so a crash never counts a line twice). A file
renamed by logrotate is finished through its inode (<file>.1); a file truncated in place (copytruncate) is
read again from the start. A file seen for the first time is read from its start (today's lines on a daily
rotation). The site is the file name (<site>.access.log); a shared file (access.log) uses the line's vhost
field of a JSON log, a combined log line counts as "(default)". A request can never create more than
MAX_HOSTS sites (a forged Host header lands in "(other)").
"""
import collections
import datetime
import ipaddress
import json
import os
import re
import time
import glob

from . import util

META_KEY = 'traffic_state'
ALERT_KEY = 'traffic_alert_hour'
COLS = ('total', 's2xx', 's3xx', 's4xx', 's5xx', 's403', 's444', 's429', 'external', 'bytes')
MAX_HOSTS = 300
READ_MAX = 64 * 1024 * 1024          # per file and pass; the rest is read on the next pass
HOST_RE = re.compile(r'[a-z0-9][a-z0-9.-]{0,252}')
COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "[^"]*" (\d{3}) (\d+|-)')
TIME_KEYS = ('timestamp', 'nginx_timestamp', 'time_iso8601', '@timestamp', 'time', 'time_local')
MONTHS = {m: i for i, m in enumerate(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}


def parse_time(s):
    """ISO 8601 ($time_iso8601) or nginx's $time_local (13/Nov/2026:15:07:00 +0800) -> epoch, or None."""
    s = (s or '').strip()
    if not s:
        return None
    try:
        if s[:1].isdigit() and len(s) >= 19 and s[4] == '-':
            d = datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
        else:
            m = re.fullmatch(r'(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})', s)
            if not m or m.group(2) not in MONTHS:
                return None
            tz = datetime.timezone((1 if m.group(7) == '+' else -1) * datetime.timedelta(hours=int(m.group(8)),
                                                                                      minutes=int(m.group(9))))
            d = datetime.datetime(int(m.group(3)), MONTHS[m.group(2)], int(m.group(1)), int(m.group(4)),
                                  int(m.group(5)), int(m.group(6)), tzinfo=tz)
        if d.tzinfo is None:
            d = d.astimezone()
        return d.timestamp()
    except (ValueError, OverflowError):
        return None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def site_of(path):
    """The site a log file belongs to, or None for a shared file."""
    name = path.rsplit('/', 1)[-1]
    m = re.fullmatch(r'(.+?)\.(?:access|combined)\.log', name)
    if m and HOST_RE.fullmatch(m.group(1).lower()):
        return m.group(1).lower()
    return None


def parse_line(line, site):
    """(epoch, host, status, bytes, ip) of one access log line, or None."""
    if line.startswith('{'):
        try:
            d = json.loads(line)
        except ValueError:
            return None
        if not isinstance(d, dict):
            return None
        ts = None
        for k in TIME_KEYS:
            if d.get(k):
                ts = parse_time(str(d[k]))
                if ts:
                    break
        status = _int(d.get('http_status') or d.get('status'))
        host = site
        if host is None:
            v = str(d.get('vhost') or d.get('host') or d.get('server_name') or '').lower()
            host = v if HOST_RE.fullmatch(v) else '(default)'
        ip = str(d.get('srcip') or d.get('remote_addr') or '')
        nbytes = _int(d.get('bytes_sent') or d.get('body_bytes_sent') or d.get('bytes_out'))
    else:
        m = COMBINED.match(line)
        if not m:
            return None
        ts, status, host = parse_time(m.group(2)), int(m.group(3)), site or '(default)'
        ip, nbytes = m.group(1), _int(m.group(4))
    if not ts or not 100 <= status <= 999:
        return None
    return ts, host, status, nbytes, ip


class Counter:
    """Counts of one pass: {(hour, host): [COLS...]}"""

    def __init__(self, internal, known_hosts):
        self.c = collections.defaultdict(lambda: [0] * len(COLS))
        self.internal = internal
        self.hosts = set(known_hosts)
        self._ipc = {}

    def _external(self, ip):
        r = self._ipc.get(ip)
        if r is None:
            try:
                a = ipaddress.ip_address(ip)
                r = not any(a.version == n.version and a in n for n in self.internal)
            except ValueError:
                r = False
            if len(self._ipc) < 50000:
                self._ipc[ip] = r
        return r

    def add(self, rec):
        ts, host, status, nbytes, ip = rec
        if host not in self.hosts:
            if len(self.hosts) >= MAX_HOSTS:
                host = '(other)'
            else:
                self.hosts.add(host)
        row = self.c[(int(ts // 3600) * 3600, host)]
        row[0] += 1
        cls = status // 100
        if 2 <= cls <= 5:
            row[cls - 1] += 1
        if status == 403:
            row[5] += 1
        elif status == 444:
            row[6] += 1
        elif status == 429:
            row[7] += 1
        if self._external(ip):
            row[8] += 1
        row[9] += nbytes


def _read(path, start, counter, site, limit=READ_MAX):
    """Count the complete lines of path from offset start; returns the offset after the last one."""
    try:
        fh = open(path, 'rb')
    except OSError:
        return start
    with fh:
        fh.seek(start)
        data = fh.read(limit)
    end = data.rfind(b'\n')
    if end < 0:
        return start
    for raw in data[:end].split(b'\n'):
        rec = parse_line(raw.decode('utf-8', 'replace').strip(), site)
        if rec:
            counter.add(rec)
    return start + end + 1


def _head(path, upto):
    """A fingerprint of the first bytes of a file (at most 128, never beyond what was read)."""
    import hashlib
    try:
        with open(path, 'rb') as fh:
            return hashlib.sha256(fh.read(min(128, upto))).hexdigest()[:16]
    except OSError:
        return None


def files(cfg):
    out = []
    for g in cfg['traffic']['logs']:
        for f in sorted(glob.glob(g)):
            if f not in out and os.path.isfile(f) and not f.endswith('.gz'):
                out.append(f)
    return out


def poll(app, now=None):
    """One pass over the access logs. Returns the number of lines counted."""
    cfg, db = app.cfg, app.db
    if not cfg['traffic']['enabled']:
        return 0
    try:
        state = json.loads(db.get_meta(META_KEY) or '{}')
    except ValueError:
        state = {}
    known = [r[0] for r in db.q('SELECT DISTINCT host FROM traffic_hourly WHERE hour >= ?',
                                (int((now or time.time()) - 86400 * 2),))]
    counter = Counter(cfg.internal_networks, known)
    new = {}
    for path in files(cfg):
        try:
            st = os.stat(path)
        except OSError:
            continue
        site = site_of(path)
        s = state.get(path)
        off = 0
        if s and s.get('ino') == st.st_ino:
            off = s.get('off', 0)
            # truncated in place (copytruncate): smaller than where we stopped, or (already grown again) its first
            # bytes are not the ones we read -- again from 0
            if st.st_size < off or s.get('head') != _head(path, off):
                off = 0
        elif s:
            # rotated: finish the old file (now <path>.1, same inode) where we stopped
            old = path + '.1'
            try:
                if os.stat(old).st_ino == s.get('ino'):
                    _read(old, s.get('off', 0), counter, site)
            except OSError:
                pass
        end = _read(path, off, counter, site)
        new[path] = {'ino': st.st_ino, 'off': end, 'head': _head(path, end)}
    rows = counter.c
    with db.tx() as c:
        for (hour, host), v in rows.items():
            c.execute('INSERT INTO traffic_hourly(hour, host, %s) VALUES (?,?,%s) ON CONFLICT(hour, host) DO UPDATE SET %s'
                      % (', '.join(COLS), ','.join('?' * len(COLS)), ', '.join('%s=%s+excluded.%s' % (k, k, k) for k in COLS)),
                      (hour, host) + tuple(v))
        c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (META_KEY, json.dumps(new)))
        c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('traffic_polled_at', ?)", (str(now or time.time()),))
    return sum(v[0] for v in rows.values())


def purge(app, now=None):
    cut = (now or time.time()) - app.cfg['traffic']['keep_days'] * 86400
    return app.db.x('DELETE FROM traffic_hourly WHERE hour < ?', (int(cut),)).rowcount


def check_alerts(app, now=None):
    """Once per finished hour (five minutes after it ends): a site with a spike, or with many 5xx answers."""
    from . import alerts
    cfg, db = app.cfg, app.db
    tr = cfg['traffic']
    now = now or time.time()
    hour = int((now - 300) // 3600) * 3600 - 3600
    if not tr['enabled'] or not tr['alert']:
        return []
    last = db.get_meta(ALERT_KEY)
    if last and int(last) >= hour:
        return []
    db.set_meta(ALERT_KEY, hour)
    raised = []
    for r in db.q('SELECT * FROM traffic_hourly WHERE hour=?', (hour,)):
        host, total = r['host'], r['total']
        base = db.one('SELECT SUM(total) s FROM traffic_hourly WHERE host=? AND hour>=? AND hour<?',
                      (host, hour - 7 * 86400, hour))['s'] or 0
        usual = base / (7 * 24.0)
        at = util.iso(hour)
        if total >= tr['min_requests'] and usual > 0 and total >= tr['spike_factor'] * usual:
            alerts.raise_alert(db, app.audit, 'traffic', 'traffic_spike', 'warning', 'traffic_spike:%s' % host,
                               {'host': host, 'hour': at, 'requests': total, 'usual': round(usual, 1),
                                'factor': round(total / usual, 1),
                                'reason': '%d requests in the hour from %s, %.1f times the usual %.0f an hour'
                                          % (total, at[11:16], total / usual, usual)}, link='/traffic?host=%s' % host)
            raised.append(('traffic_spike', host))
        if r['s5xx'] >= 50 and r['s5xx'] * 100 >= tr['error_percent'] * total:
            alerts.raise_alert(db, app.audit, 'traffic', 'traffic_errors', 'warning', 'traffic_errors:%s' % host,
                               {'host': host, 'hour': at, 'requests': total, 's5xx': r['s5xx'],
                                'percent': round(r['s5xx'] * 100.0 / total, 1),
                                'reason': '%d of %d requests in the hour from %s were answered 5xx (%.1f%%)'
                                          % (r['s5xx'], total, at[11:16], r['s5xx'] * 100.0 / total)}, link='/traffic?host=%s' % host)
            raised.append(('traffic_errors', host))
    return raised


def run(app, stop, interval=60, log=print):
    """The collector thread of the web service."""
    last_purge = 0
    while not stop.is_set():
        try:
            if app.cfg['traffic']['enabled']:
                poll(app)
                check_alerts(app)
                if time.time() - last_purge > 3600:
                    purge(app)
                    last_purge = time.time()
        except Exception as e:      # noqa: BLE001 -- a bad line or a locked database must not end the thread
            log('traffic: %s' % str(e)[:300])
        stop.wait(interval)


def report(app, since, until, host=None):
    """The counts of a window: hourly (or daily beyond 7 days) series, per site, totals; with the WAF's own
    numbers (blocked / logged events) for the same sites and time."""
    size = 3600 if until - since <= 7 * 86400 + 60 else 86400
    off = time.localtime(until).tm_gmtoff if size == 86400 else 0
    hw, ha = (' AND host=?', (host,)) if host else ('', ())
    sums = ', '.join('SUM(%s) %s' % (k, k) for k in COLS)
    buckets = {}
    for r in app.db.q('SELECT CAST((hour + ?) / ? AS INTEGER) b, %s FROM traffic_hourly WHERE hour>=? AND hour<?%s GROUP BY b'
                      % (sums, hw), (off, size, int(since // 3600 * 3600), until) + ha):
        buckets[r['b']] = {k: r[k] or 0 for k in COLS}
    waf = {}
    for r in app.db.q("SELECT CAST((ts + ?) / ? AS INTEGER) b, SUM(outcome='blocked') bl, SUM(outcome='logged') lg "
                      'FROM events WHERE ts>=? AND ts<?%s GROUP BY b' % hw, (off, size, since, until) + ha):
        waf[r['b']] = (r['bl'] or 0, r['lg'] or 0)
    first, last = int((since + off) // size), int((until - 1 + off) // size)
    zero = {k: 0 for k in COLS}
    series = []
    for b in range(first, last + 1):
        d = dict(buckets.get(b, zero))
        d['blocked'], d['logged'] = waf.get(b, (0, 0))
        d['other'] = max(0, d['total'] - d['s2xx'] - d['s3xx'] - d['s4xx'] - d['s5xx'])
        d['t'] = util.iso(b * size - off)
        series.append(d)
    by_host = {}
    for r in app.db.q('SELECT host, %s FROM traffic_hourly WHERE hour>=? AND hour<?%s GROUP BY host ORDER BY SUM(total) DESC '
                      'LIMIT 200' % (sums, hw), (int(since // 3600 * 3600), until) + ha):
        by_host[r['host']] = dict({k: r[k] or 0 for k in COLS}, host=r['host'], blocked=0, logged=0)
    for r in app.db.q("SELECT host, SUM(outcome='blocked') bl, SUM(outcome='logged') lg FROM events WHERE ts>=? AND ts<?%s "
                      'GROUP BY host' % hw, (since, until) + ha):
        if r['host'] in by_host:
            by_host[r['host']]['blocked'], by_host[r['host']]['logged'] = r['bl'] or 0, r['lg'] or 0
    totals = {k: sum(s[k] for s in series) for k in COLS + ('blocked', 'logged')}
    # the same length of time just before: the change shown on each tile
    span = until - since
    prev = app.db.one('SELECT %s FROM traffic_hourly WHERE hour>=? AND hour<?%s' % (sums, hw),
                      (int((since - span) // 3600 * 3600), int(since // 3600 * 3600)) + ha)
    previous = {k: (prev[k] or 0) for k in COLS} if prev and prev['total'] is not None else None
    if previous is not None:
        pw = app.db.one("SELECT SUM(outcome='blocked') bl FROM events WHERE ts>=? AND ts<?%s" % hw, (since - span, since) + ha)
        previous['blocked'] = (pw['bl'] or 0) if pw else 0
    polled = app.db.get_meta('traffic_polled_at')
    return {'enabled': bool(app.cfg['traffic']['enabled']), 'alert': bool(app.cfg['traffic']['alert']),
            'polled_at': util.iso(float(polled)) if polled else None, 'bucket_seconds': size,
            'since': util.iso(since), 'until': util.iso(until), 'host': host or '',
            'series': series, 'by_host': list(by_host.values()), 'totals': totals, 'previous': previous,
            'files': len(files(app.cfg)) if app.cfg['traffic']['enabled'] else 0}
