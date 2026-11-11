"""ModSecurity v3 JSON audit log: parse one record into an event, and tail the file.

libmodsecurity writes one JSON object per line (SecAuditLogFormat JSON, Serial). It does not
reopen the file on reload or USR1, so logrotate should use copytruncate; the tailer handles both
truncation (same inode, smaller size) and rename rotation (new inode: finish <path>.1 first).
"""
import datetime
import gzip
import hashlib
import json
import os
import re
import threading
import time
import zoneinfo

from .. import util

ANOMALY_RE = re.compile(r'Total Score:\s*(\d+)', re.I)
SEVERITY = {'0': 'EMERGENCY', '1': 'ALERT', '2': 'CRITICAL', '3': 'ERROR', '4': 'WARNING',
            '5': 'NOTICE', '6': 'INFO', '7': 'DEBUG'}


class Parser:
    def __init__(self, cfg):
        self.cfg = cfg
        self.redactor = util.Redactor(cfg.sensitive)
        self.local = cfg['waf']['local_range']
        self.confident = cfg['waf']['confident_range']
        self.fallback = set(cfg['waf']['fallback_rule_ids'])
        self.threshold = set(cfg['waf']['threshold_rule_ids'])
        tzname = cfg['collector']['timezone']
        self.tz = zoneinfo.ZoneInfo(tzname) if tzname else None
        self.node = cfg['node']['id']

    def origin(self, ip):
        return 'internal' if util.ip_in(ip, self.cfg.internal_networks) else 'external'

    def parse(self, line):
        """One audit log line -> event dict, or None if it is not a transaction."""
        obj = json.loads(line)
        t = obj.get('transaction') if isinstance(obj, dict) else None
        if not isinstance(t, dict):
            return None
        ts = util.parse_modsec_time(str(t.get('time_stamp', '')), self.tz)
        req = t.get('request') or {}
        resp = t.get('response') or {}
        prod = t.get('producer') or {}
        uid = str(t.get('unique_id') or '')
        uri = str(req.get('uri') or '')
        path, _, query = uri.partition('?')
        host = ''
        hdrs = req.get('headers') or {}
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                if k.lower() == 'host':
                    host = str(v)
        if not host and '-' in uid:
            # modsecurity_transaction_id "$host-$request_id": request_id is 32 hex digits
            m = re.match(r'^(.+)-[0-9a-f]{32}$', uid)
            if m:
                host = m.group(1)
        host = host.lower().split(':')[0] if not host.startswith('[') else host.lower()
        src = str(t.get('client_ip') or '')
        engine = str(prod.get('secrules_engine') or '')
        try:
            status = int(resp.get('http_code')) if resp.get('http_code') is not None else None
        except (TypeError, ValueError):
            status = None

        matches, rule_ids, families = [], [], []
        anomaly = None
        truncated = False
        msgs = t.get('messages') or []
        if not isinstance(msgs, list):
            msgs = []
        if len(msgs) > 100:
            msgs, truncated = msgs[:100], True
        for m in msgs:
            if not isinstance(m, dict):
                continue
            d = m.get('details') or {}
            try:
                rid = int(str(d.get('ruleId', '')).strip())
            except ValueError:
                continue
            message = str(m.get('message') or '')
            data = str(d.get('data') or '')
            match = str(d.get('match') or '')
            if rid in util.SCORING_RULES:
                s = ANOMALY_RE.search(message) or ANOMALY_RE.search(data)
                if s:
                    anomaly = max(anomaly or 0, int(s.group(1)))
            hit = self.redactor.references_sensitive(message, match, data)
            if hit:
                data = '[redacted: %s]' % hit
                match = '[redacted]'
            else:
                data = self.redactor.text(data)
                match = self.redactor.text(match)
            fam = util.family_of(rid, self.local)
            sev = str(d.get('severity', '')).strip()
            try:
                line_no = int(d.get('lineNumber'))
            except (TypeError, ValueError):
                line_no = None
            tags = d.get('tags') if isinstance(d.get('tags'), list) else []
            matches.append({'rule_id': rid, 'message': util.clip(self.redactor.text(message), 512),
                            'severity': SEVERITY.get(sev, sev or None), 'data': util.clip(data, 512),
                            'match': util.clip(match, 512), 'tags': [util.clip(x, 80) for x in tags[:20]],
                            'file': util.clip(d.get('file'), 300), 'line': line_no, 'family': fam,
                            'local': self.local[0] <= rid <= self.local[1]})
            if rid not in rule_ids:
                rule_ids.append(rid)
            if fam and fam not in families and fam != 'local':
                families.append(fam)

        local_ids = [r for r in rule_ids if self.local[0] <= r <= self.local[1]]
        confident = any(self.confident[0] <= r <= self.confident[1] for r in rule_ids)
        has_body_rule = any(200000 <= r <= 200099 for r in rule_ids)
        blocked = engine.lower() in ('enabled', 'on') and status is not None and (
            status == 403 or (status == 400 and has_body_rule))
        decided = None
        if blocked:
            if confident:
                decided = 'fallback' if (set(rule_ids) & self.fallback) and 949110 not in rule_ids else 'confident'
            elif 949110 in rule_ids or set(rule_ids) & (self.fallback | self.threshold):
                # The threshold rule is nolog: a block it decided shows only the fallback rule.
                decided = 'score'
            else:
                decided = 'other'
        first = next((m for m in matches if m['rule_id'] not in util.SCORING_RULES
                      and m['rule_id'] not in self.fallback), matches[0] if matches else None)
        if not families and local_ids:
            families.append('local')
        return {
            'node_id': self.node, 'unique_id': util.clip(uid, 200) or 'noid-' + hashlib.sha1(line.encode('utf-8', 'replace')).hexdigest(),
            'ts': ts, 'host': util.clip(host, 255) or '-', 'method': util.clip(str(req.get('method') or ''), 16),
            'path': util.clip(path, 2048), 'query': util.clip(self.redactor.query(query), 2048),
            'http_version': util.clip(str(req.get('http_version') or ''), 8),
            'src_ip': util.clip(src, 64), 'src_port': _int(t.get('client_port')), 'server_port': _int(t.get('host_port')),
            'origin': self.origin(src), 'status': status, 'engine': util.clip(engine, 32),
            'outcome': 'blocked' if blocked else 'logged', 'decided_by': decided, 'anomaly_score': anomaly,
            'rule_ids': rule_ids, 'local_rule_ids': local_ids, 'families': families,
            'message': first['message'] if first else '', 'matches': matches, 'truncated': truncated,
        }


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class Store:
    """Writes parsed events into SQLite."""

    def __init__(self, db):
        self.db = db

    def insert(self, events):
        if not events:
            return 0
        n = 0
        with self.db.tx() as c:
            for e in events:
                cur = c.execute(
                    'INSERT OR IGNORE INTO events(node_id, unique_id, ts, host, method, path, query, http_version, src_ip, '
                    'src_port, server_port, origin, status, engine, outcome, decided_by, anomaly_score, rule_ids, '
                    'local_rule_ids, families, message, matches, truncated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (e['node_id'], e['unique_id'], e['ts'], e['host'], e['method'], e['path'], e['query'], e['http_version'],
                     e['src_ip'], e['src_port'], e['server_port'], e['origin'], e['status'], e['engine'], e['outcome'],
                     e['decided_by'], e['anomaly_score'], ',' + ','.join(map(str, e['rule_ids'])) + ',',
                     ',' + ','.join(map(str, e['local_rule_ids'])) + ',', ',' + ','.join(e['families']) + ',',
                     e['message'], json.dumps(e['matches'], ensure_ascii=False), 1 if e['truncated'] else 0))
                if cur.rowcount != 1:
                    continue
                n += 1
                eid = cur.lastrowid
                day = datetime.date.fromtimestamp(e['ts']).isoformat()
                for rid in e['rule_ids'] or [0]:
                    if rid:
                        c.execute('INSERT INTO event_rules(event_id, rule_id, ts, outcome) VALUES (?,?,?,?)',
                                  (eid, rid, e['ts'], e['outcome']))
                    c.execute('INSERT INTO stats_daily(day, host, rule_id, origin, outcome, n) VALUES (?,?,?,?,?,1) '
                              'ON CONFLICT(day, host, rule_id, origin, outcome) DO UPDATE SET n=n+1',
                              (day, e['host'], rid, e['origin'], e['outcome']))
        return n

    def purge(self, events_days, stats_days):
        t = util.now()
        with self.db.tx() as c:
            c.execute('DELETE FROM event_rules WHERE ts < ?', (t - 86400 * events_days,))
            c.execute('DELETE FROM events WHERE ts < ?', (t - 86400 * events_days,))
            c.execute('DELETE FROM stats_daily WHERE day < ?',
                      (datetime.date.fromtimestamp(t - 86400 * stats_days).isoformat(),))


class Tailer:
    """Follows the audit log. Offsets are only advanced past complete lines."""

    def __init__(self, cfg, db, parser=None, store=None):
        self.cfg = cfg
        self.db = db
        self.path = cfg['paths']['audit_log']
        self.parser = parser or Parser(cfg)
        self.store = store or Store(db)
        self.max_rec = cfg['collector']['max_record_bytes']
        self.stats = {'parse_errors': 0, 'oversized': 0, 'inserted': 0, 'last_event_ts': None,
                      'last_read': None, 'error': None}
        self._stop = threading.Event()
        self._skipping = False

    def _state(self):
        r = self.db.one('SELECT inode, offset FROM collector_state WHERE path=?', (self.path,))
        return (r['inode'], r['offset']) if r else (None, None)

    def _save(self, inode, offset):
        self.db.x('INSERT OR REPLACE INTO collector_state(path, inode, offset, updated) VALUES (?,?,?,?)',
                  (self.path, inode, offset, util.now()))

    def _consume(self, fh, offset, final=False):
        """Read complete lines from offset; returns the new offset."""
        fh.seek(offset)
        batch = []
        buf = b''
        pos = offset
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            buf += chunk
            while True:
                nl = buf.find(b'\n')
                if nl < 0:
                    if len(buf) > self.max_rec:
                        # a record over the size limit: drop what we have, skip to its newline
                        pos += len(buf)
                        buf = b''
                        if not self._skipping:
                            self.stats['oversized'] += 1
                        self._skipping = True
                    break
                line, buf = buf[:nl], buf[nl + 1:]
                pos += nl + 1
                if self._skipping:
                    self._skipping = False
                    continue
                if len(line) > self.max_rec:
                    self.stats['oversized'] += 1
                    continue
                if not line.strip():
                    continue
                try:
                    e = self.parser.parse(line.decode('utf-8', 'replace'))
                    if e:
                        batch.append(e)
                except Exception:
                    self.stats['parse_errors'] += 1
                if len(batch) >= 500:
                    self._flush(batch)
                    batch = []
        self._flush(batch)
        if final and buf.strip() and not self._skipping:
            try:
                e = self.parser.parse(buf.decode('utf-8', 'replace'))
                if e:
                    self._flush([e])
            except Exception:
                self.stats['parse_errors'] += 1
            pos += len(buf)
        return pos

    def _flush(self, batch):
        if batch:
            self.stats['inserted'] += self.store.insert(batch)
            self.stats['last_event_ts'] = max(self.stats['last_event_ts'] or 0, max(e['ts'] for e in batch))

    def poll(self):
        """One round. Returns True if the file exists."""
        try:
            st = os.stat(self.path)
        except OSError as e:
            self.stats['error'] = 'cannot stat audit log: %s' % e.strerror
            return False
        inode, offset = self._state()
        if inode is None and self.cfg['collector']['backfill_rotated']:
            self.import_file(self.path + '.1')
        if inode is not None and inode != st.st_ino:
            # renamed away: finish the old file if it is still there as .1
            old = self.path + '.1'
            try:
                ost = os.stat(old)
                if ost.st_ino == inode and ost.st_size > offset:
                    with open(old, 'rb') as fh:
                        self._consume(fh, offset, final=True)
            except OSError:
                pass
            offset = 0
        if offset is None or offset > st.st_size:
            offset = 0  # first run, or copytruncate
        try:
            with open(self.path, 'rb') as fh:
                new = self._consume(fh, offset)
        except OSError as e:
            self.stats['error'] = 'cannot read audit log: %s' % e.strerror
            return False
        self.stats['error'] = None
        self.stats['last_read'] = util.now()
        self._save(st.st_ino, new)
        return True

    def import_file(self, path):
        """Import a whole (possibly gzipped) audit log file; duplicates are ignored."""
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rb') as fh:
                return self._consume(fh, 0, final=True)
        except OSError:
            return None

    def run(self, purge_every=3600):
        last_purge = 0
        while not self._stop.is_set():
            try:
                self.poll()
                if time.time() - last_purge > purge_every:
                    self.store.purge(self.cfg['retention']['events_days'], self.cfg['retention']['stats_days'])
                    last_purge = time.time()
            except Exception as e:  # keep the collector alive whatever happens
                self.stats['error'] = 'collector error: %s' % type(e).__name__
            self._stop.wait(self.cfg['collector']['poll_seconds'])

    def stop(self):
        self._stop.set()
