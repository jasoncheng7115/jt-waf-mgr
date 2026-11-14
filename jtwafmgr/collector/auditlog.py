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
import sqlite3
import sys
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
        self.country = cfg['waf']['country_range']
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
        return self.event(t, line)

    def event(self, t, line, truncated=False):
        """A decoded transaction object -> event dict. `line` only seeds the id of a record
        without unique_id."""
        ts = util.parse_modsec_time(str(t.get('time_stamp', ''))[:64], self.tz)
        req = t.get('request') or {}
        resp = t.get('response') or {}
        prod = t.get('producer') or {}
        uid = str(t.get('unique_id') or '')
        uri = util.clip(str(req.get('uri') or ''), 3 * util.PRE_CLIP)
        path, _, query = uri.partition('?')
        host = ''
        hdrs = req.get('headers') or {}
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                if k.lower() == 'host':
                    host = str(v)
        if not host and '-' in uid[:4096]:
            # modsecurity_transaction_id "$host-$request_id": request_id is 32 hex digits
            m = re.match(r'^(.+)-[0-9a-f]{32}$', uid[:4096])
            if m:
                host = m.group(1)
        host = host[:1024]
        host = host.lower().split(':')[0] if not host.startswith('[') else host.lower()
        src = str(t.get('client_ip') or '')[:256]
        engine = str(prod.get('secrules_engine') or '')[:256]
        try:
            status = int(resp.get('http_code')) if resp.get('http_code') is not None else None
        except (TypeError, ValueError):
            status = None

        matches, rule_ids, families = [], [], []
        anomaly = None
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
                rid = int(str(d.get('ruleId', ''))[:32].strip())
            except ValueError:
                continue
            # The variable a value came from is looked up in the whole field (linear regex);
            # everything else only ever sees the first PRE_CLIP characters.
            message_full = str(m.get('message') or '')
            data_full = str(d.get('data') or '')
            match_full = str(d.get('match') or '')
            message = util.clip(message_full, util.PRE_CLIP)
            data = util.clip(data_full, util.PRE_CLIP)
            match = util.clip(match_full, util.PRE_CLIP)
            if rid in util.SCORING_RULES:
                s = ANOMALY_RE.search(message) or ANOMALY_RE.search(data)
                if s:
                    anomaly = max(anomaly or 0, int(s.group(1)))
            hit = self.redactor.references_sensitive(message_full, match_full, data_full)
            if hit:
                data = '[redacted: %s]' % util.clip(hit, 200)
                match = '[redacted]'
            else:
                data = self.redactor.text(data)
                match = self.redactor.text(match)
            fam = util.family_of(rid, self.local)
            sev = str(d.get('severity', ''))[:16].strip()
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
        # a country rule is a confident block too: it decides by the source address alone, never by a score
        confident = any(self.confident[0] <= r <= self.confident[1] or self.country[0] <= r <= self.country[1]
                        for r in rule_ids)
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
            'node_id': self.node, 'unique_id': _uid(uid) or 'noid-' + hashlib.sha1(line.encode('utf-8', 'replace')).hexdigest(),
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


UID_MAX = 200


def _uid(uid):
    """unique_id is "$host-$request_id"; a long attacker-chosen Host must not cut off the random
    part (UNIQUE(node_id, unique_id) would then swallow later events), so a long id keeps a prefix
    and the hash of the whole id. Ids up to UID_MAX are stored as they are."""
    if len(uid) <= UID_MAX:
        return uid
    h = hashlib.sha256(uid.encode('utf-8', 'surrogatepass')).hexdigest()
    return uid[:UID_MAX - len(h) - 1] + '#' + h


# --- Records over max_record_bytes ---------------------------------------------------------
# Such a record is never held in memory whole: the first HEAD bytes are kept and the rest is
# scanned in chunks for the few structural tokens an event needs. The tokens start with
# [{,]"key": and so cannot occur inside a JSON string (a quote there is always escaped);
# header values are strings, so '"http_code":403' (a bare number) and '"producer":{' /
# '"messages":[' are structural too.

BIG_HEAD = 65536
# A token is at most ~2.6 KB; tokens ending in the last _BIG_MARGIN characters of a chunk wait
# for the next chunk, which starts _BIG_OVERLAP characters back.
_BIG_MARGIN = 3072
_BIG_OVERLAP = 8192
_JSTR = r'((?:[^"\\]|\\.){0,%d}+)'
_BIG_STREAM_RE = re.compile(
    r'[{,]\s*+"ruleId"\s*+:\s*+"(?P<rule>\d{1,10})"'
    r'|[{,]\s*+"http_code"\s*+:\s*+(?P<status>\d{1,3})\b'
    r'|[{,]\s*+"producer"\s*+:\s*+\{[^{}]{0,2048}?[{,]\s*+"secrules_engine"\s*+:\s*+"(?P<engine>[A-Za-z]{1,20})"'
    r'|(?P<msgs>[{,]\s*+"messages"\s*+:\s*+\[)'
    r'|[{,]\s*+"message"\s*+:\s*+"(?P<msg>' + (_JSTR % 512)[1:])
_BIG_HEAD_RE = {
    'client_ip': re.compile(r'[{,]\s*+"client_ip"\s*+:\s*+"([^"\\]{0,64}+)"'),
    'time_stamp': re.compile(r'[{,]\s*+"time_stamp"\s*+:\s*+"([^"\\]{0,64}+)"'),
    'unique_id': re.compile(r'[{,]\s*+"unique_id"\s*+:\s*+"' + _JSTR % 4096),
    'client_port': re.compile(r'[{,]\s*+"client_port"\s*+:\s*+(\d{1,10})\b'),
    'host_port': re.compile(r'[{,]\s*+"host_port"\s*+:\s*+(\d{1,10})\b'),
}
_BIG_REQUEST_RE = re.compile(r'[{,]\s*+"request"\s*+:\s*+\{')
_BIG_REQ_RE = {
    'method': re.compile(r'[{,]\s*+"method"\s*+:\s*+"([^"\\]{0,32}+)"'),
    'http_version': re.compile(r'[{,]\s*+"http_version"\s*+:\s*+"?([0-9.]{1,8}+)'),
    'uri': re.compile(r'[{,]\s*+"uri"\s*+:\s*+"' + _JSTR % 8192),
}
_BIG_HEADERS_RE = re.compile(r'[{,]\s*+"headers"\s*+:\s*+\{')
_BIG_HOST_RE = re.compile(r'[{,]\s*+"[Hh][Oo][Ss][Tt]"\s*+:\s*+"([^"\\]{0,1024}+)"')


def _jstr(s):
    """Decode the inside of a (possibly cut) JSON string."""
    for cut in range(0, 6):
        try:
            return json.loads('"%s"' % s[:len(s) - cut])
        except ValueError:
            continue
    return s


class _BigRecord:
    """Collects the essentials of one oversized audit log line, chunk by chunk."""

    def __init__(self):
        self.head = b''
        self.tail = ''
        self.done = 0  # matches in self.tail ending at or before this were handled
        self.size = 0
        self.status = None
        self.engine = None
        self.in_messages = False
        self.msg = None
        self.messages = []

    def feed(self, data, last=False):
        if len(self.head) < BIG_HEAD:
            self.head += data[:BIG_HEAD - len(self.head)]
        self.size += len(data)
        window = self.tail + data.decode('latin-1')  # any byte; utf-8 is restored per value
        limit = len(window) if last else len(window) - _BIG_MARGIN
        end = 0
        for m in _BIG_STREAM_RE.finditer(window):
            if m.end() <= self.done:
                continue
            if m.end() > limit:
                break
            end = m.end()
            self._token(m)
        shift = max(0, len(window) - _BIG_OVERLAP)
        self.tail = window[shift:]
        self.done = max(0, max(end, self.done) - shift)

    def _token(self, m):
        if m.group('msgs') is not None:
            self.in_messages = True
        elif not self.in_messages:
            if m.group('status') is not None and self.status is None:
                self.status = int(m.group('status'))
            elif m.group('engine') is not None and self.engine is None:
                self.engine = m.group('engine')
        elif m.group('msg') is not None:
            self.msg = m.group('msg')
        elif m.group('rule') is not None and len(self.messages) < 101:
            self.messages.append({'message': _jstr(_utf8(self.msg or '')), 'details': {'ruleId': m.group('rule')}})
            self.msg = None

    def transaction(self):
        """A transaction dict with what was found, for Parser.event()."""
        self.feed(b'', last=True)
        head = self.head.decode('utf-8', 'replace')
        r = _BIG_REQUEST_RE.search(head)
        top = head[:r.start()] if r else head
        t = {}
        for k, rx in _BIG_HEAD_RE.items():
            m = rx.search(top)
            if m:
                t[k] = _jstr(m.group(1)) if k == 'unique_id' else m.group(1)
        req = {}
        if r:
            rest = head[r.end() - 1:]
            for k, rx in _BIG_REQ_RE.items():
                m = rx.search(rest)
                if m:
                    req[k] = _jstr(m.group(1)) if k == 'uri' else m.group(1)
            h = _BIG_HEADERS_RE.search(rest)
            m = _BIG_HOST_RE.search(rest, h.end() - 1) if h else None
            if m:
                req['headers'] = {'Host': m.group(1)}
        t['request'] = req
        t['response'] = {'http_code': self.status}
        t['producer'] = {'secrules_engine': self.engine or ''}
        t['messages'] = self.messages
        return t

    def key(self):
        return 'big-%d-' % self.size + self.head.decode('latin-1')


def _utf8(s):
    # the stream is decoded as latin-1 (any byte, no split characters); undo that
    return s.encode('latin-1').decode('utf-8', 'replace')


class Store:
    """Writes parsed events into SQLite."""

    def __init__(self, db):
        self.db = db

    on_new = None      # set by the app: the events just stored go to the log servers that take them

    def insert(self, events):
        if not events:
            return 0
        n = 0
        new = []
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
                new.append(e)
                eid = cur.lastrowid
                day = datetime.date.fromtimestamp(e['ts']).isoformat()
                for rid in e['rule_ids'] or [0]:
                    if rid:
                        c.execute('INSERT INTO event_rules(event_id, rule_id, ts, outcome) VALUES (?,?,?,?)',
                                  (eid, rid, e['ts'], e['outcome']))
                    c.execute('INSERT INTO stats_daily(day, host, rule_id, origin, outcome, n) VALUES (?,?,?,?,?,1) '
                              'ON CONFLICT(day, host, rule_id, origin, outcome) DO UPDATE SET n=n+1',
                              (day, e['host'], rid, e['origin'], e['outcome']))
        if new and self.on_new is not None:
            try:            # never let a log server hold the collector up (the sender only queues)
                self.on_new(new)
            except Exception:       # noqa: BLE001
                pass
        return n

    def purge(self, events_days, stats_days):
        t = util.now()
        with self.db.tx() as c:
            c.execute('DELETE FROM event_rules WHERE ts < ?', (t - 86400 * events_days,))
            c.execute('DELETE FROM events WHERE ts < ?', (t - 86400 * events_days,))
            c.execute('DELETE FROM stats_daily WHERE day < ?',
                      (datetime.date.fromtimestamp(t - 86400 * stats_days).isoformat(),))


HEAD_CHECK = 4096


def _same_head(first, head):
    """Does a file that starts with `first` start with the bytes `head` (n, sha256) describes?"""
    if not head:
        return True  # nothing remembered (first run, or state from an older version)
    n, digest = head
    return len(first) >= n and hashlib.sha256(first[:n]).hexdigest() == digest


def _scrub(v):
    """Replace lone surrogates (\\ud800 in the JSON) that SQLite cannot store as UTF-8."""
    if isinstance(v, str):
        return v.encode('utf-8', 'replace').decode('utf-8')
    if isinstance(v, list):
        return [_scrub(x) for x in v]
    if isinstance(v, dict):
        return {k: _scrub(x) for k, x in v.items()}
    return v


class Tailer:
    """Follows the audit log. Offsets are only advanced past complete lines."""

    def __init__(self, cfg, db, parser=None, store=None):
        self.cfg = cfg
        self.db = db
        self.path = cfg['paths']['audit_log']
        self.parser = parser or Parser(cfg)
        self.store = store or Store(db)
        self.max_rec = cfg['collector']['max_record_bytes']
        self.stats = {'parse_errors': 0, 'oversized': 0, 'inserted': 0, 'insert_errors': 0,
                      'last_event_ts': None, 'last_read': None, 'error': None}
        self._stop = threading.Event()
        self._big = None  # _BigRecord while inside a line over max_record_bytes
        self._head_key = 'collector_head:' + self.path
        self._head_cache = None

    def _state(self):
        r = self.db.one('SELECT inode, offset FROM collector_state WHERE path=?', (self.path,))
        return (r['inode'], r['offset']) if r else (None, None)

    def _head_state(self):
        """(n, sha256 hex) of the first n bytes of the file at the saved offset, or None."""
        v = self.db.get_meta(self._head_key)
        try:
            n, digest = v.split(':', 1)
            return int(n), digest
        except (AttributeError, ValueError):
            return None

    def _save(self, inode, offset, first=b''):
        self.db.x('INSERT OR REPLACE INTO collector_state(path, inode, offset, updated) VALUES (?,?,?,?)',
                  (self.path, inode, offset, util.now()))
        n = min(len(first), offset, HEAD_CHECK)
        v = '%d:%s' % (n, hashlib.sha256(first[:n]).hexdigest())
        if v != self._head_cache:
            self.db.set_meta(self._head_key, v)
            self._head_cache = v

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
            if self._big is not None:
                # inside an oversized record: scan up to its newline, keep nothing else
                nl = chunk.find(b'\n')
                if nl < 0:
                    self._big.feed(chunk)
                    pos += len(chunk)
                    continue
                self._big.feed(chunk[:nl])
                pos += nl + 1
                self._finish_big(batch)
                chunk = chunk[nl + 1:]
            buf += chunk
            while True:
                nl = buf.find(b'\n')
                if nl < 0:
                    if len(buf) > self.max_rec:
                        # a record over the size limit: keep only its essentials (_BigRecord)
                        self._start_big(buf)
                        pos += len(buf)
                        buf = b''
                    break
                line, buf = buf[:nl], buf[nl + 1:]
                pos += nl + 1
                if len(line) > self.max_rec:
                    self._start_big(line)
                    self._finish_big(batch)
                elif line.strip():
                    try:
                        e = self.parser.parse(line.decode('utf-8', 'replace'))
                        if e:
                            batch.append(e)
                    except Exception:
                        self.stats['parse_errors'] += 1
                if len(batch) >= 500:
                    self._flush(batch)
                    batch = []
        if final and self._big is not None:
            self._finish_big(batch)
        self._flush(batch)
        if final and buf.strip():
            try:
                e = self.parser.parse(buf.decode('utf-8', 'replace'))
                if e:
                    self._flush([e])
            except Exception:
                self.stats['parse_errors'] += 1
            pos += len(buf)
        return pos

    def _start_big(self, data):
        self.stats['oversized'] += 1
        self._big = _BigRecord()
        self._big.feed(data)

    def _finish_big(self, batch):
        """Store a minimal event (truncated=1) for an oversized record instead of dropping it:
        an attacker must not be able to hide an attack by making its record large."""
        big, self._big = self._big, None
        try:
            e = self.parser.event(big.transaction(), big.key(), truncated=True)
            if e:
                batch.append(e)
        except Exception:
            self.stats['parse_errors'] += 1

    def _flush(self, batch):
        if not batch:
            return
        try:
            n = self.store.insert(batch)
        except sqlite3.OperationalError:
            raise  # locked, read-only, disk full: nothing advances, the batch is retried next round
        except Exception:
            # one bad row must not hold the whole batch (and the offset) back forever
            n = sum(self._insert_one(e) for e in batch)
        self.stats['inserted'] += n
        self.stats['last_event_ts'] = max(self.stats['last_event_ts'] or 0, max(e['ts'] for e in batch))

    def _insert_one(self, e):
        try:
            return self.store.insert([e])
        except sqlite3.OperationalError:
            raise
        except Exception:
            pass
        try:
            return self.store.insert([_scrub(e)])
        except sqlite3.OperationalError:
            raise
        except Exception as ex:
            self.stats['insert_errors'] += 1
            uid = util.CONTROL_RE.sub('?', util.clip(str(e.get('unique_id')), 80))
            print('jt-waf-mgr collector: skipped an event that cannot be stored (%s, unique_id %r)'
                  % (type(ex).__name__, uid), file=sys.stderr, flush=True)
            return 0

    def _rotated_rest(self, offset, head):
        """copytruncate: what was written between our last read and the copy is in <path>.1
        (its newest rotated sibling). Read it from the old offset if it is the same file."""
        if not head:
            return
        try:
            with open(self.path + '.1', 'rb') as fh:
                if os.fstat(fh.fileno()).st_size > offset and _same_head(fh.read(HEAD_CHECK), head):
                    self._consume(fh, offset, final=True)
        except OSError:
            pass

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
        rotated = inode is not None and inode != st.st_ino
        if rotated:
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
        try:
            with open(self.path, 'rb') as fh:
                first = fh.read(HEAD_CHECK)
                if not rotated and offset:
                    head = self._head_state()
                    if st.st_size < offset or not _same_head(first, head):
                        # copytruncate (shrunk, or already regrown past the old offset)
                        self._rotated_rest(offset, head)
                        offset = 0
                if offset is None or offset > st.st_size:
                    offset = 0  # first run
                new = self._consume(fh, offset)
        except OSError as e:
            self.stats['error'] = 'cannot read audit log: %s' % e.strerror
            return False
        self.stats['error'] = None
        self.stats['last_read'] = util.now()
        self._save(st.st_ino, new, first)
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
