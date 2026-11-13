"""Audit trail: every action goes to the database and to the syslog destinations (JSON, CEF, LEEF, GELF or key=value)."""
import atexit
import collections
import datetime
import errno
import json
import os
import socket
import threading
import time
import weakref

from . import util
from .config import FACILITIES

PROGRAM = 'jt-waf-mgr'
_ALL = weakref.WeakSet()


@atexit.register
def _flush_all():
    """Short-lived commands (analysis, notifications, the CLI): send what is queued before the process ends."""
    end = time.monotonic() + 3
    for a in list(_ALL):
        a.flush(max(0.0, end - time.monotonic()))


MAX_DESTINATIONS = 8


def destination_list(cfg):
    """Every syslog destination: the first is [syslog] itself (address, protocol, format = header, facility, plus
    payload and content), the others come from syslog.more (Settings). Each: {key, name, enabled, address, protocol,
    format, facility, payload, content}."""
    sl = cfg['syslog']
    out = [{'key': 'main', 'name': sl.get('name') or '', 'enabled': bool(sl['enabled']), 'address': sl['address'],
            'protocol': sl.get('protocol', 'udp'), 'format': sl.get('format', 'rfc3164'), 'facility': sl['facility'],
            'payload': sl.get('payload') or 'json', 'content': list(sl.get('content') or ['audit'])}]
    for i, d in enumerate(sl.get('more') or []):
        if isinstance(d, dict) and len(out) < MAX_DESTINATIONS:
            out.append(dict({'protocol': 'udp', 'format': 'rfc3164', 'facility': 'local0', 'payload': 'json',
                             'content': ['audit'], 'name': ''}, **d, key=str(d.get('id') or 'd%d' % (i + 2))))
    return out


class _Dest:
    """One log server: its own queue and sender thread, so a slow or unreachable one never holds the others back."""
    RETRY_AFTER = 30          # a destination that failed is tried again after this many seconds
    QUEUE_MAX = 5000          # records kept while it is unreachable (then the oldest are dropped and counted)

    def __init__(self, audit, key):
        self.audit, self.key = audit, key
        self.queue = collections.deque()
        self.cond = threading.Condition()
        self.lock = threading.Lock()
        self.sock = None
        self.thread = None
        self.retry_at = 0.0
        self.reset = False
        self.sent = self.dropped = self.errors = 0
        self.last_error = None

    def settings(self):
        return next((d for d in destination_list(self.audit.cfg) if d['key'] == self.key), None)

    def put(self, kind, rec, level, pinned):
        # pinned: sent with the settings of this moment (a change of the syslog settings goes where they pointed before)
        item = [level, kind, rec, time.time(), pinned, 0]
        with self.cond:
            if len(self.queue) >= self.QUEUE_MAX:
                self.queue.popleft()
                self.dropped += 1
            self.queue.append(item)
            self.cond.notify()
        if self.thread is None or not self.thread.is_alive():
            with self.lock:
                if self.thread is None or not self.thread.is_alive():
                    self.thread = threading.Thread(target=self._loop, name='syslog-' + self.key, daemon=True)
                    self.thread.start()

    def encode(self, item):
        """(target, stream, [bytes]) with the settings as they are now (or as pinned)."""
        level, kind, rec, ts, pinned, _tries = item
        d = pinned or self.settings()
        if d is None or not d.get('enabled'):
            raise LookupError('destination removed or switched off')
        return self.audit.encode(d, kind, rec, level, ts)

    def _loop(self):
        dest = None
        while True:
            with self.cond:
                while not self.queue:
                    self.cond.wait(5)
                wait = self.retry_at - time.monotonic()
                if wait > 0:
                    self.cond.wait(min(wait, 5))
                    continue
                head = self.queue[0]
                try:
                    target, stream, msgs = self.encode(head)
                except Exception:   # noqa: BLE001 -- a record that cannot be encoded (or has nowhere to go) is dropped
                    self.queue.popleft()
                    self.dropped += 1
                    continue
                if self.reset:
                    self.reset, dest = False, None
                    self.close()
            phase = 'connect'
            try:
                if self.sock is None or dest != target:
                    self.close()
                    self.sock = self.audit._connect(target[0], target[1], target[0].startswith('/'),
                                                    self.audit.cfg['syslog'].get('ca_file') or None)
                    dest = target
                phase = 'send'
                for msg in msgs:
                    if stream:
                        self.sock.sendall(msg)
                    else:
                        self.sock.send(msg)
            except Exception as e:     # noqa: BLE001 -- the sender thread must never die
                self.errors += 1
                self.last_error = (util.now(), ('%s: %s' % (type(e).__name__, e))[:200])
                self.close()
                dest = None
                head[5] += 1
                # only this record is at fault when the destination took the connection but not the record (too
                # big); a failed connection, name lookup or TLS handshake (certificate!) waits and retries
                unsendable = phase == 'send' and getattr(e, 'errno', None) == errno.EMSGSIZE
                if unsendable or (head[4] is not None and head[5] >= 3):
                    with self.cond:
                        if self.queue and self.queue[0] is head:
                            self.queue.popleft()
                            self.dropped += 1
                    continue
                self.retry_at = time.monotonic() + self.RETRY_AFTER
                continue
            with self.cond:
                if self.queue and self.queue[0] is head:
                    self.queue.popleft()
                self.sent += 1
                self.cond.notify_all()

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def reconnect(self):
        with self.cond:
            self.reset = True
            self.retry_at = 0
            self.cond.notify_all()

    def flush(self, end):
        with self.cond:
            while self.queue and time.monotonic() < end and self.retry_at <= time.monotonic():
                self.cond.wait(0.1)
        return len(self.queue)


class Audit:
    def __init__(self, db, cfg):
        self.db = db
        self.cfg = cfg
        self._dests = {'main': _Dest(self, 'main')}
        self._dlock = threading.Lock()
        _ALL.add(self)
        self.chain = self.__init_chain()
        self.ctx = threading.local()

    # the first destination keeps the attributes it always had (system check, compliance, tests)
    @property
    def _queue(self):
        return self._dests['main'].queue

    @property
    def syslog_sent(self):
        return self._dests['main'].sent

    @property
    def syslog_dropped(self):
        return self._dests['main'].dropped

    @property
    def syslog_errors(self):
        return self._dests['main'].errors

    @property
    def syslog_last_error(self):
        return self._dests['main'].last_error

    RETRY_AFTER = _Dest.RETRY_AFTER
    QUEUE_MAX = _Dest.QUEUE_MAX

    def __init_chain(self):
        from .integrity import AuditChain
        return AuditChain(self.db)

    def _targets(self, kind):
        """The enabled destinations that take this kind of record (notices go with the audit records)."""
        want = 'audit' if kind in ('audit', 'notice') else kind
        out = []
        for d in destination_list(self.cfg):
            if d['enabled'] and want in d['content']:
                with self._dlock:
                    dst = self._dests.get(d['key']) or self._dests.setdefault(d['key'], _Dest(self, d['key']))
                out.append((dst, d))
        return out

    def stats(self):
        """Per destination: what was sent, dropped, waits, the last error (Settings, system check)."""
        out = []
        for d in destination_list(self.cfg):
            x = self._dests.get(d['key'])
            out.append({'key': d['key'], 'name': d['name'], 'enabled': d['enabled'], 'address': d['address'],
                        'protocol': d['protocol'], 'payload': d['payload'], 'content': d['content'],
                        'sent': x.sent if x else 0, 'dropped': x.dropped if x else 0, 'queued': len(x.queue) if x else 0,
                        'errors': x.errors if x else 0,
                        'last_error': ({'at': util.iso(x.last_error[0]), 'error': x.last_error[1]} if x and x.last_error else None)})
        return out

    def log(self, action, actor=None, actor_type='user', src_ip=None, result='ok', severity=None, **details):
        """One audit row (hash-chained) and one syslog record carrying the row's id and hash, so the SIEM
        holds an independent copy of the chain. severity: None (info, or warning when the result is not ok), 'warning' or 'crit'."""
        ts = util.now()
        if src_ip is None:
            src_ip = getattr(self.ctx, 'src_ip', None)
        rid, h = self.chain.append(ts, action, actor, actor_type, src_ip, result,
                                   json.dumps(details, ensure_ascii=False))
        targets = self._targets('audit')
        if targets:
            rec = {'v': 1, 'action': action, 'actor': actor, 'actor_type': actor_type, 'src_ip': src_ip,
                   'result': result, 'node_id': self.cfg['node']['id'], 'ts': util.iso(ts),
                   'audit_id': rid, 'hash': h}
            rec.update(details)
            if severity:
                rec['severity'] = severity     # syslog files drop the priority; SIEM rules need it
            pin = action == 'settings.changed' and str(details.get('key', '')).startswith('syslog.')
            self._send(targets, 'audit', rec, 2 if severity == 'crit' else (4 if result != 'ok' or severity == 'warning' else 6), pin)
        try:      # notifications and alerts: never let them break the action that is being recorded
            from . import notify
            notify.on_audit(self, rid, action, actor, src_ip, result, severity, details)
        except Exception as e:
            self.notify_errors = getattr(self, 'notify_errors', 0) + 1
            self.notify_last_error = (util.now(), '%s: %s' % (type(e).__name__, str(e)[:200]))
        return rid

    def notice(self, kind, level=6, **fields):
        """A syslog record that is not an audit row (anchors, periodic check results)."""
        targets = self._targets('notice')
        if targets:
            rec = {'v': 1, 'kind': kind, 'node_id': self.cfg['node']['id'], 'ts': util.iso(util.now())}
            rec.update(fields)
            self._send(targets, 'notice', rec, level)

    def events(self, events):
        """WAF events the collector just stored, to the destinations that take them."""
        targets = self._targets('event')
        if not targets:
            return
        for e in events:
            rec = {'v': 1, 'type': 'event', 'ts': util.iso(e['ts']), 'node_id': e.get('node_id'),
                   'unique_id': e.get('unique_id'), 'host': e.get('host'), 'method': e.get('method'), 'path': e.get('path'),
                   'query': e.get('query'), 'src_ip': e.get('src_ip'), 'origin': e.get('origin'), 'status': e.get('status'),
                   'outcome': e.get('outcome'), 'decided_by': e.get('decided_by'), 'anomaly_score': e.get('anomaly_score'),
                   'rule_ids': list(e.get('rule_ids') or []), 'families': list(e.get('families') or []),
                   'message': e.get('message')}
            self._send(targets, 'event', rec, 4 if e.get('outcome') == 'blocked' else 6)

    def alert(self, aid, kind, severity, source, details, link):
        """An alert just opened, to the destinations that take alerts."""
        targets = self._targets('alert')
        if targets:
            d = details or {}
            rec = {'v': 1, 'type': 'alert', 'ts': util.iso(util.now()), 'node_id': self.cfg['node']['id'], 'alert_id': aid,
                   'kind': kind, 'severity': severity, 'source': source, 'link': link or '/alerts'}
            rec.update({k: d[k] for k in ('host', 'path', 'reason', 'count') if k in d})
            self._send(targets, 'alert', rec, 2 if severity == 'critical' else 4)

    def _send(self, targets, kind, rec, level, pin=False):
        for dst, d in targets:
            dst.put(kind, rec, level, dict(d) if pin else None)

    def encode(self, d, kind, rec, level, when):
        """One record for destination d: (target, stream, [bytes...])."""
        from . import __version__, logfmt
        addr, proto = d['address'], d.get('protocol', 'udp')
        local = addr.startswith('/')
        stream = not local and proto in ('tcp', 'tls')
        payload = d.get('payload') or 'json'
        if payload == 'gelf' and not local:
            body = logfmt.gelf(kind, rec, level, self._hostname(), when)
            if stream:
                return (addr, proto), True, [body + b'\0']        # GELF over TCP: one record per null-terminated frame
            chunks = logfmt.gelf_udp_chunks(body, os.urandom(8))
            if chunks is None:
                raise ValueError('record too big for GELF over UDP')
            return (addr, proto), False, chunks
        if payload == 'cef':
            line = logfmt.cef(kind, rec, level, __version__, int(when * 1000))
        elif payload == 'leef':
            line = logfmt.leef(kind, rec, level, __version__)
        elif payload == 'kv':
            line = logfmt.kv(kind, rec, level)
        else:
            line = logfmt.json_line(kind, rec)
        pri = FACILITIES[d['facility']] * 8 + level
        fmt = d.get('format', 'rfc3164')
        msg = self._format(pri, line, fmt, local, when, 'audit' if kind in ('audit', 'notice') else kind).encode('utf-8')
        if stream:      # framing: octet counting for RFC 5424 (RFC 6587), a line feed for the classic format
            msg = (b'%d ' % len(msg)) + msg if fmt == 'rfc5424' else msg + b'\n'
        return (addr, proto), stream, [msg]

    def reconnect(self):
        """Settings changed: the next record goes with the new destinations, at once."""
        for dst in list(self._dests.values()):
            dst.reconnect()

    def flush(self, timeout=3.0):
        """Wait (a little) until the queues are sent: short-lived commands call it before they exit."""
        end = time.monotonic() + timeout
        return sum(dst.flush(end) for dst in list(self._dests.values()))

    def send_test(self, d, kind='audit'):
        """Settings, "send a test": one sample record to destination d now, synchronously (a few seconds at most).
        Returns {'ok', 'error'?, 'sample'} -- the record as it was sent, to compare with what the server shows."""
        ts = time.time()
        if kind == 'event':
            rec = {'v': 1, 'type': 'event', 'ts': util.iso(ts), 'node_id': self.cfg['node']['id'], 'unique_id': 'test',
                   'host': 'www.example.com', 'method': 'GET', 'path': '/test/jt-waf-mgr', 'src_ip': '192.0.2.10',
                   'origin': 'external', 'status': 403, 'outcome': 'blocked', 'decided_by': 'score', 'anomaly_score': 5,
                   'rule_ids': [930120], 'families': ['lfi'], 'message': 'test record from jt-waf-mgr'}
            level = 4
        else:
            rec = {'v': 1, 'action': 'syslog.test', 'actor': 'jt-waf-mgr', 'actor_type': 'system', 'src_ip': None,
                   'result': 'ok', 'node_id': self.cfg['node']['id'], 'ts': util.iso(ts), 'note': 'test record from jt-waf-mgr'}
            level = 6
        try:
            target, stream, msgs = self.encode(d, kind, rec, level, ts)
        except Exception as e:      # noqa: BLE001
            return {'ok': False, 'error': ('%s: %s' % (type(e).__name__, e))[:200], 'sample': ''}
        sample = b''.join(msgs).decode('utf-8', 'replace')[:4000]
        sock = None
        try:
            sock = self._connect(target[0], target[1], target[0].startswith('/'), self.cfg['syslog'].get('ca_file') or None)
            sock.settimeout(3)
            for m in msgs:
                (sock.sendall if stream else sock.send)(m)
            return {'ok': True, 'sample': sample}
        except Exception as e:      # noqa: BLE001
            return {'ok': False, 'error': ('%s: %s' % (type(e).__name__, e))[:200], 'sample': sample}
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def _format(self, pri, line, fmt, local, when=None, msgid='audit'):
        when = when or time.time()
        if fmt == 'rfc5424':
            ts = datetime.datetime.fromtimestamp(when).astimezone().isoformat(timespec='milliseconds')
            return '<%d>1 %s %s %s %d %s - %s' % (pri, ts, self._hostname(), PROGRAM, os.getpid(), msgid, line)
        if local:        # the local syslog daemon adds the time and the host name
            return '<%d>%s: %s' % (pri, PROGRAM, line)
        now = time.localtime(when)
        ts = time.strftime('%b ', now) + ('%2d' % now.tm_mday) + time.strftime(' %H:%M:%S', now)
        return '<%d>%s %s %s: %s' % (pri, ts, self._hostname(), PROGRAM, line)

    def _hostname(self):
        h = socket.gethostname().split('.')[0]
        return ''.join(ch for ch in h if 33 <= ord(ch) < 127)[:255] or '-'

    @staticmethod
    def _connect(addr, proto, local, ca_file=None):
        if local:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                s.connect(addr)
            except BaseException:
                s.close()
                raise
            return s
        host, _, port = addr.rpartition(':')
        host = host.strip('[]')
        if proto == 'udp':
            info = socket.getaddrinfo(host, int(port or 514), type=socket.SOCK_DGRAM)[0]
            s = socket.socket(info[0], socket.SOCK_DGRAM)
            try:
                s.connect(info[4])
            except BaseException:
                s.close()
                raise
            return s
        s = socket.create_connection((host, int(port or (6514 if proto == 'tls' else 514))), timeout=2)
        if proto == 'tls':
            import ssl
            try:
                s = ssl.create_default_context(cafile=ca_file).wrap_socket(s, server_hostname=host)
            except BaseException:
                s.close()
                raise
        s.settimeout(2)
        return s

    def list(self, action=None, actor=None, limit=100, before_id=None):
        sql, args = 'SELECT * FROM audit WHERE 1=1', []
        if action:
            sql += ' AND action=?'
            args.append(action)
        if actor:
            sql += ' AND actor=?'
            args.append(actor)
        if before_id:
            sql += ' AND id<?'
            args.append(before_id)
        sql += ' ORDER BY id DESC LIMIT ?'
        args.append(limit + 1)
        rows = self.db.q(sql, args)
        items = [{'id': r['id'], 'ts': util.iso(r['ts']), 'action': r['action'], 'actor': r['actor'],
                  'actor_type': r['actor_type'], 'src_ip': r['src_ip'], 'result': r['result'],
                  'details': json.loads(r['details'] or '{}'), 'prev_hash': r['prev_hash'],
                  'hash': r['this_hash']} for r in rows[:limit]]
        nxt = str(rows[limit - 1]['id']) if len(rows) > limit else None
        return items, nxt
