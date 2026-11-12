"""Audit trail: every action goes to the database and, as one JSON line, to syslog."""
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


class Audit:
    def __init__(self, db, cfg):
        self.db = db
        self.cfg = cfg
        self._sock = None
        self._lock = threading.Lock()
        self._cond = threading.Condition()
        self._queue = collections.deque()
        self._sender = None
        self._retry_at = 0.0
        self._reset = False
        self.syslog_sent = 0
        self.syslog_dropped = 0
        _ALL.add(self)
        self.chain = self.__init_chain()
        self.ctx = threading.local()
        self.syslog_errors = 0
        self.syslog_last_error = None

    def __init_chain(self):
        from .integrity import AuditChain
        return AuditChain(self.db)

    def log(self, action, actor=None, actor_type='user', src_ip=None, result='ok', severity=None, **details):
        """One audit row (hash-chained) and one syslog line carrying the row's id and hash, so the SIEM
        holds an independent copy of the chain. severity: None (info, or warning when the result is not ok), 'warning' or 'crit'."""
        ts = util.now()
        if src_ip is None:
            src_ip = getattr(self.ctx, 'src_ip', None)
        rid, h = self.chain.append(ts, action, actor, actor_type, src_ip, result,
                                   json.dumps(details, ensure_ascii=False))
        if self.cfg['syslog']['enabled']:
            rec = {'v': 1, 'action': action, 'actor': actor, 'actor_type': actor_type, 'src_ip': src_ip,
                   'result': result, 'node_id': self.cfg['node']['id'], 'ts': util.iso(ts),
                   'audit_id': rid, 'hash': h}
            rec.update(details)
            if severity:
                rec['severity'] = severity     # syslog files drop the priority; SIEM rules need it
            self._syslog({'jt_waf_mgr': rec}, level=2 if severity == 'crit' else (4 if result != 'ok' or severity == 'warning' else 6),
                         pin=action == 'settings.changed' and str(details.get('key', '')).startswith('syslog.'))
        try:      # notifications and alerts: never let them break the action that is being recorded
            from . import notify
            notify.on_audit(self, rid, action, actor, src_ip, result, severity, details)
        except Exception as e:
            self.notify_errors = getattr(self, 'notify_errors', 0) + 1
            self.notify_last_error = (util.now(), '%s: %s' % (type(e).__name__, str(e)[:200]))
        return rid

    def notice(self, kind, level=6, **fields):
        """A syslog line that is not an audit row (anchors, periodic check results)."""
        if self.cfg['syslog']['enabled']:
            rec = {'v': 1, 'kind': kind, 'node_id': self.cfg['node']['id'], 'ts': util.iso(util.now())}
            rec.update(fields)
            self._syslog({'jt_waf_mgr': rec}, level=level)

    RETRY_AFTER = 30          # a syslog destination that failed is tried again after this many seconds
    QUEUE_MAX = 5000          # records kept while it is unreachable (then the oldest are dropped and counted)

    def _syslog(self, obj, level=6, pin=False):
        """Queue one record for the syslog sender thread: a request never waits for a network, a DNS lookup or a
        TLS handshake, and records are kept (and sent later) while the destination is unreachable."""
        # ensure_ascii escapes every control character and newline, so one record is one line
        # whatever an attacker put in a username or a URL (no log injection).
        line = json.dumps(obj, ensure_ascii=True, separators=(',', ':'))
        # pin: sent with the settings of this moment (a change of the syslog settings is reported where it went before)
        item = [level, line, time.time(), dict(self.cfg['syslog']) if pin else None, 0]
        with self._cond:
            if len(self._queue) >= self.QUEUE_MAX:
                self._queue.popleft()
                self.syslog_dropped += 1
            self._queue.append(item)
            self._cond.notify()
        self._start_sender()

    def _encode(self, item):
        """(target, stream, bytes) with the settings as they are now."""
        level, line, ts, pinned, _tries = item
        sl = pinned or self.cfg['syslog']
        pri = FACILITIES[sl['facility']] * 8 + level
        addr, proto, fmt = sl['address'], sl.get('protocol', 'udp'), sl.get('format', 'rfc3164')
        local = addr.startswith('/')
        msg = self._format(pri, line, fmt, local, ts).encode('utf-8')
        stream = not local and proto in ('tcp', 'tls')
        if stream:      # framing: octet counting for RFC 5424 (RFC 6587), a line feed for the classic format
            msg = (b'%d ' % len(msg)) + msg if fmt == 'rfc5424' else msg + b'\n'
        return (addr, proto), stream, msg

    def _start_sender(self):
        if self._sender is None or not self._sender.is_alive():
            with self._lock:
                if self._sender is None or not self._sender.is_alive():
                    self._sender = threading.Thread(target=self._send_loop, name='syslog', daemon=True)
                    self._sender.start()

    def _send_loop(self):
        dest = None
        while True:
            with self._cond:
                while not self._queue:
                    self._cond.wait(5)
                wait = self._retry_at - time.monotonic()
                if wait > 0:
                    self._cond.wait(min(wait, 5))
                    continue
                head = self._queue[0]
                target, stream, msg = self._encode(head)
                if self._reset:
                    self._reset, dest = False, None
                    self._close()
            try:
                if self._sock is None or dest != target:
                    self._close()
                    self._sock = self._connect(target[0], target[1], target[0].startswith('/'))
                    dest = target
                if stream:
                    self._sock.sendall(msg)
                else:
                    self._sock.send(msg)
            except Exception as e:     # noqa: BLE001 -- the sender thread must never die
                self.syslog_errors += 1
                self.syslog_last_error = (util.now(), ('%s: %s' % (type(e).__name__, e))[:200])
                self._close()
                dest = None
                head[4] += 1
                unsendable = isinstance(e, (ValueError, UnicodeError)) or getattr(e, 'errno', None) in (errno.EMSGSIZE,)
                if unsendable or (head[3] is not None and head[4] >= 3):
                    # this record can never go (too big, or for a destination given up on): drop it, not the queue
                    with self._cond:
                        if self._queue and self._queue[0] is head:
                            self._queue.popleft()
                            self.syslog_dropped += 1
                    continue
                self._retry_at = time.monotonic() + self.RETRY_AFTER
                continue
            with self._cond:
                if self._queue and self._queue[0] is head:
                    self._queue.popleft()
                self.syslog_sent += 1
                self._cond.notify_all()

    def _close(self):
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        self._sock = None

    def reconnect(self):
        """Settings changed: the next record goes with the new destination, at once."""
        with self._cond:
            self._reset = True
            self._retry_at = 0
            self._cond.notify_all()

    def flush(self, timeout=3.0):
        """Wait (a little) until the queue is sent: short-lived commands call it before they exit."""
        end = time.monotonic() + timeout
        with self._cond:
            while self._queue and time.monotonic() < end and self._retry_at <= time.monotonic():
                self._cond.wait(0.1)
        return len(self._queue)

    def _format(self, pri, line, fmt, local, when=None):
        when = when or time.time()
        if fmt == 'rfc5424':
            ts = datetime.datetime.fromtimestamp(when).astimezone().isoformat(timespec='milliseconds')
            return '<%d>1 %s %s %s %d audit - %s' % (pri, ts, self._hostname(), PROGRAM, os.getpid(), line)
        if local:        # the local syslog daemon adds the time and the host name
            return '<%d>%s: %s' % (pri, PROGRAM, line)
        now = time.localtime(when)
        ts = time.strftime('%b ', now) + ('%2d' % now.tm_mday) + time.strftime(' %H:%M:%S', now)
        return '<%d>%s %s %s: %s' % (pri, ts, self._hostname(), PROGRAM, line)

    def _hostname(self):
        h = socket.gethostname().split('.')[0]
        return ''.join(ch for ch in h if 33 <= ord(ch) < 127)[:255] or '-'

    @staticmethod
    def _connect(addr, proto, local):
        if local:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(addr)
            return s
        host, _, port = addr.rpartition(':')
        host = host.strip('[]')
        if proto == 'udp':
            info = socket.getaddrinfo(host, int(port or 514), type=socket.SOCK_DGRAM)[0]
            s = socket.socket(info[0], socket.SOCK_DGRAM)
            s.connect(info[4])
            return s
        s = socket.create_connection((host, int(port or (6514 if proto == 'tls' else 514))), timeout=2)
        if proto == 'tls':
            import ssl
            s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
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
