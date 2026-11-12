"""Audit trail: every action goes to the database and, as one JSON line, to syslog."""
import json
import socket
import threading

from . import util
from .config import FACILITIES

PROGRAM = 'jt-waf-mgr'


class Audit:
    def __init__(self, db, cfg):
        self.db = db
        self.cfg = cfg
        self._sock = None
        self._lock = threading.Lock()
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
            self._syslog({'jt_waf_mgr': rec}, level=2 if severity == 'crit' else (4 if result != 'ok' or severity == 'warning' else 6))
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

    def _syslog(self, obj, level=6):
        # ensure_ascii escapes every control character and newline, so one record is one line
        # whatever an attacker put in a username or a URL (no log injection).
        line = json.dumps(obj, ensure_ascii=True, separators=(',', ':'))
        pri = FACILITIES[self.cfg['syslog']['facility']] * 8 + level
        msg = ('<%d>%s: %s' % (pri, PROGRAM, line)).encode('ascii')
        addr = self.cfg['syslog']['address']
        with self._lock:
            try:
                if self._sock is None:
                    if addr.startswith('/'):
                        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                        self._sock.connect(addr)
                    else:
                        host, _, port = addr.rpartition(':')
                        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        self._sock.connect((host, int(port or 514)))
                self._sock.send(msg)
            except OSError as e:
                self.syslog_errors += 1
                self.syslog_last_error = (util.now(), str(e)[:200])
                try:
                    if self._sock:
                        self._sock.close()
                finally:
                    self._sock = None

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
