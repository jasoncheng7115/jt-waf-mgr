"""Compliance and integrity monitoring.

- Monitor: a background thread that verifies the audit hash chain and writes anchors, checks the
  installed program against the signed manifest, fingerprints the nginx / ModSecurity / CRS files and
  records every change, makes the daily database backup, and disables expired / dormant accounts.
  Every failure is an audit row with severity "crit" (syslog priority 2) so the SIEM can alert on it.
- system_check(): the self-diagnosis page.
- controls(): the compliance page -- each control with its references (ISO/IEC 27001:2022 Annex A,
  Taiwan's Cyber Security Management Act protection baseline, OWASP Top 10:2025) and a status
  computed from the live configuration. Only what the code actually does is claimed.
"""
import fnmatch
import glob
import json
import os
import sqlite3
import sys
import threading
import time

from . import __version__, integrity, util

REMIND_SECONDS = 12 * 3600


class Monitor:
    def __init__(self, app):
        self.app = app
        self.cfg = app.cfg
        self.db = app.db
        self.audit = app.audit
        self.anchors = integrity.Anchors(self.cfg['integrity']['anchor_file'])
        self.state = {'chain': None, 'program': None, 'config': None, 'backup': None, 'db': None}
        self._verified = None      # (last_id, last_hash) verified so far
        self._anchored = (None, 0.0)   # ((id, hash), time) of the last anchor written
        self._due = {}
        self._backup_lock = threading.Lock()
        self._alerted = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # --- scheduling ---------------------------------------------------------------------------
    KEEP_ALWAYS = 3

    def _is_due(self, name, every):
        t = time.monotonic()             # a wall clock set back (NTP after a wrong date) must not stop the checks
        if t >= self._due.get(name, 0):
            self._due[name] = t + every
            return True
        return False

    def run(self):
        ic = self.cfg['integrity']
        while not self._stop.is_set():
            for name, every, fn in (
                    ('chain', 60 * ic['anchor_minutes'], self.check_chain),
                    ('chain_full', 86400, lambda: self.check_chain(full=True)),
                    ('program', 60 * ic['program_check_minutes'], self.check_program),
                    ('config', 60 * ic['config_check_minutes'], self.check_config),
                    ('accounts', 3600, self.check_accounts),
                    ('db', 86400, self.check_db),
                    ('backup', 600, self.maybe_backup)):
                if self._stop.is_set():
                    break
                if self._is_due(name, every):
                    try:
                        fn()
                    except Exception as e:  # keep the monitor alive; report the failure
                        self.audit.notice('monitor_error', level=3, task=name, error=type(e).__name__)
            self._stop.wait(20)

    def stop(self):
        self._stop.set()

    def _alert(self, key, action, ok, **details):
        """Audit row on a change of state, and a reminder every 12 hours while it stays failed."""
        t = time.time()
        prev = self._alerted.get(key)
        if ok:
            if prev is not None:
                self.audit.log(action + '_recovered', 'system', 'system', None, 'ok', **details)
                self._alerted.pop(key, None)
            return
        if prev is None or t - prev > REMIND_SECONDS:
            self.audit.log(action, 'system', 'system', None, 'failed', severity='crit', **details)
            self._alerted[key] = t

    # --- audit chain ----------------------------------------------------------------------------
    def check_chain(self, full=False):
        with self._lock:
            chain = self.audit.chain
            if self._verified is not None and self._verified[0] < int(self.db.get_meta('audit_base_id', 0) or 0):
                full = True  # the retention purge removed the verified tip
            if full or self._verified is None:
                res = chain.verify()
            else:
                res = chain.verify(after_id=self._verified[0], expected_prev=self._verified[1])
                if res['ok'] and res['checked'] == 0:
                    # nothing new; make sure the verified tip is still there (tail truncation)
                    tip = self.db.one('SELECT this_hash FROM audit WHERE id=?', (self._verified[0],))
                    if self._verified[0] > int(self.db.get_meta('audit_base_id', 0) or 0) and \
                            (not tip or tip[0] != self._verified[1]):
                        res = {'ok': False, 'reason': 'verified_tip_missing', 'bad_id': self._verified[0],
                               'checked': 0, 'last_id': None, 'last_hash': None}
            problems = []
            if res['ok']:
                self._verified = (res['last_id'] or 0, res['last_hash'])
                anchors = self.anchors.read(None if full else 1)
                rewinds = integrity.Anchors.read_rewinds(os.path.join(os.path.dirname(self.cfg.path or '/etc/jt-waf-mgr/x'),
                                                                     'audit-rewinds.jsonl'))
                problems = self.anchors.check(self.db, anchors, self.cfg['retention']['audit_days'], rewinds)
            count = self.db.one('SELECT COUNT(*) FROM audit')[0]
            anchor = None
            tip = (res.get('last_id'), res.get('last_hash'))
            if res['ok'] and not problems and res['last_id'] and \
                    not (self._anchored[0] == tip and time.time() - self._anchored[1] < 60):
                # (the incremental and the daily full check can fall due together: one anchor is enough)
                try:
                    anchor = self.anchors.append(res['last_id'], res['last_hash'], count,
                                                 int(self.db.get_meta('audit_base_id', 0) or 0))
                    self._anchored = (tip, time.time())
                    self.audit.notice('audit_anchor', id=anchor['id'], hash=anchor['hash'], count=count,
                                      base_id=anchor['base_id'])
                except OSError as e:
                    problems.append({'reason': 'anchor_write_failed', 'error': e.strerror})
            ok = res['ok'] and not problems
            self.state['chain'] = {
                'ok': ok, 'checked_at': util.iso(time.time()), 'full': full, 'rows': count,
                'checked': res['checked'], 'last_id': res.get('last_id'), 'reason': res.get('reason'),
                'bad_id': res.get('bad_id'), 'anchor_problems': problems[:20],
                'last_anchor': anchor or (self.anchors.read(1) or [None])[-1]}
            self._alert('chain', 'integrity.audit_chain_failed', ok, reason=res.get('reason'),
                        bad_id=res.get('bad_id'), anchor_problems=problems[:5])
            if not res['ok']:
                self._verified = None
            return self.state['chain']

    # --- program files --------------------------------------------------------------------------
    def check_program(self):
        res = integrity.verify_program(key_path=self.cfg['integrity']['release_key'])
        self.state['program'] = res
        if res['status'] != 'not_installed':
            self._alert('program', 'integrity.program_failed', res['status'] == 'ok', reason=res.get('reason'),
                        changed=res.get('changed', [])[:20], missing=res.get('missing', [])[:20],
                        extra=res.get('extra', [])[:20])
        return res

    # --- configuration fingerprint ----------------------------------------------------------------
    def config_files(self):
        n, m = self.app.site.load()
        files = set(n.files) | set(m.files)
        files.add(self.cfg['paths']['nginx_bin'])
        try:
            files.update(self.app.workflow.sandbox._modules())
        except Exception:
            pass
        from .managed import PLACEMENTS
        mg = self.app.workflow.managed
        if mg.adopted():
            files.update(mg.path(p) for p in PLACEMENTS)
        return sorted(files)

    def check_config(self):
        files, digest = integrity.fingerprint(self.config_files())
        last = self.db.one('SELECT * FROM config_snapshots ORDER BY id DESC LIMIT 1')
        if last and last['digest'] == digest:
            self.state['config'] = {'checked_at': util.iso(time.time()), 'files': len(files), 'changed': False,
                                    'last_change_id': last['id']}
            return self.state['config']
        changes = integrity.diff_fingerprints(json.loads(last['files']), files) if last else {}
        cause = 'baseline' if not last else self._cause(last, changes)
        t = util.now()
        cur = self.db.x('INSERT INTO config_snapshots(ts, digest, files, changes, cause) VALUES (?,?,?,?,?)',
                        (t, digest, json.dumps(files), json.dumps(changes), cause))
        if last:
            self.audit.log('config.changed', 'system', 'system', None, 'ok' if cause in ('jt-waf-mgr', 'automation') else 'outside',
                           snapshot=cur.lastrowid, cause=cause, **{k: v[:30] for k, v in changes.items()})
        self.state['config'] = {'checked_at': util.iso(time.time()), 'files': len(files), 'changed': bool(last),
                                'last_change_id': cur.lastrowid, 'cause': cause}
        return self.state['config']

    def _cause(self, last, changes):
        """jt-waf-mgr when every changed file is a managed file (or the main ModSecurity file at adoption),
        the managed files match the last applied version and a version was applied since the previous
        snapshot; otherwise outside."""
        wf = self.app.workflow
        mdir = self.cfg['managed']['dir'].rstrip('/') + '/'
        touched = changes.get('added', []) + changes.get('removed', []) + changes.get('changed', [])
        applied = self.db.one("SELECT COUNT(*) FROM versions WHERE state='applied' AND created_at >= ?",
                              (last['ts'] - 1800,))[0]
        try:
            drift = wf.managed.disk_state()['drift']
        except Exception:
            drift = True
        main = set()
        try:
            _, m = self.app.site.load()
            main = set(m.main_files)
        except Exception:
            pass
        # an adoption also takes the site's old rule files out of the configuration (main.conf now includes the
        # managed files instead): those files are part of jt-waf-mgr's own change, not an outside one
        adopted_src = set()
        for (spec,) in self.db.q("SELECT spec FROM changes WHERE op='adopt' AND state='applied' AND updated_at >= ?",
                                 (last['ts'] - 1800,)):
            try:
                adopted_src.update(v.get('path') for v in (json.loads(spec).get('sources') or {}).values()
                                   if isinstance(v, dict) and v.get('path'))
            except (ValueError, AttributeError):
                continue
        if applied and not drift and all(p.startswith(mdir) or p in main or p in adopted_src for p in touched):
            return 'jt-waf-mgr'
        # a version the apply program has written but not reported yet (it waits for old nginx workers, and the web
        # service takes the result between proposal checks): the files on disk are exactly that version's
        if all(p.startswith(mdir) or p in main or p in adopted_src for p in touched):
            try:
                pending = [json.loads(h) for (h,) in self.db.q(
                    "SELECT hashes FROM versions WHERE state IN ('pending','applied') AND created_at >= ? "
                    'ORDER BY version DESC LIMIT 5', (last['ts'] - 1800,))]
                if pending and wf.managed.disk_hashes() in pending:
                    return 'jt-waf-mgr'
            except Exception:       # noqa: BLE001 -- unreadable files or rows: not proven ours
                pass
        # the temporary IP block list: written only by the apply program from the database
        bf = self.cfg['blocks']['file']
        if touched and all(p == bf for p in touched):
            return 'jt-waf-mgr'
        auto = self.cfg['integrity'].get('automation_paths') or []
        if touched and auto and all(any(fnmatch.fnmatch(p, a) or p.startswith(a.rstrip('*')) for a in auto) for p in touched):
            return 'automation'      # e.g. the CRS updater or the country lists: known, still recorded
        return 'outside'

    def config_changes(self, limit=50, before=None):
        sql, args = 'SELECT id, ts, digest, changes, cause FROM config_snapshots', []
        if before:
            sql += ' WHERE id < ?'
            args.append(before)
        rows = self.db.q(sql + ' ORDER BY id DESC LIMIT ?', args + [limit + 1])
        items = [{'id': r['id'], 'ts': util.iso(r['ts']), 'digest': r['digest'], 'cause': r['cause'],
                  'changes': json.loads(r['changes'])} for r in rows[:limit]]
        return items, (str(rows[limit - 1]['id']) if len(rows) > limit else None)

    def config_snapshot(self, sid):
        r = self.db.one('SELECT * FROM config_snapshots WHERE id=?', (sid,))
        if not r:
            return None
        return {'id': r['id'], 'ts': util.iso(r['ts']), 'digest': r['digest'], 'cause': r['cause'],
                'changes': json.loads(r['changes']), 'files': json.loads(r['files'])}

    # --- accounts -------------------------------------------------------------------------------
    def check_accounts(self):
        for name, reason in self.app.auth.expire_accounts():
            self.audit.log('user.disabled', 'system', 'system', None, 'ok', target=name, reason=reason)

    # --- database and backups -------------------------------------------------------------------
    def check_db(self):
        r = self.db.one('PRAGMA quick_check')[0]
        self.state['db'] = {'checked_at': util.iso(time.time()), 'quick_check': r}
        self._alert('db', 'integrity.database_failed', r == 'ok', result=str(r)[:200])
        return self.state['db']

    def maybe_backup(self):
        b = self.cfg['backup']
        if not b['enabled']:
            return None
        last = self.app.workflow.managed.setting('backup.last') or {}
        lts = last.get('ts', 0)
        if lts > time.time() + 300:
            # the last backup is "in the future": the clock was wrong then (or is now) -- do not wait for it
            self.audit.notice('backup_clock', level=4, last=util.iso(lts))
        elif self.last_scheduled(b['hour']) <= lts:
            # done since the scheduled time -- unless it failed: then once an hour, three times at most
            if last.get('ok', True) or last.get('fails', 0) >= 3 or time.time() - lts < 3600:
                return None
        return self.backup()

    @staticmethod
    def last_scheduled(hour, now=None):
        """The most recent scheduled backup time (today at `hour`, or yesterday before that hour). A backup is
        due when none was made since then -- also one made by hand earlier does not skip the night's backup."""
        t = time.time() if now is None else now
        lt = time.localtime(t)
        sched = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, 0, 0, 0, 0, -1))
        if sched > t:
            sched = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday - 1, hour, 0, 0, 0, 0, -1))
        return sched

    def backup(self, actor='system'):
        """SQLite online backup -> integrity_check on the copy -> SHA-256 file; old copies removed."""
        b = self.cfg['backup']
        os.makedirs(b['dir'], mode=0o700, exist_ok=True)
        with self._backup_lock:          # the nightly backup and "back up now" never write the same file
            return self._backup(b, actor)

    def _backup(self, b, actor):
        name = 'jt-waf-mgr-%s.db' % time.strftime('%Y%m%d-%H%M%S')
        path = os.path.join(b['dir'], name)
        tmp = path + '.part'
        res = {'ts': time.time(), 'at': util.iso(time.time()), 'file': name, 'ok': False}
        for old in glob.glob(os.path.join(b['dir'], 'jt-waf-mgr-*.db.part')):   # left by an interrupted backup
            try:
                os.unlink(old)
            except OSError:
                pass
        try:
            os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            dst = sqlite3.connect(tmp)
            try:
                self.db.conn().backup(dst)
                check = dst.execute('PRAGMA integrity_check').fetchone()[0]
            finally:
                dst.close()
            os.chmod(tmp, 0o600)
            if check != 'ok':
                raise OSError('integrity_check: %s' % check)
            os.replace(tmp, path)
            h = integrity.file_sha256(path)
            with open(path + '.sha256', 'w') as fh:
                fh.write('%s  %s\n' % (h, name))
            os.chmod(path + '.sha256', 0o600)
            res.update(ok=True, sha256=h, size=os.path.getsize(path))
        except (OSError, sqlite3.Error) as e:
            res['error'] = str(e)[:200]
            try:
                os.unlink(tmp)
            except OSError:
                pass
        removed = self._prune_backups() if res['ok'] else 0      # a failing backup never removes good ones
        if not res['ok']:
            prev = self.app.workflow.managed.setting('backup.last') or {}
            res['fails'] = (prev.get('fails', 0) if not prev.get('ok', True) else 0) + 1
        self.app.workflow.managed.set_setting('backup.last', res)
        self.state['backup'] = res
        self.audit.log('backup.created' if res['ok'] else 'backup.failed', actor, 'system' if actor == 'system' else 'user',
                       None, 'ok' if res['ok'] else 'failed', severity=None if res['ok'] else 'crit',
                       file=name, sha256=res.get('sha256'), error=res.get('error'), removed=removed)
        return res

    def _prune_backups(self):
        b = self.cfg['backup']
        cutoff = time.time() - 86400 * b['keep_days']
        removed = 0
        # the newest KEEP_ALWAYS copies stay whatever their age (a clock jump or days of failures must not
        # leave no backup at all)
        for p in sorted(glob.glob(os.path.join(b['dir'], 'jt-waf-mgr-*.db')), reverse=True)[self.KEEP_ALWAYS:]:
            try:
                if os.path.getmtime(p) < cutoff:
                    os.unlink(p)
                    removed += 1
                    if os.path.exists(p + '.sha256'):
                        os.unlink(p + '.sha256')
            except OSError:
                pass
        return removed

    def backups(self):
        out = []
        for p in sorted(glob.glob(os.path.join(self.cfg['backup']['dir'], 'jt-waf-mgr-*.db')), reverse=True):
            item = {'file': os.path.basename(p), 'size': os.path.getsize(p),
                    'at': util.iso(os.path.getmtime(p)), 'sha256': None, 'verified': None}
            try:
                with open(p + '.sha256') as fh:
                    item['sha256'] = fh.read().split()[0]
            except (OSError, IndexError):
                pass
            out.append(item)
        return out

    def verify_backup(self, name):
        p = os.path.join(self.cfg['backup']['dir'], os.path.basename(name))
        if not os.path.isfile(p):
            return None
        try:
            with open(p + '.sha256') as fh:
                want = fh.read().split()[0]
        except (OSError, IndexError):
            want = None
        got = integrity.file_sha256(p)
        try:
            c = sqlite3.connect('file:%s?mode=ro' % p, uri=True)
            try:
                check = c.execute('PRAGMA integrity_check').fetchone()[0]
            finally:
                c.close()
        except sqlite3.Error as e:
            check = str(e)[:200]
        return {'file': os.path.basename(p), 'sha256': got, 'sha256_ok': want == got, 'integrity_check': check,
                'ok': want == got and check == 'ok'}


# --- system check ---------------------------------------------------------------------------------

def _item(key, level, **details):
    return {'key': key, 'status': level, 'details': details}


def system_check(app):
    """status: ok | warn | fail | info. Each key has an i18n text in the UI."""
    cfg = app.cfg
    mon = app.monitor
    out = [_item('version', 'info', version=__version__, python='%d.%d.%d' % sys.version_info[:3],
                 nginx=app.site.nginx_version())]

    prog = mon.state.get('program') or mon.check_program()
    out.append(_item('program_integrity', {'ok': 'ok', 'failed': 'fail'}.get(prog['status'], 'warn'),
                     **{k: prog.get(k) for k in ('status', 'reason', 'checked', 'changed', 'missing', 'extra',
                                                 'signature', 'key_fingerprint', 'manifest_sha256', 'checked_at')}))

    ch = mon.state.get('chain') or mon.check_chain()
    out.append(_item('audit_chain', 'ok' if ch['ok'] else 'fail', **ch))
    ao = mon.anchors.append_only() if os.path.exists(mon.anchors.path) else None
    out.append(_item('anchor_file', 'ok' if ao else 'warn', path=mon.anchors.path, append_only=ao))

    sl = cfg['syslog']
    plain_remote = not sl['address'].startswith('/') and sl.get('protocol') != 'tls'
    ca_bad = bool(sl.get('ca_file')) and not os.access(sl['ca_file'], os.R_OK)
    au = app.audit
    dests = au.stats()
    others_bad = any(d['enabled'] and (d['errors'] or d['dropped']) for d in dests[1:])
    out.append(_item('syslog', 'warn' if not sl['enabled'] or au.syslog_errors or plain_remote or au.syslog_dropped or ca_bad
                     or others_bad else 'ok',
                     ca_file_unreadable=ca_bad if sl.get('ca_file') else None,
                     enabled=sl['enabled'], address=sl['address'], protocol=sl.get('protocol'), format=sl.get('format'),
                     payload=sl.get('payload', 'json'), content=sl.get('content', ['audit']),
                     unencrypted_remote=plain_remote, queued=len(au._queue), dropped=au.syslog_dropped,
                     errors=au.syslog_errors,
                     last_error=util.iso(au.syslog_last_error[0]) if au.syslog_last_error else None,
                     more=[{k: d[k] for k in ('name', 'address', 'protocol', 'payload', 'content', 'enabled', 'sent', 'dropped',
                                              'errors', 'last_error')} for d in dests[1:]]))

    try:
        n = cfg['notify']
        now = util.now()
        failed = app.db.one("SELECT COUNT(*) FROM notifications WHERE status='failed' AND test=0 AND created_at>?",
                            (now - 86400,))[0]
        stuck = app.db.one("SELECT COUNT(*) FROM notifications WHERE status IN ('pending', 'sending') AND created_at<?",
                           (now - 1800,))[0]
        from . import alerts as _alerts, notify as _notify
        active = [c for c in _notify.CHANNELS if _notify.active(n, c)]
        level = 'info' if not n['enabled'] else ('warn' if failed or stuck or not active or app.audit.__dict__.get('notify_errors') else 'ok')
        out.append(_item('notify', level, enabled=n['enabled'], channels=active, failed_24h=failed, stuck=stuck,
                         last_run=app.db.get_meta('notify.last_run'), open_alerts=_alerts.counts(app.db)['open'],
                         queue_errors=app.audit.__dict__.get('notify_errors', 0)))
    except Exception as e:
        out.append(_item('notify', 'warn', error=type(e).__name__))

    ts = integrity.time_sync()
    out.append(_item('time_sync', 'ok' if ts['synced'] else ('warn' if ts['synced'] is None else 'fail'), **ts))

    try:
        gs = app.geoip.status()
        present = [e['edition'] for e in gs['editions'] if e['present']]
        out.append(_item('geoip', 'info' if not gs['enabled'] else ('ok' if present and gs['last_ok'] is not False else
                         ('warn' if gs['configured'] else 'info')), configured=gs['configured'], present=present,
                         last_run=gs['last_run'], last_ok=gs['last_ok']))
    except Exception:
        pass
    dbdir = os.path.dirname(cfg['paths']['db']) or '.'
    try:
        st = os.statvfs(dbdir)
        free = st.f_bavail * st.f_frsize // (1 << 20)
        total = st.f_blocks * st.f_frsize // (1 << 20)
        out.append(_item('disk', 'ok' if free >= cfg['integrity']['disk_min_free_mb'] else 'warn', path=dbdir,
                         free_mb=free, total_mb=total, min_free_mb=cfg['integrity']['disk_min_free_mb']))
    except OSError:
        out.append(_item('disk', 'warn', path=dbdir))

    dbs = mon.state.get('db') or mon.check_db()
    try:
        size = os.path.getsize(cfg['paths']['db'])
    except OSError:
        size = None
    out.append(_item('database', 'ok' if dbs['quick_check'] == 'ok' else 'fail', size=size,
                     schema=app.db.get_meta('schema_version'), **dbs))

    last = app.workflow.managed.setting('backup.last') or {}
    if not cfg['backup']['enabled']:
        out.append(_item('backup', 'warn', enabled=False))
    else:
        age = time.time() - last['ts'] if last.get('ts') else None
        good = last.get('ok') and age is not None and -300 < age < 30 * 3600     # a future time is a wrong clock
        out.append(_item('backup', 'ok' if good else 'warn', enabled=True, dir=cfg['backup']['dir'],
                         keep_days=cfg['backup']['keep_days'], last_at=last.get('at'), last_ok=last.get('ok'),
                         error=last.get('error'), copies=len(mon.backups())))

    st = app.tailer.stats if app.tailer else {}
    if app.tailer:
        readable = os.access(cfg['paths']['audit_log'], os.R_OK)
        good = readable and not st.get('error')
        last_read = st.get('last_read')
    else:
        # checked from the command line (a separate process without the log's group): judge the running
        # service by how recently its collector recorded progress
        r = app.db.one('SELECT MAX(updated) FROM collector_state')
        last_read = r[0] if r and r[0] else None
        readable = None
        good = last_read is not None and time.time() - last_read < 300
    out.append(_item('collector', 'ok' if good else 'warn',
                     audit_log=cfg['paths']['audit_log'], readable=readable, running=bool(app.tailer) or good,
                     error=st.get('error'), last_read=util.iso(last_read)))

    armed = os.path.exists('/etc/systemd/system/multi-user.target.wants/jt-waf-mgr-apply.path')
    m = app.workflow.managed
    try:
        disk = m.disk_state()
    except Exception:
        disk = {'adopted': m.adopted(), 'drift': None}
    pending = len(glob.glob(os.path.join(cfg['managed']['spool'], '*.req')))
    out.append(_item('apply', ('fail' if disk.get('drift') else 'ok') if disk.get('adopted') else 'info',
                     armed=armed, adopted=disk.get('adopted'), drift=disk.get('drift'), pending=pending))

    cc = mon.state.get('config') or mon.check_config()
    outside = app.db.one("SELECT id, ts FROM config_snapshots WHERE cause='outside' ORDER BY id DESC LIMIT 1")
    recent = outside and time.time() - outside['ts'] < 7 * 86400
    out.append(_item('config_changes', 'warn' if recent else 'ok', files=cc.get('files'),
                     last_outside_id=outside['id'] if outside else None,
                     last_outside_at=util.iso(outside['ts']) if outside else None))

    t = util.now()
    req = cfg['auth']['require_totp_roles']
    rows = app.db.q('SELECT * FROM users WHERE disabled=0')
    no_totp = [r['username'] for r in rows if r['role'] in req and not r['totp_enabled']]
    locked = [r['username'] for r in rows if r['locked_until'] > t]
    stale_temp = [r['username'] for r in rows if r['must_change'] and t - (r['pw_changed_at'] or r['created_at']) > 7 * 86400]
    admins = sum(1 for r in rows if r['role'] == 'admin')
    out.append(_item('accounts', 'warn' if no_totp or stale_temp or admins == 0 else 'ok', active=len(rows),
                     admins=admins, without_totp=no_totp, locked=locked, temporary_password_unused=stale_temp))

    sc = cfg['server']
    host, _ = cfg.listen
    good = sc['secure_cookies'] and host in ('127.0.0.1', '::1', 'localhost')
    out.append(_item('web', 'ok' if good else 'warn', secure_cookies=sc['secure_cookies'], listen=sc['listen'],
                     session_idle_minutes=sc['session_idle_minutes'], session_max_hours=sc['session_max_hours']))
    return out


# --- compliance controls ----------------------------------------------------------------------------

LEVELS = {'': 0, 'low': 1, 'medium': 2, 'high': 3}


def controls(app):
    """[{id, iso, tw, owasp, status, values, needs}] -- status: met | partial | gap | organisational.
    needs: settings that would close a gap at the configured protection level."""
    cfg = app.cfg
    a = cfg['auth']
    level = LEVELS[cfg['compliance']['level']]
    mon = app.monitor
    wf = app.workflow
    ws = wf.settings()
    out = []

    def add(cid, iso, tw, owasp, state, needs=(), **values):
        out.append({'id': cid, 'iso': iso, 'tw': tw, 'owasp': owasp, 'status': state,
                    'needs': list(needs), 'values': values})

    # Access control
    needs = []
    if level >= 2 and not a['dormant_days']:
        needs.append('auth.dormant_days')
    add('account_management', ['A.5.16', 'A.5.18'], ['access.account'], ['A01'],
        'gap' if needs else 'met', needs, dormant_days=a['dormant_days'], account_expiry=True, account_review=True)
    add('least_privilege', ['A.5.15', 'A.8.2', 'A.8.3'], ['access.least_privilege'], ['A01'], 'met',
        roles=['viewer', 'operator', 'approver', 'admin'], token_scopes=True, token_source_networks=True)
    single = bool(ws.get('approval.single_admin_mode'))
    add('segregation_of_duties', ['A.5.3', 'A.8.32'], ['access.least_privilege'], ['A06'],
        'partial' if single else 'met', ['approval.single_admin_mode=false'] if single else [],
        proposer_cannot_approve=not single, single_admin_mode=single)
    idle = cfg['server']['session_idle_minutes']
    add('session_timeout', ['A.8.5'], ['access.account'], ['A07'], 'met' if idle <= 30 else 'gap',
        [] if idle <= 30 else ['server.session_idle_minutes<=30'], idle_minutes=idle,
        max_hours=cfg['server']['session_max_hours'], max_sessions=a['max_sessions_per_user'])

    # Identification and authentication
    needs = []
    if a['lockout_threshold'] > 5 or a['lockout_minutes'] < 15:
        needs.append('auth.lockout_threshold<=5,lockout_minutes>=15')
    if level >= 2:
        if a['password_min_classes'] < 3:
            needs.append('auth.password_min_classes>=3')
        if a['password_history'] < 3:
            needs.append('auth.password_history>=3')
        if not a['password_max_age_days']:
            needs.append('auth.password_max_age_days')
        if not a['password_min_age_hours']:
            needs.append('auth.password_min_age_hours')
    add('authentication', ['A.5.17', 'A.8.5'], ['ident.auth_mgmt'], ['A07'], 'gap' if needs else 'met', needs,
        min_length=a['password_min_length'], min_classes=a['password_min_classes'], history=a['password_history'],
        max_age_days=a['password_max_age_days'], min_age_hours=a['password_min_age_hours'],
        lockout=[a['lockout_threshold'], a['lockout_minutes']], hash='scrypt', first_login_change=True)
    req = a['require_totp_roles']
    all_roles = set(req) >= {'viewer', 'operator', 'approver', 'admin'}
    mfa = 'met' if all_roles or (level < 3 and {'approver', 'admin'} <= set(req)) else ('gap' if level >= 3 else 'partial')
    add('multi_factor', ['A.8.5'], ['ident.internal_users'], ['A07'], mfa,
        [] if mfa == 'met' else ['auth.require_totp_roles=[all roles]'], roles=req)
    add('auth_feedback', ['A.8.5'], ['ident.feedback'], ['A07'], 'met', masked_input=True, same_error_unknown_user=True)

    # Logging and accountability
    add('audit_logging', ['A.8.15'], ['log.events', 'log.content'], ['A09'], 'met',
        fields=['time', 'actor', 'actor_type', 'source_ip', 'action', 'result', 'details'], syslog=cfg['syslog']['enabled'])
    ch = mon.state.get('chain') or {}
    ao = mon.anchors.append_only() if os.path.exists(mon.anchors.path) else None
    st = 'met' if ch.get('ok') and ao and cfg['syslog']['enabled'] else ('gap' if ch.get('ok') is False else 'partial')
    needs = ([] if ao else ['chattr +a ' + mon.anchors.path]) + ([] if cfg['syslog']['enabled'] else ['syslog.enabled'])
    add('log_protection', ['A.8.15', 'A.5.33'], ['log.protection'], ['A09'], st, needs,
        hash_chain=True, chain_ok=ch.get('ok'), anchors_append_only=ao, append_only_table=True)
    add('log_failure_response', ['A.8.16'], ['log.failure'], ['A09'],
        'met' if cfg['syslog']['enabled'] and not app.audit.syslog_errors else 'partial',
        [] if cfg['syslog']['enabled'] else ['syslog.enabled'], syslog_errors=app.audit.syslog_errors,
        crit_alerts=['integrity.audit_chain_failed', 'integrity.program_failed', 'backup.failed', 'account.locked'])
    add('log_capacity', ['A.8.6'], ['log.capacity'], ['A09'], 'met', disk_min_free_mb=cfg['integrity']['disk_min_free_mb'],
        retention=cfg['retention'])
    ts = integrity.time_sync()
    add('time_sync', ['A.8.17'], ['log.time'], ['A09'],
        'met' if ts['synced'] else ('gap' if ts['synced'] is False else 'partial'),
        [] if ts['synced'] else ['NTP'], **ts)
    add('siem_forwarding', ['A.8.16'], ['monitor.system'], ['A09'],
        'organisational' if cfg['syslog']['enabled'] else 'gap', [] if cfg['syslog']['enabled'] else ['syslog.enabled'],
        facility=cfg['syslog']['facility'], address=cfg['syslog']['address'])
    add('evidence_export', ['A.5.28'], ['log.protection'], ['A09'], 'met', audit_export_with_hashes=True,
        events_export_sha256=True)

    # Integrity
    prog = mon.state.get('program') or {}
    add('software_integrity', ['A.8.19', 'A.8.32'], ['integrity.software'], ['A08', 'A03'],
        {'ok': 'met', 'failed': 'gap'}.get(prog.get('status'), 'partial'),
        [] if prog.get('status') == 'ok' else ['install.sh (signed release)'], status=prog.get('status'),
        signature=prog.get('signature'), key_fingerprint=prog.get('key_fingerprint'))
    add('configuration_management', ['A.8.9'], ['integrity.software'], ['A02'], 'met',
        tracked_files=(mon.state.get('config') or {}).get('files'), managed_files_drift_check=True)
    adopted = wf.managed.adopted()
    sandbox_req = ws.get('sandbox.required', True)
    add('change_management', ['A.8.32', 'A.8.31'], ['acquisition.lifecycle'], ['A06'],
        'met' if adopted and sandbox_req else 'partial', [] if adopted else ['adoption'],
        adopted=adopted, sandbox_required=sandbox_req, auto_tighten=ws.get('apply.auto_tighten'),
        rollback=True)

    # Continuity
    last = wf.managed.setting('backup.last') or {}
    add('backup', ['A.8.13'], ['continuity.backup'], [], 'met' if cfg['backup']['enabled'] and last.get('ok') else 'gap',
        [] if cfg['backup']['enabled'] else ['backup.enabled'], enabled=cfg['backup']['enabled'],
        keep_days=cfg['backup']['keep_days'], last_at=last.get('at'), offsite='organisational')

    # Data protection
    add('data_masking', ['A.8.11', 'A.8.12'], ['comm.storage'], ['A04'], 'met',
        sensitive_fields=len(cfg['waf']['sensitive_fields']), masked_before_storage=True)
    add('data_at_rest', ['A.8.24'], ['comm.storage'], ['A04'], 'organisational' if level >= 3 else 'partial',
        ['disk encryption'] if level >= 3 else [], db_mode='0600', dir_mode='0700', encrypted=False)
    sc = cfg['server']['secure_cookies']
    add('transport', ['A.8.24', 'A.8.20'], ['comm.transmission'], ['A04'], 'met' if sc else 'gap',
        [] if sc else ['server.secure_cookies'], https_only_cookies=sc, loopback_listener=True)
    add('retention', ['A.8.10'], [], [], 'met', **cfg['retention'])

    # Development and vulnerability management
    add('secure_development', ['A.8.25', 'A.8.26', 'A.8.28', 'A.8.29'], ['acquisition.lifecycle'],
        ['A03', 'A05', 'A10'], 'met', stdlib_only=True, csp_no_unsafe_inline=True, tests=True, release_preflight=True)
    add('vulnerability_management', ['A.8.8'], ['integrity.patch'], ['A03'], 'organisational',
        nginx=app.site.nginx_version())
    add('monitoring', ['A.8.16', 'A.8.20'], ['monitor.system'], ['A09'], 'met', waf_events=True)
    return {'level': cfg['compliance']['level'], 'generated_at': util.iso(time.time()), 'version': __version__,
            'node_id': cfg['node']['id'], 'controls': out}


def audit_export(app, since=None, until=None):
    """NDJSON: one line per audit row (with hashes) and a final summary line binding them."""
    import hashlib
    h = hashlib.sha256()
    sql, args = 'SELECT * FROM audit WHERE 1=1', []
    if since:
        sql += ' AND ts >= ?'
        args.append(since)
    if until:
        sql += ' AND ts < ?'
        args.append(until)
    rows = app.db.q(sql + ' ORDER BY id', args)
    lines = []
    for r in rows:
        rec = {k: r[k] for k in integrity.AUDIT_FIELDS}
        rec['ts_iso'] = util.iso(r['ts'])
        rec['prev_hash'] = r['prev_hash']
        rec['hash'] = r['this_hash']
        ln = json.dumps(rec, ensure_ascii=False, separators=(',', ':')) + '\n'
        h.update(ln.encode('utf-8'))
        lines.append(ln)
    ver = app.audit.chain.verify()
    summary = {'_summary': {'node_id': app.cfg['node']['id'], 'exported_at': util.iso(time.time()),
                            'rows': len(rows), 'first_id': rows[0]['id'] if rows else None,
                            'last_id': rows[-1]['id'] if rows else None, 'sha256_of_lines': h.hexdigest(),
                            'chain_verified': ver['ok'], 'version': __version__}}
    lines.append(json.dumps(summary, separators=(',', ':')) + '\n')
    return ''.join(lines), summary['_summary']


def verify_export(path):
    """Offline check of an audit export: line hash, and the chain inside the file."""
    import hashlib
    h = hashlib.sha256()
    prev = None
    n = 0
    summary = None
    with open(path, encoding='utf-8') as fh:
        for ln in fh:
            obj = json.loads(ln)
            if '_summary' in obj:
                summary = obj['_summary']
                break
            h.update(ln.encode('utf-8'))
            if prev is not None and obj['prev_hash'] != prev:
                return {'ok': False, 'reason': 'prev_mismatch', 'id': obj['id']}
            row = {k: obj[k] for k in integrity.AUDIT_FIELDS}
            if integrity.audit_row_hash(obj['prev_hash'], row) != obj['hash']:
                return {'ok': False, 'reason': 'hash_mismatch', 'id': obj['id']}
            prev = obj['hash']
            n += 1
    if not summary:
        return {'ok': False, 'reason': 'summary_missing', 'rows': n}
    if summary['sha256_of_lines'] != h.hexdigest() or summary['rows'] != n:
        return {'ok': False, 'reason': 'summary_mismatch', 'rows': n}
    return {'ok': True, 'rows': n, 'last_hash': prev, 'summary': summary}
