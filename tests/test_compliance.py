"""Compliance and integrity: audit hash chain, anchors, signed manifest, password policy, accounts,
backups, configuration change tracking, audit export, and the audit coverage of every write route."""
import inspect
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest

from jtwafmgr import auth, integrity
from jtwafmgr.app import App
from jtwafmgr.auth import AuthError
from jtwafmgr.compliance import audit_export, controls, system_check, verify_export
from jtwafmgr.db import SCHEMA, Database
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv, wr
from tests.test_api import Client, PW

HAVE_OPENSSL = shutil.which('openssl') is not None


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.a = self.app.audit

    def tearDown(self):
        self.env.cleanup()

    def test_chain_verifies_and_is_append_only(self):
        for i in range(5):
            self.a.log('test.action', 'alice', details_n=i)
        res = self.a.chain.verify()
        self.assertTrue(res['ok'], res)
        self.assertEqual(res['checked'], 5)
        rows = self.app.db.q('SELECT * FROM audit ORDER BY id')
        self.assertEqual(rows[1]['prev_hash'], rows[0]['this_hash'])
        with self.assertRaises(sqlite3.IntegrityError):
            self.app.db.x("UPDATE audit SET actor='mallory' WHERE id=2")
        with self.assertRaises(sqlite3.IntegrityError):
            self.app.db.x('DELETE FROM audit WHERE id=5')

    def _tamper(self, sql):
        c = self.app.db.conn()
        c.execute('DROP TRIGGER audit_no_update')
        c.execute('DROP TRIGGER audit_no_delete')
        c.execute(sql)

    def test_modified_row_detected(self):
        for i in range(4):
            self.a.log('test.action', 'alice', n=i)
        self._tamper("UPDATE audit SET actor='mallory' WHERE id=2")
        self.assertEqual(self.a.chain.verify()['reason'], 'triggers_missing')
        c = self.app.db.conn()
        for sql in integrity.AUDIT_TRIGGERS.values():
            c.execute(sql)
        res = self.a.chain.verify()
        self.assertFalse(res['ok'])
        self.assertEqual((res['bad_id'], res['reason']), (2, 'hash_mismatch'))

    def test_removed_row_detected(self):
        for i in range(4):
            self.a.log('test.action', 'alice', n=i)
        self._tamper('DELETE FROM audit WHERE id=2')
        for sql in integrity.AUDIT_TRIGGERS.values():
            self.app.db.conn().execute(sql)
        res = self.a.chain.verify()
        self.assertEqual((res['bad_id'], res['reason']), (3, 'prev_mismatch'))

    def test_anchor_detects_rewritten_chain(self):
        mon = self.app.monitor
        for i in range(3):
            self.a.log('test.action', 'alice', n=i)
        st = mon.check_chain()
        self.assertTrue(st['ok'], st)
        anchored = mon.anchors.read(1)[0]
        # an attacker with the database rewrites a row AND recomputes the whole chain
        c = self.app.db.conn()
        c.execute('DROP TRIGGER audit_no_update')
        c.execute("UPDATE audit SET actor='mallory' WHERE id=1")
        prev = self.app.db.get_meta('audit_genesis')
        for r in c.execute('SELECT * FROM audit ORDER BY id').fetchall():
            h = integrity.audit_row_hash(prev, r)
            c.execute('UPDATE audit SET prev_hash=?, this_hash=? WHERE id=?', (prev, h, r['id']))
            prev = h
        c.execute(integrity.AUDIT_TRIGGERS['audit_no_update'])
        self.assertTrue(self.a.chain.verify()['ok'])            # the chain alone cannot tell
        st = mon.check_chain(full=True)
        self.assertFalse(st['ok'])                               # the anchor can
        self.assertIn(anchored['id'], [p.get('id') for p in st['anchor_problems']])
        alerts = self.app.db.q("SELECT * FROM audit WHERE action='integrity.audit_chain_failed'")
        self.assertEqual(len(alerts), 1)

    def test_simultaneous_checks_anchor_once(self):
        mon = self.app.monitor
        self.a.log('test.action', 'alice')
        mon.check_chain()
        mon.check_chain(full=True)          # the daily full check falling due in the same minute
        self.assertEqual(len(mon.anchors.read()), 1)
        self.a.log('test.action', 'alice')
        mon.check_chain()                   # a new row is always anchored
        self.assertEqual(len(mon.anchors.read()), 2)

    def test_wiping_the_trail_is_detected(self):
        """Someone with the database opens the purge guard, deletes every row and moves the base past them."""
        for i in range(4):
            self.a.log('test.action', 'alice', n=i)
        self.assertTrue(self.app.monitor.check_chain()['ok'])
        c = self.app.db.conn()
        last = c.execute('SELECT MAX(id), (SELECT this_hash FROM audit ORDER BY id DESC LIMIT 1) FROM audit').fetchone()
        c.execute("UPDATE meta SET value='1' WHERE key='audit_purge_open'")
        c.execute('DELETE FROM audit')
        c.execute("UPDATE meta SET value='0' WHERE key='audit_purge_open'")
        c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('audit_base_id', ?)", (str(last[0]),))
        c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('audit_base_hash', ?)", (last[1],))
        st = self.app.monitor.check_chain(full=True)
        self.assertFalse(st['ok'], st)
        self.assertIn('purged_without_retention', [p['reason'] for p in st['anchor_problems']])

    def test_recorded_rewind_supersedes_later_anchors(self):
        """An upgrade rollback restores an older database; root records the rewind, so anchors written in
        between for rows that no longer exist are not reported. Without the record they are."""
        for i in range(3):
            self.a.log('test.action', 'alice', n=i)
        mon = self.app.monitor
        self.assertTrue(mon.check_chain()['ok'])
        keep = self.app.db.one('SELECT id FROM audit ORDER BY id DESC LIMIT 1')[0]
        snap = os.path.join(self.env.dir, 'snap.db')
        import sqlite3 as _s
        src = _s.connect(self.env.cfg['paths']['db']); dst = _s.connect(snap); src.backup(dst); dst.close(); src.close()
        for i in range(3):
            self.a.log('test.later', 'alice', n=i)
        time.sleep(1.1)
        self.assertTrue(mon.check_chain()['ok'])          # anchors now point past the snapshot
        anchors = mon.anchors.read()
        restored = Database(snap)
        self.assertTrue(integrity.Anchors(mon.anchors.path).check(restored, anchors))       # mismatch without a record
        rw = [{'at': time.time(), 'id': keep}]
        self.assertEqual(integrity.Anchors(mon.anchors.path).check(restored, anchors, rewinds=rw), [])

    def test_trigger_with_empty_body_is_detected(self):
        c = self.app.db.conn()
        c.execute('DROP TRIGGER audit_no_update')
        c.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT 1; END")
        self.assertEqual(self.a.chain.verify()['reason'], 'triggers_missing')

    def test_purge_keeps_chain_valid(self):
        self.app.cfg['retention']['audit_days'] = 1
        for i in range(6):
            self.a.log('test.action', 'alice', n=i)
        self.app.monitor.check_chain()
        cutoff = self.app.db.one('SELECT ts FROM audit WHERE id=4')[0]
        n = self.a.chain.purge_before(cutoff)
        self.assertEqual(n, 3)
        self.assertTrue(self.a.chain.verify()['ok'])
        self.a.log('test.after', 'alice')
        self.assertTrue(self.app.monitor.check_chain()['ok'])
        with self.assertRaises(sqlite3.IntegrityError):
            self.app.db.x('DELETE FROM audit')

    def test_migration_chains_existing_rows(self):
        path = os.path.join(self.env.dir, 'old.db')
        c = sqlite3.connect(path)
        for script in SCHEMA[:2]:
            for stmt in script.split(';'):
                if stmt.strip():
                    c.execute(stmt)
        c.execute("INSERT INTO meta(key, value) VALUES ('schema_version', '2')")
        c.execute('INSERT INTO users(username, role, pw_hash, created_at) VALUES (?,?,?,?)', ('old', 'admin', 'x', 1.0))
        for i in range(3):
            c.execute("INSERT INTO audit(ts, action, actor, actor_type, result, details) VALUES (?,?,?,?,?,?)",
                      (1000.0 + i, 'old.action', 'old', 'user', 'ok', '{}'))
        c.commit()
        c.close()
        db = Database(path)
        self.assertEqual(db.get_meta('schema_version'), str(len(SCHEMA)))
        self.assertTrue(integrity.AuditChain(db).verify()['ok'])
        self.assertEqual(db.one("SELECT pw_changed_at FROM users WHERE username='old'")[0], 1.0)

    def test_export_and_offline_verify(self):
        for i in range(3):
            self.a.log('test.action', 'alice', note='第 %d 筆' % i)
        body, summary = audit_export(self.app)
        self.assertEqual(summary['rows'], 3)
        self.assertTrue(summary['chain_verified'])
        p = os.path.join(self.env.dir, 'export.ndjson')
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(body)
        self.assertTrue(verify_export(p)['ok'])
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(body.replace('alice', 'mallo', 1))
        self.assertFalse(verify_export(p)['ok'])


@unittest.skipUnless(HAVE_OPENSSL, 'openssl needed to create a test signing key')
class TestReleaseSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='jtwaf-sig-')
        cls.key = os.path.join(cls.dir, 'key.pem')
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', cls.key],
                       check=True, capture_output=True)
        cls.pub = subprocess.run(['openssl', 'pkey', '-in', cls.key, '-pubout'], check=True, capture_output=True,
                                 text=True).stdout

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _release(self):
        rel = tempfile.mkdtemp(dir=self.dir)
        os.makedirs(os.path.join(rel, 'jtwafmgr', 'web'))
        os.makedirs(os.path.join(rel, 'release'))
        for p, t in (('jtwafmgr/__init__.py', 'x = 1\n'), ('jtwafmgr/web/api.py', 'y = 2\n'), ('LICENSE', 'AGPL\n')):
            with open(os.path.join(rel, p), 'w') as fh:
                fh.write(t)
        m = integrity.make_manifest(rel, ['jtwafmgr/__init__.py', 'jtwafmgr/web/api.py', 'LICENSE'])
        mp = os.path.join(rel, 'release', integrity.MANIFEST)
        with open(mp, 'w') as fh:
            fh.write(m)
        subprocess.run(['openssl', 'dgst', '-sha256', '-sign', self.key, '-out', mp + '.sig', mp], check=True)
        return rel

    def test_fingerprint_matches_openssl(self):
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=self.pub.encode(),
                             capture_output=True, check=True).stdout
        import hashlib
        self.assertEqual(integrity.key_fingerprint(self.pub), hashlib.sha256(der).hexdigest())

    def test_release_ok_and_tampering(self):
        rel = self._release()
        self.assertTrue(integrity.verify_release(rel, self.pub)['ok'])
        with open(os.path.join(rel, 'jtwafmgr', 'web', 'api.py'), 'a') as fh:
            fh.write('import os\n')
        r = integrity.verify_release(rel, self.pub)
        self.assertEqual(r['changed'], ['jtwafmgr/web/api.py'])
        rel = self._release()
        with open(os.path.join(rel, 'jtwafmgr', 'evil.py'), 'w') as fh:
            fh.write('import os\n')
        self.assertEqual(integrity.verify_release(rel, self.pub)['extra'], ['jtwafmgr/evil.py'])
        rel = self._release()
        with open(os.path.join(rel, 'release', integrity.MANIFEST), 'a') as fh:
            fh.write('%s  jtwafmgr/x.py\n' % ('0' * 64))
        self.assertEqual(integrity.verify_release(rel, self.pub)['reason'], 'signature_invalid')

    def test_installed_program_check(self):
        rel = self._release()
        keyf = os.path.join(self.dir, 'pub-%s.pem' % os.path.basename(rel))
        with open(keyf, 'w') as fh:
            fh.write(self.pub)
        r = integrity.verify_program(rel, keyf)
        self.assertEqual(r['status'], 'ok', r)
        # planted code Python would import: a module shadowing the standard library next to the package,
        # bytecode in __pycache__, and a linked directory
        with open(os.path.join(rel, 're.py'), 'w') as fh:
            fh.write('raise SystemExit')
        os.makedirs(os.path.join(rel, 'jtwafmgr', '__pycache__'))
        with open(os.path.join(rel, 'jtwafmgr', '__pycache__', 'util.cpython-311.pyc'), 'wb') as fh:
            fh.write(b'x')
        os.symlink(self.dir, os.path.join(rel, 'jtwafmgr', 'evil'))
        r = integrity.verify_program(rel, keyf)
        self.assertEqual(r['status'], 'failed')
        self.assertIn('re.py', r['extra'])
        self.assertIn('jtwafmgr/__pycache__/util.cpython-311.pyc', r['extra'])
        self.assertIn('jtwafmgr/evil (link)', r['extra'])
        for p in ('re.py',):
            os.unlink(os.path.join(rel, p))
        shutil.rmtree(os.path.join(rel, 'jtwafmgr', '__pycache__'))
        os.unlink(os.path.join(rel, 'jtwafmgr', 'evil'))
        self.assertEqual(integrity.verify_program(rel, keyf)['status'], 'ok')
        os.unlink(os.path.join(rel, 'LICENSE'))
        r = integrity.verify_program(rel, keyf)
        self.assertEqual((r['status'], r['missing']), ('failed', ['LICENSE']))
        self.assertEqual(integrity.verify_program(tempfile.mkdtemp(dir=self.dir), keyf)['status'], 'not_installed')

    def test_apply_refuses_modified_program(self):
        from jtwafmgr.apply import Applier
        env = TempEnv(managed={'spool': os.path.join(self.dir, 'spool'), 'dir': os.path.join(self.dir, 'managed')})
        try:
            ap = Applier(env.cfg)
            ap.program_check = lambda: {'status': 'failed', 'reason': 'files_differ', 'changed': ['jtwafmgr/apply.py'],
                                        'dir': '/usr/lib/jt-waf-mgr'}
            os.makedirs(ap.spool, exist_ok=True)
            with open(os.path.join(ap.spool, 'v1-c1.req'), 'w') as fh:
                fh.write('{}')
            ap.process()
            with open(os.path.join(ap.spool, 'v1-c1.result')) as fh:
                res = json.load(fh)
            self.assertEqual((res['result'], res['step']), ('failed', 'integrity'))
        finally:
            env.cleanup()


class TestAccountPolicy(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(auth={'password_min_classes': 3, 'password_history': 3, 'password_min_age_hours': 24,
                                 'password_max_age_days': 90, 'dormant_days': 30, 'max_sessions_per_user': 2})
        self.app = App(self.env.cfg)
        self.a = self.app.auth

    def tearDown(self):
        self.env.cleanup()

    def test_complexity_history_and_min_age(self):
        self.a.create_user('alice', 'viewer', password='Initial-Passw0rd')
        with self.assertRaises(AuthError) as e:
            self.a.set_password('alice', 'alllowercaseletters')
        self.assertEqual(e.exception.code, 'password_too_simple')
        with self.assertRaises(AuthError) as e:
            self.a.set_password('alice', 'Second-Passw0rd')
        self.assertEqual(e.exception.code, 'password_too_recent')
        self.a.set_password('alice', 'Second-Passw0rd', by_user=False)
        self.a.set_password('alice', 'Third-Passw0rd', by_user=False)
        with self.assertRaises(AuthError) as e:
            self.a.set_password('alice', 'Initial-Passw0rd', by_user=False)
        self.assertEqual(e.exception.code, 'password_reused')
        with self.assertRaises(AuthError) as e:
            self.a.set_password('alice', 'Third-Passw0rd', by_user=False)
        self.assertEqual(e.exception.code, 'password_same')

    def test_max_age_forces_change(self):
        self.a.create_user('bob', 'viewer', password='Bobs-Passw0rd-1')
        self.app.db.x("UPDATE users SET pw_changed_at=? WHERE username='bob'", (time.time() - 91 * 86400,))
        _, _, row, _ = self.a.login('bob', 'Bobs-Passw0rd-1', None, '192.0.2.5')
        self.assertTrue(row['must_change'])

    def test_previous_login_and_failures_reported(self):
        self.a.create_user('carl', 'viewer', password='Carls-Passw0rd-1')
        self.a.login('carl', 'Carls-Passw0rd-1', None, '192.0.2.5')
        for _ in range(2):
            with self.assertRaises(AuthError):
                self.a.login('carl', 'wrong', None, '198.51.100.9')
        _, _, _, prev = self.a.login('carl', 'Carls-Passw0rd-1', None, '192.0.2.6')
        self.assertEqual((prev['ip'], prev['failed_since']), ('192.0.2.5', 2))

    def test_lockout_is_a_critical_audit_event(self):
        self.a.create_user('dora', 'viewer', password='Doras-Passw0rd-1')
        for _ in range(5):
            with self.assertRaises(AuthError):
                self.a.login('dora', 'wrong', None, '198.51.100.9')
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='account.locked' AND actor='dora'"))

    def test_dormant_and_expired_accounts(self):
        self.a.create_user('root1', 'admin', password='Admin-Passw0rd-1')
        self.a.create_user('eve', 'viewer', password='Eves-Passw0rd-1')
        self.a.create_user('tmp', 'viewer', password='Tmps-Passw0rd-1', expires_at=time.time() + 60)
        old = time.time() - 31 * 86400
        self.app.db.x("UPDATE users SET activity_at=?", (old,))
        self.app.db.x("UPDATE users SET expires_at=?, activity_at=? WHERE username='tmp'", (time.time() - 1, time.time()))
        out = dict(self.a.expire_accounts())
        self.assertEqual(out, {'eve': 'dormant', 'tmp': 'expired'})   # never the last active admin
        self.assertTrue(self.a.user_row('root1')['disabled'] == 0)
        self.a.set_disabled('eve', False)                             # re-enabling restarts the clock
        self.assertEqual(self.a.expire_accounts(), [])

    def test_session_limit(self):
        self.a.create_user('fred', 'viewer', password='Freds-Passw0rd-1')
        for _ in range(3):
            self.a.login('fred', 'Freds-Passw0rd-1', None, '192.0.2.5')
        self.assertEqual(len(self.a.sessions_of('fred')), 2)


class TestMonitor(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.env.cleanup()

    def test_backup_and_verify(self):
        mon = self.app.monitor
        self.app.audit.log('test.action', 'alice')
        r = mon.backup()
        self.assertTrue(r['ok'], r)
        self.assertEqual(oct(os.stat(os.path.join(self.env.cfg['backup']['dir'], r['file'])).st_mode & 0o777), '0o600')
        self.assertTrue(mon.verify_backup(r['file'])['ok'])
        with open(os.path.join(self.env.cfg['backup']['dir'], r['file']), 'r+b') as fh:
            fh.seek(200)
            fh.write(b'\x00\x01')
        self.assertFalse(mon.verify_backup(r['file'])['sha256_ok'])
        self.assertIsNone(mon.verify_backup('../../etc/passwd'))

    def test_config_change_tracking(self):
        mon = self.app.monitor
        f = os.path.join(self.env.dir, 'site.conf')
        with open(f, 'w') as fh:
            fh.write('SecRuleEngine On\n')
        mon.config_files = lambda: [f]
        self.assertEqual(mon.check_config()['cause'], 'baseline')
        self.assertFalse(mon.check_config()['changed'])
        with open(f, 'a') as fh:
            fh.write('SecRuleRemoveById 942100\n')
        st = mon.check_config()
        self.assertEqual(st['cause'], 'outside')
        items, _ = mon.config_changes()
        self.assertEqual(items[0]['changes']['changed'], [f])
        row = self.app.db.one("SELECT * FROM audit WHERE action='config.changed'")
        self.assertEqual(row['result'], 'outside')

    def test_adoption_is_not_an_outside_change(self):
        """Adoption replaces the site's own rule files in main.conf: the old files leave the configuration as part
        of jt-waf-mgr's change (it was recorded as outside on the first site)."""
        import json as _j
        mon, now = self.app.monitor, time.time()
        mdir = self.env.cfg['managed']['dir'].rstrip('/') + '/'
        main = self.app.site.load()[1].main_files[0]
        old = '/etc/nginx/modsec/site-before.conf'
        self.app.workflow.managed.disk_state = lambda: {'drift': False}
        self.app.db.x("INSERT INTO versions(version, created_at, change_id, kind, files, hashes, state, result) "
                      "VALUES (1, ?, 1, 'adopt', '{}', '{}', 'applied', '{}')", (now,))
        ch = {'added': [mdir + 'before-crs.conf'], 'removed': [old], 'changed': [main]}
        self.assertEqual(mon._cause({'ts': now - 60}, ch), 'outside')       # no adoption recorded yet
        self.app.db.x("INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, created_at, updated_at) "
                      "VALUES ('adopt', 'system', ?, 'neutral', 'applied', 'x', 'boss', ?, ?)",
                      (_j.dumps({'sources': {'before': {'path': old, 'sha256': 'x'}}, 'items': 1}), now, now))
        self.assertEqual(mon._cause({'ts': now - 60}, ch), 'jt-waf-mgr')
        self.assertEqual(mon._cause({'ts': now - 60}, dict(ch, removed=[old, '/etc/nginx/other.conf'])), 'outside')

    def test_a_version_being_applied_is_not_an_outside_change(self):
        """The apply program writes the files, then waits for old nginx workers before it reports: in between the
        version is still pending and the files differ from the last applied one. Files equal to that pending version
        are jt-waf-mgr's own; anything else stays outside."""
        import json as _j
        mon, now = self.app.monitor, time.time()
        mg = self.app.workflow.managed
        mdir = self.env.cfg['managed']['dir'].rstrip('/') + '/'
        disk = {'before': 'a' * 64, 'after': 'b' * 64}
        mg.disk_hashes = lambda: dict(disk)
        mg.disk_state = lambda: {'drift': True}
        self.app.db.x("INSERT INTO versions(version, created_at, change_id, kind, files, hashes, state, result) "
                      "VALUES (7, ?, 9, 'change', '{}', ?, 'pending', '{}')", (now, _j.dumps(disk)))
        ch = {'added': [], 'removed': [], 'changed': [mdir + 'before-crs.conf']}
        self.assertEqual(mon._cause({'ts': now - 60}, ch), 'jt-waf-mgr')
        disk['before'] = 'c' * 64                                    # someone else's edit on top
        self.assertEqual(mon._cause({'ts': now - 60}, ch), 'outside')
        self.assertEqual(mon._cause({'ts': now - 60}, dict(ch, changed=['/etc/nginx/nginx.conf'])), 'outside')

    def test_backup_download_needs_a_fresh_code_and_is_audited(self):
        from jtwafmgr import auth
        from jtwafmgr.web import api
        from jtwafmgr.web.server import ApiError
        a = self.app.auth
        a.create_user('boss2', 'admin', password='a long test password')
        sec, _ = a.totp_setup('boss2')
        a.totp_enable('boss2', auth.totp_code(sec, int(time.time() // 30) - 1))
        r = self.app.monitor.backup(actor='test')
        self.assertTrue(r['ok'], r)

        class Req:
            def __init__(self, name, body):
                self.params, self._b, self.user, self.client_ip = {'name': name}, body, {'username': 'boss2', 'role': 'admin'}, '192.0.2.5'

            def body(self):
                return self._b
        with self.assertRaises(ApiError) as cm:                       # no code
            api.backup_download(self.app, Req(r['file'], {}))
        self.assertEqual(cm.exception.code, 'totp_required')
        with self.assertRaises(ApiError):                              # not a backup name
            api.backup_download(self.app, Req('../../etc/passwd', {'totp': auth.totp_code(sec, int(time.time() // 30))}))
        code = auth.totp_code(sec, int(time.time() // 30))
        resp = api.backup_download(self.app, Req(r['file'], {'totp': code}))
        self.assertEqual(resp.status, 200)
        data = resp.stream.read()
        resp.stream.close()
        self.assertTrue(data.startswith(b'SQLite format 3'))
        self.assertEqual(len(data), resp.length)
        self.assertIn(('X-Backup-Verified', 'yes'), resp.headers)
        with self.assertRaises(ApiError):                              # the same code twice: refused
            api.backup_download(self.app, Req(r['file'], {'totp': code}))
        acts = [x['action'] for x in self.app.db.q("SELECT action FROM audit WHERE action IN "
                                                   "('backup.downloaded', 'auth.step_up_failed')")]
        self.assertEqual(acts.count('backup.downloaded'), 1)
        self.assertEqual(acts.count('auth.step_up_failed'), 2)   # no code, a code used twice

    def test_daily_backup_schedule(self):
        from jtwafmgr.compliance import Monitor
        day = time.mktime((2026, 11, 12, 0, 0, 0, 0, 0, -1))
        # 02:59 -> yesterday 03:00; 03:00 -> today 03:00
        self.assertEqual(Monitor.last_scheduled(3, day + 2 * 3600 + 59 * 60), day - 21 * 3600)
        self.assertEqual(Monitor.last_scheduled(3, day + 3 * 3600), day + 3 * 3600)
        mon = self.app.monitor
        made = []
        mon.backup = lambda actor='system': made.append(1) or {'ok': True}
        # a backup by hand at 23:31 the evening before does not skip the 03:00 backup
        self.app.workflow.managed.set_setting('backup.last', {'ts': day - 29 * 60, 'ok': True}, 'test')
        mon.last_scheduled = lambda hour, now=None: day + 3 * 3600
        mon.maybe_backup()
        self.assertEqual(made, [1])
        self.app.workflow.managed.set_setting('backup.last', {'ts': day + 3 * 3600 + 5, 'ok': True}, 'test')
        mon.maybe_backup()
        self.assertEqual(made, [1])

    def test_backup_retries_and_pruning_keep_good_copies(self):
        mon, mg = self.app.monitor, self.app.workflow.managed
        now = time.time()
        made = []
        real = mon.backup
        mon.backup = lambda actor='system': made.append(1) or {'ok': True}
        mon.last_scheduled = lambda hour, now=None: now_ - 7200
        now_ = now
        # failed 2 hours ago (after the scheduled time), first failure: retried
        mg.set_setting('backup.last', {'ts': now - 3700, 'ok': False, 'fails': 1}, 'test')
        mon.maybe_backup()
        self.assertEqual(len(made), 1)
        # failed three times: wait for the next night
        mg.set_setting('backup.last', {'ts': now - 3700, 'ok': False, 'fails': 3}, 'test')
        mon.maybe_backup()
        self.assertEqual(len(made), 1)
        # a last backup "in the future" (wrong clock) does not stop the nightly backup
        mg.set_setting('backup.last', {'ts': now + 86400, 'ok': True}, 'test')
        mon.maybe_backup()
        self.assertEqual(len(made), 2)
        mon.backup = real
        # pruning: old copies go, but the newest three always stay
        d = self.env.cfg['backup']['dir']
        os.makedirs(d, exist_ok=True)
        for i in range(5):
            p = os.path.join(d, 'jt-waf-mgr-2026010%d-030000.db' % (i + 1))
            wr(p, 'x')
            os.utime(p, (now - 90 * 86400, now - 90 * 86400))
        mon._prune_backups()
        self.assertEqual(len([f for f in os.listdir(d) if f.endswith('.db')]), 3)

    def test_step_up_codes_are_limited_and_single_use(self):
        from jtwafmgr import auth as auth_mod
        from jtwafmgr.auth import AuthError
        a = self.app.auth
        a.create_user('boss3', 'admin', password='a long test password')
        sec, _ = a.totp_setup('boss3')
        a.totp_enable('boss3', auth_mod.totp_code(sec, int(time.time() // 30) - 1))
        code = auth_mod.totp_code(sec, int(time.time() // 30))
        a.step_up('boss3', code, 'test')
        with self.assertRaises(AuthError) as cm:                  # the same code again
            a.step_up('boss3', code, 'test')
        self.assertEqual(cm.exception.code, 'totp_required')
        for _ in range(4):
            with self.assertRaises(AuthError):
                a.step_up('boss3', '000000', 'test')
        with self.assertRaises(AuthError) as cm:                  # five failures: locked for the window
            a.step_up('boss3', auth_mod.totp_code(sec, int(time.time() // 30) + 1), 'test')
        self.assertEqual((cm.exception.code, cm.exception.status), ('too_many_attempts', 429))
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='auth.step_up_locked'"))

    def test_system_check_and_controls(self):
        keys = {i['key'] for i in system_check(self.app)}
        for k in ('program_integrity', 'audit_chain', 'time_sync', 'backup', 'database', 'accounts', 'apply'):
            self.assertIn(k, keys)
        rep = controls(self.app)
        ids = {c['id'] for c in rep['controls']}
        self.assertIn('log_protection', ids)
        for c in rep['controls']:
            self.assertIn(c['status'], ('met', 'partial', 'gap', 'organisational'))

    def test_level_medium_shows_password_gaps(self):
        env = TempEnv(compliance={'level': 'medium'})
        try:
            app = App(env.cfg)
            auth_ctl = next(c for c in controls(app)['controls'] if c['id'] == 'authentication')
            self.assertEqual(auth_ctl['status'], 'gap')
            self.assertIn('auth.password_max_age_days', auth_ctl['needs'])
        finally:
            env.cleanup()


class TestComplianceApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv()
        cls.app = App(cls.env.cfg)
        a = cls.app.auth
        a.create_user('viewer1', 'viewer', password=PW)
        a.create_user('admin1', 'admin', password=PW)
        cls.secret, _ = a.totp_setup('admin1')
        a.totp_enable('admin1', auth.totp_code(cls.secret, int(time.time() // 30)))
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.env.cleanup()

    def admin(self):
        self.app.db.x("UPDATE users SET totp_last_step=0 WHERE username='admin1'")
        c = Client(self.port)
        st, obj = c.login('admin1', totp=auth.totp_code(self.secret, int(time.time() // 30)))
        self.assertEqual(st, 200, obj)
        self.assertIn('previous_login', obj)
        return c

    def test_admin_only(self):
        c = Client(self.port)
        c.login('viewer1')
        for path in ('/api/v1/system/check', '/api/v1/compliance', '/api/v1/audit/export', '/api/v1/users/review',
                     '/api/v1/backups', '/api/v1/config-changes'):
            self.assertEqual(c.req('GET', path)[0], 403, path)

    def test_endpoints(self):
        c = self.admin()
        st, obj, _ = c.req('GET', '/api/v1/system/check')
        self.assertEqual(st, 200)
        self.assertTrue(any(i['key'] == 'audit_chain' for i in obj['items']))
        st, obj, _ = c.req('POST', '/api/v1/audit/verify')
        self.assertEqual((st, obj['ok']), (200, True))
        r, body = c.req('GET', '/api/v1/audit/export', raw=True)
        self.assertEqual(r.status, 200)
        last = json.loads(body.decode().strip().splitlines()[-1])['_summary']
        self.assertEqual(r.getheader('X-Content-SHA256'), last['sha256_of_lines'])
        st, obj, _ = c.req('GET', '/api/v1/users/review')
        self.assertEqual(st, 200)
        self.assertIn('days_since_activity', obj['users'][0])
        st, obj, _ = c.req('GET', '/api/v1/compliance')
        self.assertEqual(st, 200)
        st, obj, _ = c.req('POST', '/api/v1/backups')
        self.assertEqual(st, 201, obj)
        st, obj, _ = c.req('POST', '/api/v1/backups/%s/verify' % obj['file'])
        self.assertTrue(obj['ok'])
        st, obj, _ = c.req('GET', '/api/v1/auth/sessions')
        self.assertTrue(any(s['current'] for s in obj['items']))
        st, obj, _ = c.req('GET', '/api/v1/meta')
        self.assertIn('password_policy', obj)


# Write routes that deliberately do not add an audit row, with the reason.
AUDIT_EXEMPT = {
    'patch_me': 'own language / display name only',
    'totp_setup': 'creates an unconfirmed secret; enabling it is audited',
    'change_preview': 'read-only preview, nothing stored',
    'managed_import_preview': 'read-only comparison of an uploaded file, nothing stored',
    'login': 'audited inside Auth.login (success, failure, lockout)',
    'logout': 'audited inline when a session exists',
    'system_check_run': 'audited',
    'backup_now': 'audited by Monitor.backup',
}


class TestAuditCoverage(unittest.TestCase):
    """Every route that changes something must write an audit row (directly or through the module it
    calls). A new write route fails this test until it audits or is listed in AUDIT_EXEMPT with a reason."""

    # a route may also delegate to a Workflow method checked by test_workflow_actions_audited
    AUDITING_CALLS = ('audit.log', 'app.monitor.backup', '_wf(app).propose', '_wf(app).approve', '_wf(app).import_propose',
                      'uisettings.set_many', 'alerts.handle(',
                      '_wf(app).reject', '_wf(app).cancel', '_wf(app).recheck', '_wf(app).rollback',
                      'app.blocks.add(', 'app.blocks.remove(')

    def test_write_routes_audited(self):
        from jtwafmgr.web import api
        from jtwafmgr.web.server import Router
        r = Router()
        api.register(r)
        missing = []
        for method, _, fn, _ in r.routes:
            if method == 'GET' or fn.__name__ in AUDIT_EXEMPT:
                continue
            src = inspect.getsource(fn)
            if not any(c in src for c in self.AUDITING_CALLS):
                missing.append(fn.__name__)
        self.assertEqual(missing, [])

    def test_workflow_actions_audited(self):
        from jtwafmgr.changes import Workflow
        for name in ('_insert', 'propose_adoption', 'approve', 'reject', 'cancel', 'recheck', 'rollback'):
            src = inspect.getsource(getattr(Workflow, name))
            self.assertIn('audit.log', src, name)
        from jtwafmgr.blocks import Blocks
        for name in ('add', 'remove', 'expire', 'handle_result', '_refuse'):
            self.assertIn('audit.log', inspect.getsource(getattr(Blocks, name)), name)
        # every way of proposing goes through the audited _insert
        for name in ('propose', 'propose_bundle'):
            self.assertIn('self._insert(', inspect.getsource(getattr(Workflow, name)), name)


if __name__ == '__main__':
    unittest.main()


class TestParamBounds(unittest.TestCase):
    def test_huge_numbers_are_a_400_not_a_500(self):
        from jtwafmgr.web import api
        from jtwafmgr.web.server import ApiError

        class R:
            query = {'cursor': '99999999999999999999'}
        with self.assertRaises(ApiError) as cm:
            api._int_param(R, 'cursor')
        self.assertEqual(cm.exception.status, 400)
        R.query = {'cursor': '42'}
        self.assertEqual(api._int_param(R, 'cursor'), 42)
