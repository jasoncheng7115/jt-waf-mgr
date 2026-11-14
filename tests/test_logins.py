"""A change made outside jt-waf-mgr: who was logged in to the host meanwhile (jtwafmgr/logins.py, the host's
authentication log) and what changed (the stored, masked text of the configuration files). Synthetic data only."""
import datetime
import gzip
import json
import os
import time
import unittest

from jtwafmgr import logins
from jtwafmgr.app import App
from jtwafmgr.compliance import Monitor
from tests.helpers import TempEnv

KEY = 'ED25519 SHA256:' + 'x' * 43


def stamp(t):
    return datetime.datetime.fromtimestamp(t).strftime('%b %e %H:%M:%S').replace('  ', ' ', 0)


class TestSessions(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.log = os.path.join(self.env.dir, 'auth.log')
        self.t0 = time.time() - 3600

    def write(self, lines, path=None):
        with open(path or self.log, 'w') as fh:
            for dt, text in lines:
                fh.write('%s host1 %s\n' % (stamp(self.t0 + dt), text))

    def test_logins_in_the_window(self):
        self.write([
            (0, 'sshd[100]: Accepted publickey for root from 192.0.2.10 port 50000 ssh2: ' + KEY),
            (1, 'sshd[100]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)'),
            (60, 'sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/vi /etc/nginx/vhost/a.conf'),
            (120, 'sshd[100]: pam_unix(sshd:session): session closed for user root'),
            (130, 'sshd[200]: Accepted password for alice from 198.51.100.7 port 40000 ssh2'),
            (140, 'sudo:    alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/nginx -s reload'),
            (150, 'CRON[300]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)'),
            (3000, 'sshd[400]: Accepted publickey for bob from 203.0.113.9 port 1 ssh2: ' + KEY),   # after the window
        ])
        found, loose = logins.sessions([self.log], self.t0 + 100, self.t0 + 200, slack=0)
        self.assertEqual([(s['user'], s['from'], s['method']) for s in found],
                         [('alice', '198.51.100.7', 'password'), ('root', '192.0.2.10', 'publickey')])
        self.assertEqual(found[1]['key'], KEY)
        self.assertIsNotNone(found[1]['end'])
        self.assertIsNone(found[0]['end'])                                 # still open
        self.assertEqual([c['command'] for c in found[0]['commands']], ['/usr/sbin/nginx -s reload'])
        self.assertEqual([c['command'] for c in loose], [])                # the 60 s sudo is before the window
        found, loose = logins.sessions([self.log], self.t0 + 50, self.t0 + 70, slack=0)
        self.assertEqual([s['user'] for s in found], ['root'])
        self.assertEqual([c['by'] for c in loose], ['alice'])              # sudo by someone with no session found
        self.assertIn('root from 192.0.2.10 (publickey)', logins.summary(found))

    def test_rotated_gzip_and_iso_stamps_and_missing_files(self):
        old = self.log + '.1'
        self.write([(0, 'sshd[1]: Accepted publickey for root from 192.0.2.20 port 1 ssh2: ' + KEY)], path=old)
        iso = datetime.datetime.fromtimestamp(self.t0 + 10).astimezone().isoformat()
        with open(self.log, 'w') as fh:
            fh.write('%s host1 sshd[2]: Accepted publickey for ops from 192.0.2.21 port 2 ssh2: %s\n' % (iso, KEY))
        found, _ = logins.sessions([self.log, '/nonexistent/auth.log'], self.t0, self.t0 + 60, slack=0)
        self.assertEqual(sorted(s['user'] for s in found), ['ops', 'root'])
        with gzip.open(self.log + '.2.gz', 'wt') as fh:               # older rotations are not read
            fh.write('noise\n')
        self.assertEqual(logins.sessions(['/nonexistent'], 0, time.time()), ([], []))


class TestOutsideChange(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg)
        self.addCleanup(self.app.stop)
        self.mon = self.app.monitor
        self.f = os.path.join(self.env.dir, 'site.conf')
        self.auth = os.path.join(self.env.dir, 'auth.log')
        self.app.cfg.data['integrity']['auth_logs'] = [self.auth]
        self.mon.config_files = lambda: [self.f]

    def test_masking(self):
        text = ('proxy_set_header Authorization "Basic dXNlcjpwYXNz";\n'
                'set $api_key abc123;\n'
                '# token: hunter2\n'
                'ssl_certificate /etc/ssl/a.pem;\n'
                'add_header X-Id ' + 'A' * 48 + ';\n')
        out = Monitor.mask_config(text)
        for secret in ('dXNlcjpwYXNz', 'abc123', 'hunter2', 'A' * 48):
            self.assertNotIn(secret, out)
        self.assertIn('ssl_certificate /etc/ssl/a.pem;', out)
        self.assertIn('proxy_set_header Authorization ***;', out)

    def test_an_outside_change_says_what_and_who(self):
        with open(self.f, 'w') as fh:
            fh.write('server {\n  listen 443;\n  set $token secret-one;\n}\n')
        self.assertEqual(self.mon.check_config()['cause'], 'baseline')
        with open(self.auth, 'w') as fh:
            fh.write('%s host1 sshd[9]: Accepted publickey for root from 192.0.2.30 port 5 ssh2: %s\n' % (stamp(time.time() - 30), KEY))
        with open(self.f, 'w') as fh:
            fh.write('server {\n  listen 443;\n  if ($geo = 0) { return 403; }\n  set $token secret-two;\n}\n')
        self.assertEqual(self.mon.check_config()['cause'], 'outside')
        snap = self.mon.config_snapshot(self.mon.config_changes()[0][0]['id'])
        diff = snap['changes']['diffs'][self.f]
        self.assertIn('+  if ($geo = 0) { return 403; }', diff)
        self.assertNotIn('secret-one', diff + json.dumps(snap))
        self.assertNotIn('secret-two', diff + json.dumps(snap))
        self.assertEqual([(s['user'], s['from']) for s in snap['changes']['logins']], [('root', '192.0.2.30')])
        # the list stays light: counts, no differences
        item = self.mon.config_changes()[0][0]
        self.assertEqual((item['changes']['logins'], 'diffs' in item['changes']), (1, False))
        # the alert names the files and the login, without opening the snapshot
        al = self.app.db.one("SELECT details FROM alerts WHERE kind='config_outside'")
        d = json.loads(al['details'])
        self.assertEqual(d['path'], self.f)
        self.assertIn('root from 192.0.2.30', d['reason'])
        # nothing stored in clear: the database holds the masked text only
        raw = b''.join(bytes(r[0]) for r in self.app.db.q('SELECT body FROM config_contents'))
        import zlib
        self.assertNotIn(b'secret-', b''.join(zlib.decompress(bytes(r[0])) for r in self.app.db.q('SELECT body FROM config_contents')))
        self.assertTrue(raw)

    def test_an_older_outside_change_looks_the_logins_up_when_opened(self):
        with open(self.f, 'w') as fh:
            fh.write('a\n')
        self.mon.check_config()
        with open(self.f, 'w') as fh:
            fh.write('b\n')
        self.mon.check_config()
        sid = self.mon.config_changes()[0][0]['id']
        row = self.app.db.one('SELECT changes FROM config_snapshots WHERE id=?', (sid,))
        old = {k: v for k, v in json.loads(row['changes']).items() if k in ('added', 'removed', 'changed')}
        self.app.db.x('UPDATE config_snapshots SET changes=? WHERE id=?', (json.dumps(old), sid))     # as 0.4.29 stored it
        with open(self.auth, 'w') as fh:
            fh.write('%s host1 sshd[9]: Accepted publickey for ops from 192.0.2.31 port 5 ssh2: %s\n' % (stamp(time.time() - 5), KEY))
        snap = self.mon.config_snapshot(sid)
        self.assertTrue(snap['changes']['logins_live'])
        self.assertEqual([s['user'] for s in snap['changes']['logins']], ['ops'])
        self.assertNotIn('diffs', snap['changes'])

    def test_no_login_and_a_version_not_stored(self):
        with open(self.f, 'wb') as fh:
            fh.write(b'\x00binary')
        self.mon.check_config()
        with open(self.f, 'w') as fh:
            fh.write('text now\n')
        self.mon.check_config()
        snap = self.mon.config_snapshot(self.mon.config_changes()[0][0]['id'])
        self.assertIsNone(snap['changes']['diffs'][self.f])                  # the old version was not text
        self.assertEqual(snap['changes']['logins'], [])
        al = json.loads(self.app.db.one("SELECT details FROM alerts WHERE kind='config_outside'")['details'])
        self.assertIn('no login', al['reason'])


if __name__ == '__main__':
    unittest.main()
