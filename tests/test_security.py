"""Regression tests for the findings of the adversarial review (2026-11-12)."""
import http.client
import threading
import time
import unittest

from jtwafmgr import auth
from jtwafmgr.app import App
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv

PW = 'a long test password'


class TestLockout(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(auth={'lockout_threshold': 5, 'ip_attempts_per_10min': 1000})
        self.app = App(self.env.cfg)
        self.app.auth.create_user('alice', 'viewer', password=PW)

    def tearDown(self):
        self.env.cleanup()

    def test_concurrent_failures_all_count(self):
        def wrong(i):
            try:
                self.app.auth.login('alice', 'wrong %d' % i, None, '198.51.100.%d' % (i + 1))
            except auth.AuthError:
                pass
        ts = [threading.Thread(target=wrong, args=(i,)) for i in range(5)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        r = self.app.auth.user_row('alice')
        self.assertGreater(r['locked_until'], time.time(), 'five simultaneous wrong passwords must lock the account')

    def test_ipv6_rate_limit_by_64(self):
        self.assertEqual(auth._rate_key('2001:db8:1:2::5'), auth._rate_key('2001:db8:1:2:ffff::9'))
        self.assertNotEqual(auth._rate_key('2001:db8:1:2::5'), auth._rate_key('2001:db8:1:3::5'))


class TestTokenOwnerCannotApprove(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.wf = self.app.workflow
        self.app.auth.create_user('appr', 'approver', password=PW)

    def tearDown(self):
        self.env.cleanup()

    def test_owner_of_token_is_the_proposer(self):
        from jtwafmgr.changes import ChangeError
        cid = self.app.db.x("INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, proposed_via, "
                            "created_at, updated_at, proposed_owner) VALUES ('add', 'redaction', '{}', 'loosen', "
                            "'pending_approval', 'via token', 'sync-token', 'api', ?, ?, 'appr')", (time.time(), time.time())).lastrowid
        with self.assertRaises(ChangeError) as e:
            self.wf.approve(cid, self.app.auth.user_row('appr'))
        self.assertEqual(e.exception.code, 'own_change')


class TestBodyLength(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv()
        cls.app = App(cls.env.cfg)
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.env.cleanup()

    def test_negative_or_bad_content_length(self):
        for v in ('-1', 'abc'):
            c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
            c.putrequest('POST', '/api/v1/auth/login')
            c.putheader('Host', '127.0.0.1:%d' % self.port)
            c.putheader('Content-Type', 'application/json')
            c.putheader('Content-Length', v)
            c.endheaders()
            r = c.getresponse()
            self.assertEqual(r.status, 400, v)
            c.close()


if __name__ == '__main__':
    unittest.main()
