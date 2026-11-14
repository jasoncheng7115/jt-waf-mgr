"""The periodic WAF review (review.py): grouping, possible false blocks, focus sites, one review per slot, the
notification, the API -- and that no query string or request content reaches a review."""
import json
import time
import unittest

from jtwafmgr import auth, notify, review
from jtwafmgr.app import App
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv
from tests.test_api import PW, Client


def ev(app, i, ts, host, path, ip, origin, outcome, decided=None, rules=',930130,', fams=',lfi,', query='', status=403):
    app.db.x("INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, status, outcome, "
             "decided_by, rule_ids, local_rule_ids, families, message, matches) VALUES ('waf1', ?, ?, ?, 'POST', ?, ?, ?, ?, ?, ?, "
             "?, ?, ',', ?, '', '[]')", ('u%d' % i, ts, host, path, query, ip, origin, status, outcome, decided, rules, fams))


class TestReview(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.app.cfg.data['waf']['focus_sites'] = ['sso.example.com']
        self.app.cfg.data['notify']['report_hour'] = -1
        self.now = time.time()
        n = self.now - 600
        # an attack blocked by the score: not a suspect
        ev(self.app, 1, n, 'app.example.com', '/../etc/passwd', '203.0.113.9', 'external', 'blocked', 'score')
        # a form blocked by the score from an internal user (not a scanner), no attack type: suspect
        ev(self.app, 2, n, 'erp.example.com', '/web/dataset/call_kw', '192.168.77.50', 'internal', 'blocked', 'score',
           rules=',920170,949110,', fams=',protocol,', query='password=hunter2')
        # an outside attack only logged
        ev(self.app, 3, n, 'app.example.com', '/cgi-bin/x.cgi', '198.51.100.7', 'external', 'logged', None, fams=',rce,', status=404)
        # the focus site: 25 logins from one outside source
        for i in range(25):
            ev(self.app, 100 + i, n, 'sso.example.com', '/realms/x/login-actions/authenticate', '198.51.100.20', 'external',
               'logged', None, rules=',920420,', fams=',protocol,', status=200)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_build(self):
        d = review.build(self.app, self.now - 3 * 3600, self.now)
        self.assertEqual(d['events'], 28)
        self.assertEqual(d['score_only_groups'], 2)
        self.assertEqual(d['possible_false_blocks'], 1)
        first = d['score_only'][0]
        self.assertEqual((first['host'], first['suspect'], first['internal_sources']), ('erp.example.com', True, 1))
        self.assertNotIn(949110, first['rules'])                       # the scoring rule says nothing
        self.assertEqual(d['internal'][0]['new'], True)
        self.assertEqual(d['outside_not_refused'][0]['path'], '/cgi-bin/x.cgi')
        f = d['focus'][0]
        self.assertEqual((f['host'], f['events'], f['login_events']), ('sso.example.com', 25, 25))
        self.assertEqual(f['repeated_login'], [['198.51.100.20', 25]])
        self.assertEqual(d['level'], 'warning')
        self.assertNotIn('hunter2', json.dumps(d))                      # no query string, no content

    def test_known_scanner_is_not_a_suspect_user(self):
        import ipaddress
        self.app.cfg.known_scanners = [ipaddress.ip_network('192.168.77.0/24')]
        d = review.build(self.app, self.now - 3 * 3600, self.now)
        erp = [s for s in d['score_only'] if s['host'] == 'erp.example.com'][0]
        self.assertEqual(erp['internal_sources'], 0)
        self.assertTrue(erp['suspect'])                                 # still no attack type
        self.assertEqual(d['internal'], [])

    def test_one_review_per_slot_and_the_message(self):
        self.app.cfg.data['notify']['enabled'] = True
        self.app.cfg.data['notify']['webhook_enabled'] = True
        self.app.cfg.data['notify']['webhook_url'] = 'https://hooks.example.com/x'
        self.app.cfg.data['notify']['language'] = 'en'
        self.app.cfg.data['notify']['base_url'] = 'https://waf.example.com'
        rid = review.run_due(self.app, self.now)
        self.assertIsNotNone(rid)
        self.assertIsNone(review.run_due(self.app, self.now + 60))      # the same slot
        slot = review._slot(self.now, 3)
        self.assertIsNotNone(review.run_due(self.app, slot + 3 * 3600 + 5))   # the next one
        self.assertEqual(len(review.listing(self.app.db)), 2)
        row = self.app.db.one("SELECT details FROM notifications WHERE event='report.review' ORDER BY id LIMIT 1")
        self.assertIsNotNone(row)
        d = json.loads(row['details'])
        m = notify.render(self.app.db, self.app.cfg, 'report.review', d)
        self.assertIn('WAF review', m.title)
        self.assertEqual(m.severity, 'warning')
        labels = [a for a, _ in m.facts]
        self.assertIn('Possibly blocked by mistake', labels)
        self.assertIn('Focus site sso.example.com', labels)
        self.assertTrue(m.link.endswith('/reviews/%d' % rid))
        self.assertNotIn('hunter2', notify.fmt_text(m))

    def test_off(self):
        self.app.cfg.data['review']['enabled'] = False
        self.assertIsNone(review.run_due(self.app, self.now))

    def test_purge(self):
        review.run(self.app, 'manual', self.now, notify=False)
        review.purge(self.app, self.now + 91 * 86400)
        self.assertEqual(review.listing(self.app.db), [])

    def test_preview_sample(self):
        p = notify.preview(self.app.cfg, 'report.review', 'zh-TW')
        self.assertIn('WAF 定期檢討', p['title'])


class TestReviewApi(unittest.TestCase):
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

    def test_run_list_get(self):
        v = Client(self.port)
        self.assertEqual(v.login('viewer1')[0], 200)
        st, _, _ = v.req('POST', '/api/v1/reviews/run', {})
        self.assertEqual(st, 403)                                       # approvers only
        self.app.db.x("UPDATE users SET totp_last_step=0 WHERE username='admin1'")
        c = Client(self.port)
        self.assertEqual(c.login('admin1', totp=auth.totp_code(self.secret, int(time.time() // 30)))[0], 200)
        st, obj, _ = c.req('POST', '/api/v1/reviews/run', {})
        self.assertEqual(st, 201, obj)
        rid = obj['id']
        self.assertEqual(obj['trigger'], 'manual')
        st, obj, _ = v.req('GET', '/api/v1/reviews')
        self.assertEqual(st, 200)
        self.assertEqual(obj['items'][0]['id'], rid)
        self.assertEqual(obj['interval_hours'], 3)
        st, obj, _ = v.req('GET', '/api/v1/reviews/%d' % rid)
        self.assertEqual((st, obj['id']), (200, rid))
        st, _, _ = v.req('GET', '/api/v1/reviews/99999')
        self.assertEqual(st, 404)
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='review.run'"))


if __name__ == '__main__':
    unittest.main()
