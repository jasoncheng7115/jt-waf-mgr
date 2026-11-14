"""An event answered with a redirect although a refusing rule matched (the site redirects every path before the WAF can
step in): labelled "redirected", and the outcome filter picks exactly those. Synthetic data only."""
import json
import time
import unittest

from jtwafmgr.app import App
from jtwafmgr.web import api
from tests.helpers import TempEnv


class TestRedirected(unittest.TestCase):
    def test_label_and_filter(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        app = App(env.cfg)
        self.addCleanup(app.stop)
        lo = env.cfg['waf']['confident_range'][0]
        now = time.time()
        rows = [('r1', 301, 'logged', [lo + 5, 930130]),       # redirected, a confident block matched
                ('r2', 301, 'logged', [930130]),                # a plain redirect: no refusing rule
                ('r3', 403, 'blocked', [lo + 5, 949110]),       # refused
                ('r4', 200, 'logged', [lo + 5])]                # answered 200: not a redirect
        for uid, st, outcome, ids in rows:
            cur = app.db.x("INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, status, outcome, "
                           "rule_ids, local_rule_ids, families, message, matches) VALUES ('n', ?, ?, 'a.example.com', 'GET', "
                           "'/.env', '', '203.0.113.9', 'external', ?, ?, ?, '', '', '', '[]')",
                           (uid, now, st, outcome, ',' + ','.join(map(str, ids)) + ','))
            for i in ids:
                app.db.x('INSERT INTO event_rules(event_id, rule_id, ts, outcome) VALUES (?, ?, ?, ?)', (cur.lastrowid, i, now, outcome))

        class Req:
            def __init__(self, q):
                self.query, self.params, self.app, self.user = q, {}, app, {'username': 'v', 'role': 'viewer'}

        def items(q):
            return {x['id']: x for x in json.loads(api.events(app, Req(q)).body)['items']}
        every = items({})
        got = {x['path'] + str(x['status']): x['redirected'] for x in every.values()}
        self.assertEqual(sorted(x['redirected'] for x in every.values()), [False, False, False, True])
        self.assertEqual(sum(1 for x in every.values() if x['redirected'] and x['status'] == 301), 1)
        only = items({'outcome': 'redirected'})
        self.assertEqual([x['status'] for x in only.values()], [301])
        self.assertEqual(len(items({'outcome': 'logged'})), 3)
        self.assertTrue(got)


if __name__ == '__main__':
    unittest.main()
