"""Request counts from the nginx access logs (traffic.py): parsing, rotation, the site cap, alerts, the report and
the API. Synthetic data only."""
import json
import os
import time
import unittest

from jtwafmgr import traffic, alerts, uisettings
from jtwafmgr.app import App
from tests.helpers import TempEnv, wr

T0 = 1794528000          # a whole hour (2026-11-13 00:00 UTC)


def jline(ts, status=200, vhost='www.example.com', ip='203.0.113.5', nbytes=100):
    return json.dumps({'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(ts)), 'vhost': vhost,
                       'remote_addr': ip, 'http_status': status, 'bytes_sent': nbytes, 'request': 'GET / HTTP/1.1'})


def cline(ts, status=200, ip='198.51.100.7', nbytes=50):
    t = time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime(ts))
    return '%s - - [%s] "GET /x HTTP/1.1" %d %d "-" "test"' % (ip, t, status, nbytes)


class ParseTest(unittest.TestCase):
    def test_times(self):
        self.assertEqual(traffic.parse_time('2026-11-13T08:00:00+08:00'), T0)
        self.assertEqual(traffic.parse_time('13/Nov/2026:08:00:00 +0800'), T0)
        self.assertEqual(traffic.parse_time('13/Nov/2026:00:00:00 +0000'), T0)
        for bad in ('', 'yesterday', '99/Foo/2026:00:00:00 +0000', '2026-13-45T00:00:00'):
            self.assertIsNone(traffic.parse_time(bad))

    def test_site_from_file_name(self):
        self.assertEqual(traffic.site_of('/var/log/nginx/shop.example.com.access.log'), 'shop.example.com')
        self.assertIsNone(traffic.site_of('/var/log/nginx/access.log'))

    def test_json_and_combined(self):
        r = traffic.parse_line(jline(T0 + 5, 404, nbytes=7), None)
        self.assertEqual(r, (T0 + 5, 'www.example.com', 404, 7, '203.0.113.5'))
        # a per-site file: the file name wins over the (client-controlled) vhost field
        self.assertEqual(traffic.parse_line(jline(T0, vhost='evil.example.net'), 'shop.example.com')[1], 'shop.example.com')
        r = traffic.parse_line(cline(T0 + 9, 444, nbytes=0), None)
        self.assertEqual(r, (T0 + 9, '(default)', 444, 0, '198.51.100.7'))
        # a vhost that is not a host name is not a site
        self.assertEqual(traffic.parse_line(jline(T0, vhost='<script>'), None)[1], '(default)')
        for bad in ('', 'garbage', '{"not": "a log"}', '[1,2]', '{broken'):
            self.assertIsNone(traffic.parse_line(bad, None))


class PollTest(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.logs = os.path.join(self.env.dir, 'nginx')
        os.makedirs(self.logs)
        self.env.cfg.data['traffic']['logs'] = [os.path.join(self.logs, '*access.log')]
        self.app = App(self.env.cfg)
        self.addCleanup(self.app.stop)
        self.site = os.path.join(self.logs, 'shop.example.com.access.log')

    def rows(self):
        return {(r['hour'], r['host']): dict(r) for r in self.app.db.q('SELECT * FROM traffic_hourly')}

    def test_counts_rotation_and_truncation(self):
        wr(self.site, '\n'.join([jline(T0 + 1), jline(T0 + 2, 404), jline(T0 + 3600, 503, ip='192.168.77.9')]) + '\n')
        wr(os.path.join(self.logs, 'access.log'), cline(T0 + 10) + '\n' + cline(T0 + 11, 429) + '\n')
        self.assertEqual(traffic.poll(self.app), 5)
        r = self.rows()
        a = r[(T0, 'shop.example.com')]
        self.assertEqual((a['total'], a['s2xx'], a['s4xx'], a['external'], a['bytes']), (2, 1, 1, 2, 200))
        b = r[(T0 + 3600, 'shop.example.com')]
        self.assertEqual((b['total'], b['s5xx'], b['external']), (1, 1, 0))       # internal address
        d = r[(T0, '(default)')]
        self.assertEqual((d['total'], d['s429']), (2, 1))
        # nothing new: nothing counted twice
        self.assertEqual(traffic.poll(self.app), 0)
        # a half-written line waits for its newline
        wr(self.site, jline(T0 + 4)[:20], 'a')
        self.assertEqual(traffic.poll(self.app), 0)
        wr(self.site, jline(T0 + 4)[20:] + '\n', 'a')
        self.assertEqual(traffic.poll(self.app), 1)
        # logrotate renames: the rest of the old file (now .1) is finished, the new file read from its start
        wr(self.site, jline(T0 + 5) + '\n', 'a')
        os.rename(self.site, self.site + '.1')
        wr(self.site, jline(T0 + 6) + '\n')
        self.assertEqual(traffic.poll(self.app), 2)
        self.assertEqual(self.rows()[(T0, 'shop.example.com')]['total'], 5)
        # copytruncate: the file shrinks, read again from 0
        wr(self.site, jline(T0 + 7) + '\n')
        self.assertEqual(traffic.poll(self.app), 1)
        self.assertEqual(self.rows()[(T0, 'shop.example.com')]['total'], 6)

    def test_off_reads_nothing(self):
        wr(self.site, jline(T0) + '\n')
        self.env.cfg.data['traffic']['enabled'] = False
        self.assertEqual(traffic.poll(self.app), 0)
        self.assertEqual(self.rows(), {})

    def test_forged_hosts_are_capped(self):
        shared = os.path.join(self.logs, 'access.log')
        wr(shared, '\n'.join(jline(T0, vhost='h%d.example.com' % i) for i in range(traffic.MAX_HOSTS + 50)) + '\n')
        traffic.poll(self.app)
        hosts = {h for _, h in self.rows()}
        self.assertEqual(len(hosts), traffic.MAX_HOSTS + 1)
        self.assertEqual(self.rows()[(T0, '(other)')]['total'], 50)

    def test_purge(self):
        self.app.db.x('INSERT INTO traffic_hourly(hour, host, total) VALUES (?,?,?)', (T0 - 500 * 86400, 'old.example.com', 1))
        self.app.db.x('INSERT INTO traffic_hourly(hour, host, total) VALUES (?,?,?)', (T0, 'new.example.com', 1))
        self.assertEqual(traffic.purge(self.app, now=T0), 1)
        self.assertEqual(list(self.rows()), [(T0, 'new.example.com')])

    def _hour(self, hour, host, total, s5xx=0):
        self.app.db.x('INSERT INTO traffic_hourly(hour, host, total, s5xx) VALUES (?,?,?,?)', (hour, host, total, s5xx))

    def test_alerts(self):
        tr = self.env.cfg.data['traffic']
        tr.update(alert=True, spike_factor=5, min_requests=1000, error_percent=20)
        hour = T0 + 7 * 86400
        for h in range(T0, hour, 3600):
            self._hour(h, 'shop.example.com', 100)
            self._hour(h, 'api.example.com', 100)
        self._hour(hour, 'shop.example.com', 2000)                 # 20 times the usual hour
        self._hour(hour, 'api.example.com', 400, s5xx=120)          # 30 % answered 5xx
        self._hour(hour, 'new.example.com', 5000)                   # no history: not a spike
        now = hour + 3600 + 400
        got = traffic.check_alerts(self.app, now=now)
        self.assertEqual(sorted(got), [('traffic_errors', 'api.example.com'), ('traffic_spike', 'shop.example.com')])
        self.assertEqual(traffic.check_alerts(self.app, now=now), [])           # once per hour
        rows = alerts.listing(self.app.db, 'open')
        kinds = sorted(r['kind'] for r in (rows['items'] if isinstance(rows, dict) else rows))
        self.assertEqual(kinds, ['traffic_errors', 'traffic_spike'])
        tr['alert'] = False
        self.app.db.set_meta(traffic.ALERT_KEY, 0)
        self.assertEqual(traffic.check_alerts(self.app, now=now), [])

    def test_report_with_waf_numbers(self):
        now = T0 + 20 * 3600
        self._hour(T0 + 10 * 3600, 'shop.example.com', 1000)
        self._hour(T0 + 11 * 3600, 'shop.example.com', 500)
        self._hour(T0 + 11 * 3600, 'api.example.com', 50)
        for i, oc in enumerate(('blocked', 'blocked', 'logged')):
            self.app.db.x("INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, outcome, "
                          "rule_ids, local_rule_ids, families, message, matches) VALUES ('n', ?, ?, 'shop.example.com', 'GET', "
                          "'/', '', '203.0.113.9', 'external', ?, '', '', '', '', '[]')", ('u%d' % i, T0 + 10 * 3600 + i, oc))
        rep = traffic.report(self.app, now - 86400, now)
        self.assertEqual(rep['totals']['total'], 1550)
        self.assertEqual(rep['totals']['blocked'], 2)
        self.assertEqual(rep['bucket_seconds'], 3600)
        self.assertEqual(len(rep['series']), 24)
        shop = next(h for h in rep['by_host'] if h['host'] == 'shop.example.com')
        self.assertEqual((shop['total'], shop['blocked'], shop['logged']), (1500, 2, 1))
        self.assertEqual(rep['by_host'][0]['host'], 'shop.example.com')
        one = traffic.report(self.app, now - 86400, now, host='api.example.com')
        self.assertEqual((one['totals']['total'], one['totals']['blocked']), (50, 0))
        month = traffic.report(self.app, now - 30 * 86400, now)
        self.assertEqual(month['bucket_seconds'], 86400)

    def test_settings(self):
        ch = uisettings.set_many(self.app, {'traffic.enabled': False, 'traffic.alert': True, 'traffic.spike_factor': 8,
                                            'traffic.logs': ['/var/log/nginx/*.access.log']}, 'tester')
        self.assertEqual(set(ch), {'traffic.enabled', 'traffic.alert', 'traffic.spike_factor', 'traffic.logs'})
        for bad in ({'traffic.spike_factor': 1}, {'traffic.logs': ['relative/path.log']}, {'traffic.keep_days': 0},
                    {'traffic.error_percent': 101}):
            with self.assertRaises(uisettings.SettingError):
                uisettings.set_many(self.app, bad, 'tester')


if __name__ == '__main__':
    unittest.main()
