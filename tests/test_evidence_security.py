"""Evidence must judge exactly what the generated rule matches; regression samples must not be poisonable.
Synthetic data only (example.com, documentation addresses, 192.168.77.x)."""
import json
import os
import random
import unittest

from jtwafmgr import evidence, rulegen, util
from jtwafmgr.db import Database
from jtwafmgr.evidence import Evidence
from tests.helpers import TempEnv


def line(path, status=200, ip='198.51.100.20', host='app.example.com', ua='Mozilla/5.0', method='GET'):
    return json.dumps({'vhost': host, 'request': '%s %s HTTP/1.1' % (method, path), 'http_status': status,
                       'srcip': ip, 'user_agent': ua})


class Base(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.logdir = os.path.join(self.env.dir, 'logs')
        os.makedirs(self.logdir)
        self.env.cfg.data['evidence']['access_logs'] = [os.path.join(self.logdir, '*.access.log')]
        self.env.cfg.data['evidence']['catch_all_hosts'] = []
        self.db = Database(self.env.cfg['paths']['db'])
        self.ev = Evidence(self.env.cfg, self.db)

    def tearDown(self):
        self.env.cleanup()

    def logs(self, lines, name='app.example.com.access.log'):
        with open(os.path.join(self.logdir, name), 'a') as fh:
            fh.write('\n'.join(lines) + '\n')


class TestBlockEvidenceMatchesRule(Base):
    def test_dav_paths_are_not_skipped(self):
        # 50 Nextcloud sync requests that the rule (no exception) would block
        self.logs([line('/remote.php/dav/files/alice/report-%d.pdf' % i, ip='198.51.100.%d' % (i + 1),
                        host='cloud.example.com', ua='Mozilla/5.0 (Windows) mirall/3.10') for i in range(50)])
        r = self.ev.block_evidence({'target': 'path', 'regex': r'^/remote\.php/dav/files/'})
        self.assertFalse(r['ok'])
        self.assertEqual((r['external_hits'], r['external_success']), (50, 50))
        # with the exception in the rule itself, the same lines are exempt
        r = self.ev.block_evidence({'target': 'path', 'regex': r'^/remote\.php/dav/files/',
                                    'exceptions': [r'^/remote\.php/dav/']})
        self.assertTrue(r['ok'])
        self.assertEqual(r['external_hits'], 0)

    def test_plus_is_a_space_for_the_rule(self):
        self.logs([line('/tags/c++/page')])
        r = self.ev.block_evidence({'target': 'path', 'regex': r'/tags/c\s'})
        self.assertEqual((r['ok'], r['external_success']), (False, 1))
        r = self.ev.block_evidence({'target': 'uri', 'regex': r'/tags/c\s'})
        self.assertEqual((r['ok'], r['external_success']), (False, 1))

    def test_percent_u_and_double_decoding(self):
        # REQUEST_FILENAME is %XX-decoded once by libmodsecurity, then t:urlDecodeUni decodes again
        self.logs([line('/adm%u0069n/x'), line('/%2561dmin/y'), line('/%uff41dmin/z')])
        r = self.ev.block_evidence({'target': 'path', 'regex': r'^/admin/'})
        self.assertEqual((r['ok'], r['external_success']), (False, 3))

    def test_rx_is_multiline(self):
        # @rx is PCRE with DOTALL | MULTILINE: ^ matches after a decoded newline
        self.logs([line('/x%0a/admin/')])
        r = self.ev.block_evidence({'target': 'path', 'regex': r'^/admin/'})
        self.assertEqual((r['ok'], r['external_success']), (False, 1))

    def test_exceptions_use_the_rule_transformations(self):
        # the block matches the normalized path, the exception the decoded path without normalizePath:
        # //static/x.bak is blocked, not exempt
        self.logs([line('//static/x.bak'), line('/STATIC/y.bak', status=404)])
        r = self.ev.block_evidence({'target': 'path', 'regex': r'\.bak$', 'exceptions': [r'^/static/']})
        self.assertFalse(r['ok'])
        self.assertEqual((r['external_hits'], r['external_success']), (1, 1))

    def test_wildcard_host_scope(self):
        self.logs([line('/backup.zip', host='files.example.com'), line('/backup.zip', host='example.org')])
        r = self.ev.block_evidence({'target': 'path', 'regex': r'^/backup\.zip$',
                                    'host': {'mode': 'exact', 'value': '*.example.com'}})
        self.assertEqual((r['ok'], r['external_success'], [s['host'] for s in r['sites']]),
                         (False, 1, ['files.example.com']))

    def test_combined_log_escapes(self):
        # nginx's default escaping writes a raw newline byte as \x0A; the server saw the byte
        with open(os.path.join(self.logdir, 'app.example.com.access.log'), 'w') as fh:
            fh.write('198.51.100.30 - - [12/Nov/2026:10:00:00 +0800] "GET /a\\x0A/admin/ HTTP/1.1" 200 12 "-" "curl/8"\n')
        r = self.ev.block_evidence({'target': 'path', 'regex': r'^/admin/'})
        self.assertEqual((r['ok'], r['external_success']), (False, 1))

    def test_benign_lines_still_pass(self):
        self.logs([line('/index.html'), line('/tags/c/page'), line('/backup.zip', status=404, ip='203.0.113.9')])
        r = self.ev.block_evidence({'target': 'path', 'regex': r'^/backup\.zip$'})
        self.assertEqual((r['ok'], r['external_hits'], r['external_success']), (True, 1, 0))


class TestTransformations(unittest.TestCase):
    def test_url_decode_uni(self):
        f = evidence.url_decode_uni
        self.assertEqual(f(b'/c++/%41%u0042%uFF43%zz%4'), b'/c  /ABc%zz%4')
        self.assertEqual(f(b'%u12'), b'%u12')        # too short: %u kept
        self.assertEqual(evidence.uri_decode(b'/c++/%41%zz'), b'/c++/A%zz')

    def test_request_variables(self):
        self.assertEqual(evidence.request_filename(b'/a%3fb?c=1#f'), b'/a')
        self.assertEqual(evidence.request_uri(b'/a%20b?c=%31#frag'), b'/a b?c=1')
        self.assertEqual(evidence.request_uri(b'http://app.example.com/x?y'), b'/x?y')

    def test_normalize_path_vectors(self):
        for i, o in ((b'/foo/bar/baz', b'/foo/bar/baz'), (b'/foo/bar/./baz', b'/foo/bar/baz'), (b'/foo/../bar', b'/bar'),
                     (b'.', b''), (b'..', b'..'), (b'./', b''), (b'../', b'../'), (b'/foo/../../bar', b'/bar'),
                     (b'foo/../../bar', b'../bar'), (b'//static//x', b'/static/x'), (b'/a/b/../', b'/a/'), (b'', b'')):
            self.assertEqual(evidence.normalize_path(i), o, i)

    def test_normalize_fast_path_agrees(self):
        rnd = random.Random(7)
        for _ in range(5000):
            s = bytes(rnd.choice(b'/.ab') for _ in range(rnd.randint(1, 12)))
            self.assertEqual(evidence.normalize_path(s), evidence._normalize_path_inplace(s), s)

    def test_lowercase_ascii_only(self):
        self.assertEqual(evidence.transform('/ÀB'.encode('latin-1'), 't:none,t:lowercase'), '/Àb'.encode('latin-1'))

    def test_unknown_transformation_is_an_error(self):
        with self.assertRaises(ValueError):
            evidence.transform(b'x', 't:none,t:compressWhitespace')

    def test_generated_rule_uses_modelled_transformations(self):
        # every target's chain is modelled, and the exception condition is what evidence assumes
        for target, (_var, tr) in rulegen.BLOCK_TARGETS.items():
            evidence.transform(b'/x', tr)
        env = TempEnv()
        try:
            _, text, _ = rulegen.build('confident_block', {'target': 'path', 'regex': r'\.bak$', 'msg': 'backup',
                                                           'exceptions': [r'^/static/']}, 10500, env.cfg)
        finally:
            env.cleanup()
        self.assertIn('t:none,t:urlDecodeUni,t:normalizePath,t:lowercase', text)
        exc = text.split('SecRule REQUEST_FILENAME "!@rx', 1)[1].split('\n', 2)[1]
        self.assertIn('"%s' % evidence.EXCEPTION_TRANSFORMS, exc)


class TestRegressionSamples(Base):
    def samples(self):
        return sorted((r['host'], r['path']) for r in self.db.q('SELECT host, path FROM regression_samples'))

    def event(self, host, path, outcome='blocked', rule_ids=',930130,'):
        self.db.x('INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, outcome, rule_ids, '
                  "local_rule_ids, families, message, matches) VALUES ('n1', ?, ?, ?, 'GET', ?, '', '203.0.113.5', "
                  "'external', ?, ?, ',,', ',,', '', '[]')",
                  ('%s-%s-%s' % (host, path, outcome), util.now(), host, path, outcome, rule_ids))

    def test_one_source_hammering_is_not_a_sample(self):
        self.logs([line('/.env', ip='203.0.113.66') for _ in range(500)]
                  + [line('/', ip='198.51.100.%d' % i) for i in range(1, 4)])
        self.ev.collect_samples()
        self.assertEqual(self.samples(), [('app.example.com', '/')])

    def test_catch_all_host_gives_no_samples(self):
        self.env.cfg.data['evidence']['catch_all_hosts'] = ['parked.example.com']
        self.logs([line('/.env', ip='203.0.113.%d' % i, host='parked.example.com') for i in range(1, 30)])
        self.ev.collect_samples()
        self.assertEqual(self.samples(), [])

    def test_paths_with_waf_events_excluded(self):
        self.logs([line('/.env', ip='203.0.113.%d' % i) for i in range(1, 30)]
                  + [line('/.git/config', ip='203.0.113.%d' % i) for i in range(1, 30)]
                  + [line('/shop', ip='203.0.113.%d' % i) for i in range(1, 5)])
        self.event('app.example.com', '/.env')
        self.event('app.example.com', '/.GIT/%63onfig', outcome='passed', rule_ids=',930130,949110,')  # logged hit only
        self.event('app.example.com', '/shop', outcome='passed', rule_ids=',,')                        # no rule hit
        self.ev.collect_samples()
        self.assertEqual(self.samples(), [('app.example.com', '/shop')])

    def test_internal_sources_preferred_and_scanners_ignored(self):
        self.env.cfg.data['network']['known_scanners'] = ['192.168.77.250/32']
        self.env.cfg.known_scanners = util_networks(['192.168.77.250/32'])
        self.logs([line('/portal', ip='192.168.77.%d' % i) for i in range(1, 4)]
                  + [line('/promo', ip='203.0.113.%d' % i) for i in range(1, 40)]            # external only
                  + [line('/.env', ip='192.168.77.250') for _ in range(50)]                   # the scanner
                  + [line('/.env', ip='203.0.113.%d' % i) for i in range(1, 3)]
                  + [line('/about', ip='198.51.100.%d' % i, host='blog.example.com') for i in range(1, 4)])
        self.ev.collect_samples()
        # app has internal users: only what they use; blog has none: distinct external sources suffice
        self.assertEqual(self.samples(), [('app.example.com', '/portal'), ('blog.example.com', '/about')])


def util_networks(nets):
    import ipaddress
    return [ipaddress.ip_network(n) for n in nets]


if __name__ == '__main__':
    unittest.main()
