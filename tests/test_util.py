import ipaddress
import time
import unittest

from jtwafmgr import config, util


class TestAddresses(unittest.TestCase):
    def setUp(self):
        self.nets = config.load().internal_networks

    def test_private_edges(self):
        # a string prefix "172.2" once matched public 172.200-255 (LESSONS 18)
        self.assertTrue(util.ip_in('172.16.0.1', self.nets))
        self.assertTrue(util.ip_in('172.31.255.254', self.nets))
        self.assertFalse(util.ip_in('172.32.0.1', self.nets))
        self.assertFalse(util.ip_in('172.200.1.1', self.nets))
        self.assertFalse(util.ip_in('192.169.0.1', self.nets))
        self.assertTrue(util.ip_in('10.255.255.255', self.nets))
        self.assertFalse(util.ip_in('11.0.0.1', self.nets))

    def test_v6_and_mapped(self):
        self.assertTrue(util.ip_in('::1', self.nets))
        self.assertTrue(util.ip_in('fd00::1', self.nets))
        self.assertFalse(util.ip_in('2001:db8::1', self.nets))
        self.assertTrue(util.ip_in('::ffff:192.168.77.5', self.nets))
        self.assertFalse(util.ip_in('::ffff:203.0.113.5', self.nets))

    def test_garbage(self):
        self.assertFalse(util.ip_in('', self.nets))
        self.assertFalse(util.ip_in('not-an-ip', self.nets))
        self.assertFalse(util.ip_in('203.0.113.7, 10.0.0.1', self.nets))


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self.r = util.Redactor(config.load().sensitive)

    def test_names(self):
        for n in ('password', 'Password', 'user_password', 'json.user.password', 'data[pwd]', 'X-Auth-Token',
                  'client_secret', 'otp', 'refresh_token', 'Authorization', 'passwd'):
            self.assertTrue(self.r.is_sensitive(n), n)
        for n in ('q', 'search', 'redirect_uri', 'username', 'page', 'compass', 'bypass_cache'):
            self.assertFalse(self.r.is_sensitive(n), n)

    def test_query(self):
        self.assertEqual(self.r.query('user=a&password=hunter2&x=1'), 'user=a&password=***&x=1')
        self.assertEqual(self.r.query('access_token=abc'), 'access_token=***')
        self.assertEqual(self.r.query('pass%77ord=abc'), 'pass%77ord=***')  # percent-encoded name
        self.assertEqual(self.r.query('q=1'), 'q=1')
        self.assertEqual(self.r.query(''), '')

    def test_free_text(self):
        self.assertNotIn('hunter2', self.r.text('login=bob&password=hunter2'))
        self.assertNotIn('hunter2', self.r.text('{"login": "bob", "password": "hunter2"}'))
        self.assertNotIn('xyz', self.r.text('Authorization: Basic xyz'))
        self.assertEqual(self.r.text('Matched Data: ../ found within ARGS:file: ../etc'),
                         'Matched Data: ../ found within ARGS:file: ../etc')

    def test_references(self):
        self.assertEqual(self.r.references_sensitive("found within ARGS:password: x"), 'ARGS:password')
        self.assertEqual(self.r.references_sensitive("against variable `ARGS_POST:client_secret'"), 'ARGS_POST:client_secret')
        self.assertIsNone(self.r.references_sensitive('found within ARGS:file: ../etc'))
        self.assertTrue(self.r.references_sensitive('JSON.params.password'))


class TestFamilies(unittest.TestCase):
    def test_map(self):
        lr = (10000, 19999)
        self.assertEqual(util.family_of(930120, lr), 'lfi')
        self.assertEqual(util.family_of(942100, lr), 'sqli')
        self.assertEqual(util.family_of(932235, lr), 'rce')
        self.assertEqual(util.family_of(920170, lr), 'protocol')
        self.assertEqual(util.family_of(200002, lr), 'body')
        self.assertEqual(util.family_of(10203, lr), 'local')
        self.assertIsNone(util.family_of(949110, lr))
        self.assertIsNone(util.family_of(980170, lr))
        self.assertEqual(util.family_of(123, lr), 'other')


class TestTime(unittest.TestCase):
    def test_modsec_time_roundtrip(self):
        from tests.helpers import _c_time
        t = int(time.time())
        self.assertEqual(util.parse_modsec_time(_c_time(t)), t)

    def test_with_zone(self):
        import zoneinfo
        tz = zoneinfo.ZoneInfo('Asia/Taipei')
        self.assertEqual(util.parse_modsec_time('Mon Nov 10 08:00:00 2026', tz),
                         util.parse_iso('2026-11-10T00:00:00Z'))

    def test_bad(self):
        for s in ('', 'yesterday', 'Mon Foo 10 08:00:00 2026'):
            with self.assertRaises((ValueError, KeyError)):
                util.parse_modsec_time(s)

    def test_iso(self):
        self.assertEqual(util.parse_iso(util.iso(1700000000)), 1700000000)
        self.assertIsNone(util.iso(None))


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        c = config.load()
        self.assertEqual(c.listen, ('127.0.0.1', 8095))
        self.assertIn(ipaddress.ip_network('10.0.0.0/8'), c.internal_networks)

    def test_unknown_key(self):
        with self.assertRaises(config.ConfigError):
            config.load(None, {'server': {'lisen': 'x'}})

    def test_bad_network(self):
        with self.assertRaises(config.ConfigError):
            config.load(None, {'network': {'internal': ['10.0.0.0/33']}})

    def test_bad_type(self):
        with self.assertRaises(config.ConfigError):
            config.load(None, {'auth': {'password_min_length': '12'}})

    def test_min_password(self):
        with self.assertRaises(config.ConfigError):
            config.load(None, {'auth': {'password_min_length': 4}})


if __name__ == '__main__':
    unittest.main()
