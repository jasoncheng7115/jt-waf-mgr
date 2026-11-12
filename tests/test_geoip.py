import base64
import hashlib
import io
import json
import os
import tarfile
import unittest

from jtwafmgr import geoip
from tests import mmdb_writer
import time

from jtwafmgr import auth
from jtwafmgr.app import App
from jtwafmgr.collector.auditlog import Tailer
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv, record
from tests.test_api import Client, PW

CITY = {
    '203.0.113.0/24': {'country': {'iso_code': 'JP', 'names': {'en': 'Japan', 'ja': '日本'}},
                       'city': {'names': {'en': 'Tokyo'}}},
    '198.51.100.0/25': {'country': {'iso_code': 'DE', 'names': {'en': 'Germany'}}},
    '2001:db8:1::/48': {'country': {'iso_code': 'FR', 'names': {'en': 'France'}}},
}
ASN = {'203.0.113.0/24': {'autonomous_system_number': 64500, 'autonomous_system_organization': 'Example Net'}}


class TestReader(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.path = os.path.join(self.env.dir, 'c.mmdb')
        mmdb_writer.write(self.path, CITY)

    def tearDown(self):
        self.env.cleanup()

    def test_lookups(self):
        db = geoip.MMDB(self.path)
        self.assertEqual(db.database_type, 'GeoLite2-City')
        self.assertEqual(db.lookup('203.0.113.77')['country']['iso_code'], 'JP')
        self.assertEqual(db.lookup('203.0.113.77')['city']['names']['en'], 'Tokyo')
        self.assertEqual(db.lookup('198.51.100.5')['country']['iso_code'], 'DE')
        self.assertIsNone(db.lookup('198.51.100.200'))          # outside the /25
        self.assertEqual(db.lookup('2001:db8:1:2::9')['country']['iso_code'], 'FR')
        self.assertIsNone(db.lookup('192.0.2.1'))
        db.close()

    def test_rejects_garbage(self):
        bad = os.path.join(self.env.dir, 'bad.mmdb')
        with open(bad, 'wb') as fh:
            fh.write(os.urandom(4096))
        with self.assertRaises(geoip.MMDBError):
            geoip.MMDB(bad)


class TestService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv()
        d = cls.env.cfg['geoip']['dir']
        os.makedirs(d)
        mmdb_writer.write(os.path.join(d, 'GeoLite2-City.mmdb'), CITY)
        mmdb_writer.write(os.path.join(d, 'GeoLite2-ASN.mmdb'), ASN, database_type='GeoLite2-ASN')
        cls.env.write_log([record(ip='203.0.113.9', status=403, engine='Enabled', rules=[942100, 949110])])
        cls.app = App(cls.env.cfg)
        cls.app.tailer = Tailer(cls.env.cfg, cls.app.db)
        cls.app.tailer.poll()
        a = cls.app.auth
        a.create_user('viewer1', 'viewer', password=PW)
        a.create_user('approver1', 'approver', password=PW)
        a.create_user('admin1', 'admin', password=PW)
        cls.secret, _ = a.totp_setup('admin1')
        a.totp_enable('admin1', auth.totp_code(cls.secret, int(time.time() // 30)))
        cls.asecret, _ = a.totp_setup('approver1')
        a.totp_enable('approver1', auth.totp_code(cls.asecret, int(time.time() // 30)))
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.env.cleanup()

    def client(self, user, secret=None):
        self.app.db.x('UPDATE users SET totp_last_step=0')
        c = Client(self.port)
        st, obj = c.login(user, totp=auth.totp_code(secret, int(time.time() // 30)) if secret else None)
        self.assertEqual(st, 200, obj)
        return c

    def test_lookup_merges_city_and_asn(self):
        g = self.app.geoip.lookup('203.0.113.9')
        self.assertEqual((g['scope'], g['cc'], g['country'], g['city'], g['asn'], g['org']),
                         ('external', 'JP', 'Japan', 'Tokyo', 64500, 'Example Net'))

    def test_internal_never_looked_up(self):
        for ip in ('10.0.0.50', '192.168.77.50', '127.0.0.1', '::1', 'fe80::1'):
            self.assertEqual(self.app.geoip.lookup(ip), {'scope': 'internal'})

    def test_events_carry_geo(self):
        c = self.client('viewer1')
        st, body, _ = c.req('GET', '/api/v1/events')
        self.assertEqual(st, 200)
        self.assertEqual(body['items'][0]['src_geo']['cc'], 'JP')
        st, body, _ = c.req('GET', '/api/v1/overview?range=7d')
        self.assertEqual(body['by_country'][0]['key'], 'JP')
        self.assertEqual(body['by_asn'][0]['label'], 'Example Net')
        st, body, _ = c.req('GET', '/api/v1/lookups/ip/203.0.113.9')
        self.assertEqual(body['geo']['org'], 'Example Net')

    def test_overview_filters(self):
        c = self.client('viewer1')
        st, all_, _ = c.req('GET', '/api/v1/overview?range=7d')
        st, ext, _ = c.req('GET', '/api/v1/overview?range=7d&origin=external&src_ip=203.0.113.9')
        self.assertEqual(st, 200)
        self.assertEqual(ext['filters'], {'origin': 'external', 'src_ip': '203.0.113.9'})
        self.assertEqual(ext['totals']['events'], all_['totals']['events'])
        st, none, _ = c.req('GET', '/api/v1/overview?range=7d&origin=internal')
        self.assertEqual((none['totals']['events'], none['by_rule'], none['by_country']), (0, [], []))
        st, _, _ = c.req('GET', '/api/v1/overview?range=7d&origin=sideways')
        self.assertEqual(st, 400)

    def test_status_and_request(self):
        c = self.client('admin1', self.secret)
        st, body, _ = c.req('GET', '/api/v1/geoip')
        self.assertEqual(st, 200)
        self.assertEqual([e['present'] for e in body['editions']], [True, True])
        self.assertFalse(body['configured'])
        st, body, _ = c.req('POST', '/api/v1/geoip/update')
        self.assertEqual(st, 202)
        self.assertTrue(os.path.exists(os.path.join(self.env.cfg['geoip']['dir'], geoip.REQUEST_FILE)))
        self.assertTrue(self.app.db.q("SELECT 1 FROM audit WHERE action='geoip.update_requested'"))
        c = self.client('approver1', self.asecret)
        self.assertEqual(c.req('POST', '/api/v1/geoip/update')[0], 403)


class TestUpdater(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.cfg = self.env.cfg
        g = self.cfg['geoip']
        g['account_id'] = '12345'
        g['editions'] = ['GeoLite2-City']
        os.makedirs(self.cfg['geoip']['dir'], exist_ok=True)
        with open(g['license_key_file'], 'w') as fh:
            fh.write('secret-key\n')
        src = os.path.join(self.env.dir, 'src.mmdb')
        mmdb_writer.write(src, CITY)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tf:
            tf.add(src, arcname='GeoLite2-City_20261110/GeoLite2-City.mmdb')
        self.archive = buf.getvalue()
        self.calls = []

    def tearDown(self):
        self.env.cleanup()

    def fetch(self, sha=None, archive=None):
        def f(url, auth, limit):
            self.calls.append((url, auth))
            if url.endswith('sha256'):
                return ((sha or hashlib.sha256(archive or self.archive).hexdigest()) + '  x.tar.gz\n').encode()
            return archive or self.archive
        return f

    def test_update_installs_verified_file(self):
        st = geoip.update(self.cfg, fetch=self.fetch(), log=lambda *_: None)
        self.assertTrue(st['ok'], st)
        self.assertTrue(os.path.exists(os.path.join(self.cfg['geoip']['dir'], 'GeoLite2-City.mmdb')))
        self.assertEqual(base64.b64decode(self.calls[0][1]).decode(), '12345:secret-key')
        st = geoip.update(self.cfg, fetch=self.fetch(), log=lambda *_: None)          # fresh: no download
        self.assertEqual(st['editions']['GeoLite2-City'].get('skipped'), 'fresh')

    def test_checksum_mismatch_keeps_old_file(self):
        st = geoip.update(self.cfg, fetch=self.fetch(sha='0' * 64), log=lambda *_: None)
        self.assertFalse(st['ok'])
        self.assertIn('SHA-256', st['editions']['GeoLite2-City']['error'])
        self.assertFalse(os.path.exists(os.path.join(self.cfg['geoip']['dir'], 'GeoLite2-City.mmdb')))

    def test_wrong_database_type_rejected(self):
        src = os.path.join(self.env.dir, 'asn.mmdb')
        mmdb_writer.write(src, ASN, database_type='GeoLite2-ASN')
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tf:
            tf.add(src, arcname='x/GeoLite2-City.mmdb')
        st = geoip.update(self.cfg, fetch=self.fetch(archive=buf.getvalue()), log=lambda *_: None)
        self.assertFalse(st['ok'])
        self.assertIn('unexpected database type', st['editions']['GeoLite2-City']['error'])

    def test_not_configured(self):
        self.cfg['geoip']['account_id'] = ''
        st = geoip.update(self.cfg, fetch=self.fetch(), log=lambda *_: None)
        self.assertIsNone(st['ok'])
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
