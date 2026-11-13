"""CRS updates, step 1 (check, download, verify, stage): a local release server and a test signing key made here.
No network, synthetic data only."""
import http.server
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest

from jtwafmgr import crsupdate, uisettings
from jtwafmgr.app import App
from tests.helpers import FIXTURE_SITE, TempEnv


def gpg(home, *args, inp=None):
    return subprocess.run(['gpg', '--homedir', home, '--batch', '--no-tty', '--quiet', '--pinentry-mode', 'loopback',
                           '--passphrase', ''] + list(args), input=inp, capture_output=True, check=True)


def make_key(home):
    os.makedirs(home, mode=0o700, exist_ok=True)
    gpg(home, '--quick-gen-key', 'CRS test <crs-test@example.com>', 'ed25519', 'sign', 'never')
    out = gpg(home, '--with-colons', '--list-keys').stdout.decode()
    fpr = next(l.split(':')[9] for l in out.splitlines() if l.startswith('fpr'))
    pub = os.path.join(home, 'pub.asc')
    with open(pub, 'wb') as fh:
        fh.write(gpg(home, '--armor', '--export', fpr).stdout)
    return fpr, pub


def tarball(version, evil=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        def add(name, data):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        top = 'coreruleset-%s' % version
        add(top + '/crs-setup.conf.example', b'# example\n')
        add(top + '/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf',
            ("SecRule ARGS \"@rx x\" \"id:930110,phase:2,block,msg:'x',ver:'OWASP_CRS/%s'\"\n" % version).encode())
        if evil:
            ti = tarfile.TarInfo(top + '/rules/evil.conf')
            ti.type = tarfile.SYMTYPE
            ti.linkname = '/etc/shadow'
            tf.addfile(ti)
    return buf.getvalue()


class _Srv(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.files.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class TestCrsUpdate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='jtwaf-crs-')
        cls.fpr, cls.pub = make_key(os.path.join(cls.tmp, 'gpg'))
        cls.other_fpr, _ = make_key(os.path.join(cls.tmp, 'gpg2'))
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Srv)
        cls.srv.files = {}
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = 'http://127.0.0.1:%d' % cls.srv.server_address[1]
        crsupdate.ALLOW_HTTP = True

    @classmethod
    def tearDownClass(cls):
        crsupdate.ALLOW_HTTP = False
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        site = os.path.join(self.env.dir, 'site')
        shutil.copytree(FIXTURE_SITE, site, symlinks=True)
        self.env.cfg.data['paths']['nginx_conf'] = os.path.join(site, 'nginx.conf')
        self.env.cfg.data['crs']['dir'] = os.path.join(self.env.dir, 'crs')
        self.app = App(self.env.cfg)

    def release(self, version, age_days, signer='gpg', evil=False):
        name = 'coreruleset-%s-minimal.tar.gz' % version
        tb = tarball(version, evil)
        sig = gpg(os.path.join(self.tmp, signer), '--armor', '--detach-sign', inp=tb).stdout
        self.srv.files['/dl/' + name] = tb
        self.srv.files['/dl/' + name + '.asc'] = sig
        pub = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - age_days * 86400))
        self.srv.files['/releases'] = json.dumps([{'tag_name': 'v' + version, 'published_at': pub, 'draft': False,
                                                   'prerelease': False, 'assets': [
                                                       {'name': name, 'browser_download_url': self.base + '/dl/' + name},
                                                       {'name': name + '.asc', 'browser_download_url': self.base + '/dl/' + name + '.asc'}]}]).encode()

    def check(self, **kw):
        return crsupdate.run(self.app, api=self.base + '/releases', keyfile=self.pub, fpr=self.fpr, log=lambda m: None, **kw)

    def manage(self, on=True, wait=7):
        uisettings.set_many(self.app, {'crs.manage': on, 'crs.wait_days': wait}, 'admin1')

    def test_off_by_default_does_nothing(self):
        self.release('4.30.1', 10)
        st = self.check()
        self.assertEqual(st['state'], 'off')
        self.assertFalse(os.path.exists(os.path.join(self.env.cfg['crs']['dir'], 'stage')))

    def test_a_signed_release_that_waited_is_staged(self):
        self.manage()
        self.release('4.30.1', 10)
        st = self.check()
        self.assertEqual((st['state'], st['installed'], st['staged']['version']), ('ready', '4.30.0', '4.30.1'), st)
        path = st['staged']['path']
        self.assertEqual(crsupdate.installed_version(path), (4, 30, 1))
        self.assertTrue(os.path.isfile(os.path.join(path, 'crs-setup.conf.example')))
        self.assertEqual(crsupdate.read_status(self.env.cfg)['staged']['version'], '4.30.1')
        al = self.app.db.one("SELECT kind, link FROM alerts WHERE kind='crs_update'")
        self.assertEqual((al['kind'], al['link']), ('crs_update', '/crs'))
        self.assertIsNotNone(self.app.db.one("SELECT id FROM audit WHERE action='crs.staged'"))
        # a second check: kept, not downloaded again
        self.srv.files.pop('/dl/coreruleset-4.30.1-minimal.tar.gz')
        self.assertEqual(self.check()['staged']['version'], '4.30.1')

    def test_a_new_release_waits(self):
        self.manage(wait=7)
        self.release('4.30.1', 2)
        st = self.check()
        self.assertEqual((st['state'], st['candidate']['version']), ('waiting', '4.30.1'))
        self.assertNotIn('staged', st)

    def test_a_signature_by_another_key_is_refused(self):
        self.manage()
        self.release('4.30.1', 10, signer='gpg2')
        st = self.check()
        self.assertEqual(st['state'], 'error')
        self.assertIn('signature', st['error'])
        self.assertIsNotNone(self.app.db.one("SELECT id FROM audit WHERE action='crs.signature_bad' AND result='failed'"))

    def test_links_in_the_tarball_are_refused(self):
        self.manage()
        self.release('4.30.1', 10, evil=True)
        st = self.check()
        self.assertEqual(st['state'], 'error')
        self.assertIn('unexpected entry', st['error'])

    def test_api(self):
        from jtwafmgr.web.api import crs_check, crs_updates
        from jtwafmgr.web.server import ApiError

        class Req:
            query, user, client_ip = {}, {'username': 'admin1', 'role': 'admin'}, '192.0.2.1'
        r = json.loads(crs_updates(self.app, Req()).body)
        self.assertEqual((r['manage'], r['location']['version']), (False, '4.30.0'))
        with self.assertRaises(ApiError):
            crs_check(self.app, Req())
        self.manage()
        crs_check(self.app, Req())
        self.assertTrue(os.path.exists(os.path.join(self.env.cfg['crs']['dir'], crsupdate.REQUEST)))


if __name__ == '__main__':
    unittest.main()
