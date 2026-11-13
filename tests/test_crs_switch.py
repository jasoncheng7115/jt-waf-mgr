"""CRS updates, step 2: the switch as a change (checks, approval, request, result) and the root program's install /
rollback of crs-<version> behind the crs link. Test signing key and tarballs made here; no network."""
import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest

from jtwafmgr import auth, config, crsupdate
from jtwafmgr.app import App
from jtwafmgr.apply import Applier, Fail
from jtwafmgr.changes import ChangeError
from tests.helpers import FIXTURE_SITE, TempEnv, jload
from tests.test_crsupdate import gpg, make_key, tarball


class _Keys:
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='jtwaf-crsk-')
        cls.fpr, cls.pub = make_key(os.path.join(cls.tmp, 'gpg'))
        cls._key, cls._fpr = crsupdate.KEY_FILE, crsupdate.PINNED_FPR
        crsupdate.KEY_FILE, crsupdate.PINNED_FPR = cls.pub, cls.fpr        # the root program's pinned key, for the test

    @classmethod
    def tearDownClass(cls):
        crsupdate.KEY_FILE, crsupdate.PINNED_FPR = cls._key, cls._fpr
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def stage(self, crs_dir, version='4.30.1', evil_after=False):
        """What jt-waf-mgr-crs.service leaves: the signed tarball, its .asc, the unpacked copy and the status."""
        stage = os.path.join(crs_dir, 'stage')
        os.makedirs(stage, exist_ok=True)
        name = 'coreruleset-%s-minimal.tar.gz' % version
        tb = tarball(version)
        with open(os.path.join(stage, name), 'wb') as fh:
            fh.write(tb)
        with open(os.path.join(stage, name + '.asc'), 'wb') as fh:
            fh.write(gpg(os.path.join(self.tmp, 'gpg'), '--armor', '--detach-sign', inp=tb).stdout)
        top = crsupdate.safe_extract(os.path.join(stage, name), stage, 'coreruleset-%s' % version)
        path = os.path.join(stage, 'crs-%s' % version)
        os.rename(top, path)
        man = hashlib.sha256(json.dumps(crsupdate.manifest(path), sort_keys=True).encode()).hexdigest()
        return {'version': version, 'path': path, 'tarball': name, 'tarball_sha256': hashlib.sha256(tb).hexdigest(),
                'manifest_sha256': man, 'files': 2, 'verified_at': 'x'}


class TestCrsChange(_Keys, unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        site = os.path.join(self.env.dir, 'site')
        shutil.copytree(FIXTURE_SITE, site, symlinks=True)
        self.spool = os.path.join(self.env.dir, 'spool')
        self.env.cfg = config.load(None, {
            'paths': dict(self.env.cfg['paths'], nginx_conf=os.path.join(site, 'nginx.conf')), 'server': {'secure_cookies': False},
            'syslog': {'enabled': False}, 'collector': {'backfill_rotated': False},
            'managed': {'dir': os.path.join(self.env.dir, 'managed'), 'spool': self.spool,
                        'sandbox_dir': os.path.join(self.env.dir, 'sbx')},
            'crs': {'dir': os.path.join(self.env.dir, 'crs'), 'manage': True}})
        self.app = App(self.env.cfg)
        self.wf = self.app.workflow
        self.wf.set_setting('sandbox.required', False, 'test')
        for n, r in (('op', 'operator'), ('appr', 'approver'), ('boss', 'admin')):
            self.app.auth.create_user(n, r, password='a long test password')

    def tearDown(self):
        self.env.cleanup()

    def user(self, name):
        return self.app.auth.user_row(name)

    def test_switch_is_a_change_a_person_approves(self):
        st = self.stage(self.env.cfg['crs']['dir'])
        crsupdate._write_status(self.env.cfg, {'state': 'ready', 'staged': st})
        with self.assertRaises(ChangeError):
            self.wf.propose_crs('install', '4.30.1', 'monthly update', 'op', role='operator')     # approvers only
        cid = self.wf.propose_crs('install', '4.30.1', 'monthly update', 'appr', role='approver')
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_crs('rollback', '4.29.0', 'x', 'appr', role='approver')
        self.assertEqual(cm.exception.code, 'crs_change_pending')
        self.wf.run_checks(cid)
        r = self.wf.get(cid)
        self.assertEqual((r['state'], r['direction']), ('pending_approval', 'loosen'), r['checks'])
        self.assertEqual(self.wf.public(r)['summary'], 'OWASP CRS 4.30.0 -> 4.30.1')
        with self.assertRaises(ChangeError):
            self.wf.approve(cid, self.user('appr'), note='mine')                                   # not the proposer
        self.wf.approve(cid, self.user('boss'), note='looked at the comparison')
        req = jload(os.path.join(self.spool, 'crs-c%d.req' % cid))
        self.assertEqual((req['action'], req['mode'], req['to'], req['tarball_sha256'], req['manifest_sha256']),
                         ('crs_switch', 'install', '4.30.1', st['tarball_sha256'], st['manifest_sha256']))
        self.assertTrue(req['tarball'].endswith('/stage/coreruleset-4.30.1-minimal.tar.gz'))
        # the root program's answer
        from jtwafmgr import alerts
        alerts.raise_alert(self.app.db, self.app.audit, 'system', 'crs_update', 'warning', 'crs_update:4.30.1', {})
        with open(os.path.join(self.spool, 'crs-c%d.result' % cid), 'w') as fh:
            json.dump({'request_id': 'crs-c%d' % cid, 'action': 'crs_switch', 'change_id': cid, 'result': 'ok',
                       'summary': 'crs -> crs-4.30.1'}, fh)
        self.wf.collect_results()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')
        self.assertEqual(self.app.db.one("SELECT state FROM alerts WHERE kind='crs_update'")['state'], 'handled')

    def test_a_changed_stage_or_a_missing_version_is_refused(self):
        st = self.stage(self.env.cfg['crs']['dir'])
        crsupdate._write_status(self.env.cfg, {'state': 'ready', 'staged': st})
        with open(os.path.join(st['path'], 'rules', 'REQUEST-930-APPLICATION-ATTACK-LFI.conf'), 'a') as fh:
            fh.write('SecRuleEngine Off\n')
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_crs('install', '4.30.1', 'update', 'appr', role='approver')
        self.assertEqual(cm.exception.code, 'crs_stage_changed')
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_crs('rollback', '4.20.0', 'back', 'appr', role='approver')
        self.assertEqual(cm.exception.code, 'crs_not_on_host')


class TestCrsApplier(_Keys, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='jtwaf-crsa-')
        self.site = os.path.join(self.d, 'site')
        shutil.copytree(FIXTURE_SITE, self.site, symlinks=True)
        self.cfg = config.load(None, {'paths': {'nginx_conf': os.path.join(self.site, 'nginx.conf'), 'nginx_bin': '/bin/true'},
                                      'managed': {'dir': os.path.join(self.d, 'managed'), 'spool': os.path.join(self.d, 'spool'),
                                                  'apply_state': os.path.join(self.d, 'apply-state')},
                                      'crs': {'dir': os.path.join(self.d, 'crsstate')}})
        os.makedirs(self.cfg['managed']['apply_state'])
        self.ap = Applier(self.cfg)
        self.ap.check_binary = lambda: None
        self.ap.reload = lambda wait: 'reloaded (test)'
        self.ap.test_config = lambda: 'ok'
        self.ap.health = lambda urls: {u: 200 for u in urls}
        self.crs = os.path.join(self.site, 'modsec', 'crs')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def req(self, st, **kw):
        r = {'action': 'crs_switch', 'change_id': 7, 'mode': 'install', 'to': '4.30.1', 'crs_path': self.crs,
             'tarball': os.path.join(os.path.realpath(self.cfg['crs']['dir']), 'stage', st['tarball']),
             'tarball_sha256': st['tarball_sha256'], 'manifest_sha256': st['manifest_sha256'], 'health_urls': []}
        r.update(kw)
        return r

    def test_install_and_rollback(self):
        st = self.stage(self.cfg['crs']['dir'])
        res = self.ap.crs_switch(self.ap.check_crs(self.req(st)))
        self.assertEqual(res['result'], 'ok', res)
        self.assertTrue(os.path.islink(self.crs))
        self.assertEqual(os.readlink(self.crs), 'crs-4.30.1')
        self.assertEqual(crsupdate.installed_version(self.crs), (4, 30, 1))
        self.assertTrue(os.path.isdir(os.path.join(self.site, 'modsec', 'crs-4.30.0')))           # the old one kept
        back = self.ap.crs_switch(self.ap.check_crs({'action': 'crs_switch', 'change_id': 8, 'mode': 'rollback', 'to': '4.30.0',
                                                     'crs_path': self.crs}))
        self.assertEqual((back['result'], os.readlink(self.crs)), ('ok', 'crs-4.30.0'))

    def test_a_plain_crs_directory_becomes_a_link_first(self):
        real = os.path.join(self.site, 'modsec', 'crs-4.30.0')
        os.unlink(self.crs)
        os.rename(real, self.crs)                                # crs/ is the directory itself (no versions yet)
        st = self.stage(self.cfg['crs']['dir'])
        res = self.ap.crs_switch(self.ap.check_crs(self.req(st)))
        self.assertIn('is now a link to crs-4.30.0', res['summary'])
        self.assertEqual(os.readlink(self.crs), 'crs-4.30.1')
        self.assertEqual(crsupdate.installed_version(real), (4, 30, 0))

    def test_refusals(self):
        st = self.stage(self.cfg['crs']['dir'])
        for bad in (dict(crs_path='/etc'), dict(tarball='/tmp/coreruleset-4.30.1-minimal.tar.gz'), dict(to='4.30.1; rm -rf /'),
                    dict(tarball_sha256='x')):
            with self.assertRaises(Fail, msg=bad):
                self.ap.check_crs(self.req(st, **bad))
        with self.assertRaises(Fail) as cm:                       # the tarball is not the one that was checked
            self.ap.crs_switch(self.ap.check_crs(self.req(st, tarball_sha256='0' * 64)))
        self.assertEqual(cm.exception.step, 'verify')
        with self.assertRaises(Fail) as cm:                       # the files differ from those compared in the sandbox
            self.ap.crs_switch(self.ap.check_crs(self.req(st, manifest_sha256='0' * 64)))
        self.assertEqual(cm.exception.step, 'verify')
        self.assertEqual(os.readlink(self.crs), 'crs-4.30.0')    # nothing switched
        self.assertFalse(os.path.exists(os.path.join(self.site, 'modsec', 'crs-4.30.1')))
        with self.assertRaises(Fail):                             # a rollback to a version that is not there
            self.ap.crs_switch(self.ap.check_crs({'action': 'crs_switch', 'change_id': 9, 'mode': 'rollback', 'to': '4.1.0',
                                                  'crs_path': self.crs}))

    def test_nginx_t_failure_switches_back(self):
        st = self.stage(self.cfg['crs']['dir'])

        def bad():
            raise Fail('nginx_t', 'nginx -t failed')
        self.ap.test_config = bad
        with self.assertRaises(Fail) as cm:
            self.ap.crs_switch(self.ap.check_crs(self.req(st)))
        self.assertIn('switched back', cm.exception.summary)
        self.assertEqual(os.readlink(self.crs), 'crs-4.30.0')


class TestSandboxCrsSwap(unittest.TestCase):
    def test_the_crs_include_points_at_the_other_version(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        app = App(env.cfg)
        from jtwafmgr.sandbox import Sandbox
        sb = Sandbox(app.cfg, app.site)
        root = tempfile.mkdtemp(prefix='sbx-', dir=env.dir)
        crs = os.path.join(os.path.dirname(env.cfg['paths']['nginx_conf']), 'modsec', 'crs')
        sb.build(root, {}, crs_swap=(crs, '/var/lib/jt-waf-mgr/crs/stage/crs-4.30.1'))
        with open(os.path.join(root, 'conf', 'main-0.conf')) as fh:
            main = fh.read()
        self.assertIn('Include /var/lib/jt-waf-mgr/crs/stage/crs-4.30.1/rules/*.conf', main)
        self.assertNotIn(crs + '/rules', main)


if __name__ == '__main__':
    unittest.main()
