"""Switching several rules (or a whole category) on and off as one change. Synthetic site only."""
import json
import os
import time
import unittest

from jtwafmgr import auth, config
from jtwafmgr.app import App
from jtwafmgr.changes import ChangeError
from tests.helpers import TempEnv, jload


class TestRuleToggle(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.mdir = os.path.join(self.env.dir, 'managed')
        self.spool = os.path.join(self.env.dir, 'spool')
        self.env.cfg = config.load(None, {
            'paths': dict(self.env.cfg['paths']), 'server': {'secure_cookies': False}, 'syslog': {'enabled': False},
            'collector': {'backfill_rotated': False}, 'waf': {'focus_sites': []},
            'managed': {'dir': self.mdir, 'spool': self.spool, 'sandbox_dir': os.path.join(self.env.dir, 'sbx')},
            'evidence': {'access_logs': [os.path.join(self.env.dir, '*access.log')]}})
        self.app = App(self.env.cfg)
        self.wf = self.app.workflow
        self.wf.set_setting('sandbox.required', False, 'test')
        a = self.app.auth
        for n, r in (('op', 'operator'), ('appr', 'approver'), ('boss', 'admin')):
            a.create_user(n, r, password='a long test password')
        self.secret, _ = a.totp_setup('boss')
        a.totp_enable('boss', auth.totp_code(self.secret, int(time.time() // 30)))
        self.adopt()

    def tearDown(self):
        self.env.cleanup()

    def user(self, name):
        self.app.db.x('UPDATE users SET totp_last_step=0 WHERE username=?', (name,))
        return self.app.auth.user_row(name)

    def fake_apply(self):
        for n in sorted(os.listdir(self.spool)):
            if not n.endswith('.req'):
                continue
            req = jload(os.path.join(self.spool, n))
            os.makedirs(self.mdir, exist_ok=True)
            for p, f in (('before', 'before-crs.conf'), ('after', 'after-crs.conf')):
                with open(os.path.join(self.mdir, f), 'w') as fh:
                    fh.write(req['files'][p])
            with open(os.path.join(self.spool, n[:-4] + '.result'), 'w') as fh:
                json.dump({'request_id': n[:-4], 'version': req['version'], 'change_id': req['change_id'],
                           'result': 'ok', 'step': 'done', 'summary': 'test'}, fh)
            os.unlink(os.path.join(self.spool, n))
        self.wf.collect_results()

    def adopt(self):
        cid = self.wf.propose_adoption('boss')
        self.wf.run_checks(cid)
        self.wf.set_setting('approval.single_admin_mode', True, 'boss')
        self.wf.approve(cid, self.user('boss'), auth.totp_code(self.secret, int(time.time() // 30)), 'adopting the rule files')
        self.fake_apply()
        self.wf.set_setting('approval.single_admin_mode', False, 'boss')
        self.app.site._nginx = None

    def ops(self, cid):
        return json.loads(self.wf.get(cid)['spec'])['ops']

    def test_site_rules_off_and_on_in_one_change(self):
        cid, plan = self.wf.propose_toggle('disable', [10111, 10119, 99999], None, 'two exclusions no longer needed', 'op',
                                           role='operator')
        self.assertEqual([o['op'] for o in self.ops(cid)], ['disable', 'disable'])
        self.assertEqual(plan['skipped'], [{'id': 99999, 'reason': 'not_loaded'}])
        self.assertEqual(self.wf.get(cid)['direction'], 'tighten')       # an exclusion off = stricter

    def test_crs_rules_off_for_chosen_sites(self):
        cid, plan = self.wf.propose_toggle('disable', [930110, 930120, 949110], {'mode': 'hosts', 'hosts': ['app.example.com']},
                                           'false positives on this application', 'op', role='operator')
        ops = self.ops(cid)
        self.assertEqual(len(ops), 1)
        self.assertEqual((ops[0]['kind'], ops[0]['spec']['action'], ops[0]['spec']['rule_ids'], ops[0]['spec']['host']['value']),
                         ('exclusion', 'remove_rule', [930110, 930120], 'app.example.com'))
        self.assertEqual(plan['skipped'], [{'id': 949110, 'reason': 'system_rule'}])
        self.assertEqual(self.wf.get(cid)['direction'], 'loosen')
        with self.assertRaises(ChangeError) as cm:
            self.wf.toggle_plan('disable', [930110], None)
        self.assertEqual(cm.exception.code, 'scope_required')

    def test_off_for_every_request_is_an_expert_rule_for_admins(self):
        with self.assertRaises(ChangeError):                              # an operator may not add expert rules
            self.wf.propose_toggle('disable', [930110], {'mode': 'all'}, 'switch it off everywhere', 'op', role='operator')
        cid, _ = self.wf.propose_toggle('disable', [930110], {'mode': 'all'}, 'switch it off everywhere', 'boss', role='admin')
        ops = self.ops(cid)
        self.assertEqual((ops[0]['kind'], ops[0]['spec']['placement']), ('raw', 'after'))
        self.assertIn('SecRuleRemoveById 930110', ops[0]['spec']['text'])

    def test_a_category_off_needs_an_admin_code_and_reason(self):
        cid, _ = self.wf.propose_toggle('disable', [930110, 930120], {'mode': 'hosts', 'hosts': ['app.example.com']},
                                        'the whole lfi family off for this app', 'op', role='operator', strict=True)
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval', self.wf.get(cid)['checks'])
        with self.assertRaises(ChangeError) as cm:
            self.wf.approve(cid, self.user('appr'), note='looks fine to me')
        self.assertEqual(cm.exception.code, 'admin_required')
        with self.assertRaises(ChangeError):
            self.wf.approve(cid, self.user('boss'), '000000', 'checked the evidence')     # wrong code
        with self.assertRaises(ChangeError) as cm:
            self.wf.approve(cid, self.user('boss'), auth.totp_code(self.secret, int(time.time() // 30)), 'ok')
        self.assertEqual(cm.exception.code, 'note_required')
        # the code above was used up (replay protection): the next 30-second step's code
        self.wf.approve(cid, self.user('boss'), auth.totp_code(self.secret, int(time.time() // 30) + 1),
                        'checked the evidence for the app')
        self.assertEqual(self.wf.get(cid)['state'], 'applying')

    def test_switching_crs_rules_on_again(self):
        cid, _ = self.wf.propose_toggle('disable', [930110], {'mode': 'hosts', 'hosts': ['app.example.com']}, 'off for app',
                                        'op', role='operator')
        self.wf.run_checks(cid)
        self.wf.approve(cid, self.user('appr'), note='fine')
        self.fake_apply()
        # the fake apply does not touch the site's main file: say what nginx would now load
        from unittest import mock
        from jtwafmgr.modsecconf import ModsecConfig
        with mock.patch.object(ModsecConfig, 'rule_states', lambda m: {930110: {'state': 'partial'}, 930120: {'state': 'on'}}):
            cid2, plan = self.wf.propose_toggle('enable', [930110, 930120], None, 'back on', 'op', role='operator')
        self.assertEqual([o['op'] for o in self.ops(cid2)], ['disable'])        # the exclusion is switched off
        self.assertEqual(plan['skipped'], [{'id': 930120, 'reason': 'already'}])

    def test_nothing_to_change(self):
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_toggle('enable', [930110], None, 'it is on already', 'op', role='operator')
        self.assertEqual(cm.exception.code, 'nothing_to_change')


if __name__ == '__main__':
    unittest.main()
