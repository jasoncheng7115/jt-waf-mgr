"""Internal protection building blocks: confident blocks that also cover internal sources (known scanners
excepted), raw rules placed before a given rule, and no automatic apply for anything that blocks internal sources."""
import json
import unittest

from jtwafmgr import rulegen, uisettings
from jtwafmgr.changes import ChangeError
from tests import test_p2

_W = test_p2.TestWorkflow   # borrow its fixtures without collecting its tests here

SPEC = {'target': 'path', 'regex': '^/\\.env$', 'msg': 'env probe', 'host': {'mode': 'any', 'value': ''}}


class TestInternalProtection(unittest.TestCase):
    setUp = _W.setUp
    tearDown = _W.tearDown
    user = _W.user
    fake_apply = _W.fake_apply
    adopt = _W.adopt

    def test_confident_block_source(self):
        cfg = self.app.cfg
        _, ext, _ = rulegen.build('confident_block', dict(SPEC), 10230, cfg)
        self.assertIn('!@ipMatch ' + rulegen._ip_list(cfg.internal_networks), ext)
        uisettings.set_many(self.app, {'network.known_scanners': ['192.168.77.7', '192.168.77.16/28']}, 'boss')
        norm, allsrc, _ = rulegen.build('confident_block', dict(SPEC, source='all'), 10230, cfg)
        self.assertEqual(norm['source'], 'all')
        self.assertIn('REMOTE_ADDR "!@ipMatch 192.168.77.7/32,192.168.77.16/28"', allsrc)
        self.assertNotIn(rulegen._ip_list(cfg.internal_networks), allsrc)
        self.assertIn('setvar:tx.jt_block=1', allsrc)
        rulegen.check_raw_text(allsrc, cfg=cfg)
        # no scanners: no source condition at all
        uisettings.set_many(self.app, {'network.known_scanners': []}, 'boss')
        _, bare, _ = rulegen.build('confident_block', dict(SPEC, source='all'), 10230, cfg)
        self.assertNotIn('REMOTE_ADDR', bare)
        with self.assertRaises(rulegen.SpecError):
            rulegen.build('confident_block', dict(SPEC, source='internal-only'), 10230, cfg)

    def test_internal_block_never_auto_applied(self):
        self.adopt()
        self.wf.set_setting('apply.auto_tighten', True, 'boss')
        ext = self.wf.propose('add', 'confident_block', dict(SPEC), 'external probe', 'op')
        self.wf.run_checks(ext)
        self.assertEqual(self.wf.get(ext)['state'], 'applying')          # the control: auto apply works here
        self.fake_apply()
        cid = self.wf.propose('add', 'confident_block', dict(SPEC, regex='^/\\.git/config$', source='all'),
                              'internal too', 'op')
        self.assertEqual(self.wf.get(cid)['direction'], 'tighten')
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval')
        # rules suggested by the language model wait for a person unless their own switch is on
        tests = [{'expect': 403, 'source': 'external', 'host': 'app.example.com', 'path': '/.svn/entries'}]
        an = self.wf.propose('add', 'confident_block', dict(SPEC, regex='^/\\.svn/'), 'model says probe', 'analyst',
                             via='api', owner='analyst', tests=tests)
        self.wf.run_checks(an)
        self.assertEqual(self.wf.get(an)['state'], 'pending_approval')
        self.wf.set_setting('apply.auto_tighten', False, 'boss')
        self.wf.set_setting('apply.auto_tighten_analyst', True, 'boss')
        an2 = self.wf.propose('add', 'confident_block', dict(SPEC, regex='^/\\.hg/'), 'model says probe', 'analyst',
                              via='api', owner='analyst', tests=[dict(tests[0], path='/.hg/store')])
        self.wf.run_checks(an2)
        self.assertEqual(self.wf.get(an2)['state'], 'applying')
        self.fake_apply()
        # ... never for internal sources, and the switch does not cover people's changes
        an3 = self.wf.propose('add', 'confident_block', dict(SPEC, regex='^/\\.bzr/', source='all'), 'model', 'analyst',
                              via='api', owner='analyst', tests=[dict(tests[0], path='/.bzr/x')])
        self.wf.run_checks(an3)
        self.assertEqual(self.wf.get(an3)['state'], 'pending_approval')
        op = self.wf.propose('add', 'confident_block', dict(SPEC, regex='^/\\.idea/'), 'person', 'op')
        self.wf.run_checks(op)
        self.assertEqual(self.wf.get(op)['state'], 'pending_approval')

    def test_raw_rule_before_another(self):
        self.adopt()
        text = ('SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge 15" "id:10050,phase:2,pass,nolog,t:none,'
                'setvar:tx.jt_block=1,ctl:ruleEngine=On"')
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose('add', 'raw', {'text': text, 'placement': 'after', 'before_rule_id': 10111}, 'x', 'boss',
                            role='admin')
        self.assertEqual(cm.exception.details.get('reason'), 'anchor_not_found')   # 10111 is in the other file
        cid = self.wf.propose('add', 'raw', {'text': text, 'placement': 'after', 'before_rule_id': 10299},
                              'internal threshold', 'boss', role='admin')
        self.assertEqual(json.loads(self.wf.get(cid)['spec'])['before_rule_id'], 10299)
        items, files, _ = self.wf.build_files(self.wf.get(cid), 99)
        after = files['after']
        self.assertLess(after.index('id:10297'), after.index('id:10050'))
        self.assertLess(after.index('id:10050'), after.index('id:10299'))
        # a second one before the same anchor goes between the first and the anchor
        self.wf.run_checks(cid)
        self.wf.approve(cid, self.user('appr'), note='ok')
        self.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')
        text2 = text.replace('10050', '10051').replace('@ge 15', '@ge 20')
        c2 = self.wf.propose('add', 'raw', {'text': text2, 'placement': 'after', 'before_rule_id': 10299}, 'y', 'boss',
                             role='admin')
        after = self.wf.build_files(self.wf.get(c2), 100)[1]['after']
        self.assertLess(after.index('id:10050'), after.index('id:10051'))
        self.assertLess(after.index('id:10051'), after.index('id:10299'))

    def _boss(self):
        return {'username': 'boss', 'role': 'admin'}

    def test_bundle_one_change_one_version(self):
        self.adopt()
        mg = self.wf.managed
        v0 = mg.current_version()['version']
        it = mg.item_by_rule(10203)
        new_text = it['text'].replace('!@ipMatch 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8', '!@ipMatch 192.0.2.7')
        self.assertNotEqual(new_text, it['text'])
        thr = ('SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge 15" "id:10050,phase:2,pass,nolog,t:none,'
               'setvar:tx.jt_block=1,ctl:ruleEngine=On"')
        ops = [{'op': 'modify', 'item_id': it['id'], 'spec': {'text': new_text, 'placement': 'before'}},
               {'op': 'add', 'kind': 'raw', 'spec': {'text': thr, 'placement': 'after', 'before_rule_id': 10299}},
               {'op': 'add', 'kind': 'confident_block', 'spec': dict(SPEC, source='all')},
               {'op': 'add', 'kind': 'confident_block', 'spec': dict(SPEC, regex='^/\\.git/')}]
        cid = self.wf.propose_bundle(ops, 'internal protection', 'boss', role='admin')
        r = self.wf.get(cid)
        self.assertEqual((r['op'], r['kind'], r['direction']), ('bundle', 'bundle', 'loosen'))   # a modify is in it
        spec = json.loads(r['spec'])
        ids = [b['rule_id'] for b in spec['ops']]
        self.assertEqual(ids[:2], [10203, 10050])
        self.assertEqual(ids[3], ids[2] + 1)                   # two new template rules, two different ids
        self.assertIn('4 operations', self.wf.public(r)['summary'])
        self.wf.run_checks(cid)
        r = self.wf.get(cid)
        self.assertEqual(r['state'], 'pending_approval', r['checks'])
        ev = json.loads(r['checks'])['evidence']
        self.assertEqual(len(ev['bundle']), 4)
        with self.assertRaises(ChangeError):                   # the proposer cannot approve it
            self.wf.approve(cid, self.user('boss'), note='self')
        self.wf.approve(cid, self.user('appr'), note='ok')
        self.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')
        self.assertEqual(mg.current_version()['version'], v0 + 1)           # one version for all four
        self.assertEqual(mg.item_by_rule(10203)['text'], new_text)
        self.assertEqual(json.loads(mg.item_by_rule(ids[2])['spec'])['source'], 'all')
        after = open(mg.path('after')).read()
        self.assertLess(after.index('id:10050'), after.index('id:10299'))
        before = open(mg.path('before')).read()
        self.assertIn('id:%d' % ids[3], before)
        # only the touched rows carry the change id
        rows = {x['rule_id']: x['change_id'] for x in self.app.db.q('SELECT rule_id, change_id FROM managed_rules')}
        self.assertEqual({k for k, v in rows.items() if v == cid}, set(ids))

    def test_bundle_refusals(self):
        self.adopt()
        it = self.wf.managed.item_by_rule(10203)
        for ops, code in (([], 'invalid_bundle'), ('x', 'invalid_bundle'),
                          ([{'op': 'disable', 'item_id': it['id']}, {'op': 'delete', 'item_id': it['id']}], 'invalid_bundle'),
                          ([{'op': 'add', 'kind': 'confident_block', 'spec': {'regex': '.*'}}], 'invalid_spec')):
            with self.assertRaises(ChangeError) as cm:
                self.wf.propose_bundle(ops, 'x', 'boss', role='admin')
            self.assertEqual(cm.exception.code, code, ops)
        with self.assertRaises(ChangeError) as cm:             # raw rules: administrators only, also in a bundle
            self.wf.propose_bundle([{'op': 'disable', 'item_id': it['id']},
                                    {'op': 'modify', 'item_id': it['id'] + 0, 'spec': {'text': it['text']}}], 'x', 'op',
                                   role='operator')
        self.assertIn(cm.exception.code, ('raw_admin_only', 'invalid_bundle'))
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_bundle([{'op': 'add', 'kind': 'raw', 'spec': {'text': 'SecAction "id:10051,phase:1,pass,nolog"'}}],
                                   'x', 'op', role='operator')
        self.assertEqual((cm.exception.code, cm.exception.details.get('index')), ('raw_admin_only', 0))

    def test_import_as_one_change_keeps_file_order(self):
        self.adopt()
        mg = self.wf.managed
        after = open(mg.path('after')).read()
        new = ('SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge 15" "id:10050,phase:2,pass,nolog,t:none,'
               'setvar:tx.jt_block=1,ctl:ruleEngine=On"\n\n')
        i = after.index('SecRule TX:JT_BLOCK')
        text = after[:i] + new + after[i:]
        out = self.wf.import_propose('after', text, 'internal threshold', self._boss(), as_one=True)
        self.assertEqual(len(out['changes']), 1)
        r = self.wf.get(out['changes'][0]['change_id'])
        ops = json.loads(r['spec'])['ops']
        self.assertEqual([(b['op'], b['rule_id']) for b in ops], [('add', 10050)])
        self.assertEqual(ops[0]['spec']['before_rule_id'], 10299)
        self.assertEqual(r['direction'], 'tighten')

    def test_sandbox_cases_follow_the_source(self):
        sb = self.wf.sandbox
        t = [{'expect': 403, 'source': 'external', 'host': 'app.example.com', 'path': '/.env'}]
        def internal_expect(r):
            return [c['expect'] for c in sb.cases_for(r, t, []) if c['origin'] == 'internal-same']
        one = lambda src: {'op': 'add', 'kind': 'confident_block', 'direction': 'tighten', 'spec': json.dumps(dict(SPEC, source=src))}
        self.assertEqual(internal_expect(one('external')), [200])
        self.assertEqual(internal_expect(one('all')), [403])
        mixed = {'op': 'bundle', 'kind': 'bundle', 'direction': 'tighten', 'spec': json.dumps({'ops': [
            {'op': 'add', 'kind': 'confident_block', 'spec': dict(SPEC)},
            {'op': 'add', 'kind': 'confident_block', 'spec': dict(SPEC, source='all')}]})}
        self.assertEqual(internal_expect(mixed), [])
        self.assertTrue(any(c['origin'] == 'variant' for c in sb.cases_for(mixed, t, [])))
        # a bundle that adds a confident block needs a 403 test, like a single one
        res = sb.run_change(mixed, {}, [], self.wf.managed)
        self.assertIn(res.get('error'), ('test_required', 'test_per_block'))

    def test_review_fixes(self):
        self.adopt()
        mg = self.wf.managed
        # bundle ids are reserved: a later single proposal gets the next id, not one of the bundle's
        cid = self.wf.propose_bundle([{'op': 'add', 'kind': 'confident_block', 'spec': dict(SPEC)}], 'x', 'op')
        rid = json.loads(self.wf.get(cid)['spec'])['ops'][0]['rule_id']
        self.assertIn(rid, mg.occupied_ids())
        c2 = self.wf.propose('add', 'confident_block', dict(SPEC, regex='^/\\.git/'), 'y', 'op')
        self.assertNotEqual(self.wf.get(c2)['rule_id'], rid)
        # item ids must be integers
        for bad in ([1], '5', True):
            with self.assertRaises(ChangeError) as cm:
                self.wf.propose_bundle([{'op': 'disable', 'item_id': bad}], 'x', 'boss', role='admin')
            self.assertEqual(cm.exception.code, 'invalid_bundle')
        # at most BUNDLE_MAX_BLOCKS confident blocks
        many = [{'op': 'add', 'kind': 'confident_block', 'spec': dict(SPEC, regex='^/probe-%02d$' % i)}
                for i in range(self.wf.BUNDLE_MAX_BLOCKS + 1)]
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_bundle(many, 'x', 'op')
        self.assertEqual(cm.exception.details.get('reason'), 'too_many_blocks')
        # every block of a bundle needs its own matching 403 test
        two = {'op': 'bundle', 'kind': 'bundle', 'direction': 'tighten', 'spec': json.dumps({'ops': [
            {'op': 'add', 'kind': 'confident_block', 'rule_id': 1, 'spec': dict(SPEC)},
            {'op': 'add', 'kind': 'confident_block', 'rule_id': 2, 'spec': dict(SPEC, regex='^/\\.git/')}]})}
        t = [{'expect': 403, 'source': 'external', 'host': 'app.example.com', 'path': '/.env'}]
        res = self.wf.sandbox.run_change(two, {}, t, mg)
        self.assertEqual((res.get('error'), res.get('rule_id')), ('test_per_block', 2))
        # a comment never ends in a backslash
        from jtwafmgr.changes import _comment
        self.assertNotIn('\\', _comment({'reason': 'ends with \\', 'id': 1, 'proposed_by': 'x'}))

    def test_known_scanners_must_be_internal(self):
        from jtwafmgr.uisettings import SettingError
        for bad in (['0.0.0.0/0'], ['198.51.100.7'], ['10.0.0.0/8']):
            with self.assertRaises(SettingError) as cm:
                uisettings.set_many(self.app, {'network.known_scanners': bad}, 'boss')
            self.assertEqual(cm.exception.code, 'scanner_outside_internal', bad)
        uisettings.set_many(self.app, {'network.known_scanners': ['192.168.77.7', '192.168.77.0/24']}, 'boss')
        # the sandbox's internal address is never a known scanner
        uisettings.set_many(self.app, {'network.known_scanners': ['10.0.0.50']}, 'boss')
        self.assertNotEqual(self.wf.sandbox.internal_ip, '10.0.0.50')

    def test_rules_changed_after_approval_are_checked_again(self):
        self.adopt()
        uisettings.set_many(self.app, {'network.known_scanners': ['192.168.77.7']}, 'boss')
        cid = self.wf.propose('add', 'confident_block', dict(SPEC, source='all'), 'internal too', 'op',
                              tests=[{'expect': 403, 'source': 'external', 'host': 'app.example.com', 'path': '/.env'}])
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval')
        uisettings.set_many(self.app, {'network.known_scanners': ['192.168.77.8']}, 'boss')   # the rule text changes
        self.wf.approve(cid, self.user('appr'), note='ok')
        self.assertEqual(self.wf.get(cid)['state'], 'checking')

    def test_many_inserts_before_one_rule_keep_order(self):
        self.adopt()
        mg = self.wf.managed
        items = mg.items(include_deleted=True)
        for i in range(80):
            text = 'SecAction "id:%d,phase:1,pass,nolog"' % (10400 + i)
            items, _ = mg.with_op('add', None, {'rule_id': 10400 + i, 'kind': 'raw', 'placement': 'after',
                                                'spec': {'text': text, 'before_rule_id': 10299}, 'text': text}, items=items)
        order = [x['rule_id'] for x in sorted((x for x in items if x['placement'] == 'after'), key=lambda x: x['position'])]
        self.assertEqual(order[-1], 10299)
        self.assertEqual(order[-81:-1], list(range(10400, 10480)))


del _W   # not a test class of this module

if __name__ == '__main__':
    unittest.main()
