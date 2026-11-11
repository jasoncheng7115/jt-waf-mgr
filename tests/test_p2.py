import json
import os
import shutil
import tempfile
import time
import unittest

from jtwafmgr import auth, rulegen
from jtwafmgr.app import App
from jtwafmgr.apply import Applier, Fail
from jtwafmgr.changes import ChangeError
from jtwafmgr.managed import Managed, split_items
from jtwafmgr.modsecconf import parse_rules_text
from tests.helpers import FIXTURE_SITE, TempEnv, record


class TestRulegen(unittest.TestCase):
    def setUp(self):
        self.cfg = TempEnv().cfg

    def test_confident_shape(self):
        spec, text, pl = rulegen.build('confident_block', {'target': 'path', 'regex': r'^/\.env', 'msg': 'secret file'},
                                       10222, self.cfg)
        self.assertEqual(pl, 'before')
        self.assertIn("id:10222,phase:1,pass,log,msg:'jt confident block: secret file',tag:'jt-confident-block'", text)
        self.assertIn('t:urlDecodeUni,t:normalizePath,t:lowercase,chain', text)
        self.assertIn('SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8', text)
        self.assertTrue(text.rstrip().endswith('"t:none,setvar:tx.jt_block=1,ctl:ruleEngine=On"'))
        rules = []
        parse_rules_text(text, 'x', rules, [], [], [])
        self.assertEqual([r.id for r in rules], [10222])
        self.assertEqual(len(rules[0].parts), 2)
        self.assertEqual(rulegen.direction('add', 'confident_block', text), 'tighten')
        self.assertEqual(rulegen.direction('disable', 'confident_block', text), 'loosen')

    def test_exclusion_shape(self):
        spec, text, _ = rulegen.build('exclusion', {
            'host': {'mode': 'exact', 'value': 'App.Example.com'}, 'path': {'mode': 'prefix', 'value': '/api/'},
            'method': 'post', 'source': 'internal', 'action': 'remove_target_by_id', 'rule_ids': [930120, 932235],
            'targets': ['ARGS:q']}, 10130, self.cfg)
        self.assertIn(r'"@rx ^app\.example\.com(?::[0-9]+)?$"', text)
        self.assertIn('"@beginsWith /api/"', text)
        self.assertIn('"@streq POST"', text)
        self.assertIn('ctl:ruleRemoveTargetById=930120;ARGS:q,ctl:ruleRemoveTargetById=932235;ARGS:q', text)
        rules = []
        parse_rules_text(text, 'x', rules, [], [], [])
        self.assertEqual(len(rules[0].parts), 4)
        self.assertEqual(rulegen.direction('add', 'exclusion', text), 'loosen')
        self.assertEqual(rulegen.direction('disable', 'exclusion', text), 'tighten')

    def test_rejections(self):
        bad = [
            ('exclusion', {'action': 'remove_rule', 'rule_ids': [1]}, 'scope_required'),
            ('exclusion', {'host': {'mode': 'exact', 'value': 'a b'}, 'action': 'remove_rule', 'rule_ids': [1]}, 'invalid_host'),
            ('exclusion', {'path': {'mode': 'exact', 'value': '/a"b'}, 'action': 'remove_rule', 'rule_ids': [1]}, 'invalid_path'),
            ('exclusion', {'path': {'mode': 'prefix', 'value': '/'}, 'action': 'remove_tag', 'tag': 'OWASP_CRS'}, 'confirmation_required'),
            ('exclusion', {'path': {'mode': 'prefix', 'value': '/'}, 'action': 'remove_target_by_id', 'rule_ids': [1],
                           'targets': ['ARGS:x" ,exec:/bin/sh']}, 'invalid_targets'),
            ('confident_block', {'target': 'path', 'regex': '.*', 'msg': 'x'}, 'matches_empty'),
            ('confident_block', {'target': 'path', 'regex': '[a-z/]', 'msg': 'x'}, 'too_broad'),
            ('confident_block', {'target': 'path', 'regex': '(a+)+$', 'msg': 'x'}, 'redos_shape'),
            ('confident_block', {'target': 'path', 'regex': '^/x', 'msg': "it's"}, 'invalid_text'),
            ('confident_block', {'target': 'path', 'regex': '^/x('}, 'invalid_regex'),
            ('confident_block', {'target': 'header', 'header': 'X Y', 'regex': '^x', 'msg': 'm'}, 'invalid_header'),
            ('redaction', {'fields': ['pass word']}, 'invalid_fields'),
            ('plugin', {'plugin': 'wordpress-rule-exclusions'}, 'scope_required'),
        ]
        for kind, spec, code in bad:
            with self.assertRaises(rulegen.SpecError, msg=(kind, spec)) as cm:
                rulegen.build(kind, spec, 10130, self.cfg)
            self.assertEqual(cm.exception.code, code, (kind, spec))

    def test_raw_forbidden(self):
        for text, what in [('SecRuleEngine Off', 'forbidden'), ('SecAction "id:10140,phase:1,pass,ctl:ruleEngine=Off"', 'forbidden'),
                           ('Include /etc/shadow', 'forbidden'), ('SecAuditLog /tmp/x', 'forbidden'),
                           ('SecRule ARGS "@pmFromFile /etc/passwd" "id:10141,deny"', 'forbidden'),
                           ('SecRule ARGS "@rx x" "id:10142,exec:/bin/sh"', 'forbidden'),
                           ('SecRuleRemoveById 10299', 'removes_system_rule'),
                           ('SecAction "id:10143,phase:1,pass,ctl:ruleRemoveById=10298"', 'removes_system_rule'),
                           ('SecMarker x\nSecFoo bar', 'directive_not_allowed')]:
            with self.assertRaises(rulegen.SpecError, msg=text) as cm:
                rulegen.check_raw_text(text, cfg=self.cfg)
            self.assertEqual(cm.exception.code, what, text)
        self.assertEqual(rulegen.check_raw_text('SecRule ARGS "@rx x" "id:10150,phase:2,deny"', cfg=self.cfg), [10150])
        self.assertEqual(rulegen.raw_direction('SecRule ARGS "@rx x" "id:10150,phase:2,deny"'), 'tighten')
        self.assertEqual(rulegen.raw_direction('SecRuleRemoveById 942100'), 'loosen')


class TestImport(unittest.TestCase):
    def test_roundtrip_fixture(self):
        path = os.path.join(FIXTURE_SITE, 'modsec', 'local-before-crs.conf')
        text = open(path).read()
        items = split_items(text)
        its = [dict(it, placement='before', position=float(i), enabled=1, deleted=0) for i, it in enumerate(items)]
        out = Managed.render(its, 1)['before']
        strip = lambda t: [l.rstrip() for l in t.splitlines() if l.strip() and not l.lstrip().startswith('#')]
        self.assertEqual(strip(text), strip(out))
        self.assertTrue(out.startswith('# Generated by jt-waf-mgr'))
        self.assertEqual([i['rule_id'] for i in items if i['text']], [10000, 10001, 10111, 10119, 10203])

    def test_comment_inside_chain_kept_with_rule(self):
        t = ('SecRule A "@rx x" "id:10001,chain"\n# note\n    SecRule B "@rx y" "t:none"\n\n# standalone\n\n'
             'SecAction "id:10002,pass"\n')
        items = split_items(t)
        self.assertEqual([i['rule_id'] for i in items], [10001, None, 10002])
        self.assertIn('SecRule B', items[0]['text'])


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.mdir = os.path.join(self.env.dir, 'managed')
        self.spool = os.path.join(self.env.dir, 'spool')
        from jtwafmgr import config
        self.env.cfg = config.load(None, {
            'paths': dict(self.env.cfg['paths']), 'server': {'secure_cookies': False}, 'syslog': {'enabled': False},
            'collector': {'backfill_rotated': False}, 'waf': {'focus_sites': []},
            'managed': {'dir': self.mdir, 'spool': self.spool, 'sandbox_dir': os.path.join(self.env.dir, 'sbx')},
            'evidence': {'access_logs': [os.path.join(self.env.dir, '*access.log')]}})
        self.app = App(self.env.cfg)
        self.wf = self.app.workflow
        self.wf.set_setting('sandbox.required', False, 'test')
        a = self.app.auth
        a.create_user('op', 'operator', password='a long test password')
        a.create_user('appr', 'approver', password='a long test password')
        a.create_user('boss', 'admin', password='a long test password')
        self.secret, _ = a.totp_setup('boss')
        a.totp_enable('boss', auth.totp_code(self.secret, int(time.time() // 30)))

    def tearDown(self):
        self.env.cleanup()

    def user(self, name):
        # approving with an OTP consumes the 30 s step (replay protection); tests approve often
        self.app.db.x('UPDATE users SET totp_last_step=0 WHERE username=?', (name,))
        return self.app.auth.user_row(name)

    def fake_apply(self, ok=True):
        """Stands in for the root program: write the files, answer with a result."""
        for n in sorted(os.listdir(self.spool)):
            if not n.endswith('.req'):
                continue
            req = json.load(open(os.path.join(self.spool, n)))
            if ok:
                os.makedirs(self.mdir, exist_ok=True)
                for p, f in (('before', 'before-crs.conf'), ('after', 'after-crs.conf')):
                    with open(os.path.join(self.mdir, f), 'w') as fh:
                        fh.write(req['files'][p])
            res = {'request_id': n[:-4], 'version': req['version'], 'change_id': req['change_id'],
                   'result': 'ok' if ok else 'failed', 'step': 'done' if ok else 'nginx_t', 'summary': 'test'}
            with open(os.path.join(self.spool, n[:-4] + '.result'), 'w') as fh:
                json.dump(res, fh)
            os.unlink(os.path.join(self.spool, n))
        self.wf.collect_results()

    def adopt(self):
        cid = self.wf.propose_adoption('boss')
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval', self.wf.get(cid)['checks'])
        self.wf.set_setting('approval.single_admin_mode', True, 'boss')
        with self.assertRaises(ChangeError):          # an approver may not approve an adoption
            self.wf.approve(cid, self.user('appr'))
        self.wf.approve(cid, self.user('boss'), auth.totp_code(self.secret, int(time.time() // 30)),
                        'adopting the existing rule files')
        self.assertEqual(self.wf.get(cid)['state'], 'applying')
        self.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')
        self.wf.set_setting('approval.single_admin_mode', False, 'boss')
        return cid

    def test_not_adopted(self):
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose('add', 'exclusion', {}, 'x', 'op')
        self.assertEqual(cm.exception.code, 'not_adopted')

    def test_adopt_then_change_flow(self):
        self.adopt()
        self.assertTrue(self.wf.managed.adopted())
        items = self.wf.managed.items()
        self.assertEqual([i['rule_id'] for i in items if i['rule_id']], [10000, 10001, 10111, 10119, 10203, 10297, 10299])
        # a new exclusion gets the next free id in its range and never collides
        cid = self.wf.propose('add', 'exclusion', {'host': {'mode': 'exact', 'value': 'app.example.com'},
                                                   'path': {'mode': 'exact', 'value': '/search'},
                                                   'action': 'remove_target_by_id', 'rule_ids': [941100], 'targets': ['ARGS:q']},
                              'search box false positive', 'op')
        r = self.wf.get(cid)
        self.assertEqual((r['rule_id'], r['direction']), (10120, 'loosen'))   # 10119 is the highest used in 10100-10199
        self.wf.run_checks(cid)
        r = self.wf.get(cid)
        self.assertEqual(r['state'], 'pending_approval', r['checks'])
        self.assertIn('+SecRule REQUEST_HEADERS:Host', json.loads(r['checks'])['diff']['before'])
        with self.assertRaises(ChangeError) as cm:     # the proposer cannot approve
            self.wf.approve(cid, self.user('op'))
        self.assertEqual(cm.exception.code, 'own_change')
        self.wf.approve(cid, self.user('appr'), note='ok')
        self.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')
        it = self.wf.managed.item_by_rule(10120)
        self.assertEqual(it['kind'], 'exclusion')
        with open(os.path.join(self.mdir, 'before-crs.conf')) as fh:
            self.assertIn('id:10120,', fh.read())
        # disable it: tightening
        cid2 = self.wf.propose('disable', None, {}, 'not needed any more', 'op', item_id=it['id'])
        self.assertEqual(self.wf.get(cid2)['direction'], 'tighten')
        self.wf.run_checks(cid2)
        self.wf.approve(cid2, self.user('appr'))
        self.fake_apply()
        with open(os.path.join(self.mdir, 'before-crs.conf')) as fh:
            self.assertNotIn('id:10120,', fh.read())
        # delete -> tombstone; the id is not handed out again
        cid3 = self.wf.propose('delete', None, {}, 'remove', 'op', item_id=it['id'])
        self.wf.run_checks(cid3)
        self.wf.approve(cid3, self.user('appr'))
        self.fake_apply()
        self.assertEqual(self.wf.managed.next_rule_id('exclusion'), 10121)
        # roll back to the version right after the exclusion was added
        v_added = self.wf.get(cid)['applied_version']
        rb = self.wf.rollback(v_added, self.user('appr'), 'restore the exclusion')
        self.fake_apply()
        self.assertEqual(self.wf.get(rb)['state'], 'applied')
        it = self.wf.managed.item_by_rule(10120)
        self.assertEqual((it['deleted'], it['enabled']), (0, 1))
        self.assertEqual(self.wf.get(cid3)['state'], 'rolled_back')

    def test_failed_apply_and_drift_and_stale(self):
        self.adopt()
        spec = {'target': 'path', 'regex': r'^/wp-login\.php$', 'msg': 'WordPress login probe'}
        cid = self.wf.propose('add', 'confident_block', spec, 'probes', 'op',
                              tests=[{'expect': 403, 'source': 'external', 'host': 'app.example.com', 'path': '/wp-login.php'}])
        self.assertEqual(self.wf.get(cid)['rule_id'], 10204)
        self.wf.run_checks(cid)
        self.wf.approve(cid, self.user('appr'))
        self.fake_apply(ok=False)
        self.assertEqual(self.wf.get(cid)['state'], 'apply_failed')
        # a change prepared against an older version is checked again before it is applied
        c1 = self.wf.propose('add', 'redaction', {'fields': ['pin']}, 'r1', 'op')
        c2 = self.wf.propose('add', 'redaction', {'fields': ['otp']}, 'r2', 'op')
        self.wf.run_checks(c1)
        self.wf.run_checks(c2)
        self.wf.approve(c1, self.user('appr'))
        self.fake_apply()
        self.wf.approve(c2, self.user('appr'))
        self.assertEqual(self.wf.get(c2)['state'], 'checking')
        self.assertIn('stale', [x['action'] for x in self.wf.public(self.wf.get(c2), True)['log']])
        # manual edit of a managed file is detected
        with open(os.path.join(self.mdir, 'before-crs.conf'), 'a') as fh:
            fh.write('# hand edit\n')
        self.assertTrue(self.wf.managed.disk_state()['drift'])
        # ...and stops the next apply instead of silently overwriting the edit
        c3 = self.wf.propose('add', 'redaction', {'fields': ['pan']}, 'r3', 'op')
        self.wf.run_checks(c3)
        self.wf.approve(c3, self.user('appr'))
        self.assertEqual(self.wf.get(c3)['state'], 'apply_failed')
        self.assertIn('drift', self.wf.get(c3)['error'])
        self.assertEqual([n for n in os.listdir(self.spool) if n.endswith('.req')], [])
        self.assertTrue(self.app.db.q("SELECT 1 FROM audit WHERE action='change.apply_blocked_drift'"))
        cur = self.wf.managed.current_version()['version']
        with self.assertRaises(ChangeError) as e:
            self.wf.rollback(cur, self.app.auth.user_row('appr'), 'restore')
        self.assertEqual(e.exception.code, 'drift')
        # an approver may explicitly put jt-waf-mgr's files back (re-writing the current version)
        self.wf.rollback(cur, self.app.auth.user_row('appr'), 'restore after hand edit', overwrite_drift=True)
        self.assertTrue(self.app.db.q("SELECT 1 FROM audit WHERE action='change.drift_overwritten'"))
        self.fake_apply()
        self.assertFalse(self.wf.managed.disk_state()['drift'])

    def test_expected_disk_is_last_applied_version(self):
        self.adopt()
        c = self.wf.propose('add', 'redaction', {'fields': ['pin']}, 'r', 'op')
        self.wf.run_checks(c)
        self.wf.approve(c, self.user('appr'))
        req = [json.load(open(os.path.join(self.spool, n))) for n in os.listdir(self.spool) if n.endswith('.req')][0]
        hashes = json.loads(self.wf.managed.current_version()['hashes'])
        self.assertEqual(req['expected_disk'], {p: hashes[p] for p in req['files']})

    def test_evidence_blocks_and_override(self):
        self.adopt()
        with open(os.path.join(self.env.dir, 'app.example.com.access.log'), 'w') as fh:
            for ip, st in (('203.0.113.9', 404), ('198.51.100.7', 200), ('192.168.77.9', 404)):
                fh.write(json.dumps({'vhost': 'app.example.com', 'request': 'GET /backup.zip HTTP/1.1',
                                     'http_status': st, 'srcip': ip, 'user_agent': 'x'}) + '\n')
        cid = self.wf.propose('add', 'confident_block', {'target': 'path', 'regex': r'^/backup\.zip$', 'msg': 'backup file'},
                              'backup probes', 'op',
                              tests=[{'expect': 403, 'source': 'external', 'host': 'app.example.com', 'path': '/backup.zip'}])
        self.wf.run_checks(cid)
        r = self.wf.get(cid)
        ev = json.loads(r['checks'])['evidence']
        self.assertEqual((r['state'], ev['external_success'], ev['internal_other']), ('failed', 1, 1))
        self.wf.recheck(cid, self.user('op'), 'the 200 was the catch-all page; the internal hit was me testing')
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval')

    def test_auto_apply_tighten(self):
        self.adopt()
        self.wf.set_setting('apply.auto_tighten', True, 'boss')
        cid = self.wf.propose('add', 'confident_block', {'target': 'ua', 'regex': 'sqlmap', 'msg': 'sqlmap'}, 'tool', 'op',
                              tests=[{'expect': 403, 'source': 'external', 'host': 'app.example.com', 'path': '/',
                                      'headers': {'User-Agent': 'sqlmap/1.8'}}])
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'applying')
        # loosening is never applied automatically
        c2 = self.wf.propose('add', 'redaction', {'fields': ['pin']}, 'r', 'op')
        self.wf.run_checks(c2)
        self.assertEqual(self.wf.get(c2)['state'], 'pending_approval')

    def test_single_admin_loosening_needs_totp(self):
        self.adopt()
        self.wf.set_setting('approval.single_admin_mode', True, 'boss')
        cid = self.wf.propose('add', 'redaction', {'fields': ['pin']}, 'r', 'boss', role='admin')
        self.wf.run_checks(cid)
        with self.assertRaises(ChangeError) as cm:
            self.wf.approve(cid, self.user('boss'), '000000', 'a long enough note')
        self.assertEqual(cm.exception.code, 'totp_required')
        with self.assertRaises(ChangeError) as cm:
            self.wf.approve(cid, self.user('boss'), auth.totp_code(self.secret, int(time.time() // 30)), 'short')
        self.assertEqual(cm.exception.code, 'note_required')

    def test_raw_admin_only_and_api_cannot_approve(self):
        self.adopt()
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose('add', 'raw', {'text': 'SecRule ARGS "@rx x" "id:10150,phase:2,deny"'}, 'r', 'op', role='operator')
        self.assertEqual(cm.exception.code, 'raw_admin_only')
        cid = self.wf.propose('add', 'raw', {'text': 'SecRule ARGS "@rx zz" "id:10150,phase:2,deny,status:403"'}, 'r',
                              'boss', role='admin')
        self.assertEqual(self.wf.get(cid)['direction'], 'tighten')
        with self.assertRaises(ChangeError) as cm:     # id already in use
            self.wf.propose('add', 'raw', {'text': 'SecRule ARGS "@rx x" "id:10111,phase:2,deny"'}, 'r', 'boss', role='admin')
        self.assertEqual(cm.exception.code, 'rule_id_in_use')


class TestApplier(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='jtwaf-apply-')
        site = os.path.join(self.d, 'site')
        shutil.copytree(FIXTURE_SITE, site, symlinks=True)
        from jtwafmgr import config
        self.cfg = config.load(None, {'paths': {'nginx_conf': os.path.join(site, 'nginx.conf'), 'nginx_bin': '/bin/true'},
                                      'managed': {'dir': os.path.join(self.d, 'managed'), 'spool': os.path.join(self.d, 'spool')}})
        self.site = site
        self.ap = Applier(self.cfg)
        self.ap.check_binary = lambda: None
        self.ap.reload = lambda wait: 'reloaded (test)'
        self.ap.test_config = lambda: 'ok'
        self.ap.health = lambda urls: {u: 200 for u in urls}

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def request(self, files, **extra):
        import hashlib
        req = {'action': 'apply', 'version': 1, 'change_id': 1, 'files': files,
               'sha256': {p: hashlib.sha256(t.encode()).hexdigest() for p, t in files.items()},
               'expected_disk': {'before': None, 'after': None}, 'health_urls': []}
        req.update(extra)
        os.makedirs(self.cfg['managed']['spool'], exist_ok=True)
        path = os.path.join(self.cfg['managed']['spool'], 'v1-c1.req')
        with open(path, 'w') as fh:
            json.dump(req, fh)
        return path

    def files(self, before_body='SecAction "id:10150,phase:1,pass,nolog"\n'):
        h = '# Generated by jt-waf-mgr test\n# x\n# y\n\n'
        return {'before': h + before_body, 'after': h + '\n'}

    def result(self):
        self.ap.process()
        with open(os.path.join(self.cfg['managed']['spool'], 'v1-c1.result')) as fh:
            return json.load(fh)

    def test_adopt_rewrites_main_include(self):
        main = os.path.join(self.site, 'modsec', 'main.conf')
        self.request(self.files(), adopt={'main_conf': main, 'replace': {
            os.path.join(self.site, 'modsec', 'local-before-crs.conf'): os.path.join(self.cfg['managed']['dir'], 'before-crs.conf'),
            os.path.join(self.site, 'modsec', 'local-after-crs.conf'): os.path.join(self.cfg['managed']['dir'], 'after-crs.conf')}})
        res = self.result()
        self.assertEqual(res['result'], 'ok', res)
        text = open(main).read()
        self.assertIn('Include %s/before-crs.conf' % self.cfg['managed']['dir'], text)
        self.assertNotIn('local-before-crs.conf', text)
        self.assertFalse(os.path.exists(os.path.join(self.cfg['managed']['spool'], 'v1-c1.req')))

    def test_refuses_forbidden_content_and_bad_checksum(self):
        self.request(self.files('SecRuleEngine Off\n'), adopt=None)
        res = self.result()
        self.assertEqual((res['result'], res['step']), ('failed', 'validate'))
        path = self.request(self.files())
        req = json.load(open(path))
        req['sha256']['before'] = '0' * 64
        json.dump(req, open(path, 'w'))
        self.assertEqual(self.result()['step'], 'request')

    def test_refuses_foreign_paths_in_adopt(self):
        self.request(self.files(), adopt={'main_conf': '/etc/passwd', 'replace': {'/x': '/etc/shadow'}})
        self.assertEqual(self.result()['step'], 'request')

    def test_drift_and_rollback_on_failure(self):
        md = self.cfg['managed']['dir']
        os.makedirs(md)
        for f in ('before-crs.conf', 'after-crs.conf'):
            with open(os.path.join(md, f), 'w') as fh:
                fh.write('# Generated by jt-waf-mgr old\n\n')
        self.request(self.files())   # expected_disk None, but the files exist with other content
        self.assertEqual(self.result()['step'], 'drift')
        import hashlib
        cur = {p: hashlib.sha256(open(os.path.join(md, f), 'rb').read()).hexdigest()
               for p, f in (('before', 'before-crs.conf'), ('after', 'after-crs.conf'))}
        self.request(self.files(), expected_disk=cur)

        def bad():
            raise Fail('nginx_t', 'nginx -t failed')
        self.ap.test_config = bad
        res = self.result()
        self.assertEqual(res['step'], 'nginx_t')
        self.assertIn('restored', res['summary'])
        self.assertEqual(open(os.path.join(md, 'before-crs.conf')).read(), '# Generated by jt-waf-mgr old\n\n')

    def test_health_change_rolls_back(self):
        calls = iter([{'https://a.example.com/': 200}, {'https://a.example.com/': 502}])
        self.ap.health = lambda urls: next(calls)
        self.request(self.files(), health_urls=['https://a.example.com/'])
        res = self.result()
        self.assertEqual(res['step'], 'health')
        self.assertFalse(os.path.exists(os.path.join(self.cfg['managed']['dir'], 'before-crs.conf')))


class TestSandboxBuild(unittest.TestCase):
    def test_config_rewrites(self):
        env = TempEnv(managed={'sandbox_dir': ''})
        try:
            app = App(env.cfg)
            sb = app.workflow.sandbox
            root = tempfile.mkdtemp(dir=env.dir)
            b = os.path.join(FIXTURE_SITE, 'modsec', 'local-before-crs.conf')
            port = sb.build(root, {b: '# candidate\nSecAction "id:10150,phase:1,pass,nolog"\n'})
            main = open(os.path.join(root, 'conf', 'main-0.conf')).read()
            self.assertIn('cand-local-before-crs.conf', main)
            self.assertIn(os.path.join(FIXTURE_SITE, 'modsec', 'crs-setup.conf'), main)
            rw = [f for f in os.listdir(os.path.join(root, 'conf')) if f.startswith('rw-')]
            self.assertEqual(len(rw), 1)
            body = open(os.path.join(root, 'conf', rw[0])).read()
            self.assertIn('SecAuditLog %s/logs/audit.log' % root, body)
            self.assertNotIn('/var/log/modsecurity', body)
            nc = open(os.path.join(root, 'conf', 'nginx.conf')).read()
            self.assertIn('listen 127.0.0.1:%d;' % port, nc)
            self.assertIn('real_ip_header X-Forwarded-For', nc)
            self.assertNotIn('user ', nc)
        finally:
            env.cleanup()

    def test_evaluate(self):
        from jtwafmgr.sandbox import evaluate
        cfg = TempEnv().cfg
        cases = [{'host': 'a.example.com', 'path': '/x', 'expect': 403},
                 {'host': 'a.example.com', 'path': '/y', 'expect': 403},
                 {'host': 'a.example.com', 'path': '/z', 'expect': 'not403', 'origin': 'regression'},
                 {'host': 'a.example.com', 'path': '/q', 'expect': 200, 'absent_rules': [930120]}]
        res = [{'status': 403, 'rules': [10203, 949110]}, {'status': 403, 'rules': [10203, 10299]},
               {'status': 200, 'rules': []}, {'status': 200, 'rules': [930120]}]
        out = evaluate(cases, res, cfg)
        self.assertEqual((out['ok'], out['failed']), (False, 2))


if __name__ == '__main__':
    unittest.main()
