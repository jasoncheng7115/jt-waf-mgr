"""The WAF decision model (jtwafmgr/decision.py) and GET /api/v1/waf/model. Synthetic data only."""
import json
import os
import shutil
import tempfile
import unittest

from jtwafmgr.app import App
from jtwafmgr.decision import model
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv
from tests.test_api import PW, Client

INTERNAL = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8']
CRS_EVAL = ('SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" '
            '"id:949110,phase:2,deny,t:none,msg:\'Inbound Anomaly Score Exceeded\',ver:\'OWASP_CRS/4.30.0\','
            'severity:\'CRITICAL\'"\n')
CRS_DETECT = ('SecRule ARGS "@rx x" "id:941100,phase:2,block,t:none,msg:\'XSS\',tag:\'paranoia-level/1\','
              'severity:\'CRITICAL\',setvar:\'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}\'"\n'
              'SecRule ARGS "@rx y" "id:942200,phase:2,block,t:none,msg:\'SQLi\',tag:\'paranoia-level/2\','
              'severity:\'WARNING\',setvar:\'tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}\'"\n'
              'SecRule ARGS "@rx z" "id:920300,phase:2,block,t:none,msg:\'Header\',tag:\'paranoia-level/1\','
              'severity:\'NOTICE\',setvar:\'tx.inbound_anomaly_score_pl1=+%{tx.notice_anomaly_score}\'"\n')


def fixture_model(**over):
    env = TempEnv(**over)
    try:
        return model(App(env.cfg))
    finally:
        env.cleanup()


class SyntheticSite:
    """A minimal nginx + ModSecurity tree written to a temp dir."""

    def __init__(self, engine='DetectionOnly', setup='', before='', after='', vhost_extra=''):
        self.dir = tempfile.mkdtemp(prefix='jtwaf-decision-')
        w = self.write
        w('nginx.conf', 'events {}\nhttp {\n modsecurity off;\n modsecurity_rules_file modsec/main.conf;\n'
                        ' server { listen 443; server_name www.example.com; modsecurity on;\n'
                        '  location / { return 200; }\n%s }\n'
                        ' server { listen 443; server_name off.example.com; location / { return 200; } }\n}\n'
          % vhost_extra)
        w('modsec/main.conf', 'Include modsecurity.conf\nInclude crs-setup.conf\nInclude site-before.conf\n'
                              'Include crs/rules/*.conf\nInclude site-after.conf\n')
        w('modsec/modsecurity.conf', 'SecRuleEngine %s\nSecRequestBodyAccess On\nSecAuditLogFormat JSON\n' % engine)
        w('modsec/crs-setup.conf', 'SecDefaultAction "phase:2,log,auditlog,pass"\n' + setup)
        w('modsec/site-before.conf', before)
        w('modsec/site-after.conf', after)
        w('modsec/crs/rules/REQUEST-941-XSS.conf', CRS_DETECT)
        w('modsec/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf', CRS_EVAL)

    def write(self, rel, text):
        p = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w') as fh:
            fh.write(text)

    def model(self):
        env = TempEnv(paths={'nginx_conf': os.path.join(self.dir, 'nginx.conf')}, network={'internal': INTERNAL})
        try:
            return model(App(env.cfg))
        finally:
            env.cleanup()
            shutil.rmtree(self.dir, ignore_errors=True)


def rule(md, rid):
    return next(r for r in md['rules'] if r['id'] == rid)


def stage(md, key):
    return next((s for s in md['stages'] if s['key'] == key), None)


class TestFixtureModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.md = fixture_model()

    def test_json_and_shape(self):
        json.dumps(self.md)
        for k in ('engine', 'crs', 'scoring', 'stages', 'rules', 'summary', 'facts', 'vhosts'):
            self.assertIn(k, self.md)
        keys = [s['key'] for s in self.md['stages']]
        self.assertEqual(keys[0], 'not_inspected')
        self.assertEqual(keys[-1], 'outcome')
        # CRS scores, then 949110 decides, then the engine mode, then the site rules after CRS
        for a, b in (('crs_detect', 'crs_eval'), ('crs_eval', 'engine'), ('engine', 'threshold_block'),
                     ('threshold_block', 'fallback'), ('exclusions', 'crs_detect'), ('confident', 'crs_detect')):
            self.assertLess(keys.index(a), keys.index(b), (a, b))
        for s in self.md['stages']:
            self.assertIn(s['effect'], ('blocks', 'logs', 'scores', 'loosens', 'not_inspected', 'info'))
            self.assertEqual(set(s['per_source']), {'external', 'internal'})

    def test_detection_only_but_external_blocked(self):
        md = self.md
        self.assertEqual(md['engine']['global'], 'DetectionOnly')
        ext, intl = md['summary']['external'], md['summary']['internal']
        self.assertEqual(ext['mode'], 'blocking')
        self.assertEqual(ext['min_block_score'], 5)
        self.assertEqual(ext['over_by'], 10299)                 # refused by the fallback deny ...
        self.assertEqual(ext['over_enabled_by'], [10297])       # ... after the threshold rule turned the engine on
        self.assertIn(949110, ext['over_would_block_by'])       # 949110 alone only logs in DetectionOnly
        self.assertEqual(ext['below_result'], 'logged')
        self.assertEqual((ext['confident_blocked'], ext['confident_total']), (1, 1))
        self.assertEqual(intl['mode'], 'logging')
        self.assertIsNone(intl['min_block_score'])
        self.assertEqual(intl['min_flag_score'], 5)
        self.assertEqual(intl['confident_applies'], 0)
        facts = {f['key']: f for f in md['facts']}
        self.assertEqual(facts['effective_external']['value'], 'blocking')
        self.assertEqual(facts['effective_internal']['value'], 'logging')

    def test_rule_roles_and_effects(self):
        md = self.md
        self.assertEqual(rule(md, 10203)['role'], 'confident_block')
        self.assertEqual(rule(md, 10203)['effect'], {'external': 'blocks', 'internal': 'not_applicable'})
        self.assertEqual(rule(md, 10297)['role'], 'threshold_block')
        self.assertEqual(rule(md, 10297)['effect']['internal'], 'not_applicable')
        self.assertEqual(rule(md, 10299)['role'], 'fallback_deny')
        self.assertEqual(rule(md, 10111)['role'], 'exclusion')
        self.assertEqual(rule(md, 10111)['effect']['external'], 'loosens')
        self.assertEqual(rule(md, 10111)['hosts'], ['sso.example.com'])
        self.assertEqual(rule(md, 949110)['stage'], 'crs_eval')
        self.assertEqual(rule(md, 949110)['effects']['external'], ['blocks', 'logs'])
        self.assertEqual(rule(md, 949110)['effect']['internal'], 'logs')
        # the base rule's deny only logs while the engine is DetectionOnly
        self.assertEqual(rule(md, 200002)['role'], 'deny_rule')
        self.assertEqual(rule(md, 200002)['effect']['external'], 'logs')
        src = next(c for c in rule(md, 10203)['conditions'] if c['type'] == 'source')
        self.assertEqual(src['applies'], 'external')
        # the default internal list is wider than the one in the fixture's rules
        self.assertIn('::1/128', src['missing_internal'])
        self.assertIn('source_list_mismatch', [f['key'] for f in md['facts']])
        removals = [r for r in md['rules'] if r['source'] == 'config']
        self.assertEqual({r['directive'] for r in removals}, {'SecRuleRemoveById', 'SecRuleUpdateTargetById'})

    def test_vhosts_and_contexts(self):
        md = self.md
        ni = stage(md, 'not_inspected')['data']
        self.assertIn({'server': 'static.example.com', 'waf': 'off'}, ni['servers'])
        self.assertIn({'server': 'app.example.com', 'location': '/remote.php/dav'}, ni['locations'])
        ctx = md['engine']['contexts']
        self.assertTrue(ctx[0]['default'])
        self.assertEqual(ctx[0]['engine'], 'DetectionOnly')
        block = next(c for c in ctx if c['engine'] == 'On')
        self.assertIn('intranet.example.com', block['servers'])
        # with SecRuleEngine On in the vhost, internal sources are blocked over the threshold too
        self.assertEqual(block['outcomes']['internal']['over']['result'], 'blocked')
        self.assertEqual(block['outcomes']['internal']['over']['by'], 949110)
        self.assertEqual(rule(md, 10100)['role'], 'threshold_override')
        self.assertEqual(md['scoring']['threshold_overrides'][0]['set'], {'outbound': 10000})

    def test_scoring_numbers(self):
        sc = self.md['scoring']
        self.assertEqual(sc['threshold'], 5)
        self.assertEqual(sc['points'], {'critical': 5, 'error': 4, 'warning': 3, 'notice': 2})
        self.assertEqual(sc['levels'][0]['level'], 1)
        self.assertEqual(sc['levels'][0]['state'], 'blocking')
        self.assertEqual(sc['levels'][0]['counts']['critical'], 2)    # 930110, 930120 (no tag: level 1)
        ex = {(e['severity'], e['count']): e for e in sc['examples']}
        self.assertEqual(ex[('critical', 1)]['outcome']['external']['result'], 'blocked')
        self.assertEqual(ex[('critical', 1)]['outcome']['internal']['result'], 'logged')
        self.assertEqual(ex[('warning', 1)]['outcome']['external']['result'], 'logged')
        self.assertEqual(ex[('warning', 2)]['score'], 6)


class TestOtherSites(unittest.TestCase):
    def test_engine_on_blocks_everyone_by_crs(self):
        md = SyntheticSite(engine='On').model()
        for src in ('external', 'internal'):
            self.assertEqual(md['summary'][src]['mode'], 'blocking')
            self.assertEqual(md['summary'][src]['over_by'], 949110)
        self.assertEqual(stage(md, 'crs_eval')['per_source'], {'external': 'blocks', 'internal': 'blocks'})
        self.assertIsNone(stage(md, 'threshold_block'))
        self.assertEqual([s['server'] for s in stage(md, 'not_inspected')['data']['servers']], ['off.example.com'])

    def test_detection_only_without_site_rules_never_blocks(self):
        md = SyntheticSite().model()
        for src in ('external', 'internal'):
            self.assertEqual(md['summary'][src]['mode'], 'logging')
            self.assertIsNone(md['summary'][src]['min_block_score'])

    def test_engine_off(self):
        md = SyntheticSite(engine='Off').model()
        self.assertEqual(md['summary']['external']['mode'], 'off')

    def test_other_ids_points_and_threshold_from_setup(self):
        # a different numbering, threshold 7 and custom points: nothing is assumed about the first site
        setup = ('SecAction "id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=7,'
                 'setvar:tx.outbound_anomaly_score_threshold=6"\n'
                 'SecAction "id:900100,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=7,'
                 'setvar:tx.warning_anomaly_score=2"\n'
                 'SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=2"\n')
        before = ('SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap" "id:50010,phase:1,pass,log,msg:\'scanner\',chain"\n'
                  '    SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8" '
                  '"t:none,setvar:tx.ext_hit=1,ctl:ruleEngine=On"\n'
                  'SecRule REQUEST_FILENAME "@beginsWith /upload" "id:50020,phase:1,pass,nolog,ctl:ruleRemoveById=941100"\n'
                  'SecRule REQUEST_FILENAME "@beginsWith /x" "id:50030,phase:1,pass,nolog,setvar:tx.something=+3"\n'
                  'SecRule REQUEST_FILENAME "@beginsWith /y" "id:50040,phase:1,pass,log,msg:\'just a note\'"\n')
        after = ('SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" "id:50090,phase:2,pass,nolog,chain"\n'
                 '    SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8" '
                 '"t:none,ctl:ruleEngine=On,setvar:tx.ext_hit=1"\n'
                 'SecRule TX:EXT_HIT "@eq 1" "id:50099,phase:2,deny,status:403,log,msg:\'refused\'"\n')
        md = SyntheticSite(setup=setup, before=before, after=after).model()
        sc = md['scoring']
        self.assertEqual(sc['threshold'], 7)
        self.assertEqual(sc['points']['critical'], 7)
        self.assertEqual(sc['points_from']['critical'], 'setup')
        self.assertEqual(sc['points']['warning'], 2)
        self.assertEqual(sc['points']['error'], 4)
        self.assertEqual([lv['state'] for lv in sc['levels']], ['blocking', 'blocking', 'inactive', 'inactive'])
        self.assertEqual(sc['levels'][1]['counts']['warning'], 1)
        self.assertEqual(rule(md, 50010)['role'], 'confident_block')
        self.assertEqual(rule(md, 50020)['role'], 'exclusion')
        self.assertEqual(rule(md, 50020)['weakens'], [])
        self.assertEqual(rule(md, 50090)['role'], 'threshold_block')
        self.assertEqual(rule(md, 50099)['role'], 'fallback_deny')
        self.assertEqual(rule(md, 50040)['role'], 'other')
        self.assertIn(50040, md['unclassified'])
        ext = md['summary']['external']
        self.assertEqual(ext['min_block_score'], 7)
        self.assertEqual(ext['over_by'], 50099)
        self.assertEqual(ext['confident_by'], 50099)       # under the threshold: the fallback refuses it
        self.assertEqual(md['summary']['internal']['mode'], 'logging')
        ex = {(e['severity'], e['count']): e for e in sc['examples']}
        self.assertEqual(ex[('notice', 4)]['score'], 8)
        self.assertEqual(ex[('notice', 4)]['outcome']['external']['result'], 'blocked')

    def test_exclusion_that_removes_a_blocking_rule_is_flagged(self):
        before = ('SecRule REQUEST_HEADERS:Host "@rx ^mail\\.example\\.com$" "id:50100,phase:1,pass,nolog,'
                  'ctl:ruleRemoveById=50090"\n')
        after = ('SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" '
                 '"id:50090,phase:2,deny,status:403,log,chain"\n'
                 '    SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8" '
                 '"t:none,ctl:ruleEngine=On"\n'
                 'SecRuleRemoveById 949110\n')
        md = SyntheticSite(before=before, after=after).model()
        self.assertEqual(rule(md, 50100)['weakens'], [50090])
        self.assertEqual(rule(md, 50100)['hosts'], ['mail.example.com'])
        self.assertIn(50090, stage(md, 'exclusions')['data']['weakens'])
        self.assertIn(949110, stage(md, 'exclusions')['data']['weakens'])
        self.assertEqual(rule(md, 949110)['effect']['external'], 'removed')
        # 50090 denies directly once it has turned the engine on
        self.assertEqual(md['summary']['external']['over_by'], 50090)

    def test_allow_rule_loosens(self):
        before = ('SecRule REMOTE_ADDR "@ipMatch 192.0.2.10" "id:50200,phase:1,allow,nolog"\n')
        md = SyntheticSite(engine='On', before=before).model()
        self.assertEqual(rule(md, 50200)['role'], 'allow')
        self.assertEqual(rule(md, 50200)['stage'], 'exclusions')


class TestRoute(unittest.TestCase):
    def test_get_waf_model(self):
        env = TempEnv()
        app = App(env.cfg)
        app.auth.create_user('viewer1', 'viewer', password=PW)
        srv, _ = start_background(app)
        try:
            port = srv.server_address[1]
            self.assertEqual(Client(port).req('GET', '/api/v1/waf/model')[0], 401)
            c = Client(port)
            c.login('viewer1')
            st, obj, _ = c.req('GET', '/api/v1/waf/model')
            self.assertEqual(st, 200)
            self.assertEqual(obj['summary']['external']['mode'], 'blocking')
            self.assertEqual(c.req('POST', '/api/v1/waf/model', {})[0], 405)
        finally:
            srv.shutdown()
            srv.server_close()
            env.cleanup()


if __name__ == '__main__':
    unittest.main()
