"""Whether each loaded rule really runs (rules list, CRS page): removed, removed for some sites, above the paranoia
level, on. Synthetic site only."""
import json
import os
import shutil
import tempfile
import unittest

from jtwafmgr import config
from jtwafmgr.modsecconf import ModsecConfig
from jtwafmgr.nginxconf import NginxConfig
from tests.helpers import FIXTURE_SITE, TempEnv, rd, wr


def site_copy(d):
    site = os.path.join(d, 'site')
    shutil.copytree(FIXTURE_SITE, site, symlinks=True)
    crs = os.path.join(site, 'modsec', 'crs', 'rules', 'REQUEST-930-APPLICATION-ATTACK-LFI.conf')
    wr(crs, rd(crs) + '\nSecRule ARGS "@rx x" "id:930130,phase:2,block,msg:\'Restricted File Access Attempt\','
                      'tag:\'attack-lfi\',tag:\'paranoia-level/2\',tag:\'OWASP_CRS\'"\n'
                      'SecRule ARGS "@rx y" "id:930140,phase:2,block,msg:\'Sensitive file\',tag:\'attack-lfi\','
                      'tag:\'paranoia-level/1\',tag:\'custom-off\'"\n')
    # CRS's own exception for a few internal requests (like 905100): not a site exclusion
    wr(crs, rd(crs) + 'SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "id:905100,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS"\n'
                      'SecRule ARGS "@rx z" "id:930150,phase:2,block,msg:\'x\',tag:\'attack-lfi\',tag:\'paranoia-level/1\','
                      'tag:\'OWASP_CRS\'"\n')
    before = os.path.join(site, 'modsec', 'local-before-crs.conf')
    wr(before, rd(before) + '\nSecRule REQUEST_HEADERS:Host "@streq app.example.com" '
                            '"id:10150,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=930120"\n')
    after = os.path.join(site, 'modsec', 'local-after-crs.conf')
    wr(after, rd(after) + '\nSecRuleRemoveByTag "custom-off"\n')
    return site


class TestRuleStates(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='jtwaf-states-')
        self.site = site_copy(self.d)
        self.cfg = config.load(None, {'paths': {'nginx_conf': os.path.join(self.site, 'nginx.conf')}})

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_states(self):
        m = ModsecConfig(NginxConfig(self.cfg['paths']['nginx_conf']), self.cfg)
        st = m.rule_states()
        self.assertEqual(st[930110]['state'], 'on')
        self.assertEqual(st[930150]['state'], 'on')            # CRS's own localhost exception is not a site exclusion
        self.assertEqual((st[930120]['state'], st[930120]['hosts']), ('partial', ['app.example.com']))   # one site
        self.assertEqual((st[930130]['state'], st[930130]['level']), ('inactive', 2))                   # paranoia 2 > 1
        self.assertEqual(st[930140]['state'], 'off')                                                     # by tag
        self.assertIn('local-after-crs.conf:', st[930140]['where'])
        self.assertIs(m.rule_states(), st)                                                               # cached


class TestRulesApi(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        site = site_copy(self.env.dir)
        self.env.cfg.data['paths']['nginx_conf'] = os.path.join(site, 'nginx.conf')
        from jtwafmgr.app import App
        from jtwafmgr.web.api import rules
        self.app = App(self.env.cfg)
        self.rules = rules

    def tearDown(self):
        self.env.cleanup()

    def call(self, **q):
        class Req:
            query = {k: str(v) for k, v in q.items()}
        return json.loads(self.rules(self.app, Req()).body)

    def test_crs_states_families_and_summary(self):
        r = self.call(source='crs')
        by = {d['id']: d for d in r['items'] if d['id']}
        self.assertEqual((by[930120]['state'], by[930120]['family']), ('partial', 'lfi'))
        lfi = next(c for c in r['summary'] if c['key'] == 'lfi')
        self.assertEqual((lfi['on'], lfi['off'], lfi['partial'], lfi['inactive']), (2, 1, 1, 1))
        self.assertEqual([d['id'] for d in self.call(source='crs', state='inactive')['items']], [930130])
        self.assertEqual({d['id'] for d in self.call(source='crs', family='lfi')['items']}, {930110, 930120, 930130, 930140, 930150})

    def test_bad_state_is_refused(self):
        from jtwafmgr.web.server import ApiError
        with self.assertRaises(ApiError):
            self.call(source='crs', state='maybe')


if __name__ == '__main__':
    unittest.main()
