import os
import tempfile
import unittest

from jtwafmgr import config
from jtwafmgr.modsecconf import ModsecConfig, readable_host, split_actions, split_args
from jtwafmgr.nginxconf import NginxConfig, tokenize
from tests.helpers import FIXTURE_SITE


class TestNginx(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.n = NginxConfig(os.path.join(FIXTURE_SITE, 'nginx.conf'))
        cls.servers = {s['server_names'][0]: s for s in cls.n.servers()}

    def test_no_errors(self):
        self.assertEqual(self.n.errors, [])

    def test_waf_states(self):
        self.assertEqual(self.servers['app.example.com']['waf'], 'on')
        self.assertEqual(self.servers['intranet.example.com']['waf'], 'block')
        self.assertEqual(self.servers['static.example.com']['waf'], 'off')
        self.assertEqual(self.servers['intranet.example.com']['inline_rule_ids'], [10100])

    def test_bypass_and_limits(self):
        app = self.servers['app.example.com']
        self.assertEqual([b['location'] for b in app['bypass']], ['/remote.php/dav'])
        self.assertEqual(app['body_limit'], '2G')
        self.assertEqual(self.servers['static.example.com']['body_limit'], '10m')  # inherited from http
        self.assertIn('location ~* ^/admin/ { return 403; }', app['restrictions'])
        self.assertEqual(app['upstreams'], ['http://192.0.2.10:8080'])
        self.assertTrue(app['realip'])

    def test_restrictions(self):
        self.assertIn('if ($lan = 0) { return 444; }', self.servers['intranet.example.com']['restrictions'])
        self.assertEqual(self.servers['static.example.com']['restrictions'], ['allow 192.0.2.0/24', 'deny all'])
        self.assertEqual(self.servers['intranet.example.com']['server_names'], ['intranet.example.com', 'intra.example.com'])

    def test_tokenizer_quotes(self):
        toks = [t for t, _, q in tokenize("a 'b c' \"d\\\"e\" f;# x\n") if t != '#']
        self.assertEqual(toks, ['a', 'b c', 'd"e', 'f', ';'])

    def test_broken_file_reports_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'nginx.conf')
            with open(p, 'w') as fh:
                fh.write('http { server { listen 80; }\n')
            n = NginxConfig(p)
            self.assertTrue(n.errors)

    def test_include_loop_is_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'nginx.conf')
            with open(p, 'w') as fh:
                fh.write('include nginx.conf;\n')
            n = NginxConfig(p)
            self.assertTrue(any('limit' in e for e in n.errors))


class TestModsec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = config.load()
        cls.n = NginxConfig(os.path.join(FIXTURE_SITE, 'nginx.conf'))
        cls.m = ModsecConfig(cls.n, cls.cfg)
        cls.rules = {r.id: cls.m.rule_dict(r) for r in cls.m.rules}

    def test_rules_loaded(self):
        self.assertEqual(self.m.errors, [])
        for rid in (10000, 10001, 10111, 10119, 10203, 10297, 10299, 930110, 930120, 949110, 200002, 10100):
            self.assertIn(rid, self.rules)

    def test_sources(self):
        self.assertEqual(self.rules[10111]['source'], 'local')
        self.assertEqual(self.rules[930110]['source'], 'crs')
        self.assertEqual(self.rules[200002]['source'], 'base')
        self.assertEqual(self.rules[9508100]['source'], 'plugin')
        self.assertEqual(self.rules[10100]['source'], 'vhost_inline')

    def test_categories(self):
        self.assertEqual(self.rules[10111]['category'], 'exclusion')
        self.assertEqual(self.rules[10119]['category'], 'redaction')
        self.assertEqual(self.rules[10203]['category'], 'confident_block')
        self.assertEqual(self.rules[10000]['category'], 'plugin_toggle')
        self.assertEqual(self.rules[10297]['category'], 'system')
        self.assertEqual(self.rules[10299]['category'], 'system')

    def test_chain_and_comment(self):
        r = self.rules[10111]
        self.assertIn('ctl:ruleRemoveTargetById=930120;ARGS:redirect_uri', r['text'])
        self.assertIn('OIDC redirect', r['comment'])
        self.assertEqual(r['hosts'], ['sso.example.com'])
        self.assertEqual(r['phase'], 1)

    def test_msg_with_comma_and_tags(self):
        r = self.rules[930110]
        self.assertEqual(r['msg'], 'Path Traversal Attack (/../) or (/.../)')
        self.assertIn('attack-lfi', r['tags'])
        self.assertEqual(r['disruptive'], 'block')
        self.assertEqual(self.rules[10299]['msg'], 'jt confident block: refused (under the CRS threshold)')

    def test_removals(self):
        d = {x['directive']: x for x in self.m.removals}
        self.assertEqual(d['SecRuleUpdateTargetById']['target_ids'], [942100])
        self.assertEqual(d['SecRuleUpdateTargetById']['args'], '!ARGS:search')
        self.assertEqual(d['SecRuleRemoveById']['target_ids'], [920350])

    def test_crs_status(self):
        s = self.m.crs_status()
        self.assertEqual(s['version'], '4.30.0')
        self.assertEqual(s['engine_mode'], 'DetectionOnly')  # the vhost's inline SecRuleEngine On is not global
        self.assertEqual(s['inbound_threshold'], 5)
        self.assertEqual(s['request_body_limit'], 13107200)
        self.assertEqual(s['audit']['format'], 'JSON')
        self.assertEqual([p['name'] for p in s['plugins']], ['nextcloud-rule-exclusions'])
        self.assertTrue(self.m.external_threshold_block())

    def test_helpers(self):
        self.assertEqual(readable_host(r'^app\.example\.com(?::[0-9]+)?$'), 'app.example.com')
        self.assertEqual(readable_host(r'^mail[12]?\.example\.com(?::[0-9]+)?$'), r'^mail[12]?\.example\.com$')
        self.assertEqual(split_args('SecRule A "@rx \\"x\\"" "id:1"'), ['SecRule', 'A', '@rx "x"', 'id:1'])
        self.assertEqual(split_actions("id:1,msg:'a, b',t:none"), [('id', '1'), ('msg', 'a, b'), ('t', 'none')])

    def test_per_vhost_rules_file_warning(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'r.conf'), 'w') as fh:
                fh.write('SecRuleEngine DetectionOnly\n')
            with open(os.path.join(d, 'nginx.conf'), 'w') as fh:
                fh.write('http { server { server_name a.example.com; modsecurity on; modsecurity_rules_file r.conf; } }\n')
            m = ModsecConfig(NginxConfig(os.path.join(d, 'nginx.conf')), self.cfg)
            self.assertTrue(any(w.startswith('rules_file_per_vhost') for w in m.warnings))


if __name__ == '__main__':
    unittest.main()
