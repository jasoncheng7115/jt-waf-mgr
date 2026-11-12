"""Settings edited in the web interface: validation, overlay at start, secrets write-only, GeoIP hand-over,
and the LLM client against a fake OpenAI-compatible server."""
import http.server
import json
import os
import threading
import unittest

from jtwafmgr import llm, uisettings
from jtwafmgr.app import App
from tests.helpers import TempEnv


class TestUiSettings(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.env.cleanup()

    def test_validate_store_apply_and_secrets(self):
        ch = uisettings.set_many(self.app, {'geoip.account_id': '123456', 'geoip.license_key': 'abcDEF_123456789',
                                            'network.known_scanners': ['192.168.77.7', '192.168.77.0/24'],
                                            'compliance.level': 'medium'}, 'admin1')
        self.assertEqual(sorted(ch), ['compliance.level', 'geoip.account_id', 'geoip.license_key', 'network.known_scanners'])
        pub = uisettings.public(self.app.cfg, self.app.db)
        self.assertNotIn('value', pub['geoip.license_key'])
        self.assertTrue(pub['geoip.license_key']['set'])
        self.assertNotIn('abcDEF', json.dumps(pub))
        self.assertEqual(pub['network.known_scanners']['value'], ['192.168.77.7/32', '192.168.77.0/24'])
        self.assertEqual(pub['compliance.level']['source'], 'ui')
        # derived networks refreshed in place
        self.assertTrue(any(str(n) == '192.168.77.0/24' for n in self.app.cfg.known_scanners))
        # the GeoIP updater gets the credentials as files (0600)
        d = self.app.cfg['geoip']['dir']
        self.assertEqual(oct(os.stat(os.path.join(d, 'license.key')).st_mode & 0o777), '0o600')
        from jtwafmgr import geoip
        self.assertEqual(geoip.credentials(dict(self.env.cfg['geoip'], account_id='', license_key='')), ('123456', 'abcDEF_123456789'))
        # a secret change is audited without its value
        rows = self.app.db.q("SELECT details FROM audit WHERE action='settings.changed'")
        self.assertFalse(any('abcDEF' in r['details'] for r in rows))
        # survives a restart (overlay at start)
        from jtwafmgr import config as _c
        app2 = App(_c.load(None, {k: dict(v) for k, v in self.env.cfg.data.items() if k in ('paths', 'integrity', 'backup', 'geoip', 'managed', 'syslog')}))
        self.assertEqual(app2.cfg['compliance']['level'], 'medium')

    def test_invalid_values_refused(self):
        for k, v in (('auth.lockout_threshold', 1), ('geoip.account_id', 'abc'), ('network.known_scanners', ['not-an-ip']),
                     ('llm.url', 'ftp://x'), ('compliance.level', 'extreme'), ('nope.key', 1), ('ui.login_notice', 5)):
            with self.assertRaises(uisettings.SettingError, msg=k):
                uisettings.set_many(self.app, {k: v}, 'admin1')

    def test_geoip_enabled_takes_effect_without_restart(self):
        self.assertTrue(hasattr(self.app, 'geoip'))
        uisettings.set_many(self.app, {'geoip.enabled': False}, 'admin1')
        self.assertFalse(self.app.geoip.enabled)
        self.assertFalse(self.app.geoip.status()['enabled'])
        uisettings.set_many(self.app, {'geoip.enabled': True}, 'admin1')
        self.assertTrue(self.app.geoip.enabled)

    def test_interval_in_minutes_and_legacy_hours(self):
        with self.assertRaises(uisettings.SettingError):
            uisettings.set_many(self.app, {'analyst.interval_minutes': 9}, 'a')          # at least 10 minutes
        uisettings.set_many(self.app, {'analyst.interval_minutes': 10}, 'a')
        self.assertEqual(self.app.cfg['analyst']['interval_minutes'], 10)
        # a value stored by 0.3.4 in hours is read as minutes
        self.app.db.x("DELETE FROM settings WHERE key='ui.analyst.interval_minutes'")
        self.app.db.x("INSERT INTO settings(key, value, updated_by, updated_at) VALUES ('ui.analyst.interval_hours', '2', 'a', 0)")
        self.assertEqual(uisettings.stored(self.app.db)['analyst.interval_minutes']['value'], 120)

    def test_secret_none_keeps_empty_clears(self):
        uisettings.set_many(self.app, {'llm.api_key': 'k' * 20}, 'a')
        uisettings.set_many(self.app, {'llm.api_key': None, 'llm.timeout_seconds': 60}, 'a')
        self.assertEqual(self.app.cfg['llm']['api_key'], 'k' * 20)
        uisettings.set_many(self.app, {'llm.api_key': ''}, 'a')
        self.assertEqual(self.app.cfg['llm']['api_key'], '')


class _Fake(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer secret-key':
            return self._send(401, {'error': 'no'})
        self._send(200, {'data': [{'id': 'test-model'}]})

    def do_POST(self):
        if self.headers.get('Authorization') != 'Bearer secret-key':
            return self._send(401, {'error': 'no'})
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self._send(200, {'choices': [{'message': {'content': 'OK' if 'OK' in body['messages'][-1]['content'] else '```json\n{"a": 1}\n```'}}]})


class TestLLMClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def cfg(self, key):
        return {'llm': {'url': 'http://127.0.0.1:%d/v1' % self.srv.server_address[1], 'model': 'test-model',
                        'api_key': key, 'timeout_seconds': 10, 'enabled': True}}

    def test_ok_and_wrong_key(self):
        out = llm.Client(self.cfg('secret-key')).test()
        self.assertEqual((out['ok'], out['reply'], out['model']), (True, 'OK', 'test-model'))
        with self.assertRaises(llm.LLMError) as e:
            llm.Client(self.cfg('wrong')).test()
        self.assertEqual(e.exception.code, 'unauthorized')

    def test_json_reply_parsing(self):
        text, _, _ = llm.Client(self.cfg('secret-key')).chat([{'role': 'user', 'content': 'give json'}])
        self.assertEqual(llm.parse_json_reply(text), {'a': 1})

    def test_not_configured(self):
        with self.assertRaises(llm.LLMError) as e:
            llm.Client({'llm': {'url': ''}}).test()
        self.assertEqual(e.exception.code, 'not_configured')


if __name__ == '__main__':
    unittest.main()


class TestLLMTestThroughUnit(unittest.TestCase):
    """The web service only asks; the analysis unit (allowed to reach the LLM server) answers."""
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.env.cleanup()

    def test_request_then_result(self):
        from jtwafmgr import analyst
        url = 'http://127.0.0.1:%d/v1' % self.srv.server_address[1]
        uisettings.set_many(self.app, {'llm.url': url, 'llm.model': 'test-model', 'llm.api_key': 'wrong-key-1234'}, 'a')
        self.assertIsNone(analyst.run_test(self.app, log=lambda m: None))        # nothing asked yet
        at = analyst.request_test(self.app.cfg)
        out = analyst.run(self.app, log=lambda m: None)                          # what the unit runs
        self.assertEqual(out['reason'], 'tested')
        r = analyst.test_result(self.app.cfg)
        self.assertEqual((r['ok'], r['error'], r['requested_at']), (False, 'unauthorized', at))
        self.assertNotIn('wrong-key-1234', json.dumps(r))
        uisettings.set_many(self.app, {'llm.api_key': 'secret-key'}, 'a')
        at = analyst.request_test(self.app.cfg)
        analyst.run(self.app, log=lambda m: None)
        r = analyst.test_result(self.app.cfg)
        self.assertTrue(r['ok'])
        self.assertEqual((r['model'], r['reply'], r['requested_at']), ('test-model', 'OK', at))
        rows = [x['action'] for x in self.app.db.q("SELECT action FROM audit WHERE action LIKE 'llm.%'")]
        self.assertEqual(rows.count('llm.tested'), 2)


class TestReasoningModels(unittest.TestCase):
    def test_think_blocks_are_removed(self):
        self.assertEqual(llm.strip_thinking('<think>let me {see}</think>\nOK'), 'OK')
        self.assertEqual(llm.strip_thinking('<think>never closed {"a": 2}'), '')
        self.assertEqual(llm.parse_json_reply('<think>maybe {"x": 1}?</think>{"verdicts": []}'), {'verdicts': []})
