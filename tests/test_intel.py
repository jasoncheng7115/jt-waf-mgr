"""Threat intelligence (intel.py) and the software list (software.py), against fake LLM and MCP servers: the tool
loop of both providers, what is kept from the answer, alerts for exploited vulnerabilities, the budget, fetch_url's
limits, the guesses from packages and access logs, the API."""
import http.server
import json
import os
import threading
import time
import unittest

from jtwafmgr import auth, intel, notify, software
from jtwafmgr.app import App
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv
from tests.test_api import PW, Client

ANSWER = {'notes': 'checked', 'threats': [
    {'id': 'CVE-2026-11111', 'product': 'Example CMS', 'summary': 'path traversal in the upload handler',
     'affected_versions': '< 3.2.1', 'fixed_version': '3.2.1', 'our_version': '3.1.0', 'affected': 'yes', 'exploited': True,
     'exploited_evidence': 'CISA KEV', 'severity': 'critical', 'attack_vector': 'url',
     'request_pattern': 'POST /upload.php with ../ in the filename parameter', 'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-11111']},
    {'id': 'CVE-2026-22222', 'product': 'Something Else', 'summary': 'not ours', 'affected_versions': '', 'fixed_version': '',
     'our_version': '', 'affected': 'yes', 'exploited': True, 'exploited_evidence': '', 'severity': 'critical',
     'attack_vector': 'url', 'request_pattern': '', 'references': ['https://example.com/x']},
    {'id': 'not-an-id', 'product': 'nginx', 'summary': 'invented', 'affected_versions': '', 'fixed_version': '', 'our_version': '',
     'affected': 'unknown', 'exploited': False, 'exploited_evidence': '', 'severity': 'low', 'attack_vector': 'unknown',
     'request_pattern': '', 'references': ['https://nginx.org/']},
    {'id': 'CVE-2026-33333', 'product': 'nginx', 'summary': 'no references', 'affected_versions': '', 'fixed_version': '',
     'our_version': '', 'affected': 'unknown', 'exploited': False, 'exploited_evidence': '', 'severity': 'low',
     'attack_vector': 'unknown', 'request_pattern': '', 'references': ['http://insecure.example.com/']},
    {'id': 'cve-2026-44444', 'product': 'NGINX', 'summary': 'request smuggling', 'affected_versions': '1.20-1.27',
     'fixed_version': '1.27.4', 'our_version': '1.22.1', 'affected': 'unknown', 'exploited': False, 'exploited_evidence': '',
     'severity': 'high', 'attack_vector': 'header', 'request_pattern': 'two Content-Length headers',
     'references': ['https://nginx.org/en/security_advisories.html', 'javascript:alert(1)']}]}


def sweep(*names):
    return ['%s security advisory %s' % (n, time.strftime('%B %Y')) for n in names]


class Fake(http.server.BaseHTTPRequestHandler):
    """One server for all fakes: /v1/chat/completions (OpenAI), /v1/messages (Anthropic), /mcp (MCP)."""
    script = []          # replies for the LLM, in order
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)) or b'{}')
        Fake.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        if self.path == '/mcp':
            if body.get('method') == 'notifications/initialized':
                self.send_response(202)
                self.end_headers()
                return
            if body.get('method') == 'initialize':
                res = {'protocolVersion': intel.MCP_PROTOCOL, 'capabilities': {}, 'serverInfo': {'name': 'fake'}}
            elif body.get('method') == 'tools/list':
                res = {'tools': [{'name': 'web_search'}, {'name': 'code_search'}]}
            else:
                res = {'content': [{'type': 'text', 'text': 'Example CMS 3.2.1 fixes CVE-2026-11111 (exploited) '
                                                            'https://nvd.nist.gov/vuln/detail/CVE-2026-11111'}]}
            data = ('event: message\ndata: %s\n\n' % json.dumps({'jsonrpc': '2.0', 'id': body.get('id'), 'result': res})).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Mcp-Session-Id', 'sess-1')
            self.end_headers()
            self.wfile.write(data)
            return
        reply = Fake.script.pop(0) if Fake.script else {'error': 'no more'}
        status = reply.pop('_status', 200) if isinstance(reply, dict) else 200
        data = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


    def do_GET(self):
        Fake.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, None))
        if self.path.split('?')[0] not in ('/v1/models',):
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps({'data': [{'id': 'm'}, {'id': 'big-model'}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def openai_reply(content=None, calls=None):
    m = {'role': 'assistant', 'content': content}
    if calls:
        m['tool_calls'] = [{'id': 'c%d' % i, 'type': 'function', 'function': {'name': n, 'arguments': json.dumps(a)}}
                           for i, (n, a) in enumerate(calls)]
    return {'choices': [{'message': m}], 'usage': {'prompt_tokens': 1000, 'completion_tokens': 200}}


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = 'http://127.0.0.1:%d' % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Fake.script, Fake.seen = [], []
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.app.cfg.data['notify']['enabled'] = True
        self.app.cfg.data['notify']['webhook_enabled'] = True
        self.app.cfg.data['notify']['webhook_url'] = 'https://hooks.example.com/x'
        self.app.cfg.data['intel'].update(enabled=True, provider='openai', url=self.url + '/v1', model='m', api_key='k',
                                          search='mcp', mcp_url=self.url + '/mcp', max_rounds=5, timeout_seconds=60)
        software.save(self.app.db, 'test', 'Example CMS', '3.1.0')
        software.save(self.app.db, 'test', 'nginx', '1.22.1')
        software.save(self.app.db, 'test', 'Unconfirmed App', '1.0', confirmed_flag=False)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()


class TestRun(Base):
    def test_name_only_exploited_is_urgent(self):
        """Confirmed by name only (version unknown) and exploited (read on CISA): may affect us -> critical alert."""
        self.app.cfg.data['intel']['patches'] = False
        a = json.loads(json.dumps(ANSWER))
        a['threats'] = a['threats'][:1]
        a['threats'][0].update(affected='unknown', our_version='unknown')
        Fake.script = [openai_reply(calls=[('fetch_url', {'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'})]),
                       openai_reply(content=json.dumps(a))]
        old_public, old_get = intel._public, intel._get_pinned
        intel._public = lambda h, p: '203.0.113.5'
        intel._get_pinned = lambda u, ip, t: (200, {'content-type': 'text/html'}, b'<td>CVE-2026-11111</td>')
        try:
            intel.run(self.app, 'manual', log=lambda m: None)
        finally:
            intel._public, intel._get_pinned = old_public, old_get
        al = self.app.db.one("SELECT severity, details FROM alerts WHERE kind='exploited_vulnerability'")
        self.assertEqual(al['severity'], 'critical')
        self.assertIn('may affect us', al['details'])

    def _cisa_run(self, threat):
        a = json.loads(json.dumps(ANSWER))
        a['threats'] = [dict(a['threats'][0], **threat)]
        Fake.script = [openai_reply(calls=[('fetch_url', {'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'})]),
                       openai_reply(content=json.dumps(a))]
        old_public, old_get = intel._public, intel._get_pinned
        intel._public = lambda h, p: '203.0.113.5'
        intel._get_pinned = lambda u, ip, t: (200, {'content-type': 'text/html'}, b'<td>CVE-2026-11111</td>')
        try:
            intel.run(self.app, 'manual', log=lambda m: None)
        finally:
            intel._public, intel._get_pinned = old_public, old_get

    def test_kev_marks_exploited_without_reading_a_page(self):
        """With the KEV catalog on, a threat it lists is exploited even when the model read no CISA page; its entries
        for the confirmed software go to the model."""
        from jtwafmgr import kev
        from tests.test_kev import catalog
        self.app.cfg.data['intel'].update(kev=True, patches=False)
        kev.update(self.app.cfg, get=lambda u, t: catalog(extra=[{'cveID': 'CVE-2026-11111', 'vendorProject': 'Example',
                                                                   'product': 'Example CMS', 'dateAdded': '2026-11-10'}]), log=lambda m: None)
        a = json.loads(json.dumps(ANSWER))
        a['threats'] = [dict(a['threats'][0], exploited=False)]
        Fake.script = [openai_reply(content=json.dumps(a))]
        intel.run(self.app, 'manual', log=lambda m: None)
        t = intel.threats(self.app.db)[0]
        self.assertTrue(t['exploited'])
        self.assertIn('Known Exploited', t['exploited_evidence'])
        user = [b for p, h, b in Fake.seen if p == '/v1/chat/completions'][0]['messages'][1]['content']
        self.assertIn('CVE-2026-11111', user)

    def test_preconditions_the_host_does_not_meet(self):
        """Exploited, the version matches, but it needs musl and sshd without PAM (an Alpine build): not us."""
        self.app.cfg.data['intel']['patches'] = False
        self._cisa_run({'preconditions': 'musl libc and sshd built without PAM', 'conditions_met': 'no'})
        self.assertEqual(self.app.db.one('SELECT affected FROM intel_threats')['affected'], 'no')
        self.assertIsNone(self.app.db.one("SELECT 1 FROM alerts WHERE kind='exploited_vulnerability'"))
        # the host facts went with the list (operating system, C library); no site names
        user = [b for p, h, b in Fake.seen if p == '/v1/chat/completions'][0]['messages'][1]['content']
        self.assertIn('Host facts', user)
        self.assertIn('architecture', user)

    def test_preconditions_not_confirmed_give_a_warning_not_the_urgent_path(self):
        self.app.cfg.data['intel']['patches'] = False
        self._cisa_run({'preconditions': 'the mod_example module enabled', 'conditions_met': 'unknown'})
        al = self.app.db.one("SELECT severity, details FROM alerts WHERE kind='exploited_vulnerability'")
        self.assertEqual(al['severity'], 'warning')
        self.assertIn('check whether it applies', al['details'])

    def test_unknown_version_is_no_version_and_the_alert_is_worded_per_language(self):
        """The model writes "unknown" for a version it does not know: the alert says so instead of "Example CMS unknown",
        and the notification and the interface word it from the structured values, in their own language."""
        self.app.cfg.data['intel']['patches'] = False
        self.app.db.x("UPDATE software SET version='' WHERE name='Example CMS'")     # the version here is not known
        self._cisa_run({'preconditions': 'the mod_example module enabled', 'conditions_met': 'unknown', 'our_version': 'unknown'})
        d = json.loads(self.app.db.one("SELECT details FROM alerts WHERE kind='exploited_vulnerability'")['details'])
        self.assertEqual((d['msg'], d['sw_version']), ('intel_check', ''))
        self.assertNotIn(' unknown ', d['reason'])
        zh = notify.alert_text('zh-TW', d)
        self.assertIn('本站版本未知', zh)
        self.assertNotIn('unknown', zh)
        self.assertNotIn('exploited', zh)
        self.assertIn('version here is not known', notify.alert_text('en', d))
        self.assertIn('バージョン不明', notify.alert_text('ja', d))
        self.assertEqual(intel.known_version(' Unknown '), '')
        self.assertEqual(intel.known_version('10.1.9'), '10.1.9')
        # an alert without a message key keeps its own sentence
        self.assertEqual(notify.alert_text('zh-TW', {'reason': 'probe answered 200'}), 'probe answered 200')

    def test_a_threat_that_becomes_urgent_later_raises_the_alert_then(self):
        self.app.cfg.data['intel']['patches'] = False
        self._cisa_run({'preconditions': 'the mod_example module enabled', 'conditions_met': 'unknown'})
        self.assertIsNone(self.app.db.one("SELECT 1 FROM alerts WHERE kind='exploited_vulnerability' AND severity='critical'"))
        self._cisa_run({'preconditions': 'the mod_example module enabled', 'conditions_met': 'yes'})   # confirmed next time
        self.assertTrue(self.app.db.one("SELECT 1 FROM alerts WHERE kind='exploited_vulnerability' AND severity='critical'"))

    def test_openai_tool_loop_and_what_is_kept(self):
        self.app.cfg.data['intel']['patches'] = False        # virtual patches: TestPatches
        Fake.script = [openai_reply(calls=[('web_search', {'query': 'Example CMS CVE'}),
                                           ('fetch_url', {'url': 'http://nvd.nist.gov/x'}),
                                           ('fetch_url', {'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'})]),
                       openai_reply(content=json.dumps(ANSWER))]
        # the CISA catalog page, read in this run, lists CVE-2026-11111: "exploited" is believed for that one only
        old_public, old_get = intel._public, intel._get_pinned
        intel._public = lambda h, p: '203.0.113.5'
        intel._get_pinned = lambda u, ip, t: (200, {'content-type': 'text/html'}, b'<td>CVE-2026-11111</td>')
        try:
            rid = intel.run(self.app, 'manual', log=lambda m: None)
        finally:
            intel._public, intel._get_pinned = old_public, old_get
        r = self.app.db.one('SELECT * FROM intel_runs WHERE id=?', (rid,))
        self.assertIsNone(r['error'])
        self.assertEqual((r['tokens_in'], r['tokens_out']), (2000, 400))
        # 0.5.8: the program's own searches first (every product), then the model's
        self.assertEqual(json.loads(r['searches']), sweep('Example CMS', 'nginx') + ['Example CMS CVE'])
        kept = json.loads(r['threats'])
        self.assertEqual([t['id'] for t in kept], ['CVE-2026-11111', 'CVE-2026-44444'])
        ng = kept[1]
        self.assertEqual((ng['product'], ng['our_version']), ('nginx', '1.22.1'))      # our list, not the model's
        self.assertEqual(ng['references'], ['https://nginx.org/en/security_advisories.html'])
        # what went to the model: confirmed products only, nothing about sites
        first = [b for p, h, b in Fake.seen if p == '/v1/chat/completions'][0]
        user = first['messages'][1]['content']
        self.assertIn('Example CMS 3.1.0', user)
        self.assertNotIn('Unconfirmed App', user)
        tool_msgs = [m for m in [b for p, h, b in Fake.seen if p == '/v1/chat/completions'][1]['messages'] if m['role'] == 'tool']
        self.assertIn('only https', tool_msgs[1]['content'])                          # fetch_url refused http
        # exploited and affecting our version: a critical alert; new threats: a notification
        a = self.app.db.one("SELECT * FROM alerts WHERE kind='exploited_vulnerability'")
        self.assertEqual(a['severity'], 'critical')
        self.assertTrue(self.app.db.one("SELECT 1 FROM notifications WHERE event='intel.new_threats'"))
        # the same threats again: nothing new, no second alert
        Fake.script = [openai_reply(content=json.dumps(ANSWER))]
        intel.run(self.app, 'manual', log=lambda m: None)
        self.assertEqual(self.app.db.one("SELECT COUNT(*) FROM alerts WHERE kind='exploited_vulnerability'")[0], 1)
        self.assertEqual(self.app.db.one("SELECT COUNT(*) FROM intel_threats")[0], 2)

    def test_gemini_through_its_openai_compatible_endpoint(self):
        c = self.app.cfg.data['intel']
        c.update(provider='gemini', model='', api_key='')
        self.assertEqual(intel.readiness(self.app.cfg), 'llm_not_configured')     # a key and a model are needed
        c.update(model='gemini-test', api_key='g-key', patches=False)
        self.assertIsNone(intel.readiness(self.app.cfg))
        self.assertTrue(intel.openai_target(self.app.cfg)[0].startswith(self.url))  # the URL set wins; empty: Google's
        Fake.script = [openai_reply(content=json.dumps(dict(ANSWER, threats=[])))]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        r = self.app.db.one('SELECT provider, model, error FROM intel_runs WHERE id=?', (rid,))
        self.assertEqual((r['provider'], r['model'], r['error']), ('gemini', 'gemini-test', None))
        self.assertIn('/v1/chat/completions', [p for p, h, b in Fake.seen])
        c.update(url='')
        self.assertEqual(intel.openai_target(self.app.cfg)[0], intel.GEMINI_URL)

    def test_handled_threat_raises_no_alert(self):
        a = dict(ANSWER, threats=[dict(ANSWER['threats'][0], exploited=False)])
        Fake.script = [openai_reply(content=json.dumps(a))]
        intel.run(self.app, 'manual', log=lambda m: None)
        tid = self.app.db.one('SELECT id FROM intel_threats')['id']
        intel.set_status(self.app.db, self.app.audit, tid, 'handled', 'alice')
        Fake.script = [openai_reply(content=json.dumps(ANSWER))]           # now exploited, but a person handled it
        intel.run(self.app, 'manual', log=lambda m: None)
        self.assertIsNone(self.app.db.one("SELECT 1 FROM alerts WHERE kind='exploited_vulnerability'"))

    def test_failure_and_budget(self):
        Fake.script = [{'_status': 401, 'error': 'bad key'}]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        self.assertTrue(self.app.db.one('SELECT error FROM intel_runs WHERE id=?', (rid,))['error'].startswith('unauthorized'))
        self.assertTrue(self.app.db.one("SELECT 1 FROM notifications WHERE event='intel.failed'"))
        self.app.cfg.data['intel']['daily_tokens'] = 100
        self.app.db.x('UPDATE intel_runs SET tokens_in=500')
        self.assertEqual(intel.over_budget(self.app.cfg, self.app.db), 'daily_tokens')
        self.assertIsNone(intel.run(self.app, 'manual', log=lambda m: None))

    def test_budget_stops_a_run_and_its_tokens_count(self):
        self.app.cfg.data['intel']['daily_tokens'] = 1500
        Fake.script = [openai_reply(calls=[('web_search', {'query': 'a'})]), openai_reply(calls=[('web_search', {'query': 'b'})]),
                       openai_reply(content=json.dumps(ANSWER))]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        r = self.app.db.one('SELECT * FROM intel_runs WHERE id=?', (rid,))
        self.assertTrue(r['error'].startswith('budget_reached'))
        self.assertEqual((r['tokens_in'], r['tokens_out']), (2000, 400))          # what it used before stopping
        self.assertEqual(intel.over_budget(self.app.cfg, self.app.db), 'daily_tokens')

    def test_unexpected_error_is_recorded(self):
        Fake.script = [['not', 'an', 'object']]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        r = self.app.db.one('SELECT * FROM intel_runs WHERE id=?', (rid,))
        self.assertIsNotNone(r['finished_at'])
        self.assertTrue(r['error'])

    def test_not_ready_and_due(self):
        self.app.cfg.data['intel']['enabled'] = False
        self.assertIsNone(intel.run_job(self.app, log=lambda m: None) and None)
        self.assertEqual(intel.readiness(self.app.cfg), 'disabled')
        self.app.cfg.data['intel'].update(enabled=True, url='', model='')
        self.app.cfg.data['llm'].update(url=self.url + '/v1', model='local-model', api_key='k1')   # the first tier's server
        self.assertIsNone(intel.readiness(self.app.cfg))
        self.assertEqual(intel.openai_target(self.app.cfg), (self.url + '/v1', 'local-model', 'k1'))
        Fake.script = [openai_reply(content=json.dumps({'notes': '', 'threats': []}))]
        self.assertIsNotNone(intel.run_job(self.app, log=lambda m: None))         # first run: due
        self.assertIsNone(intel.run_job(self.app, log=lambda m: None))            # not due again yet
        intel.request_run(self.app.cfg)
        Fake.script = [openai_reply(content=json.dumps({'notes': '', 'threats': []}))]
        self.assertIsNotNone(intel.run_job(self.app, log=lambda m: None))         # asked
        self.assertFalse(os.path.exists(intel.request_file(self.app.cfg)))

    def test_empty_model_is_the_server_default(self):
        # 0.5.54: "default" in Settings (an empty model) with the second tier's own server left the search never
        # running (llm_not_configured) while the connection test passed with the server's first model
        intel._RESOLVED.clear()
        self.app.cfg.data['intel'].update(enabled=True, provider='openai', url=self.url + '/v1', model='', api_key='k2')
        self.assertIsNone(intel.readiness(self.app.cfg))
        Fake.seen.clear()
        Fake.script = [openai_reply(content=json.dumps({'notes': '', 'threats': []}))]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        r = self.app.db.one('SELECT * FROM intel_runs WHERE id=?', (rid,))
        self.assertIsNone(r['error'])
        self.assertEqual(r['model'], 'm')                                          # the first model the server lists
        posts = [b for p, h, b in Fake.seen if b is not None and p.endswith('/chat/completions')]
        self.assertTrue(posts and all(b['model'] == 'm' for b in posts))
        # OpenAI itself has no default in its list: a model stays required there
        self.app.cfg.data['intel'].update(url=intel.OPENAI_URL)
        self.assertEqual(intel.readiness(self.app.cfg), 'llm_not_configured')

    def test_first_tier_empty_model_is_the_server_default(self):
        from jtwafmgr import analyst, llm
        self.app.cfg.data['llm'].update(enabled=True, url=self.url + '/v1', model='', api_key='')
        self.assertIsNone(analyst.llm_ready(self.app.cfg))
        c = llm.Client(self.app.cfg)
        Fake.seen.clear()
        Fake.script = [openai_reply(content='OK')]
        c.chat([{'role': 'user', 'content': 'x'}], max_tokens=10)
        self.assertEqual(c.model, 'm')
        posts = [b for p, h, b in Fake.seen if b is not None]
        self.assertEqual(posts[-1]['model'], 'm')

    def test_anthropic_loop(self):
        c = self.app.cfg.data['intel']
        c.update(provider='anthropic', url=self.url, model='')
        msg = lambda content, stop: {'content': content, 'stop_reason': stop, 'usage': {'input_tokens': 300, 'output_tokens': 50}}  # noqa: E731
        Fake.script = [msg([{'type': 'tool_use', 'id': 't1', 'name': 'web_search', 'input': {'query': 'nginx CVE'}}], 'tool_use'),
                       msg([{'type': 'server_tool_use', 'id': 's1', 'name': 'web_search', 'input': {'query': 'x'}}], 'pause_turn'),
                       msg([{'type': 'text', 'text': json.dumps(ANSWER)}], 'end_turn')]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        r = self.app.db.one('SELECT * FROM intel_runs WHERE id=?', (rid,))
        self.assertIsNone(r['error'])
        self.assertEqual(r['model'], intel.ANTHROPIC_MODEL)
        calls = [(h, b) for p, h, b in Fake.seen if p == '/v1/messages']
        h, b = calls[0]
        self.assertEqual(h.get('anthropic-version'), intel.ANTHROPIC_VERSION)
        self.assertEqual(h.get('x-api-key'), 'k')
        self.assertNotIn('fallbacks', b)                        # only on the Anthropic API itself
        self.assertEqual(b['output_config']['format']['type'], 'json_schema')
        self.assertNotIn('temperature', b)
        self.assertEqual(calls[1][1]['messages'][-1]['content'][0]['type'], 'tool_result')
        self.assertEqual(calls[2][1]['messages'][-1]['role'], 'assistant')          # pause_turn: resent as is
        self.assertEqual(json.loads(r['searches'])[-2:], ['nginx CVE', 'x'])
        self.assertEqual(len(json.loads(r['threats'])), 2)
        # the provider's own search tools
        c['search'] = 'provider'
        tools = intel.Session(self.app.cfg).anthropic_tools()
        self.assertEqual([t['type'] for t in tools], ['web_search_20260209', 'web_fetch_20260209'])
        self.assertIn('nvd.nist.gov', tools[1]['allowed_domains'])

    def test_anthropic_refusal(self):
        self.app.cfg.data['intel'].update(provider='anthropic', url=self.url)
        Fake.script = [{'content': [], 'stop_reason': 'refusal', 'stop_details': {'category': 'cyber'}, 'usage': {}}]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        self.assertTrue(self.app.db.one('SELECT error FROM intel_runs WHERE id=?', (rid,))['error'].startswith('refused'))

    def test_software_that_is_not_web_facing_is_not_followed(self):
        """An SSH server an older version guessed (and a person confirmed): a WAF cannot shield it, so it leaves the
        list, its open threat is set aside and its alert handled; a web product's threat stays open."""
        from jtwafmgr import alerts
        db = self.app.db
        db.x("INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) "
             "VALUES ('OpenSSH', '1:9.2p1-2', '[]', 'host', 'guess', 1, 'dpkg: openssh-client', '', 0, 'x')")
        self.assertNotIn('OpenSSH', [p['name'] for p in software.confirmed(db)])      # never sent to the model
        ids = {}
        for cve, product in (('CVE-2026-0001', 'OpenSSH'), ('CVE-2026-0002', 'nginx')):
            ids[product] = db.x('INSERT INTO intel_threats(cve, product, first_seen, last_seen, last_run, affected, exploited, severity, details) '
                                "VALUES (?, ?, 0, 0, 0, 'unknown', 1, 'critical', '{}')", (cve, product)).lastrowid
            alerts.raise_alert(db, self.app.audit, 'intel', 'exploited_vulnerability', 'critical', 'intel:%s:%s' % (cve, product),
                               {'reason': 'x', 'cve': cve, 'product': product}, notify=False)
        done = intel.retire_unrelated(self.app, log=lambda *a: None)
        self.assertEqual(done, [ids['OpenSSH']])
        st = {r['product']: r['status'] for r in db.q('SELECT product, status FROM intel_threats')}
        self.assertEqual(st, {'OpenSSH': 'ignored', 'nginx': 'open'})
        a = {r['dedup']: r['state'] for r in db.q('SELECT dedup, state FROM alerts')}
        self.assertEqual((a['intel:CVE-2026-0001:OpenSSH'], a['intel:CVE-2026-0002:nginx']), ('handled', 'open'))
        self.assertIsNone(db.one("SELECT 1 FROM software WHERE name='OpenSSH'"))
        self.assertIsNotNone(db.one("SELECT 1 FROM software WHERE name='nginx'"))
        self.assertEqual(intel.retire_unrelated(self.app, log=lambda *a: None), [])      # once
        # a person's own entry of the same kind stays theirs
        db.x("INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) "
             "VALUES ('OpenSSH', '9.2', '[]', 'host', 'person', 1, '', '', 0, 'alice')")
        self.assertIn('OpenSSH', [p['name'] for p in software.confirmed(db)])

    def test_no_confirmed_software(self):
        self.app.db.x('UPDATE software SET confirmed=0')
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        self.assertEqual(self.app.db.one('SELECT note FROM intel_runs WHERE id=?', (rid,))['note'], 'no confirmed software')
        self.assertFalse([1 for p, h, b in Fake.seen if p.startswith('/v1')])


class TestPatches(Base):
    T = {'id': 'CVE-2026-11111', 'product': 'Example CMS', 'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-11111']}

    def good(self, **k):
        return dict({'possible': True, 'target': 'path', 'header': '', 'regex': '^/upload\\.php/\\.\\./',
                     'attack_examples': ['/upload.php/../etc/passwd'], 'benign_examples': ['/upload.php', '/index.php'],
                     'explanation': 'x'}, **k)

    def test_spec_checks(self):
        samples = [{'host': 'cms.example.com', 'method': 'GET', 'path': '/news/2026/11/hello?page=2'}]
        spec, tests = intel._patch_spec(self.good(), self.T, samples, ['cms.example.com'])
        self.assertEqual((spec['target'], spec['host'], spec['source']), ('path', {'mode': 'exact', 'value': 'cms.example.com'}, 'external'))
        self.assertEqual(tests, [{'expect': 403, 'source': 'external', 'host': 'cms.example.com', 'path': '/upload.php/../etc/passwd'}])
        self.assertEqual(intel._patch_spec(self.good(), self.T, samples, [], 'www.example.com')[0]['host']['mode'], 'any')
        with self.assertRaises(intel.IntelError) as cm:                    # no site to test it on
            intel._patch_spec(self.good(), self.T, samples, [])
        self.assertEqual(cm.exception.code, 'no_test_possible')
        for bad, code in ((dict(possible=False), 'not_possible'), (dict(regex='upload'), 'not_anchored'),
                          (dict(regex='^/(a+)+$', attack_examples=['/aaa']), 'regex_redos'),
                          (dict(attack_examples=['/other']), 'misses_examples'),
                          (dict(regex='^/'), 'bad_regex'), (dict(regex='^/news/'), 'misses_examples'),
                          (dict(regex='^/[[:alnum:]]', attack_examples=['/a']), 'bad_regex'),
                          (dict(regex='^/news/', attack_examples=['/news/x']), 'matches_normal'),
                          (dict(target='header', header='Cookie', regex='x', attack_examples=['x']), 'bad_header'),
                          (dict(target='header', header='X-Api-Version', regex='', attack_examples=['x']), 'bad_regex'),
                          (dict(target='header', header='User-Agent', regex='mozilla', attack_examples=['mozilla/5']), 'matches_normal')):
            with self.assertRaises(intel.IntelError) as cm:
                intel._patch_spec(self.good(**bad), self.T, samples, [], 'www.example.com')
            self.assertEqual(cm.exception.code, code, bad)

    def test_propose(self):
        now = time.time()
        det = dict(self.T, attack_vector='url', request_pattern='../ in the path after upload.php', summary='traversal', our_version='3.1.0')
        for cve, exploited, vector in (('CVE-2026-11111', 1, 'url'), ('CVE-2026-22222', 1, 'url'), ('CVE-2026-33333', 1, 'body')):
            self.app.db.x("INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, details) "
                          "VALUES (?, 'Example CMS', ?, ?, 'yes', ?, 'critical', ?)",
                          (cve, now, now, exploited, json.dumps(dict(det, id=cve, attack_vector=vector))))
        seen = []
        self.app.db.x("INSERT INTO regression_samples(host, method, path, source, added_at) VALUES ('cms.example.com', 'GET', '/news', 'auto', 0)")

        def propose(op, kind, spec, reason, actor, **k):
            seen.append((kind, spec, actor, k.get('owner')))
            return 77

        self.app.workflow.propose = propose
        # 0.5.8: a body attack is asked about too (a parameter's name can be matched); here the model finds none
        answers = iter([self.good(), dict(self.good(), possible=False), dict(self.good(), possible=False)])
        out, a, b = intel.propose_patches(self.app, 1, ask=lambda *x: (next(answers), 10, 5), log=lambda m: None)
        self.assertEqual((out, a, b), ([77], 30, 15))
        self.assertEqual(seen[0][0], 'confident_block')
        self.assertEqual((seen[0][2], seen[0][3]), ('intel', 'intel'))
        rows = {r['cve']: r for r in self.app.db.q('SELECT * FROM intel_threats')}
        self.assertEqual(rows['CVE-2026-11111']['patch_change_id'], 77)
        self.assertEqual(rows['CVE-2026-22222']['patch_note'], 'not_possible')
        self.assertEqual(rows['CVE-2026-33333']['patch_note'], 'not_possible')
        # exploited, affects us, and no rule could be written: a person decides now
        self.assertTrue(self.app.db.one("SELECT 1 FROM alerts WHERE dedup LIKE 'intel-patch:CVE-2026-22222%'"))
        # the patch is in force and a person updated the software: the patch may go
        self.app.db.x("INSERT INTO changes(id, op, kind, spec, direction, state, proposed_by, created_at, updated_at, rule_id) "
                      "VALUES (77, 'add', 'confident_block', '{}', 'tighten', 'applied', 'intel', 0, 0, 10260)")
        self.assertEqual(intel.remind_removal(self.app), 0)
        self.app.db.x("UPDATE software SET version='3.2.1' WHERE name='Example CMS'")
        self.assertEqual(intel.remind_removal(self.app), 1)
        self.assertTrue(self.app.db.one("SELECT 1 FROM alerts WHERE dedup LIKE 'intel-remove:CVE-2026-11111%'"))
        # tried once: not again
        out, _, _ = intel.propose_patches(self.app, 2, ask=lambda *x: (self.good(), 1, 1), log=lambda m: None)
        self.assertEqual(out, [])


class TestFetch(unittest.TestCase):
    def test_limits(self):
        doms = ['nvd.nist.gov']
        self.assertIn('only https', intel.fetch_url('http://nvd.nist.gov/', doms))
        self.assertIn('not on the list', intel.fetch_url('https://evil.example.com/', doms))
        self.assertIn('not on the list', intel.fetch_url('https://nvd.nist.gov.evil.example.com/', doms))
        self.assertIn('public addresses', intel.fetch_url('https://nvd.nist.gov/', doms, resolve=lambda h, p: False))
        self.assertTrue(intel.allowed('services.nvd.nist.gov', doms))
        self.assertFalse(intel.allowed('xnvd.nist.gov', doms))

    def test_html_text(self):
        t = intel.html_text('<html><head><title>x</title><script>evil()</script></head><body><h1>CVE-1</h1><p>a&amp;b</p></body></html>')
        self.assertNotIn('evil', t)
        self.assertIn('CVE-1', t)
        self.assertIn('a&b', t)

    def test_mcp_sse(self):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fake)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            m = intel.Mcp('http://127.0.0.1:%d/mcp' % srv.server_address[1])
            out = m.call('web_search', {'query': 'q'})
            self.assertIn('CVE-2026-11111', out)
            self.assertEqual(m.session, 'sess-1')
        finally:
            srv.shutdown()
            srv.server_close()


class TestSoftware(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_versions_the_applications_tell(self):
        """Read from the application itself (here a stand-in fetch): JSON field, header, body; a person's version stays."""
        db = self.app.db
        ins = ("INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) "
               "VALUES (?, ?, ?, 'site', ?, 1, '', '', 0, ?)")
        db.x(ins, ('Nextcloud', '', '["files.example.com"]', 'guess', 'x'))
        db.x(ins, ('Zulip', '9.0', '["chat.example.com"]', 'person', 'alice'))        # a person's version
        db.x(ins, ('Jenkins', '', '["ci.example.com"]', 'guess', 'x'))
        db.x(ins, ('WordPress', '', '["www.example.com"]', 'guess', 'x'))
        answers = {
            ('files.example.com', '/status.php'): (200, {}, b'{"installed":true,"versionstring":"30.0.4","version":"30.0.4.1"}'),
            ('chat.example.com', '/api/v1/server_settings'): (200, {}, b'{"zulip_version":"12.3"}'),
            ('ci.example.com', '/login'): (200, {'x-jenkins': '2.479.1'}, b''),
            ('www.example.com', '/feed/'): (200, {}, b'<generator>https://wordpress.org/?v=6.8.1</generator>'),
        }
        seen = []

        def fetch(host, probe, token=None):
            seen.append((host, probe['path']))
            return answers.get((host, probe['path']))
        changed = software.detect_versions(self.app, fetch=fetch, log=lambda *a: None)
        got = {r['name']: r['version'] for r in software.listing(db)}
        self.assertEqual((got['Nextcloud'], got['Jenkins'], got['WordPress']), ('30.0.4', '2.479.1', '6.8.1'))
        self.assertEqual(got['Zulip'], '9.0')                                          # never replaced
        self.assertNotIn(('chat.example.com', '/api/v1/server_settings'), seen)        # not even asked
        self.assertEqual(len(changed), 3)
        self.assertTrue(db.one("SELECT 1 FROM audit WHERE action='software.version_detected'"))
        # upgraded later: the version read before follows; a broken answer is refused
        answers[('files.example.com', '/status.php')] = (200, {}, b'{"versionstring":"31.0.0"}')
        answers[('www.example.com', '/feed/')] = (200, {}, b'<generator>https://wordpress.org/?v=<script></generator>')
        software.detect_versions(self.app, fetch=fetch, log=lambda *a: None)
        got = {r['name']: r['version'] for r in software.listing(db)}
        self.assertEqual((got['Nextcloud'], got['WordPress']), ('31.0.0', '6.8.1'))
        self.assertIsNone(software.extract_version({'json': 'version'}, 500, {}, b'{"version":"1.0"}'))
        self.assertIsNone(software.extract_version({'json': 'version'}, 200, {}, b'{"version":"1.0; rm -rf /"}'))
        self.assertEqual(software.extract_version({'json': 'harbor_version', 'regex': 'v?([0-9]+\\.[0-9]+\\.[0-9]+)'}, 200, {},
                                                  b'{"harbor_version":"v2.10.0-abc"}'), '2.10.0')
        src = software.version_sources()
        names = {s[0] for s in software.SIGNATURES}
        for p in src['auto']:                  # read automatically: only for an application the guess finds
            self.assertIn(p['name'], names, 'a version source for a name the guess does not know')
        # LibreNMS: only with its API token (sent in its header), the version in a list
        db.x(ins, ('LibreNMS / Observium', '', '["nms.example.com"]', 'guess', 'x'))
        tokens = []

        def fetch2(host, probe, token=None):
            if probe['path'] != '/api/v0/system':
                return None
            tokens.append(token)
            return (200, {}, b'{"status":"ok","system":[{"local_ver":"25.11.0","local_sha":"abc"}]}')
        software.detect_versions(self.app, fetch=fetch2, log=lambda *a: None)
        self.assertEqual(tokens, [])                                        # no token set: not asked
        self.app.cfg.data['intel']['librenms_token'] = 'tok-1'
        software.detect_versions(self.app, fetch=fetch2, log=lambda *a: None)
        self.assertEqual(tokens, ['tok-1'])
        self.assertEqual({r['name']: r['version'] for r in software.listing(db)}['LibreNMS / Observium'], '25.11.0')

    def test_dpkg(self):
        p = os.path.join(self.env.dir, 'status')
        with open(p, 'w') as fh:
            fh.write('Package: nginx\nStatus: install ok installed\nVersion: 1.22.1-9\n\n'
                     'Package: openssl\nStatus: deinstall ok config-files\nVersion: 3.0.1\n\n'
                     'Package: libmodsecurity3t64\nStatus: install ok installed\nVersion: 3.0.14-1build2\n')
        self.assertEqual(software.dpkg_packages(p), {'nginx': '1.22.1-9', 'libmodsecurity3t64': '3.0.14-1build2'})

    def test_logs_and_refresh(self):
        d = os.path.join(self.env.dir, 'tr')
        os.makedirs(d, exist_ok=True)
        lines = [json.dumps({'vhost': 'sso.example.com', 'path': '/realms/x/protocol/openid-connect/token', 'http_status': 200})] * 4
        lines += [json.dumps({'vhost': 'www.example.com', 'path': '/wp-content/x.css', 'http_status': 404})] * 5   # probes
        lines += ['192.0.2.1 - - [14/Nov/2026:10:00:00 +0800] "GET /remote.php/dav/files/a HTTP/1.1" 207 10 "-" "x"'] * 3
        with open(os.path.join(d, 'files.example.com.access.log'), 'w') as fh:
            fh.write('\n'.join(lines[8:]) + '\n')
        with open(os.path.join(d, 'access.log'), 'w') as fh:
            fh.write('\n'.join(lines[:9]) + '\n')
        self.app.cfg.data['traffic']['logs'] = [d + '/*access.log']
        found = software.scan_logs(self.app.cfg)
        self.assertEqual(found['Keycloak'], {'sso.example.com': 4})
        self.assertNotIn('WordPress', found)
        self.assertEqual(found['Nextcloud'], {'files.example.com': 3})
        out = software.refresh(self.app, 'alice')
        self.assertGreaterEqual(out['added'], 2)
        rows = {r['name']: r for r in software.listing(self.app.db)}
        self.assertFalse(rows['Keycloak']['confirmed'])
        self.assertEqual(rows['Keycloak']['hosts'], ['sso.example.com'])
        self.assertEqual(software.confirmed(self.app.db), [])
        software.save(self.app.db, 'alice', 'Keycloak', '26.0.5', sid=rows['Keycloak']['id'])
        self.assertEqual(software.confirmed(self.app.db), [{'name': 'Keycloak', 'version': '26.0.5'}])
        software.refresh(self.app, 'alice')                               # a person's entry stays
        self.assertEqual(software.confirmed(self.app.db), [{'name': 'Keycloak', 'version': '26.0.5'}])

    def test_redirects_own_site_stale_and_confirm_all(self):
        d = os.path.join(self.env.dir, 'tr2')
        os.makedirs(d, exist_ok=True)
        lines = [json.dumps({'vhost': 'example.com', 'path': '/guacamole/api/tokens', 'http_status': 301})] * 9     # redirected probes
        lines += [json.dumps({'vhost': 'waf.example.com', 'path': '/api/v1/login', 'http_status': 200})] * 9       # our own UI
        lines += [json.dumps({'vhost': 'sso.example.com', 'path': '/realms/x/protocol/openid-connect/token', 'http_status': 200})] * 4
        with open(os.path.join(d, 'access.log'), 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        self.app.cfg.data['traffic']['logs'] = [d + '/*access.log']
        found = software.scan_logs(self.app.cfg, exclude={'waf.example.com'})
        self.assertEqual(set(found), {'Keycloak'})
        self.assertIn('Rocket.Chat', software.scan_logs(self.app.cfg))          # without the exclusion it would count
        self.app.db.x("INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) "
                      "VALUES ('Apache Guacamole', '', '[\"example.com\"]', 'site', 'guess', 0, '', '', 0, 'x')")
        out = software.refresh(self.app, 'alice')
        names = {r['name'] for r in software.listing(self.app.db)}
        self.assertNotIn('Apache Guacamole', names)                            # no longer guessed, nobody confirmed it
        self.assertGreaterEqual(out['removed'], 1)
        n = software.confirm_all(self.app.db, 'alice')
        self.assertGreaterEqual(n, 1)
        self.assertTrue(all(r['confirmed'] for r in software.listing(self.app.db)))
        self.assertIn({'name': 'Keycloak', 'version': 'unknown'}, software.confirmed(self.app.db))   # a name is enough

    def test_zulip_api_not_rocketchat_and_removed_guess_stays_removed(self):
        d = os.path.join(self.env.dir, 'tr3')
        os.makedirs(d, exist_ok=True)
        lines = [json.dumps({'vhost': 'chat.example.com', 'path': p, 'http_status': 200})
                 for p in ('/api/v1/messages', '/api/v1/messages/flags', '/api/v1/register', '/api/v1/events?x=1') * 3]
        lines += [json.dumps({'vhost': 'rc.example.com', 'path': '/api/v1/me', 'http_status': 200})] * 6
        with open(os.path.join(d, 'access.log'), 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        self.app.cfg.data['traffic']['logs'] = [d + '/*access.log']
        found = software.scan_logs(self.app.cfg)
        self.assertEqual(set(found.get('Rocket.Chat', {})), {'rc.example.com'})   # /api/v1/messages is not /api/v1/me
        self.assertIn('chat.example.com', found.get('Zulip', {}))
        software.refresh(self.app, 'alice')
        r = self.app.db.one("SELECT id FROM software WHERE name='Rocket.Chat'")
        self.assertTrue(software.delete(self.app.db, r['id']))
        self.assertIn('Rocket.Chat', software.dismissed_names(self.app.db))
        software.refresh(self.app, 'alice')                                     # a person removed it: not guessed again
        self.assertIsNone(self.app.db.one("SELECT id FROM software WHERE name='Rocket.Chat'"))
        software.save(self.app.db, 'alice', 'Rocket.Chat', '7.0.0')              # adding it by hand takes it off the list
        self.assertNotIn('Rocket.Chat', software.dismissed_names(self.app.db))
        self.app.db.x("DELETE FROM software WHERE name='Rocket.Chat'")

    def test_renamed_guess_is_not_guessed_again(self):
        d = os.path.join(self.env.dir, 'tr4')
        os.makedirs(d, exist_ok=True)
        lines = [json.dumps({'vhost': 'mail.example.com', 'path': '/owa/auth/logon.aspx', 'http_status': 200})] * 5
        lines += [json.dumps({'vhost': 'push.example.com', 'path': '/Microsoft-Server-ActiveSync?Cmd=Ping', 'http_status': 200})] * 9
        with open(os.path.join(d, 'access.log'), 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        self.app.cfg.data['traffic']['logs'] = [d + '/*access.log']
        self.assertEqual(software.scan_logs(self.app.cfg).get('Exchange (OWA)'), {'mail.example.com': 5})   # ActiveSync alone: no
        software.refresh(self.app, 'alice')
        r = self.app.db.one("SELECT id FROM software WHERE name='Exchange (OWA)'")
        software.save(self.app.db, 'alice', 'Exchange 2019', '', ['mail.example.com'], sid=r['id'])
        software.refresh(self.app, 'alice')
        names = {x['name'] for x in software.listing(self.app.db)}
        self.assertIn('Exchange 2019', names)
        self.assertIn('Z-Push', names)                              # push.example.com: ActiveSync alone
        self.assertNotIn('Exchange (OWA)', names)                    # the person's rename stands
        self.app.db.x("DELETE FROM software WHERE name IN ('Exchange 2019', 'Z-Push')")
        self.app.db.set_meta(software.DISMISSED_KEY, '[]')

    def test_activesync_alone_is_zpush_unless_a_mail_server_answers_there(self):
        d = os.path.join(self.env.dir, 'tr5')
        os.makedirs(d, exist_ok=True)
        lines = [json.dumps({'vhost': 'push.example.com', 'path': '/Microsoft-Server-ActiveSync?Cmd=Ping', 'http_status': 200})] * 5
        lines += [json.dumps({'vhost': 'mail.example.com', 'path': p, 'http_status': 200})
                  for p in ('/Microsoft-Server-ActiveSync?Cmd=Sync', '/service/soap/AuthRequest') * 4]
        lines += [json.dumps({'vhost': 'mon.example.com', 'path': '/api/v0/devices', 'http_status': 200})] * 4
        with open(os.path.join(d, 'access.log'), 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        self.app.cfg.data['traffic']['logs'] = [d + '/*access.log']
        by = {g['name']: g['hosts'] for g in software.guess(self.app) if g['kind'] == 'site'}
        self.assertEqual(by.get('Z-Push'), ['push.example.com'])         # mail.example.com is Zimbra's own ActiveSync
        self.assertEqual(by.get('Zimbra'), ['mail.example.com'])
        self.assertEqual(by.get('LibreNMS / Observium'), ['mon.example.com'])

    def test_validation(self):
        for name, ver in (('<script>', '1'), ('ok', 'a b'), ('', '1')):
            with self.assertRaises(software.SoftwareError):
                software.save(self.app.db, 'a', name, ver)
        software.save(self.app.db, 'a', 'Grafana', '11.2.0')
        with self.assertRaises(software.SoftwareError):
            software.save(self.app.db, 'a', 'Grafana', '11.2.0')


class TestIntelApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv()
        cls.app = App(cls.env.cfg)
        a = cls.app.auth
        a.create_user('viewer1', 'viewer', password=PW)
        a.create_user('admin1', 'admin', password=PW)
        cls.secret, _ = a.totp_setup('admin1')
        a.totp_enable('admin1', auth.totp_code(cls.secret, int(time.time() // 30)))
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.env.cleanup()

    def admin(self):
        self.app.db.x("UPDATE users SET totp_last_step=0 WHERE username='admin1'")
        c = Client(self.port)
        self.assertEqual(c.login('admin1', totp=auth.totp_code(self.secret, int(time.time() // 30)))[0], 200)
        return c

    def test_software_and_run(self):
        v = Client(self.port)
        self.assertEqual(v.login('viewer1')[0], 200)
        st, obj, _ = v.req('GET', '/api/v1/intel')
        self.assertEqual(st, 200)
        self.assertEqual(obj['status']['not_ready_reason'], 'disabled')
        self.assertEqual(v.req('POST', '/api/v1/intel/software', {'name': 'Grafana', 'version': '11.2.0'})[0], 403)
        c = self.admin()
        st, obj, _ = c.req('POST', '/api/v1/intel/software', {'name': 'Grafana', 'version': '11.2.0', 'hosts': ['mon.example.com']})
        self.assertEqual(st, 201, obj)
        sid = obj['software'][0]['id']
        self.assertTrue(obj['software'][0]['confirmed'])
        self.assertEqual(c.req('POST', '/api/v1/intel/software', {'name': 'Grafana', 'version': '1'})[0], 409)
        # the same product on another server, another version: its own entry, its own sites (never the same site twice)
        st, obj, _ = c.req('POST', '/api/v1/intel/software', {'name': 'Grafana', 'version': '10.4.1', 'hosts': ['mon2.example.com']})
        self.assertEqual(st, 201, obj)
        self.assertEqual(c.req('POST', '/api/v1/intel/software', {'name': 'Grafana', 'version': '9', 'hosts': ['mon2.example.com']})[0], 409)
        self.assertEqual([p for p in software.confirmed(self.app.db) if p['name'] == 'Grafana'],
                         [{'name': 'Grafana', 'version': '10.4.1, 11.2.0'}])        # one line, every version, no sites
        self.assertEqual(software.hosts_of(self.app.db, 'Grafana'), ['mon.example.com', 'mon2.example.com'])
        g2 = [x for x in c.req('GET', '/api/v1/intel')[1]['software'] if x['name'] == 'Grafana' and x['version'] == '10.4.1'][0]
        self.assertEqual(c.req('DELETE', '/api/v1/intel/software/%d' % g2['id'])[0], 200)
        self.assertEqual(c.req('POST', '/api/v1/intel/software', {'name': 'x<y', 'version': '1'})[0], 400)
        st, obj, _ = c.req('PATCH', '/api/v1/intel/software/%d' % sid, {'version': '11.3.0', 'confirmed': False})
        self.assertEqual((st, obj['software'][0]['version'], obj['software'][0]['confirmed']), (200, '11.3.0', False))
        st, obj, _ = c.req('POST', '/api/v1/intel/software/guess', {})
        self.assertEqual(st, 200)
        self.assertIn('added', obj)
        st, obj, _ = c.req('POST', '/api/v1/intel/software/confirm-all', {})
        self.assertEqual(st, 200)
        self.assertGreaterEqual(obj['confirmed'], 1)                                # the edited entry, plus any guesses
        self.assertTrue(all(x['confirmed'] for x in obj['software']))
        self.assertEqual(c.req('POST', '/api/v1/intel/run', {})[0], 409)          # not switched on
        self.assertEqual(c.req('DELETE', '/api/v1/intel/software/%d' % sid)[0], 200)
        self.assertEqual(c.req('DELETE', '/api/v1/intel/software/%d' % sid)[0], 404)
        self.assertEqual(c.req('POST', '/api/v1/intel/threats/999', {'status': 'handled'})[0], 404)
        for action in ('software.added', 'software.changed', 'software.guessed', 'software.removed', 'software.confirmed_all'):
            self.assertTrue(self.app.db.one('SELECT 1 FROM audit WHERE action=?', (action,)), action)



def responses_reply(text=None, calls=None, searches=(), rid='resp_1'):
    out = [{'type': 'web_search_call', 'id': 'ws_%d' % i, 'status': 'completed',
            'action': {'type': 'search', 'query': q, 'sources': [{'type': 'url', 'url': 'https://nvd.nist.gov/vuln/x%d' % i}]}}
           for i, q in enumerate(searches)]
    for i, (n, a) in enumerate(calls or []):
        out.append({'type': 'function_call', 'id': 'fc_%d' % i, 'call_id': 'call_%d' % i, 'name': n, 'arguments': json.dumps(a)})
    if text is not None:
        out.append({'type': 'message', 'id': 'msg_1', 'status': 'completed', 'role': 'assistant',
                    'content': [{'type': 'output_text', 'text': text, 'annotations': []}]})
    return {'id': rid, 'object': 'response', 'status': 'completed', 'output': out, 'usage': {'input_tokens': 900, 'output_tokens': 100}}


class TestOpenAIProviderSearch(Base):
    """OpenAI's own web search (Responses API) plus our fetch_url: "exploited" still needs a CISA page read here."""
    def setUp(self):
        super().setUp()
        self.old = intel.OPENAI_URL
        intel.OPENAI_URL = self.url + '/v1'           # the fake stands in for api.openai.com
        self.app.cfg.data['intel'].update(search='provider', patches=False)

    def tearDown(self):
        intel.OPENAI_URL = self.old
        super().tearDown()

    def test_search_fetch_and_answer(self):
        Fake.script = [responses_reply(searches=['Example CMS CVE 2026'],
                                       calls=[('fetch_url', {'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'})], rid='r1'),
                       responses_reply(text=json.dumps(ANSWER), rid='r2')]
        old_public, old_get = intel._public, intel._get_pinned
        intel._public = lambda h, p: '203.0.113.5'
        intel._get_pinned = lambda u, ip, t: (200, {'content-type': 'text/html'}, b'<td>CVE-2026-11111</td>')
        try:
            rid = intel.run(self.app, 'manual', log=lambda m: None)
        finally:
            intel._public, intel._get_pinned = old_public, old_get
        r = self.app.db.one('SELECT * FROM intel_runs WHERE id=?', (rid,))
        self.assertIsNone(r['error'])
        self.assertEqual((r['tokens_in'], r['tokens_out']), (1800, 200))
        self.assertEqual(json.loads(r['searches']), ['Example CMS CVE 2026'])
        first, second = [b for p, h, b in Fake.seen if p == '/v1/responses']
        self.assertEqual([t['type'] for t in first['tools']], ['web_search', 'function'])
        self.assertEqual((second['previous_response_id'], second['input'][0]['type'], second['input'][0]['call_id']),
                         ('r1', 'function_call_output', 'call_0'))
        t = self.app.db.one("SELECT exploited FROM intel_threats WHERE cve='CVE-2026-11111'")
        self.assertEqual(t['exploited'], 1)                       # read on the CISA page in this run

    def test_json_asked_again_when_the_text_is_not_json(self):
        Fake.script = [responses_reply(text='Here is what I found: nothing new.'), responses_reply(text=json.dumps({'notes': '', 'threats': []}))]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        self.assertIsNone(self.app.db.one('SELECT error FROM intel_runs WHERE id=?', (rid,))['error'])
        last = [b for p, h, b in Fake.seen if p == '/v1/responses'][-1]
        self.assertEqual(last['text']['format']['type'], 'json_schema')

    def test_needs_openai_itself(self):
        intel.OPENAI_URL = 'https://api.openai.com/v1'
        self.assertEqual(intel.readiness(self.app.cfg), 'provider_search_unsupported')


class TestConnectionTest(Base):
    """Settings > "Test connection" for the second tier: done by the intel unit, even before it is switched on."""
    def test_openai_and_search(self):
        self.app.cfg.data['intel']['enabled'] = False
        intel.request_test(self.app.cfg)
        Fake.script = [openai_reply(content='OK')]
        intel.run_job(self.app, log=lambda m: None)
        r = intel.test_result(self.app.cfg)
        self.assertTrue(r['ok'], r)
        self.assertEqual((r['models'], r['model'], r['reply']), (['m', 'big-model'], 'm', 'OK'))
        self.assertNotIn('search', r)                             # the MCP server has its own test button
        self.assertFalse(os.path.exists(intel._state(self.app.cfg, intel.TEST_REQUEST)))
        self.assertEqual(self.app.db.one("SELECT COUNT(*) FROM intel_runs")[0], 0)          # no search was run
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='intel.tested'"))

    def test_failure_hides_the_key(self):
        self.app.cfg.data['intel'].update(model='nope', api_key='secret-key-123')
        intel.request_test(self.app.cfg)
        intel.run_job(self.app, log=lambda m: None)
        r = intel.test_result(self.app.cfg)
        self.assertEqual((r['ok'], r['error']), (False, 'model_not_found'))
        self.assertNotIn('secret-key-123', json.dumps(r))

    def test_mcp_only(self):
        self.app.cfg.data['intel'].update(enabled=False, url='', api_key='')     # no LLM needed
        intel.request_test(self.app.cfg, 'mcp')
        intel.run_job(self.app, log=lambda m: None)
        r = intel.test_result(self.app.cfg)
        self.assertEqual((r['ok'], r['what'], r['search']['tools']), (True, 'mcp', ['web_search', 'code_search']))
        self.assertFalse([p for p, h, b in Fake.seen if p.startswith('/v1/')])           # the LLM was not asked
        self.app.cfg.data['intel']['mcp_url'] = 'http://127.0.0.1:9/mcp'
        intel.request_test(self.app.cfg, 'mcp')
        intel.run_job(self.app, log=lambda m: None)
        self.assertEqual(intel.test_result(self.app.cfg)['error'], 'mcp_unreachable')

    def test_anthropic(self):
        self.app.cfg.data['intel'].update(provider='anthropic', url=self.url, model='')
        Fake.script = [{'content': [{'type': 'text', 'text': 'OK'}], 'usage': {}}]
        r = intel.connection_test(self.app.cfg)
        self.assertEqual((r['model'], r['reply'], r['models']), (intel.ANTHROPIC_MODEL, 'OK', ['m', 'big-model']))
        get = [h for p, h, b in Fake.seen if p.startswith('/v1/models')][0]
        self.assertEqual(get['x-api-key'], 'k')


if __name__ == '__main__':
    unittest.main()
