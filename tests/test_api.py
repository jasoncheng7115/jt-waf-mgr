import hashlib
import http.client
import json
import time
import unittest

from jtwafmgr import auth
from jtwafmgr.app import App
from jtwafmgr.collector.auditlog import Tailer
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv, record

PW = 'a long test password'


class Client:
    def __init__(self, port, ip=None):
        self.port = port
        self.cookie = None
        self.csrf = None
        self.ip = ip

    def req(self, method, path, body=None, headers=None, raw=False):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        h = {'Host': '127.0.0.1:%d' % self.port}
        if self.cookie:
            h['Cookie'] = self.cookie
        if self.csrf and method not in ('GET', 'HEAD'):
            h['X-CSRF-Token'] = self.csrf
        if self.ip:
            h['X-Real-IP'] = self.ip
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h['Content-Type'] = 'application/json'
        h.update(headers or {})
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        payload = r.read()
        sc = r.getheader('Set-Cookie')
        if sc:
            self.cookie = sc.split(';', 1)[0] if 'Max-Age=0' not in sc else None
        c.close()
        if raw:
            return r, payload
        try:
            obj = json.loads(payload) if payload else None
        except ValueError:
            obj = payload
        return r.status, obj, r

    def login(self, user, pw=PW, totp=None):
        st, obj, _ = self.req('POST', '/api/v1/auth/login', {'username': user, 'password': pw, 'totp': totp})
        if st == 200:
            self.csrf = obj['csrf_token']
        return st, obj


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv()
        cls.app = App(cls.env.cfg)
        a = cls.app.auth
        a.create_user('viewer1', 'viewer', password=PW)
        a.create_user('op1', 'operator', password=PW)
        a.create_user('admin1', 'admin', password=PW)
        cls.admin_secret, _ = a.totp_setup('admin1')
        a.totp_enable('admin1', auth.totp_code(cls.admin_secret, int(time.time() // 30)))
        cls.env.write_log([
            record(host='app.example.com', uri='/../etc/passwd', status=403, engine='Enabled',
                   rules=[930110, 10203, (949110, 'Inbound Anomaly Score Exceeded (Total Score: 10)', '')]),
            record(host='sso.example.com', uri='/realms/x/login-actions', ip='203.0.113.9', status=403, engine='Enabled',
                   rules=[942100, 949110, 10299]),
            record(host='app.example.com', uri='/search?q=<script>alert(1)</script>&password=hunter2', ip='192.168.77.50',
                   rules=[(941100, 'XSS Attack Detected via libinjection', 'Matched Data: <script> found within ARGS:q')]),
        ])
        cls.app.tailer = Tailer(cls.env.cfg, cls.app.db)
        cls.app.tailer.poll()
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.env.cleanup()

    def admin(self):
        # replay protection refuses a code already used in this 30 s window; tests log in often
        self.app.db.x("UPDATE users SET totp_last_step=0 WHERE username='admin1'")
        c = Client(self.port)
        st, obj = c.login('admin1', totp=auth.totp_code(self.admin_secret, int(time.time() // 30)))
        self.assertEqual(st, 200, obj)
        return c

    def test_meta_public_and_headers(self):
        st, obj, r = Client(self.port).req('GET', '/api/v1/meta')
        self.assertEqual(st, 200)
        self.assertEqual(obj['name'], 'jt-waf-mgr')
        csp = r.getheader('Content-Security-Policy')
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn('unsafe-inline', csp)
        self.assertEqual(r.getheader('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(r.getheader('Cache-Control'), 'no-store')
        self.assertEqual(r.getheader('Server'), 'jt-waf-mgr')

    def test_unauthenticated(self):
        st, obj, _ = Client(self.port).req('GET', '/api/v1/events')
        self.assertEqual((st, obj['error']['code']), (401, 'not_authenticated'))

    def test_unknown_route_and_method(self):
        c = Client(self.port)
        self.assertEqual(c.req('GET', '/api/v1/nope')[0], 404)
        self.assertEqual(c.req('DELETE', '/api/v1/meta')[0], 405)

    def test_login_bad(self):
        st, obj = Client(self.port).login('viewer1', 'wrong password!')
        self.assertEqual((st, obj['error']['code']), (401, 'invalid_credentials'))

    def test_must_change_gate(self):
        temp = self.app.auth.create_user('newbie', 'viewer')
        c = Client(self.port)
        st, obj = c.login('newbie', temp)
        self.assertEqual(st, 200)
        self.assertTrue(obj['user']['must_change_password'])
        st, obj, _ = c.req('GET', '/api/v1/events')
        self.assertEqual((st, obj['error']['code']), (403, 'password_change_required'))
        st, _, _ = c.req('POST', '/api/v1/auth/password', {'current_password': temp, 'new_password': 'new long password 1'})
        self.assertEqual(st, 204)
        self.assertEqual(c.req('GET', '/api/v1/events')[0], 200)  # same session still valid

    def test_totp_required_gate_for_admin(self):
        self.app.auth.create_user('admin2', 'admin', password=PW)
        c = Client(self.port)
        st, obj = c.login('admin2')
        self.assertTrue(obj['user']['totp_setup_required'])
        st, obj, _ = c.req('GET', '/api/v1/users')
        self.assertEqual((st, obj['error']['code']), (403, 'totp_setup_required'))
        st, obj, _ = c.req('POST', '/api/v1/auth/totp/setup')
        self.assertEqual(st, 200)
        code = auth.totp_code(obj['secret'], int(time.time() // 30))
        self.assertEqual(c.req('POST', '/api/v1/auth/totp/enable', {'code': code})[0], 204)
        self.assertEqual(c.req('GET', '/api/v1/users')[0], 200)

    def test_csrf_required(self):
        c = Client(self.port)
        c.login('viewer1')
        token = c.csrf
        c.csrf = None
        st, obj, _ = c.req('PATCH', '/api/v1/auth/me', {'language': 'ja'})
        self.assertEqual((st, obj['error']['code']), (403, 'csrf_failed'))
        c.csrf = token
        st, obj, _ = c.req('PATCH', '/api/v1/auth/me', {'language': 'ja'}, headers={'Origin': 'https://evil.example.net'})
        self.assertEqual((st, obj['error']['code']), (403, 'csrf_failed'))
        st, obj, _ = c.req('PATCH', '/api/v1/auth/me', {'language': 'ja'})
        self.assertEqual((st, obj['user']['language']), (200, 'ja'))

    def test_roles(self):
        c = Client(self.port)
        c.login('op1')
        self.assertEqual(c.req('GET', '/api/v1/overview')[0], 200)
        self.assertEqual(c.req('GET', '/api/v1/users')[0], 403)
        self.assertEqual(c.req('GET', '/api/v1/audit')[0], 403)

    def test_events_and_filters(self):
        c = Client(self.port)
        c.login('viewer1')
        st, obj, _ = c.req('GET', '/api/v1/events')
        self.assertEqual(st, 200)
        self.assertEqual(len(obj['items']), 3)
        st, obj, _ = c.req('GET', '/api/v1/events?outcome=blocked&decided_by=score')
        self.assertEqual([e['host'] for e in obj['items']], ['sso.example.com'])
        st, obj, _ = c.req('GET', '/api/v1/events?src_ip=192.168.0.0/16')
        self.assertEqual(len(obj['items']), 1)
        e = obj['items'][0]
        self.assertEqual(e['origin'], 'internal')
        self.assertNotIn('hunter2', json.dumps(obj))
        self.assertIn('<script>', e['query'])  # verbatim text; the UI never renders it as HTML
        st, full, _ = c.req('GET', '/api/v1/events/%d' % e['id'])
        self.assertEqual(full['matches'][0]['rule_id'], 941100)
        self.assertEqual(c.req('GET', '/api/v1/events?outcome=maybe')[0], 400)
        self.assertEqual(c.req('GET', '/api/v1/events/999999')[0], 404)
        st, obj, _ = c.req('GET', '/api/v1/events?limit=1')
        self.assertEqual(len(obj['items']), 1)
        st, obj2, _ = c.req('GET', '/api/v1/events?limit=1&cursor=' + obj['next_cursor'])
        self.assertNotEqual(obj['items'][0]['id'], obj2['items'][0]['id'])

    def test_custom_range_and_event_timeline(self):
        import urllib.parse
        c = Client(self.port)
        c.login('viewer1')
        iso = lambda ts: urllib.parse.quote(time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(ts)))   # noqa: E731
        now = time.time()
        st, o, _ = c.req('GET', '/api/v1/overview?range=custom&since=%s&until=%s' % (iso(now - 2 * 3600), iso(now + 30)))
        self.assertEqual((st, o['range'], o['bucket_seconds'], o['totals']['events']), (200, 'custom', 3600, 3))
        self.assertEqual(sum(b['blocked'] + b['logged'] for b in o['timeline']), 3)
        st, o, _ = c.req('GET', '/api/v1/overview?range=custom&since=%s' % iso(now - 20 * 86400))
        self.assertEqual((st, o['bucket_seconds']), (200, 86400))           # days beyond a week
        for bad in ('range=custom', 'range=custom&since=%s' % iso(now - 40 * 86400), 'range=custom&since=%s' % iso(now - 60),
                    'range=custom&since=x', 'range=1y'):
            self.assertEqual(c.req('GET', '/api/v1/overview?' + bad)[0], 400, bad)
        st, tl, _ = c.req('GET', '/api/v1/events/timeline?outcome=blocked')
        self.assertEqual(st, 200)
        self.assertEqual(sum(b['blocked'] for b in tl['timeline']), 2)
        self.assertEqual(sum(b['logged'] for b in tl['timeline']), 0)
        st, tl, _ = c.req('GET', '/api/v1/events/timeline?since=%s' % iso(now - 90 * 86400))
        self.assertTrue(tl['clamped'])

    def test_reserved_names(self):
        from jtwafmgr.auth import AuthError
        for n in ('analyst', 'system', 'cli'):
            with self.assertRaises(AuthError):
                self.app.auth.create_user(n, 'viewer', password=PW)
            with self.assertRaises(AuthError):
                self.app.auth.create_token(n.upper(), ['events:read'], [], None, 'admin1')

    def test_overview(self):
        c = Client(self.port)
        c.login('viewer1')
        st, o, _ = c.req('GET', '/api/v1/overview?range=24h')
        self.assertEqual(st, 200)
        self.assertEqual(o['totals']['events'], 3)
        self.assertEqual(o['totals']['blocked'], 2)
        self.assertEqual(o['totals']['blocked_score'], 1)
        self.assertEqual([e['host'] for e in o['score_only']], ['sso.example.com'])
        self.assertEqual(o['focus'][0]['host'], 'sso.example.com')
        self.assertEqual(o['focus'][0]['blocked'], 1)
        self.assertEqual(len(o['timeline']), 24)
        self.assertEqual(c.req('GET', '/api/v1/overview?range=1y')[0], 400)

    def test_rules_vhosts_crs_status(self):
        c = Client(self.port)
        c.login('viewer1')
        st, obj, _ = c.req('GET', '/api/v1/rules')
        ids = [r['id'] for r in obj['items']]
        self.assertIn(10203, ids)
        self.assertNotIn(930110, ids)
        r = next(r for r in obj['items'] if r['id'] == 10203)
        self.assertEqual(r['hits_7d'], 1)
        st, obj, _ = c.req('GET', '/api/v1/rules?source=crs&q=traversal')
        self.assertEqual([r['id'] for r in obj['items']], [930110])
        self.assertEqual(c.req('GET', '/api/v1/rules/10111')[1]['hosts'], ['sso.example.com'])
        self.assertEqual(c.req('GET', '/api/v1/rules/1')[0], 404)
        self.assertEqual(len(c.req('GET', '/api/v1/rules/10203/hits')[1]['items']), 1)
        self.assertEqual(c.req('GET', '/api/v1/rules/removals')[0], 200)
        st, obj, _ = c.req('GET', '/api/v1/vhosts')
        self.assertEqual(len(obj['items']), 3)
        st, obj, _ = c.req('GET', '/api/v1/crs')
        self.assertEqual(obj['version'], '4.30.0')
        st, obj, _ = c.req('GET', '/api/v1/status')
        self.assertEqual(obj['engine_mode'], 'DetectionOnly')
        self.assertEqual(obj['collector']['events_total'], 3)

    def test_lookup(self):
        c = Client(self.port)
        c.login('viewer1')
        st, obj, _ = c.req('GET', '/api/v1/lookups/ip/203.0.113.7')
        self.assertEqual(obj['d7']['events'], 1)
        self.assertEqual(obj['origin'], 'external')
        self.assertEqual(c.req('GET', '/api/v1/lookups/ip/not-an-ip')[0], 400)

    def test_admin_users_tokens_and_api_token_use(self):
        c = self.admin()
        st, obj, _ = c.req('POST', '/api/v1/users', {'username': 'zed', 'role': 'viewer'})
        self.assertEqual(st, 201)
        self.assertTrue(obj['temporary_password'])
        self.assertEqual(c.req('POST', '/api/v1/users', {'username': 'zed', 'role': 'viewer'})[0], 409)
        self.assertEqual(c.req('PATCH', '/api/v1/users/admin1', {'role': 'viewer'})[1]['error']['code'], 'cannot_modify_self')
        self.assertEqual(c.req('PATCH', '/api/v1/users/zed', {'disabled': True})[1]['disabled'], True)
        st, obj, _ = c.req('POST', '/api/v1/tokens', {'name': 'archive', 'scopes': ['events:read']})
        self.assertEqual(st, 201)
        secret = obj['secret']
        self.assertEqual(c.req('POST', '/api/v1/tokens', {'name': 'x', 'scopes': ['admin']})[0], 400)
        t = Client(self.port)
        bearer = {'Authorization': 'Bearer ' + secret}
        self.assertEqual(t.req('GET', '/api/v1/events', headers=bearer)[0], 200)
        self.assertEqual(t.req('GET', '/api/v1/rules', headers=bearer)[0], 403)        # scope missing
        self.assertEqual(t.req('GET', '/api/v1/users', headers=bearer)[0], 403)        # never for tokens
        self.assertEqual(t.req('GET', '/api/v1/auth/me', headers=bearer)[0], 403)
        r, body = t.req('GET', '/api/v1/events/export', headers=bearer, raw=True)
        self.assertEqual(r.getheader('X-Content-SHA256'), hashlib.sha256(body).hexdigest())
        self.assertEqual(len(body.splitlines()), 3)
        r, body = t.req('GET', '/api/v1/events/export?cursor=' + r.getheader('X-Next-Cursor'), headers=bearer, raw=True)
        self.assertEqual(body, b'')
        st, obj, _ = c.req('GET', '/api/v1/audit?action=token.used')
        self.assertTrue(obj['items'])
        tid = c.req('GET', '/api/v1/tokens')[1]['items'][0]['id']
        self.assertEqual(c.req('DELETE', '/api/v1/tokens/' + tid)[0], 204)
        self.assertEqual(t.req('GET', '/api/v1/events', headers=bearer)[0], 401)

    def test_logout(self):
        c = Client(self.port)
        c.login('viewer1')
        self.assertEqual(c.req('POST', '/api/v1/auth/logout')[0], 204)
        self.assertEqual(c.req('GET', '/api/v1/auth/me')[0], 401)

    def test_bad_bodies(self):
        c = Client(self.port)
        self.assertEqual(c.req('POST', '/api/v1/auth/login', ['x'])[0], 400)
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        conn.request('POST', '/api/v1/auth/login', body=b'{"a"', headers={'Content-Type': 'application/json'})
        self.assertEqual(conn.getresponse().status, 400)
        conn.close()
        # refused from the declared length, before reading the body
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        conn.putrequest('POST', '/api/v1/auth/login')
        conn.putheader('Content-Type', 'application/json')
        conn.putheader('Content-Length', str(2 * 1048576))
        conn.endheaders(b'{}')
        self.assertEqual(conn.getresponse().status, 413)
        conn.close()

    def test_untrusted_real_ip_header_is_used_only_from_trusted_proxy(self):
        # the test client connects from 127.0.0.1 (a trusted proxy), so X-Real-IP is honoured
        c = Client(self.port, ip='203.0.113.55')
        c.login('viewer1')
        st, obj, _ = self.admin().req('GET', '/api/v1/audit?action=login&actor=viewer1')
        self.assertIn('203.0.113.55', [i['src_ip'] for i in obj['items']])

    def test_static_traversal(self):
        c = Client(self.port)
        r, body = c.req('GET', '/../../etc/passwd', raw=True)
        self.assertNotIn(b'root:', body)
        r, body = c.req('GET', '/assets/%2e%2e/%2e%2e/config.py', raw=True)
        self.assertEqual(r.status, 404)


if __name__ == '__main__':
    unittest.main()
