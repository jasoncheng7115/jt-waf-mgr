"""HTTP server (standard library), request routing, authentication and security headers.

Listens on 127.0.0.1 behind nginx. Only a trusted proxy may supply the client address.
"""
import gzip
import hmac
import http.server
import json
import mimetypes
import os
import re
import socketserver
import sys
import threading
import traceback
import urllib.parse
from http.cookies import SimpleCookie

from .. import util
from ..auth import AuthError

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
SECURITY_HEADERS = [
    ('Content-Security-Policy', CSP),
    ('X-Content-Type-Options', 'nosniff'),
    ('X-Frame-Options', 'DENY'),
    ('Referrer-Policy', 'no-referrer'),
    ('Cross-Origin-Opener-Policy', 'same-origin'),
    ('Cross-Origin-Resource-Policy', 'same-origin'),
    ('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()'),
]
ROLE_RANK = {'viewer': 1, 'operator': 2, 'approver': 3, 'admin': 4}


class ApiError(Exception):
    def __init__(self, status, code, message='', **details):
        super().__init__(code)
        self.status, self.code, self.message, self.details = status, code, message or code.replace('_', ' '), details


class Response:
    def __init__(self, status=200, body=b'', ctype='application/json', headers=None):
        self.status, self.body, self.ctype = status, body, ctype
        self.headers = headers or []


def json_response(status, obj, headers=None):
    return Response(status, json.dumps(obj, ensure_ascii=False).encode('utf-8'), 'application/json; charset=utf-8', headers)


class Request:
    def __init__(self, handler, app):
        self.h = handler
        self.app = app
        self.method = handler.command
        u = urllib.parse.urlsplit(handler.path)
        self.path = u.path
        self.query = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        self.headers = handler.headers
        peer = handler.client_address[0]
        self.peer = peer
        self.client_ip = peer
        if util.ip_in(peer, app.cfg.trusted_proxies):
            real = (self.headers.get('X-Real-IP') or '').strip()
            if real:
                self.client_ip = real[:64]
        self.user = None
        self.token = None
        self.csrf = None
        self.sid = None
        self.params = {}
        self._body = None

    def body(self):
        if self._body is None:
            try:
                n = int(self.headers.get('Content-Length') or 0)
            except ValueError:
                raise ApiError(400, 'bad_request', 'invalid Content-Length')
            if n < 0:
                raise ApiError(400, 'bad_request', 'invalid Content-Length')
            if n > self.app.cfg['server']['max_body_bytes']:
                raise ApiError(413, 'payload_too_large')
            raw = self.h.rfile.read(n) if n else b''
            if not raw:
                self._body = {}
            else:
                ctype = (self.headers.get('Content-Type') or '').split(';')[0].strip().lower()
                if ctype != 'application/json':
                    raise ApiError(415, 'bad_request', 'Content-Type must be application/json')
                try:
                    self._body = json.loads(raw)
                except ValueError:
                    raise ApiError(400, 'bad_request', 'invalid JSON')
                if not isinstance(self._body, dict):
                    raise ApiError(400, 'bad_request', 'JSON object expected')
        return self._body

    def actor(self):
        if self.user is not None:
            return self.user['username'], 'user'
        if self.token is not None:
            return self.token['name'], 'token'
        return None, 'anonymous'

    def cookie_name(self):
        return '__Host-jtwaf_sid' if self.app.cfg['server']['secure_cookies'] else 'jtwaf_sid'

    def get_cookie(self):
        raw = self.headers.get('Cookie')
        if not raw:
            return None
        try:
            c = SimpleCookie()
            c.load(raw)
        except Exception:
            return None
        m = c.get(self.cookie_name())
        return m.value if m else None

    def set_cookie_header(self, value, clear=False):
        attrs = ['%s=%s' % (self.cookie_name(), '' if clear else value), 'Path=/', 'HttpOnly', 'SameSite=Lax']
        if self.app.cfg['server']['secure_cookies']:
            attrs.append('Secure')
        if clear:
            attrs.append('Max-Age=0')
        return ('Set-Cookie', '; '.join(attrs))


class Router:
    def __init__(self):
        self.routes = []

    def add(self, method, pattern, fn, perm):
        """perm: 'public' | 'session' (any logged-in user, even with pending password change) |
        ('role', role, scope_or_None) | ('admin',)"""
        rx = re.compile('^' + re.sub(r'\{(\w+)\}', r'(?P<\1>[^/]+)', pattern) + '$')
        self.routes.append((method, rx, fn, perm))

    def match(self, method, path):
        allowed = False
        for m, rx, fn, perm in self.routes:
            g = rx.match(path)
            if g:
                if m == method:
                    return fn, perm, {k: urllib.parse.unquote(v) for k, v in g.groupdict().items()}
                allowed = True
        if allowed:
            raise ApiError(405, 'method_not_allowed')
        raise ApiError(404, 'not_found')


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'jt-waf-mgr'
    sys_version = ''
    timeout = 30

    def version_string(self):
        return 'jt-waf-mgr'

    def log_message(self, fmt, *args):
        pass  # nginx keeps the access log; the audit table keeps the actions

    def do_GET(self):
        self._dispatch()

    def do_HEAD(self):
        self._dispatch(head=True)

    def do_POST(self):
        self._dispatch()

    def do_PATCH(self):
        self._dispatch()

    def do_DELETE(self):
        self._dispatch()

    def do_PUT(self):
        self._dispatch()

    def _dispatch(self, head=False):
        app = self.server.app
        req = Request(self, app)
        try:
            if req.path.startswith('/api/'):
                resp = self._api(app, req)
            else:
                if req.method not in ('GET', 'HEAD'):
                    raise ApiError(405, 'method_not_allowed')
                resp = static(req.path)
        except ApiError as e:
            resp = json_response(e.status, {'error': {'code': e.code, 'message': e.message, 'details': e.details}})
            if e.status == 429 and 'retry_after' in e.details:
                resp.headers.append(('Retry-After', str(e.details['retry_after'])))
        except AuthError as e:
            resp = json_response(e.status, {'error': {'code': e.code, 'message': e.code.replace('_', ' '), 'details': e.details}})
            if e.status == 429 and 'retry_after' in e.details:
                resp.headers.append(('Retry-After', str(e.details['retry_after'])))
        except Exception:
            traceback.print_exc(file=sys.stderr)
            resp = json_response(500, {'error': {'code': 'internal_error', 'message': 'internal error', 'details': {}}})
        self._send(req, resp, head)

    def _api(self, app, req):
        fn, perm, params = app.router.match(req.method, req.path)
        req.params = params
        app.audit.ctx.src_ip = req.client_ip   # audit rows written deeper down get the client address
        try:
            self._authenticate(app, req, perm)
            return fn(app, req)
        finally:
            app.audit.ctx.src_ip = None

    def _authenticate(self, app, req, perm):
        if perm == 'public':
            return
        authz = req.headers.get('Authorization') or ''
        if authz.lower().startswith('bearer '):
            if perm == 'session' or perm[0] == 'admin':
                raise ApiError(403, 'forbidden', 'not available to API tokens')
            req.token = app.auth.token(authz[7:].strip(), req.client_ip)
            scope = perm[2]
            scopes = json.loads(req.token['scopes'])
            if not scope or scope not in scopes:
                app.audit.log('token.denied', req.token['name'], 'token', req.client_ip, 'denied',
                              endpoint='%s %s' % (req.method, req.path[:200]), reason='scope')
                raise ApiError(403, 'forbidden', 'token lacks scope', scope=scope)
            app.audit.log('token.used', req.token['name'], 'token', req.client_ip, 'ok',
                          endpoint='%s %s' % (req.method, req.path[:200]))
            return
        sid = req.get_cookie()
        s = app.auth.session(sid)
        if not s:
            raise ApiError(401, 'not_authenticated')
        req.user, req.csrf = s
        req.sid = sid
        if req.method not in ('GET', 'HEAD'):
            sent = req.headers.get('X-CSRF-Token') or ''
            if not hmac.compare_digest(sent.encode(), req.csrf.encode()):
                raise ApiError(403, 'csrf_failed')
            origin = req.headers.get('Origin')
            if origin and urllib.parse.urlsplit(origin).netloc != (req.headers.get('Host') or ''):
                raise ApiError(403, 'csrf_failed', 'cross-origin request')
        if perm == 'session':
            return
        if req.user['must_change']:
            raise ApiError(403, 'password_change_required')
        if app.auth.totp_missing(req.user):
            raise ApiError(403, 'totp_setup_required')
        need = 'admin' if perm[0] == 'admin' else perm[1]
        if ROLE_RANK.get(req.user['role'], 0) < ROLE_RANK[need]:
            raise ApiError(403, 'forbidden')

    def _send(self, req, resp, head):
        body = resp.body if isinstance(resp.body, bytes) else resp.body.encode('utf-8')
        enc = None
        if len(body) > 1024 and 'gzip' in (self.headers.get('Accept-Encoding') or '') and (
                resp.ctype.startswith(('application/json', 'application/x-ndjson', 'text/', 'application/javascript'))):
            body = gzip.compress(body, 6)
            enc = 'gzip'
        try:
            self.send_response(resp.status)
            self.send_header('Content-Type', resp.ctype)
            self.send_header('Content-Length', str(len(body)))
            if enc:
                self.send_header('Content-Encoding', enc)
                self.send_header('Vary', 'Accept-Encoding')
            for k, v in SECURITY_HEADERS:
                self.send_header(k, v)
            if req.path.startswith('/api/'):
                self.send_header('Cache-Control', 'no-store')
            for k, v in resp.headers:
                self.send_header(k, v)
            self.end_headers()
            if not head and resp.status not in (204, 304):
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


_TYPES = {'.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
          '.html': 'text/html; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
          '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.json': 'application/json', '.txt': 'text/plain; charset=utf-8'}


def static(path):
    root = os.path.realpath(STATIC_DIR)
    rel = urllib.parse.unquote(path).lstrip('/')
    full = os.path.realpath(os.path.join(root, rel)) if rel else os.path.join(root, 'index.html')
    if not full.startswith(root + os.sep) or not os.path.isfile(full):
        if rel.startswith('assets/') or os.path.splitext(rel)[1] in _TYPES and rel != '':
            raise ApiError(404, 'not_found')
        full = os.path.join(root, 'index.html')  # SPA route
        if not os.path.isfile(full):
            return Response(503, b'frontend not built', 'text/plain; charset=utf-8')
    ext = os.path.splitext(full)[1].lower()
    with open(full, 'rb') as fh:
        body = fh.read()
    headers = [('Cache-Control', 'public, max-age=31536000, immutable' if '/assets/' in full else 'no-cache')]
    return Response(200, body, _TYPES.get(ext) or mimetypes.guess_type(full)[0] or 'application/octet-stream', headers)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, app, host, port):
        self.app = app
        if ':' in host:
            import socket
            self.address_family = socket.AF_INET6
        super().__init__((host, port), Handler)


def serve(app, host, port, ready=None):
    srv = Server(app, host, port)
    if ready is not None:
        ready(srv)
    try:
        srv.serve_forever(poll_interval=0.5)
    finally:
        srv.server_close()
    return srv


def start_background(app, host='127.0.0.1', port=0):
    """For tests: start on a free port in a thread, return (server, thread)."""
    srv = Server(app, host, port)
    th = threading.Thread(target=srv.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)
    th.start()
    return srv, th
