"""Sandbox: a throwaway nginx on 127.0.0.1 with the production ModSecurity configuration plus a
candidate change (SPEC 6.3). Its audit log stays in a temporary directory (never reaches the
production log or the SIEM). Client addresses come from X-Forwarded-For, trusted in the sandbox
only. Runs as the service user; nothing is left behind (processes, files, ports).
"""
import http.client
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time

from . import util
from .managed import FILES
from .nginxconf import NginxConfig, walk

EXTERNAL_IP = '203.0.113.50'
AUDIT_REWRITE = re.compile(r'^(\s*)(SecAuditLog|SecAuditLogStorageDir|SecTmpDir|SecDataDir|SecUploadDir|SecDebugLog)\b.*$',
                           re.I | re.M)


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class SandboxError(Exception):
    pass


class Sandbox:
    def __init__(self, cfg, site):
        self.cfg = cfg
        self.site = site
        self.nginx = cfg['paths']['nginx_bin']
        self.base = cfg['managed']['sandbox_dir']

    @property
    def internal_ip(self):
        """An address inside the internal networks that is not a known scanner (computed each time: both
        lists can change in Settings)."""
        for n in sorted((n for n in self.cfg.internal_networks if n.version == 4), key=lambda n: -n.num_addresses):
            for off in (50, 51, 77, 100, 150, 200, 2, 1):
                if off >= n.num_addresses:
                    continue
                ip = n.network_address + off
                if not any(ip in s for s in self.cfg.known_scanners if s.version == 4):
                    return str(ip)
        return '10.0.0.50'

    def available(self):
        if not (os.path.isfile(self.nginx) and os.access(self.nginx, os.X_OK)):
            return False
        try:
            _, m = self.site.load()
            return bool(m.main_files)
        except Exception:
            return False

    # --- configuration ----------------------------------------------------------------------
    def _modules(self):
        n, _ = self.site.load()
        return [d.args[0] for d, ctx in walk(n.tree) if d.name == 'load_module' and d.args and not ctx]

    def build(self, root, replace, crs_swap=None, crs_add=None):
        # crs_add: (main file, anchor Include or None, [Include paths]) -- a first CRS installation: the paths go
        # right after the anchor (or at the end of that main file)
        """Writes <root>/conf/*.conf. replace: {absolute production path: text to use instead}. crs_swap: (the CRS
        directory the main file includes, another CRS version's directory) -- the same configuration with the other
        CRS rules (a CRS update compared in the sandbox)."""
        conf = os.path.join(root, 'conf')
        tmp = os.path.join(root, 'tmp')
        logs = os.path.join(root, 'logs')
        for d in (conf, tmp, logs):
            os.makedirs(d, mode=0o700, exist_ok=True)
        _, m = self.site.load()
        mains = []
        for i, main in enumerate(m.main_files):
            out = []
            with open(main, encoding='utf-8', errors='replace') as fh:
                text = fh.read()
            add = crs_add if crs_add and crs_add[0] == main else None
            added = False
            for line in text.splitlines():
                mm = re.match(r'(\s*)Include\s+"?([^"\s]+)"?\s*$', line, re.I)
                if not mm:
                    out.append(self._rewrite(line, root))
                    continue
                p = mm.group(2)
                p = p if os.path.isabs(p) else os.path.join(os.path.dirname(main), p)
                if add and not added and add[1] == p:
                    # the anchor (modsecurity.conf, with SecAuditLog) and the new CRS files go through the same
                    # rewrite as any other Include: the sandbox never writes the production audit log
                    out.append(self._include(p, replace, conf, root, len(out)))
                    out += [self._include(x, replace, conf, root, len(out) + j) for j, x in enumerate(add[2])]
                    added = True
                    continue
                if crs_swap and p.startswith(crs_swap[0].rstrip('/') + '/'):
                    p = crs_swap[1].rstrip('/') + p[len(crs_swap[0].rstrip('/')):]
                out.append(self._include(p, replace, conf, root, len(out)))
            if add and not added:
                out += [self._include(x, replace, conf, root, len(out) + j) for j, x in enumerate(add[2])]
            dst = os.path.join(conf, 'main-%d.conf' % i)
            with open(dst, 'w', encoding='utf-8') as fh:
                fh.write('\n'.join(out) + '\n')
            mains.append(dst)
        port, backend = free_port(), free_port()
        mods = ''.join('load_module %s;\n' % p for p in self._modules())
        nginx_conf = """%(mods)sworker_processes 1;
pid %(root)s/nginx.pid;
error_log %(root)s/logs/error.log warn;
events { worker_connections 256; }
http {
    access_log off;
    client_body_temp_path %(tmp)s/body; proxy_temp_path %(tmp)s/proxy; fastcgi_temp_path %(tmp)s/fcgi;
    uwsgi_temp_path %(tmp)s/uwsgi; scgi_temp_path %(tmp)s/scgi;
    modsecurity off;
%(rules)s
    modsecurity_transaction_id "case-$http_x_jtwaf_case-$request_id";
    server { listen 127.0.0.1:%(backend)d; location / { return 200 "ok\\n"; } }
    server {
        listen 127.0.0.1:%(port)d;
        set_real_ip_from 127.0.0.1;
        real_ip_header X-Forwarded-For;
        client_max_body_size 20m;
        modsecurity on;
        location / { proxy_pass http://127.0.0.1:%(backend)d; proxy_set_header Host $host; }
    }
}
""" % {'mods': mods, 'root': root, 'tmp': tmp, 'backend': backend, 'port': port,
       'rules': ''.join('    modsecurity_rules_file %s;\n' % p for p in mains)}
        with open(os.path.join(conf, 'nginx.conf'), 'w') as fh:
            fh.write(nginx_conf)
        return port

    def _include(self, p, replace, conf, root, n):
        """The Include line for production file p in the sandbox: the candidate text when p is replaced, a copy
        with SecAuditLog / SecDebugLog / directories pointed into the sandbox when p sets them, else p itself."""
        if p in replace:
            dst = os.path.join(conf, 'cand-%s' % os.path.basename(p))
            with open(dst, 'w', encoding='utf-8') as fh:
                fh.write(replace[p])
            return 'Include %s' % dst
        if not any(ch in p for ch in '*?[') and os.path.isfile(p) and self._needs_rewrite(p):
            dst = os.path.join(conf, 'rw-%d-%s' % (n, os.path.basename(p)))
            with open(p, encoding='utf-8', errors='replace') as fh:
                body = fh.read()
            with open(dst, 'w', encoding='utf-8') as fh:
                fh.write(AUDIT_REWRITE.sub(lambda x: self._audit_line(x, root), body))
            return 'Include %s' % dst
        return 'Include %s' % p

    @staticmethod
    def _needs_rewrite(path):
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                return bool(AUDIT_REWRITE.search(fh.read()))
        except OSError:
            return False

    @staticmethod
    def _audit_line(m, root):
        d = m.group(2).lower()
        target = {'secauditlog': os.path.join(root, 'logs', 'audit.log'),
                  'secdebuglog': os.path.join(root, 'logs', 'debug.log')}.get(d, os.path.join(root, 'tmp') + '/')
        return '%s%s %s' % (m.group(1), m.group(2), target)

    def _rewrite(self, line, root):
        return AUDIT_REWRITE.sub(lambda x: self._audit_line(x, root), line)

    # --- running ----------------------------------------------------------------------------
    def run(self, replace, cases, crs_swap=None, crs_add=None):
        """Starts a sandbox with `replace`, sends `cases`, returns per-case results. Always cleans up."""
        os.makedirs(self.base, mode=0o700, exist_ok=True)
        root = tempfile.mkdtemp(prefix='sbx-', dir=self.base)
        pid = None
        try:
            port = self.build(root, replace, crs_swap, crs_add)
            conf = os.path.join(root, 'conf', 'nginx.conf')
            base_cmd = [self.nginx, '-p', root + '/', '-c', conf, '-e', os.path.join(root, 'logs', 'error.log')]
            t = subprocess.run(base_cmd + ['-t'], capture_output=True, text=True, timeout=120)
            if t.returncode != 0:
                raise SandboxError('nginx -t failed: ' + _clean(t.stderr)[-1500:])
            s = subprocess.run(base_cmd, capture_output=True, text=True, timeout=120)
            if s.returncode != 0:
                raise SandboxError('nginx did not start: ' + _clean(s.stderr)[-1500:])
            pid = self._wait_pid(root)
            self._wait_port(port)
            results = []
            for i, c in enumerate(cases):
                results.append(self._send(port, i, c))
            audits = self._read_audit(root)
            for i, r in enumerate(results):
                a = audits.get(str(i), {})
                r['rules'] = a.get('rules', [])
                r['engine'] = a.get('engine')
            return results
        finally:
            self._stop(root, pid)
            shutil.rmtree(root, ignore_errors=True)

    @staticmethod
    def _wait_pid(root):
        for _ in range(50):
            try:
                with open(os.path.join(root, 'nginx.pid')) as fh:
                    return int(fh.read().strip())
            except (OSError, ValueError):
                time.sleep(0.1)
        raise SandboxError('nginx wrote no pid file')

    @staticmethod
    def _wait_port(port):
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', port), 0.5).close()
                return
            except OSError:
                time.sleep(0.1)
        raise SandboxError('sandbox port did not open')

    def _send(self, port, i, c):
        ip = EXTERNAL_IP if c.get('source', 'external') == 'external' else self.internal_ip
        headers = {'Host': c['host'], 'X-Forwarded-For': ip, 'X-JTWAF-Case': str(i),
                   'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) jt-waf-mgr-sandbox'}
        headers.update(c.get('headers') or {})
        body = c.get('body')
        if body is not None and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        try:
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
            conn.putrequest(c.get('method', 'GET'), c['path'], skip_host=True, skip_accept_encoding=True)
            for k, v in headers.items():
                conn.putheader(k, v)
            data = body.encode('utf-8') if isinstance(body, str) else None
            if data is not None:
                conn.putheader('Content-Length', str(len(data)))
            conn.endheaders(data)
            r = conn.getresponse()
            r.read()
            status = r.status
            conn.close()
        except Exception as e:
            status = 'error:%s' % type(e).__name__
        return {'case': i, 'status': status}

    @staticmethod
    def _read_audit(root):
        out = {}
        try:
            fh = open(os.path.join(root, 'logs', 'audit.log'), encoding='utf-8', errors='replace')
        except OSError:
            return out
        with fh:
            for line in fh:
                try:
                    t = json.loads(line)['transaction']
                except Exception:
                    continue
                m = re.match(r'^case-(\d+)-', t.get('unique_id', ''))
                if not m:
                    continue
                ids = []
                for msg in t.get('messages') or []:
                    try:
                        ids.append(int(msg['details']['ruleId']))
                    except (KeyError, ValueError, TypeError):
                        pass
                out[m.group(1)] = {'rules': ids, 'engine': (t.get('producer') or {}).get('secrules_engine')}
        return out

    @staticmethod
    def _stop(root, pid):
        if pid:
            try:
                os.kill(pid, signal.SIGQUIT)
            except ProcessLookupError:
                return
            for _ in range(100):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return
                time.sleep(0.1)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    # --- a change ---------------------------------------------------------------------------
    def replacements(self, files, managed):
        """Which production files the candidate replaces: the managed files once adopted, else the
        files adoption would take over."""
        if managed.adopted():
            return {managed.path(p): files[p] for p in FILES}
        b, a = managed.detect_import_files()
        out = {}
        if b:
            out[b] = files['before']
        if a:
            out[a] = files['after']
        return out

    @staticmethod
    def _blocks(r):
        """The confident blocks a change adds or changes: [spec]."""
        spec = r['spec']
        spec = json.loads(spec) if isinstance(spec, str) else spec
        if r['op'] == 'bundle':
            return [b['spec'] for b in spec.get('ops', []) if b['kind'] == 'confident_block' and b['op'] in ('add', 'modify')]
        return [spec] if r['kind'] == 'confident_block' and r['op'] in ('add', 'modify') else []

    def cases_for(self, r, user_tests, samples):
        cases = []
        blocks = self._blocks(r)
        sources = {(b.get('source') or 'external') for b in blocks}
        for t in user_tests:
            cases.append(dict(t, origin='test'))
            # path blocks must survive encoding / case / slash tricks (LESSONS 14)
            if blocks and t.get('expect') == 403 and t.get('source') == 'external':
                p, _, q = t['path'].partition('?')
                variants = {p.upper(), p.replace('/', '//', 1), re.sub(r'[a-z]', lambda x: '%%%02x' % ord(x.group(0)), p, 1)}
                for v in sorted(variants - {p}):
                    cases.append(dict(t, path=v + ('?' + q if q else ''), origin='variant'))
                # the same request from inside: let through by an external-only block, refused by one that
                # also covers internal sources (a bundle mixing both cannot tell which rule a test is for)
                if sources == {'external'}:
                    cases.append(dict(t, source='internal', expect=200, origin='internal-same'))
                elif sources == {'all'}:
                    cases.append(dict(t, source='internal', expect=403, origin='internal-same'))
        if r['direction'] == 'tighten' or r['kind'] in ('raw', 'bundle'):
            for s in samples:
                cases.append({'host': s['host'], 'method': s['method'], 'path': s['path'], 'source': 'external',
                              'expect': 'not403', 'origin': 'regression'})
        return cases

    def run_change(self, r, files, user_tests, managed, samples=None):
        adds = r['op'] == 'add' and r['kind'] == 'confident_block' or r['op'] == 'bundle' and any(
            b['op'] == 'add' and b['kind'] == 'confident_block' for b in json.loads(r['spec']).get('ops', []))
        if r['op'] == 'bundle':
            # each confident block of a bundle needs its own 403 test (one rule's test must not vouch for another)
            for b in json.loads(r['spec']).get('ops', []):
                if b['kind'] == 'confident_block' and b['op'] in ('add', 'modify') and not any(
                        t.get('expect') == 403 and t.get('source', 'external') == 'external' and _test_hits(b['spec'], t)
                        for t in user_tests):
                    return {'ok': False, 'error': 'test_per_block', 'rule_id': b.get('rule_id'),
                            'message': 'rule %s: no external test expecting 403 that it matches' % b.get('rule_id')}
        if adds and not any(t.get('expect') == 403 for t in user_tests):
            return {'ok': False, 'error': 'test_required', 'message': 'a confident block needs at least one test case expecting 403'}
        cases = self.cases_for(r, user_tests, samples or [])
        if not cases:
            cases = [{'host': 'sandbox.invalid', 'path': '/', 'source': 'external', 'expect': 'not403', 'origin': 'smoke'}]
        try:
            res = self.run(self.replacements(files, managed), cases)
        except SandboxError as e:
            return {'ok': False, 'error': 'sandbox_failed', 'message': _clean(str(e))[-2000:]}
        return evaluate(cases, res, self.cfg)

    def run_crs_compare(self, crs_dir, new_dir, requests):
        """A CRS update: the same requests through the CRS in use and through new_dir (everything else as it is).
        Differences in status or matched rules, with counts of newly blocked and no longer blocked requests."""
        try:
            old = self.run({}, requests)
            new = self.run({}, requests, crs_swap=(crs_dir, new_dir))
        except SandboxError as e:
            return {'ok': False, 'error': 'sandbox_failed', 'message': _clean(str(e))[-2000:]}
        return self._compare(requests, old, new)

    def run_crs_first(self, main, anchor, new_dir, requests):
        """A first CRS installation: the same requests without and with the CRS (its example setup and its rules)."""
        try:
            old = self.run({}, requests)
            new = self.run({}, requests, crs_add=(main, anchor, [os.path.join(new_dir, 'crs-setup.conf.example'),
                                                               os.path.join(new_dir, 'rules', '*.conf')]))
        except SandboxError as e:
            return {'ok': False, 'error': 'sandbox_failed', 'message': _clean(str(e))[-2000:]}
        return self._compare(requests, old, new)

    @staticmethod
    def _refused(r):
        """Refused in the sandbox: any 4xx / 5xx. The sandbox backend answers 200 to everything, so an error status
        comes from ModSecurity (403, or a site's own status:406 / 400 ...) or nginx, never from the application."""
        return isinstance(r.get('status'), int) and r['status'] >= 400

    @classmethod
    def _compare(cls, requests, old, new):
        diffs, more, fewer = [], 0, 0
        for c, a, b in zip(requests, old, new):
            if a['status'] != b['status'] or sorted(a['rules']) != sorted(b['rules']):
                more += not cls._refused(a) and cls._refused(b)
                fewer += cls._refused(a) and not cls._refused(b)
                diffs.append({'request': _case_view(c), 'before': [a['status'], a['rules']], 'after': [b['status'], b['rules']]})
        return {'ok': True, 'requests': len(requests), 'blocked_before': sum(1 for a in old if cls._refused(a)),
                'blocked_after': sum(1 for b in new if cls._refused(b)), 'newly_blocked': more, 'no_longer_blocked': fewer,
                'changed': len(diffs), 'differences': diffs[:50]}

    def run_equivalence(self, files, managed, requests):
        """Adoption: the same requests through the current and the candidate configuration."""
        try:
            old = self.run({}, requests)
            new = self.run(self.replacements(files, managed), requests)
        except SandboxError as e:
            return {'ok': False, 'error': 'sandbox_failed', 'message': _clean(str(e))[-2000:]}
        diffs = []
        for c, a, b in zip(requests, old, new):
            if a['status'] != b['status'] or sorted(a['rules']) != sorted(b['rules']):
                diffs.append({'request': _case_view(c), 'before': [a['status'], a['rules']], 'after': [b['status'], b['rules']]})
        blocked = sum(1 for a in old if a['status'] == 403)
        return {'ok': not diffs, 'requests': len(requests), 'blocked_before': blocked, 'differences': diffs[:50]}


def _test_hits(spec, t):
    """Whether a confident block's own condition matches a test request (host / path / User-Agent)."""
    from .evidence import Evidence, _Rx
    view = Evidence.rule_view(spec)
    if view is None:          # a header the test case may not carry: the sandbox run decides
        return True
    hdr = {k.lower(): v for k, v in (t.get('headers') or {}).items()}
    d = {'uri': t.get('path') or '/', 'esc': False, 'ua': hdr.get('user-agent', ''), 'host': t.get('host') or ''}
    try:
        return bool(_Rx(spec['regex']).search(view(d)))
    except Exception:
        return False


def evaluate(cases, res, cfg):
    fallback = set(cfg['waf']['fallback_rule_ids'])
    out, ok = [], True
    for c, r in zip(cases, res):
        st = r['status']
        exp = c.get('expect')
        good = (st != 403 and isinstance(st, int)) if exp == 'not403' else st == exp
        note = ''
        if st == 403 and 949110 not in r['rules'] and set(r['rules']) & fallback:
            good, note = False, 'refused by the fallback rule, not by 949110'
        for rid in c.get('absent_rules') or []:
            if rid in r['rules']:
                good, note = False, 'rule %d still matches' % rid
        for rid in c.get('present_rules') or []:
            if rid not in r['rules']:
                good, note = False, 'rule %d did not match' % rid
        ok = ok and good
        out.append(dict(_case_view(c), expect=exp, status=st, rules=r['rules'][:30], ok=good, note=note))
    return {'ok': ok, 'cases': len(out), 'failed': sum(1 for x in out if not x['ok']),
            'results': [x for x in out if not x['ok']][:50] + [x for x in out if x['ok'] and x['origin'] != 'regression'][:50],
            'regression_checked': sum(1 for x in out if x['origin'] == 'regression')}


def _case_view(c):
    return {'origin': c.get('origin', 'test'), 'source': c.get('source', 'external'), 'host': c['host'],
            'method': c.get('method', 'GET'), 'path': util.clip(c['path'], 300)}


def _clean(s):
    return re.sub(r'[^\x09\x0a\x20-\x7e]', '?', s or '')
