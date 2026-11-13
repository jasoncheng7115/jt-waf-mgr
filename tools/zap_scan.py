#!/usr/bin/env python3
"""Release gate: OWASP ZAP scan of a disposable, logged-in instance (synthetic data only).

Why a script: a scan that has to be rebuilt by hand before each release is a scan that stops being run.

  tools/zap_scan.py [--minutes N] [--passive-only] [--out DIR]

What it does
  1. starts the synthetic environment of tools/e2e (setup.py: accounts, events, GeoIP test data) on 127.0.0.1;
  2. logs in as the admin (password + one-time code) and gives ZAP the session cookie and CSRF header;
  3. ZAP automation plan: requestor (every GET route of the API, taken from the code, and every page of the
     interface) + spider, passive scan, active scan (attacks on the disposable instance only; the routes that
     would end the session or lock the admin out are excluded), reports (HTML, JSON, Markdown);
  4. summary by risk; every alert that is not accepted in deploy/zap-baseline.conf (with its reason) fails.

ZAP: the snap package on the build host (/snap/zaproxy/current/zap.sh with its own Java 17). Reading the result:
look at the number of URLs first -- a handful means the session did not work and the scan proves nothing.
Exit status: 0 no unaccepted High / Medium / Low alert, 1 otherwise, 2 the scan did not run.
"""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOP)
ZAP = os.environ.get('ZAP_SH', '/snap/zaproxy/current/zap.sh')
JAVA_HOME = os.environ.get('ZAP_JAVA_HOME', '/snap/zaproxy/current/usr/lib/jvm/java-17-openjdk-amd64')
BASELINE = os.path.join(TOP, 'deploy', 'zap-baseline.conf')
PW = 'Smoke-Passw0rd-1'
# never attacked: they end the scanner's own session or lock its account
EXCLUDE = [r'/api/v1/auth/logout.*', r'/api/v1/auth/password.*', r'/api/v1/auth/sessions.*', r'/api/v1/auth/totp/.*',
           r'/api/v1/admin/users.*', r'/api/v1/tokens.*', r'/api/v1/auth/login.*']
PAGES = ['/', '/events', '/rules', '/vhosts', '/crs', '/managed', '/changes', '/changes/new', '/versions', '/config-changes',
         '/guide', '/account', '/admin/users', '/admin/users/review', '/admin/tokens', '/admin/audit', '/admin/system',
         '/admin/compliance', '/admin/settings', '/waf', '/analysis', '/lookup/203.0.113.9', '/login']


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def totp(secret):
    key = base64.b32decode(secret + '=' * (-len(secret) % 8))
    h = hmac.new(key, struct.pack('>Q', int(time.time() // 30)), hashlib.sha1).digest()
    o = h[-1] & 15
    return '%06d' % ((struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000)


def config_text(w, port):
    return f'''[paths]
db = "{w}/c.db"
nginx_conf = "{TOP}/tests/fixtures/site/nginx.conf"
audit_log = "{w}/modsec_audit.log"
nginx_bin = "/nonexistent/nginx"
[server]
secure_cookies = false
listen = "127.0.0.1:{port}"
[syslog]
enabled = false
[collector]
backfill_rotated = false
[managed]
dir = "{w}/managed"
spool = "{w}/spool"
sandbox_dir = "{w}/sandbox"
apply_state = "{w}/apply-state"
[evidence]
access_logs = ["{w}/access.log"]
[traffic]
logs = ["{w}/traffic/*access.log"]
[countries]
enabled = true
dir = "{w}/countries"
rules_dir = "{w}/country-lists"
[blocks]
enabled = true
file = "{w}/nginx-blocks/blocked-ips.conf"
[waf]
focus_sites = ["sso.example.com"]
[integrity]
anchor_file = "{w}/anchors.jsonl"
[backup]
dir = "{w}/backups"
[geoip]
dir = "{w}/geoip"
'''


def start_instance(w):
    port = free_port()
    open(os.path.join(w, 'config.toml'), 'w').write(config_text(w, port))
    subprocess.run([sys.executable, os.path.join(TOP, 'tools', 'e2e', 'setup.py'), w], check=True, stdout=subprocess.DEVNULL)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    proc = subprocess.Popen([sys.executable, '-m', 'jtwafmgr', '--config', os.path.join(w, 'config.toml'), 'serve'],
                            cwd=TOP, env=env, stdout=open(os.path.join(w, 'server.log'), 'w'), stderr=subprocess.STDOUT)
    for _ in range(40):
        try:
            c = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            c.request('GET', '/login')
            if c.getresponse().status == 200:
                break
        except OSError:
            pass
        time.sleep(0.5)
    else:
        proc.terminate()
        raise SystemExit(2)
    secret = json.load(open(os.path.join(w, 'totp.json')))['admin']
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    c.request('POST', '/api/v1/auth/login', body=json.dumps({'username': 'admin', 'password': PW, 'totp': totp(secret)}),
              headers={'Content-Type': 'application/json'})
    r = c.getresponse()
    body = json.loads(r.read())
    if r.status != 200:
        proc.terminate()
        raise SystemExit('login failed: %s' % body)
    cookie = r.getheader('Set-Cookie').split(';', 1)[0]
    return proc, port, cookie, body['csrf_token']


def get_urls(base):
    from jtwafmgr.web import api
    from jtwafmgr.web.server import Router
    r = Router()
    api.register(r)
    urls = [base + p for p in PAGES]
    for method, rx, fn, perm in r.routes:
        if method != 'GET':
            continue
        path = re.sub(r'\(\?P<(\w+)>\[\^/\]\+\)', lambda m: {'ip': '203.0.113.9', 'placement': 'before', 'version': '1',
                                                             'name': 'x', 'id': '1'}.get(m.group(1), '1'), rx.pattern[1:-1])
        urls.append(base + path.replace('\\', ''))
    return sorted(set(urls))


def plan(base, cookie, csrf, out, minutes, passive_only, version):
    name = 'jt-waf-mgr-%s' % version
    jobs = [
        {'type': 'replacer', 'parameters': {'deleteAllRules': True}, 'rules': [
            {'description': 'admin session', 'matchType': 'req_header', 'matchString': 'Cookie', 'matchRegex': False,
             'replacementString': cookie},
            {'description': 'csrf', 'matchType': 'req_header', 'matchString': 'X-CSRF-Token', 'matchRegex': False,
             'replacementString': csrf}]},
        # the first request is a sentinel: 200 only with a working session (ZAP logs a warning otherwise)
        {'type': 'requestor', 'parameters': {}, 'requests': [{'url': base + '/api/v1/auth/me', 'method': 'GET', 'responseCode': 200}]
         + [{'url': u, 'method': 'GET'} for u in get_urls(base)]},
        {'type': 'spider', 'parameters': {'context': 'app', 'url': base, 'maxDuration': 3, 'maxDepth': 6}},
        {'type': 'passiveScan-wait', 'parameters': {'maxDuration': 5}},
    ]
    if not passive_only:
        jobs.append({'type': 'activeScan', 'parameters': {'context': 'app', 'maxScanDurationInMins': minutes,
                                                          'maxRuleDurationInMins': 2, 'threadPerHost': 2}})
        jobs.append({'type': 'passiveScan-wait', 'parameters': {'maxDuration': 5}})
    for tpl, ext in (('traditional-html', 'html'), ('traditional-json', 'json'), ('traditional-md', 'md')):
        jobs.append({'type': 'report', 'parameters': {'template': tpl, 'reportDir': out, 'reportFile': 'zap-' + version,
                                                      'reportTitle': name + ' ZAP scan'}})
    p = {'env': {'contexts': [{'name': 'app', 'urls': [base], 'includePaths': [re.escape(base) + '.*'],
                               'excludePaths': [re.escape(base) + x for x in EXCLUDE]}],
                 'parameters': {'failOnError': False, 'failOnWarning': False, 'progressToStdout': True}},
         'jobs': jobs}
    path = os.path.join(out, 'plan-%s.yaml' % version)
    with open(path, 'w') as fh:
        json.dump(p, fh, indent=1)          # JSON is valid YAML
    return path


def baseline():
    """pluginId -> (path regex, reason), from deploy/zap-baseline.conf: "<pluginId> <path regex> <reason>".
    An alert is accepted only when every place it was found matches the path regex."""
    out = {}
    if os.path.exists(BASELINE):
        for line in open(BASELINE, encoding='utf-8'):
            line = line.strip()
            if line and not line.startswith('#'):
                pid, rx, why = (line.split(None, 2) + ['', ''])[:3]
                out[pid] = (re.compile(rx), why)
    return out


def summarise(report, accepted):
    d = json.load(open(report, encoding='utf-8'))
    urls, rows, bad = set(), [], []
    for site in d.get('site', []):
        for a in site.get('alerts', []):
            risk = a.get('riskdesc', '').split(' ')[0]
            pid = str(a.get('pluginid'))
            n = int(a.get('count') or len(a.get('instances', [])))
            paths = [urllib.parse.urlsplit(inst.get('uri') or '').path for inst in a.get('instances', [])]
            urls.update(paths)
            acc = pid in accepted and all(accepted[pid][0].match(p) for p in paths)
            ok = risk == 'Informational' or acc
            rows.append((risk, pid, a.get('name'), n, ('accepted: ' + accepted[pid][1]) if acc else
                         ('outside the accepted paths' if pid in accepted else '')))
            if not ok:
                bad.append((risk, pid, a.get('name'), n))
    return urls, rows, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--minutes', type=int, default=10, help='active scan budget')
    ap.add_argument('--passive-only', action='store_true')
    ap.add_argument('--out', default=os.path.join(TOP, 'zap-reports'))
    a = ap.parse_args()
    if not os.path.exists(ZAP):
        print('ZAP not found at %s (set ZAP_SH)' % ZAP)
        return 2
    from jtwafmgr import __version__ as version
    out = os.path.abspath(a.out)                 # the snap resolves relative paths against itself
    os.makedirs(out, exist_ok=True)
    w = tempfile.mkdtemp(prefix='jtwaf-zap.')
    proc = None
    try:
        proc, port, cookie, csrf = start_instance(w)
        base = 'http://127.0.0.1:%d' % port
        p = plan(base, cookie, csrf, out, a.minutes, a.passive_only, version)
        print('ZAP plan %s against %s' % (p, base), flush=True)
        run = subprocess.run(['nice', '-n', '10', ZAP, '-cmd', '-autorun', p], env=dict(os.environ, JAVA_HOME=JAVA_HOME),
                             check=False, capture_output=True, text=True)
        log = run.stdout + run.stderr
        open(os.path.join(out, 'zap-%s.log' % version), 'w').write(log)
        spider = int((re.search(r'spider found (\d+) URLs', log) or [0, 0])[1])
        requested = len(re.findall(r'requestor requesting URL', log))
        session_ok = not re.search(r'(?i)unexpected response|response code.*expected', log)
        report = os.path.join(out, 'zap-%s.json' % version)
        if not os.path.exists(report):
            print('no report written: the scan did not run (see the ZAP output above)')
            return 2
        urls, rows, bad = summarise(report, baseline())
        print('requested %d URLs, spider found %d, session %s' % (requested, spider, 'OK' if session_ok else 'NOT USED'))
        for r in sorted(rows, key=lambda r: ['High', 'Medium', 'Low', 'Informational'].index(r[0]) if r[0] in
                        ('High', 'Medium', 'Low', 'Informational') else 9):
            print('  %-13s %-6s %-60s %4d %s' % r)
        print('ZAP scan: %s (%d alerts not accepted) -- reports in %s' % ('OK' if not bad else 'FAILED', len(bad), out))
        if not session_ok or requested + spider < 40:
            print('the scan did not see the logged-in application: it proves nothing')
            return 1
        return 1 if bad else 0
    finally:
        if proc:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(w, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
