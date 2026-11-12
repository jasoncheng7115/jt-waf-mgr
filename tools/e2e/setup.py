"""Synthetic environment for tools/e2e/e2e.cjs: events, GeoIP test databases, accounts with TOTP, a token.
Test data only (documentation address ranges, example.com)."""
import json, sys, time, os, random
import os.path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from jtwafmgr import config, auth
from jtwafmgr.app import App
from jtwafmgr.collector.auditlog import Tailer
from tests.helpers import record
from tests import mmdb_writer
R = sys.argv[1]
os.makedirs(R + '/geoip', exist_ok=True)
mmdb_writer.write(R + '/geoip/GeoLite2-City.mmdb', {
  '203.0.113.0/26': {'country': {'iso_code': 'JP', 'names': {'en': 'Japan'}}, 'city': {'names': {'en': 'Tokyo'}}},
  '203.0.113.64/26': {'country': {'iso_code': 'US', 'names': {'en': 'United States'}}},
  '198.51.100.0/24': {'country': {'iso_code': 'DE', 'names': {'en': 'Germany'}}},
  '192.0.2.0/24': {'country': {'iso_code': 'TW', 'names': {'en': 'Taiwan'}}}})
mmdb_writer.write(R + '/geoip/GeoLite2-ASN.mmdb', {
  '203.0.113.0/24': {'autonomous_system_number': 64500, 'autonomous_system_organization': 'Example Hosting'},
  '198.51.100.0/24': {'autonomous_system_number': 64501, 'autonomous_system_organization': 'Doc Net <b>x</b>'}}, database_type='GeoLite2-ASN')
random.seed(7)
now = time.time()
lines = []
hosts = ['app.example.com', 'sso.example.com', 'shop.example.com', 'www.example.com']
for i in range(260):
    ip = random.choice(['203.0.113.%d' % random.randint(1, 120), '198.51.100.%d' % random.randint(1, 50), '192.0.2.%d' % random.randint(1, 20), '192.168.77.%d' % random.randint(1, 9)])
    blocked = random.random() < 0.45
    rules = random.choice([[930110, 949110], [942100, 949110], [941100], [920350], [913100, 949110]])
    lines.append(record(host=random.choice(hosts), uri=random.choice(['/wp-login.php', '/index.php?id=1%27', '/../etc/passwd', '/search?q=<script>', '/']),
                        ip=ip, status=403 if blocked else 200, engine='Enabled', rules=rules, ts=now - random.randint(60, 6 * 86400)))
open(R + '/modsec_audit.log', 'w').write('\n'.join(lines) + '\n')
cfg = config.load(R + '/config.toml')
app = App(cfg)
app.tailer = Tailer(cfg, app.db); app.tailer.poll()
a = app.auth
PW = 'Smoke-Passw0rd-1'
sec = {}
for u, role in (('admin', 'admin'), ('approver', 'approver'), ('viewer', 'viewer'), ('oper', 'operator')):
    a.create_user(u, role, password=PW)
    if role in ('admin', 'approver'):
        s, _ = a.totp_setup(u)
        a.totp_enable(u, auth.totp_code(s, int(time.time() // 30) - 1))
        sec[u] = s
for i in range(30):
    app.audit.log('test.action', 'admin', src_ip='192.0.2.10', n=i)
a.create_token('wazuh-sync', ['events:read'], ['192.0.2.0/24'], None, 'admin')
app.monitor.check_chain(); app.monitor.backup()
# notifications and alerts (synthetic; nothing is sent: the notify unit does not run here)
from jtwafmgr import alerts, uisettings
uisettings.set_many(app, {'notify.enabled': True, 'notify.base_url': 'https://waf.example.com', 'notify.webhook_enabled': True,
                          'notify.webhook_url': 'https://hooks.example.com/waf', 'notify.webhook_secret': 'e2e-signing-secret-0123456789',
                          'llm.enabled': True, 'llm.url': 'http://192.0.2.10:8080/v1', 'llm.model': 'example-model',
                          'analyst.enabled': True, 'analyst.window_hours': 168}, 'admin')
# one synthetic analysis run (no LLM here): what the analysis page and its summary show
cands = [
    {'id': 'c1', 'path': '/.env', 'events': 14, 'sources': 9, 'hosts': ['app.example.com', 'shop.example.com'], 'host_count': 2,
     'families': ['lfi'], 'rules': [{'id': 930130, 'msg': 'Restricted File Access Attempt', 'hits': 14}], 'statuses': {'404': 11, '200': 3},
     'variants': ['/.env'], 'blocked_by_score': 2, 'logged': 12, 'answered_2xx': 3, 'internal_users': 0, 'methods': {'GET': 14},
     'first_seen': '2026-11-10T01:00:00+00:00', 'last_seen': '2026-11-12T01:00:00+00:00'},
    {'id': 'c2', 'path': '/wp-login.php', 'events': 22, 'sources': 12, 'hosts': ['www.example.com'], 'host_count': 1,
     'families': ['scanner'], 'rules': [{'id': 913100, 'msg': 'Found User-Agent associated with security scanner', 'hits': 9}],
     'statuses': {'404': 22}, 'variants': ['/wp-login.php'], 'blocked_by_score': 0, 'logged': 22, 'answered_2xx': 0,
     'internal_users': 0, 'methods': {'GET': 20, 'POST': 2}, 'first_seen': '2026-11-10T03:00:00+00:00', 'last_seen': '2026-11-12T02:00:00+00:00'},
    {'id': 'f1', 'type': 'false_positive', 'host': 'shop.example.com', 'path': '/api/notes', 'events': 12, 'sources': 5,
     'internal_sources': 3, 'methods': {'POST': 12}, 'variants': ['/api/notes'], 'families': ['xss'],
     'rules': [{'id': 941100, 'msg': 'XSS Attack Detected via libinjection', 'hits': 12, 'targets': ['ARGS:body'], 'matched': ['<p>hello</p>']}],
     'first_seen': '2026-11-11T08:00:00+00:00', 'last_seen': '2026-11-12T08:00:00+00:00'}]
verdicts = [
    {'id': 'c1', 'verdict': 'attack_probe', 'confidence': 0.95, 'reason': 'Environment file probe; no site serves it.', 'regex': '^/\\.env$', 'label': 'env file probe', 'problem': None},
    {'id': 'c2', 'verdict': 'attack_probe', 'confidence': 0.9, 'reason': 'WordPress login probe; these sites do not run WordPress.', 'regex': '^/wp-login\\.php$', 'label': 'wordpress login probe', 'problem': None},
    {'id': 'f1', 'verdict': 'false_positive', 'confidence': 0.9, 'reason': 'Rich-text editor content (HTML) of the notes API.', 'regex': None, 'label': None, 'problem': None}]
app.db.x("INSERT INTO analyst_runs(node_id, started_at, finished_at, trigger, window_hours, model, llm_seconds, prompt_chars, candidates, "
         "verdicts, proposals, skipped, usage, alerts, events_scanned) VALUES ('waf1', ?, ?, 'timer', 168, 'example-model', 61.4, 8200, ?, ?, '[]', ?, "
         "'{\"prompt_tokens\": 2400, \"completion_tokens\": 900}', '[]', 260)",
         (now - 3600, now - 3500, json.dumps(cands), json.dumps(verdicts),
          json.dumps([{'id': 'c1', 'path': '/.env', 'reason': 'not_adopted'}, {'id': 'c2', 'path': '/wp-login.php', 'reason': 'not_adopted'},
                      {'id': 'f1', 'host': 'shop.example.com', 'path': '/api/notes', 'reason': 'not_adopted'}])))
alerts.raise_alert(app.db, app.audit, 'analyst', 'attack_passed', 'critical', 'attack_passed:/.env',
                   {'path': '/.env', 'host': 'app.example.com', 'count': 3, 'reason': '<b>not markup</b> probe answered 200'}, link='/analysis')
alerts.raise_alert(app.db, app.audit, 'analyst', 'false_positive', 'warning', 'false_positive:shop.example.com/api/notes',
                   {'path': '/api/notes', 'host': 'shop.example.com', 'count': 12, 'reason': 'rich text editor content'}, link='/changes')
json.dump(sec, open(R + '/totp.json', 'w'))
print('events', app.db.one('SELECT COUNT(*) n FROM events')['n'])
