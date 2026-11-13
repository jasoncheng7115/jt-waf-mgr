"""Synthetic environment for tools/e2e/e2e.cjs: events, GeoIP test databases, accounts with TOTP, a token.
Test data only (documentation address ranges, example.com)."""
import json
import sys, time, os, random
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
  '198.51.100.0/24': {'autonomous_system_number': 64501, 'autonomous_system_organization': 'Documentation Net'}}, database_type='GeoLite2-ASN')
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
# request volume (traffic.py): a week of hourly counts for three synthetic sites, with a daily rhythm
import math
h0 = int(now // 3600) * 3600
for i in range(7 * 24, 0, -1):
    hr = h0 - i * 3600
    day = 0.55 + 0.45 * math.sin((time.localtime(hr).tm_hour - 6) / 24 * 2 * math.pi)
    for host, base, err in (('www.example.com', 900, 2), ('shop.example.com', 420, 6), ('api.example.com', 260, 1)):
        tot = int(base * day) + (i * 37 % 41)
        s4, s5 = tot // 12 + i % 7, err + (i % 5 == 0) * err * 3
        s3 = tot // 9
        app.db.x('INSERT INTO traffic_hourly(hour, host, total, s2xx, s3xx, s4xx, s5xx, s403, s444, s429, external, bytes) '
                 'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', (hr, host, tot, tot - s3 - s4 - s5, s3, s4, s5, s4 // 3, i % 4, i % 3,
                                                       int(tot * 0.8), tot * 18000))
app.db.set_meta('traffic_polled_at', now - 30)
# temporary IP blocks: two from a mail host's fail2ban (an API token), one by hand
if cfg['blocks']['enabled']:
    app.blocks.add('203.0.113.66', 86400, 'mail2/zimbra-webmail', '4 failed logins in 24 h', 'mail2', via='token', token_id='e2etoken')
    app.blocks.add('203.0.113.67', 3600, 'mail2/zimbra-webmail', '5 failed logins in 24 h', 'mail2', via='token', token_id='e2etoken')
    app.blocks.add('192.0.2.0/24', 7 * 86400, 'ui', 'scanner range', 'admin', role='admin')
# changes in every state and from every kind of proposer (rows only: this environment is not adopted), and the alerts
# an operator sees on a busy day -- synthetic, for the pages and the project site's screenshots
def chg(op, kind, rid, spec, direction, state, reason, by, via, ago, text, owner=None):
    app.db.x('INSERT INTO changes(op, kind, item_id, rule_id, spec, direction, state, reason, proposed_by, proposed_via, created_at, '
             'updated_at, base_version, rule_text, checks, tests, evidence_override, applied_version, error, proposed_owner) '
             "VALUES (?,?,NULL,?,?,?,?,?,?,?,?,?,1,?,'{}','[]',0,NULL,NULL,?)",
             (op, kind, rid, json.dumps(spec), direction, state, reason, by, via, now - ago, now - ago + 120, text, owner or by))
def blockrule(rid, rx, msg):
    return ('SecRule REQUEST_FILENAME "@rx %s" "id:%d,phase:1,pass,log,msg:\'jt confident block: %s\',tag:\'jt-confident-block\'"' % (rx, rid, msg))
for i, (rx, label, ago, state) in enumerate([
        (r'^/server/config\.json$', 'config file probe', 2400, 'pending_approval'),
        (r'^/kube-config\.yaml$', 'kubernetes config probe', 2500, 'pending_approval'),
        (r'^/aws-secrets\.json$', 'cloud secret probe', 2600, 'pending_approval'),
        (r'^/ai_config\.json$', 'ai config probe', 5400, 'pending_approval'),
        (r'^/env\.old$', 'env backup probe', 5500, 'applied')]):
    chg('add', 'confident_block', 10260 - i, {'target': 'path', 'regex': rx, 'source': 'external', 'msg': 'jt analyst: ' + label,
        'host': {'mode': 'any'}}, 'tighten', state,
        'Probe for %s from outside only; no internal user, never answered 2xx.\n[jt analyst] model example-model, confidence 0.95. '
        'Last 168h, external sources only: 6 events, 3 sources.' % rx.strip('^$').replace('\\', ''), 'analyst', 'api', ago,
        blockrule(10260 - i, rx, 'jt analyst: ' + label), owner='analyst')
chg('add', 'confident_block', 10224, {'target': 'header', 'header': 'Upgrade', 'regex': '(?i)h2c', 'source': 'external',
    'msg': 'h2c upgrade request'}, 'tighten', 'applied', 'Block requests that ask to upgrade to h2c.', 'admin', 'user', 7200,
    'SecRule REQUEST_HEADERS:Upgrade "@rx (?i)h2c" "id:10224,phase:1,pass,log,msg:\'jt confident block: h2c upgrade request\'"')
chg('add', 'confident_block', 10230, {'target': 'ua', 'regex': '(?i)sqlmap', 'source': 'external', 'msg': 'sqlmap'}, 'tighten',
    'pending_approval', 'SOAR playbook: sqlmap user agent seen on shop.example.com.', 'soar-playbook', 'api', 900,
    'SecRule REQUEST_HEADERS:User-Agent "@rx (?i)sqlmap" "id:10230,phase:1,pass,log,msg:\'jt confident block: sqlmap\'"', owner='admin')
chg('add', 'exclusion', 10120, {'host': {'mode': 'exact', 'value': 'shop.example.com'}, 'path': {'mode': 'exact', 'value': '/api/notes'},
    'action': 'remove_target', 'rule_ids': [941100], 'targets': ['ARGS:body']}, 'loosen', 'applied',
    'Rich-text notes are HTML by design (941100 on ARGS:body).', 'approver', 'user', 86400,
    'SecRule REQUEST_FILENAME "@streq /api/notes" "id:10120,phase:1,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:body"')
for kind, sev, ded, det, ago in (
        ('config_outside', 'critical', 'config_outside:1', {'event': 'config.changed_outside', 'reason': 'nginx.conf changed outside jt-waf-mgr'}, 1500),
        ('attack_in_progress', 'warning', 'attack_in_progress:1', {'path': '/ai_config.json, /bitbucket-pipelines.yml, /config.yaml, /public/config.json, /settings.py.bak',
         'host': 'app.example.com', 'reason': 'Several sources probe secret and backup files on app.example.com in a short time.'}, 3000),
        ('attack_in_progress', 'warning', 'attack_in_progress:2', {'path': '/.kube/config, /auth.json, /config.ini, /.environment, /config.inc.php',
         'host': 'www.example.com', 'reason': 'Scans for configuration files across several sites.'}, 3100),
        ('traffic_spike', 'warning', 'traffic_spike:shop.example.com', {'host': 'shop.example.com', 'reason': '6200 requests in the hour from 14:00, 8.4 times the usual 740 an hour'}, 4200),
        ('crs_update', 'warning', 'crs_update:4.31.0', {'reason': 'OWASP CRS 4.31.0 downloaded and verified; compare it in the sandbox and propose it'}, 9000)):
    aid = alerts.raise_alert(app.db, app.audit, 'analyst' if kind.startswith('attack') else ('traffic' if kind.startswith('traffic') else 'system'),
                             kind, sev, ded, det, link='/alerts')
    app.db.x('UPDATE alerts SET created_at=?, last_seen=? WHERE dedup=?', (now - ago, now - ago, ded))
json.dump(sec, open(R + '/totp.json', 'w'))
print('events', app.db.one('SELECT COUNT(*) n FROM events')['n'])
