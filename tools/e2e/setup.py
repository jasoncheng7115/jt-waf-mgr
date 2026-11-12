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
json.dump(sec, open(R + '/totp.json', 'w'))
print('events', app.db.one('SELECT COUNT(*) n FROM events')['n'])
