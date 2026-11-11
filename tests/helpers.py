"""Shared test helpers. Synthetic data only: example.com and documentation addresses."""
import json
import os
import shutil
import tempfile
import time

from jtwafmgr import config

FIXTURE_SITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures', 'site')


def modsec_time(ts):
    return time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(ts)) if False else _c_time(ts)


def _c_time(ts):
    # locale-independent English names, like libmodsecurity writes them
    t = time.localtime(ts)
    days = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')
    months = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
    return '%s %s %02d %02d:%02d:%02d %d' % (days[t.tm_wday], months[t.tm_mon - 1], t.tm_mday,
                                             t.tm_hour, t.tm_min, t.tm_sec, t.tm_year)


_seq = [0]


def record(host='app.example.com', uri='/index.php', ip='203.0.113.7', method='GET', status=200,
           engine='DetectionOnly', rules=(), ts=None, request_id=None):
    """rules: list of (rule_id, message, data) or rule ids."""
    _seq[0] += 1
    msgs = []
    for r in rules:
        if isinstance(r, int):
            r = (r, 'rule %d' % r, '')
        rid, msg, data = r
        msgs.append({'message': msg, 'details': {
            'match': 'Matched "Operator `Rx\' against variable `ARGS:q\' (Value: `x\' )', 'reference': 'o0,1',
            'ruleId': str(rid), 'file': '/etc/nginx/modsec/crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf',
            'lineNumber': '50', 'data': data, 'severity': '2', 'ver': 'OWASP_CRS/4.30.0', 'rev': '',
            'tags': ['attack-lfi', 'paranoia-level/1'], 'maturity': '0', 'accuracy': '0'}})
    rid = request_id or '%032x' % _seq[0]
    return json.dumps({'transaction': {
        'client_ip': ip, 'time_stamp': _c_time(ts or time.time()), 'server_id': 'x' * 40, 'client_port': 51234,
        'host_ip': '192.0.2.1', 'host_port': 443, 'unique_id': '%s-%s' % (host, rid),
        'request': {'method': method, 'http_version': 1.1, 'uri': uri},
        'response': {'http_code': status},
        'producer': {'modsecurity': 'ModSecurity v3.0.9 (Linux)', 'connector': 'ModSecurity-nginx v1.0.4',
                     'secrules_engine': engine, 'components': ['OWASP_CRS/4.30.0"']},
        'messages': msgs}})


class TempEnv:
    """A temp dir with a config pointing at the fixture site and a temp audit log."""

    def __init__(self, **over):
        self.dir = tempfile.mkdtemp(prefix='jtwaf-test-')
        self.audit_log = os.path.join(self.dir, 'modsec_audit.log')
        o = {'paths': {'db': os.path.join(self.dir, 'test.db'),
                       'nginx_conf': os.path.join(FIXTURE_SITE, 'nginx.conf'),
                       'audit_log': self.audit_log, 'nginx_bin': '/nonexistent/nginx'},
             'server': {'secure_cookies': False},
             'syslog': {'enabled': False},
             'collector': {'backfill_rotated': False},
             'waf': {'focus_sites': ['sso.example.com']},
             # test passwords are simple; the policy itself is tested in test_compliance
             'auth': {'password_min_classes': 0, 'password_history': 0, 'dormant_days': 0},
             'integrity': {'anchor_file': os.path.join(self.dir, 'anchors.jsonl')},
             'backup': {'dir': os.path.join(self.dir, 'backups')},
             'geoip': {'dir': os.path.join(self.dir, 'geoip'), 'license_key_file': os.path.join(self.dir, 'maxmind.key')}}
        for k, v in over.items():
            o.setdefault(k, {}).update(v)
        self.cfg = config.load(None, o)

    def write_log(self, lines, mode='a'):
        with open(self.audit_log, mode) as fh:
            for line in lines:
                fh.write(line + '\n')

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)
