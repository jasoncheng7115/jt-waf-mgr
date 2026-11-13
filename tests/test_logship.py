"""Log servers: several destinations, each with its own format (JSON, CEF, LEEF, GELF, key=value), protocol and
content (audit records, WAF events, alerts). Synthetic data only."""
import json
import re
import socketserver
import threading
import time
import unittest

from jtwafmgr import logfmt, uisettings
from jtwafmgr.app import App
from tests.helpers import TempEnv

EVIL = {'v': 1, 'type': 'event', 'ts': '2026-11-13T10:00:00+08:00', 'node_id': 'waf1', 'host': 'app.example.com',
        'method': 'GET', 'path': '/a|b=c\\d\nCEF:0|fake|x', 'src_ip': '203.0.113.9', 'origin': 'external', 'status': 403,
        'outcome': 'blocked', 'decided_by': 'score', 'anomaly_score': 10, 'rule_ids': [930120, 949110],
        'families': ['lfi'], 'message': 'msg\twith\ttabs and "quotes"\r\nnew line', 'unique_id': 'u1'}


class _Udp(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.got.append(self.request[0])


class _Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(1)
        while True:
            try:
                b = self.request.recv(65536)
            except OSError:
                return
            if not b:
                return
            self.server.got.append(b)


class TestFormats(unittest.TestCase):
    def test_cef_escapes_what_could_fake_a_field(self):
        line = logfmt.cef('event', EVIL, 4, '0.4.19', 1000)
        self.assertNotIn('\n', line)
        self.assertTrue(line.startswith('CEF:0|jt-waf-mgr|jt-waf-mgr|0.4.19|waf.blocked|'))
        # a CEF reader takes the first 7 unescaped separators as the header, the rest is the extension (where a pipe
        # needs no escape): the header must hold exactly what we put there
        head = re.split(r'(?<!\\)\|', line, maxsplit=7)
        self.assertEqual(head[:5], ['CEF:0', 'jt-waf-mgr', 'jt-waf-mgr', '0.4.19', 'waf.blocked'])
        self.assertTrue(head[7].startswith('rt=1000 '))          # what an attacker sent stays inside a value
        self.assertIn('request=/a|b\\=c\\\\d\\nCEF:0|fake|x', line)        # = and \\ escaped, the line break as \\n
        self.assertIn('src=203.0.113.9', line)
        self.assertIn('cs1Label=rule_ids cs1=930120,949110', line)
        self.assertEqual(head[6], '6')                                      # syslog warning -> CEF 6

    def test_leef_and_kv(self):
        lf = logfmt.leef('event', EVIL, 4, '0.4.19')
        self.assertTrue(lf.startswith('LEEF:2.0|jt-waf-mgr|jt-waf-mgr|0.4.19|waf.blocked|x09|'))
        attrs = lf.split('|', 6)[6].split('\t')
        self.assertIn('src=203.0.113.9', attrs)
        self.assertTrue(all('\n' not in a and '\r' not in a for a in attrs))
        self.assertTrue(any(a.startswith('message=msg with tabs') for a in attrs))     # its tabs are not separators
        kv = logfmt.kv('event', EVIL, 4)
        self.assertNotIn('\n', kv)
        self.assertIn('message="msg\\twith\\ttabs and \\"quotes\\"\\r\\nnew line"', kv)
        self.assertNotIn('\t', kv)
        self.assertIn('src=203.0.113.9', kv)

    def test_json_keeps_the_original_shape(self):
        rec = {'v': 1, 'action': 'x.y', 'actor': 'alice'}
        self.assertEqual(json.loads(logfmt.json_line('audit', rec)), {'jt_waf_mgr': rec})
        self.assertEqual(json.loads(logfmt.json_line('event', EVIL))['jt_waf_mgr']['path'], EVIL['path'])
        self.assertNotIn('\n', logfmt.json_line('event', EVIL))

    def test_gelf_fields_and_chunks(self):
        g = json.loads(logfmt.gelf('event', EVIL, 4, 'waf1', 1000.5))
        self.assertEqual((g['version'], g['host'], g['level'], g['_src'], g['_status'], g['_jt_type']),
                         ('1.1', 'waf1', 4, '203.0.113.9', 403, 'event'))
        self.assertTrue(all(k == k.strip() and (k in ('version', 'host', 'short_message', 'timestamp', 'level') or k.startswith('_'))
                            for k in g))
        big = b'x' * 20000
        chunks = logfmt.gelf_udp_chunks(big, b'12345678')
        self.assertEqual(len(chunks), 3)
        self.assertTrue(all(c[:2] == b'\x1e\x0f' and c[2:10] == b'12345678' for c in chunks))
        self.assertEqual([c[10] for c in chunks], [0, 1, 2])
        self.assertEqual(b''.join(c[12:] for c in chunks), big)
        self.assertIsNone(logfmt.gelf_udp_chunks(b'x' * (logfmt.GELF_CHUNK * 129), b'12345678'))


class TestDestinations(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg)

    def server(self, kind):
        srv = (socketserver.ThreadingUDPServer if kind == 'udp' else socketserver.ThreadingTCPServer)(
            ('127.0.0.1', 0), _Udp if kind == 'udp' else _Tcp)
        srv.got = []
        srv.daemon_threads, srv.block_on_close = True, False
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv

    def settle(self, srv, pred, tries=60):
        for _ in range(tries):
            if pred():
                return
            time.sleep(0.05)

    def test_each_destination_its_own_content_and_format(self):
        a, b, c = self.server('udp'), self.server('udp'), self.server('tcp')
        uisettings.set_many(self.app, {
            'syslog.enabled': True, 'syslog.address': '127.0.0.1:%d' % a.server_address[1], 'syslog.protocol': 'udp',
            'syslog.more': [
                {'id': 'siem', 'name': 'SIEM', 'address': '127.0.0.1:%d' % b.server_address[1], 'protocol': 'udp',
                 'payload': 'cef', 'content': ['event', 'alert']},
                {'id': 'graylog', 'address': '127.0.0.1:%d' % c.server_address[1], 'protocol': 'tcp', 'payload': 'gelf',
                 'content': ['audit', 'event']}]}, 'admin1')
        self.app.audit.log('test.action', 'alice')
        self.app.audit.events([dict(EVIL, ts=time.time(), rule_ids=[930120], families=['lfi'])])
        self.settle(b, lambda: any(b'CEF:0|' in g for g in b.got))
        self.settle(c, lambda: b'"_actor":"alice"' in b''.join(c.got) and b'"_jt_type":"event"' in b''.join(c.got))
        self.settle(a, lambda: any(b'"actor":"alice"' in g for g in a.got))
        self.assertTrue(any(b'"actor":"alice"' in g for g in a.got))                # the first: audit, JSON
        self.assertFalse(any(b'waf.blocked' in g or b'"type":"event"' in g for g in a.got))   # no events there
        cef = [g for g in b.got if b'CEF:0|' in g]
        self.assertTrue(cef and all(b'waf.blocked' in g for g in cef))                # the SIEM: events, CEF
        self.assertFalse(any(b'test.action' in g for g in b.got))                     # no audit records there
        frames = b''.join(c.got).split(b'\0')
        self.assertTrue(any(json.loads(f).get('_actor') == 'alice' for f in frames if f))     # GELF over TCP, \0 framed
        stats = {d['key']: d for d in self.app.audit.stats()}
        self.assertGreaterEqual(stats['siem']['sent'], 1)
        self.assertEqual(stats['siem']['payload'], 'cef')

    def test_an_alert_reaches_the_destinations_that_take_alerts(self):
        b = self.server('udp')
        uisettings.set_many(self.app, {'syslog.more': [{'id': 'al', 'address': '127.0.0.1:%d' % b.server_address[1],
                                                         'payload': 'kv', 'content': ['alert']}]}, 'admin1')
        from jtwafmgr import alerts
        alerts.raise_alert(self.app.db, self.app.audit, 'analyst', 'attack_passed', 'critical', 'x', {'host': 'app.example.com',
                                                                                                     'path': '/.env'})
        self.settle(b, lambda: b.got)
        line = b.got[0].decode()
        self.assertIn('type=alert event=alert.attack_passed', line)
        self.assertIn('path=/.env', line)

    def test_validation(self):
        good = {'address': 'logs.example.com:514', 'content': ['audit']}
        for bad in ([dict(good, payload='gelf', address='/dev/log')], [dict(good, content=[])], [dict(good, content=['x'])],
                    [dict(good, id='a'), dict(good, id='a')], [dict(good, address='logs.example.com:0')],
                    [dict(good, protocol='quic')], [dict(good, name='x\ny')], [dict(good)] * 8, [dict(good, id='main')]):
            with self.assertRaises(uisettings.SettingError, msg=bad):
                uisettings.set_many(self.app, {'syslog.more': bad}, 'admin1')
        for bad in ({'syslog.payload': 'xml'}, {'syslog.content': ['audit', 'nope']}):
            with self.assertRaises(uisettings.SettingError, msg=bad):
                uisettings.set_many(self.app, bad, 'admin1')
        uisettings.set_many(self.app, {'syslog.more': [dict(good, payload='leef')], 'syslog.payload': 'cef'}, 'admin1')
        self.assertEqual(self.app.cfg['syslog']['more'][0]['payload'], 'leef')
        self.assertEqual(len(self.app.audit.stats()), 2)

    def test_send_test_returns_what_was_sent(self):
        a = self.server('udp')
        res = self.app.audit.send_test({'address': '127.0.0.1:%d' % a.server_address[1], 'protocol': 'udp', 'format': 'rfc5424',
                                        'facility': 'local0', 'payload': 'cef', 'content': ['event'], 'enabled': True}, 'event')
        self.assertTrue(res['ok'], res)
        self.assertIn('CEF:0|jt-waf-mgr|jt-waf-mgr|', res['sample'])
        self.settle(a, lambda: a.got)
        self.assertIn(b'CEF:0|', a.got[0])
        res = self.app.audit.send_test({'address': '127.0.0.1:9', 'protocol': 'tcp', 'format': 'rfc3164', 'facility': 'local0',
                                        'payload': 'json', 'content': ['audit'], 'enabled': True})
        self.assertFalse(res['ok'])
        self.assertTrue(res['error'])


if __name__ == '__main__':
    unittest.main()
