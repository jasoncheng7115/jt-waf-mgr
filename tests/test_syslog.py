"""Syslog: local socket, UDP / TCP to a server, RFC 3164 and RFC 5424, framing, back-off, web settings."""
import json
import re
import socket
import socketserver
import threading
import time
import unittest

from jtwafmgr import uisettings
from jtwafmgr.app import App
from tests.helpers import TempEnv


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


class TestSyslog(unittest.TestCase):
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

    def settle(self, srv, n=1):
        for _ in range(50):
            if len(srv.got) >= n:
                return
            time.sleep(0.05)

    def test_udp_rfc5424_and_rfc3164(self):
        srv = self.server('udp')
        uisettings.set_many(self.app, {'syslog.enabled': True, 'syslog.address': '127.0.0.1:%d' % srv.server_address[1],
                                       'syslog.protocol': 'udp', 'syslog.format': 'rfc5424'}, 'admin1')
        self.app.audit.log('test.action', 'alice', src_ip='192.0.2.5', note='x\ny')
        self.settle(srv, 2)
        m = srv.got[-1].decode()
        self.assertRegex(m, r'^<1(3[0-9]|2[0-9])>1 \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d \S+ jt-waf-mgr \d+ audit - \{')
        rec = json.loads(m.split(' - ', 1)[1])['jt_waf_mgr']
        self.assertEqual((rec['action'], rec['note']), ('test.action', 'x\ny'))
        self.assertNotIn('\n', m)                                      # one record, one line
        uisettings.set_many(self.app, {'syslog.format': 'rfc3164'}, 'admin1')
        self.app.audit.log('test.action', 'bob')
        self.settle(srv, 4)
        self.assertRegex(srv.got[-1].decode(), r'^<\d+>[A-Z][a-z]{2} [ 0-9]\d \d\d:\d\d:\d\d \S+ jt-waf-mgr: \{')

    def test_tcp_framing(self):
        srv = self.server('tcp')
        # switched on last: the setting changes before it are not sent (syslog was off), only the record below
        uisettings.set_many(self.app, {'syslog.address': '127.0.0.1:%d' % srv.server_address[1], 'syslog.protocol': 'tcp',
                                       'syslog.format': 'rfc5424', 'syslog.enabled': True}, 'admin1')
        self.app.audit.log('test.action', 'alice')
        self.app.audit.flush()
        self.settle(srv)
        data = b''.join(srv.got)
        m = re.search(rb'(\d+) (<\d+>1 [^\n]*?"actor":"alice"[^\n]*?\}\})', data)
        self.assertIsNotNone(m, data[-300:])
        self.assertEqual(int(m.group(1)), len(m.group(2)))

    def test_unreachable_server_never_slows_requests_and_records_wait(self):
        s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()     # nothing listens
        uisettings.set_many(self.app, {'syslog.enabled': True, 'syslog.address': '127.0.0.1:%d' % port, 'syslog.protocol': 'tcp'}, 'admin1')
        t0 = time.monotonic()
        for _ in range(20):
            self.app.audit.log('test.action', 'alice')
        self.assertLess(time.monotonic() - t0, 1)                      # requests never wait for the network
        for _ in range(40):
            if self.app.audit.syslog_errors:
                break
            time.sleep(0.05)
        self.assertGreaterEqual(self.app.audit.syslog_errors, 1)
        self.assertGreaterEqual(len(self.app.audit._queue), 20)       # kept, not lost
        # a working destination: everything waiting goes out, in order
        srv = self.server('udp')
        uisettings.set_many(self.app, {'syslog.address': '127.0.0.1:%d' % srv.server_address[1], 'syslog.protocol': 'udp'}, 'admin1')
        self.settle(srv, 20)
        self.assertEqual(sum(1 for g in srv.got if b'"actor":"alice"' in g), 20)   # every waiting record arrives
        # (the setting changes themselves were for the old, dead destination: given up on and counted, not resent)

    def test_switching_off_is_recorded_before_it_takes_effect(self):
        srv = self.server('udp')
        uisettings.set_many(self.app, {'syslog.enabled': True, 'syslog.address': '127.0.0.1:%d' % srv.server_address[1]}, 'admin1')
        uisettings.set_many(self.app, {'syslog.enabled': False}, 'admin1')
        self.settle(srv, 2)
        last = json.loads(srv.got[-1].decode().split(': ', 1)[1])['jt_waf_mgr']
        self.assertEqual((last['action'], last['key'], last['new'], last['severity']), ('settings.changed', 'syslog.enabled', False, 'crit'))

    def test_unsendable_record_does_not_block_the_queue(self):
        srv = self.server('udp')
        uisettings.set_many(self.app, {'syslog.address': '127.0.0.1:%d' % srv.server_address[1], 'syslog.enabled': True}, 'admin1')
        self.app.audit.log('test.action', 'alice', blob='x' * 70000)        # larger than a UDP datagram
        self.app.audit.log('test.action', 'bob')
        self.settle(srv, 2)
        self.assertTrue(any(b'"actor":"bob"' in g for g in srv.got))
        self.assertGreaterEqual(self.app.audit.syslog_dropped, 1)

    def test_settings_validation(self):
        for bad in ({'syslog.address': 'logs.example.com'}, {'syslog.address': 'a b:514'}, {'syslog.protocol': 'quic'},
                    {'syslog.format': 'cef'}, {'syslog.facility': 'local9'}, {'syslog.address': 'logs.example.com:99999'},
                    {'syslog.address': 'logs.example.com:0'}):
            with self.assertRaises(uisettings.SettingError, msg=bad):
                uisettings.set_many(self.app, bad, 'admin1')
        uisettings.set_many(self.app, {'syslog.address': 'logs.example.com:6514', 'syslog.protocol': 'tls'}, 'admin1')
        self.assertEqual(self.app.cfg['syslog']['protocol'], 'tls')


if __name__ == '__main__':
    unittest.main()
