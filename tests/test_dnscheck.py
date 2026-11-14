"""The DNS check and PTR lookups (jtwafmgr/dnscheck.py) against small fake DNS servers on 127.0.0.1. Synthetic names
(example.com / example.net) and documentation addresses only."""
import json
import os
import socket
import struct
import threading
import time
import unittest

from jtwafmgr import dnscheck
from jtwafmgr.dnscheck import A, AAAA, CNAME, PTR
from tests.helpers import TempEnv


def _enc(name):
    return b''.join(bytes([len(p)]) + p.encode() for p in name.rstrip('.').split('.')) + b'\x00'


class FakeDns:
    """Answers from a table {(name, qtype): [(type, value)]}; a name not there is NXDOMAIN. truncate: the UDP answer
    has the TC bit and no records, the TCP one has them. silent: never answers."""

    def __init__(self, table, wildcard=None, truncate=False, silent=False):
        self.table, self.wildcard, self.truncate, self.silent = table, wildcard, truncate, silent
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.1', 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(('127.0.0.1', self.port))
        self.tcp.listen(5)
        self.stop = False
        self.questions = []
        for target in (self._serve_udp, self._serve_tcp):
            threading.Thread(target=target, daemon=True).start()

    @property
    def addr(self):
        return '127.0.0.1:%d' % self.port

    def answer(self, q, tcp=False):
        qid = struct.unpack('>H', q[:2])[0]
        name, off = dnscheck._name(q, 12)
        qtype = struct.unpack('>H', q[off:off + 2])[0]
        self.questions.append((name, qtype))
        recs = self.table.get((name, qtype))
        if recs is None and self.wildcard and name.endswith('.' + self.wildcard[0]) and qtype == A:
            recs = [(A, self.wildcard[1])]
        known = recs is not None or any(k[0] == name for k in self.table)
        recs = recs or []
        tc = self.truncate and not tcp
        flags = 0x8180 | (0 if known or recs else 3) | (0x0200 if tc else 0)
        body = q[12:off + 4]
        out = struct.pack('>HHHHHH', qid, flags, 1, 0 if tc else len(recs), 0, 0) + body
        for t, v in ([] if tc else recs):
            if t == A:
                rd = socket.inet_aton(v)
            elif t == AAAA:
                rd = socket.inet_pton(socket.AF_INET6, v)
            else:
                rd = _enc(v)
            out += b'\xc0\x0c' + struct.pack('>HHIH', t, 1, 60, len(rd)) + rd
        return out

    def _serve_udp(self):
        self.udp.settimeout(0.2)
        while not self.stop:
            try:
                q, src = self.udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not self.silent:
                self.udp.sendto(self.answer(q), src)

    def _serve_tcp(self):
        self.tcp.settimeout(0.2)
        while not self.stop:
            try:
                c, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with c:
                n = struct.unpack('>H', c.recv(2))[0]
                q = c.recv(n)
                a = self.answer(q, tcp=True)
                c.sendall(struct.pack('>H', len(a)) + a)

    def close(self):
        self.stop = True
        self.udp.close()
        self.tcp.close()


class TestClient(unittest.TestCase):
    def test_servers(self):
        self.assertEqual(dnscheck.parse_server('192.0.2.53'), ('192.0.2.53', 53))
        self.assertEqual(dnscheck.parse_server('192.0.2.53:5353'), ('192.0.2.53', 5353))
        self.assertEqual(dnscheck.parse_server('[2001:db8::53]:53'), ('2001:db8::53', 53))
        self.assertEqual(dnscheck.parse_server('2001:db8::53'), ('2001:db8::53', 53))
        for bad in ('dns.example.com', '192.0.2.53:0', '192.0.2.53:99999', '', '[nope]'):
            with self.assertRaises((ValueError, TypeError)):
                dnscheck.parse_server(bad)

    def test_answers_cname_nxdomain_tcp_and_silence(self):
        fake = FakeDns({('www.example.com', A): [(CNAME, 'web.example.com'), (A, '192.0.2.10')],
                        ('www.example.com', AAAA): [(AAAA, '2001:db8::10')]})
        self.addCleanup(fake.close)
        srv = dnscheck.parse_server(fake.addr)
        r = dnscheck.resolve(srv, 'www.example.com', timeout=1)
        self.assertEqual((r['rcode'], r['addrs'], r['cname']), ('NOERROR', ['192.0.2.10', '2001:db8::10'], ['web.example.com']))
        self.assertEqual(dnscheck.resolve(srv, 'nope.example.com', timeout=1)['rcode'], 'NXDOMAIN')
        big = FakeDns({('big.example.com', A): [(A, '192.0.2.%d' % i) for i in range(1, 40)]}, truncate=True)
        self.addCleanup(big.close)
        self.assertEqual(len(dnscheck.resolve(dnscheck.parse_server(big.addr), 'big.example.com', timeout=1)['addrs']), 39)
        quiet = FakeDns({}, silent=True)
        self.addCleanup(quiet.close)
        self.assertIn('error', dnscheck.resolve(dnscheck.parse_server(quiet.addr), 'x.example.com', timeout=0.3))

    def test_a_forged_answer_is_not_taken(self):
        with self.assertRaises(dnscheck.DnsError):
            dnscheck.parse_response(struct.pack('>HHHHHH', 7, 0x8180, 0, 0, 0, 0), 8)      # another id
        with self.assertRaises(dnscheck.DnsError):                                      # a pointer loop
            dnscheck._name(b'\x00' * 12 + b'\xc0\x0c', 12)


class TestCheck(unittest.TestCase):
    def setUp(self):
        self.inside = FakeDns({('erp.example.com', A): [(A, '192.168.77.20')], ('www.example.com', A): [(A, '198.51.100.10')],
                               ('leak.example.com', A): [(A, '192.168.77.30')]})
        self.outside = FakeDns({('www.example.com', A): [(A, '198.51.100.10')], ('leak.example.com', A): [(A, '192.168.77.30')]},
                               wildcard=('example.net', '203.0.113.99'))
        self.dead = FakeDns({}, silent=True)
        for f in (self.inside, self.outside, self.dead):
            self.addCleanup(f.close)

    def test_classes(self):
        out, wild = dnscheck.check_names(['erp.example.com', 'www.example.com', 'leak.example.com', 'gone.example.com', 'shop.example.net'],
                                         [self.inside.addr], [self.outside.addr], timeout=0.5)
        got = {n: d['class'] for n, d in out.items()}
        self.assertEqual(got, {'erp.example.com': 'internal_only', 'www.example.com': 'public', 'leak.example.com': 'public',
                               'gone.example.com': 'not_found', 'shop.example.net': 'wildcard'})
        self.assertTrue(out['leak.example.com']['public_private'])     # public DNS gives an internal address
        self.assertFalse(out['www.example.com']['public_private'])
        self.assertIn('example.net', wild)
        out, _ = dnscheck.check_names(['erp.example.com'], [self.dead.addr], [self.dead.addr], timeout=0.3)
        self.assertEqual(out['erp.example.com']['class'], 'error')

    def test_ptr_with_forward_check(self):
        fake = FakeDns({('7.2.0.192.in-addr.arpa', PTR): [(PTR, 'host7.example.com')], ('host7.example.com', A): [(A, '192.0.2.7')],
                        ('8.2.0.192.in-addr.arpa', PTR): [(PTR, 'liar.example.com')], ('liar.example.com', A): [(A, '198.51.100.1')]})
        self.addCleanup(fake.close)
        srv = [('x', dnscheck.parse_server(fake.addr))]
        self.assertEqual(dnscheck.ptr_lookup('192.0.2.7', srv, timeout=0.5), {'name': 'host7.example.com', 'confirmed': True})
        self.assertEqual(dnscheck.ptr_lookup('192.0.2.8', srv, timeout=0.5), {'name': 'liar.example.com', 'confirmed': False})
        self.assertIsNone(dnscheck.ptr_lookup('192.0.2.9', srv, timeout=0.5)['name'])

    def test_the_job(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        d = os.path.join(env.dir, 'dns')
        os.makedirs(d)
        ptr = FakeDns({('7.2.0.192.in-addr.arpa', PTR): [(PTR, 'host7.example.com')], ('host7.example.com', A): [(A, '192.0.2.7')]})
        self.addCleanup(ptr.close)
        targets = {'check_hours': 24, 'internal': [self.inside.addr], 'external': [self.outside.addr],
                   'names': ['erp.example.com', 'bad name!', 'www.example.com'], 'ptr': True, 'ptr_servers': [ptr.addr],
                   'ips': ['192.0.2.7', '192.168.77.9', 'not-an-ip']}
        with open(os.path.join(d, dnscheck.TARGETS), 'w') as fh:
            json.dump(targets, fh)
        st = dnscheck.run(d, log=lambda m: None, timeout=0.5)
        self.assertEqual((st['names'], st['ptr']), (2, 1))                  # the bad name and the private address dropped
        with open(os.path.join(d, dnscheck.RESULTS)) as fh:
            res = json.load(fh)
        self.assertEqual(res['names']['erp.example.com']['class'], 'internal_only')
        with open(os.path.join(d, dnscheck.PTRS)) as fh:
            self.assertEqual(json.load(fh)['192.0.2.7']['name'], 'host7.example.com')
        # not due again for a day, unless asked; PTR names already known are not asked again
        st = dnscheck.run(d, now=time.time() + 60, log=lambda m: None, timeout=0.5)
        self.assertEqual((st.get('names'), st['ptr']), (None, 0))
        open(os.path.join(d, dnscheck.REQUEST), 'w').close()
        st = dnscheck.run(d, now=time.time() + 120, log=lambda m: None, timeout=0.5)
        self.assertEqual(st['names'], 2)
        self.assertFalse(os.path.exists(os.path.join(d, dnscheck.REQUEST)))


class TestWebSide(unittest.TestCase):
    def test_targets_card_and_sites(self):
        from jtwafmgr.app import App
        from jtwafmgr.web import api
        env = TempEnv()
        self.addCleanup(env.cleanup)
        env.cfg.data['dns'].update(enabled=True, internal_servers=['192.0.2.53'],
                                   external_servers=['198.51.100.53'])
        app = App(env.cfg)
        self.addCleanup(app.stop)
        t = app.dns.targets()
        self.assertIn('app.example.com', t['names'])
        self.assertEqual((t['internal'], t['external'], t['ptr']), (['192.0.2.53'], ['198.51.100.53'], True))
        self.assertTrue(app.dns.write_targets())
        self.assertFalse(app.dns.write_targets())                          # unchanged: not written again
        with open(os.path.join(app.dns.dir, dnscheck.RESULTS), 'w') as fh:
            json.dump({'checked_at': 'x', 'names': {'app.example.com': {'class': 'internal_only', 'public_private': False,
                                                                        'internal': {}, 'external': {}}}}, fh)
        self.assertEqual(api._dns_of(app, ['app.example.com'])['class'], 'internal_only')

        class Req:
            def __init__(self, ip):
                self.params, self.query, self.user, self.client_ip = {'ip': ip}, {}, {'username': 'v', 'role': 'viewer'}, '192.0.2.5'
        card = json.loads(api.ip_card(app, Req('203.0.113.9')).body)
        self.assertEqual(card['ptr'], {'pending': True})                    # not known: asked for
        self.assertTrue(os.path.exists(os.path.join(app.dns.dir, dnscheck.REQUEST)))
        self.assertIn('203.0.113.9', app.dns.targets()['ips'])
        with open(os.path.join(app.dns.dir, dnscheck.PTRS), 'w') as fh:
            json.dump({'203.0.113.9': {'name': 'scan.example.net', 'confirmed': False, 'at': time.time()}}, fh)
        card = json.loads(api.ip_card(app, Req('203.0.113.9')).body)
        self.assertEqual((card['ptr']['name'], card['ptr']['confirmed']), ('scan.example.net', False))
        self.assertIsNone(json.loads(api.ip_card(app, Req('192.168.77.5')).body)['ptr'])      # internal: never asked

    def test_the_folder_follows_the_database(self):
        """Without [dns] dir the job's folder is next to the database: a test with a temporary database (however it builds
        its configuration) never writes into /var/lib (G10 runs the tests as root on the server)."""
        from jtwafmgr import config
        env = TempEnv()
        self.addCleanup(env.cleanup)
        cfg = config.load(None, {'paths': {'db': os.path.join(env.dir, 'x', 'jt.db')}})
        self.assertEqual(dnscheck.dns_dir(cfg), os.path.join(env.dir, 'x', 'dns'))
        cfg = config.load(None, {'paths': {'db': os.path.join(env.dir, 'x', 'jt.db')}, 'dns': {'dir': '/srv/dns'}})
        self.assertEqual(dnscheck.dns_dir(cfg), '/srv/dns')

    def test_settings_refuse_names_for_servers(self):
        from jtwafmgr import uisettings
        self.assertEqual(uisettings._validate('dns.internal_servers', ['192.0.2.53', '[2001:db8::53]:53']),
                         ['192.0.2.53', '[2001:db8::53]:53'])
        with self.assertRaises(uisettings.SettingError):
            uisettings._validate('dns.external_servers', ['dns.example.com'])


if __name__ == '__main__':
    unittest.main()
