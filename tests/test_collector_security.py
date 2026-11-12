"""Collector and redaction hardening: ReDoS, oversized records, long unique ids, cookies,
copytruncate rotation and bad rows. Synthetic data only (example.com, documentation ranges)."""
import io
import json
import os
import shutil
import sqlite3
import time
import unittest
from contextlib import redirect_stderr

from jtwafmgr import config, util
from jtwafmgr.collector.auditlog import Parser, Store, Tailer, _uid
from jtwafmgr.db import Database
from tests.helpers import TempEnv, record

SQLI = 'SQL Injection Attack Detected via libinjection'


def tweak(line, fn):
    """Change a helpers.record() line through its decoded transaction."""
    obj = json.loads(line)
    fn(obj['transaction'])
    return json.dumps(obj)


def set_match(match):
    def fn(t):
        for m in t['messages']:
            m['details']['match'] = match
    return fn


class TestRedactionLinear(unittest.TestCase):
    def setUp(self):
        self.r = util.Redactor(config.load().sensitive)

    def test_one_megabyte_field_is_fast(self):
        # was quadratic: 16 KB took ~11 s, 12 KB through Parser ~7 s
        for s in ('Matched Data: x found within ARGS:q: ' + 'a' * 1000000, 'a=' * 500000, '"a":' * 250000,
                  'name="' * 170000, '[' * 1000000, ' =' * 500000, 'cookie: ' * 125000):
            t = time.monotonic()
            out = self.r.text(s)
            self.assertLess(time.monotonic() - t, 0.5, s[:20])
            self.assertLessEqual(len(out), util.PRE_CLIP + 1)

    def test_regexes_are_linear_without_the_clip(self):
        # even with the pre-clip lifted, a 1 MB run is handled in about a second, not hours
        for s in ('a' * 1000000, 'a.b[c]-' * 140000, '"' + 'x' * 1000000):
            t = time.monotonic()
            self.r.text(s, limit=10 ** 7)
            self.assertLess(time.monotonic() - t, 3, s[:20])

    def test_references_bounded_and_fail_closed(self):
        t = time.monotonic()
        self.assertIsNone(self.r.references_sensitive('ARGS:a ' * 150000))
        # too many different names: treated as sensitive instead of checked one by one
        self.assertTrue(self.r.references_sensitive(' '.join('ARGS:a%d' % i for i in range(5000))))
        self.assertLess(time.monotonic() - t, 1)

    def test_clip_keeps_names_in_front_of_values(self):
        s = 'q=' + 'x' * (util.PRE_CLIP - 20) + '&password=hunter2hunter2hunter2'
        self.assertNotIn('hunter2', self.r.text(s))
        s = 'x' * (util.PRE_CLIP - 20) + ' {"password": "hunter2hunter2hunter2hunter2"}'
        self.assertNotIn('hunter2', self.r.text(s))  # closing quote cut off by the clip

    def test_existing_behaviour(self):
        self.assertEqual(self.r.text('login=bob&password=hunter2'), 'login=bob&password=***')
        self.assertEqual(self.r.text('{"login": "bob", "password": "hunter2"}'), '{"login": "bob", "password": "***"}')
        self.assertEqual(self.r.text('Matched Data: ../ found within ARGS:file: ../etc'),
                         'Matched Data: ../ found within ARGS:file: ../etc')

    def test_parser_with_one_megabyte_parameter(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        p = Parser(env.cfg)
        val = "1' or 1=1-- " + 'a' * 1000000
        line = record(rules=[(942100, SQLI, 'Matched Data: s&1c found within ARGS:q: ' + val)])
        t = time.monotonic()
        e = p.parse(line)
        self.assertLess(time.monotonic() - t, 1)
        self.assertLessEqual(len(e['matches'][0]['data']), 513)
        self.assertTrue(e['matches'][0]['data'].startswith('Matched Data: s&1c found within ARGS:q: 1'))


class TestOversized(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.db = Database(self.env.cfg['paths']['db'])
        self.t = Tailer(self.env.cfg, self.db)

    def tearDown(self):
        self.env.cleanup()

    def events(self):
        return [dict(r) for r in self.db.q('SELECT * FROM events ORDER BY id')]

    def big_attack(self, size, compact=False, spoof=False):
        payload = "1' union select " + 'a' * size
        if spoof:
            # an attacker trying to plant structure: all of it is escaped inside the JSON string
            payload += '",{"ruleId":"10299"},"http_code":200,"producer":{"secrules_engine":"DetectionOnly"}'
        line = record(host='shop.example.com', uri='/search?q=1', ip='198.51.100.23', status=403, engine='Enabled',
                      rules=[(942100, SQLI, 'Matched Data: s&1 found within ARGS:q: ' + payload),
                             (949110, 'Inbound Anomaly Score Exceeded (Total Score: 10)', '')])
        if compact:  # libmodsecurity (yajl) writes no spaces
            line = json.dumps(json.loads(line), separators=(',', ':'))
        return line

    def check_big(self, e):
        self.assertEqual(e['truncated'], 1)
        self.assertEqual(e['host'], 'shop.example.com')
        self.assertEqual(e['path'], '/search')
        self.assertEqual(e['query'], 'q=1')
        self.assertEqual(e['src_ip'], '198.51.100.23')
        self.assertEqual(e['status'], 403)
        self.assertEqual(e['engine'], 'Enabled')
        self.assertEqual(e['outcome'], 'blocked')
        self.assertEqual(e['rule_ids'], ',942100,949110,')
        self.assertEqual(e['anomaly_score'], 10)
        self.assertEqual(e['message'], SQLI)
        self.assertNotIn('union select', e['matches'])

    def test_two_megabyte_attack_parameter_is_kept(self):
        size = 2 * self.env.cfg['collector']['max_record_bytes']
        for compact in (False, True):
            self.env.write_log([self.big_attack(size, compact=compact), record(uri='/after')], mode='w')
            self.t = Tailer(self.env.cfg, self.db)
            self.db.x('DELETE FROM collector_state')
            self.db.x('DELETE FROM event_rules')
            self.db.x('DELETE FROM events')
            self.t.poll()
            ev = self.events()
            self.assertEqual([e['path'] for e in ev], ['/search', '/after'])
            self.check_big(ev[0])
            self.assertEqual(self.t.stats['oversized'], 1)
            self.assertEqual(self.t.stats['parse_errors'], 0)

    def test_structure_in_the_payload_is_not_believed(self):
        self.env.write_log([self.big_attack(self.env.cfg['collector']['max_record_bytes'], compact=True, spoof=True)])
        self.t.poll()
        self.check_big(self.events()[0])

    def test_oversized_within_one_read_and_across_polls(self):
        env = TempEnv(collector={'max_record_bytes': 4096})
        self.addCleanup(env.cleanup)
        db = Database(env.cfg['paths']['db'])
        t = Tailer(env.cfg, db)
        env.write_log([self.big_attack(50000), record(uri='/next')])  # whole line in one read
        line = self.big_attack(50000, compact=True)
        with open(env.audit_log, 'a') as fh:
            fh.write(line[:30000])  # half written: scanned, nothing stored yet
        t.poll()
        self.assertEqual(db.one('SELECT COUNT(*) FROM events')[0], 2)
        with open(env.audit_log, 'a') as fh:
            fh.write(line[30000:] + '\n' + record(uri='/last') + '\n')
        t.poll()
        rows = db.conn().execute('SELECT path, truncated, rule_ids FROM events ORDER BY id').fetchall()
        self.assertEqual([tuple(r) for r in rows], [('/search', 1, ',942100,949110,'), ('/next', 0, ',,'),
                                                     ('/search', 1, ',942100,949110,'), ('/last', 0, ',,')])
        self.assertEqual(t.stats['oversized'], 2)

    def test_host_from_unique_id_when_headers_are_far(self):
        def fn(t):
            t['request']['body'] = 'x' * 200000
            t['request']['headers'] = {'Host': 'shop.example.com'}
        line = tweak(self.big_attack(self.env.cfg['collector']['max_record_bytes']), fn)
        self.env.write_log([line])
        self.t.poll()
        self.check_big(self.events()[0])


class TestLongUniqueId(unittest.TestCase):
    def test_same_long_host_events_all_stored(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        db = Database(env.cfg['paths']['db'])
        t = Tailer(env.cfg, db)
        host = 'a' * 388 + '.example.com'
        self.assertEqual(len(host), 400)
        env.write_log([record(host=host, uri='/benign', rules=[920350])] +
                      [record(host=host, uri='/etc/passwd%d' % i, rules=[930120]) for i in range(5)])
        t.poll()
        self.assertEqual(db.one('SELECT COUNT(*) FROM events')[0], 6)
        uids = [r[0] for r in db.conn().execute('SELECT unique_id FROM events')]
        self.assertTrue(all(len(u) == 200 and '#' in u for u in uids))
        t.import_file(env.audit_log)  # the same records again: still deduplicated
        self.assertEqual(db.one('SELECT COUNT(*) FROM events')[0], 6)

    def test_short_ids_unchanged(self):
        uid = 'app.example.com-' + '0' * 32
        self.assertEqual(_uid(uid), uid)
        self.assertEqual(_uid('x' * 200), 'x' * 200)
        self.assertNotEqual(_uid('x' * 201), _uid('x' * 200 + 'y'))


class TestCookies(unittest.TestCase):
    NAMES = ('PHPSESSID', 'KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION', 'wordpress_logged_in_0123abcd', 'sid',
             'connect.sid', 'remember_web_59ba45f1', 'laravel_session', 'JSESSIONID', 'AUTH_SESSION_ID')

    def setUp(self):
        self.env = TempEnv()
        self.p = Parser(self.env.cfg)
        self.r = util.Redactor(self.env.cfg.sensitive)

    def tearDown(self):
        self.env.cleanup()

    def test_request_cookies_always_masked(self):
        for name in self.NAMES:
            data = "Matched Data: x' found within REQUEST_COOKIES:%s: SECRETVALUE' or 1=1" % name
            match = "Matched \"Operator `DetectSQLi' with parameter `' against variable `REQUEST_COOKIES:%s' " \
                    "(Value: `SECRETVALUE' or 1=1' )" % name
            e = self.p.parse(tweak(record(rules=[(942100, SQLI, data)]), set_match(match)))
            self.assertNotIn('SECRETVALUE', json.dumps(e), name)
            self.assertTrue(e['matches'][0]['data'].startswith('[redacted'), name)
            self.assertEqual(e['rule_ids'], [942100])

    def test_cookie_names_and_bare_collection(self):
        for data in ("Matched Data: KEYCLOAK_SESSION found within REQUEST_COOKIES_NAMES:KEYCLOAK_SESSION: KEYCLOAK_SESSION",
                     "Matched Data: SECRETVALUE found within REQUEST_COOKIES: SECRETVALUE"):
            e = self.p.parse(record(rules=[(942100, SQLI, data)]))
            self.assertTrue(e['matches'][0]['data'].startswith('[redacted'), data)
            self.assertNotIn('SECRETVALUE', json.dumps(e))

    def test_secret_headers(self):
        for hdr in ('Authorization', 'Proxy-Authorization', 'Cookie', 'Set-Cookie', 'cookie'):
            data = "Matched Data: ' or 1=1 found within REQUEST_HEADERS:%s: Basic SECRETVALUE' or 1=1" % hdr
            e = self.p.parse(record(rules=[(942100, SQLI, data)]))
            self.assertNotIn('SECRETVALUE', json.dumps(e), hdr)
        for text in ('Cookie: PHPSESSID=SECRETVALUE; theme=dark', 'Set-Cookie: sid=SECRETVALUE; HttpOnly',
                     'Proxy-Authorization: Basic SECRETVALUE', 'cookie: a=SECRETVALUE\nnext line kept'):
            out = self.r.text(text)
            self.assertNotIn('SECRETVALUE', out, text)
        self.assertTrue(self.r.text('cookie: a=SECRETVALUE\nnext line kept').endswith('\nnext line kept'))

    def test_args_still_by_name(self):
        e = self.p.parse(record(rules=[(942100, SQLI, "Matched Data: s&1 found within ARGS:q: 1' or 1=1")]))
        self.assertEqual(e['matches'][0]['data'], "Matched Data: s&1 found within ARGS:q: 1' or 1=1")
        e = self.p.parse(record(rules=[(942100, SQLI, "Matched Data: s&1 found within ARGS:session_id: SECRETVALUE")]))
        self.assertNotIn('SECRETVALUE', json.dumps(e))

    def test_multipart_sensitive_part(self):
        for nl in ('\r\n', '\\r\\n', '\n'):
            body = ('------WebKitFormBoundaryX{nl}Content-Disposition: form-data; name="user"{nl}{nl}bob{nl}'
                    '------WebKitFormBoundaryX{nl}Content-Disposition: form-data; name="password"{nl}{nl}SECRETVALUE{nl}'
                    '------WebKitFormBoundaryX{nl}Content-Disposition: form-data; name="next"{nl}{nl}/home{nl}'
                    '------WebKitFormBoundaryX--').format(nl=nl)
            out = self.r.text(body)
            self.assertNotIn('SECRETVALUE', out, repr(nl))
            self.assertIn('bob', out)
            self.assertIn('/home', out)
            self.assertIn('name="password"', out)
        out = self.r.text('Content-Disposition: form-data; name="api_key"; filename="k.txt" SECRETVALUE')
        self.assertNotIn('SECRETVALUE', out)
        self.assertEqual(self.r.text('form-data; name="comment"\r\n\r\nhello'), 'form-data; name="comment"\r\n\r\nhello')


class TestCopytruncate(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.db = Database(self.env.cfg['paths']['db'])
        self.t = Tailer(self.env.cfg, self.db)
        self.rot = self.env.audit_log + '.1'

    def tearDown(self):
        self.env.cleanup()

    def count(self):
        return self.db.one('SELECT COUNT(*) FROM events')[0]

    def copytruncate(self, new_lines):
        shutil.copyfile(self.env.audit_log, self.rot)  # logrotate: copy, then truncate in place
        ino = os.stat(self.env.audit_log).st_ino
        self.env.write_log(new_lines, mode='w')
        self.assertEqual(os.stat(self.env.audit_log).st_ino, ino)

    def test_shrunk_reads_rest_of_rotated_file(self):
        self.env.write_log([record() for _ in range(3)])
        self.t.poll()
        self.env.write_log([record(uri='/unread%d' % i) for i in range(2)])  # after our read, before the copy
        self.copytruncate([record()])
        self.t.poll()
        self.assertEqual(self.count(), 6)
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM events WHERE path LIKE '/unread%'")[0], 2)

    def test_regrown_past_old_offset(self):
        self.env.write_log([record() for _ in range(3)])
        self.t.poll()
        self.env.write_log([record(uri='/unread%d' % i) for i in range(2)])
        self.copytruncate([record(uri='/new%d' % i) for i in range(10)])  # bigger than the old offset
        self.t.poll()
        self.assertEqual(self.count(), 15)
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM events WHERE path LIKE '/new%'")[0], 10)
        self.t.poll()
        self.assertEqual(self.count(), 15)

    def test_after_restart(self):
        self.env.write_log([record() for _ in range(3)])
        self.t.poll()
        self.env.write_log([record(uri='/unread')])
        self.copytruncate([record(uri='/new%d' % i) for i in range(10)])
        Tailer(self.env.cfg, self.db).poll()
        self.assertEqual(self.count(), 14)

    def test_unrelated_rotated_file_is_not_read(self):
        self.env.write_log([record() for _ in range(3)])
        self.t.poll()
        with open(self.rot, 'w') as fh:  # some other file, larger than our offset
            fh.write('\n'.join(record(uri='/other%d' % i) for i in range(20)) + '\n')
        self.env.write_log([record(uri='/new')], mode='w')
        self.t.poll()
        self.assertEqual(self.count(), 4)
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM events WHERE path LIKE '/other%'")[0], 0)

    def test_growing_file_unaffected(self):
        for i in range(5):
            self.env.write_log([record() for _ in range(300)])  # crosses the 4 KB head
            self.t.poll()
        self.assertEqual(self.count(), 1500)


class TestBadRows(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.db = Database(self.env.cfg['paths']['db'])
        self.t = Tailer(self.env.cfg, self.db)

    def tearDown(self):
        self.env.cleanup()

    def count(self):
        return self.db.one('SELECT COUNT(*) FROM events')[0]

    def offset(self):
        return self.db.one('SELECT offset FROM collector_state')[0]

    def test_bad_row_skipped_and_offset_advances(self):
        def port(t):
            t['client_port'] = 10 ** 20  # too large for an SQLite integer
        self.env.write_log([record(uri='/a'), tweak(record(uri='/bad'), port), record(uri='/b')])
        err = io.StringIO()
        with redirect_stderr(err):
            self.t.poll()
        self.assertEqual(self.count(), 2)
        self.assertEqual(self.t.stats['insert_errors'], 1)
        self.assertIn('skipped an event', err.getvalue())
        self.assertEqual(self.offset(), os.path.getsize(self.env.audit_log))
        self.env.write_log([record(uri='/c')])
        with redirect_stderr(io.StringIO()):
            self.t.poll()
        self.assertEqual(self.count(), 3)
        self.assertEqual(self.t.stats['insert_errors'], 1)

    def test_lone_surrogate_stored_after_scrub(self):
        line = record(rules=[(942100, '\ud800 odd message', 'Matched Data: \ud800 found within ARGS:q: \udfff')])
        self.env.write_log([line, record(uri='/b')])
        self.t.poll()
        self.assertEqual(self.count(), 2)
        self.assertEqual(self.t.stats['insert_errors'], 0)

    def test_database_errors_do_not_advance(self):
        class Locked(Store):
            def insert(self, events):
                raise sqlite3.OperationalError('database is locked')
        self.env.write_log([record(), record()])
        t = Tailer(self.env.cfg, self.db, store=Locked(self.db))
        with self.assertRaises(sqlite3.OperationalError):
            t.poll()
        self.assertIsNone(self.db.one('SELECT offset FROM collector_state'))
        self.t.poll()
        self.assertEqual(self.count(), 2)


if __name__ == '__main__':
    unittest.main()
