import gzip
import json
import os
import time
import unittest

from jtwafmgr.collector.auditlog import Parser, Store, Tailer
from jtwafmgr.db import Database
from tests.helpers import TempEnv, record


class TestParser(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.p = Parser(self.env.cfg)

    def tearDown(self):
        self.env.cleanup()

    def test_confident_block(self):
        e = self.p.parse(record(uri='/../etc/passwd', status=403, engine='Enabled',
                                rules=[(930110, 'Path Traversal Attack', 'Matched Data: ../ found within REQUEST_URI_RAW: /../etc'),
                                       10203, (949110, 'Inbound Anomaly Score Exceeded (Total Score: 10)', '')]))
        self.assertEqual(e['outcome'], 'blocked')
        self.assertEqual(e['decided_by'], 'confident')
        self.assertEqual(e['origin'], 'external')
        self.assertEqual(e['anomaly_score'], 10)
        self.assertEqual(e['local_rule_ids'], [10203])
        self.assertIn('lfi', e['families'])
        self.assertEqual(e['host'], 'app.example.com')
        self.assertEqual(e['message'], 'Path Traversal Attack')

    def test_fallback(self):
        e = self.p.parse(record(status=403, engine='Enabled', rules=[10203, 10299]))
        self.assertEqual(e['decided_by'], 'fallback')

    def test_score_only_shows_only_fallback(self):
        # 10297 is nolog: a block it decided shows the fallback rule and CRS rules only (LESSONS 17)
        e = self.p.parse(record(status=403, engine='Enabled', rules=[930120, 949110, 10299]))
        self.assertEqual(e['decided_by'], 'score')

    def test_logged_internal(self):
        e = self.p.parse(record(ip='192.168.77.50', rules=[930120]))
        self.assertEqual(e['outcome'], 'logged')
        self.assertIsNone(e['decided_by'])
        self.assertEqual(e['origin'], 'internal')

    def test_detection_only_403_from_backend_is_not_blocked(self):
        e = self.p.parse(record(status=403, engine='DetectionOnly', rules=[930120]))
        self.assertEqual(e['outcome'], 'logged')

    def test_body_error_400(self):
        e = self.p.parse(record(status=400, engine='Enabled', rules=[200002]))
        self.assertEqual(e['outcome'], 'blocked')
        self.assertEqual(e['decided_by'], 'other')
        e = self.p.parse(record(status=400, engine='Enabled', rules=[930120]))
        self.assertEqual(e['outcome'], 'logged')

    def test_redacts_password_in_data_and_query(self):
        e = self.p.parse(record(uri='/login?user=bob&password=hunter2', rules=[
            (942100, 'SQL Injection Attack Detected via libinjection', "Matched Data: s&1 found within ARGS:password: hunter2' or 1=1")]))
        blob = json.dumps(e)
        self.assertNotIn('hunter2', blob)
        self.assertEqual(e['query'], 'user=bob&password=***')
        self.assertTrue(e['matches'][0]['data'].startswith('[redacted'))

    def test_attacker_strings_kept_as_text(self):
        evil = '/<script>alert(1)</script>\x1b[31m'
        e = self.p.parse(record(uri=evil, rules=[941100]))
        self.assertEqual(e['path'], evil)  # stored verbatim; the UI renders text nodes only

    def test_unique_id_host_with_dash(self):
        e = self.p.parse(record(host='my-app.example.com'))
        self.assertEqual(e['host'], 'my-app.example.com')

    def test_not_a_transaction(self):
        self.assertIsNone(self.p.parse('{"foo": 1}'))
        self.assertIsNone(self.p.parse('[1,2]'))
        with self.assertRaises(ValueError):
            self.p.parse('{not json')

    def test_many_messages_truncated(self):
        e = self.p.parse(record(rules=list(range(930000, 930150))))
        self.assertTrue(e['truncated'])
        self.assertEqual(len(e['matches']), 100)


class TestTailer(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.db = Database(self.env.cfg['paths']['db'])
        self.t = Tailer(self.env.cfg, self.db)

    def tearDown(self):
        self.env.cleanup()

    def count(self):
        return self.db.one('SELECT COUNT(*) FROM events')[0]

    def test_incremental_and_partial_line(self):
        self.env.write_log([record(rules=[930120]) for _ in range(3)])
        self.t.poll()
        self.assertEqual(self.count(), 3)
        with open(self.env.audit_log, 'a') as fh:
            fh.write(record(rules=[930120])[:50])  # half-written line
        self.t.poll()
        self.assertEqual(self.count(), 3)
        self.t.poll()
        self.assertEqual(self.count(), 3)

    def test_copytruncate(self):
        self.env.write_log([record() for _ in range(5)])
        self.t.poll()
        self.env.write_log([record()], mode='w')  # truncated, then one new line
        self.t.poll()
        self.assertEqual(self.count(), 6)

    def test_rename_rotation(self):
        self.env.write_log([record() for _ in range(2)])
        self.t.poll()
        self.env.write_log([record()])  # written after our last read, before rotation
        os.rename(self.env.audit_log, self.env.audit_log + '.1')
        self.env.write_log([record(), record()], mode='w')
        self.t.poll()
        self.assertEqual(self.count(), 5)

    def test_garbage_and_oversized(self):
        big = record(uri='/' + 'A' * (self.env.cfg['collector']['max_record_bytes'] + 10))
        self.env.write_log(['not json', '', big, record()])
        self.t.poll()
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.t.stats['parse_errors'], 1)
        self.assertEqual(self.t.stats['oversized'], 1)

    def test_import_gz_and_dedupe(self):
        lines = [record() for _ in range(4)]
        gz = os.path.join(self.env.dir, 'old.log.2.gz')
        with gzip.open(gz, 'wt') as fh:
            fh.write('\n'.join(lines) + '\n')
        self.t.import_file(gz)
        self.t.import_file(gz)
        self.assertEqual(self.count(), 4)

    def test_restart_resumes(self):
        self.env.write_log([record() for _ in range(3)])
        self.t.poll()
        t2 = Tailer(self.env.cfg, self.db)
        self.env.write_log([record()])
        t2.poll()
        self.assertEqual(self.count(), 4)

    def test_purge(self):
        old = time.time() - 40 * 86400
        self.env.write_log([record(ts=old, rules=[930120]), record(rules=[930120])])
        self.t.poll()
        Store(self.db).purge(30, 365)
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.db.one('SELECT COUNT(*) FROM event_rules')[0], 1)

    def test_missing_file(self):
        self.assertFalse(self.t.poll())
        self.assertIn('cannot stat', self.t.stats['error'])


if __name__ == '__main__':
    unittest.main()
