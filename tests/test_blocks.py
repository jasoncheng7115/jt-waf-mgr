"""Temporary IP blocks (blocks.py, apply.py blocks action, api_blocks.py). Synthetic data only."""
import json
import os
import shutil
import tempfile
import time
import unittest

from jtwafmgr import auth, blocks, config
from jtwafmgr.app import App
from jtwafmgr.apply import Applier, Fail
from jtwafmgr.blocks import BlockError
from jtwafmgr.web.server import start_background
from tests.helpers import FIXTURE_SITE, TempEnv, rd, wr
from tests.test_api import PW, Client


def env_with_blocks(**over):
    env = TempEnv()
    b = {'enabled': True, 'file': os.path.join(env.dir, 'nginx', 'jt-waf-mgr', 'blocked-ips.conf'),
         'protected': ['198.51.100.0/25'], 'reload_seconds': 5}
    b.update(over)
    env.cfg.data['blocks'].update(b)
    env.cfg.data['managed']['spool'] = os.path.join(env.dir, 'spool')
    os.makedirs(env.cfg.data['managed']['spool'])
    return env


class LogicTest(unittest.TestCase):
    def setUp(self):
        self.env = env_with_blocks()
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg)
        self.addCleanup(self.app.stop)
        self.b = self.app.blocks

    def audit(self, action):
        return [json.loads(r['details']) for r in self.app.db.q('SELECT details FROM audit WHERE action=? ORDER BY id', (action,))]

    def requests(self):
        d = self.env.cfg['managed']['spool']
        return sorted(n for n in os.listdir(d) if n.startswith('blocks-') and n.endswith('.req'))

    def test_targets(self):
        cfg = self.env.cfg
        self.assertEqual(blocks.check_target(cfg, '203.0.113.7'), '203.0.113.7')
        self.assertEqual(blocks.check_target(cfg, '2001:db8::7'), '2001:db8::7')
        for bad, code in (('192.168.77.5', 'not_public'), ('127.0.0.1', 'not_public'),
                          ('100.64.1.1', 'not_public'), ('fe80::1', 'not_public'), ('::1', 'not_public'),
                          ('198.51.100.20', 'protected'), ('nonsense', 'invalid_ip'), ('', 'invalid_ip'),
                          ('203.0.113.0/24', 'single_address_only'), ('203.0.113.7; deny all', 'invalid_ip')):
            with self.assertRaises(BlockError) as cm:
                blocks.check_target(cfg, bad)
            self.assertEqual(cm.exception.code, code, bad)
        self.assertEqual(blocks.check_target(cfg, '203.0.113.9/24', allow_range=True), '203.0.113.0/24')
        with self.assertRaises(BlockError) as cm:
            blocks.check_target(cfg, '203.0.0.0/16', allow_range=True)
        self.assertEqual(cm.exception.code, 'range_too_wide')
        # a range that contains a protected network is refused too
        with self.assertRaises(BlockError):
            blocks.check_target(cfg, '198.51.100.0/24', allow_range=True)

    def test_add_extend_sources_remove_expire(self):
        a = self.b.add('203.0.113.7', 600, 'mail2/zimbra-webmail', '4 failed logins', 'tok-mail2', via='token', token_id='t2')
        self.assertEqual((a['ip'], a['state']), ('203.0.113.7', 'active'))
        # the same source again: extended, not a second entry
        e = self.b.add('203.0.113.7', 3600, 'mail2/zimbra-webmail', 'again', 'tok-mail2', via='token', token_id='t2')
        self.assertEqual(e['id'], a['id'])
        self.assertEqual(e['extended'], 1)
        # another source: its own entry; the list has the address once
        self.b.add('203.0.113.7', 600, 'mail1/zimbra-webmail', 'x', 'tok-mail1', via='token', token_id='t1')
        self.assertEqual(len(self.b.active()), 2)
        self.assertEqual(self.b.desired(), ['203.0.113.7'])
        self.assertEqual(len(self.b.blocked('203.0.113.7')), 2)
        self.assertEqual(self.b.blocked('203.0.113.8'), [])
        # a token removes only its own
        with self.assertRaises(BlockError):
            self.b.remove('tok-mail1', via='token', ip='203.0.113.99', token_id='t1')
        self.assertEqual(self.b.remove('tok-mail1', via='token', ip='203.0.113.7', token_id='t1'), 1)
        self.assertEqual(self.b.desired(), ['203.0.113.7'])           # still blocked for mail2
        # a person ends one entry by id, with a note
        with self.assertRaises(BlockError):
            self.b.remove('admin1', block_id=a['id'], note='')
        self.assertEqual(self.b.remove('admin1', block_id=a['id'], note='false alarm'), 1)
        self.assertEqual(self.b.desired(), [])
        # expiry
        self.b.add('203.0.113.8', 60, 'ui', 'test', 'admin1', role='admin')
        self.assertEqual(self.b.expire(now=time.time() + 61), 1)
        self.assertEqual(self.b.desired(), [])
        acts = [r['action'] for r in self.app.db.q("SELECT action FROM audit WHERE action LIKE 'block.%' ORDER BY id")]
        self.assertEqual(acts[:5], ['block.add', 'block.extend', 'block.add', 'block.refused', 'block.remove'])
        self.assertIn('block.expired', acts)
        self.assertEqual(self.audit('block.expired')[-1]['ips'], ['203.0.113.8'])

    def test_limits(self):
        with self.assertRaises(BlockError) as cm:
            self.b.add('203.0.113.7', 9 * 86400, 's', 'r', 'tok', via='token', token_id='t')
        self.assertEqual(cm.exception.code, 'invalid_ttl')          # tokens: at most 7 days
        with self.assertRaises(BlockError) as cm:
            self.b.add('203.0.113.7', 600, 's', '', 'tok', via='token', token_id='t')
        self.assertEqual(cm.exception.code, 'reason_required')
        with self.assertRaises(BlockError) as cm:
            self.b.add('203.0.113.0/24', 600, 's', 'r', 'tok', via='token', token_id='t')
        self.assertEqual(cm.exception.code, 'single_address_only')
        # an approver may block a narrow range for up to 30 days
        self.assertEqual(self.b.add('203.0.113.0/24', 20 * 86400, 'ui', 'r', 'admin1', role='approver')['ip'], '203.0.113.0/24')
        # the hourly limit of a token
        self.env.cfg.data['blocks']['token_per_hour'] = 3
        for i in range(3):
            self.b.add('192.0.2.%d' % (i + 1), 600, 's', 'r', 'tok', via='token', token_id='rate')
        with self.assertRaises(BlockError) as cm:
            self.b.add('192.0.2.9', 600, 's', 'r', 'tok', via='token', token_id='rate')
        self.assertEqual((cm.exception.code, cm.exception.status), ('rate_limited', 429))
        # the list is full: refused, and an alert says so
        self.env.cfg.data['blocks']['max_active'] = len(self.b.active())
        with self.assertRaises(BlockError) as cm:
            self.b.add('192.0.2.50', 600, 'ui', 'r', 'admin1', role='admin')
        self.assertEqual(cm.exception.code, 'too_many_blocks')
        self.assertTrue(self.app.db.one("SELECT 1 FROM alerts WHERE dedup='blocks_full'"))
        # off: nothing is accepted
        self.env.cfg.data['blocks']['enabled'] = False
        with self.assertRaises(BlockError) as cm:
            self.b.add('192.0.2.60', 600, 'ui', 'r', 'admin1', role='admin')
        self.assertEqual(cm.exception.code, 'blocks_off')

    def test_sync_queues_once_and_takes_the_result(self):
        self.b.add('203.0.113.7', 600, 's', 'r', 'tok', via='token', token_id='t')
        reqs = self.requests()
        self.assertEqual(len(reqs), 1)
        req = json.loads(rd(os.path.join(self.env.cfg['managed']['spool'], reqs[0])))
        self.assertEqual((req['action'], req['entries']), ('blocks', ['203.0.113.7']))
        # one in flight: no second request
        self.b.add('203.0.113.8', 600, 's', 'r', 'tok', via='token', token_id='t')
        self.assertEqual(len(self.requests()), 1)
        self.assertFalse(self.b.status()['in_sync'])
        # the apply program answers for the first list; the second goes out after reload_seconds
        self.app.workflow._handle_result({'request_id': req['request_id'], 'action': 'blocks', 'result': 'ok', 'count': 1,
                                          'sha256': req['sha256'], 'changed': True, 'summary': 'ok'})
        self.assertEqual(self.b.sync(), None)                 # too soon after the last write
        self.b.sync(force=True)
        reqs = self.requests()
        self.assertEqual(len(reqs), 2)
        req2 = json.loads(rd(os.path.join(self.env.cfg['managed']['spool'], reqs[-1])))
        self.assertEqual(req2['entries'], ['203.0.113.7', '203.0.113.8'])
        self.app.workflow._handle_result({'request_id': req2['request_id'], 'action': 'blocks', 'result': 'ok', 'count': 2,
                                          'sha256': req2['sha256'], 'changed': True, 'summary': 'ok'})
        self.assertTrue(self.b.status()['in_sync'])
        self.assertEqual(self.b.sync(force=False), None)       # nothing new
        # a failed write: crit audit and an alert
        self.b.add('203.0.113.9', 600, 's', 'r', 'tok', via='token', token_id='t')
        req3 = self.b.sync(force=True) or json.loads(rd(os.path.join(self.env.cfg['managed']['spool'], self.requests()[-1])))['request_id']
        self.app.workflow._handle_result({'request_id': req3, 'action': 'blocks', 'result': 'failed', 'summary': 'nginx -t failed'})
        self.assertTrue(self.app.db.one("SELECT 1 FROM alerts WHERE dedup='blocks_apply_failed'"))
        self.assertFalse(self.b.status()['in_sync'])

    def test_status_finds_the_include_and_uncovered_servers(self):
        site = os.path.join(self.env.dir, 'site')
        shutil.copytree(FIXTURE_SITE, site, symlinks=True)
        conf = os.path.join(site, 'nginx.conf')
        self.env.cfg.data['paths']['nginx_conf'] = conf
        path = self.env.cfg['blocks']['file']
        os.makedirs(os.path.dirname(path))
        wr(path, blocks.render(['203.0.113.7'], path))
        st = self.b.status()
        self.assertFalse(st['included'])
        text = rd(conf)
        self.assertIn('http {', text)
        wr(conf, text.replace('http {', 'http {\n    include %s;' % path, 1))
        st = self.b.status()
        self.assertTrue(st['included'], st)
        self.assertEqual(st['included_in'], 'http')
        # an empty list (no deny lines at all) is still seen as loaded: the include itself is what counts
        wr(path, blocks.render([], path))
        self.assertTrue(self.b.status()['included'])
        # loaded inside a server instead: reported as such, not as covering every site
        wr(conf, text)
        vh = os.path.join(site, 'vhost', sorted(os.listdir(os.path.join(site, 'vhost')))[0])
        wr(vh, rd(vh).replace('server {', 'server {\n    include %s;' % path, 1))
        st = self.b.status()
        self.assertFalse(st['included'])
        self.assertEqual(st['included_in'], 'server')

    def test_list_has_no_allow(self):
        # nginx stops at the first allow / deny that matches within a level: an "allow all" at the end of this file
        # would turn an administrator's own "deny" after the include (same http{}) from 403 into 200
        for entries in ([], ['203.0.113.7', '2001:db8::/64']):
            body = [ln for ln in blocks.render(entries, '/x').splitlines() if ln and not ln.startswith('#')]
            self.assertEqual(body, ['deny %s;' % e for e in entries])

    def _probe(self, ip, paths, ago=60, status=403):
        for i, p in enumerate(paths):
            self.app.db.x("INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, status, outcome, "
                          "rule_ids, local_rule_ids, families, message, matches) VALUES ('n', ?, ?, 'www.example.com', 'GET', ?, '', "
                          "?, 'external', ?, ?, '', '', '', '', '[]')",
                          ('%s-%d-%d-%d' % (ip, i, ago, status), time.time() - ago, p, ip, status,
                           'blocked' if status == 403 else 'detected'))

    def test_auto_recon_leaves_answered_and_ambiguous_sources(self):
        self.env.cfg.data['blocks']['auto_recon'] = True
        cfgs = ['/team%d/config.json' % i for i in range(5)]
        self._probe('203.0.113.80', cfgs, status=200)              # five config.json, all answered: a real front end
        self._probe('203.0.113.81', cfgs, status=404)              # five config.json, not found: no unmistakable name
        secrets = ['/.env', '/.aws/credentials', '/wp-config.php.bak', '/id_rsa.pem', '/backup.sql']
        self._probe('203.0.113.82', secrets)                       # refused secrets ...
        self._probe('203.0.113.82', ['/settings.json'], status=200)  # ... but one answered 2xx: for a person to look at
        self._probe('203.0.113.83', ['/a/config.json', '/b/config.json', '/c/settings.yml', '/d/database.yml'], status=404)
        self._probe('203.0.113.83', ['/.git/config'], status=403)  # four ambiguous plus one unmistakable: a scanner
        self.assertEqual(self.b.auto_recon(), ['203.0.113.83'])

    def test_auto_recon(self):
        secrets = ['/.env', '/config.json', '/.aws/credentials', '/wp-config.php.bak', '/docker-compose.yml', '/id_rsa.pem']
        self._probe('203.0.113.70', secrets)                       # six secret names: a scanner
        self._probe('203.0.113.71', secrets[:3] + ['/', '/about'])  # three: below the threshold
        self._probe('198.51.100.10', secrets)                      # protected network: never
        self._probe('203.0.113.72', secrets, ago=3 * 3600)         # outside the window
        self.assertEqual(self.b.auto_recon(), [])                  # off by default
        self.env.cfg.data['blocks']['auto_recon'] = True
        self.assertEqual(self.b.auto_recon(), ['203.0.113.70'])
        r = self.b.blocked('203.0.113.70')[0]
        self.assertEqual((r['source'], r['via'], r['created_by']), ('jt-waf-mgr/recon', 'system', 'system'))
        self.assertIn('guessed 6 secret', r['reason'])
        self.assertEqual(self.b.auto_recon(), [])                  # already blocked
        # a person ends it: the rule leaves this address alone for a week
        self.b.remove('admin1', block_id=r['id'], note='our own scanner')
        self.assertEqual(self.b.auto_recon(), [])
        # the hourly cap
        self.env.cfg.data['blocks']['auto_recon_per_hour'] = 1
        self._probe('203.0.113.73', secrets)
        self.assertEqual(self.b.auto_recon(), [])                  # one rule block already this hour
        acts = [r['action'] for r in self.app.db.q("SELECT action FROM audit WHERE action LIKE 'block.%' ORDER BY id")]
        self.assertEqual(acts.count('block.refused'), 1)           # the protected address, refused once only

    def test_render(self):
        t = blocks.render(['203.0.113.7', '2001:db8::/64'], '/etc/nginx/jt-waf-mgr/blocked-ips.conf')
        lines = [l for l in t.splitlines() if not l.startswith('#')]
        self.assertEqual(lines, ['deny 203.0.113.7;', 'deny 2001:db8::/64;'])


class ApplierTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='jtwaf-test-')
        self.addCleanup(shutil.rmtree, self.d, True)
        self.file = os.path.join(self.d, 'nginx', 'jt-waf-mgr', 'blocked-ips.conf')
        self.cfg = config.load(None, {'paths': {'nginx_conf': os.path.join(FIXTURE_SITE, 'nginx.conf'), 'nginx_bin': '/bin/true'},
                                      'managed': {'dir': os.path.join(self.d, 'managed'), 'spool': os.path.join(self.d, 'spool'),
                                                  'apply_state': os.path.join(self.d, 'state')},
                                      'blocks': {'file': self.file, 'protected': ['198.51.100.0/25']}})
        self.ap = Applier(self.cfg)
        self.ap.check_binary = lambda: None
        self.reloads = []
        self.ap.reload = lambda wait: self.reloads.append(wait) or 'reloaded (test)'
        self.ap.test_config = lambda: 'ok'

    def req(self, entries):
        import hashlib
        return {'action': 'blocks', 'entries': entries, 'sha256': hashlib.sha256('\n'.join(entries).encode()).hexdigest()}

    def test_write_test_reload(self):
        r = self.ap.blocks_write(self.ap.check_blocks(self.req(['203.0.113.7'])))
        self.assertEqual((r['result'], r['changed'], r['count']), ('ok', True, 1))
        self.assertIn('deny 203.0.113.7;', rd(self.file))
        self.assertEqual(self.reloads, [0])
        # the same list: no reload
        r = self.ap.blocks_write(self.ap.check_blocks(self.req(['203.0.113.7'])))
        self.assertFalse(r['changed'])
        self.assertEqual(len(self.reloads), 1)

    def test_failed_reload_is_not_taken_as_loaded(self):
        # the list is written and nginx -t passes, but the reload fails: the file goes back to what nginx runs, and
        # sending the same list again reloads (it is not "unchanged" just because a file once had that content)
        def bad_reload(wait):
            raise Fail('reload', 'reload failed: signal not sent')
        self.ap.reload = bad_reload
        with self.assertRaises(Fail):
            self.ap.blocks_write(self.ap.check_blocks(self.req(['203.0.113.7'])))
        self.assertFalse(os.path.exists(self.file))
        self.ap.reload = lambda wait: self.reloads.append(wait) or 'reloaded (test)'
        r = self.ap.blocks_write(self.ap.check_blocks(self.req(['203.0.113.7'])))
        self.assertTrue(r['changed'])
        self.assertEqual(self.reloads, [0])
        # a crash between writing and reloading: the file already has the list, nothing says nginx loaded it
        os.unlink(os.path.join(self.d, 'state', 'blocks-loaded.json'))
        r = self.ap.blocks_write(self.ap.check_blocks(self.req(['203.0.113.7'])))
        self.assertTrue(r['changed'])
        self.assertIn('not yet loaded', r['summary'])
        self.assertEqual(self.reloads, [0, 0])
        r = self.ap.blocks_write(self.ap.check_blocks(self.req(['203.0.113.7'])))
        self.assertFalse(r['changed'])
        self.assertEqual(self.reloads, [0, 0])

    def test_nginx_t_failure_restores(self):
        self.ap.blocks_write(self.ap.check_blocks(self.req(['203.0.113.7'])))
        before = rd(self.file)

        def bad():
            raise Fail('nginx_t', 'nginx -t failed')
        self.ap.test_config = bad
        with self.assertRaises(Fail):
            self.ap.blocks_write(self.ap.check_blocks(self.req(['203.0.113.7', '203.0.113.8'])))
        self.assertEqual(rd(self.file), before)

    def test_root_refuses_what_the_web_side_should_not_send(self):
        for entries in (['10.0.0.1'], ['192.168.77.1'], ['198.51.100.5'], ['203.0.0.0/16'], ['203.0.113.7; deny all'],
                        ['127.0.0.1'], 'not a list'):
            with self.assertRaises(Fail, msg=str(entries)):
                self.ap.check_blocks(self.req(entries) if isinstance(entries, list) else {'action': 'blocks', 'entries': entries})
        bad = self.req(['203.0.113.7'])
        bad['sha256'] = '0' * 64
        with self.assertRaises(Fail):
            self.ap.check_blocks(bad)
        with self.assertRaises(Fail):
            self.ap.check_blocks(self.req(['203.0.113.007']))     # not normalised

    def test_root_reads_the_protected_networks_set_in_the_web_interface(self):
        # a range added only in Settings (stored in the database) is refused by the root program too
        from jtwafmgr.db import Database
        from jtwafmgr import uisettings
        db = os.path.join(self.d, 'jt.db')
        self.cfg.data['paths']['db'] = db
        self.ap.check_blocks(self.req(['203.0.113.7']))                   # nothing stored yet: allowed
        d = Database(db)
        d.migrate()
        d.x("INSERT INTO settings(key, value, updated_by, updated_at) VALUES (?, ?, 'admin1', 0)",
            (uisettings.PREFIX + 'blocks.protected', json.dumps(['203.0.113.0/26'])))
        with self.assertRaises(Fail):
            self.ap.check_blocks(self.req(['203.0.113.7']))
        self.ap.check_blocks(self.req(['203.0.113.70']))                  # outside that range: still allowed
        d.x("UPDATE settings SET value='not json' WHERE key=?", (uisettings.PREFIX + 'blocks.protected',))
        with self.assertRaises(Fail):                                     # unreadable: fail closed
            self.ap.check_blocks(self.req(['203.0.113.70']))

    def test_link_refused(self):
        os.makedirs(os.path.dirname(self.file))
        os.symlink('/etc/hostname', self.file)
        with self.assertRaises(Fail):
            self.ap.blocks_write(self.ap.check_blocks(self.req(['203.0.113.7'])))


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = env_with_blocks()
        cls.app = App(cls.env.cfg)
        a = cls.app.auth
        a.create_user('viewer1', 'viewer', password=PW)
        a.create_user('admin1', 'admin', password=PW)
        cls.admin_secret, _ = a.totp_setup('admin1')
        a.totp_enable('admin1', auth.totp_code(cls.admin_secret, int(time.time() // 30)))
        _, cls.tok_w = a.create_token('mail2', ['blocks:write', 'blocks:read'], ['127.0.0.0/8'], None, 'admin1')
        _, cls.tok_w2 = a.create_token('mail1', ['blocks:write'], ['127.0.0.0/8'], None, 'admin1')
        _, cls.tok_r = a.create_token('reader', ['events:read'], ['127.0.0.0/8'], None, 'admin1')
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.app.stop()
        cls.env.cleanup()

    def tok(self, method, path, secret, body=None):
        return Client(self.port).req(method, path, body, headers={'Authorization': 'Bearer ' + secret})

    def test_token_flow(self):
        st, obj, _ = self.tok('POST', '/api/v1/blocks', self.tok_w,
                              {'ip': '203.0.113.17', 'ttl': 3600, 'source': 'mail2/zimbra-webmail', 'reason': '4 failed logins'})
        self.assertEqual(st, 201, obj)
        self.assertEqual(obj['ip'], '203.0.113.17')
        st, obj, _ = self.tok('POST', '/api/v1/blocks', self.tok_w, {'ip': '192.168.77.50', 'ttl': 3600, 'source': 's', 'reason': 'r'})
        self.assertEqual((st, obj['error']['code'] if isinstance(obj.get('error'), dict) else obj.get('code')), (422, 'not_public'))
        # without the scope
        self.assertEqual(self.tok('POST', '/api/v1/blocks', self.tok_r, {'ip': '203.0.113.18', 'source': 's', 'reason': 'r'})[0], 403)
        self.assertEqual(self.tok('GET', '/api/v1/blocks', self.tok_w2)[0], 403)       # write only, no read
        st, obj, _ = self.tok('GET', '/api/v1/blocks', self.tok_w)
        self.assertEqual(st, 200)
        self.assertIn('203.0.113.17', [i['ip'] for i in obj['items']])
        self.assertFalse(obj['included'])
        # another token cannot end it
        self.assertEqual(self.tok('DELETE', '/api/v1/blocks/203.0.113.17', self.tok_w2)[0], 404)
        st, obj, _ = self.tok('DELETE', '/api/v1/blocks/203.0.113.17?source=mail2/zimbra-webmail', self.tok_w)
        self.assertEqual((st, obj['removed']), (200, 1))
        # tokens never reach the person's removal
        self.assertEqual(self.tok('POST', '/api/v1/blocks/1/remove', self.tok_w, {'note': 'x'})[0], 403)

    def test_people(self):
        c = Client(self.port)
        c.login('viewer1')
        self.assertEqual(c.req('GET', '/api/v1/blocks')[0], 200)
        self.assertEqual(c.req('POST', '/api/v1/blocks', {'ip': '203.0.113.30', 'reason': 'r'})[0], 403)
        self.app.db.x("UPDATE users SET totp_last_step=0 WHERE username='admin1'")
        a = Client(self.port)
        st, _ = a.login('admin1', totp=auth.totp_code(self.admin_secret, int(time.time() // 30)))
        self.assertEqual(st, 200)
        st, obj, _ = a.req('POST', '/api/v1/blocks', {'ip': '203.0.113.0/24', 'ttl': 86400, 'reason': 'scanner range'})
        self.assertEqual(st, 201, obj)
        bid = obj['id']
        self.assertEqual(a.req('POST', '/api/v1/blocks/%d/remove' % bid, {'note': ''})[0], 422)
        st, obj, _ = a.req('POST', '/api/v1/blocks/%d/remove' % bid, {'note': 'done'})
        self.assertEqual((st, obj['removed']), (200, 1))
        self.assertEqual(a.req('DELETE', '/api/v1/blocks/203.0.113.30')[0], 400)


if __name__ == '__main__':
    unittest.main()
