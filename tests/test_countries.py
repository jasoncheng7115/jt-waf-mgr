"""Per-site country blocks (countries.py, rulegen kind "country", apply.py countries action). Synthetic data only:
the documentation ranges stand in for countries (TW 198.51.100.0/24, US 203.0.113.0/24, JP 192.0.2.0/24)."""
import hashlib
import ipaddress
import json
import os
import time
import unittest

from jtwafmgr import auth, config, countries, rulegen
from jtwafmgr.app import App
from jtwafmgr.apply import Applier, Fail
from jtwafmgr.changes import ChangeError
from tests.helpers import FIXTURE_SITE, TempEnv, rd, wr

# per registry: (cc, type, start, value, status)
FAKE = {
    'apnic': [('TW', 'ipv4', '198.51.100.0', 256, 'allocated'), ('JP', 'ipv4', '192.0.2.0', 128, 'assigned'),
              ('JP', 'ipv4', '192.0.2.128', 128, 'allocated'), ('TW', 'ipv6', '2001:db8:1::', 48, 'allocated'),
              ('', 'ipv4', '198.18.0.0', 256, 'available')],
    'arin': [('US', 'ipv4', '203.0.113.0', 256, 'allocated'), ('US', 'ipv6', '2001:db8:2::', 48, 'assigned')],
    'ripencc': [('DE', 'ipv4', '198.18.1.0', 256, 'allocated'), ('ZZ', 'ipv4', '198.18.2.0', 256, 'reserved')],
    'lacnic': [('BR', 'ipv4', '198.18.3.0', 256, 'allocated')],
    'afrinic': [('ZA', 'ipv4', '198.18.4.0', 256, 'allocated')],
}


def delegated(name, rows, summary_extra=0):
    v4 = sum(1 for r in rows if r[1] == 'ipv4')
    v6 = sum(1 for r in rows if r[1] == 'ipv6')
    out = ['# synthetic test data', '2.3|%s|20261113|%d|19700101|20261113|+0000' % (name, v4 + v6),
           '%s|*|asn|*|0|summary' % name, '%s|*|ipv4|*|%d|summary' % (name, v4 + summary_extra),
           '%s|*|ipv6|*|%d|summary' % (name, v6)]
    for cc, t, start, value, status in rows:
        out.append('%s|%s|%s|%s|%d|20200101|%s' % (name, cc, t, start, value, status))
    return ('\n'.join(out) + '\n').encode()


def fetcher(overrides=None):
    files = {}
    for name, url in countries.REGISTRIES:
        body = (overrides or {}).get(name) or delegated(name, FAKE[name])
        files[url] = body
        files[url + '.md5'] = ('MD5 (x) = %s\n' % hashlib.md5(body).hexdigest()).encode()
    return lambda url, limit, timeout=0: files[url]


def stage(d):
    os.makedirs(d, exist_ok=True)
    st = countries.update({'countries': {'dir': d, 'update_hours': 24}}, force=True, fetch=fetcher(), log=lambda m: None)
    assert st['ok'], st
    return st


class TestData(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.d = os.path.join(self.env.dir, 'countries')

    def test_parse_counts_and_statuses(self):
        by_cc, counts = countries.parse(delegated('apnic', FAKE['apnic']).decode(), 'apnic')
        self.assertEqual(counts, {'ipv4': 4, 'ipv6': 1})
        self.assertEqual(sorted(by_cc), ['JP', 'TW'])                  # the available block has no country
        self.assertEqual([str(n) for n in by_cc['JP']], ['192.0.2.0/25', '192.0.2.128/25'])

    def test_parse_refuses_a_cut_or_odd_file(self):
        with self.assertRaises(countries.DataError):                   # one record fewer than the summary says
            countries.parse(delegated('apnic', FAKE['apnic'], summary_extra=1).decode(), 'apnic')
        with self.assertRaises(countries.DataError):                   # another registry's file
            countries.parse(delegated('arin', FAKE['arin']).decode(), 'apnic')
        bad = delegated('lacnic', [('BR', 'ipv4', '198.18.3.999', 256, 'allocated')]).decode()
        with self.assertRaises(countries.DataError):
            countries.parse(bad, 'lacnic')

    def test_update_stages_all_or_nothing(self):
        st = stage(self.d)
        self.assertEqual(st['countries'], 6)                           # TW JP US DE BR ZA (ZZ never)
        man = countries.read_manifest(self.d)
        self.assertEqual(man['countries']['TW']['v6'], 1)
        self.assertEqual(rd(os.path.join(self.d, 'data', 'JP.txt')), '192.0.2.0/24\n')    # collapsed
        sha = countries.manifest_sha(self.d)
        # one registry's checksum does not match: everything stays as it was
        bad = fetcher()
        url = dict(countries.REGISTRIES)['ripencc']

        def f(u, limit, timeout=0):
            return b'tampered' if u == url else bad(u, limit)
        st = countries.update({'countries': {'dir': self.d, 'update_hours': 24}}, force=True, fetch=f, log=lambda m: None)
        self.assertFalse(st['ok'])
        self.assertIn('MD5', st['registries']['ripencc']['error'])
        self.assertEqual(countries.manifest_sha(self.d), sha)
        # a registry that suddenly shrinks (a half-empty file with a matching checksum) is refused too
        big = {'arin': delegated('arin', FAKE['arin'] + [('US', 'ipv4', '198.18.%d.0' % i, 256, 'allocated') for i in (5, 6, 7, 8)])}
        self.assertTrue(countries.update({'countries': {'dir': self.d, 'update_hours': 24}}, force=True, fetch=fetcher(big),
                                         log=lambda m: None)['ok'])
        st = countries.update({'countries': {'dir': self.d, 'update_hours': 24}}, force=True, fetch=fetcher(),
                              log=lambda m: None)
        self.assertFalse(st['ok'])
        self.assertIn('fell', st['registries']['arin']['error'])

    def test_update_only_while_on(self):
        st = countries.update({'countries': {'dir': self.d, 'update_hours': 24}}, fetch=fetcher(), log=lambda m: None)
        self.assertIsNone(st['ok'])
        self.assertIsNone(countries.read_manifest(self.d))
        wr(os.path.join(self.d, countries.ENABLED_FILE), 'x')
        st = countries.update({'countries': {'dir': self.d, 'update_hours': 24}}, fetch=fetcher(), log=lambda m: None)
        self.assertTrue(st['ok'])
        st = countries.update({'countries': {'dir': self.d, 'update_hours': 24}}, fetch=fetcher(), log=lambda m: None)
        self.assertEqual(st.get('note'), 'fresh')

    def test_sets_and_lookup(self):
        stage(self.d)
        self.assertEqual(countries.set_name(['tw', 'JP', 'TW']), 'JP-TW')
        with self.assertRaises(countries.DataError):
            countries.set_name(['TWN'])
        self.assertEqual(countries.build_set(self.d, ['TW', 'JP']), '192.0.2.0/24\n198.51.100.0/24\n2001:db8:1::/48\n')
        lk = countries.Lookup(self.d)
        self.assertEqual((lk.country('198.51.100.9'), lk.country('203.0.113.1'), lk.country('2001:db8:2::5'),
                          lk.country('10.0.0.1')), ('TW', 'US', 'US', None))
        self.assertEqual(lk.sample('US'), '203.0.113.1')


class TestRule(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(blocks={'protected': ['198.51.100.128/25']})
        self.addCleanup(self.env.cleanup)
        self.cfg = self.env.cfg

    def test_allow_and_deny(self):
        spec = {'host': {'mode': 'exact', 'value': 'App.Example.com'}, 'mode': 'allow', 'countries': ['tw', 'jp']}
        norm, text, pl = rulegen.build('country', spec, 10300, self.cfg)
        self.assertEqual((norm['countries'], norm['host']['value'], pl), (['JP', 'TW'], 'app.example.com', 'before'))
        path = os.path.join(self.cfg['countries']['rules_dir'], 'JP-TW.data')
        self.assertIn('"!@ipMatchFromFile %s"' % path, text)
        self.assertIn("msg:'jt country block: only JP TW'", text)
        self.assertIn('198.51.100.128/25', text)                     # the protected list is never refused
        self.assertIn('10.0.0.0/8', text)                            # nor the internal networks
        self.assertEqual(rulegen.check_raw_text(text, cfg=self.cfg), [10300])
        _, deny, _ = rulegen.build('country', dict(spec, mode='deny'), 10301, self.cfg)
        self.assertIn('"@ipMatchFromFile %s"' % path, deny)
        self.assertEqual(rulegen.direction('add', 'country'), 'tighten')
        self.assertEqual(rulegen.direction('delete', 'country'), 'loosen')

    def test_shown_with_the_confident_blocks(self):
        from jtwafmgr.modsecconf import ModsecConfig, parse_rules_text
        _, text, _ = rulegen.build('country', {'host': {'mode': 'exact', 'value': 'a.example.com'}, 'mode': 'deny',
                                               'countries': ['US']}, 10300, self.cfg)
        rules = []
        parse_rules_text(text, '/etc/nginx/modsec/jt-waf-mgr/before-crs.conf', rules, [], [], [])
        mc = ModsecConfig.__new__(ModsecConfig)
        mc.cfg = self.cfg
        self.assertEqual(mc.category_of(rules[0]), 'confident_block')

    def test_refused_specs(self):
        for spec, field in (({'host': {'mode': 'any'}, 'mode': 'allow', 'countries': ['TW']}, 'host'),
                            ({'host': {'mode': 'exact', 'value': 'a.example.com'}, 'mode': 'maybe', 'countries': ['TW']}, 'mode'),
                            ({'host': {'mode': 'exact', 'value': 'a.example.com'}, 'mode': 'allow', 'countries': []}, 'countries'),
                            ({'host': {'mode': 'exact', 'value': 'a.example.com'}, 'mode': 'allow', 'countries': ['T1']}, 'countries')):
            with self.assertRaises(rulegen.SpecError) as cm:
                rulegen.build('country', spec, 10300, self.cfg)
            self.assertEqual(cm.exception.field, field)

    def test_list_files_only_from_the_country_directory(self):
        ok = 'SecRule REMOTE_ADDR "@ipMatchFromFile %s/TW.data" "id:10300,phase:1,deny"' % self.cfg['countries']['rules_dir']
        self.assertEqual(rulegen.check_raw_text(ok, cfg=self.cfg), [10300])
        for bad in ('%s/../x.data' % self.cfg['countries']['rules_dir'], '%s/tw.data' % self.cfg['countries']['rules_dir'],
                    '/tmp/TW.data'):
            with self.assertRaises(rulegen.SpecError):
                rulegen.check_raw_text('SecRule REMOTE_ADDR "@ipMatchFromFile %s" "id:10300,phase:1,deny"' % bad, cfg=self.cfg)


class TestRoot(unittest.TestCase):
    """The root program's countries action."""

    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        d = self.env.dir
        self.data = os.path.join(d, 'countries')
        self.rd = os.path.join(d, 'lists')
        stage(self.data)
        self.cfg = config.load(None, {'paths': {'nginx_conf': os.path.join(FIXTURE_SITE, 'nginx.conf'), 'nginx_bin': '/bin/true'},
                                      'managed': {'dir': os.path.join(d, 'managed'), 'spool': os.path.join(d, 'spool'),
                                                  'apply_state': os.path.join(d, 'state')},
                                      'countries': {'dir': self.data, 'rules_dir': self.rd}})
        self.ap = Applier(self.cfg)
        self.ap.check_binary = lambda: None
        self.reloads = []
        self.ap.reload = lambda wait: self.reloads.append(wait) or 'reloaded (test)'
        self.ap.test_config = lambda: 'ok'

    def req(self, *sets):
        sha = countries.manifest_sha(self.data)
        s = {countries.set_name(x): sorted(x) for x in sets}
        return {'action': 'countries', 'sets': s, 'manifest_sha256': sha,
                'want': hashlib.sha256(json.dumps([sha, sorted(s)]).encode()).hexdigest()}

    def test_write_reload_and_unchanged(self):
        r = self.ap.countries_write(self.ap.check_countries(self.req(['TW'], ['JP', 'TW'])))
        self.assertEqual((r['result'], r['changed'], r['sets']), ('ok', True, ['JP-TW', 'TW']))
        self.assertEqual(rd(os.path.join(self.rd, 'TW.data')), '198.51.100.0/24\n2001:db8:1::/48\n')
        self.assertEqual(self.reloads, [0])
        r = self.ap.countries_write(self.ap.check_countries(self.req(['TW'], ['JP', 'TW'])))
        self.assertFalse(r['changed'])
        self.assertEqual(self.reloads, [0])
        # a set nobody asks for any more is removed
        r = self.ap.countries_write(self.ap.check_countries(self.req(['TW'])))
        self.assertTrue(r['changed'])
        self.assertEqual(sorted(os.listdir(self.rd)), ['TW.data'])

    def test_a_list_the_managed_rules_use_is_kept(self):
        mdir = self.cfg['managed']['dir']
        os.makedirs(mdir)
        wr(os.path.join(mdir, 'before-crs.conf'), '# x\nSecRule REMOTE_ADDR "!@ipMatchFromFile %s/US.data" "id:10300"\n' % self.rd)
        r = self.ap.countries_write(self.ap.check_countries(self.req(['TW'])))
        self.assertEqual(r['sets'], ['TW', 'US'])
        self.assertTrue(os.path.exists(os.path.join(self.rd, 'US.data')))

    def test_failures_put_everything_back(self):
        self.ap.countries_write(self.ap.check_countries(self.req(['TW'])))
        before = rd(os.path.join(self.rd, 'TW.data'))

        def bad():
            raise Fail('nginx_t', 'nginx -t failed')
        self.ap.test_config = bad
        with self.assertRaises(Fail):
            self.ap.countries_write(self.ap.check_countries(self.req(['US'])))
        self.assertEqual(sorted(os.listdir(self.rd)), ['TW.data'])
        self.assertEqual(rd(os.path.join(self.rd, 'TW.data')), before)
        self.ap.test_config = lambda: 'ok'

        def bad_reload(wait):
            raise Fail('reload', 'reload failed')
        self.ap.reload = bad_reload
        with self.assertRaises(Fail):
            self.ap.countries_write(self.ap.check_countries(self.req(['US'])))
        self.assertEqual(sorted(os.listdir(self.rd)), ['TW.data'])

    def test_refusals(self):
        with self.assertRaises(Fail):
            self.ap.check_countries(dict(self.req(['TW']), sets={'TW-JP': ['TW', 'JP']}))     # not sorted
        with self.assertRaises(Fail):
            self.ap.check_countries(dict(self.req(['TW']), sets={'../x': ['TW']}))
        stale = self.req(['TW'])
        stale['manifest_sha256'] = '0' * 64
        with self.assertRaises(Fail) as cm:
            self.ap.countries_write(self.ap.check_countries(stale))
        self.assertIn('changed', cm.exception.summary)
        # a list line that is not a network: refused, nothing written
        wr(os.path.join(self.data, 'data', 'US.txt'), '203.0.113.0/24\nSecRule x\n')
        with self.assertRaises(Fail):
            self.ap.countries_write(self.ap.check_countries(self.req(['US'])))
        self.assertFalse(os.path.exists(os.path.join(self.rd, 'US.data')))
        # the list directory may not be a link
        import shutil
        shutil.rmtree(self.rd, ignore_errors=True)
        os.symlink('/tmp', self.rd)
        with self.assertRaises(Fail):
            self.ap.countries_write(self.ap.check_countries(self.req(['TW'])))


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        from tests.test_p2 import TestWorkflow as P2
        self.p2 = P2('adopt')
        P2.setUp(self.p2)
        self.addCleanup(self.p2.tearDown)
        self.app, self.wf = self.p2.app, self.p2.wf
        cd = os.path.join(self.p2.env.dir, 'countries')
        self.app.cfg.data['countries'].update(dir=cd, rules_dir=os.path.join(self.p2.env.dir, 'lists'))
        self.p2.adopt()
        self.spec = {'host': {'mode': 'exact', 'value': 'app.example.com'}, 'mode': 'allow', 'countries': ['TW']}

    def test_needs_the_feature_and_its_data(self):
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose('add', 'country', self.spec, 'only Taiwan', 'appr')
        self.assertEqual(cm.exception.code, 'countries_off')
        self.app.cfg.data['countries']['enabled'] = True
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose('add', 'country', self.spec, 'only Taiwan', 'appr')
        self.assertEqual(cm.exception.code, 'countries_no_data')
        stage(self.app.cfg['countries']['dir'])
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose('add', 'country', dict(self.spec, countries=['FR']), 'x', 'appr')
        self.assertEqual(cm.exception.details.get('reason'), 'unknown_country')

    def test_proposal_tests_sets_and_sync(self):
        self.app.cfg.data['countries']['enabled'] = True
        stage(self.app.cfg['countries']['dir'])
        cid = self.wf.propose('add', 'country', self.spec, 'only Taiwan', 'appr')
        r = self.wf.get(cid)
        self.assertEqual((r['rule_id'], r['direction']), (10300, 'tighten'))
        tests = json.loads(r['tests'])
        self.assertEqual([(t.get('src_ip'), t['source'], t['expect']) for t in tests],
                         [('198.51.100.1', 'external', 200), ('203.0.113.1', 'external', 403), (None, 'internal', 200)])
        # the waiting rule's list is queued for the root program before the rule is approved
        self.assertEqual(self.app.countries.desired_sets(), ['TW'])
        rid = self.app.countries.sync()
        req = json.loads(rd(os.path.join(self.p2.spool, rid + '.req')))
        self.assertEqual((req['action'], req['sets']), ('countries', {'TW': ['TW']}))
        self.assertIsNone(self.app.countries.sync())                  # one request at a time
        res = {'request_id': rid, 'action': 'countries', 'result': 'ok', 'sets': ['TW'], 'want': req['want'], 'summary': 't'}
        wr(os.path.join(self.p2.spool, rid + '.result'), json.dumps(res))
        os.unlink(os.path.join(self.p2.spool, rid + '.req'))
        self.wf.collect_results()
        st = self.app.countries.status()
        self.assertTrue(st['applied']['ok'])
        self.assertFalse(st['pending'])
        self.assertIsNone(self.app.countries.sync())                  # in sync
        self.assertTrue(os.path.exists(os.path.join(self.app.cfg['countries']['dir'], countries.ENABLED_FILE)))
        # a failed write raises a critical alert
        rid = self.app.countries.sync(force=True)
        wr(os.path.join(self.p2.spool, rid + '.result'), json.dumps(dict(res, request_id=rid, result='failed', summary='nginx -t')))
        os.unlink(os.path.join(self.p2.spool, rid + '.req'))
        self.wf.collect_results()
        self.assertTrue(self.app.db.one("SELECT 1 FROM alerts WHERE dedup='countries_apply_failed'"))

    def test_checks_give_the_sandbox_the_resulting_rules(self):
        self.app.cfg.data['countries']['enabled'] = True
        stage(self.app.cfg['countries']['dir'])
        seen = {}

        class Stub:
            def available(self):
                return True

            def run_change(self, r, files, tests, managed, samples=None, items=None):
                seen['items'] = items
                return {'ok': True, 'cases': 0, 'failed': 0, 'results': []}
        self.wf.sandbox = Stub()
        cid = self.wf.propose('add', 'country', self.spec, 'only Taiwan', 'appr')
        self.wf.run_checks(cid)
        got = [json.loads(i['spec']) if isinstance(i['spec'], str) else i['spec']
               for i in seen['items'] if i['kind'] == 'country' and not i.get('deleted')]
        self.assertEqual([(g['host']['value'], g['countries']) for g in got], [('app.example.com', ['TW'])])

    def test_changing_a_limit_and_the_sites_page(self):
        from jtwafmgr.web import api
        self.app.cfg.data['countries']['enabled'] = True
        stage(self.app.cfg['countries']['dir'])
        two = dict(self.spec, countries=['JP', 'TW'])
        cid = self.wf.propose('add', 'country', two, 'Taiwan and Japan', 'op')
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval', self.wf.get(cid)['checks'])
        servers = [{'server_names': ['app.example.com', 'www.example.com']}, {'server_names': ['_']},
                   {'server_names': ['other.example.com']}]
        api._vhost_countries(self.app, servers)
        self.assertEqual(servers[0]['countries'], [])
        self.assertEqual([(c['change_id'], c['op'], c['countries']) for c in servers[0]['country_changes']],
                         [(cid, 'add', ['JP', 'TW'])])
        self.assertEqual((servers[1]['country_changes'], servers[2]['country_changes']), ([], []))
        self.wf.approve(cid, self.p2.user('appr'))
        self.p2.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')
        api._vhost_countries(self.app, servers)
        item = self.wf.managed.item_by_rule(self.wf.get(cid)['rule_id'])
        self.assertEqual([(c['item_id'], c['mode'], c['countries'], c['enabled']) for c in servers[0]['countries']],
                         [(item['id'], 'allow', ['JP', 'TW'], True)])
        self.assertEqual((servers[0]['country_changes'], servers[2]['countries']), ([], []))

        def direction(spec):
            c = self.wf.propose('modify', 'country', spec, 'change the limit', 'op', item_id=item['id'])
            d = self.wf.get(c)['direction']
            self.wf.cancel(c, self.p2.user('op'))
            return d
        self.assertEqual(direction(dict(two, countries=['TW'])), 'tighten')                 # fewer allowed
        self.assertEqual(direction(dict(two, note='same countries')), 'tighten')
        self.assertEqual(direction(dict(two, countries=['JP', 'TW', 'US'])), 'loosen')      # one more allowed
        self.assertEqual(direction(dict(two, mode='deny')), 'loosen')                       # turned around
        self.assertEqual(direction(dict(two, host={'mode': 'exact', 'value': 'other.example.com'})), 'loosen')
        # a waiting disable shows on the site whose rule it changes
        c = self.wf.propose('disable', None, None, 'off for a test', 'op', item_id=item['id'])
        api._vhost_countries(self.app, servers)
        self.assertEqual([(x['change_id'], x['op']) for x in servers[0]['country_changes']], [(c, 'disable')])

    def _applied_rule(self, countries=('JP', 'TW')):
        self.app.cfg.data['countries']['enabled'] = True
        stage(self.app.cfg['countries']['dir'])
        cid = self.wf.propose('add', 'country', dict(self.spec, countries=list(countries)), 'a limit', 'op')
        self.wf.run_checks(cid)
        self.wf.approve(cid, self.p2.user('appr'))
        self.p2.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')
        return self.wf.managed.item_by_rule(self.wf.get(cid)['rule_id'])

    def test_a_changed_limit_is_checked_as_changed_and_never_applied_alone(self):
        item = self._applied_rule()
        self.wf.set_setting('apply.auto_tighten', True, 'boss')
        seen = {}

        class Stub:
            def available(self):
                return True

            def run_change(self, r, files, tests, managed, samples=None, items=None):
                seen['items'], seen['tests'] = items, tests
                return {'ok': True, 'cases': 0, 'failed': 0, 'results': []}
        self.wf.sandbox = Stub()
        cid = self.wf.propose('modify', 'country', dict(self.spec, countries=['TW']), 'Taiwan only now', 'op', item_id=item['id'])
        r = self.wf.get(cid)
        self.assertEqual(r['direction'], 'tighten')
        # the change carries its own country tests, the sandbox sees the new limit (not the old one), the list it
        # needs is queued for the root program, and a tightening country change still waits for a person
        self.assertEqual([(t.get('src_ip'), t['expect']) for t in json.loads(r['tests'])],
                         [('198.51.100.1', 200), ('203.0.113.1', 403), (None, 200)])
        self.assertIn('TW', self.app.countries.desired_sets())
        self.wf.run_checks(cid)
        got = [json.loads(i['spec']) if isinstance(i['spec'], str) else i['spec']
               for i in seen['items'] if i['kind'] == 'country' and not i.get('deleted')]
        self.assertEqual([g['countries'] for g in got], [['TW']])
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval')
        self.assertIn('requests', json.loads(self.wf.get(cid)['checks'])['evidence'])     # its impact, counted

    def test_one_more_country_is_a_loosening(self):
        item = self._applied_rule(['TW'])
        self.wf.set_setting('approval.single_admin_mode', True, 'boss')
        cid = self.wf.propose('modify', 'country', dict(self.spec, countries=['JP', 'TW']), 'Japan too', 'boss',
                              item_id=item['id'])
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['direction'], 'loosen')
        with self.assertRaises(ChangeError):                      # one's own loosening: a fresh code and a reason
            self.wf.approve(cid, self.p2.user('boss'), '', 'Japan too, ten chars')
        for op in ('disable', 'delete'):
            c = self.wf.propose(op, None, None, 'test %s' % op, 'op', item_id=item['id'])
            self.assertEqual(self.wf.get(c)['direction'], 'loosen')
            self.wf.cancel(c, self.p2.user('op'))

    def test_preview_gives_the_direction_the_change_will_get(self):
        from jtwafmgr.web import api
        item = self._applied_rule()

        class Req:
            def __init__(self, body):
                self._b, self.user, self.client_ip = body, {'username': 'op', 'role': 'operator'}, '192.0.2.5'

            def body(self):
                return self._b

        def preview(body):
            resp = api.change_preview(self.app, Req(body))
            return json.loads(resp.body)
        self.assertEqual(preview({'kind': 'country', 'spec': self.spec})['direction'], 'tighten')
        self.assertEqual(preview({'kind': 'country', 'spec': dict(self.spec, countries=['TW']), 'item_id': item['id']})['direction'], 'tighten')
        self.assertEqual(preview({'kind': 'country', 'spec': dict(self.spec, countries=['JP', 'TW', 'US']), 'item_id': item['id']})['direction'], 'loosen')
        blocks = [i for i in self.wf.managed.items() if i['kind'] == 'confident_block']
        if blocks:                                # any other changed rule loosens, as the change itself will
            b = blocks[0]
            self.assertEqual(preview({'kind': 'confident_block', 'spec': json.loads(b['spec']), 'item_id': b['id']})['direction'], 'loosen')

    def test_sites_page_names_and_states(self):
        from jtwafmgr.web import api
        item = self._applied_rule()
        wild = self.wf.propose('add', 'country', {'host': {'mode': 'exact', 'value': '*.example.org'}, 'mode': 'deny',
                                                  'countries': ['US']}, 'not from the US', 'op')
        bundle = self.wf.propose_bundle([{'op': 'add', 'kind': 'country', 'spec': {
            'host': {'mode': 'exact', 'value': 'shop.example.net'}, 'mode': 'allow', 'countries': ['TW']}}], 'shop', 'op')
        servers = [{'server_names': ['app.example.com']}, {'server_names': ['a.example.org', 'b.example.org']},
                   {'server_names': ['shop.example.net']}, {'server_names': ['~^(?<x>.+)\\.example\\.com$']},
                   {'server_names': []}]
        api._vhost_countries(self.app, servers)
        self.assertEqual([c['item_id'] for c in servers[0]['countries']], [item['id']])
        self.assertEqual([(c['change_id'], c['mode']) for c in servers[1]['country_changes']], [(wild, 'deny')])
        self.assertEqual([c['change_id'] for c in servers[2]['country_changes']], [bundle])
        self.assertEqual((servers[3]['countries'], servers[4]['countries']), ([], []))      # regex names, none
        # a cancelled change and a deleted rule are gone from the page
        self.wf.cancel(wild, self.p2.user('op'))
        c = self.wf.propose('delete', None, None, 'no limit any more', 'op', item_id=item['id'])
        self.wf.run_checks(c)
        self.wf.approve(c, self.p2.user('appr'), '', 'no limit any more')
        self.p2.fake_apply()
        api._vhost_countries(self.app, servers)
        self.assertEqual((servers[0]['countries'], servers[0]['country_changes'], servers[1]['country_changes']), ([], [], []))

    def test_crs_comparison_requests_come_from_allowed_countries(self):
        self._applied_rule(['TW'])
        self.wf.equivalence_requests = lambda limit=400: [
            {'host': 'app.example.com', 'method': 'GET', 'path': '/', 'source': 'external'},
            {'host': 'app.example.com', 'method': 'GET', 'path': '/', 'source': 'internal'},
            {'host': 'other.example.com', 'method': 'GET', 'path': '/', 'source': 'external'}]
        from jtwafmgr.sandbox import Sandbox
        self.wf.sandbox = Sandbox(self.app.cfg, self.app.site)
        self.assertEqual([r.get('src_ip') for r in self.wf._crs_requests()], ['198.51.100.1', None, None])

    def test_country_sites_page(self):
        from jtwafmgr.web import api
        item = self._applied_rule()                      # app.example.com: TW and JP
        rid = item['rule_id']
        intra = self.wf.propose('add', 'country', {'host': {'mode': 'exact', 'value': 'intranet.example.com'}, 'mode': 'allow',
                                                   'countries': ['TW']}, 'intranet', 'op')
        self.wf.run_checks(intra)
        self.wf.approve(intra, self.p2.user('appr'))
        self.p2.fake_apply()
        gone = self.wf.propose('add', 'country', {'host': {'mode': 'exact', 'value': 'gone.example.net'}, 'mode': 'deny',
                                                  'countries': ['US']}, 'a site that is not there', 'op')
        now = time.time()
        for i, ip in enumerate(('203.0.113.7', '203.0.113.7', '192.0.2.9')):
            cur = self.app.db.x("INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, outcome, "
                                "decided_by, rule_ids, local_rule_ids, families, message, matches) VALUES ('n', ?, ?, "
                                "'app.example.com', 'GET', '/', '', ?, 'external', 'blocked', 'confident', ?, '', '', '', '[]')",
                                ('cs%d' % i, now - 60, ip, ',%d,' % rid))
            self.app.db.x("INSERT INTO event_rules(event_id, rule_id, ts, outcome) VALUES (?, ?, ?, 'blocked')",
                          (cur.lastrowid, rid, now - 60))

        class Req:
            query, params, user, client_ip = {}, {}, {'username': 'v', 'role': 'viewer'}, '192.0.2.5'
        out = json.loads(api.country_sites(self.app, Req()).body)
        sites = {x['host']: x for x in out['sites']}
        app_site = sites['app.example.com']
        self.assertEqual([(c['mode'], c['countries']) for c in app_site['countries']], [('allow', ['JP', 'TW'])])
        self.assertEqual((app_site['recent']['refused'], app_site['recent']['sources']), (3, 2))
        self.assertEqual({c['country']: c['requests'] for c in app_site['recent']['countries']}, {'US': 2, 'JP': 1})
        self.assertTrue(app_site['bypass'])                                     # /remote.php/dav skips the WAF
        # a server block with two names: the rule names one, the other is open
        self.assertEqual(sites['intranet.example.com']['uncovered'], ['intra.example.com'])
        self.assertTrue(sites['static.example.com']['waf_off'])
        self.assertEqual(sites['static.example.com']['countries'], [])
        self.assertEqual([c['change_id'] for c in out['unmatched_changes']], [gone])
        self.assertEqual(out['unmatched_rules'], [])

    def test_modify_direction_rules(self):
        d = rulegen.country_modify_direction
        h = {'mode': 'exact', 'value': 'a.example.com'}
        self.assertEqual(d({'host': h, 'mode': 'allow', 'countries': ['JP', 'TW']}, {'host': h, 'mode': 'allow', 'countries': ['TW']}), 'tighten')
        self.assertEqual(d({'host': h, 'mode': 'allow', 'countries': ['TW']}, {'host': h, 'mode': 'allow', 'countries': []}), 'loosen')
        self.assertEqual(d({'host': h, 'mode': 'deny', 'countries': ['CN']}, {'host': h, 'mode': 'deny', 'countries': ['CN', 'RU']}), 'tighten')
        self.assertEqual(d({'host': h, 'mode': 'deny', 'countries': ['CN', 'RU']}, {'host': h, 'mode': 'deny', 'countries': ['CN']}), 'loosen')
        self.assertEqual(d({'host': h, 'mode': 'allow', 'countries': ['TW']},
                           {'host': {'mode': 'exact', 'value': 'A.example.com'}, 'mode': 'allow', 'countries': ['TW']}), 'tighten')
        self.assertEqual(d({}, {'host': h, 'mode': 'allow', 'countries': ['TW']}), 'loosen')

    def test_impact_from_the_access_logs(self):
        self.app.cfg.data['countries']['enabled'] = True
        stage(self.app.cfg['countries']['dir'])
        log = os.path.join(self.p2.env.dir, 'app.example.com.access.log')
        lines = []
        for ip, status in (('198.51.100.7', 200), ('203.0.113.9', 200), ('203.0.113.9', 404), ('192.0.2.5', 200),
                           ('192.168.77.3', 200)):
            lines.append('%s - - [13/Oct/2026:10:00:00 +0800] "GET /x HTTP/1.1" %d 1 "-" "Mozilla/5.0"' % (ip, status))
        wr(log, '\n'.join(lines) + '\n')
        ev = self.wf.evidence.country_impact(dict(self.spec, host={'mode': 'exact', 'value': 'app.example.com'}))
        self.assertEqual((ev['requests'], ev['refused'], ev['refused_sources'], ev['refused_success']), (5, 3, 2, 2))
        self.assertEqual(ev['recent'], {'requests': 0, 'refused': 0, 'refused_success': 0})      # all from a month ago
        wr(log, '203.0.113.9 - - [%s] "GET /x HTTP/1.1" 200 1 "-" "M"\n' % time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime()), 'a')
        ev = self.wf.evidence.country_impact(dict(self.spec, host={'mode': 'exact', 'value': 'app.example.com'}))
        self.assertEqual(ev['recent'], {'requests': 1, 'refused': 1, 'refused_success': 1})
        self.assertEqual({c['country'] for c in ev['countries']}, {'US', 'JP'})
        self.assertTrue(ev['ok'])

    def test_config_monitor_counts_the_lists_as_ours(self):
        from jtwafmgr.compliance import Monitor
        cd = self.app.cfg['countries']['rules_dir'].rstrip('/') + '/'
        m = Monitor(self.app)
        self.assertEqual(m._cause({'ts': time.time()}, {'added': [cd + 'TW.data'], 'removed': [], 'changed': []}), 'jt-waf-mgr')
        self.assertEqual(m._cause({'ts': time.time()}, {'added': [cd + 'notes.txt'], 'removed': [], 'changed': []}), 'outside')


class TestStoredEvents(unittest.TestCase):
    def test_country_blocks_stored_as_score_blocks_are_put_right_once(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        app = App(env.cfg)
        app.stop()
        app.db.set_meta('fix.country_decided', '')
        now = time.time()
        for i, (rid, decided) in enumerate(((10309, 'score'), (930130, 'score'), (10305, 'confident'))):
            cur = app.db.x("INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, outcome, decided_by, "
                           "rule_ids, local_rule_ids, families, message, matches) VALUES ('n', ?, ?, 'a.example.com', 'GET', '/', '', "
                           "'203.0.113.5', 'external', 'blocked', ?, ?, '', '', '', '[]')", ('u%d' % i, now, decided, ',%d,949110,' % rid))
            eid = cur.lastrowid if hasattr(cur, 'lastrowid') else app.db.one('SELECT MAX(id) FROM events')[0]
            app.db.x("INSERT INTO event_rules(event_id, rule_id, ts, outcome) VALUES (?, ?, ?, 'blocked')", (eid, rid, now))
        app2 = App(env.cfg)
        self.addCleanup(app2.stop)
        got = [r[0] for r in app2.db.q('SELECT decided_by FROM events ORDER BY id')]
        self.assertEqual(got, ['confident', 'score', 'confident'])
        self.assertEqual(app2.db.get_meta('fix.country_decided'), '1')


class TestSandbox(unittest.TestCase):
    def test_requests_come_from_a_country_their_site_lets_through(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        stage(env.cfg['countries']['dir'])
        app = App(env.cfg)
        self.addCleanup(app.stop)
        from jtwafmgr.sandbox import Sandbox, _host_match
        sb = Sandbox(app.cfg, app.site)

        def rule(host, mode, ccs, **kw):
            return dict({'kind': 'country', 'spec': json.dumps({'host': {'mode': 'exact', 'value': host}, 'mode': mode,
                                                                 'countries': ccs})}, **kw)
        items = [rule('a.example.com', 'allow', ['TW']), rule('b.example.com', 'allow', ['JP', 'TW']),
                 rule('c.example.com', 'deny', ['US']), rule('d.example.com', 'allow', ['TW']),
                 rule('d.example.com', 'deny', ['TW']), rule('e.example.com', 'allow', ['US'], deleted=1),
                 {'kind': 'confident_block', 'spec': '{}'}]
        # the change: b's rule (JP+TW), whose own tests pass from Japan and are refused from the US
        tests = [{'host': 'b.example.com', 'path': '/', 'source': 'external', 'src_ip': '192.0.2.1', 'expect': 200},
                 {'host': 'b.example.com', 'path': '/', 'source': 'external', 'src_ip': '203.0.113.1', 'expect': 403},
                 {'host': 'a.example.com', 'path': '/x', 'source': 'external', 'expect': 200},
                 {'host': 'a.example.com', 'path': '/x', 'source': 'internal', 'expect': 200},
                 {'host': 'd.example.com', 'path': '/', 'source': 'external', 'expect': 403}]
        samples = [{'host': h, 'method': 'GET', 'path': '/app.js'} for h in
                   ('a.example.com', 'b.example.com', 'c.example.com', 'd.example.com', 'e.example.com', 'f.example.com')]
        r = {'op': 'add', 'kind': 'country', 'direction': 'tighten', 'spec': '{}'}
        cases = sb.cases_for(r, tests, samples, items)
        reg = {c['host']: c.get('src_ip') for c in cases if c['origin'] == 'regression'}
        # a: Taiwan only -> a Taiwanese address, even though the change itself passes Japan (the #59 case)
        self.assertEqual(reg['a.example.com'], '198.51.100.1')
        self.assertEqual(reg['b.example.com'], '192.0.2.1')          # the change's own address where it passes
        self.assertIsNone(reg['c.example.com'])                      # deny only: the usual address is in no country
        self.assertNotIn('d.example.com', reg)                       # no outside address passes: sample left out
        self.assertIsNone(reg['e.example.com'])                      # a deleted rule does not count
        self.assertIsNone(reg['f.example.com'])
        tst = [c for c in cases if c['origin'] == 'test']
        self.assertEqual([c.get('src_ip') for c in tst], ['192.0.2.1', '203.0.113.1', '198.51.100.1', None, None])
        # any other change: the same per-site addresses for its regression samples
        r = {'op': 'add', 'kind': 'confident_block', 'direction': 'tighten', 'spec': '{}'}
        reg = {c['host']: c.get('src_ip') for c in sb.cases_for(r, [], samples, items) if c['origin'] == 'regression'}
        self.assertEqual((reg['a.example.com'], reg['b.example.com'], reg['c.example.com']),
                         ('198.51.100.1', '198.51.100.1', None))
        # no country rules: nothing changes
        self.assertEqual(sb.country_sources([dict(tests[2])], [{'kind': 'raw', 'spec': '{}'}]), [tests[2]])
        self.assertTrue(_host_match({'mode': 'exact', 'value': 'a.example.com'}, 'A.example.com:443'))
        self.assertFalse(_host_match({'mode': 'exact', 'value': 'a.example.com'}, 'xa.example.com'))
        self.assertTrue(_host_match({'mode': 'exact', 'value': '*.example.com'}, 'w.example.com'))
        self.assertFalse(_host_match({'mode': 'exact', 'value': '*.example.com'}, 'a.b.example.com'))
        self.assertTrue(_host_match({'mode': 'regex', 'value': r'^(a|b)\.example\.com$'}, 'b.example.com'))
        self.assertTrue(_host_match({'mode': 'any'}, 'z.example.com'))

    def test_no_address_to_send_from_fails_the_check(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        stage(env.cfg['countries']['dir'])
        app = App(env.cfg)
        self.addCleanup(app.stop)
        from jtwafmgr.sandbox import Sandbox, SandboxError
        sb = Sandbox(app.cfg, app.site)
        items = [{'kind': 'country', 'spec': json.dumps({'host': {'mode': 'exact', 'value': 'a.example.com'}, 'mode': 'allow',
                                                         'countries': ['ZA', 'FR']})}]
        cases = [{'host': 'a.example.com', 'path': '/x', 'source': 'external', 'expect': 'not403', 'origin': 'regression'}]
        # FR has no staged list, but ZA has: ZA is used; with only FR the samples cannot be sent, so the check fails
        self.assertEqual(sb.country_sources(cases, items)[0]['src_ip'], '198.18.4.1')
        items[0]['spec'] = json.dumps({'host': {'mode': 'exact', 'value': 'a.example.com'}, 'mode': 'allow', 'countries': ['FR']})
        with self.assertRaises(SandboxError):
            sb.country_sources(cases, items)
        r = {'op': 'disable', 'kind': 'exclusion', 'direction': 'tighten', 'spec': '{}'}
        res = sb.run_change(r, {}, [], app.workflow.managed, [{'host': 'a.example.com', 'method': 'GET', 'path': '/x'}], items)
        self.assertEqual((res['ok'], res['error']), (False, 'sandbox_failed'))
        self.assertIn('no address of FR', res['message'])

    def test_a_preferred_address_that_is_never_refused_is_not_used(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        stage(env.cfg['countries']['dir'])
        env.cfg.data['blocks']['protected'] = ['198.51.100.0/28']       # the change's own "passes" address is protected
        app = App(env.cfg)
        self.addCleanup(app.stop)
        from jtwafmgr.sandbox import Sandbox
        sb = Sandbox(app.cfg, app.site)
        items = [{'kind': 'country', 'spec': json.dumps({'host': {'mode': 'exact', 'value': 'a.example.com'}, 'mode': 'allow',
                                                         'countries': ['TW']})}]
        cases = [{'host': 'a.example.com', 'path': '/', 'source': 'external', 'expect': 'not403', 'origin': 'regression'}]
        with self.assertRaises(Exception):          # TW's only sample address is protected: nothing usable to send from
            sb.country_sources(cases, items, prefer='198.51.100.1')

    def test_candidate_lists_built_inside_the_sandbox(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        stage(env.cfg['countries']['dir'])
        app = App(env.cfg)
        self.addCleanup(app.stop)
        from jtwafmgr.sandbox import Sandbox
        sb = Sandbox(app.cfg, app.site)
        root = os.path.join(env.dir, 'sbx')
        os.makedirs(root)
        text = 'SecRule REMOTE_ADDR "!@ipMatchFromFile %s/JP-TW.data" "id:10300"\n' % env.cfg['countries']['rules_dir']
        out = sb._country_lists(text, root)
        self.assertIn(os.path.join(root, 'countries', 'JP-TW.data'), out)
        self.assertEqual(rd(os.path.join(root, 'countries', 'JP-TW.data')).splitlines()[0], '192.0.2.0/24')


if __name__ == '__main__':
    unittest.main()
