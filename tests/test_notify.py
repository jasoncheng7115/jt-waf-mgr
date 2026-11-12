"""Notifications and alerts: which events, the matrix, queueing from the audit trail, rendering per channel
(untrusted values never become markup, mentions or links), sending to fake endpoints (webhook signature, Zulip,
Nextcloud, Telegram, Slack, Teams, Discord, e-mail), retries, rate limit, redirects refused, secrets scrubbed,
alerts (dedup, handle, reminders), settings validation and the API. Synthetic data only."""
import base64
import hashlib
import hmac
import http.server
import json
import socket
import socketserver
import threading
import time
import unittest
import urllib.parse

from jtwafmgr import alerts, auth, notify, uisettings
from jtwafmgr.app import App
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv
from tests.test_api import Client

PW = 'a long test password'
EVIL = '<b>x</b> `y` [click](https://evil.example/) @everyone @**all** <@123> *bold*'


class _Hook(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n)
        self.server.seen.append({'path': self.path, 'headers': dict(self.headers), 'body': body})
        code, payload, extra = self.server.reply(self.path)
        self.send_response(code)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _Smtp(socketserver.StreamRequestHandler):
    """Just enough SMTP for smtplib (no TLS)."""

    def handle(self):
        w = lambda s: self.wfile.write(s.encode() + b'\r\n')   # noqa: E731
        w('220 test')
        data, in_data = [], False
        while True:
            line = self.rfile.readline()
            if not line:
                return
            s = line.decode('utf-8', 'replace').rstrip('\r\n')
            if in_data:
                if s == '.':
                    in_data = False
                    self.server.mails.append('\n'.join(data))
                    data = []
                    w('250 ok')
                else:
                    data.append(s[1:] if s.startswith('..') else s)
                continue
            cmd = s.split(' ', 1)[0].upper()
            if cmd in ('EHLO', 'HELO'):
                w('250 test')
            elif cmd == 'DATA':
                in_data = True
                w('354 go')
            elif cmd == 'QUIT':
                w('221 bye')
                return
            else:
                w('250 ok')


class NotifyBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hook = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Hook)
        cls.hook.seen = []
        cls.hook.reply = lambda path: (200, b'{"ok": true}', None)
        threading.Thread(target=cls.hook.serve_forever, daemon=True).start()
        cls.smtp = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _Smtp)
        cls.smtp.mails = []
        threading.Thread(target=cls.smtp.serve_forever, daemon=True).start()
        cls.base = 'http://127.0.0.1:%d' % cls.hook.server_address[1]
        notify.TELEGRAM_API = cls.base + '/tg'
        notify.ALLOW_LOCAL = True

    @classmethod
    def tearDownClass(cls):
        notify.TELEGRAM_API = 'https://api.telegram.org'
        notify.ALLOW_LOCAL = False
        for s in (cls.hook, cls.smtp):
            s.shutdown()
            s.server_close()

    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.hook.seen.clear()
        self.smtp.mails.clear()
        self.hook.reply = lambda path: (200, b'{"ok": true}', None)

    def tearDown(self):
        self.env.cleanup()

    def setn(self, **kw):
        self.app.cfg.data['notify'].update(kw)

    def webhook(self, **kw):
        self.setn(enabled=True, webhook_enabled=True, webhook_url=self.base + '/hook', webhook_secret='s3cret-signing-key',
                  **kw)

    def rows(self, **where):
        sql = 'SELECT * FROM notifications' + (' WHERE ' + ' AND '.join('%s=?' % k for k in where) if where else '')
        return self.app.db.q(sql + ' ORDER BY id', tuple(where.values()))

    def send(self):
        return notify.run(self.app, log=lambda m: None)


class TestRouting(NotifyBase):
    def test_event_mapping(self):
        e = notify.event_of
        self.assertEqual(e('config.changed', 'outside', {}), 'config.changed_outside')
        self.assertIsNone(e('config.changed', 'ok', {}))
        self.assertEqual(e('change.checked', 'ok', {'state': 'pending_approval'}), 'change.awaiting_approval')
        self.assertEqual(e('change.checked', 'error', {'state': 'failed'}), 'change.check_failed')
        self.assertEqual(e('analyst.run', 'ok', {'proposals': [3]}), 'analyst.proposals')
        self.assertIsNone(e('analyst.run', 'ok', {'proposals': []}))
        self.assertEqual(e('analyst.run', 'error', {}), 'analyst.failed')
        self.assertIsNone(e('notify.failed', 'failed', {}))              # never about itself (no loop)
        self.assertIsNone(e('alert.handled', 'ok', {}))
        self.assertIsNone(e('alert.created', 'ok', {'notify': False}))
        self.assertIsNone(e('login', 'ok', {}))

    def test_nothing_queued_when_off_and_matrix_respected(self):
        self.app.audit.log('account.locked', 'alice', src_ip='203.0.113.5', result='denied', severity='crit', failures=5)
        self.assertEqual(self.rows(), [])                                   # notifications are off
        self.webhook()
        self.setn(slack_enabled=True, slack_webhook=self.base + '/slack')
        self.app.audit.log('account.locked', 'alice', src_ip='203.0.113.5', result='denied', severity='crit', failures=5)
        self.assertEqual(sorted(r['channel'] for r in self.rows()), ['slack', 'webhook'])
        self.app.audit.log('account.locked', 'alice', src_ip='203.0.113.5', result='denied', severity='crit', failures=6)
        self.assertEqual(len(self.rows()), 2)                               # the same thing again within 10 min
        self.setn(matrix={'user.created': ['webhook'], 'account.locked': []})
        self.app.audit.log('account.locked', 'bob', result='denied', severity='crit')
        self.app.audit.log('user.created', 'admin1', target='carol')
        self.assertEqual([(r['event'], r['channel']) for r in self.rows()][2:], [('user.created', 'webhook')])
        m = notify.matrix(self.app.cfg['notify'])
        self.assertEqual(m['backup.failed'], list(notify.CHANNELS))         # default on: every channel
        self.assertEqual(m['change.rejected'], [])                          # default off

    def test_queue_problem_never_breaks_the_action(self):
        self.webhook()
        self.app.db.x('DROP TABLE notifications')
        rid = self.app.audit.log('backup.failed', 'system', 'system', None, 'failed', severity='crit', error='disk full')
        self.assertTrue(rid)
        self.assertEqual(self.app.audit.notify_errors, 1)


class TestRendering(NotifyBase):
    def msg(self):
        self.setn(base_url='https://waf.example.com', language='en')
        return notify.render(self.app.db, self.app.cfg, 'account.locked',
                             {'_actor': EVIL, '_src_ip': '203.0.113.5\n<script>', 'failures': 5, 'minutes': 15})

    def test_untrusted_values_stay_text(self):
        m = self.msg()
        self.assertEqual(m.link, 'https://waf.example.com/admin/audit')
        self.assertNotIn('\n', ''.join(v for _, v in m.facts))
        tg = notify.fmt_telegram(m)
        self.assertNotIn('<b>x</b>', tg)
        self.assertIn('&lt;b&gt;x&lt;/b&gt;', tg)
        self.assertIn('<a href="https://waf.example.com/admin/audit">', tg)
        self.assertEqual(tg.count('<a '), 1)
        md = notify.fmt_markdown(m)
        self.assertEqual(md.count('](https://waf.example.com/'), 1)
        self.assertIn("`<b>x</b> 'y' [click](https://evil.example/) @everyone", md)   # inside a code span
        sl = json.dumps(notify.fmt_slack(m))
        self.assertNotIn('<b>', sl)
        self.assertNotIn('<@123>', sl)
        dc = notify.fmt_discord(m)
        self.assertEqual(dc['allowed_mentions'], {'parse': []})
        self.assertTrue(all(f['value'].startswith('`') for f in dc['embeds'][0]['fields']))
        tm = json.dumps(notify.fmt_teams(m), ensure_ascii=False)
        self.assertNotIn('[click](https', tm)
        self.assertIn('［click］', tm)
        self.assertNotIn('@everyone', tm)
        # chat services: no usable @ in any value (mentions are found in the raw text, even inside code)
        ch = m.chat()
        for fmt in (notify.fmt_markdown, notify.fmt_telegram):
            out = fmt(ch)
            self.assertNotIn('@everyone', out)
            self.assertNotIn('@**all**', out)
        em = notify.fmt_email_html(m)
        self.assertNotIn('<b>x</b>', em)
        self.assertNotIn('<script>', em)

    def test_languages_and_change_lookup(self):
        for lang, word in (('zh-TW', '等待核准'), ('en', 'awaits approval'), ('ja', '承認待ち')):
            self.setn(language=lang)
            m = notify.render(self.app.db, self.app.cfg, 'change.awaiting_approval', {'change_id': 7})
            self.assertIn('#7', m.title)
            self.assertIn(word, m.title)
        self.setn(language='en')
        m = notify.render(self.app.db, self.app.cfg, 'system.version_changed', {'previous': '0.3.5', 'current': '0.4.0'})
        self.assertIn('0.3.5 → 0.4.0', m.title)
        self.assertIsNone(m.link)                                           # no base URL: no links


class TestSending(NotifyBase):
    def test_every_channel_format_and_auth(self):
        self.setn(enabled=True, language='en', base_url='https://waf.example.com',
                  telegram_enabled=True, telegram_token='123456:' + 'A' * 30, telegram_chat_id='-1001',
                  slack_enabled=True, slack_webhook=self.base + '/slack',
                  teams_enabled=True, teams_webhook=self.base + '/teams',
                  discord_enabled=True, discord_webhook=self.base + '/discord',
                  zulip_enabled=True, zulip_site=self.base, zulip_bot_email='bot@example.com', zulip_api_key='ZK' * 10,
                  zulip_stream='waf', nextcloud_enabled=True, nextcloud_url=self.base, nextcloud_token='abcd1234',
                  nextcloud_secret='n' * 40, email_enabled=True, smtp_host='127.0.0.1',
                  smtp_port=self.smtp.server_address[1], smtp_tls='none', smtp_from='waf@example.com',
                  email_to=['ops@example.com'])
        self.webhook()
        self.app.audit.log('backup.failed', 'system', 'system', None, 'failed', severity='crit', file='x.db', error=EVIL)
        counts = self.send()
        self.assertEqual(counts, {'sent': 8}, [dict(r) for r in self.rows()])
        by = {s['path'].split('?')[0]: s for s in self.hook.seen}
        tg = json.loads(by['/tg/bot123456:%s/sendMessage' % ('A' * 30)]['body'])
        self.assertEqual((tg['chat_id'], tg['parse_mode']), ('-1001', 'HTML'))
        self.assertIn('Database backup failed', tg['text'])
        self.assertIn('blocks', json.loads(by['/slack']['body']))
        card = json.loads(by['/teams']['body'])['attachments'][0]
        self.assertEqual(card['contentType'], 'application/vnd.microsoft.card.adaptive')
        self.assertEqual(json.loads(by['/discord']['body'])['allowed_mentions'], {'parse': []})
        z = by['/api/v1/messages']
        self.assertEqual(z['headers']['Authorization'], 'Basic ' + base64.b64encode(b'bot@example.com:' + b'ZK' * 10).decode())
        self.assertEqual(urllib.parse.parse_qs(z['body'].decode())['to'], ['waf'])
        nc = by['/ocs/v2.php/apps/spreed/api/v1/bot/abcd1234/message']
        msg = json.loads(nc['body'])['message']
        want = hmac.new(b'n' * 40, (nc['headers']['X-Nextcloud-Talk-Bot-Random'] + msg).encode(), hashlib.sha256).hexdigest()
        self.assertEqual(nc['headers']['X-Nextcloud-Talk-Bot-Signature'], want)
        wh = by['/hook']
        sig = hmac.new(b's3cret-signing-key', wh['headers']['X-Jt-Waf-Mgr-Timestamp'].encode() + b'.' + wh['body'],
                       hashlib.sha256).hexdigest()
        self.assertEqual(wh['headers']['X-Jt-Waf-Mgr-Signature'], 'sha256=' + sig)
        body = json.loads(wh['body'])
        self.assertEqual((body['event'], body['severity'], body['app']), ('backup.failed', 'critical', 'jt-waf-mgr'))
        self.assertEqual(len(self.smtp.mails), 1)
        mail = self.smtp.mails[0]
        self.assertIn('Subject: [jt-waf-mgr] Database backup failed', mail)
        self.assertIn('multipart/alternative', mail)
        self.assertIn('ops@example.com', mail)

    def test_retry_then_failed_with_audit_and_scrubbed_error(self):
        self.webhook()
        secret_url = self.base + '/hook/' + 'T' * 24
        self.setn(webhook_url=secret_url)
        self.hook.reply = lambda path: (500, json.dumps({'message': 'broken for ' + path}).encode(), None)
        self.app.audit.log('backup.failed', 'system', 'system', None, 'failed', severity='crit', error='x')
        self.assertEqual(self.send(), {'retry': 1})
        r = self.rows()[0]
        self.assertEqual((r['status'], r['attempts']), ('pending', 1))
        self.assertIn('HTTP 500', r['error'])
        self.assertNotIn('T' * 24, r['error'])                              # the secret part of the URL
        for _ in range(3):
            self.app.db.x('UPDATE notifications SET next_at=0')
            self.send()
        r = self.rows(channel='webhook')[0]
        self.assertEqual((r['status'], r['attempts']), ('failed', 4))
        a = self.app.db.one("SELECT * FROM audit WHERE action='notify.failed'")
        self.assertIsNotNone(a)
        self.assertNotIn('T' * 24, a['details'])
        self.assertEqual(self.rows(event='notify.failed'), [])             # no notification about notifications

    def test_redirect_is_not_followed(self):
        self.webhook()
        self.hook.reply = lambda path: ((302, b'', {'Location': 'http://169.254.169.254/latest'}) if path == '/hook'
                                        else (200, b'{}', None))
        self.app.audit.log('backup.failed', 'system', 'system', None, 'failed', severity='crit')
        self.send()
        self.assertEqual([s['path'] for s in self.hook.seen], ['/hook'])
        self.assertIn('HTTP 302', self.rows()[0]['error'])

    def test_rate_limit_and_obsolete(self):
        self.webhook(max_per_hour=2)
        for i in range(4):
            self.app.audit.log('user.created', 'admin1', target='u%d' % i)
        self.setn(matrix={'user.created': ['webhook']})
        for i in range(4):
            self.app.audit.log('user.created', 'admin1', target='u%d' % i)
        st = self.send()
        self.assertEqual(st, {'sent': 2, 'suppressed': 2})
        # an approval request for a change that is no longer waiting is not sent
        notify.enqueue(self.app.db, self.app.cfg, 'change.awaiting_approval', {'change_id': 999})
        self.setn(max_per_hour=100)
        self.assertEqual(self.send(), {'skipped': 1})
        self.assertEqual(self.rows(event='change.awaiting_approval')[0]['error'], 'obsolete')

    def test_channel_switched_off_after_queueing(self):
        self.webhook()
        self.app.audit.log('backup.failed', 'system', 'system', None, 'failed', severity='crit')
        self.setn(webhook_enabled=False)
        self.assertEqual(self.send(), {'skipped': 1})
        self.assertEqual(self.hook.seen, [])


class TestHardening(NotifyBase):
    def test_smtp_password_never_in_clear(self):
        self.setn(smtp_host='127.0.0.1', smtp_port=self.smtp.server_address[1], smtp_tls='none', smtp_from='waf@example.com',
                  email_to=['ops@example.com'], smtp_username='waf', smtp_password='pw')
        with self.assertRaises(notify.SendError) as c:
            notify.send_email(self.app.cfg['notify'], notify.Msg('x', 'info'))
        self.assertIn('without TLS', str(c.exception))
        self.assertEqual(self.smtp.mails, [])

    def test_loopback_and_link_local_refused(self):
        notify.ALLOW_LOCAL = False
        try:
            for url in ('http://127.0.0.1:9/x', 'http://169.254.169.254/latest/meta-data', 'http://[::1]/x'):
                with self.assertRaises(notify.SendError, msg=url):
                    notify.http_post(url, b'{}', {})
        finally:
            notify.ALLOW_LOCAL = True

    def test_webhook_secrets_bound_to_the_address(self):
        uisettings.set_many(self.app, {'notify.webhook_url': 'https://hooks.example.com/a', 'notify.webhook_token': 'T' * 20}, 'admin1')
        for new in ('https://other.example.net/a', 'http://hooks.example.com/a', 'https://hooks.example.com:8443/a'):
            with self.assertRaises(uisettings.SettingError, msg=new) as c:
                uisettings.set_many(self.app, {'notify.webhook_url': new}, 'admin1')
            self.assertEqual(c.exception.details['key'], 'notify.webhook_token')
        uisettings.set_many(self.app, {'notify.webhook_url': 'https://hooks.example.com/b'}, 'admin1')    # same server

    def test_unreachable_channel_does_not_hold_up_the_others(self):
        self.webhook()
        self.setn(slack_enabled=True, slack_webhook='https://198.51.100.1:9/x')       # documentation address: no answer
        notify.TIMEOUT, old = 1, notify.TIMEOUT
        try:
            for i in range(3):        # three different things (one alert / account is notified once per 10 minutes)
                self.app.audit.log('account.locked', 'user%d' % i, src_ip='203.0.113.5', result='denied', severity='crit')
            counts = self.send()
        finally:
            notify.TIMEOUT = old
        self.assertEqual(counts.get('sent'), 3)                          # the webhook ones
        self.assertEqual(counts.get('retry'), 1)                         # one try on the dead channel...
        self.assertEqual(counts.get('deferred'), 2)                      # ...its others wait

    def test_long_messages_are_shortened_not_cut(self):
        m = notify.Msg('t', 'info', [('k%d' % i, '<&>' * 90) for i in range(40)])
        out = notify._fit(m.chat(), notify.fmt_telegram, len, 4000)
        self.assertLessEqual(len(out), 4000)
        self.assertTrue(out.endswith('</code>'))


class TestAlerts(NotifyBase):
    def test_system_events_open_one_alert_and_remind(self):
        self.webhook(remind_hours=1)
        for _ in range(3):
            self.app.audit.log('integrity.program_failed', 'system', 'system', None, 'failed', severity='crit',
                               reason='files_changed')
        rows = self.app.db.q('SELECT * FROM alerts')
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['kind'], rows[0]['count'], rows[0]['state']), ('integrity', 3, 'open'))
        self.assertEqual(self.rows(event='alert.created'), [])            # the event itself is the notification
        self.assertEqual(len(self.rows(event='integrity.program_failed')), 1)
        self.send()
        self.assertEqual(self.rows(event='alert.reminder'), [])           # not yet due
        self.app.db.x('UPDATE alerts SET created_at=created_at-7200')
        self.send()
        rem = self.rows(event='alert.reminder')
        self.assertEqual(len(rem), 1)
        self.assertEqual(json.loads(rem[0]['details'])['open'], 1)
        self.send()
        self.assertEqual(len(self.rows(event='alert.reminder')), 1)       # once per period
        a = alerts.handle(self.app.db, self.app.audit, rows[0]['id'], 'appr', 'reinstalled the release')
        self.assertEqual((a['state'], a['handled_by']), ('handled', 'appr'))
        with self.assertRaises(alerts.AlertError):
            alerts.handle(self.app.db, self.app.audit, rows[0]['id'], 'appr', 'again')
        self.assertIsNotNone(self.app.db.one("SELECT 1 FROM audit WHERE action='alert.handled'"))
        # a new failure after handling opens a new alert
        self.app.audit.log('integrity.program_failed', 'system', 'system', None, 'failed', severity='crit')
        self.assertEqual(alerts.counts(self.app.db)['open'], 1)

    def test_analyst_alert_notifies_with_its_severity(self):
        self.webhook()
        aid = alerts.raise_alert(self.app.db, self.app.audit, 'analyst', 'attack_passed', 'critical', 'attack_passed:/x',
                                 {'path': '/x', 'host': 'app.example.com', 'reason': EVIL}, link='/analysis/1')
        r = self.rows(event='alert.created')
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]['severity'], 'critical')
        self.assertEqual(json.loads(r[0]['details'])['alert_id'], aid)
        self.setn(base_url='https://waf.example.com', language='en')
        m = notify.render(self.app.db, self.app.cfg, 'alert.created', json.loads(r[0]['details']))
        self.assertEqual(m.link, 'https://waf.example.com/analysis/1')
        self.assertIn('attack may have passed', m.title)
        self.assertNotIn('<b>', m.title)
        self.send()
        self.assertEqual(json.loads(self.hook.seen[0]['body'])['severity'], 'critical')


class TestSettings(NotifyBase):
    def test_validation(self):
        bad = [{'notify.telegram_token': 'not a token'}, {'notify.slack_webhook': 'http://plain.example.com/x'},
               {'notify.matrix': {'no.such.event': ['email']}}, {'notify.matrix': {'backup.failed': ['pigeon']}},
               {'notify.email_to': ['not-an-address']}, {'notify.language': 'fr'},
               {'notify.base_url': 'javascript:alert(1)'}, {'notify.zulip_stream': 'a\nb'}]
        for b in bad:
            with self.assertRaises(uisettings.SettingError, msg=b):
                uisettings.set_many(self.app, b, 'admin1')
        uisettings.set_many(self.app, {'notify.matrix': {'backup.failed': ['webhook', 'email']},
                                       'notify.zulip_site': 'https://chat.example.com', 'notify.zulip_api_key': 'K' * 32},
                            'admin1')
        self.assertEqual(self.app.cfg['notify']['matrix'], {'backup.failed': ['email', 'webhook']})
        pub = uisettings.public(self.app.cfg, self.app.db)
        self.assertNotIn('K' * 32, json.dumps(pub))
        # the stored key is never sent to another server unless entered again
        with self.assertRaises(uisettings.SettingError) as c:
            uisettings.set_many(self.app, {'notify.zulip_site': 'https://other.example.net'}, 'admin1')
        self.assertEqual(c.exception.code, 'key_required_for_new_host')
        a = self.app.db.q("SELECT details FROM audit WHERE action='settings.changed'")
        self.assertNotIn('K' * 32, json.dumps([r['details'] for r in a]))


class TestApi(NotifyBase):
    def setUp(self):
        super().setUp()
        a = self.app.auth
        a.create_user('viewer1', 'viewer', password=PW)
        a.create_user('appr', 'approver', password=PW)
        a.create_user('admin1', 'admin', password=PW)
        for u in ('appr', 'admin1'):
            s, _ = a.totp_setup(u)
            a.totp_enable(u, auth.totp_code(s, int(time.time() // 30)))
            setattr(self, 'sec_' + u, s)
        self.app.db.x('UPDATE users SET totp_last_step=0')
        self.srv, _ = start_background(self.app)
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def client(self, user):
        c = Client(self.port)
        sec = getattr(self, 'sec_' + user, None)
        self.app.db.x('UPDATE users SET totp_last_step=0 WHERE username=?', (user,))
        st, _ = c.login(user, totp=auth.totp_code(sec, int(time.time() // 30)) if sec else None)
        self.assertEqual(st, 200)
        return c

    def test_test_send_deliveries_and_alerts(self):
        adm = self.client('admin1')
        st, obj, _ = adm.req('POST', '/api/v1/notify/test', {'channel': 'webhook'})
        self.assertEqual((st, obj['error']['code']), (409, 'channel_not_configured'))
        self.webhook()
        self.setn(enabled=False)                                           # a test works while notifications are off
        st, obj, _ = adm.req('POST', '/api/v1/notify/test', {'channel': 'webhook'})
        self.assertEqual(st, 202)
        self.send()
        st, d, _ = adm.req('GET', '/api/v1/notify/deliveries/%d' % obj['id'])
        self.assertEqual((d['status'], d['event'], d['test']), ('sent', 'notify.test', True))
        self.assertTrue(json.loads(self.hook.seen[-1]['body'])['test'])
        st, lst, _ = adm.req('GET', '/api/v1/notify/deliveries?channel=webhook')
        self.assertEqual(len(lst['items']), 1)
        st, s, _ = adm.req('GET', '/api/v1/notify/status')
        self.assertEqual(st, 200)
        self.assertNotIn('s3cret', json.dumps(s))
        viewer = self.client('viewer1')
        self.assertEqual(viewer.req('GET', '/api/v1/notify/status')[0], 403)
        self.assertEqual(viewer.req('POST', '/api/v1/notify/test', {'channel': 'webhook'})[0], 403)
        aid = alerts.raise_alert(self.app.db, self.app.audit, 'analyst', 'false_positive', 'warning', 'fp:x',
                                 {'host': 'app.example.com', 'path': '/edit'})
        st, lst, _ = viewer.req('GET', '/api/v1/alerts?state=open')
        self.assertEqual((st, lst['counts']['open'], lst['items'][0]['id']), (200, 1, aid))
        self.assertEqual(viewer.req('POST', '/api/v1/alerts/%d/handle' % aid, {'note': 'x'})[0], 403)
        appr = self.client('appr')
        st, a, _ = appr.req('POST', '/api/v1/alerts/%d/handle' % aid, {'note': 'exclusion approved'})
        self.assertEqual((st, a['state'], a['note']), (200, 'handled', 'exclusion approved'))
        self.assertEqual(appr.req('POST', '/api/v1/alerts/%d/handle' % aid, {})[0], 409)
        self.assertEqual(appr.req('GET', '/api/v1/alerts/counts')[1]['open'], 0)
        self.assertEqual(appr.req('GET', '/api/v1/alerts/999999')[0], 404)
        self.assertEqual(appr.req('GET', '/api/v1/alerts?state=bogus')[0], 400)


if __name__ == '__main__':
    unittest.main()
