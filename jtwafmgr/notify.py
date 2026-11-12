"""Notifications: e-mail and chat channels (Telegram, Microsoft Teams, Slack, Discord, Zulip, Nextcloud Talk and
a signed generic webhook) for the events people must hear about, and reminders of open alerts.

  Audit.log(...) -> event_of() -> one `notifications` row per channel (pending) + a request file
  jt-waf-mgr-notify.service (path unit, one-minute timer) -> run() -> sent | retried | failed | suppressed

- The web service never connects out: it only queues rows. Sending happens in the notify unit.
- A message is rendered when it is sent, from the stored details, in the configured language. Values that may
  come from outside (user names, addresses, paths, host names, what the language model wrote) are always shown
  as code or escaped for the channel: never as markup, never as a mention, never as a link.
- Bot tokens, webhook URLs and passwords are write-only settings; recorded errors never contain them.
- A failed delivery is retried after 1, 5 and 15 minutes, then recorded as failed (audit notify.failed). Each
  channel sends at most notify.max_per_hour messages an hour; the rest are recorded as suppressed.
"""
import base64
import datetime
import email.message
import email.utils
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import smtplib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__, util

CHANNELS = ('email', 'telegram', 'teams', 'slack', 'discord', 'zulip', 'nextcloud', 'webhook')
REQUEST_FILE = 'notify.request'
BACKOFF = (60, 300, 900)            # seconds before the 2nd, 3rd and 4th attempt
DEDUP_SECONDS = 600
KEEP_DAYS = 90
TIMEOUT = 15
TELEGRAM_API = 'https://api.telegram.org'    # tests point this at a local server
SEVERITIES = ('critical', 'warning', 'info', 'success')

# event -> (category, severity, on by default). The matrix (Settings > Notifications) decides per channel.
EVENTS = {
    'alert.created': ('alerts', 'warning', True),
    'alert.reminder': ('alerts', 'warning', True),
    'integrity.audit_chain_failed': ('security', 'critical', True),
    'integrity.audit_chain_failed_recovered': ('security', 'success', True),
    'integrity.program_failed': ('security', 'critical', True),
    'integrity.program_failed_recovered': ('security', 'success', True),
    'config.changed_outside': ('security', 'critical', True),
    'change.apply_blocked_drift': ('security', 'critical', True),
    'auth.step_up_locked': ('security', 'critical', True),
    'account.locked': ('security', 'warning', True),
    'totp.disabled': ('security', 'warning', True),
    'change.awaiting_approval': ('changes', 'info', True),
    'change.check_failed': ('changes', 'warning', True),
    'change.applied': ('changes', 'success', True),
    'change.apply_failed': ('changes', 'critical', True),
    'change.rejected': ('changes', 'info', False),
    'change.rollback_requested': ('changes', 'warning', True),
    'report.daily': ('system', 'info', True),
    'analyst.proposals': ('analysis', 'info', True),
    'analyst.failed': ('analysis', 'warning', True),
    'backup.failed': ('system', 'critical', True),
    'system.version_changed': ('system', 'info', True),
    'user.created': ('accounts', 'info', False),
    'token.created': ('accounts', 'info', False),
    'settings.changed': ('system', 'info', False),
}
TEST_EVENT = 'notify.test'

# --- texts (three languages; values are inserted as data, never as markup) ---------------------------------

TEXT = {
    'zh-TW': {
        'alert.created': '新的待處理警示：{kind}',
        'alert.reminder': '還有 {open} 個警示待處理',
        'integrity.audit_chain_failed': '稽核記錄的雜湊鏈驗證失敗',
        'integrity.audit_chain_failed_recovered': '稽核記錄的雜湊鏈驗證恢復正常',
        'integrity.program_failed': '程式檔案與簽章清單不符',
        'integrity.program_failed_recovered': '程式檔案驗證恢復正常',
        'config.changed_outside': 'nginx / ModSecurity 設定被 jt-waf-mgr 以外的方式修改',
        'change.apply_blocked_drift': '套用已停止：受管理的規則檔被外部修改',
        'auth.step_up_locked': '一次性驗證碼錯誤太多次，已暫停驗證',
        'account.locked': '帳號因登入失敗太多次被鎖定',
        'totp.disabled': '帳號的雙因素驗證被關閉',
        'change.awaiting_approval': '變更 #{change_id} 檢查通過，等待核准',
        'change.check_failed': '變更 #{change_id} 檢查沒有通過',
        'change.applied': '變更 #{change_id} 已套用（版本 {version}）',
        'change.apply_failed': '變更 #{change_id} 套用失敗',
        'change.rejected': '變更 #{change_id} 被退回',
        'change.rollback_requested': '已要求退回版本（變更 #{change_id}）',
        'analyst.proposals': '事件分析提出 {n} 筆變更',
        'analyst.failed': '事件分析執行失敗',
        'backup.failed': '資料庫備份失敗',
        'system.version_changed': 'jt-waf-mgr 版本變更：{previous} → {current}',
        'user.created': '新增帳號',
        'token.created': '新增 API 權杖',
        'settings.changed': '設定已變更',
        'report.daily': '每日摘要（{day}）',
        'f.events': '事件',
        'f.blocked': '封鎖',
        'f.logged': '只記錄',
        'f.sources': '外部來源',
        'f.top_hosts': '事件最多的站台',
        'f.top_rules': '命中最多的規則',
        'f.open_alerts': '待處理警示',
        'f.applied': '已套用的變更',
        'f.proposed': '事件分析提案',
        'f.vs': '前 24 小時',
        'notify.test': '測試通知',
        'notify.test_text': '這是 jt-waf-mgr 的測試通知，收到表示這個管道設定正確。',
        'open': '前往檢視',
        'f.change': '變更', 'f.kind': '類型', 'f.direction': '方向', 'f.rule': '規則', 'f.by': '提出者',
        'f.reason': '理由', 'f.user': '帳號', 'f.src_ip': '來源', 'f.failures': '失敗次數', 'f.minutes': '鎖定分鐘',
        'f.purpose': '用途', 'f.files': '檔案', 'f.cause': '來源判斷', 'f.problem': '問題', 'f.step': '失敗步驟',
        'f.version': '版本', 'f.run': '分析', 'f.proposals': '提案', 'f.error': '錯誤', 'f.file': '檔案',
        'f.key': '設定', 'f.target': '對象', 'f.alert': '警示', 'f.severity': '嚴重度', 'f.path': '路徑',
        'f.host': '站台', 'f.count': '次數', 'f.since': '開始', 'f.node': '節點', 'f.channel': '管道',
        'f.items': '項目', 'f.state': '狀態',
        'dir.tighten': '收緊', 'dir.loosen': '放寬', 'dir.neutral': '不變',
        'k.attack_in_progress': '攻擊進行中', 'k.attack_passed': '攻擊可能沒被封鎖', 'k.false_positive': '誤判影響使用者',
        'k.integrity': '完整性問題', 'k.config_outside': '設定被外部修改', 'k.apply_failed': '套用失敗',
        'k.backup_failed': '備份失敗', 'k.auth_attack': '驗證遭到攻擊', 'k.other': '其他',
    },
    'en': {
        'alert.created': 'New alert to follow up: {kind}',
        'alert.reminder': '{open} alerts are still open',
        'integrity.audit_chain_failed': 'Audit trail hash chain check failed',
        'integrity.audit_chain_failed_recovered': 'Audit trail hash chain check is fine again',
        'integrity.program_failed': 'Program files do not match the signed manifest',
        'integrity.program_failed_recovered': 'Program file check is fine again',
        'config.changed_outside': 'nginx / ModSecurity configuration changed outside jt-waf-mgr',
        'change.apply_blocked_drift': 'Apply stopped: managed rule files were changed outside',
        'auth.step_up_locked': 'Too many wrong one-time codes: verification paused',
        'account.locked': 'Account locked after too many failed sign-ins',
        'totp.disabled': 'Two-factor authentication turned off for an account',
        'change.awaiting_approval': 'Change #{change_id} passed its checks and awaits approval',
        'change.check_failed': 'Change #{change_id} did not pass its checks',
        'change.applied': 'Change #{change_id} applied (version {version})',
        'change.apply_failed': 'Change #{change_id} failed to apply',
        'change.rejected': 'Change #{change_id} rejected',
        'change.rollback_requested': 'Rollback requested (change #{change_id})',
        'analyst.proposals': 'Event analysis proposed {n} changes',
        'analyst.failed': 'Event analysis failed',
        'backup.failed': 'Database backup failed',
        'system.version_changed': 'jt-waf-mgr version changed: {previous} → {current}',
        'user.created': 'Account created',
        'token.created': 'API token created',
        'settings.changed': 'Setting changed',
        'report.daily': 'Daily report ({day})',
        'f.events': 'Events',
        'f.blocked': 'Blocked',
        'f.logged': 'Logged only',
        'f.sources': 'External sources',
        'f.top_hosts': 'Busiest sites',
        'f.top_rules': 'Most matched rules',
        'f.open_alerts': 'Open alerts',
        'f.applied': 'Changes applied',
        'f.proposed': 'Analysis proposals',
        'f.vs': 'previous 24 h',
        'notify.test': 'Test notification',
        'notify.test_text': 'This is a test notification from jt-waf-mgr: this channel is set up correctly.',
        'open': 'Open',
        'f.change': 'Change', 'f.kind': 'Kind', 'f.direction': 'Direction', 'f.rule': 'Rule', 'f.by': 'Proposed by',
        'f.reason': 'Reason', 'f.user': 'Account', 'f.src_ip': 'Source', 'f.failures': 'Failures',
        'f.minutes': 'Locked minutes', 'f.purpose': 'Purpose', 'f.files': 'Files', 'f.cause': 'Cause',
        'f.problem': 'Problem', 'f.step': 'Failed step', 'f.version': 'Version', 'f.run': 'Run',
        'f.proposals': 'Proposals', 'f.error': 'Error', 'f.file': 'File', 'f.key': 'Setting', 'f.target': 'Target',
        'f.alert': 'Alert', 'f.severity': 'Severity', 'f.path': 'Path', 'f.host': 'Site', 'f.count': 'Count',
        'f.since': 'Since', 'f.node': 'Node', 'f.channel': 'Channel', 'f.items': 'Items', 'f.state': 'State',
        'dir.tighten': 'tightening', 'dir.loosen': 'loosening', 'dir.neutral': 'neutral',
        'k.attack_in_progress': 'attack in progress', 'k.attack_passed': 'attack may have passed',
        'k.false_positive': 'false positive affecting users', 'k.integrity': 'integrity problem',
        'k.config_outside': 'configuration changed outside', 'k.apply_failed': 'apply failed',
        'k.backup_failed': 'backup failed', 'k.auth_attack': 'attack on sign-in', 'k.other': 'other',
    },
    'ja': {
        'alert.created': '新しい対応待ちアラート：{kind}',
        'alert.reminder': '対応待ちのアラートが {open} 件あります',
        'integrity.audit_chain_failed': '監査記録のハッシュチェーン検証に失敗しました',
        'integrity.audit_chain_failed_recovered': '監査記録のハッシュチェーン検証が正常に戻りました',
        'integrity.program_failed': 'プログラムファイルが署名済みリストと一致しません',
        'integrity.program_failed_recovered': 'プログラムファイルの検証が正常に戻りました',
        'config.changed_outside': 'nginx / ModSecurity の設定が jt-waf-mgr 以外で変更されました',
        'change.apply_blocked_drift': '適用を停止：管理対象のルールファイルが外部で変更されました',
        'auth.step_up_locked': 'ワンタイムコードの誤りが多すぎるため検証を停止しました',
        'account.locked': 'サインイン失敗が多すぎるためアカウントがロックされました',
        'totp.disabled': 'アカウントの二要素認証が無効になりました',
        'change.awaiting_approval': '変更 #{change_id} は検査に合格し、承認待ちです',
        'change.check_failed': '変更 #{change_id} は検査に合格しませんでした',
        'change.applied': '変更 #{change_id} を適用しました（バージョン {version}）',
        'change.apply_failed': '変更 #{change_id} の適用に失敗しました',
        'change.rejected': '変更 #{change_id} は却下されました',
        'change.rollback_requested': 'ロールバックが要求されました（変更 #{change_id}）',
        'analyst.proposals': 'イベント分析が {n} 件の変更を提案しました',
        'analyst.failed': 'イベント分析に失敗しました',
        'backup.failed': 'データベースのバックアップに失敗しました',
        'system.version_changed': 'jt-waf-mgr のバージョン変更：{previous} → {current}',
        'user.created': 'アカウントを作成しました',
        'token.created': 'API トークンを作成しました',
        'settings.changed': '設定が変更されました',
        'report.daily': '日次レポート（{day}）',
        'f.events': 'イベント',
        'f.blocked': 'ブロック',
        'f.logged': '記録のみ',
        'f.sources': '外部の送信元',
        'f.top_hosts': 'イベントの多いサイト',
        'f.top_rules': '一致の多いルール',
        'f.open_alerts': '対応待ちアラート',
        'f.applied': '適用した変更',
        'f.proposed': 'イベント分析の提案',
        'f.vs': '直前 24 時間',
        'notify.test': 'テスト通知',
        'notify.test_text': 'jt-waf-mgr からのテスト通知です。このチャネルは正しく設定されています。',
        'open': '表示する',
        'f.change': '変更', 'f.kind': '種類', 'f.direction': '方向', 'f.rule': 'ルール', 'f.by': '提案者',
        'f.reason': '理由', 'f.user': 'アカウント', 'f.src_ip': '送信元', 'f.failures': '失敗回数',
        'f.minutes': 'ロック（分）', 'f.purpose': '用途', 'f.files': 'ファイル', 'f.cause': '原因判定',
        'f.problem': '問題', 'f.step': '失敗した手順', 'f.version': 'バージョン', 'f.run': '分析',
        'f.proposals': '提案', 'f.error': 'エラー', 'f.file': 'ファイル', 'f.key': '設定', 'f.target': '対象',
        'f.alert': 'アラート', 'f.severity': '重大度', 'f.path': 'パス', 'f.host': 'サイト', 'f.count': '回数',
        'f.since': '開始', 'f.node': 'ノード', 'f.channel': 'チャネル', 'f.items': '項目', 'f.state': '状態',
        'dir.tighten': '強化', 'dir.loosen': '緩和', 'dir.neutral': '変化なし',
        'k.attack_in_progress': '攻撃が進行中', 'k.attack_passed': '攻撃が防がれていない可能性',
        'k.false_positive': '誤検知が利用者に影響', 'k.integrity': '完全性の問題', 'k.config_outside': '設定の外部変更',
        'k.apply_failed': '適用失敗', 'k.backup_failed': 'バックアップ失敗', 'k.auth_attack': '認証への攻撃',
        'k.other': 'その他',
    },
}


def _t(lang, key, **kw):
    s = TEXT.get(lang, TEXT['en']).get(key) or TEXT['en'].get(key) or key
    try:
        return s.format(**{k: v for k, v in kw.items()})
    except (KeyError, IndexError, ValueError):
        return s


# --- which events, which channels ----------------------------------------------------------------------------

def event_of(action, result, details):
    """An audit action -> the notification event, or None."""
    if action.startswith('notify.') or action.startswith('alert.') and action != 'alert.created':
        return None
    if action == 'config.changed':
        return 'config.changed_outside' if result == 'outside' else None
    if action == 'change.checked':
        return 'change.awaiting_approval' if details.get('state') == 'pending_approval' else 'change.check_failed'
    if action == 'analyst.run':
        if result != 'ok':
            return 'analyst.failed'
        return 'analyst.proposals' if details.get('proposals') else None
    if action == 'alert.created':
        return 'alert.created' if details.get('notify', True) else None
    return action if action in EVENTS else None


def configured(n, ch):
    """The channel has what it needs to send (it may still be switched off)."""
    if ch == 'email':
        return bool(n['smtp_host'] and n['smtp_from'] and n['email_to'])
    if ch == 'telegram':
        return bool(n['telegram_token'] and n['telegram_chat_id'])
    if ch in ('teams', 'slack', 'discord'):
        return bool(n[ch + '_webhook'])
    if ch == 'zulip':
        return bool(n['zulip_site'] and n['zulip_bot_email'] and n['zulip_api_key'] and n['zulip_stream'])
    if ch == 'nextcloud':
        return bool(n['nextcloud_url'] and n['nextcloud_token'] and n['nextcloud_secret'])
    if ch == 'webhook':
        return bool(n['webhook_url'])
    return False


def active(n, ch):
    return bool(n['enabled'] and n.get(ch + '_enabled') and configured(n, ch))


def matrix(n):
    """{event: [channels]} with the defaults filled in (default: every channel for an event that is on)."""
    stored = n.get('matrix') or {}
    out = {}
    for ev, (_, _, on) in EVENTS.items():
        out[ev] = [c for c in CHANNELS if c in stored[ev]] if ev in stored else (list(CHANNELS) if on else [])
    return out


def routes(n, event):
    chosen = matrix(n).get(event, [])
    return [c for c in CHANNELS if c in chosen and active(n, c)]


def request_file(cfg):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['paths']['db'])), REQUEST_FILE)


def _wake(cfg):
    try:
        fd = os.open(request_file(cfg), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, util.iso(time.time()).encode())
        finally:
            os.close(fd)
    except OSError:
        pass       # the one-minute timer sends it anyway


def _dedup_key(event, d):
    for k in ('change_id', 'alert_id', 'snapshot', 'run_id'):
        if d.get(k) is not None:
            return '%s:%s' % (event, d[k])
    if event in ('account.locked', 'auth.step_up_locked', 'totp.disabled'):
        return '%s:%s' % (event, d.get('_actor'))
    return ''


def enqueue(db, cfg, event, details, audit_id=None, severity=None, channels=None, test=False, by=None):
    """Queue one message per channel. Returns the new row ids."""
    n = cfg['notify']
    if channels is None:
        channels = routes(n, event)
    if not channels:
        return []
    sev = severity if severity in SEVERITIES else EVENTS.get(event, ('', 'info', False))[1]
    now = util.now()
    dd = '' if test else _dedup_key(event, details)
    ids = []
    for ch in channels:
        if dd and db.one('SELECT 1 FROM notifications WHERE dedup=? AND channel=? AND created_at>?',
                         (dd, ch, now - DEDUP_SECONDS)):
            continue
        ids.append(db.x('INSERT INTO notifications(created_at, event, severity, channel, audit_id, details, dedup, test, '
                        'requested_by, next_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
                        (now, event, sev, ch, audit_id, json.dumps(details, ensure_ascii=False, default=str)[:20000], dd,
                         1 if test else 0, by, now)).lastrowid)
    if ids:
        _wake(cfg)
    return ids


SYSTEM_ALERTS = {
    # audit action (result) -> alert kind: these must be followed up by a person, not only read
    'integrity.audit_chain_failed': 'integrity', 'integrity.program_failed': 'integrity',
    'config.changed_outside': 'config_outside', 'change.apply_blocked_drift': 'config_outside',
    'change.apply_failed': 'apply_failed', 'backup.failed': 'backup_failed', 'auth.step_up_locked': 'auth_attack',
}
SYSTEM_ALERT_LINKS = {'integrity': '/admin/system', 'config_outside': '/config-changes', 'apply_failed': '/changes',
                      'backup_failed': '/admin/system', 'auth_attack': '/admin/audit'}


def on_audit(audit, rid, action, actor, src_ip, result, severity, details):
    """Called by Audit.log after every row: queue notifications, open alerts for what needs following up."""
    db, cfg = audit.db, audit.cfg
    ev = event_of(action, result, details)
    if not ev:
        return
    d = dict(details)
    d['_actor'], d['_src_ip'], d['_ts'] = actor, src_ip, util.now()
    kind = SYSTEM_ALERTS.get(ev)
    if kind:
        from . import alerts
        ref = d.get('change_id') or d.get('snapshot') or (d.get('_actor') if kind == 'auth_attack' else None) or ''
        dd = '%s:%s' % (ev, ref)
        link = SYSTEM_ALERT_LINKS.get(kind, '')
        if kind == 'config_outside' and d.get('snapshot'):
            link = '/config-changes/%s' % d['snapshot']
        elif kind == 'apply_failed' and d.get('change_id'):
            link = '/changes/%s' % d['change_id']
        aid = alerts.raise_alert(db, audit, 'system', kind, 'critical', dd or ev, {'event': ev, 'audit_id': rid,
                                 **{k: v for k, v in details.items() if k in ('change_id', 'snapshot', 'reason', 'file',
                                                                               'error', 'step', 'purpose', 'cause')}},
                                 link=link, notify=False)
        d['alert_id'] = aid
    sev = None
    if ev == 'system.version_changed' and severity == 'crit':
        sev = 'critical'
    elif ev == 'alert.created':
        sev = details.get('alert_severity')
    enqueue(db, cfg, ev, d, audit_id=rid, severity=sev)


# --- rendering ------------------------------------------------------------------------------------------------

class Msg:
    """title: from our own texts (numbers and ids only); facts: [(label, value)] with untrusted values;
    text: optional untrusted free text; link: absolute URL or None."""

    def __init__(self, title, severity, facts=(), text='', link=None, lang='en'):
        self.title, self.severity, self.facts, self.text, self.link, self.lang = title, severity, list(facts), text, link, lang

    def chat(self):
        """The same message for a chat service: no usable @ in any value."""
        return Msg(self.title, self.severity, [(a, _nomention(b)) for a, b in self.facts], _nomention(self.text),
                   self.link, self.lang)

    def shorter(self):
        """A bit shorter, for services with a message size limit: first the free text (the model's reason), then
        long values, then the last facts (the first ones say what and where)."""
        if len(self.text) > 80:
            return Msg(self.title, self.severity, self.facts, self.text[:len(self.text) // 2] + '…', self.link, self.lang)
        if any(len(b) > 100 for _, b in self.facts):
            f = [(a, b[:max(60, len(b) // 2)] + '…' if len(b) > 100 else b) for a, b in self.facts]
            return Msg(self.title, self.severity, f, self.text, self.link, self.lang)
        if self.facts:
            return Msg(self.title, self.severity, self.facts[:-1], self.text, self.link, self.lang)
        return Msg(self.title, self.severity, [], self.text[:len(self.text) // 2], self.link, self.lang)

    @property
    def open_label(self):
        return _t(self.lang, 'open')


def _v(x, n=300):
    """One line of untrusted text for a fact value."""
    if x is None:
        return ''
    if isinstance(x, (list, tuple)):
        x = ', '.join(str(i) for i in x[:20]) + (' …' if len(x) > 20 else '')
    s = re.sub(r'[\x00-\x1f\x7f  ​-‏‪-‮⁦-⁩]+', ' ', str(x)).strip()
    return s if len(s) <= n else s[:n] + '…'


def _int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _link(cfg, path):
    base = (cfg['notify'].get('base_url') or '').rstrip('/')
    return base + path if base and path else None


def render(db, cfg, event, d):
    lang = cfg['notify']['language']
    L = lambda k: _t(lang, k)       # noqa: E731
    sev = EVENTS.get(event, ('', 'info', False))[1]
    facts, text, path = [], '', None
    kw = {}
    cid = _int(d.get('change_id'))
    if event == TEST_EVENT:
        text = L('notify.test_text')
        facts.append((L('f.node'), cfg['node']['id']))
    elif event.startswith('change.') and cid:
        kw['change_id'] = cid
        kw['version'] = _int(d.get('version')) or '-'
        r = db.one('SELECT kind, op, direction, rule_id, proposed_by, reason, state FROM changes WHERE id=?', (cid,))
        if r:
            facts += [(L('f.kind'), '%s / %s' % (r['op'], r['kind'])),
                      (L('f.direction'), L('dir.' + r['direction']) if r['direction'] in ('tighten', 'loosen', 'neutral') else r['direction']),
                      (L('f.rule'), r['rule_id'] or '-'), (L('f.by'), r['proposed_by'])]
            text = (r['reason'] or '').split('\n', 1)[0]
        if d.get('step'):
            facts.append((L('f.step'), d['step']))
        if d.get('files'):
            facts.append((L('f.files'), d['files']))
        path = '/changes/%d' % cid
    elif event in ('account.locked', 'auth.step_up_locked', 'totp.disabled'):
        facts += [(L('f.user'), d.get('_actor')), (L('f.src_ip'), d.get('_src_ip') or '-')]
        if d.get('failures') is not None:
            facts.append((L('f.failures'), d['failures']))
        if d.get('minutes') is not None:
            facts.append((L('f.minutes'), d['minutes']))
        if d.get('purpose'):
            facts.append((L('f.purpose'), d['purpose']))
        path = '/admin/audit'
    elif event == 'config.changed_outside':
        for k in ('changed', 'added', 'removed'):
            if d.get(k):
                facts.append((L('f.files') + ' (%s)' % k, d[k]))
        snap = _int(d.get('snapshot'))
        path = '/config-changes/%d' % snap if snap else '/config-changes'
    elif event.startswith('integrity.'):
        if d.get('reason'):
            facts.append((L('f.problem'), d['reason']))
        for k in ('changed', 'missing', 'extra'):
            if d.get(k):
                facts.append((L('f.files') + ' (%s)' % k, d[k]))
        path = '/admin/system'
    elif event in ('analyst.proposals', 'analyst.failed'):
        run = _int(d.get('run_id'))
        props = d.get('proposals') or []
        kw['n'] = len(props)
        facts.append((L('f.run'), '#%s' % run))
        if props:
            facts.append((L('f.proposals'), ', '.join('#%s' % p for p in props[:20])))
        if d.get('error'):
            facts.append((L('f.error'), d['error']))
        path = '/analysis/%d' % run if run else '/analysis'
    elif event == 'backup.failed':
        facts += [(L('f.file'), d.get('file')), (L('f.error'), d.get('error'))]
        path = '/admin/system'
    elif event == 'system.version_changed':
        kw.update(previous=_v(d.get('previous'), 40), current=_v(d.get('current'), 40))
        facts.append((L('f.node'), cfg['node']['id']))
        path = '/admin/system'
    elif event == 'alert.created':
        kind = d.get('kind') or 'other'
        kw['kind'] = L('k.' + kind) if ('k.' + kind) in TEXT['en'] else kind
        sev = d.get('alert_severity') if d.get('alert_severity') in SEVERITIES else 'warning'
        for k, label in (('host', 'f.host'), ('path', 'f.path'), ('count', 'f.count')):
            if d.get(k):
                facts.append((L(label), d[k]))
        text = d.get('reason') or ''
        path = d.get('link') or '/alerts'
    elif event == 'report.daily':
        kw['day'] = _v(d.get('day'), 20)
        def cnt(k):
            cur, prev = int(d.get(k) or 0), d.get('prev_' + k)
            return '%d（%s %s）' % (cur, L('f.vs'), prev) if prev is not None and lang == 'zh-TW' else \
                ('%d (%s %s)' % (cur, L('f.vs'), prev) if prev is not None else str(cur))
        facts += [(L('f.events'), cnt('events')), (L('f.blocked'), cnt('blocked')), (L('f.logged'), cnt('logged')),
                  (L('f.sources'), d.get('sources', 0))]
        if d.get('top_hosts'):
            facts.append((L('f.top_hosts'), ', '.join('%s %s' % (h, n) for h, n in d['top_hosts'][:3])))
        if d.get('top_rules'):
            facts.append((L('f.top_rules'), ', '.join('%s %s' % (r, n) for r, n in d['top_rules'][:3])))
        facts += [(L('f.open_alerts'), d.get('open_alerts', 0)), (L('f.applied'), d.get('applied', 0)),
                  (L('f.proposed'), d.get('proposed', 0))]
        if d.get('open_alerts'):
            sev = 'warning'
        path = '/'
    elif event == 'alert.reminder':
        kw['open'] = _int(d.get('open')) or 0
        for it in (d.get('items') or [])[:5]:
            kind = it.get('kind') or 'other'
            facts.append(('#%s' % _int(it.get('id')), (L('k.' + kind) if ('k.' + kind) in TEXT['en'] else kind)
                          + (' · ' + it['summary'] if it.get('summary') else '')))
        path = '/alerts'
    elif event in ('user.created', 'token.created', 'settings.changed'):
        facts.append((L('f.by'), d.get('_actor')))
        for k in ('target', 'username', 'name', 'key'):
            if d.get(k):
                facts.append((L('f.key') if k == 'key' else L('f.target'), d[k]))
        path = '/admin/audit'
    if d.get('change_id') is not None and not cid:
        facts.append((L('f.change'), d['change_id']))
    title = _t(lang, event, **kw)
    return Msg(title, sev, [(a, _v(b)) for a, b in facts if b not in (None, '', [])], _v(text, 600), _link(cfg, path), lang)


def still_relevant(db, event, d):
    """False when the message no longer says anything true (an approval request for a change that is decided)."""
    if event == 'change.awaiting_approval' and _int(d.get('change_id')):
        r = db.one('SELECT state FROM changes WHERE id=?', (_int(d['change_id']),))
        return bool(r and r['state'] == 'pending_approval')
    if event in ('alert.created',) and _int(d.get('alert_id')):
        r = db.one('SELECT state FROM alerts WHERE id=?', (_int(d['alert_id']),))
        return bool(r and r['state'] == 'open')
    return True


# --- formats per channel ----------------------------------------------------------------------------------------

EMOJI = {'critical': '\U0001F6A8', 'warning': '⚠️', 'info': 'ℹ️', 'success': '✅'}
COLOR = {'critical': 0xD93025, 'warning': 0xE8A317, 'info': 0x1A73E8, 'success': 0x188038}
TEAMS_STYLE = {'critical': 'attention', 'warning': 'warning', 'info': 'accent', 'success': 'good'}


def _head(m):
    return '%s %s' % (EMOJI.get(m.severity, ''), m.title)


def _code(s):
    """Markdown code span (Zulip, Nextcloud, Slack, Discord): a backtick in the value cannot end it."""
    return '`' + s.replace('`', "'") + '`'


_FULLWIDTH = str.maketrans({'[': '［', ']': '］', '*': '＊', '_': '＿', '`': '｀', '<': '＜', '>': '＞', '@': '＠', '\\': '＼'})


def _md_escape(s):
    """Teams Adaptive Card text: markdown characters become their full-width look-alikes (backslash escapes are
    not honoured everywhere), so a value can never become a link, emphasis or a mention; a bare address is broken
    with a zero-width space so Teams does not turn it into a link either."""
    s = re.sub(r'(?i)(https?|ftp)://', lambda m: m.group(1) + ':\u200b//', s.translate(_FULLWIDTH))
    return re.sub(r'(?i)\bwww\.', 'www\u200b.', s)


def _nomention(s):
    """Chat services find mentions (@all, @**all**, @channel) in the raw text, even inside code: never let a value
    contain a usable @."""
    return s.replace('@', '＠')


def fmt_text(m):
    lines = [_head(m)]
    if m.text:
        lines.append(m.text)
    lines += ['%s: %s' % (a, b) for a, b in m.facts]
    if m.link:
        lines.append('%s: %s' % (m.open_label, m.link))
    return '\n'.join(lines)


def fmt_markdown(m):
    lines = ['**%s**' % _head(m)]
    if m.text:
        lines.append(_code(m.text))
    lines += ['- %s: %s' % (a, _code(b)) for a, b in m.facts]
    if m.link:
        lines += ['', '[%s](%s)' % (m.open_label, m.link)]
    return '\n'.join(lines)


def fmt_telegram(m):
    e = html.escape
    parts = ['<b>%s</b>' % e(_head(m))]
    if m.text:
        parts.append('<code>%s</code>' % e(m.text))
    parts += ['%s: <code>%s</code>' % (e(a), e(b)) for a, b in m.facts]
    if m.link:
        parts.append('<a href="%s">%s</a>' % (e(m.link, quote=True), e(m.open_label)))
    return '\n'.join(parts)


def fmt_slack(m):
    esc = lambda s: s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')   # noqa: E731
    lines = ['*%s*' % esc(_head(m))]
    if m.text:
        lines.append(_code(esc(m.text)))
    lines += ['*%s*: %s' % (esc(a), _code(esc(b))) for a, b in m.facts]
    blocks = [{'type': 'section', 'text': {'type': 'mrkdwn', 'text': '\n'.join(lines)}}]
    if m.link:
        blocks.append({'type': 'actions', 'elements': [{'type': 'button', 'url': m.link,
                                                        'text': {'type': 'plain_text', 'text': m.open_label}}]})
    return {'text': _head(m)[:150], 'blocks': blocks}


def fmt_discord(m):
    emb = {'title': _head(m)[:256], 'color': COLOR.get(m.severity, 0x5F6368),
           'fields': [{'name': a[:256], 'value': _code(b)[:1024], 'inline': len(b) < 40} for a, b in m.facts[:25]],
           'footer': {'text': 'jt-waf-mgr'}}
    if m.text:
        emb['description'] = _code(m.text)[:4000]
    if m.link:
        emb['url'] = m.link
    return {'username': 'jt-waf-mgr', 'embeds': [emb], 'allowed_mentions': {'parse': []}}


def fmt_teams(m):
    body = [{'type': 'Container', 'style': TEAMS_STYLE.get(m.severity, 'emphasis'), 'bleed': True,
             'items': [{'type': 'TextBlock', 'text': _md_escape(_head(m)), 'weight': 'Bolder', 'size': 'Medium',
                        'wrap': True}]}]
    if m.text:
        body.append({'type': 'TextBlock', 'text': _md_escape(m.text), 'wrap': True})
    if m.facts:
        body.append({'type': 'FactSet', 'facts': [{'title': _md_escape(a), 'value': _md_escape(b)} for a, b in m.facts]})
    card = {'$schema': 'http://adaptivecards.io/schemas/adaptive-card.json', 'type': 'AdaptiveCard',
            'version': '1.4', 'body': body, 'msteams': {'width': 'Full'}}
    if m.link:
        card['actions'] = [{'type': 'Action.OpenUrl', 'title': m.open_label, 'url': m.link}]
    return {'type': 'message', 'attachments': [{'contentType': 'application/vnd.microsoft.card.adaptive',
                                                 'contentUrl': None, 'content': card}]}


def fmt_email_html(m):
    e = html.escape
    color = '#%06x' % COLOR.get(m.severity, 0x5F6368)
    rows = ''.join('<tr><td style="padding:2px 12px 2px 0;color:#555">%s</td><td><code>%s</code></td></tr>' % (e(a), e(b))
                   for a, b in m.facts)
    text = '<p><code>%s</code></p>' % e(m.text) if m.text else ''
    link = '<p><a href="%s">%s</a></p>' % (e(m.link, quote=True), e(m.open_label)) if m.link else ''
    return ('<!doctype html><html><body style="font-family:sans-serif">'
            '<h3 style="border-left:4px solid %s;padding-left:8px">%s</h3>%s<table>%s</table>%s'
            '<p style="color:#888;font-size:12px">jt-waf-mgr</p></body></html>') % (color, e(m.title), text, rows, link)


# --- sending ----------------------------------------------------------------------------------------------------

class SendError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None          # a redirect is an error: never follow to a target that was not configured


_OPENER = None


def _opener():
    global _OPENER
    if _OPENER is None:
        _OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                              urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return _OPENER


def _error_detail(body):
    """A short, safe reason from an error response (JSON APIs say why); never the whole page."""
    try:
        j = json.loads(body[:4000].decode('utf-8', 'replace'))
    except ValueError:
        s = body[:200].decode('utf-8', 'replace')
        return _v(s, 120) if s and '<' not in s else ''
    if isinstance(j, dict):
        for k in ('description', 'msg', 'message', 'error'):
            if isinstance(j.get(k), str):
                return _v(j[k], 160)
    return ''


ALLOW_LOCAL = False      # tests send to fake endpoints on 127.0.0.1


def _check_target(url):
    """Never this host's own loopback or a link-local address (cloud metadata services live there)."""
    import ipaddress
    import socket
    host = urllib.parse.urlsplit(url).hostname or ''
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        raise SendError('cannot resolve the host name')
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped           # ::ffff:127.0.0.1 is 127.0.0.1
        if (ip.is_loopback and not ALLOW_LOCAL) or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            raise SendError('refusing a loopback / link-local address')


def http_post(url, body, headers):
    _check_target(url)
    req = urllib.request.Request(url, data=body, method='POST', headers=dict(headers, **{'User-Agent': 'jt-waf-mgr/' + __version__}))
    try:
        with _opener().open(req, timeout=TIMEOUT) as r:
            r.read(65536)
            return r.status
    except urllib.error.HTTPError as e:
        try:
            detail = _error_detail(e.read(4000))
        except Exception:
            detail = ''
        finally:
            e.close()
        raise SendError('HTTP %d%s' % (e.code, (': ' + detail) if detail else ''))
    except urllib.error.URLError as e:
        raise SendError('connection failed: %s' % _v(getattr(e, 'reason', e), 160))
    except (OSError, ValueError) as e:
        raise SendError('%s: %s' % (type(e).__name__, _v(e, 160)))


def _json_post(url, obj, headers=None):
    return http_post(url, json.dumps(obj, ensure_ascii=False).encode('utf-8'),
                     dict({'Content-Type': 'application/json'}, **(headers or {})))


def send_email(n, m):
    msg = email.message.EmailMessage()
    msg['Subject'] = _v('[jt-waf-mgr] ' + m.title, 200)
    msg['From'] = n['smtp_from']
    msg['To'] = ', '.join(n['email_to'])
    msg['Date'] = email.utils.formatdate(localtime=True)
    msg['Message-ID'] = email.utils.make_msgid(domain=n['smtp_from'].rsplit('@', 1)[-1])
    msg.set_content(fmt_text(m))
    msg.add_alternative(fmt_email_html(m), subtype='html')
    if n['smtp_username'] and n['smtp_tls'] == 'none':
        raise SendError('refusing to send the SMTP password without TLS (choose STARTTLS or TLS)')
    ctx = ssl.create_default_context()
    try:
        if n['smtp_tls'] == 'tls':
            s = smtplib.SMTP_SSL(n['smtp_host'], n['smtp_port'], timeout=TIMEOUT, context=ctx)
        else:
            s = smtplib.SMTP(n['smtp_host'], n['smtp_port'], timeout=TIMEOUT)
        with s:
            if n['smtp_tls'] == 'starttls':
                s.starttls(context=ctx)
            if n['smtp_username']:
                s.login(n['smtp_username'], n['smtp_password'])
            s.send_message(msg)
    except smtplib.SMTPException as e:
        raise SendError('SMTP: %s' % _v(e, 160))
    except (OSError, ssl.SSLError) as e:
        raise SendError('connection failed: %s' % _v(e, 160))


def _fit(m, fmt, size, limit):
    """Drop facts until the formatted message fits (never cut inside an escape or a code span)."""
    out = fmt(m)
    for _ in range(200):
        if size(out) <= limit:
            break
        m = m.shorter()
        out = fmt(m)
    return out


def send_telegram(n, m):
    _json_post('%s/bot%s/sendMessage' % (TELEGRAM_API, n['telegram_token']),
               {'chat_id': n['telegram_chat_id'], 'text': _fit(m.chat(), fmt_telegram, len, 4000), 'parse_mode': 'HTML',
                'disable_web_page_preview': True})


def send_zulip(n, m):
    auth = base64.b64encode(('%s:%s' % (n['zulip_bot_email'], n['zulip_api_key'])).encode()).decode()
    body = urllib.parse.urlencode({'type': 'stream', 'to': n['zulip_stream'], 'topic': n['zulip_topic'] or 'jt-waf-mgr',
                                   'content': _fit(m.chat(), fmt_markdown, len, 9000)}).encode()
    http_post(n['zulip_site'].rstrip('/') + '/api/v1/messages', body,
              {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + auth})


def send_nextcloud(n, m):
    message = _fit(m.chat(), fmt_markdown, len, 30000)
    rnd = secrets.token_hex(32)
    sig = hmac.new(n['nextcloud_secret'].encode(), (rnd + message).encode(), hashlib.sha256).hexdigest()
    _json_post('%s/ocs/v2.php/apps/spreed/api/v1/bot/%s/message' % (n['nextcloud_url'].rstrip('/'), n['nextcloud_token']),
               {'message': message}, {'OCS-APIRequest': 'true', 'Accept': 'application/json',
                                      'X-Nextcloud-Talk-Bot-Random': rnd, 'X-Nextcloud-Talk-Bot-Signature': sig})


def webhook_body(cfg, event, m, row):
    return {'app': 'jt-waf-mgr', 'version': __version__, 'node': cfg['node']['id'], 'event': event,
            'severity': m.severity, 'title': m.title, 'text': m.text, 'facts': [{'label': a, 'value': b} for a, b in m.facts],
            'link': m.link, 'id': row['id'], 'audit_id': row['audit_id'], 'test': bool(row['test']),
            'ts': util.iso(row['created_at'])}


def send_webhook(n, m, cfg, event, row):
    body = json.dumps(webhook_body(cfg, event, m, row), ensure_ascii=False).encode('utf-8')
    ts = str(int(time.time()))
    h = {'Content-Type': 'application/json', 'X-Jt-Waf-Mgr-Event': event, 'X-Jt-Waf-Mgr-Timestamp': ts}
    if n['webhook_secret']:
        h['X-Jt-Waf-Mgr-Signature'] = 'sha256=' + hmac.new(n['webhook_secret'].encode(), ts.encode() + b'.' + body,
                                                           hashlib.sha256).hexdigest()
    if n['webhook_token']:
        h['Authorization'] = 'Bearer ' + n['webhook_token']
    http_post(n['webhook_url'], body, h)


def send(cfg, ch, event, m, row):
    n = cfg['notify']
    if ch == 'email':
        send_email(n, m)
    elif ch == 'telegram':
        send_telegram(n, m)
    elif ch == 'teams':
        _json_post(n['teams_webhook'], fmt_teams(m))
    elif ch == 'slack':
        _json_post(n['slack_webhook'], _fit(m.chat(), fmt_slack, lambda o: len(o['blocks'][0]['text']['text']), 2900))
    elif ch == 'discord':
        _json_post(n['discord_webhook'], fmt_discord(m.chat()))
    elif ch == 'zulip':
        send_zulip(n, m)
    elif ch == 'nextcloud':
        send_nextcloud(n, m)
    elif ch == 'webhook':
        send_webhook(n, m, cfg, event, row)
    else:
        raise SendError('unknown channel')


SECRET_KEYS = ('smtp_password', 'telegram_token', 'teams_webhook', 'slack_webhook', 'discord_webhook', 'zulip_api_key',
               'nextcloud_secret', 'webhook_url', 'webhook_secret', 'webhook_token')


def scrub(cfg, s):
    for k in SECRET_KEYS:
        v = cfg['notify'].get(k)
        if v and len(v) >= 6:
            s = s.replace(v, '[secret]')
            for part in re.split(r'[/?&=:]', v):
                if len(part) >= 16:
                    s = s.replace(part, '[secret]')
    return s


def process(app, row, broken=None):
    """Send one queued message. Returns the new status."""
    cfg, db = app.cfg, app.db
    n, ch, now = cfg['notify'], row['channel'], util.now()
    try:
        d = json.loads(row['details'] or '{}')
    except ValueError:
        d = {}

    def done(status, error):
        db.x('UPDATE notifications SET status=?, error=? WHERE id=?', (status, error, row['id']))
        return status
    if not configured(n, ch):
        return done('failed', 'not_configured')
    if not row['test'] and not active(n, ch):
        return done('skipped', 'channel_off')
    if not row['test'] and not still_relevant(db, row['event'], d):
        return done('skipped', 'obsolete')
    if not row['test']:
        sent = db.one("SELECT COUNT(*) FROM notifications WHERE channel=? AND status='sent' AND sent_at>?",
                      (ch, now - 3600))[0]
        if sent >= n['max_per_hour'] * (3 if row['severity'] == 'critical' else 1):
            return done('suppressed', 'max_per_hour')
    try:
        m = render(db, cfg, row['event'], d)
        send(cfg, ch, row['event'], m, row)
    except SendError as e:
        attempts = row['attempts'] + 1
        err = scrub(cfg, str(e))
        if broken is not None and err.startswith(('connection failed', 'cannot resolve', 'TimeoutError', 'timeout')):
            broken.add(ch)
        if attempts <= len(BACKOFF) and not row['test']:
            db.x("UPDATE notifications SET status='pending', attempts=?, next_at=?, error=? WHERE id=?",
                 (attempts, now + BACKOFF[attempts - 1], util.clip(err, 300), row['id']))
            return 'retry'
        db.x("UPDATE notifications SET status='failed', attempts=?, error=? WHERE id=?", (attempts, util.clip(err, 300), row['id']))
        app.audit.log('notify.failed', 'system', 'system', None, 'failed', notification=row['id'], channel=ch,
                      event=row['event'], error=util.clip(err, 200), test=bool(row['test']))
        return 'failed'
    db.x("UPDATE notifications SET status='sent', attempts=attempts+1, sent_at=?, error=NULL WHERE id=?", (now, row['id']))
    return 'sent'


def remind(app):
    """One reminder listing the open alerts, every notify.remind_hours (counted from the newest reminder)."""
    cfg, db = app.cfg, app.db
    hours = cfg['notify']['remind_hours']
    if not hours:
        return 0
    now = util.now()
    rows = db.q("SELECT id, kind, severity, details, created_at, reminded_at FROM alerts WHERE state='open' ORDER BY id")
    due = [r for r in rows if now - (r['reminded_at'] or r['created_at']) >= hours * 3600]
    if not due:
        return 0
    from .alerts import summary
    items = [{'id': r['id'], 'kind': r['kind'], 'summary': summary(r)} for r in rows[:5]]
    enqueue(db, cfg, 'alert.reminder', {'open': len(rows), 'items': items}, severity='critical' if any(
        r['severity'] == 'critical' for r in rows) else 'warning')
    db.x("UPDATE alerts SET reminded_at=? WHERE state='open'", (now,))
    return len(rows)


def daily_report(app, now=None):
    """Once a day at notify.report_hour: what happened in the last 24 hours. Returns the details, or None."""
    cfg, db = app.cfg, app.db
    hour = cfg['notify'].get('report_hour', -1)
    if hour is None or hour < 0:
        return None
    now = now or util.now()
    lt = time.localtime(now)
    day = time.strftime('%Y-%m-%d', lt)
    if lt.tm_hour < hour or db.get_meta('notify.report_day') == day:
        return None
    db.set_meta('notify.report_day', day)        # first: one report a day even if sending fails later
    since, prev = now - 86400, now - 2 * 86400

    def counts(a, b):
        r = db.one("SELECT COUNT(*) n, SUM(outcome='blocked') b, SUM(outcome='logged') l FROM events WHERE ts>=? AND ts<?", (a, b))
        return r['n'] or 0, r['b'] or 0, r['l'] or 0
    n, b, lg = counts(since, now)
    pn, pb, pl = counts(prev, since)
    d = {'day': day, 'events': n, 'blocked': b, 'logged': lg, 'prev_events': pn, 'prev_blocked': pb, 'prev_logged': pl,
         'sources': db.one("SELECT COUNT(DISTINCT src_ip) FROM events WHERE ts>=? AND origin='external'", (since,))[0],
         # the time index first (the day's rows), then group: never a scan of the whole history
         'top_hosts': [[r['host'], r['c']] for r in db.q('SELECT host, COUNT(*) c FROM events INDEXED BY events_ts WHERE ts>=? '
                                                          'GROUP BY host ORDER BY c DESC LIMIT 3', (since,))],
         'top_rules': [[r['rule_id'], r['c']] for r in db.q(
             'SELECT er.rule_id, COUNT(*) c FROM events e INDEXED BY events_ts JOIN event_rules er ON er.event_id=e.id '
             'WHERE e.ts>=? AND er.rule_id NOT IN (%s) GROUP BY er.rule_id ORDER BY c DESC LIMIT 3'
             % ','.join(str(int(x)) for x in sorted(util.SCORING_RULES)), (since,))],
         'open_alerts': db.one("SELECT COUNT(*) FROM alerts WHERE state='open'")[0],
         'applied': db.one("SELECT COUNT(*) FROM audit WHERE action='change.applied' AND ts>=?", (since,))[0],
         'proposed': db.one("SELECT COUNT(*) FROM changes WHERE proposed_by='analyst' AND created_at>=?", (since,))[0]}
    enqueue(db, cfg, 'report.daily', d, severity='warning' if d['open_alerts'] else 'info')
    return d


def run(app, log=print, limit=200):
    """jt-waf-mgr-notify.service: send what is due, remind open alerts, forget old rows."""
    cfg, db = app.cfg, app.db
    try:
        os.unlink(request_file(cfg))     # first: the path unit starts the job again while it exists
    except OSError:
        pass
    now = util.now()
    db.x("UPDATE notifications SET status='pending' WHERE status='sending' AND next_at<?", (now - 600,))
    try:
        remind(app)
    except Exception as e:      # a reminder problem must not stop the sending
        log('notify: reminder failed: %s' % type(e).__name__)
    counts = {}
    broken = set()
    for _ in range(3):          # rows queued while sending (a failure audit, a reminder) go out in the same run
        rows = db.q("SELECT * FROM notifications WHERE status='pending' AND next_at<=? ORDER BY id LIMIT ?", (util.now(), limit))
        if not rows:
            break
        for r in rows:
            if r['channel'] in broken:
                # this channel did not answer a moment ago: try its other messages next time
                db.x("UPDATE notifications SET next_at=? WHERE id=? AND status='pending'", (util.now() + 60, r['id']))
                counts['deferred'] = counts.get('deferred', 0) + 1
                continue
            if db.x("UPDATE notifications SET status='sending', next_at=? WHERE id=? AND status='pending'",
                    (util.now(), r['id'])).rowcount != 1:
                continue
            st = process(app, r, broken)
            counts[st] = counts.get(st, 0) + 1
    try:      # after what was due went out: the counting never delays an urgent message
        if cfg['notify']['enabled'] and daily_report(app):
            for r in db.q("SELECT * FROM notifications WHERE status='pending' AND event='report.daily' AND next_at<=?", (util.now(),)):
                if db.x("UPDATE notifications SET status='sending' WHERE id=? AND status='pending'", (r['id'],)).rowcount == 1:
                    st = process(app, r, broken)
                    counts[st] = counts.get(st, 0) + 1
    except Exception as e:
        log('notify: daily report failed: %s' % type(e).__name__)
    db.x('DELETE FROM notifications WHERE created_at<?', (now - KEEP_DAYS * 86400,))
    db.set_meta('notify.last_run', util.iso(now))
    if counts:
        log('notify: %s' % ', '.join('%s %d' % kv for kv in sorted(counts.items())))
    return counts


# --- reading (API) ---------------------------------------------------------------------------------------------

def delivery(r):
    try:
        d = json.loads(r['details'] or '{}')
    except ValueError:
        d = {}
    keep = {k: d[k] for k in ('change_id', 'run_id', 'alert_id', 'snapshot', 'kind') if k in d}
    return {'id': r['id'], 'created_at': util.iso(r['created_at']), 'event': r['event'], 'severity': r['severity'],
            'channel': r['channel'], 'status': r['status'], 'attempts': r['attempts'], 'error': r['error'],
            'sent_at': util.iso(r['sent_at']) if r['sent_at'] else None, 'test': bool(r['test']),
            'requested_by': r['requested_by'], 'ref': keep}


def status(app):
    n, db = app.cfg['notify'], app.db
    since = util.now() - 86400
    counts = {}
    for r in db.q('SELECT channel, status, COUNT(*) AS c FROM notifications WHERE created_at>? GROUP BY channel, status', (since,)):
        counts.setdefault(r['channel'], {})[r['status']] = r['c']
    return {'enabled': bool(n['enabled']), 'last_run': db.get_meta('notify.last_run'),
            'pending': db.one("SELECT COUNT(*) FROM notifications WHERE status IN ('pending', 'sending')")[0],
            'channels': [{'channel': c, 'enabled': bool(n.get(c + '_enabled')), 'configured': configured(n, c),
                          'active': active(n, c), 'last_24h': counts.get(c, {})} for c in CHANNELS],
            'events': [{'event': e, 'category': cat, 'severity': sev, 'default': on} for e, (cat, sev, on) in EVENTS.items()],
            'matrix': matrix(n), 'channel_list': list(CHANNELS)}


def today():
    return datetime.date.today().isoformat()
