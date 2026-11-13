"""Settings people change in the web interface (admin, audited), stored in the database and laid over the
configuration file. config.toml keeps what the program needs to start (paths, listen address, node id).

- Every editable key is declared here with its type and limits; a change is validated by building the whole
  configuration again (the same checks as at start-up) before it is stored and applied.
- Secrets are write-only: the API reports only whether one is set and its last characters.
- The GeoIP updater runs in its own restricted unit that cannot read the database: its account and key are
  also written to the GeoIP directory (0600, service user) whenever they change.
"""
import copy
import json
import os
import re

from . import util
from .config import FACILITIES, Config, ConfigError, GEOIP_EDITIONS, LANGUAGES, ROLES  # noqa: F401

PREFIX = 'ui.'
EMAIL_RE = r'[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}'
HTTPS_URL_RE = r'(https://[A-Za-z0-9.-]+(?::\d{1,5})?/[^\s"\'<>\\]{0,1990})?'
# a URL setting and the secret that belongs to that server: a stored secret is never sent to a different server
# unless it is entered again (or cleared)
BOUND = {'llm.url': ('llm.api_key',), 'notify.zulip_site': ('notify.zulip_api_key',),
         'notify.nextcloud_url': ('notify.nextcloud_secret',), 'notify.smtp_host': ('notify.smtp_password',),
         'notify.webhook_url': ('notify.webhook_token', 'notify.webhook_secret')}
SECRET = object()

# key -> (type, extra): type is bool | int | str | list | secret | choice
EDITABLE = {
    # GeoIP
    'geoip.enabled': ('bool', {}),
    'geoip.account_id': ('str', {'re': r'\d{0,12}', 'max': 12}),
    'geoip.license_key': ('secret', {'re': r'[A-Za-z0-9_]{0,80}'}),
    'geoip.editions': ('list', {'choices': GEOIP_EDITIONS, 'max_items': 6}),
    'geoip.update_days': ('int', {'min': 1, 'max': 60}),
    # local LLM for the event analysis
    'llm.enabled': ('bool', {}),
    'llm.url': ('str', {'re': r'(https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[\w./-]*)?)?', 'max': 300}),
    'llm.model': ('str', {'re': r'[\w.:/-]{0,120}', 'max': 120}),
    'llm.api_key': ('secret', {'re': r'[\x21-\x7e]{0,300}'}),
    'llm.timeout_seconds': ('int', {'min': 10, 'max': 900}),
    # scheduled event analysis
    'analyst.enabled': ('bool', {}),
    'analyst.interval_minutes': ('int', {'min': 10, 'max': 10080}),
    'analyst.window_hours': ('int', {'min': 1, 'max': 720}),
    'analyst.max_proposals': ('int', {'min': 0, 'max': 20}),
    'analyst.min_events': ('int', {'min': 1, 'max': 10000}),
    'analyst.min_sources': ('int', {'min': 1, 'max': 1000}),
    'analyst.rules': ('bool', {}),
    # notifications (sent by jt-waf-mgr-notify.service; see notify.py)
    'notify.enabled': ('bool', {}),
    'notify.language': ('choice', {'choices': LANGUAGES}),
    'notify.base_url': ('str', {'re': r'(https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[\w./-]*)?)?', 'max': 300}),
    'notify.max_per_hour': ('int', {'min': 1, 'max': 1000}),
    'notify.remind_hours': ('int', {'min': 0, 'max': 720}),
    'notify.report_hour': ('int', {'min': -1, 'max': 23}),
    'notify.matrix': ('matrix', {}),
    'notify.email_enabled': ('bool', {}),
    'notify.smtp_host': ('str', {'re': r'[A-Za-z0-9.:-]{0,253}', 'max': 253}),
    'notify.smtp_port': ('int', {'min': 1, 'max': 65535}),
    'notify.smtp_tls': ('choice', {'choices': ('starttls', 'tls', 'none')}),
    'notify.smtp_username': ('str', {'re': r'[\x21-\x7e]{0,200}', 'max': 200}),
    'notify.smtp_password': ('secret', {'re': r'[^\x00-\x1f\x7f]{0,200}'}),
    'notify.smtp_from': ('str', {'re': EMAIL_RE + '|', 'max': 254}),
    'notify.email_to': ('list', {'re': EMAIL_RE, 'max_items': 20}),
    'notify.telegram_enabled': ('bool', {}),
    'notify.telegram_token': ('secret', {'re': r'(\d{3,15}:[A-Za-z0-9_-]{20,100})?'}),
    'notify.telegram_chat_id': ('str', {'re': r'(-?\d{1,20}|@[A-Za-z0-9_]{4,64})?', 'max': 65}),
    'notify.teams_enabled': ('bool', {}),
    'notify.teams_webhook': ('secret', {'re': HTTPS_URL_RE, 'max': 2000}),
    'notify.slack_enabled': ('bool', {}),
    'notify.slack_webhook': ('secret', {'re': HTTPS_URL_RE, 'max': 2000}),
    'notify.discord_enabled': ('bool', {}),
    'notify.discord_webhook': ('secret', {'re': HTTPS_URL_RE, 'max': 2000}),
    'notify.zulip_enabled': ('bool', {}),
    'notify.zulip_site': ('str', {'re': r'(https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[\w./-]*)?)?', 'max': 300}),
    'notify.zulip_bot_email': ('str', {'re': EMAIL_RE + '|', 'max': 254}),
    'notify.zulip_api_key': ('secret', {'re': r'[A-Za-z0-9]{0,128}'}),
    'notify.zulip_stream': ('str', {'re': r'[^\x00-\x1f\x7f]{0,60}', 'max': 60}),
    'notify.zulip_topic': ('str', {'re': r'[^\x00-\x1f\x7f]{0,60}', 'max': 60}),
    'notify.nextcloud_enabled': ('bool', {}),
    'notify.nextcloud_url': ('str', {'re': r'(https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[\w./-]*)?)?', 'max': 300}),
    'notify.nextcloud_token': ('str', {'re': r'[A-Za-z0-9]{0,64}', 'max': 64}),
    'notify.nextcloud_secret': ('secret', {'re': r'[\x21-\x7e]{0,200}'}),
    'notify.webhook_enabled': ('bool', {}),
    'notify.webhook_url': ('secret', {'re': r'(https?://[^\s"\'<>\\]{1,1990})?', 'max': 2000}),
    'notify.webhook_secret': ('secret', {'re': r'[\x21-\x7e]{0,200}'}),
    'notify.webhook_token': ('secret', {'re': r'[\x21-\x7e]{0,500}'}),
    # syslog (audit rows as one JSON line each)
    'syslog.enabled': ('bool', {}),
    'syslog.address': ('str', {'re': r'/[\w./-]{1,200}|(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]{1,253}):\d{1,5}', 'max': 260}),
    'syslog.protocol': ('choice', {'choices': ('udp', 'tcp', 'tls')}),
    'syslog.format': ('choice', {'choices': ('rfc3164', 'rfc5424')}),
    'syslog.facility': ('choice', {'choices': tuple(FACILITIES)}),
    'blocks.enabled': ('bool', {}),
    'blocks.protected': ('list', {'cidr': True, 'max_items': 200}),
    'blocks.max_active': ('int', {'min': 1, 'max': 20000}),
    'blocks.max_per_token': ('int', {'min': 1, 'max': 20000}),
    'blocks.token_per_hour': ('int', {'min': 1, 'max': 100000}),
    'blocks.default_ttl': ('int', {'min': 10, 'max': 2592000}),
    'blocks.api_max_ttl': ('int', {'min': 60, 'max': 2592000}),
    'blocks.ui_max_ttl': ('int', {'min': 60, 'max': 2592000}),
    'blocks.reload_seconds': ('int', {'min': 5, 'max': 3600}),
    'blocks.auto_recon': ('bool', {}),
    'blocks.auto_recon_paths': ('int', {'min': 3, 'max': 100}),
    'blocks.auto_recon_minutes': ('int', {'min': 5, 'max': 1440}),
    'blocks.auto_recon_ttl': ('int', {'min': 600, 'max': 2592000}),
    'blocks.auto_recon_per_hour': ('int', {'min': 1, 'max': 1000}),
    'traffic.enabled': ('bool', {}),
    'traffic.logs': ('list', {'re': r'/[\w./*-]{1,300}', 'max_items': 20}),
    'traffic.keep_days': ('int', {'min': 1, 'max': 3650}),
    'traffic.alert': ('bool', {}),
    'traffic.spike_factor': ('int', {'min': 2, 'max': 100}),
    'traffic.min_requests': ('int', {'min': 10, 'max': 1000000000}),
    'traffic.error_percent': ('int', {'min': 1, 'max': 100}),
    'crs.manage': ('bool', {}),
    'crs.wait_days': ('int', {'min': 0, 'max': 60}),
    'syslog.payload': ('choice', {'choices': ('json', 'cef', 'leef', 'gelf', 'kv')}),
    'syslog.content': ('list', {'choices': ('audit', 'event', 'alert'), 'max_items': 3}),
    'syslog.more': ('destinations', {}),       # the other log servers (up to 7), each with its own format and content
    # interface, people and policy
    'ui.login_notice': ('str', {'max': 2000, 'multiline': True}),
    'compliance.level': ('choice', {'choices': ('', 'low', 'medium', 'high')}),
    'managed.imported_author': ('choice', {'choices': ('site', 'jason_tools')}),
    'waf.focus_sites': ('list', {'re': r'[a-z0-9.-]{1,253}', 'max_items': 50}),
    'network.known_scanners': ('list', {'cidr': True, 'max_items': 200}),
    'evidence.catch_all_hosts': ('list', {'re': r'[a-z0-9.-]{1,253}', 'max_items': 50}),
    'integrity.automation_paths': ('list', {'re': r'/[\w./*-]{1,300}', 'max_items': 50}),
    'auth.password_max_age_days': ('int', {'min': 0, 'max': 3650}),
    'auth.password_min_age_hours': ('int', {'min': 0, 'max': 720}),
    'auth.password_history': ('int', {'min': 0, 'max': 24}),
    'auth.dormant_days': ('int', {'min': 0, 'max': 3650}),
    'auth.max_sessions_per_user': ('int', {'min': 0, 'max': 100}),
    'auth.lockout_threshold': ('int', {'min': 3, 'max': 100}),
    'auth.lockout_minutes': ('int', {'min': 1, 'max': 1440}),
}


class SettingError(ValueError):
    def __init__(self, code, **details):
        super().__init__(code)
        self.code, self.details = code, details


def _validate(key, value):
    if key not in EDITABLE:
        raise SettingError('unknown_setting', key=key)
    kind, x = EDITABLE[key]
    if kind == 'bool':
        if not isinstance(value, bool):
            raise SettingError('invalid_value', key=key)
        return value
    if kind == 'int':
        if not isinstance(value, int) or isinstance(value, bool) or not x['min'] <= value <= x['max']:
            raise SettingError('invalid_value', key=key, min=x['min'], max=x['max'])
        return value
    if kind in ('str', 'secret'):
        if not isinstance(value, str):
            raise SettingError('invalid_value', key=key)
        value = value if x.get('multiline') else value.strip()
        if len(value) > x.get('max', 300) or '\x00' in value or (x.get('re') and not re.fullmatch(x['re'], value)):
            raise SettingError('invalid_value', key=key)
        return value
    if kind == 'choice':
        if value not in x['choices']:
            raise SettingError('invalid_value', key=key, choices=list(x['choices']))
        return value
    if kind == 'matrix':
        from .notify import CHANNELS, EVENTS
        if not isinstance(value, dict) or len(value) > len(EVENTS):
            raise SettingError('invalid_value', key=key)
        out = {}
        for ev, chs in value.items():
            if ev not in EVENTS or not isinstance(chs, list) or not all(c in CHANNELS for c in chs):
                raise SettingError('invalid_value', key=key, item=str(ev)[:80])
            out[ev] = [c for c in CHANNELS if c in chs]
        return out
    if kind == 'list':
        if not isinstance(value, list) or len(value) > x['max_items'] or not all(isinstance(v, str) for v in value):
            raise SettingError('invalid_value', key=key)
        out = []
        for v in (s.strip() for s in value):
            if not v:
                continue
            if x.get('choices') and v not in x['choices']:
                raise SettingError('invalid_value', key=key, item=v[:80])
            if x.get('re') and not re.fullmatch(x['re'], v):
                raise SettingError('invalid_value', key=key, item=v[:80])
            if x.get('cidr'):
                import ipaddress
                try:
                    v = str(ipaddress.ip_network(v, strict=False))
                except ValueError:
                    raise SettingError('invalid_value', key=key, item=v[:80])
            if v not in out:
                out.append(v)
        return out
    if kind == 'destinations':
        return _destinations(key, value)
    raise SettingError('unknown_setting', key=key)


_ADDR = re.compile(r'/[\w./-]{1,200}|(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]{1,253}):\d{1,5}')


def _destinations(key, value):
    """syslog.more: [{id, name, enabled, address, protocol, format, facility, payload, content}], up to 7."""
    if not isinstance(value, list) or len(value) > 7:
        raise SettingError('invalid_value', key=key)
    out, ids = [], set()
    for i, d in enumerate(value):
        if not isinstance(d, dict):
            raise SettingError('invalid_value', key=key, item=i)
        did = str(d.get('id') or 'd%d' % (i + 2))
        addr = str(d.get('address') or '').strip()
        name = str(d.get('name') or '').strip()
        content = d.get('content') if isinstance(d.get('content'), list) else []
        bad = (not re.fullmatch(r'[a-z0-9]{1,12}', did) or did in ids or did == 'main' or len(name) > 60
               or any(ord(ch) < 32 for ch in name) or not _ADDR.fullmatch(addr)
               or (not addr.startswith('/') and not 1 <= int(addr.rsplit(':', 1)[1]) <= 65535)
               or d.get('protocol', 'udp') not in ('udp', 'tcp', 'tls') or d.get('format', 'rfc3164') not in ('rfc3164', 'rfc5424')
               or d.get('facility', 'local0') not in FACILITIES or d.get('payload', 'json') not in ('json', 'cef', 'leef', 'gelf', 'kv')
               or not content or not all(c in ('audit', 'event', 'alert') for c in content)
               or (d.get('payload') == 'gelf' and addr.startswith('/')) or not isinstance(d.get('enabled', True), bool))
        if bad:
            raise SettingError('invalid_value', key=key, item=i)
        ids.add(did)
        out.append({'id': did, 'name': name, 'enabled': d.get('enabled', True), 'address': addr,
                    'protocol': d.get('protocol', 'udp'), 'format': d.get('format', 'rfc3164'),
                    'facility': d.get('facility', 'local0'), 'payload': d.get('payload', 'json'),
                    'content': [c for c in ('audit', 'event', 'alert') if c in content]})
    return out


LEGACY = {'analyst.interval_hours': ('analyst.interval_minutes', lambda v: max(10, int(v) * 60))}   # 0.3.4


def stored(db):
    out = {}
    rows = db.q('SELECT key, value, updated_by, updated_at FROM settings WHERE key LIKE ?', (PREFIX + '%',))
    keys = {r['key'][len(PREFIX):] for r in rows}
    for r in rows:
        k = r['key'][len(PREFIX):]
        if k in LEGACY and LEGACY[k][0] not in keys:      # a setting renamed since it was stored
            try:
                out[LEGACY[k][0]] = {'value': LEGACY[k][1](json.loads(r['value'])), 'by': r['updated_by'], 'at': r['updated_at']}
            except (ValueError, TypeError):
                pass
            continue
        if k in EDITABLE:
            try:
                out[k] = {'value': json.loads(r['value']), 'by': r['updated_by'], 'at': r['updated_at']}
            except ValueError:
                continue
    return out


def _with(data, key, value):
    sec, name = key.split('.', 1)
    data.setdefault(sec, {})[name] = value


def apply(cfg, db):
    """Lay the stored settings over the loaded configuration (at start). A stored value that no longer
    validates is skipped, never fatal."""
    for k, rec in stored(db).items():
        trial = copy.deepcopy(cfg.data)
        _with(trial, k, rec['value'])
        try:
            Config(trial, cfg.path)
        except (ConfigError, KeyError, TypeError, ValueError):
            continue
        _with(cfg.data, k, rec['value'])
    _refresh(cfg)


def _refresh(cfg):
    """Recompute the derived fields of a Config in place (network lists)."""
    fresh = Config(cfg.data, cfg.path)
    for attr in ('internal_networks', 'known_scanners', 'trusted_proxies'):
        setattr(cfg, attr, getattr(fresh, attr))


def public(cfg, db):
    """Every editable setting with its current value (secrets: set / hint only) and where it comes from."""
    st = stored(db)
    out = {}
    for k, (kind, x) in EDITABLE.items():
        sec, name = k.split('.', 1)
        v = cfg.data.get(sec, {}).get(name)
        item = {'type': kind, 'source': 'ui' if k in st else 'file',
                'updated_by': st[k]['by'] if k in st else None, 'updated_at': util.iso(st[k]['at']) if k in st else None}
        for lim in ('min', 'max', 'choices', 'max_items'):
            if lim in x:
                item[lim] = list(x[lim]) if isinstance(x[lim], tuple) else x[lim]
        if kind == 'secret':
            item.update(set=bool(v), hint=('…' + v[-4:]) if v and len(v) > 8 else ('set' if v else ''))
        else:
            item['value'] = v
        out[k] = item
    return out


def set_many(app, changes, actor, src_ip=None):
    """Validate every change against the whole configuration, then store and apply them together.
    Returns the list of keys changed. Secrets: an empty string clears, None leaves unchanged."""
    cfg, db = app.cfg, app.db
    clean = {}
    for k, v in (changes or {}).items():
        if k in EDITABLE and EDITABLE[k][0] == 'secret' and v is None:
            continue
        clean[k] = _validate(k, v)
    trial = copy.deepcopy(cfg.data)
    for k, v in clean.items():
        _with(trial, k, v)
    try:
        tc = Config(trial, cfg.path)
    except ConfigError as e:
        raise SettingError('invalid_configuration', reason=str(e)[:300])
    # a known scanner is an internal address (or a small internal range): 0.0.0.0/0 would silently turn every
    # "internal too" block off
    for n in tc.known_scanners:
        if n.prefixlen < (16 if n.version == 4 else 48) or not any(
                n.version == i.version and n.subnet_of(i) for i in tc.internal_networks):
            raise SettingError('scanner_outside_internal', key='network.known_scanners', item=str(n))
    # the stored API key is never sent to a different server unless it is entered again (or cleared)
    import urllib.parse

    def host(u):
        """scheme, host and port: a stored secret goes to exactly the server it was entered for"""
        u = u or ''
        if '://' not in u:
            return (u.lower(), None, None)
        s = urllib.parse.urlsplit(u)
        try:
            port = s.port
        except ValueError:
            port = None
        return ((s.hostname or '').lower(), s.scheme.lower(), port or {'https': 443, 'http': 80}.get(s.scheme.lower()))
    for uk, sks in BOUND.items():
        us, un = uk.split('.', 1)
        old_url = cfg.data.get(us, {}).get(un)
        if uk not in clean or host(clean[uk]) == host(old_url) or not host(old_url)[0]:
            continue
        for sk in sks:
            ss, sn = sk.split('.', 1)
            if cfg.data.get(ss, {}).get(sn) and sk not in clean:
                raise SettingError('key_required_for_new_host', key=sk)
    changed = []
    for k, v in clean.items():
        sec, name = k.split('.', 1)
        old = cfg.data.get(sec, {}).get(name)
        if old == v:
            continue
        db.x('INSERT OR REPLACE INTO settings(key, value, updated_by, updated_at) VALUES (?,?,?,?)',
             (PREFIX + k, json.dumps(v), actor, util.now()))
        secret = EDITABLE[k][0] == 'secret'
        entry = dict(key=k, old=None if secret else old, new=('(secret %s)' % ('cleared' if not v else 'set')) if secret else v)
        if k.startswith('syslog.'):
            # recorded with the old settings, before they change: the SIEM always sees where its copy went (or
            # that it was switched off)
            app.audit.log('settings.changed', actor, src_ip=src_ip,
                          severity='crit' if k == 'syslog.enabled' and not v else 'warning', **entry)
            _with(cfg.data, k, v)
        else:
            _with(cfg.data, k, v)
            app.audit.log('settings.changed', actor, src_ip=src_ip, **entry)
        changed.append(k)
    if changed:
        _refresh(cfg)
        if any(k.startswith('syslog.') for k in changed):
            app.audit.reconnect()          # the next record goes with the new settings
        if any(k.startswith('geoip.') for k in changed):
            write_geoip_files(cfg)
    return changed


def write_geoip_files(cfg):
    """The GeoIP updater runs without database access: hand it the account and key as files (0600)."""
    g = cfg['geoip']
    d = g['dir']
    try:
        os.makedirs(d, mode=0o750, exist_ok=True)
        for name, data in (('account.json', json.dumps({'account_id': g.get('account_id', ''),
                                                        'editions': g.get('editions'), 'update_days': g.get('update_days'),
                                                        'enabled': g.get('enabled')})),
                           ('license.key', (g.get('license_key') or '') + '\n')):
            tmp = os.path.join(d, '.' + name + '.tmp')
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as fh:
                fh.write(data)
            os.replace(tmp, os.path.join(d, name))
    except OSError:
        pass
