"""Configuration: one TOML file, every key optional, validated at load time.

TOML rather than YAML because tomllib is in the standard library (Python 3.11+), so the
service installs offline with no third-party packages at all.
"""
import copy
import ipaddress
import os
import re
import tomllib

DEFAULT_PATH = '/etc/jt-waf-mgr/config.toml'

DEFAULTS = {
    'node': {
        'id': 'waf1',
    },
    'server': {
        'listen': '127.0.0.1:8095',
        # Only these peers may set X-Real-IP / X-Forwarded-For (the local nginx).
        'trusted_proxies': ['127.0.0.1', '::1'],
        # Cookies get the __Host- prefix and Secure; turn off only for plain-HTTP local testing.
        'secure_cookies': True,
        'session_idle_minutes': 30,
        'session_max_hours': 12,
        'max_body_bytes': 1048576,
    },
    'paths': {
        'db': '/var/lib/jt-waf-mgr/jt-waf-mgr.db',
        'nginx_conf': '/etc/nginx/nginx.conf',
        'nginx_bin': '/usr/sbin/nginx',
        'audit_log': '/var/log/modsecurity/modsec_audit.log',
    },
    'collector': {
        'enabled': True,
        'poll_seconds': 2.0,
        # On the very first start, also import the rotated <audit_log>.1 if it is plain text.
        'backfill_rotated': True,
        'max_record_bytes': 1048576,
        # Interpret the audit log's time_stamp (no zone in it) in this zone; empty = system local.
        'timezone': '',
    },
    'network': {
        'internal': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
                     '::1/128', 'fc00::/7', 'fe80::/10', '100.64.0.0/10'],
        'known_scanners': [],
    },
    'waf': {
        # Local (site) rule IDs. CRS reserves 1-99,999 for local use.
        'local_range': [10000, 19999],
        'system_range': [10000, 10099],
        'exclusion_range': [10100, 10199],
        'confident_range': [10200, 10296],
        'country_range': [10300, 10399],
        # Rule(s) adding a critical score for a confident match so that CRS's 949110 decides.
        'score_rule_ids': [10298],
        # Rules that turn the engine on for "external over the CRS threshold" (nolog).
        'threshold_rule_ids': [10297],
        # Rules that refuse a request flagged by a confident block when the score stayed low.
        'fallback_rule_ids': [10299],
        'focus_sites': [],
        'sensitive_fields': ['password', 'passwd', 'pass', 'pwd', 'secret', 'token', 'otp',
                             'credential', 'credentials', 'client_secret', 'api_key', 'apikey',
                             'access_token', 'refresh_token', 'id_token', 'authorization',
                             'session', 'sessionid', 'pin', 'totp', 'passphrase'],
    },
    'managed': {
        # who wrote the rules imported unchanged at adoption, as the rule list shows it: 'site' (the site's own) or
        # 'jason_tools' (a site whose rules Jason Tools wrote before adoption)
        'imported_author': 'site',
        # jt-waf-mgr writes only these files (created by the adoption step).
        'dir': '/etc/nginx/modsec/jt-waf-mgr',
        # Existing site rule files to import at adoption; empty = detect from the main ModSecurity file
        # (the local files included right before / after the CRS rules).
        'import_before': '',
        'import_after': '',
        'spool': '/var/lib/jt-waf-mgr/spool',
        'sandbox_dir': '/var/lib/jt-waf-mgr/sandbox',
        'snapshots_kept': 200,
        # root-only working directory of the apply program (lock, snapshots); never inside the service
        # user's directories, so a compromised service cannot plant links there
        'apply_state': '/var/lib/jt-waf-mgr-apply',
    },
    'evidence': {
        # nginx access logs scanned for evidence and regression samples (JSON lines or combined).
        # One log per request: point this at either the JSON or the combined logs, not both.
        'access_logs': ['/var/log/nginx/*access.log', '/var/log/nginx/*access.log.1', '/var/log/nginx/*access.log.*.gz'],
        # Sites answering every path with the same page: 2xx/3xx there is not evidence of success.
        'catch_all_hosts': [],
        'max_scan_seconds': 900,
    },
    'retention': {
        'events_days': 30,
        'stats_days': 365,
        'audit_days': 0,  # 0 = keep forever
    },
    'auth': {
        'password_min_length': 12,
        'require_totp_roles': ['approver', 'admin'],
        'lockout_threshold': 5,
        'lockout_minutes': 15,
        'ip_attempts_per_10min': 30,
        # Character classes (lower, upper, digit, other) a new password needs; 0 = length only.
        'password_min_classes': 3,
        # A new password may not repeat the current one or the last N.
        'password_history': 3,
        # 0 = no expiry. Taiwan's Cyber Security Management Act (medium / high level systems) asks for
        # a maximum and a minimum password age.
        'password_max_age_days': 0,
        'password_min_age_hours': 0,
        # Accounts without a sign-in for this many days are disabled (never the last active admin); 0 = off.
        'dormant_days': 90,
        # Sessions per user (oldest signed out first); 0 = unlimited.
        'max_sessions_per_user': 5,
    },
    'syslog': {
        'enabled': True,
        # a local socket (/dev/log: the host's rsyslog / journald forwards it; recommended) or host:port
        'address': '/dev/log',
        'facility': 'local0',
        # for host:port: udp | tcp | tls (TCP with TLS, the server certificate checked against the system CAs)
        'protocol': 'udp',
        # rfc3164 (classic BSD syslog) | rfc5424 (with an ISO timestamp, host name and message id)
        'format': 'rfc3164',
        # tls: a CA bundle for a SIEM with its own CA (set by root here, never in the web interface); empty = system CAs
        'ca_file': '',
        # what the record looks like: json (one line) | cef | leef | gelf | kv; and what this destination receives
        'payload': 'json',
        'content': ['audit'],
        # more log servers (Settings): [{id, name, enabled, address, protocol, format, facility, payload, content}]
        'more': [],
    },
    'ui': {
        'source_url': '',
        # Text shown above the sign-in form (authorised use only, monitoring notice...). Plain text.
        'login_notice': '',
    },
    'integrity': {
        # Append-only file (install.sh sets chattr +a) receiving the audit chain's newest (id, hash).
        'anchor_file': '/var/lib/jt-waf-mgr/audit-anchors.jsonl',
        'anchor_minutes': 5,
        # Installed program files against the signed release manifest.
        'program_check_minutes': 60,
        'release_key': '/etc/jt-waf-mgr/release-key.pem',
        # nginx / ModSecurity / CRS files: fingerprint and record every change.
        'config_check_minutes': 5,
        # System check: warn below this much free space where the database lives.
        'disk_min_free_mb': 1024,
        # files changed by known automation (CRS updates, country lists): recorded as "automation", not as an
        # outside change; glob patterns
        'automation_paths': [],
        # the host's authentication logs: who was logged in when a file changed outside jt-waf-mgr (read with the
        # adm group; missing files are skipped)
        'auth_logs': ['/var/log/auth.log', '/var/log/secure'],
    },
    'backup': {
        # Daily copy of the database (SQLite online backup) with a SHA-256 file, kept keep_days.
        'enabled': True,
        'dir': '/var/lib/jt-waf-mgr/backups',
        'hour': 3,
        'keep_days': 14,
    },
    'review': {
        # the periodic WAF review (review.py): every interval_hours (1, 2, 3, 4, 6, 8, 12 or 24; slots start at
        # midnight, local time), stored and sent through the notification channels (event report.review)
        'enabled': True,
        'interval_hours': 3,
        'keep_days': 90,
    },
    'dns': {
        # DNS check (dnscheck.py, jt-waf-mgr-dns.service): which site names the internal and the external DNS servers
        # know (addresses, optional :port); and the PTR names of outside addresses (with a forward check). The web
        # service never asks DNS itself.
        'enabled': False,
        'dir': '',                    # empty: the "dns" folder next to the database (/var/lib/jt-waf-mgr/dns)
        'internal_servers': [],
        'external_servers': [],
        'check_hours': 24,
        'ptr': True,                  # look up the PTR of outside addresses (their zone's owner can see the question)
        'ptr_servers': [],            # empty: the internal servers, else the host's resolvers
    },
    'countries': {
        # per-site country blocks (countries.py, rulegen kind "country"): lists from the five regional registries,
        # downloaded by jt-waf-mgr-countries.service into dir, written for ModSecurity into rules_dir by the root apply
        # program. Off until switched on in Settings.
        'enabled': False,
        'dir': '/var/lib/jt-waf-mgr/countries',
        'rules_dir': '/etc/nginx/modsec/jt-waf-mgr/countries',
        'update_hours': 24,
        'max_age_days': 14,
    },
    'blocks': {
        # temporary IP blocks (blocks.py): an nginx deny list the apply program writes; the administrator includes it
        # once inside http { }. Off until then. protected: networks never blocked (e.g. a CDN in front of the sites).
        'enabled': False,
        'file': '/etc/nginx/jt-waf-mgr/blocked-ips.conf',
        'protected': [],
        'max_active': 500,
        'max_per_token': 200,
        'token_per_hour': 60,
        'default_ttl': 86400,
        'min_ttl': 60,
        'api_max_ttl': 7 * 86400,
        'ui_max_ttl': 30 * 86400,
        'reload_seconds': 60,
        # automatic blocks of sources that guess secret / configuration files (program rule, no LLM): one external
        # address asking for auto_recon_paths different such names within auto_recon_minutes is blocked for
        # auto_recon_ttl seconds; at most auto_recon_per_hour such blocks an hour; an address a person unblocked is
        # left alone for 7 days. Off by default.
        'auto_recon': True,           # on by default (user 2026-11-14); acts only once IP blocks are on
        'auto_recon_paths': 5,
        'auto_recon_minutes': 60,
        'auto_recon_ttl': 86400,
        'auto_recon_per_hour': 30,
    },
    'traffic': {
        # request counts from the nginx access logs (traffic.py): per site and hour, counts only -- no address,
        # no URL is kept. logs: the live access logs (the rotated copies are finished through their inode).
        'enabled': True,
        'logs': ['/var/log/nginx/*access.log'],
        'keep_days': 400,
        # alerts on a site's traffic: an hour with spike_factor times its usual requests (at least
        # min_requests), or with error_percent % or more answered 5xx (at least 50 of them)
        'alert': False,
        'spike_factor': 5,
        'min_requests': 1000,
        'error_percent': 20,
    },
    'crs': {
        # OWASP CRS updates by jt-waf-mgr (jt-waf-mgr-crs.service): off = another program (or a person) keeps the
        # CRS current. On: check daily, download and verify the newest release of the major version in use once it
        # has been out for wait_days, and stage it; switching to it is a change a person approves (CRS page).
        'manage': False,
        'wait_days': 7,
        'dir': '/var/lib/jt-waf-mgr/crs',
    },
    'geoip': {
        # Country / city / network owner of external addresses, from MaxMind databases (free GeoLite2 needs
        # a MaxMind account). The web service only reads the files; jt-waf-mgr-geoip.service downloads them.
        'enabled': True,
        'dir': '/var/lib/jt-waf-mgr/geoip',
        'account_id': '',
        # the license key, alone in a file readable by root and the jtwaf group (0640): never in this file
        'license_key_file': '/etc/jt-waf-mgr/maxmind-license.key',
        'license_key': '',          # normally set in the web interface (Settings), stored in the database
        'editions': ['GeoLite2-City', 'GeoLite2-ASN'],
        'update_days': 3,
    },
    'llm': {
        # a local, OpenAI-compatible LLM server for the event analysis (set in Settings)
        'enabled': False,
        'url': '',
        'model': '',
        'api_key': '',
        'timeout_seconds': 180,
    },
    'analyst': {
        # scheduled analysis of recent events: proposes confident blocks (never approves them)
        'enabled': False,
        'interval_minutes': 180,       # at least 10; the timer wakes the job every 5 minutes
        'window_hours': 24,
        'max_proposals': 5,
        'min_events': 5,
        'min_sources': 2,
        # the program's own rules (no LLM needed): a secret or configuration file name asked for from outside only,
        # never answered 2xx, no internal user -> a confident-block proposal without asking the model
        'rules': True,
    },
    'notify': {
        # notifications (e-mail and chat channels): set in Settings > Notifications; sent by jt-waf-mgr-notify.service
        'enabled': False,
        'language': 'zh-TW',
        'base_url': '',               # https://waf.example.com: links in messages; empty = no links
        'max_per_hour': 60,           # per channel; more are recorded as suppressed
        'remind_hours': 24,           # open alerts are reminded every N hours; 0 = never
        'report_hour': 8,             # the daily report (the last 24 hours) at this hour, local time; -1 = none
        'matrix': {},                 # {event: [channels]}; an event not listed uses its default
        'email_enabled': False, 'smtp_host': '', 'smtp_port': 587, 'smtp_tls': 'starttls', 'smtp_username': '',
        'smtp_password': '', 'smtp_from': '', 'email_to': [],
        'telegram_enabled': False, 'telegram_token': '', 'telegram_chat_id': '',
        'teams_enabled': False, 'teams_webhook': '',
        'slack_enabled': False, 'slack_webhook': '',
        'discord_enabled': False, 'discord_webhook': '',
        'zulip_enabled': False, 'zulip_site': '', 'zulip_bot_email': '', 'zulip_api_key': '', 'zulip_stream': '',
        'zulip_topic': 'jt-waf-mgr',
        'nextcloud_enabled': False, 'nextcloud_url': '', 'nextcloud_token': '', 'nextcloud_secret': '',
        'webhook_enabled': False, 'webhook_url': '', 'webhook_secret': '', 'webhook_token': '',
    },
    'compliance': {
        # Taiwan Cyber Security Management Act protection level of this system: "", "low", "medium", "high".
        # Only decides what the compliance page checks the settings against.
        'level': '',
    },
}

ROLES = ('viewer', 'operator', 'approver', 'admin')
LANGUAGES = ('zh-TW', 'en', 'ja')
GEOIP_EDITIONS = ('GeoLite2-City', 'GeoLite2-Country', 'GeoLite2-ASN', 'GeoIP2-City', 'GeoIP2-Country', 'GeoIP2-ISP')
FACILITIES = {'kern': 0, 'user': 1, 'daemon': 3, 'auth': 4, 'authpriv': 10,
              **{'local%d' % i: 16 + i for i in range(8)}}


class ConfigError(ValueError):
    pass


def _merge(base, over, where=''):
    for k, v in over.items():
        if k not in base:
            raise ConfigError('unknown setting %s%s' % (where, k))
        if isinstance(base[k], dict):
            if not isinstance(v, dict):
                raise ConfigError('%s%s must be a table' % (where, k))
            _merge(base[k], v, '%s%s.' % (where, k))
        else:
            if base[k] is not None and not isinstance(v, type(base[k])) and not (
                    isinstance(base[k], float) and isinstance(v, int)):
                raise ConfigError('%s%s: expected %s' % (where, k, type(base[k]).__name__))
            base[k] = v


def _networks(values, key):
    out = []
    for v in values:
        try:
            out.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            raise ConfigError('%s: not an address or network: %r' % (key, v))
    return out


class Config:
    def __init__(self, data, path=None):
        self.path = path
        self.data = data
        self.internal_networks = _networks(data['network']['internal'], 'network.internal')
        self.known_scanners = _networks(data['network']['known_scanners'], 'network.known_scanners')
        self.trusted_proxies = _networks(data['server']['trusted_proxies'], 'server.trusted_proxies')
        for key in ('local_range', 'system_range', 'exclusion_range', 'confident_range', 'country_range'):
            r = data['waf'][key]
            if len(r) != 2 or not all(isinstance(x, int) for x in r) or r[0] > r[1]:
                raise ConfigError('waf.%s must be [low, high]' % key)
        for role in data['auth']['require_totp_roles']:
            if role not in ROLES:
                raise ConfigError('auth.require_totp_roles: unknown role %r' % role)
        if data['syslog']['facility'] not in FACILITIES:
            raise ConfigError('syslog.facility: unknown facility')
        sl = data['syslog']
        if sl['protocol'] not in ('udp', 'tcp', 'tls') or sl['format'] not in ('rfc3164', 'rfc5424'):
            raise ConfigError('syslog.protocol: udp, tcp or tls; syslog.format: rfc3164 or rfc5424')
        if not sl['address'].startswith('/') and not re.fullmatch(r'(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]{1,253}):\d{1,5}', sl['address']):
            raise ConfigError('syslog.address: a socket path (/dev/log) or host:port')
        if not sl['address'].startswith('/') and not 1 <= int(sl['address'].rsplit(':', 1)[1]) <= 65535:
            raise ConfigError('syslog.address: port 1-65535')
        if sl.get('payload', 'json') not in ('json', 'cef', 'leef', 'gelf', 'kv'):
            raise ConfigError('syslog.payload: json, cef, leef, gelf or kv')
        if not isinstance(sl.get('content', ['audit']), list) or not all(c in ('audit', 'event', 'alert') for c in sl.get('content', ['audit'])):
            raise ConfigError('syslog.content: a list of audit, event, alert')
        if not isinstance(sl.get('more', []), list) or len(sl.get('more', [])) > 7:
            raise ConfigError('syslog.more: up to 7 more destinations')
        if data['managed'].get('imported_author', 'site') not in ('site', 'jason_tools'):
            raise ConfigError('managed.imported_author: site or jason_tools')
        dn = data['dns']
        from .dnscheck import parse_server
        for k in ('internal_servers', 'external_servers', 'ptr_servers'):
            if not isinstance(dn[k], list) or len(dn[k]) > 10:
                raise ConfigError('dns.%s: up to 10 addresses' % k)
            for x in dn[k]:
                try:
                    parse_server(x)
                except (ValueError, TypeError):
                    raise ConfigError('dns.%s: %r is not an address (optional :port)' % (k, x))
        if not isinstance(dn['check_hours'], int) or not 1 <= dn['check_hours'] <= 168:
            raise ConfigError('dns.check_hours: 1-168')
        co = data['countries']
        if not (isinstance(co['rules_dir'], str) and re.fullmatch(r'/[\w./-]{1,200}', co['rules_dir'])
                and '..' not in co['rules_dir'].split('/') and co['rules_dir'].rstrip('/') != ''):
            raise ConfigError('countries.rules_dir: an absolute directory (normally below /etc/nginx/modsec/)')
        if not (isinstance(co['dir'], str) and co['dir'].startswith('/') and '..' not in co['dir']):
            raise ConfigError('countries.dir: an absolute path')
        for k, lo, hi in (('update_hours', 6, 24 * 30), ('max_age_days', 1, 365)):
            if not isinstance(co[k], int) or isinstance(co[k], bool) or not lo <= co[k] <= hi:
                raise ConfigError('countries.%s: %d-%d' % (k, lo, hi))
        lo, hi = data['waf']['local_range']
        cr = data['waf']['country_range']
        if not (lo <= cr[0] and cr[1] <= hi) or any(not (cr[1] < data['waf'][k][0] or cr[0] > data['waf'][k][1])
                                                   for k in ('system_range', 'exclusion_range', 'confident_range')):
            raise ConfigError('waf.country_range: inside local_range, apart from the other ranges')
        bl = data['blocks']
        for k, lo, hi in (('max_active', 1, 20000), ('max_per_token', 1, 20000), ('token_per_hour', 1, 100000),
                          ('min_ttl', 10, 86400), ('default_ttl', 10, 30 * 86400), ('api_max_ttl', 60, 30 * 86400),
                          ('ui_max_ttl', 60, 30 * 86400), ('reload_seconds', 5, 3600), ('auto_recon_paths', 3, 100),
                          ('auto_recon_minutes', 5, 1440), ('auto_recon_ttl', 600, 30 * 86400), ('auto_recon_per_hour', 1, 1000)):
            if not isinstance(bl[k], int) or isinstance(bl[k], bool) or not lo <= bl[k] <= hi:
                raise ConfigError('blocks.%s: %d-%d' % (k, lo, hi))
        if not bl['min_ttl'] <= bl['default_ttl'] <= bl['ui_max_ttl']:
            raise ConfigError('blocks: min_ttl <= default_ttl <= ui_max_ttl')
        if not (isinstance(bl['file'], str) and re.fullmatch(r'/[\w./-]{1,250}\.conf', bl['file']) and '..' not in bl['file']):
            raise ConfigError('blocks.file: an absolute path to a .conf file')
        for n in bl['protected'] or []:
            try:
                ipaddress.ip_network(str(n), strict=False)
            except ValueError:
                raise ConfigError('blocks.protected: %r is not a network' % str(n)[:60])
        tr = data['traffic']
        for k, lo, hi in (('keep_days', 1, 3650), ('spike_factor', 2, 100), ('min_requests', 10, 10 ** 9),
                          ('error_percent', 1, 100)):
            if not isinstance(tr[k], int) or isinstance(tr[k], bool) or not lo <= tr[k] <= hi:
                raise ConfigError('traffic.%s: %d-%d' % (k, lo, hi))
        if not isinstance(tr['logs'], list) or len(tr['logs']) > 20 or not all(
                isinstance(x, str) and re.fullmatch(r'/[\w./*-]{1,300}', x) for x in tr['logs']):
            raise ConfigError('traffic.logs: up to 20 absolute paths (globs allowed)')
        if not isinstance(data['crs']['wait_days'], int) or not 0 <= data['crs']['wait_days'] <= 60:
            raise ConfigError('crs.wait_days: 0-60')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', data['node']['id']):
            raise ConfigError('node.id: letters, digits, _ . - only')
        host, _, port = data['server']['listen'].rpartition(':')
        if not host or not port.isdigit():
            raise ConfigError('server.listen must be host:port')
        if data['auth']['password_min_length'] < 8:
            raise ConfigError('auth.password_min_length must be at least 8')
        a = data['auth']
        if not 0 <= a['password_min_classes'] <= 4:
            raise ConfigError('auth.password_min_classes must be 0-4')
        for k in ('password_history', 'password_max_age_days', 'password_min_age_hours', 'dormant_days',
                  'max_sessions_per_user'):
            if a[k] < 0:
                raise ConfigError('auth.%s must not be negative' % k)
        g = data['geoip']
        if not isinstance(g['editions'], list) or not all(isinstance(e, str) and e in GEOIP_EDITIONS for e in g['editions']):
            raise ConfigError('geoip.editions: a list of ' + ', '.join(GEOIP_EDITIONS))
        if not isinstance(g['account_id'], str) or not re.fullmatch(r'\d{0,12}', g['account_id']):
            raise ConfigError('geoip.account_id: the MaxMind account number (digits), or ""')
        if not isinstance(g['update_days'], int) or not 1 <= g['update_days'] <= 60:
            raise ConfigError('geoip.update_days: 1-60')
        if data['compliance']['level'] not in ('', 'low', 'medium', 'high'):
            raise ConfigError('compliance.level: "", "low", "medium" or "high"')
        if len(data['ui']['login_notice']) > 2000:
            raise ConfigError('ui.login_notice: up to 2000 characters')
        for k in ('anchor_minutes', 'program_check_minutes', 'config_check_minutes'):
            if data['integrity'][k] < 1:
                raise ConfigError('integrity.%s must be at least 1' % k)
        al = data['integrity']['auth_logs']
        if not isinstance(al, list) or len(al) > 5 or not all(isinstance(x, str) and x.startswith('/') for x in al):
            raise ConfigError('integrity.auth_logs: up to 5 absolute paths')
        if not 0 <= data['backup']['hour'] <= 23 or data['backup']['keep_days'] < 1:
            raise ConfigError('backup.hour 0-23, backup.keep_days at least 1')
        nt = data['notify']
        if nt['language'] not in LANGUAGES:
            raise ConfigError('notify.language: ' + ', '.join(LANGUAGES))
        if nt['smtp_tls'] not in ('none', 'starttls', 'tls'):
            raise ConfigError('notify.smtp_tls: none, starttls or tls')
        rv = data['review']
        if rv['interval_hours'] not in (1, 2, 3, 4, 6, 8, 12, 24):
            raise ConfigError('review.interval_hours: 1, 2, 3, 4, 6, 8, 12 or 24')
        if not 1 <= rv['keep_days'] <= 3650:
            raise ConfigError('review.keep_days: 1-3650')
        if not -1 <= nt['report_hour'] <= 23:
            raise ConfigError('notify.report_hour: -1 (none) or 0-23')
        if not 1 <= nt['smtp_port'] <= 65535 or not 1 <= nt['max_per_hour'] <= 1000 or not 0 <= nt['remind_hours'] <= 720:
            raise ConfigError('notify: smtp_port 1-65535, max_per_hour 1-1000, remind_hours 0-720')
        if not isinstance(nt['matrix'], dict):
            raise ConfigError('notify.matrix must be a table')
        self.sensitive = [s.lower() for s in data['waf']['sensitive_fields']]

    def __getitem__(self, k):
        return self.data[k]

    @property
    def listen(self):
        host, _, port = self.data['server']['listen'].rpartition(':')
        return host.strip('[]'), int(port)

    @property
    def source_url(self):
        from . import SOURCE_URL
        return self.data['ui']['source_url'] or SOURCE_URL


def load(path=None, overrides=None):
    data = copy.deepcopy(DEFAULTS)
    if path:
        try:
            with open(path, 'rb') as fh:
                _merge(data, tomllib.load(fh))
        except tomllib.TOMLDecodeError as e:
            raise ConfigError('%s: %s' % (path, e))
    if overrides:
        _merge(data, overrides)
    return Config(data, path)


def default_path():
    return os.environ.get('JT_WAF_MGR_CONFIG', DEFAULT_PATH)
