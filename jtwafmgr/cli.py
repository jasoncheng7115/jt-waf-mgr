"""Command line: jt-waf-mgr [--config FILE] <command>"""
import argparse
import getpass
import json
import os
import signal
import sys

from . import __version__
from . import config as config_mod


def _app(args, collector=False):
    from .app import App
    cfg = config_mod.load(args.config if os.path.exists(args.config) or args.config != config_mod.DEFAULT_PATH else None)
    return App(cfg, start_collector=collector)


def cmd_serve(args):
    from .web.server import serve
    app = _app(args, collector=True)
    host, port = app.cfg.listen

    def stop(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    print('jt-waf-mgr %s listening on %s:%d' % (__version__, host, port), flush=True)
    try:
        serve(app, host, port)
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()
    return 0


def cmd_user(args):
    app = _app(args)
    a = app.auth
    if args.action == 'list':
        for r in app.db.q('SELECT * FROM users ORDER BY username'):
            print('%-24s %-9s %s%s%s' % (r['username'], r['role'], 'disabled ' if r['disabled'] else '',
                                         'totp ' if r['totp_enabled'] else '', 'must-change' if r['must_change'] else ''))
        return 0
    if not args.username:
        print('username required', file=sys.stderr)
        return 2
    name = args.username.strip().lower()
    if args.action == 'add':
        temp = a.create_user(name, args.role, args.display_name or '')
        app.audit.log('user.created', 'cli', 'system', None, 'ok', target=name, role=args.role)
        print('created %s (%s); temporary password, must be changed at first login:\n%s' % (name, args.role, temp))
        return 0
    if not a.user_row(name):
        print('no such user', file=sys.stderr)
        return 1
    if args.action == 'reset':
        temp = a.reset_password(name)
        app.audit.log('user.reset', 'cli', 'system', None, 'ok', target=name)
        print('temporary password for %s (TOTP cleared, must change at login):\n%s' % (name, temp))
    elif args.action == 'passwd':
        pw = getpass.getpass('new password: ')
        if pw != getpass.getpass('again: '):
            print('passwords differ', file=sys.stderr)
            return 1
        a.set_password(name, pw, by_user=False)
        app.audit.log('user.password_set', 'cli', 'system', None, 'ok', target=name)
        print('password set')
    elif args.action in ('disable', 'enable'):
        a.set_disabled(name, args.action == 'disable')
        app.audit.log('user.changed', 'cli', 'system', None, 'ok', target=name, disabled=args.action == 'disable')
        print('%sd %s' % (args.action, name))
    elif args.action == 'unlock':
        app.db.x('UPDATE users SET failed_count=0, locked_until=0 WHERE username=?', (name,))
        app.audit.log('user.changed', 'cli', 'system', None, 'ok', target=name, unlocked=True)
        print('unlocked %s' % name)
    return 0


def cmd_import(args):
    from .collector.auditlog import Tailer
    app = _app(args)
    t = Tailer(app.cfg, app.db)
    for f in args.files:
        before = t.stats['inserted']
        r = t.import_file(f)
        print('%s: %s, %d new events, %d parse errors, %d oversized' % (
            f, 'read' if r is not None else 'cannot read', t.stats['inserted'] - before,
            t.stats['parse_errors'], t.stats['oversized']))
    return 0


def cmd_check(args):
    """Parse the site configuration and print a summary (read-only)."""
    app = _app(args)
    n, m = app.site.load()
    crs = m.crs_status()
    servers = n.servers()
    out = {
        'nginx_files': len(n.files), 'nginx_errors': n.errors, 'modsec_files': len(m.files), 'modsec_errors': m.errors,
        'rules': len(m.rules), 'local_rules': sum(1 for r in m.rules if m.source_of(r) == 'local'),
        'removals': len(m.removals), 'servers': len(servers),
        'servers_waf': {s: sum(1 for x in servers if x['waf'] == s) for s in ('on', 'off', 'block', 'unknown')},
        'crs': {k: crs[k] for k in ('version', 'paranoia_level', 'inbound_threshold', 'engine_mode', 'rule_count')},
        'external_threshold_block': m.external_threshold_block(), 'warnings': m.warnings,
        'audit_log_readable': os.access(app.cfg['paths']['audit_log'], os.R_OK),
    }
    print(json.dumps(out, indent=1, ensure_ascii=False))
    return 0 if not (n.errors or m.errors) else 1


def cmd_integrity(args):
    """Installed program against the signed manifest, and the audit hash chain with its anchors."""
    from . import integrity
    app = _app(args)
    prog = app.monitor.check_program()
    chain = app.monitor.check_chain(full=True)
    print(json.dumps({'program': {k: prog.get(k) for k in ('status', 'reason', 'signature', 'key_fingerprint',
                                                              'checked', 'changed', 'missing', 'extra')},
                      'audit_chain': {k: chain.get(k) for k in ('ok', 'rows', 'checked', 'reason', 'bad_id',
                                                                'anchor_problems', 'last_anchor')},
                      'time_sync': integrity.time_sync()}, indent=1, ensure_ascii=False))
    app.audit.log('integrity.checked', 'cli', 'system', None, 'ok' if prog['status'] != 'failed' and chain['ok'] else 'failed',
                  program=prog['status'], chain_ok=chain['ok'])
    return 0 if prog['status'] != 'failed' and chain['ok'] else 1


def cmd_verify_release(args):
    """Check an unpacked release with the installed code and the pinned key (before upgrading)."""
    from . import integrity
    cfg = config_mod.load(args.config if os.path.exists(args.config) else None)
    key = args.key or cfg['integrity']['release_key']
    with open(key) as fh:
        pem = fh.read()
    r = integrity.verify_release(os.path.abspath(args.dir), pem)
    print(json.dumps(r, indent=1))
    return 0 if r['ok'] else 1


def cmd_audit_verify(args):
    """Verify an audit export file offline (line hash and the chain inside it)."""
    from .compliance import verify_export
    r = verify_export(args.file)
    print(json.dumps(r, indent=1, ensure_ascii=False))
    return 0 if r['ok'] else 1


def cmd_backup(args):
    app = _app(args)
    if args.verify:
        r = app.monitor.verify_backup(args.verify)
        if r is None:
            print('no such backup', file=sys.stderr)
            return 1
    else:
        r = app.monitor.backup(actor='cli')
    print(json.dumps({k: v for k, v in r.items() if k != 'ts'}, indent=1))
    return 0 if r['ok'] else 1


def cmd_geoip_update(args):
    """Run by jt-waf-mgr-geoip.service (sandboxed, user jtwaf); also usable by hand."""
    from . import geoip
    cfg = config_mod.load(args.config if os.path.exists(args.config) or args.config != config_mod.DEFAULT_PATH else None)
    st = geoip.update(cfg, force=args.force, log=lambda m: print(m, flush=True))
    print(json.dumps(st, indent=1))
    return 1 if st.get('ok') is False else 0


def cmd_geoip(args):
    app = _app(args)
    print(json.dumps({'geo': app.geoip.lookup(args.ip), 'status': app.geoip.status()}, indent=1, ensure_ascii=False))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog='jt-waf-mgr')
    p.add_argument('--config', default=config_mod.default_path())
    p.add_argument('--version', action='version', version='jt-waf-mgr ' + __version__)
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('serve', help='run the web service and the collector')
    u = sub.add_parser('user', help='manage local accounts')
    u.add_argument('action', choices=('add', 'list', 'reset', 'passwd', 'disable', 'enable', 'unlock'))
    u.add_argument('username', nargs='?')
    u.add_argument('--role', default='viewer', choices=config_mod.ROLES)
    u.add_argument('--display-name')
    im = sub.add_parser('import', help='import audit log files (plain or .gz); duplicates are skipped')
    im.add_argument('files', nargs='+')
    sub.add_parser('check', help='parse the nginx / ModSecurity configuration and print a summary')
    sub.add_parser('integrity', help='check the installed program (signed manifest) and the audit hash chain')
    vr = sub.add_parser('verify-release', help='verify an unpacked release with the pinned key before upgrading')
    vr.add_argument('dir')
    vr.add_argument('--key', help='public key (default: the pinned [integrity] release_key)')
    av = sub.add_parser('audit-verify', help='verify an audit export file (NDJSON) offline')
    av.add_argument('file')
    bk = sub.add_parser('backup', help='back up the database now (or --verify a backup file)')
    bk.add_argument('--verify', metavar='FILE')
    gu = sub.add_parser('geoip-update', help='download the GeoIP databases now (normally run by its own unit)')
    gu.add_argument('--force', action='store_true', help='even when the files are recent')
    gl = sub.add_parser('geoip', help='look up one address and show the GeoIP status')
    gl.add_argument('ip')
    args = p.parse_args(argv)
    try:
        return {'serve': cmd_serve, 'user': cmd_user, 'import': cmd_import, 'check': cmd_check,
                'integrity': cmd_integrity, 'verify-release': cmd_verify_release, 'audit-verify': cmd_audit_verify,
                'backup': cmd_backup, 'geoip-update': cmd_geoip_update, 'geoip': cmd_geoip}[args.cmd](args)
    except config_mod.ConfigError as e:
        print('configuration error: %s' % e, file=sys.stderr)
        return 2
    except Exception as e:
        from .auth import AuthError
        if isinstance(e, AuthError):
            print('error: %s %s' % (e.code, e.details or ''), file=sys.stderr)
            return 1
        raise
