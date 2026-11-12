#!/bin/sh
# jt-waf-mgr upgrade, run as root from the unpacked NEW release:
#
#   sudo ./upgrade.sh                 upgrade the installed jt-waf-mgr to this release
#   sudo ./upgrade.sh --check         run every check only; nothing is changed
#   sudo ./upgrade.sh --rollback [DIR]  put back what an upgrade saved (the newest backup if DIR is omitted)
#   options: --allow-downgrade  --accept-new-key  --keep-backups N (default 5)
#
# Order (nothing is stopped before every check passed):
#   1. checks: an installed jt-waf-mgr; no apply in progress; free disk space; this release verified by
#      the INSTALLED code with the pinned key; the existing configuration accepted by the NEW code;
#      Python version
#   2. backup to /var/backups/jt-waf-mgr/upgrade-<old>-to-<new>-<time>/: program, units, command,
#      /etc/jt-waf-mgr, and the database (SQLite online backup, integrity-checked), with a SHA-256 list
#   3. stop the service and the apply trigger; install the files (install.sh --no-start)
#   4. migrate the database with the new code; start; wait until the service answers with the new
#      version; check the program against its signed manifest and the audit chain
#   5. re-arm the apply trigger if it was armed
# A failure after step 3 began rolls back automatically: the saved program, configuration and database
# are put back and the previous version is started and checked again. The nginx configuration is never
# touched.
#
# Testing hooks (tools/test_upgrade.sh): JTWAF_ROOT=<staging root> works below that directory and runs
# commands as the current user; JTWAF_SYSTEMCTL=<program> replaces systemctl.
set -eu

SRC=$(cd "$(dirname "$0")" && pwd)
ROOT=${JTWAF_ROOT:-}
SYSTEMCTL=${JTWAF_SYSTEMCTL:-systemctl}
MODE=upgrade
RB_DIR=""
ALLOW_DOWN=0
NEW_KEY=""
KEEP=5
while [ $# -gt 0 ]; do
    case "$1" in
        --check) MODE=check; shift ;;
        --rollback) MODE=rollback; shift; if [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; then RB_DIR=$1; shift; fi ;;
        --allow-downgrade) ALLOW_DOWN=1; shift ;;
        --accept-new-key) NEW_KEY=--accept-new-key; shift ;;
        --keep-backups) KEEP=${2:?}; shift 2 ;;
        -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

LIB="$ROOT/usr/lib/jt-waf-mgr"
ETC="$ROOT/etc/jt-waf-mgr"
UNITS="$ROOT/etc/systemd/system"
BIN="$ROOT/usr/bin/jt-waf-mgr"
BACKUPS="$ROOT/var/backups/jt-waf-mgr"
CONF="$ETC/config.toml"
LOG_TS=$(date +%Y%m%d-%H%M%S)

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[ -n "$ROOT" ] || [ "$(id -u)" = 0 ] || die "run as root"

# run the given code as the service user (the database belongs to it); in a staging root as ourselves
as_svc() {
    if [ -z "$ROOT" ]; then runuser -u jtwaf -- env PYTHONPATH="$1" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$CONF" "$2" ; \
    else env PYTHONPATH="$1" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$CONF" "$2"; fi
}
version_of() { sed -n "s/^__version__ = '\([0-9A-Za-z.+-]*\)'.*/\1/p" "$1/jtwafmgr/__init__.py" 2>/dev/null | head -1; }
vnum() { echo "$1" | awk -F. '{ printf "%05d%05d%05d", $1, $2, $3 }'; }
conf_get() {  # <python expression on cfg>, evaluated by the INSTALLED code
    PYTHONPATH="$LIB" python3 -I -B -c "
import sys; sys.path.insert(0, '$LIB')
from jtwafmgr import config
cfg = config.load('$CONF')
print($1)"
}
unit_active()  { $SYSTEMCTL is-active --quiet "$1" 2>/dev/null; }
unit_enabled() { $SYSTEMCTL is-enabled --quiet "$1" 2>/dev/null; }

wait_serving() {  # <expected version> <seconds>
    want=$1; n=$2
    while [ "$n" -gt 0 ]; do
        got=$(python3 -I -c "
import json, urllib.request
try:
    print(json.load(urllib.request.urlopen('http://$LISTEN/api/v1/meta', timeout=3)).get('version', ''))
except Exception:
    print('')" 2>/dev/null)
        [ "$got" = "$want" ] && return 0
        sleep 2; n=$((n - 2))
    done
    return 1
}

post_checks() {  # <lib> <version> [rewound-to audit id]: serving this version, files and audit chain verify
    wait_serving "$2" 90 || { say "  the service does not answer with version $2"; return 1; }
    say "  serving version $2"
    out=$(as_svc "$1" integrity 2>&1) || true
    printf '%s' "$out" | REWOUND="${3:-}" python3 -I -c "
import json, os, sys
try:
    d = json.loads(sys.stdin.read())
except ValueError:
    print('  integrity check did not run'); sys.exit(1)
p, c = d['program'], d['audit_chain']
rw = os.environ.get('REWOUND')
chain_ok = c['ok']
if not chain_ok and rw and c.get('reason') is None:
    # an older version does not know rewinds: only anchors for rows the rollback took back may be off
    chain_ok = all(x.get('id') is not None and x['id'] > int(rw) for x in c.get('anchor_problems') or [])
    if chain_ok:
        print('  (anchors written by the failed version for rows the rollback took back are expected to differ)')
print('  program: %s (%s files, signature %s); audit chain: %s, %s rows' % (p['status'], p.get('checked'), p.get('signature'), 'ok' if chain_ok else 'FAILED %s %s' % (c.get('reason'), c.get('anchor_problems')), c.get('rows')))
sys.exit(0 if p['status'] in ('ok', 'not_installed') and chain_ok else 1)"
}

restore_from() {  # <backup dir>
    B=$1
    [ -f "$B/files.tar" ] && [ -f "$B/SHA256SUMS" ] || die "not an upgrade backup: $B"
    ( cd "$B" && sha256sum -c --quiet SHA256SUMS ) || die "backup $B does not match its SHA256SUMS; not restoring"
    $SYSTEMCTL stop jt-waf-mgr-apply.path 2>/dev/null || true
    # nothing else may write the database while it is replaced
    for u in jt-waf-mgr-notify.path jt-waf-mgr-notify.timer jt-waf-mgr-analyst.path jt-waf-mgr-analyst.timer \
             jt-waf-mgr-notify.service jt-waf-mgr-analyst.service; do $SYSTEMCTL stop "$u" 2>/dev/null || true; done
    $SYSTEMCTL stop jt-waf-mgr.service 2>/dev/null || true
    rm -rf "$LIB/jtwafmgr" "$LIB/release" "$LIB/LICENSE"
    tar -C "${ROOT:-/}" -xf "$B/files.tar"
    # units that came with the newer version (not in the backup) go away with it
    for u in jt-waf-mgr-notify.path jt-waf-mgr-notify.timer jt-waf-mgr-notify.service; do
        if ! tar -tf "$B/files.tar" | grep -qx "etc/systemd/system/$u" && [ -e "${ROOT:-}/etc/systemd/system/$u" ]; then
            $SYSTEMCTL disable --now "$u" >/dev/null 2>&1 || true
            rm -f "${ROOT:-}/etc/systemd/system/$u"
        fi
    done
    DBP=$(cat "$B/db.path")
    cp "$B/db.sqlite" "$DBP.restore-tmp"
    rm -f "$DBP-wal" "$DBP-shm"
    mv "$DBP.restore-tmp" "$DBP"
    [ -z "$ROOT" ] && chown jtwaf:jtwaf "$DBP" && chmod 600 "$DBP"
    # The audit chain went back to the backup: record that (root-only file the integrity check reads),
    # so anchors written meanwhile for rows that no longer exist are not mistaken for tampering.
    RW_ID=$(cat "$B/audit.last_id"); RW_HASH=$(cat "$B/audit.last_hash")
    RW_LINE=$(printf '{"at":"%s","id":%s,"hash":"%s","reason":"upgrade rollback","from":"%s","to":"%s"}' \
        "$(date -Iseconds)" "$RW_ID" "$RW_HASH" "$(version_of "$SRC" 2>/dev/null)" "$(cat "$B/version.old")")
    printf '%s\n' "$RW_LINE" >> "$ETC/audit-rewinds.jsonl"
    chmod 640 "$ETC/audit-rewinds.jsonl"; [ -z "$ROOT" ] && chown root:jtwaf "$ETC/audit-rewinds.jsonl"
    [ -z "$ROOT" ] && logger -p local0.crit -t jt-waf-mgr "{\"jt_waf_mgr\":{\"v\":1,\"kind\":\"audit_rewind\",\"severity\":\"crit\",\"rewind\":$RW_LINE}}" || true
    [ -z "$ROOT" ] && $SYSTEMCTL daemon-reload
    $SYSTEMCTL start jt-waf-mgr.service
    if [ "$(cat "$B/apply.armed")" = 1 ]; then $SYSTEMCTL start jt-waf-mgr-apply.path || true; fi
    for u in jt-waf-mgr-analyst.timer jt-waf-mgr-analyst.path jt-waf-mgr-notify.timer jt-waf-mgr-notify.path; do
        if [ -e "${ROOT:-}/etc/systemd/system/$u" ]; then $SYSTEMCTL start "$u" 2>/dev/null || true; fi
    done
}

record() {  # one line per upgrade / rollback, next to the backups
    mkdir -p "$BACKUPS"
    printf '{"at":"%s","action":"%s","from":"%s","to":"%s","result":"%s","backup":"%s"}\n' \
        "$(date -Iseconds)" "$1" "$2" "$3" "$4" "${5:-}" >> "$BACKUPS/history.jsonl"
}

# --- rollback on request ------------------------------------------------------------------
if [ "$MODE" = rollback ]; then
    [ -n "$RB_DIR" ] || RB_DIR=$(ls -1d "$BACKUPS"/upgrade-* 2>/dev/null | sort | tail -1)
    [ -n "$RB_DIR" ] && [ -d "$RB_DIR" ] || die "no upgrade backup found in $BACKUPS"
    OLD=$(cat "$RB_DIR/version.old"); CUR=$(version_of "$LIB")
    LISTEN=$(conf_get "cfg['server']['listen']")
    step "rolling back $CUR -> $OLD from $RB_DIR"
    say "  the database goes back to the moment of that backup: changes made since then are lost"
    restore_from "$RB_DIR"
    if post_checks "$LIB" "$OLD" "$(cat "$RB_DIR/audit.last_id")"; then record rollback "$CUR" "$OLD" ok "$RB_DIR"; say "rolled back to $OLD"; exit 0; fi
    record rollback "$CUR" "$OLD" failed "$RB_DIR"; die "rolled back, but the checks failed: see journalctl -u jt-waf-mgr"
fi

# --- 1. checks ------------------------------------------------------------------------------
step "checks"
[ -f "$SRC/install.sh" ] && [ -d "$SRC/jtwafmgr" ] || die "run from the unpacked jt-waf-mgr release"
OLD=$(version_of "$LIB"); NEW=$(version_of "$SRC")
[ -n "$OLD" ] || die "no installed jt-waf-mgr in $LIB: use ./install.sh for a first install"
[ -n "$NEW" ] || die "cannot read this release's version"
say "  installed $OLD, this release $NEW"
if [ "$(vnum "$NEW")" -le "$(vnum "$OLD")" ] && [ "$ALLOW_DOWN" = 0 ]; then
    die "$NEW is not newer than the installed $OLD (use --allow-downgrade, or --rollback to undo an upgrade)"
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "Python 3.11 or newer is required"
LISTEN=$(conf_get "cfg['server']['listen']")
DB=$(conf_get "cfg['paths']['db']")
SPOOL=$(conf_get "cfg['managed']['spool']")
if ls "$SPOOL"/*.req >/dev/null 2>&1; then die "an apply request is waiting in $SPOOL; try again when it is done"; fi
PENDING=$(python3 -I -c "
import sqlite3
c = sqlite3.connect('file:$DB?mode=ro', uri=True)
try:
    print(c.execute(\"SELECT COUNT(*) FROM changes WHERE state IN ('approved','applying')\").fetchone()[0])
except sqlite3.Error:
    print(0)")
[ "$PENDING" = 0 ] || die "$PENDING change(s) are being applied; try again when they are done"
DB_MB=$(( $(stat -c %s "$DB") / 1048576 + 1 ))
FREE_MB=$(( $(df -Pk "$(dirname "$DB")" | awk 'NR==2 {print $4}') / 1024 ))
NEED_MB=$(( DB_MB * 3 + 200 ))
[ "$FREE_MB" -ge "$NEED_MB" ] || die "not enough free disk space: ${FREE_MB} MB free, ${NEED_MB} MB needed"
say "  disk: ${FREE_MB} MB free, database ${DB_MB} MB"
say "  release verified with the installed code and the pinned key:"
PYTHONPATH="$LIB" python3 -I -B -c "
import sys; sys.path.insert(0, '$LIB')
from jtwafmgr import integrity
r = integrity.verify_release('$SRC', open('$ETC/release-key.pem').read())
print('    %s, %s files, key %s' % ('ok' if r['ok'] else 'FAILED: %s %s' % (r.get('reason'), {k: r.get(k) for k in ('changed', 'missing', 'extra') if r.get(k)}), r.get('checked'), r.get('key_fingerprint', '?')[:16]))
sys.exit(0 if r['ok'] else 1)" || { [ -n "$NEW_KEY" ] || die "release verification failed; nothing changed (a release signed with a new key needs --accept-new-key)"; }
# (the new release is unpacked under root's home, which the service user cannot read; it was verified above)
out=$(env PYTHONPATH="$SRC" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$CONF" config-check 2>&1) \
    || die "the new version does not accept $CONF: $out"
say "  configuration accepted by $NEW"
APPLY_ARMED=0; unit_enabled jt-waf-mgr-apply.path && APPLY_ARMED=1
SERVICE_UP=0; unit_active jt-waf-mgr.service && SERVICE_UP=1
say "  service running: $SERVICE_UP, apply trigger armed: $APPLY_ARMED"
if [ "$MODE" = check ]; then say ""; say "all checks passed; nothing was changed"; exit 0; fi

# --- 2. backup ------------------------------------------------------------------------------
step "backup"
B="$BACKUPS/upgrade-$OLD-to-$NEW-$LOG_TS"
mkdir -p "$BACKUPS" && chmod 700 "$BACKUPS" && mkdir -m 700 "$B"
echo "$OLD" > "$B/version.old"; echo "$NEW" > "$B/version.new"; echo "$APPLY_ARMED" > "$B/apply.armed"; echo "$DB" > "$B/db.path"
( cd "${ROOT:-/}" && tar -cf "$B/files.tar" \
    $(for p in usr/lib/jt-waf-mgr/jtwafmgr usr/lib/jt-waf-mgr/release usr/lib/jt-waf-mgr/LICENSE usr/bin/jt-waf-mgr \
               etc/jt-waf-mgr etc/systemd/system/jt-waf-mgr.service etc/systemd/system/jt-waf-mgr.service.d \
               etc/systemd/system/jt-waf-mgr-apply.service etc/systemd/system/jt-waf-mgr-apply.path \
               etc/systemd/system/jt-waf-mgr-geoip.service etc/systemd/system/jt-waf-mgr-geoip.timer \
               etc/systemd/system/jt-waf-mgr-geoip.path etc/systemd/system/jt-waf-mgr-analyst.service \
               etc/systemd/system/jt-waf-mgr-analyst.timer etc/systemd/system/jt-waf-mgr-analyst.path \
               etc/systemd/system/jt-waf-mgr-notify.service etc/systemd/system/jt-waf-mgr-notify.timer \
               etc/systemd/system/jt-waf-mgr-notify.path; do [ -e "$p" ] && echo "$p"; done) )
python3 -I -c "
import sqlite3, sys
src = sqlite3.connect('file:$DB?mode=ro', uri=True)
dst = sqlite3.connect('$B/db.sqlite')
src.backup(dst)
ok = dst.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
dst.close(); src.close()
sys.exit(0 if ok else 1)" || die "the database backup failed its integrity check; nothing changed"
python3 -I -c "
import sqlite3
r = sqlite3.connect('$B/db.sqlite').execute('SELECT id, this_hash FROM audit ORDER BY id DESC LIMIT 1').fetchone() or (0, '')
open('$B/audit.last_id', 'w').write(str(r[0])); open('$B/audit.last_hash', 'w').write(r[1] or '')"
( cd "$B" && sha256sum files.tar db.sqlite version.old version.new apply.armed db.path audit.last_id audit.last_hash > SHA256SUMS )
say "  $B ($(du -sh "$B" | cut -f1))"

# --- 3-5. switch, with automatic rollback --------------------------------------------------------
STAGE=stopped
rollback_now() {
    trap - EXIT INT TERM
    printf '\n== upgrade FAILED at "%s": rolling back to %s\n' "$STAGE" "$OLD" >&2
    restore_from "$B" >&2 || true
    if post_checks "$LIB" "$OLD" "$(cat "$B/audit.last_id")" >&2; then
        record upgrade "$OLD" "$NEW" "rolled_back_at_$STAGE" "$B"
        printf 'rolled back: %s is running again. The backup stays in %s\n' "$OLD" "$B" >&2
    else
        record upgrade "$OLD" "$NEW" "rollback_failed_at_$STAGE" "$B"
        printf 'ROLLBACK FAILED: restore by hand from %s (files.tar to /, db.sqlite to %s); see journalctl -u jt-waf-mgr\n' "$B" "$DB" >&2
    fi
    exit 1
}
trap 'rollback_now' EXIT INT TERM

step "switch $OLD -> $NEW"
$SYSTEMCTL stop jt-waf-mgr-apply.path 2>/dev/null || true
$SYSTEMCTL stop jt-waf-mgr.service 2>/dev/null || true
STAGE=install
if [ -n "$ROOT" ]; then "$SRC/install.sh" --no-start $NEW_KEY --root "$ROOT" >"$B/install.log" 2>&1; \
else "$SRC/install.sh" --no-start $NEW_KEY >"$B/install.log" 2>&1; fi
say "  files installed (log: $B/install.log)"
STAGE=migrate
out=$(as_svc "$LIB" migrate 2>&1) || { say "$out"; false; }
say "  database: $out"
STAGE=start
[ -z "$ROOT" ] && $SYSTEMCTL daemon-reload
$SYSTEMCTL start jt-waf-mgr.service
STAGE=checks
post_checks "$LIB" "$NEW"
[ "$APPLY_ARMED" = 1 ] && $SYSTEMCTL start jt-waf-mgr-apply.path
trap - EXIT INT TERM
record upgrade "$OLD" "$NEW" ok "$B"

# keep the newest backups only
ls -1d "$BACKUPS"/upgrade-* 2>/dev/null | sort | head -n "-$KEEP" | while read -r d; do rm -rf "$d"; done
say ""
say "upgraded $OLD -> $NEW. Backup: $B"
say "undo with: sudo ./upgrade.sh --rollback $B   (the database returns to the moment of the backup)"
