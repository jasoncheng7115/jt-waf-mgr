#!/bin/sh
# jt-waf-mgr installer (offline: everything it needs is in this directory).
#
#   sudo ./install.sh              install or upgrade, enable and start the service
#   sudo ./install.sh --no-start   install, do not start
#   sudo ./install.sh --enable-apply  also arm the apply program (it writes the managed nginx files)
#   sudo ./install.sh --accept-new-key  the release is signed with a different key than the pinned one
#   ./install.sh --root DIR        stage into DIR only (no user, no systemd; for testing)
#
# Every file of the release is checked against release/MANIFEST.sha256, whose signature is checked
# with the pinned release key (/etc/jt-waf-mgr/release-key.pem; pinned from this release on the
# first install). Stronger, before an upgrade: jt-waf-mgr verify-release <unpacked dir> (runs the
# installed, already verified code).
#
# The installer never changes the nginx configuration. The management vhost is a separate,
# explicit step (see deploy/nginx-vhost.conf.example).
set -eu

SRC=$(cd "$(dirname "$0")" && pwd)
ROOT=""
START=1
ENABLE_APPLY=0
NEW_KEY=0
PIN_NEW=0
while [ $# -gt 0 ]; do
    case "$1" in
        --root) ROOT=${2:?--root needs a directory}; shift 2 ;;
        --no-start) START=0; shift ;;
        --enable-apply) ENABLE_APPLY=1; shift ;;
        --accept-new-key) NEW_KEY=1; shift ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ -d "$SRC/jtwafmgr" ] || die "run from the unpacked jt-waf-mgr directory"
[ -f "$SRC/jtwafmgr/static/index.html" ] || die "jtwafmgr/static/index.html missing (frontend not built)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "Python 3.11 or newer is required (found $(python3 -V 2>&1))"
# read without importing anything from the release (it is not verified yet)
VERSION=$(sed -n "s/^__version__ = '\([0-9A-Za-z.+-]*\)'.*/\1/p" "$SRC/jtwafmgr/__init__.py" | head -1)
[ -n "$VERSION" ] || die "cannot read the version"

if [ -z "$ROOT" ]; then
    [ "$(id -u)" = 0 ] || die "run as root (or use --root DIR to stage)"
fi

LIB="$ROOT/usr/lib/jt-waf-mgr"
ETC="$ROOT/etc/jt-waf-mgr"
VAR="$ROOT/var/lib/jt-waf-mgr"
UNIT_DIR="$ROOT/etc/systemd/system"
say "jt-waf-mgr $VERSION"

# --- release integrity -------------------------------------------------------------------
PIN="$ETC/release-key.pem"
# The check runs with the ALREADY INSTALLED (and itself verified) code when there is one, so a tampered
# release cannot vouch for itself; only a first install has to use the code it ships.
CHECKER="$SRC"
[ -f "$LIB/jtwafmgr/integrity.py" ] && [ -f "$LIB/release/MANIFEST.sha256" ] && CHECKER="$LIB"
verify() {  # $1 key file; prints the result, returns 0 when the whole release verifies
    python3 -I -B -c '
import sys
sys.path.insert(0, sys.argv[3])
from jtwafmgr import integrity
r = integrity.verify_release(sys.argv[1], open(sys.argv[2]).read())
print("  key %s: %s" % (r.get("key_fingerprint", "?"), "ok, %d files" % r["checked"] if r["ok"] else
      "%s %s" % (r.get("reason"), {k: r.get(k) for k in ("changed", "missing", "extra") if r.get(k)})))
sys.exit(0 if r["ok"] else 1)
' "$SRC" "$1" "$CHECKER"
}
if [ -f "$PIN" ]; then
    say "verifying the release with the pinned key"
    if ! verify "$PIN"; then
        if [ "$NEW_KEY" = 1 ] && verify "$SRC/deploy/release-key.pem"; then
            say "release signed with a NEW key (accepted with --accept-new-key); it will be pinned"
            PIN_NEW=1
        else
            die "release verification failed (a modified or foreign release?); nothing installed"
        fi
    fi
else
    say "verifying the release with its own key (first install; the key gets pinned)"
    verify "$SRC/deploy/release-key.pem" || die "release verification failed; nothing installed"
    PIN_NEW=1
fi

# --- user --------------------------------------------------------------------------------
if [ -z "$ROOT" ] && ! id jtwaf >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/jt-waf-mgr --no-create-home --shell /usr/sbin/nologin \
        --comment "jt-waf-mgr" jtwaf
    say "created system user jtwaf"
fi

# --- program -----------------------------------------------------------------------------
mkdir -p "$LIB"
if [ -d "$LIB/jtwafmgr" ]; then
    rm -rf "$LIB/jtwafmgr.old"
    mv "$LIB/jtwafmgr" "$LIB/jtwafmgr.old"
fi
cp -R "$SRC/jtwafmgr" "$LIB/jtwafmgr"
find "$LIB/jtwafmgr" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$LIB/jtwafmgr" -type d -exec chmod 755 {} +
find "$LIB/jtwafmgr" -type f -exec chmod 644 {} +
rm -rf "$LIB/jtwafmgr.old"
cp "$SRC/LICENSE" "$LIB/LICENSE"
# The signed manifest stays with the program: the service and the apply program check against it.
rm -rf "$LIB/release"
cp -R "$SRC/release" "$LIB/release"
chmod 755 "$LIB/release" && chmod 644 "$LIB/release/"*

mkdir -p "$ROOT/usr/bin"
cp "$SRC/deploy/jt-waf-mgr.sh" "$ROOT/usr/bin/jt-waf-mgr"
chmod 755 "$ROOT/usr/bin/jt-waf-mgr"

# --- configuration and data --------------------------------------------------------------
mkdir -p "$ETC" "$VAR"
if [ ! -f "$ETC/config.toml" ]; then
    cp "$SRC/deploy/config.toml.example" "$ETC/config.toml"
    say "wrote $ETC/config.toml (review it: [node] id, [waf] focus_sites, [network] internal)"
else
    say "kept existing $ETC/config.toml"
fi
cp "$SRC/deploy/config.toml.example" "$ETC/config.toml.example"
if [ "$PIN_NEW" = 1 ]; then
    cp "$SRC/deploy/release-key.pem" "$PIN"
    say "pinned release key $(openssl pkey -pubin -in "$PIN" -outform DER 2>/dev/null | sha256sum | cut -c1-64)"
fi
chmod 644 "$PIN"
cp "$SRC/deploy/nginx-vhost.conf.example" "$ETC/nginx-vhost.conf.example"
chmod 750 "$ETC" && chmod 640 "$ETC/config.toml"
chmod 700 "$VAR"
# Audit chain anchors: append-only (chattr +a) so the service user can add lines but never change
# or remove them. Clearing the flag needs root (CAP_LINUX_IMMUTABLE).
# (An append-only file refuses chmod / chown too: only set them when the file is new.)
ANCHORS="$VAR/audit-anchors.jsonl"
ANCHORS_NEW=0
if [ ! -e "$ANCHORS" ]; then
    : > "$ANCHORS" && chmod 600 "$ANCHORS" && ANCHORS_NEW=1
fi
if [ -z "$ROOT" ]; then
    chown root:jtwaf "$ETC" "$ETC/config.toml"
    chown jtwaf:jtwaf "$VAR"
    install -d -m 750 -o jtwaf -g jtwaf "$VAR/geoip"
    # GeoIP license key: alone in its own file, readable by root and the jtwaf group only
    KEY="$ETC/maxmind-license.key"
    [ -e "$KEY" ] || { : > "$KEY"; }
    chown root:jtwaf "$KEY" && chmod 640 "$KEY"
    [ "$ANCHORS_NEW" = 1 ] && chown jtwaf:jtwaf "$ANCHORS"
    if lsattr -d "$ANCHORS" 2>/dev/null | cut -d' ' -f1 | grep -q a; then
        say "audit anchors: $ANCHORS (append-only)"
    elif chattr +a "$ANCHORS" 2>/dev/null; then
        say "audit anchors: $ANCHORS (append-only)"
    else
        say "WARNING: could not set the append-only flag on $ANCHORS"
        say "  (a container without CAP_LINUX_IMMUTABLE, or a filesystem without it: set it from the host; see docs/COMPLIANCE.md)"
    fi
fi

# --- systemd -----------------------------------------------------------------------------
mkdir -p "$UNIT_DIR/jt-waf-mgr.service.d"
for u in jt-waf-mgr.service jt-waf-mgr-apply.service jt-waf-mgr-apply.path \
         jt-waf-mgr-geoip.service jt-waf-mgr-geoip.timer jt-waf-mgr-geoip.path \
         jt-waf-mgr-analyst.service jt-waf-mgr-analyst.timer jt-waf-mgr-analyst.path \
         jt-waf-mgr-notify.service jt-waf-mgr-notify.timer jt-waf-mgr-notify.path; do
    cp "$SRC/deploy/$u" "$UNIT_DIR/$u"
    chmod 644 "$UNIT_DIR/$u"
done

# Read access to the audit log: through the group that owns it (the log itself is not changed).
AUDIT_LOG=$(PYTHONPATH="$SRC" python3 - "$ETC/config.toml" <<'EOF'
import sys
from jtwafmgr import config
print(config.load(sys.argv[1])['paths']['audit_log'])
EOF
)
# The directory needs search (x) and the file read (r) permission, either for everyone or for a
# group the service joins. Typical: directory root:adm 0750 with a world-readable file -> adm.
LOG_GROUP=""
need_group() {  # $1 path, $2 permission bit for "other" (1 = x, 4 = r); prints a group or "!"
    m=$(stat -c %a "$1"); o=$(( ${m#"${m%?}"} & $2 )); g=$(( $(echo "$m" | cut -c$((${#m}-1))) & $2 ))
    if [ "$o" -ne 0 ]; then return 0; fi
    grp=$(stat -c %G "$1")
    if [ "$g" -ne 0 ] && [ "$grp" != root ]; then echo "$grp"; else echo "!"; fi
}
if [ -e "$AUDIT_LOG" ]; then
    for spec in "$(dirname "$AUDIT_LOG"):1" "$AUDIT_LOG:4"; do
        g=$(need_group "${spec%:*}" "${spec##*:}")
        if [ "$g" = "!" ]; then
            say "WARNING: jtwaf cannot reach ${spec%:*} ($(stat -c '%U:%G %a' "${spec%:*}")); grant a non-root group or read access"
        elif [ -n "$g" ] && [ -n "$LOG_GROUP" ] && [ "$g" != "$LOG_GROUP" ]; then
            say "WARNING: the audit log directory and file need different groups ($LOG_GROUP, $g); using $LOG_GROUP"
        elif [ -n "$g" ]; then
            LOG_GROUP=$g
        fi
    done
else
    say "WARNING: audit log $AUDIT_LOG not found (set [paths] audit_log)"
fi
{
    echo "# written by install.sh: read access to the ModSecurity audit log"
    echo "[Service]"
    if [ -n "$LOG_GROUP" ]; then echo "SupplementaryGroups=$LOG_GROUP"; fi
} > "$UNIT_DIR/jt-waf-mgr.service.d/10-log-group.conf"
if [ -n "$LOG_GROUP" ]; then say "service gets supplementary group $LOG_GROUP (audit log)"; fi

if [ -n "$ROOT" ]; then
    say "staged into $ROOT (no user, no systemd changes)"
    exit 0
fi

systemctl daemon-reload
systemctl enable jt-waf-mgr.service >/dev/null
# GeoIP: a separate, sandboxed one-shot job (daily timer + "update now" from the UI); it does nothing
# until an admin enters the MaxMind account and license key in Settings (web interface).
systemctl enable --now jt-waf-mgr-geoip.timer jt-waf-mgr-geoip.path >/dev/null
# Event analysis with the local LLM: hourly wake-up + "run now" from the UI; it does nothing until
# [analyst] and [llm] are enabled and configured in Settings, and it only ever proposes changes.
systemctl enable --now jt-waf-mgr-analyst.timer jt-waf-mgr-analyst.path >/dev/null
# Notifications: queued by the web service, sent by this one-shot job (request file + one-minute timer for
# retries and reminders); it sends nothing until channels are set up in Settings > Notifications.
systemctl enable --now jt-waf-mgr-notify.timer jt-waf-mgr-notify.path >/dev/null
# The apply program writes nginx configuration: it is armed only on request (--enable-apply),
# normally right before the adoption step.
if [ "$ENABLE_APPLY" = 1 ]; then
    install -d -m 700 -o jtwaf -g jtwaf /var/lib/jt-waf-mgr/spool
    systemctl enable --now jt-waf-mgr-apply.path >/dev/null
    say "apply program armed (jt-waf-mgr-apply.path)"
elif systemctl is-enabled --quiet jt-waf-mgr-apply.path 2>/dev/null; then
    systemctl restart jt-waf-mgr-apply.path
else
    say "apply program installed but not armed; enable it with: systemctl enable --now jt-waf-mgr-apply.path"
fi
if [ "$START" = 1 ]; then
    systemctl restart jt-waf-mgr.service
    sleep 2
    systemctl is-active --quiet jt-waf-mgr.service && say "jt-waf-mgr is running" \
        || { systemctl status --no-pager jt-waf-mgr.service || true; die "service did not start"; }
fi

say ""
say "Next steps:"
say "  1. jt-waf-mgr check                                 (reads the nginx / ModSecurity configuration)"
say "  2. jt-waf-mgr user add <name> --role admin          (prints a temporary password)"
say "  3. add the management vhost: $ETC/nginx-vhost.conf.example, then nginx -t and reload"
say "  4. sign in, change the password, set up TOTP"
