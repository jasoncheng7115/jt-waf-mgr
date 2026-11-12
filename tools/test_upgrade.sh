#!/bin/sh
# Release gate: install the PREVIOUS release into a throwaway staging root, put synthetic data in it, then
# upgrade to the NEW release with upgrade.sh exactly as on a server — plus the paths that must not break:
# --check changes nothing, data survives, the audit trail records the change, a refused downgrade, a
# refused upgrade while an apply is pending, an automatic rollback when the new version fails to start,
# and a manual rollback. systemd is replaced by tools/upgrade-test/fake_systemctl.sh (no containers, no
# root, nothing outside the staging directory).
#
#   tools/test_upgrade.sh dist/jt-waf-mgr-OLD.tar.gz dist/jt-waf-mgr-NEW.tar.gz
set -eu
OLD_TGZ=$(readlink -f "${1:?previous release tarball}"); NEW_TGZ=$(readlink -f "${2:?new release tarball}")
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/jtwaf-upgrade-test.XXXXXX")
R="$W/root"; export JTWAF_ROOT="$R" FAKE_STATE="$W/state" JTWAF_SYSTEMCTL="$HERE/upgrade-test/fake_systemctl.sh"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
FAILS=0
pass() { printf '  PASS %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; FAILS=$((FAILS + 1)); }
cleanup() { "$JTWAF_SYSTEMCTL" stop jt-waf-mgr.service >/dev/null 2>&1 || true; [ "${KEEP:-0}" = 1 ] || rm -rf "$W"; }
trap cleanup EXIT
mkdir -p "$W/old" "$W/new" "$R"
tar -C "$W/old" -xzf "$OLD_TGZ"; tar -C "$W/new" -xzf "$NEW_TGZ"
OLDD=$(ls -d "$W"/old/jt-waf-mgr-*); NEWD=$(ls -d "$W"/new/jt-waf-mgr-*)
OLDV=${OLDD##*-}; NEWV=${NEWD##*-}
q() { python3 -I -c "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:$PORT$1', timeout=5))$2)"; }
db() { python3 -I -c "import sqlite3; print(sqlite3.connect('file:$W/data/jt-waf-mgr.db?mode=ro', uri=True).execute(\"$1\").fetchone()[0])"; }

echo "== install $OLDV into $R"
"$OLDD/install.sh" --root "$R" >/dev/null
cat > "$R/etc/jt-waf-mgr/config.toml" <<CONF
[node]
id = "upgrade-test"
[server]
listen = "127.0.0.1:$PORT"
secure_cookies = false
[paths]
db = "$W/data/jt-waf-mgr.db"
audit_log = "$W/data/modsec_audit.log"
nginx_conf = "$HERE/../tests/fixtures/site/nginx.conf"
nginx_bin = "/nonexistent/nginx"
[syslog]
enabled = false
[managed]
dir = "$W/data/managed"
spool = "$W/data/spool"
sandbox_dir = "$W/data/sandbox"
[integrity]
anchor_file = "$W/data/anchors.jsonl"
release_key = "$R/etc/jt-waf-mgr/release-key.pem"
[backup]
dir = "$W/data/backups"
CONF
if grep -q geoip "$OLDD/deploy/config.toml.example"; then printf '[geoip]\ndir = "%s"\nlicense_key_file = "%s"\n' "$W/data/geoip" "$W/data/mm.key" >> "$R/etc/jt-waf-mgr/config.toml"; fi
if grep -q apply_state "$OLDD/jtwafmgr/config.py"; then
    sed -i "s#^sandbox_dir = .*#&\napply_state = \"$W/data/apply-state\"#" "$R/etc/jt-waf-mgr/config.toml"
fi
mkdir -p "$W/data/spool"
python3 -c "
import sys; sys.path.insert(0, '$HERE/..')
from tests.helpers import record
open('$W/data/modsec_audit.log', 'w').write('\n'.join(record(ip='203.0.113.%d' % (i % 50 + 1), status=403 if i % 3 else 200, engine='Enabled', rules=[942100, 949110]) for i in range(120)) + '\n')"
PYTHONPATH="$R/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$R/etc/jt-waf-mgr/config.toml" user add alice --role admin >/dev/null
PYTHONPATH="$R/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$R/etc/jt-waf-mgr/config.toml" import "$W/data/modsec_audit.log" >/dev/null
"$JTWAF_SYSTEMCTL" enable jt-waf-mgr-apply.path; "$JTWAF_SYSTEMCTL" start jt-waf-mgr-apply.path
"$JTWAF_SYSTEMCTL" start jt-waf-mgr.service; sleep 3
[ "$(q /api/v1/meta "['version']")" = "$OLDV" ] && pass "$OLDV serving" || fail "$OLDV not serving"
EV0=$(db "SELECT COUNT(*) FROM events"); AU0=$(db "SELECT COUNT(*) FROM audit")
echo "   data: $EV0 events, $AU0 audit rows"

echo "== refusals"
touch "$W/data/spool/v9-c9.req"
if "$NEWD/upgrade.sh" >/dev/null 2>&1; then fail "upgrade ran with an apply pending"; else pass "refused while an apply request is pending"; fi
rm -f "$W/data/spool/v9-c9.req"
[ "$(q /api/v1/meta "['version']")" = "$OLDV" ] && pass "refusal changed nothing" || fail "refusal touched the service"

echo "== --check"
"$NEWD/upgrade.sh" --check > "$W/check.log" 2>&1 && pass "--check passes" || { fail "--check"; cat "$W/check.log"; }
[ -z "$(ls "$R/var/backups/jt-waf-mgr" 2>/dev/null | grep upgrade-)" ] && pass "--check made no backup" || fail "--check wrote a backup"

echo "== automatic rollback when $NEWV does not start"
if FAKE_FAIL_VERSION=$NEWV "$NEWD/upgrade.sh" > "$W/fail.log" 2>&1; then fail "upgrade reported success although start failed"; else pass "failed upgrade reported"; fi
grep -q "rolled back" "$W/fail.log" && pass "rolled back automatically" || { fail "no automatic rollback"; tail -20 "$W/fail.log"; }
[ "$(q /api/v1/meta "['version']")" = "$OLDV" ] && pass "$OLDV serving again" || fail "$OLDV not serving after rollback"
[ "$(db "SELECT COUNT(*) FROM events")" = "$EV0" ] && pass "events intact" || fail "events changed"
"$JTWAF_SYSTEMCTL" is-active jt-waf-mgr-apply.path && pass "apply trigger re-armed" || fail "apply trigger left disarmed"

echo "== upgrade $OLDV -> $NEWV"
"$NEWD/upgrade.sh" > "$W/up.log" 2>&1 && pass "upgrade succeeded" || { fail "upgrade failed"; tail -30 "$W/up.log"; }
[ "$(q /api/v1/meta "['version']")" = "$NEWV" ] && pass "$NEWV serving" || fail "$NEWV not serving"
[ "$(db "SELECT COUNT(*) FROM events")" = "$EV0" ] && pass "events kept ($EV0)" || fail "events lost"
[ "$(db "SELECT COUNT(*) FROM users WHERE username='alice'")" = 1 ] && pass "accounts kept" || fail "account lost"
[ "$(db "SELECT COUNT(*) FROM audit WHERE action='system.version_changed'")" -ge 1 ] && pass "audit trail records the version change" || fail "no version-change audit row"
"$JTWAF_SYSTEMCTL" is-active jt-waf-mgr-apply.path && pass "apply trigger re-armed" || fail "apply trigger left disarmed"
grep -q '"result":"ok"' "$R/var/backups/jt-waf-mgr/history.jsonl" && pass "history recorded" || fail "no history"
PYTHONPATH="$R/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$R/etc/jt-waf-mgr/config.toml" integrity >/dev/null && pass "integrity ok after upgrade" || fail "integrity after upgrade"

echo "== manual rollback"
"$NEWD/upgrade.sh" --rollback > "$W/rb.log" 2>&1 && pass "rollback succeeded" || { fail "rollback"; tail -20 "$W/rb.log"; }
[ "$(q /api/v1/meta "['version']")" = "$OLDV" ] && pass "$OLDV serving after rollback" || fail "$OLDV not serving"
[ "$(db "SELECT COUNT(*) FROM users WHERE username='alice'")" = 1 ] && pass "accounts intact after rollback" || fail "accounts lost"

[ -s "$R/etc/jt-waf-mgr/audit-rewinds.jsonl" ] && pass "rollbacks recorded as audit rewinds" || fail "no rewind record"

echo "== upgrade again (the path a site takes after fixing a problem)"
"$NEWD/upgrade.sh" > "$W/up2.log" 2>&1 && [ "$(q /api/v1/meta "['version']")" = "$NEWV" ] && pass "second upgrade ok" || fail "second upgrade"
PYTHONPATH="$R/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$R/etc/jt-waf-mgr/config.toml" integrity >/dev/null \
    && pass "integrity ok after rollbacks and re-upgrade (rewinds honoured)" || fail "integrity after re-upgrade"
if "$NEWD/upgrade.sh" >/dev/null 2>&1; then fail "re-upgrading to the same version was allowed"; else pass "same version refused"; fi

echo
[ "$FAILS" = 0 ] && echo "upgrade test: OK ($OLDV -> $NEWV)" || { echo "upgrade test: $FAILS FAILED (work dir kept: $W)"; KEEP=1; exit 1; }
