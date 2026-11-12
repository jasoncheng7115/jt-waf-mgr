#!/bin/sh
# Stand-in for systemctl in tools/test_upgrade.sh: runs the staged service as a plain background process.
# State lives in $FAKE_STATE. FAKE_FAIL_VERSION=<v> makes "start" of that version fail (failure injection).
set -u
S=${FAKE_STATE:?}; R=${JTWAF_ROOT:?}
mkdir -p "$S"
[ "${1:-}" = "--quiet" ] && shift
cmd=${1:-}; [ "$cmd" = "is-active" ] || [ "$cmd" = "is-enabled" ] && [ "${2:-}" = "--quiet" ] && set -- "$1" "$3"
unit=${2:-}
pidf="$S/$unit.pid"
alive() { [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; }
case "$cmd" in
    start)
        case "$unit" in
            jt-waf-mgr.service)
                alive && exit 0
                v=$(sed -n "s/^__version__ = '\(.*\)'/\1/p" "$R/usr/lib/jt-waf-mgr/jtwafmgr/__init__.py")
                if [ "${FAKE_FAIL_VERSION:-}" = "$v" ]; then echo "fake: refusing to start $v" >&2; exit 1; fi
                PYTHONPATH="$R/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 nohup python3 -P -m jtwafmgr \
                    --config "$R/etc/jt-waf-mgr/config.toml" serve >>"$S/service.log" 2>&1 &
                echo $! > "$pidf" ;;
            *) touch "$S/$unit.active" ;;
        esac ;;
    stop)
        if alive; then kill "$(cat "$pidf")"; sleep 1; fi
        rm -f "$pidf" "$S/$unit.active" ;;
    is-active) alive || [ -f "$S/$unit.active" ] ;;
    is-enabled) [ -f "$S/$unit.enabled" ] ;;
    enable) touch "$S/$unit.enabled" ;;
    daemon-reload) : ;;
    *) echo "fake systemctl: $*" >&2 ;;
esac
