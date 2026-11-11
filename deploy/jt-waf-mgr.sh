#!/bin/sh
# Runs the jt-waf-mgr command line as the service user (the database belongs to it).
export PYTHONPATH=/usr/lib/jt-waf-mgr PYTHONDONTWRITEBYTECODE=1
if [ "$(id -u)" = 0 ]; then
    exec runuser -u jtwaf -- python3 -m jtwafmgr --config /etc/jt-waf-mgr/config.toml "$@"
fi
exec python3 -m jtwafmgr --config /etc/jt-waf-mgr/config.toml "$@"
