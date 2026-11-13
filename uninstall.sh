#!/bin/sh
# jt-waf-mgr uninstaller.
#
#   sudo ./uninstall.sh            remove the service and the program; keep data and configuration
#   sudo ./uninstall.sh --purge    also remove /var/lib/jt-waf-mgr, /etc/jt-waf-mgr and the jtwaf user
#
# The nginx configuration is never touched: remove the management vhost yourself.
set -eu
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

for u in jt-waf-mgr-countries.path jt-waf-mgr-countries.timer jt-waf-mgr-countries.service jt-waf-mgr-notify.path jt-waf-mgr-notify.timer jt-waf-mgr-notify.service jt-waf-mgr-analyst.path jt-waf-mgr-analyst.timer jt-waf-mgr-analyst.service jt-waf-mgr-geoip.path jt-waf-mgr-geoip.timer jt-waf-mgr-geoip.service jt-waf-mgr-apply.path jt-waf-mgr-apply.service jt-waf-mgr.service; do
    systemctl disable --now "$u" 2>/dev/null || true
    rm -f "/etc/systemd/system/$u"
done
echo "note: the managed files in /etc/nginx/modsec/jt-waf-mgr stay in place (nginx includes them)" 
rm -rf /etc/systemd/system/jt-waf-mgr.service.d
systemctl daemon-reload
rm -rf /usr/lib/jt-waf-mgr
rm -f /usr/bin/jt-waf-mgr
echo "removed the service and the program"

if [ "$PURGE" = 1 ]; then
    chattr -a /var/lib/jt-waf-mgr/audit-anchors.jsonl 2>/dev/null || true
    rm -rf /var/lib/jt-waf-mgr /etc/jt-waf-mgr
    id jtwaf >/dev/null 2>&1 && userdel jtwaf
    echo "removed data, configuration and the jtwaf user"
else
    echo "kept /var/lib/jt-waf-mgr (database) and /etc/jt-waf-mgr (configuration)"
fi
echo "nginx: remove the jt-waf-mgr management vhost yourself if you added one"
