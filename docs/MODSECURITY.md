# Installing ModSecurity (nginx + libmodsecurity v3 + OWASP CRS 4)

**English** · [繁體中文](MODSECURITY.zh-TW.md) · [日本語](MODSECURITY.ja.md)

This guide starts from a host with only nginx (or nothing yet) and sets up the ModSecurity environment jt-waf-mgr
needs. You set up nginx, the ModSecurity module, `modsecurity.conf` and a main file (sections 1–5). The OWASP CRS is
then handled by jt-waf-mgr: it downloads, verifies and installs CRS 4 and keeps it current through approved changes
(section 6, the recommended way). Installing the CRS by hand still works (section 7). Sites that already run
ModSecurity do not have to follow this guide: compare with "What jt-waf-mgr needs" at the end of section 8.

jt-waf-mgr writes only ModSecurity files and never writes nginx configuration. It reads nginx's configuration (to find
the sites and ModSecurity's main file), runs `nginx -t` and reloads nginx. `modsecurity on;` in nginx (section 3) and
the management vhost ([README](../README.md#connect-to-the-management-interface)) are your own one-time edits.

> Go live in detection-only mode (`DetectionOnly`) first, watch the events in jt-waf-mgr for a while and deal with the
> false positives, then switch to blocking (`On`).

## 1. System and packages

- Debian 12 / 13: `libnginx-mod-http-modsecurity`; libmodsecurity 3.0.9 or later comes with it.
- Ubuntu 24.04: `libnginx-mod-http-modsecurity`; libmodsecurity 3.0.12 (package `libmodsecurity3t64`).
- Ubuntu 22.04: the packaged libmodsecurity is older than 3.0.9; use 24.04 or build it yourself.

```sh
sudo apt install nginx libnginx-mod-http-modsecurity
apt-cache policy libmodsecurity3 libmodsecurity3t64   # the version must be 3.0.9 or later
nginx -V 2>&1 | head -1                                # the distribution's nginx
ls /etc/nginx/modules-enabled/ | grep -i modsecurity    # the module is loaded
```

The connector module must come from the same build as the running nginx. With the nginx.org packages the
distribution's module does not load: use the distribution's nginx, or build the dynamic module from the same nginx
version's source (`./configure --with-compat --add-dynamic-module=ModSecurity-nginx`).

The distribution's `modsecurity-crs` package is CRS 3.3: **do not install it**. jt-waf-mgr installs CRS 4 for you
(section 6), or you install it by hand (section 7).

## 2. ModSecurity basics

The configuration lives in `/etc/nginx/modsec/`. Take `modsecurity.conf-recommended` and `unicode.mapping` from the
ModSecurity source at the tag of **the same version as your libmodsecurity**
([github.com/owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)).

```sh
sudo install -d -m 755 /etc/nginx/modsec
V=3.0.9   # the version apt-cache policy shows
cd /etc/nginx/modsec
sudo curl -fLo modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/modsecurity.conf-recommended
sudo curl -fLO https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/unicode.mapping
```

In `modsecurity.conf`, check or change these lines:

```apache
SecRuleEngine DetectionOnly          # log only at first; On after watching
SecAuditEngine RelevantOnly
SecAuditLogType Serial
SecAuditLogFormat JSON               # jt-waf-mgr reads the JSON format
SecAuditLog /var/log/modsecurity/modsec_audit.log
```

Keep `SecAuditLogParts` as it is in the file; jt-waf-mgr redacts sensitive request values (passwords, tokens,
cookies...) before they reach its database.

## 3. Main file and nginx

`/etc/nginx/modsec/main.conf`:

```apache
Include /etc/nginx/modsec/modsecurity.conf
```

That one line is all the recommended path needs: when jt-waf-mgr installs the CRS, it inserts the CRS Includes right
after it, and adoption adds jt-waf-mgr's managed rule files around the CRS rules. Site rule files of your own are
optional (section 7); adoption works without them.

In nginx, in `http { }` (all sites) or in a `server { }`:

```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

## 4. Audit log directory and rotation

```sh
sudo install -d -m 750 -o root -g adm /var/log/modsecurity
```

`/etc/logrotate.d/modsecurity` (libmodsecurity does not reopen the file on reload, hence `copytruncate`):

```
/var/log/modsecurity/modsec_audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

## 5. Check nginx

```sh
sudo nginx -t && sudo systemctl reload nginx
```

Without the CRS there are no rules yet, so nothing is logged; the request test follows in section 8, once the CRS is
installed.

## 6. OWASP CRS 4 through jt-waf-mgr (recommended)

1. Install jt-waf-mgr as the [README](../README.md#install) describes, connect to the management interface and arm the
   apply program (`sudo ./install.sh --enable-apply`). `sudo jt-waf-mgr check` lists the main file it found.
2. On the CRS page, switch on "Keep the CRS current from here".
3. jt-waf-mgr downloads the newest CRS 4.x once it has been out `wait_days` (default 7) and verifies it against the
   pinned CRS signing key.
4. "Compare in the sandbox and propose installing" creates a change.
5. After a person approves it, jt-waf-mgr installs `crs-<version>`, the `crs` link and `crs-setup.conf`, and inserts
   the Includes right after `modsecurity.conf`. `main.conf` then reads:

   ```apache
   Include /etc/nginx/modsec/modsecurity.conf
   Include /etc/nginx/modsec/crs-setup.conf
   Include /etc/nginx/modsec/crs/rules/*.conf
   ```

6. Then adoption (Rules → Managed rules, approved by an admin like any change) adds jt-waf-mgr's managed rule files
   around the CRS rules (`/etc/nginx/modsec/jt-waf-mgr/before-crs.conf` and `after-crs.conf`).

Later CRS updates work the same way: download, verify, compare in the sandbox, a person approves, install; 3 versions
are kept to roll back.

## 7. Alternative: install the CRS by hand

Download the latest 4.x release and its `.asc` signature from
[CRS's GitHub releases](https://github.com/coreruleset/coreruleset/releases), verify it with `gpg --verify` as the
CRS documentation describes, then unpack it:

```sh
CRS=4.x.y                                # the actual version
cd /etc/nginx/modsec
sudo tar xzf ~/coreruleset-$CRS.tar.gz   # file and directory names as on the releases page
sudo ln -sfn coreruleset-$CRS crs        # a later CRS upgrade only moves the link
sudo cp crs/crs-setup.conf.example crs-setup.conf
```

`/etc/nginx/modsec/main.conf` then reads:

```apache
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs-setup.conf
# optional: the site's own rules, before and after the CRS rules
Include /etc/nginx/modsec/site-before-crs.conf
Include /etc/nginx/modsec/crs/rules/*.conf
Include /etc/nginx/modsec/site-after-crs.conf
```

The two site files are optional. They hold the site's own rules (exclusions, blocks) and may start empty
(`sudo touch /etc/nginx/modsec/site-before-crs.conf /etc/nginx/modsec/site-after-crs.conf`). Without them, adoption
adds empty managed files around the CRS rules. With them, adoption imports their rules unchanged and points
`main.conf` at the files it manages. Either way, every rule change from then on goes through jt-waf-mgr's workflow,
and later CRS updates can go through jt-waf-mgr as in section 6.

## 8. Test

```sh
sudo nginx -t && sudo systemctl reload nginx
curl -s -o /dev/null -w '%{http_code}\n' 'http://localhost/?q=<script>alert(1)</script>'
sudo tail -n 1 /var/log/modsecurity/modsec_audit.log | python3 -m json.tool | head -20
```

In detection-only mode the response code is the usual one (200, for example) and the audit log has one JSON record
with CRS rule numbers.

What jt-waf-mgr needs:

- `SecAuditLogFormat JSON` and `SecAuditEngine` not `Off`;
- a main file that Includes `modsecurity.conf`, loaded in nginx with `modsecurity on;` and `modsecurity_rules_file`;
- the audit log directory readable by the `adm` group;
- the OWASP CRS 4, installed by jt-waf-mgr (section 6) or by hand (section 7).

## 9. Check and switch to blocking

Run `sudo jt-waf-mgr check`: it lists the main file it found, the CRS version and rule count, and any setting that does
not meet the requirements above. After watching for a while and dealing with the false positives, set
`SecRuleEngine` to `On`.
