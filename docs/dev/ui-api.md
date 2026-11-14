# jt-waf-mgr UI ↔ backend contract (P0 + P1)

Internal development contract between the Vue frontend and the Python backend. The public API
description is `docs/spec/API.md`; this file pins the exact JSON the UI uses.

## Conventions

- Base path `/api/v1`. JSON, UTF-8. Times are RFC 3339 strings with offset (`2026-11-10T10:21:00+08:00`).
- Errors: HTTP status + `{"error": {"code": "snake_case", "message": "English text", "details": {}}}`.
  The UI translates by `code` (i18n key `error.<code>`), falling back to `message`.
- Session auth: cookie set by `/auth/login` (HttpOnly; the UI never reads it). Every non-GET request
  must send header `X-CSRF-Token: <csrf_token>` (value from `/auth/login` or `/auth/me`).
- Lists: `?limit=` (default 100, max 1000) and `?cursor=`; response `{"items": [...], "next_cursor": "..." | null}`.
- 401 `not_authenticated` on any call → UI goes to the login page.
- 403 `forbidden` → role too low.
- Roles, ascending: `viewer` < `operator` < `approver` < `admin`.
- All strings that come from requests (uri, path, query, host, user agent, matched data, messages)
  are attacker-controlled: render with `{{ }}` text interpolation only. **Never `v-html`.**

## Public

`GET /api/v1/meta` (no auth)
```json
{"name": "jt-waf-mgr", "version": "0.1.0", "source_url": "https://github.com/jasoncheng7115/jt-waf-mgr",
 "sso_enabled": false, "node_id": "waf1"}
```

## Auth

`GET /api/v1/auth/me` → 200
```json
{"user": {"username": "alice", "display_name": "Alice", "role": "admin", "totp_enabled": true,
          "must_change_password": false, "language": "zh-TW"},
 "csrf_token": "…"}
```
or 401 `not_authenticated`.

`POST /api/v1/auth/login` body `{"username": "", "password": "", "totp": "123456"}` (`totp` optional)
- 200 same shape as `/auth/me`.
- 401 `invalid_credentials` | 401 `totp_required` (show the TOTP field, resubmit with it) | 401 `totp_invalid`
- 429 `too_many_attempts` with `details.retry_after` seconds.
- No CSRF header needed for login.

`POST /api/v1/auth/logout` → 204.

`POST /api/v1/auth/password` body `{"current_password": "", "new_password": ""}` → 204 |
400 `password_too_short` (`details.min_length`) | 400 `password_same` | 401 `invalid_credentials`.
When `must_change_password` is true the UI shows only the change-password screen.

`POST /api/v1/auth/totp/setup` → `{"secret": "BASE32…", "otpauth_uri": "otpauth://totp/…"}` (not yet enabled)
`POST /api/v1/auth/totp/enable` body `{"code": "123456"}` → 204 | 400 `totp_invalid`
`POST /api/v1/auth/totp/disable` body `{"password": "", "code": ""}` → 204 | 401 | 400 `totp_required_for_role`

`PATCH /api/v1/auth/me` body `{"language": "en|zh-TW|ja", "display_name": "…"}` → 200 user object.

## Status and overview

`GET /api/v1/status` (viewer)
```json
{"version": "0.1.0", "node_id": "waf1",
 "engine_mode": "DetectionOnly",              // global SecRuleEngine
 "external_threshold_block": true,           // a rule like "external over threshold → block" exists
 "crs": {"version": "4.30.0", "paranoia_level": 1, "blocking_paranoia_level": 1,
         "inbound_threshold": 5, "outbound_threshold": 4},
 "collector": {"audit_log": "/var/log/modsecurity/modsec_audit.log", "running": true,
               "last_event_at": "…", "lag_seconds": 3, "parse_errors": 0, "oversized": 0,
               "events_total": 12345},
 "nginx": {"version": "1.30.6", "module_mismatch": null},   // null = unknown/not checked
 "managed_files_drift": null,                                 // P2
 "last_apply": null}                                          // P2
```

`GET /api/v1/overview?range=24h|7d` (viewer)
```json
{"range": "24h", "since": "…", "until": "…",
 "totals": {"events": 0, "blocked": 0, "logged": 0, "external": 0, "internal": 0,
            "blocked_confident": 0, "blocked_score": 0},
 "timeline": [{"t": "…", "blocked": 0, "logged": 0}],          // 24 hourly or 7*24 hourly buckets
 "by_host":   [{"key": "app.example.com", "blocked": 0, "logged": 0}],   // top 15
 "by_family": [{"key": "sqli", "blocked": 0, "logged": 0}],
 "by_src":    [{"key": "203.0.113.7", "origin": "external", "blocked": 0, "logged": 0}],
 "by_rule":   [{"key": "930120", "msg": "…", "blocked": 0, "logged": 0}],
 "by_country": [{"key": "JP", "label": "Japan", "blocked": 0, "logged": 0, "sources": 0}],   // external, GeoIP: every country (the UI draws the world map and lists the top 15); [] without GeoIP
 "by_asn":    [{"key": "64500", "label": "Example Hosting", "blocked": 0, "logged": 0, "sources": 0}],   // top 15; [] without GeoIP
 "geoip": true,                         // false: no GeoIP database yet (the overview then says how to set it up)
 "score_only": [EventSummary, …],      // external, blocked, decided_by=score: most likely false positives, newest first, max 50
 "focus": [{"host": "sso.example.com", "events": 0, "blocked": 0, "external": 0,
            "external_not_blocked": 0, "recent": [EventSummary, …]}]}   // one per configured focus site
```
Families (stable keys, UI translates `family.<key>`): `protocol`, `lfi`, `rfi`, `rce`, `php`, `generic`,
`xss`, `sqli`, `session`, `java`, `scanner`, `method`, `body`, `data_leak`, `local`, `other`.

## Events

`EventSummary`
```json
{"id": 123, "ts": "…", "host": "app.example.com", "method": "GET",
 "path": "/x.php", "query": "a=1&password=***",     // already redacted, may be ""
 "src_ip": "203.0.113.7", "origin": "external",     // external | internal
 "status": 403, "outcome": "blocked",                // blocked | logged
 "decided_by": "confident",                          // confident | score | fallback | other | null (logged)
 "rule_ids": [930120, 949110], "families": ["lfi"], "message": "first non-scoring rule message",
 "local_rule_ids": [10203]}                          // rule ids in the site's local range (10000–19999)
```

`GET /api/v1/events?since&until&host&path_prefix&src_ip&country&rule_id&outcome&decided_by&origin&family&q&limit&cursor`
→ `{"items": [EventSummary], "next_cursor": …}`, newest first. `src_ip` may be a CIDR. `q` = substring on path.
`country` = two-letter code: external sources GeoIP places in that country (none without a GeoIP database); the
same filter works on `/overview` and `/events/timeline`.

`GET /api/v1/events/{id}` → EventSummary plus
```json
{"unique_id": "…", "http_version": "1.1", "engine": "Enabled", "client_port": 51234,
 "server_port": 443, "anomaly_score": 10,           // null if not derivable
 "matches": [{"rule_id": 930120, "message": "…", "severity": "CRITICAL", "data": "Matched Data: … (redacted, ≤512 chars)",
              "tags": ["attack-lfi", "paranoia-level/1"], "file": "/etc/nginx/modsec/crs/rules/REQUEST-930-…conf",
              "line": 123, "family": "lfi", "local": false}],
 "truncated": false}
```

`GET /api/v1/events/stats?group_by=host|rule|src_ip|family|hour&since&until` →
`{"group_by": "host", "items": [{"key": "…", "blocked": 0, "logged": 0}]}`

`GET /api/v1/events/export?cursor=` → NDJSON (headers `X-Next-Cursor`, `X-Content-SHA256`). UI does not use it.

## Rules (read-only in P1)

`Rule`
```json
{"id": 10203, "file": "/etc/nginx/modsec/jt-before-crs.conf", "line": 120,
 "directive": "SecRule",                 // SecRule | SecAction | SecRuleRemoveById | SecRuleUpdateTargetById | modsecurity_rules
 "phase": 1, "disruptive": "pass",       // deny | block | pass | allow | drop | redirect | null
 "msg": "…", "tags": ["…"], "severity": null,
 "source": "local",                      // local | crs | plugin | vhost_inline | base
 "managed": false,
 "category": "exclusion",                // exclusion | confident_block | system | redaction | plugin_toggle | other  (guessed for unmanaged)
 "hosts": ["file2.example.com"],         // best-effort from REQUEST_HEADERS:Host conditions, [] if global
 "comment": "comment lines right above the rule, joined",
 "text": "full rule text as written (multi-line)",
 "hits_7d": 0, "hits_30d": 0, "last_hit": null}
```
`GET /api/v1/rules?source=local|crs|plugin|vhost_inline|base|all&category=&family=&state=&q=&limit&cursor` (viewer) →
`{"items": [Rule], "next_cursor", "total", "summary": [{"key": "<category, or attack family for source=crs>", "on": n,
"partial": n, "off": n, "inactive": n}]}` (the summary counts the whole source, before the other filters).
Default `source=local` (CRS has ~700 rules; UI offers a filter). `q` matches id, msg, comment, hosts.
Every Rule also has `"state": "on|partial|off|inactive"` with `"state_detail"`: `off` = removed for every request
(`{"where": "file:line"}`, or `{"managed_item": id}` for a managed rule switched off, listed although not in the files),
`partial` = removed by a `ctl:ruleRemoveById/ByTag` exclusion (`{"hosts": [..., "*" = by path or source]}`),
`inactive` = a CRS rule above the paranoia level (`{"level", "paranoia_level"}`); `"family"` (CRS attack type) and
`"managed"` (true when the rule is in a jt-waf-mgr managed file).
`author` (who wrote the rule; also a filter `author=` and counts `"authors": [{"key", "n"}]` over the source):
`owasp_crs` | `owasp_crs_plugin` (a plugin whose header names the OWASP CRS project) | `third_party` (another plugin) |
`modsecurity` (modsecurity.conf, 200000-200099) | `jason_tools` (generated by jt-waf-mgr from a form, i.e. a managed
rule other than raw, or the jt-modsecurity rule pack: ids 13501-13599 / files jt-modsecurity*) | `site` (written for
this site: imported at adoption, raw rules, vhost inline rules, other site files).
`GET /api/v1/rules/{id}` → Rule. `GET /api/v1/rules/{id}/hits?days=30` → `{"items": [{"day": "2026-11-10", "blocked": 0, "logged": 0}]}`

`POST /api/v1/rules/toggle` (operator; token scope `changes:propose`) — switch several rules, or a whole category, on
or off as ONE change (a bundle): `{"action": "disable|enable", "rule_ids": [..] | "group": {"source": "crs|local",
"key": "<family|category>"}, "scope": {"mode": "hosts", "hosts": [..]} | {"mode": "all"}, "reason": "...",
"preview": true?}`. Managed site rules are disabled / enabled; CRS rules are switched off by exclusions for the chosen
sites, or by `SecRuleRemoveById` for every request (an expert rule: admins only), and back on by switching off the
managed rules that remove them. `preview` → `{"rule_ids", "operations", "by_kind", "skipped": [{"id", "reason"}],
"strict"}`; otherwise 202 `{"change_id", "direction", "state", "operations", "skipped", "strict"}`. A whole CRS
category switched off is `strict`: only an admin approves it, with a one-time code and a written reason. Skip reasons:
already, not_loaded, not_managed, system_rule, paranoia_level, shared_item, removed_outside.

Also `GET /api/v1/rules/removals` → configure-time removals/updates
`{"items": [{"directive": "SecRuleUpdateTargetById", "target_ids": [942100], "args": "!ARGS:search", "file": "…", "line": 3, "comment": "…"}]}`

## Request volume

`GET /api/v1/traffic?range=24h|7d|30d|custom&since&until&host=` (viewer; token scope `events:read`) →
`{"enabled", "alert", "polled_at", "files", "range", "since", "until", "host", "bucket_seconds": 3600 | 86400,
"series": [{"t", "total", "s2xx", "s3xx", "s4xx", "s5xx", "s403", "s444", "s429", "external", "bytes", "other",
"blocked", "logged"}], "by_host": [{"host", ...the same counts..., "blocked", "logged"}] (200 busiest),
"totals": {...}}`. Counts come from the nginx access logs (traffic.py; numbers only), `blocked` / `logged` from the
WAF events of the same sites and time. Hourly up to 7 days, per local day beyond. Settings: `traffic.enabled`,
`traffic.logs`, `traffic.keep_days`, `traffic.alert`, `traffic.spike_factor`, `traffic.min_requests`,
`traffic.error_percent` (PATCH /settings/ui). Alerts: kinds `traffic_spike`, `traffic_errors` (source `traffic`).

## Temporary IP blocks

blocks.py, api_blocks.py; settings `blocks.*` (`blocks.file` only in config.toml). An nginx deny list the apply program
writes (`action: blocks` requests in the spool, `blocks-<ms>.req`, at most once per `reload_seconds`, one in flight);
the administrator includes the file once inside `http { }`. The file always ends in `allow all;` (nginx's default), which
is also how `included` is detected.

- `GET /api/v1/blocks?state=active|all|removed|expired` (viewer; token `blocks:read`) → `{"enabled", "file", "included",
  "included_in": "http"|"server"|null, "uncovered": [{"server", "location", "file", "line"}], "applied": {"at", "ok",
  "count", "summary"}, "pending", "in_sync", "limits": {...}, "items": [Block]}`
- `POST /api/v1/blocks` (approver: ranges up to /24 or /64, up to `ui_max_ttl`; token `blocks:write`: single addresses,
  up to `api_max_ttl`, `token_per_hour`) `{"ip", "ttl"?, "source"?, "reason"}` → 201 Block. Same (ip, source) active →
  extended.
- `DELETE /api/v1/blocks/{ip}?source=` (token `blocks:write`: its own entries only) → `{"removed": n}`
- `POST /api/v1/blocks/{id}/remove` (approver, `{"note"}` required) → `{"removed": 1}`
- `POST /api/v1/blocks/{id}/extend` (approver; `{"ttl": seconds | "permanent", "reason"}`) → the block. A new end is
  counted from now, up to `ui_max_ttl`, and must be later than the current one (409 `not_later`); `"permanent"` is for
  an admin (403 `admin_required`). `POST /blocks` also takes `"ttl": "permanent"` from an admin in the interface, never
  from a token. Each block has `permanent` (its `expires_at` is then null) and, in the list, `geo`.
- Events: `redirected` (logged, a 3xx answer, a confident-block or country rule matched); `GET /events?outcome=redirected`.
- `GET /traffic` has `previous`: the totals of the same length of time just before (null when nothing was counted).

Country blocks (0.4.27; countries.py, rulegen kind `country`):
- `GET /api/v1/countries` (viewer) → `{"enabled", "rules_dir", "generated_at", "stale", "countries": {CC: {"v4", "v6",
  "v4_addresses"}}, "registries": {name: {"ipv4", "ipv6", "countries", "size"}}, "last_run", "last_ok", "last_note",
  "last_errors", "requested", "sets": [SET...], "set_users": {SET: [host, "host (#change)"...]},
  "applied": {"at", "ok", "summary"}, "pending"}`
- `GET /api/v1/countries/sites` (viewer, scope `rules:read`) → `{"enabled", "generated_at", "sites": [{"host", "names",
  "blocks": [{"file", "line", "listen", "waf"}], "waf_off", "bypass": [location...], "restrictions": [text...],
  "countries": [{"item_id", "rule_id", "enabled", "mode", "countries"}], "country_changes": [{"change_id", "op", "state",
  "item_id", "mode", "countries"}], "uncovered": [name...], "recent": null | {"days": 7, "refused", "sources", "last_at",
  "countries": [{"country", "requests"}]}}], "unmatched_rules": [...], "unmatched_changes": [...]}`. Sites are server
  blocks grouped by their first plain name; a regex-only or catch-all block is not a site.
- `POST /api/v1/countries/update` (admin) → 202, the same object; leaves `update.request` for jt-waf-mgr-countries.path.
- Changes: `kind: "country"`, spec `{"host": {"mode": "exact", "value"}, "mode": "allow"|"deny", "countries": [CC...],
  "note"}`; 409 `countries_off` / `countries_no_data`, 422 `invalid_spec` (`unknown_country`, `invalid_countries`).
  Evidence: `{"informational": true, "requests", "refused", "refused_sources", "refused_success", "countries",
  "success_samples"}`. Tests may carry `src_ip` (public, `external` only).
- Root apply request `{"action": "countries", "sets": {SET: [CC...]}, "manifest_sha256", "want"}`; result
  `{"action": "countries", "sets", "want", "changed", "summary"}` (file `countries-<ms>.req`).

`Block`: `{"id", "ip", "source", "reason", "state": "active|removed|expired", "created_at", "expires_at", "created_by",
"via": "token|user", "extended", "ended_at", "ended_by"}`. Errors: 409 `blocks_off`, `too_many_blocks`,
`too_many_for_token`; 422 `invalid_ip`, `not_public`, `protected`, `single_address_only`, `range_too_wide`,
`invalid_ttl`, `invalid_source`, `reason_required`, `note_required`; 429 `rate_limited`; 404 `not_found`.
Audit: `block.add`, `block.extend`, `block.remove`, `block.refused`, `block.expired`, `block.applied`,
`block.apply_failed` (crit, plus an alert). `GET /lookups/ip/{ip}` has `blocked_now` and `blocks`.

## Vhosts

`GET /api/v1/vhosts` (viewer)
```json
{"items": [{"server_names": ["app.example.com"], "listen": ["443 ssl"], "file": "/etc/nginx/vhost/app.conf", "line": 40,
  "waf": "on",                    // on | off | block (vhost forces SecRuleEngine On) | unknown
  "inline_rule_ids": [10100],
  "bypass": [{"location": "/remote.php/dav", "file": "…", "line": 88}],   // locations with modsecurity off
  "body_limit": "10G",            // client_max_body_size, null if default
  "restrictions": ["if ($lan = 0) { return 444; }", "allow 192.0.2.0/24; deny all"],   // raw directives, text only
  "realip": false,                // set_real_ip_from in effect for this server
  "upstreams": ["http://192.0.2.10:8080"],
  "reach": "internal",            // internal | country | limited | restricted | open: nginx's own checks for the block
  "reach_by": "if ($lan = 0)",    // the checks it was decided from, text only
  "redirect_only": false,         // the block only redirects (return 30x, nothing served)
  "outside_7d": 0,                // outside requests to its names in the last 7 days (null: statistics off)
  // the managed country rules whose site covers one of the server names, and country changes still on their way
  "countries": [{"item_id": 7, "rule_id": 10301, "enabled": true, "mode": "allow", "countries": ["JP", "TW"]}],
  "country_changes": [{"change_id": 41, "op": "modify", "state": "pending_approval", "item_id": 7, "mode": "allow",
                       "countries": ["TW"]}]}],
 "warnings": ["rules file loaded per vhost: …"]}
```

## CRS

`GET /api/v1/crs` (viewer)
```json
{"version": "4.30.0", "path": "/etc/nginx/modsec/crs", "setup_file": "/etc/nginx/modsec/crs-setup.conf",
 "paranoia_level": 1, "blocking_paranoia_level": 1, "detection_paranoia_level": 1,
 "inbound_threshold": 5, "outbound_threshold": 4,
 "engine_mode": "DetectionOnly", "request_body_access": true, "request_body_limit": 13107200,
 "request_body_limit_action": "ProcessPartial", "pcre_match_limit": 1000,
 "audit": {"engine": "RelevantOnly", "parts": "AHZ", "format": "JSON", "log": "/var/log/…", "relevant_status": "^999$"},
 "plugins": [{"name": "nextcloud-rule-exclusions", "files": ["…-config.conf", "…-before.conf"]}],
 "rule_files": 27, "rule_count": 690,
 "warnings": []}
```

CRS updates (0.4.20; step 1 of 3: check, download, verify, stage — nothing in nginx changes):

`GET /api/v1/crs/updates` (viewer) →
```json
{"manage": false, "wait_days": 7, "external_updater": "/etc/cron.d/jt-crs-update" | null,
 "location": {"path": "/etc/nginx/modsec/crs", "link": true, "target": "/etc/nginx/modsec/crs-4.30.0", "version": "4.30.0"},
 "versions": ["4.29.0", "4.30.0"],
 "status": {"checked_at": "…", "state": "current|waiting|ready|error|off", "installed": "4.30.0",
            "candidate": {"version": "4.31.0", "published_at": "…", "ready_at": "…"},
            "staged": {"version": "4.31.0", "path": "…/stage/crs-4.31.0", "tarball": "coreruleset-4.31.0-minimal.tar.gz",
                       "tarball_sha256": "…", "manifest_sha256": "…", "files": 50, "verified_at": "…"},
            "newer_major": "5.0.0" | null, "error": "…"}}
```
`POST /api/v1/crs/updates/check` (admin; 409 `crs_not_managed` while `crs.manage` is off) → 202: asks
`jt-waf-mgr-crs.service` to check now. Settings: `crs.manage` (default off), `crs.wait_days` (0–60, default 7).
The unit takes the newest release of the major version in use once it has been out `wait_days`, downloads the
"minimal" tarball and its `.asc`, keeps it only if the signature is valid and made by the pinned CRS release key
(primary key `36006F0E0BA167832158821138EEACA1AB8A6E72`, shipped in `jtwafmgr/data/`), unpacks plain files only into
`/var/lib/jt-waf-mgr/crs/stage/crs-<version>` and opens a `crs_update` alert. A bad signature is audited as
`crs.signature_bad` (critical).

Step 2 (0.4.21): `POST /api/v1/crs/updates/propose` (approver; not API tokens) `{"mode": "install" | "rollback",
"version": "4.31.0", "reason": "..."}` → 202 `{"change_id"}`: a change `op: "crs"` (one open at a time,
`crs_change_pending`). Install takes the staged release (its files are hashed again: `crs_stage_changed`), rollback a
`crs-<version>` directory kept on the host. Checks: the sandbox runs the same recent requests through the CRS in use
and through the other version (`checks.sandbox`: `requests`, `blocked_before`, `blocked_after`, `newly_blocked`,
`no_longer_blocked`, `changed`, `differences` (≤ 50)). Always approved by a person other than the proposer. The root
program (`crs_switch` request) reads the staged tarball without following links, checks its SHA-256 and the signature
again (pinned key), unpacks it itself into `<dir>/crs-<version>`, refuses it unless its files hash to exactly the
manifest that was compared, turns a plain `crs/` directory into `crs-<version>` + link on the first switch, points the
`crs` link at the new directory, runs `nginx -t`, reloads and health-checks, and switches back on any failure; it keeps
the three newest `crs-*` directories. When applied, the open `crs_update` alert is closed.

Step 3 (0.4.22), a host without the CRS: the unit stages the newest 4.x release (`status.first_install: true`); `mode:
"first_install"` proposes installing it. The sandbox compares the requests without and with the CRS (its example setup
and rules added after `modsecurity.conf`). The root program refuses unless no CRS is included and `crs` next to the
main file does not exist yet; it installs `crs-<version>`, links `crs` to it, copies `crs-setup.conf.example` to
`crs-setup.conf` when there is none, and inserts `Include <dir>/crs-setup.conf` and `Include <dir>/crs/rules/*.conf`
right after the `modsecurity.conf` Include (else at the end); any failure puts the main file back and removes what it
created. Error `crs_path_exists`: a crs directory is there but not included.

## Lookups

`GET /api/v1/lookups/ip/{ip}` (viewer) →
```json
{"ip": "203.0.113.7", "origin": "external",
 "d7": {"events": 0, "blocked": 0}, "d30": {"events": 0, "blocked": 0},
 "first_seen": null, "last_seen": null,
 "hosts": [{"key": "…", "events": 0}], "rules": [{"key": "930120", "events": 0}],
 "blocked_now": false}
```

## Admin (role admin)

`GET /api/v1/users` → `{"items": [{"username", "display_name", "role", "disabled", "totp_enabled", "last_login", "created_at"}]}`
`POST /api/v1/users` body `{"username", "display_name", "role"}` → 201 `{"user": …, "temporary_password": "…"}` (shown once; user must change at first login)
`PATCH /api/v1/users/{username}` body any of `{"display_name", "role", "disabled"}` → 200 user.
`POST /api/v1/users/{username}/reset` → `{"temporary_password": "…"}` (also clears TOTP).
Errors: 409 `user_exists`, 400 `invalid_username`, 400 `cannot_modify_self` (own role/disabled), 400 `last_admin`.

`GET /api/v1/tokens` → `{"items": [{"id": "abc123", "name": "jt-ipam", "scopes": ["lookups:read"], "allowed_cidrs": ["192.0.2.0/24"],
  "expires_at": null, "created_by": "alice", "created_at": "…", "last_used_at": null, "revoked": false}]}`
`POST /api/v1/tokens` body `{"name", "scopes": [], "allowed_cidrs": [], "expires_at": null}` → 201 `{"token": {…}, "secret": "jwm_abc123_…"}` (shown once)
`DELETE /api/v1/tokens/{id}` → 204 (revokes).
Scopes offered in P1: `status:read`, `events:read`, `rules:read`, `lookups:read`.

`GET /api/v1/audit?action=&actor=&limit&cursor` → `{"items": [{"id", "ts", "action", "actor", "actor_type": "user|token|system",
  "src_ip", "result": "ok|denied|error", "details": {}}], "next_cursor"}`

`GET /api/v1/settings` (admin) → read-only view of the effective configuration (`internal_networks`, `focus_sites`,
`sensitive_fields`, `id_ranges`, `audit_log`, `nginx_conf`, `retention_days`, `password_min_length`, `require_totp_roles`).
Editing comes in a later phase (config file for now).

## UI pages (P1)

- Login (+ TOTP step), forced password change, my account (language, display name, password, TOTP setup with secret text + otpauth URI)
- Overview (range toggle 24h/7d; totals; "blocked only by CRS score" list on top; focus site cards; by host/family/source/rule; simple hourly bar chart in SVG, no chart library)
- Events (filters in the URL query so links are shareable; table; detail page; buttons "same IP", "same rule", "same host", "IP lookup")
- Rules (local by default, filter by source/category/q; detail with comment + full text in `<pre>` as text; removals list)
- Vhosts (WAF state, bypass locations, body limit, restrictions, realip, inline rule ids, warnings)
- CRS (status card)
- Admin: users, API tokens, audit log, settings (read-only)
- Footer on every page: `jt-waf-mgr v<version>` + "Source code (AGPL-3.0)" link to `source_url`.
- Language switcher en / zh-TW / ja (saved via PATCH /auth/me, and localStorage before login).
