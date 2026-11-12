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

`GET /api/v1/events?since&until&host&path_prefix&src_ip&rule_id&outcome&decided_by&origin&family&q&limit&cursor`
→ `{"items": [EventSummary], "next_cursor": …}`, newest first. `src_ip` may be a CIDR. `q` = substring on path.

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
`GET /api/v1/rules?source=local|crs|plugin|vhost_inline|base|all&category=&q=&limit&cursor` (viewer) → list.
Default `source=local` (CRS has ~700 rules; UI offers a filter). `q` matches id, msg, comment, hosts.
`GET /api/v1/rules/{id}` → Rule. `GET /api/v1/rules/{id}/hits?days=30` → `{"items": [{"day": "2026-11-10", "blocked": 0, "logged": 0}]}`

Also `GET /api/v1/rules/removals` → configure-time removals/updates
`{"items": [{"directive": "SecRuleUpdateTargetById", "target_ids": [942100], "args": "!ARGS:search", "file": "…", "line": 3, "comment": "…"}]}`

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
  "upstreams": ["http://192.0.2.10:8080"]}],
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
