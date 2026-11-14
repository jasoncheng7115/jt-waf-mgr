# API manual for integrators

**English** · [繁體中文](API.zh-TW.md) · [日本語](API.ja.md)

This manual is for people who connect another system to jt-waf-mgr: a SIEM that pulls WAF events, a SOAR playbook
that proposes a block, or a script. The web interface uses the same endpoints with a signed-in session; an
integration uses an **API token**. Everything below describes what a token can do.

> **API tokens can propose changes but can never approve them.** Approving, rejecting, cancelling and rolling back
> are done by a person in the web interface. A token's proposal goes through the same checks as anyone else's.

All examples use made-up values: `waf.example.com`, addresses from 192.0.2.0/24, 198.51.100.0/24 and
203.0.113.0/24, and a fake token.

## 1. Basics

- **Base URL**: `https://<your jt-waf-mgr host>/api/v1`, for example `https://waf.example.com/api/v1`. jt-waf-mgr
  listens on 127.0.0.1 behind nginx; call it through that nginx site.
- **JSON**: responses are UTF-8 JSON (`application/json; charset=utf-8`) unless noted (NDJSON export, rule file
  download). A request with a body must send `Content-Type: application/json` and a JSON object; otherwise the answer
  is 415 or 400. Bodies are limited to 1 MiB by default (413 `payload_too_large`).
- **Versioning**: the major version is in the path (`/api/v1`). `GET /meta` returns the program version. New fields
  appear over time: ignore fields you do not know.
- **Time**: responses use RFC 3339 with the server's local offset, to the second, for example
  `2026-11-13T15:13:27+08:00`. Parameters such as `since` and `until` take RFC 3339 (`Z` or an offset); a time
  without an offset, or a bare date, is read in the server's local time.
- **Paging**: lists take `limit` and `cursor` and return `next_cursor` (a string, `null` on the last page). Pass
  `next_cursor` back unchanged as `cursor`. Lists are newest first unless noted.
- **Caching and compression**: every API response carries `Cache-Control: no-store`; send
  `Accept-Encoding: gzip` to get larger answers compressed.
- **Sensitive data**: fields such as passwords in request data are masked before they are stored. There is no option
  to see the original.

## 2. Authentication

### 2.1 Creating a token

- Only an **admin** can create tokens: in the web interface, **Admin > API tokens** (`/admin/tokens`), section
  "Create a token".
- Fill in a name (for example the name of the calling system), the allowed source addresses, an optional expiry date
  and one or more scopes.
- The token is shown **once**, right after it is created. Copy it into the calling system's secret store. The
  database keeps only a hash; a lost token cannot be shown again: revoke it and create a new one.
- A token looks like `jwm_<12 characters>_<secret>`. The examples use the fake
  `jwm_example00000_EXAMPLE-not-a-real-token`.
- The same page lists the tokens (scopes, sources, expiry, last use) and revokes them. A revoked token stops
  working at once.
- The admin who creates a token owns the changes proposed with it. That admin cannot approve those changes (see 6.3).

### 2.2 Scopes

A token has one or more of these scopes. There are no others.

- `status:read`: `GET /status`.
- `events:read`: events, event statistics, timeline, overview, NDJSON export.
- `rules:read`: rules, rule hits, sites (vhosts), CRS status and updates, the WAF decision model, managed rule files.
- `lookups:read`: IP lookup and GeoIP lookup.
- `changes:read`: changes, versions, alerts, event analysis runs, regression samples.
- `changes:propose`: propose changes (`POST /changes`, `POST /changes/preview`, `POST /rules/toggle`). Never approve.
- `blocks:read`: list the temporary IP blocks (`GET /blocks`).
- `blocks:write`: add, extend and end the token's own temporary IP blocks (single addresses only).

Give each token only what it needs. A SIEM that reads events needs `events:read`; a playbook that proposes blocks
needs `changes:propose` and `changes:read`.

### 2.3 Source restriction

- "Allowed source addresses" is a list of CIDRs, for example `192.0.2.10/32, 198.51.100.0/24`. Empty means any source.
  Restricting it is strongly recommended.
- The address checked is the client address as jt-waf-mgr sees it: the `X-Real-IP` that the local nginx sets (only a
  trusted proxy may supply it). Make sure the calling system reaches nginx directly, not through another proxy that
  hides its address.
- A call from another address gets 403 `token_source_not_allowed` and is recorded in the audit log.

### 2.4 Expiry

- Optional. Without an expiry date the token stays valid until revoked.
- An expired, revoked, unknown or malformed token gets 401 `invalid_token`.

### 2.5 Sending the token

Send it in the `Authorization` header with the `Bearer` scheme. Tokens need no cookie and no CSRF header.

```sh
TOKEN='jwm_example00000_EXAMPLE-not-a-real-token'
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/status
```

Every call with a token writes an audit record (`token.used`, or `token.denied` with the reason), with the token
name, source address and endpoint.

### 2.6 Sessions (for reference)

The web interface signs in with a user name, password and one-time code, gets a session cookie, and sends
`X-CSRF-Token` on every request that changes something. Integrations should not use sessions: use a token.

## 3. Errors and limits

Every error has the same shape:

```json
{"error": {"code": "token_source_not_allowed", "message": "token source not allowed", "details": {}}}
```

Act on `code`; `message` is for people; `details` adds context (for example the field that failed). Common codes:

- **400**: `bad_request` (a parameter is malformed, for example `limit must be a number`), `reason_required`,
  `invalid_op`, `invalid_kind`, `invalid_tests`, `no_effect` (for example disabling an item that is already off).
- **401**: `not_authenticated` (no token sent), `invalid_token` (unknown, malformed, revoked or expired).
- **403**: `forbidden` with message `token lacks scope` (`details.scope` names the scope needed; it is `null` on
  endpoints that no token may call); `forbidden` with message `not available to API tokens` (admin and account
  endpoints); `token_source_not_allowed`; `raw_admin_only` (expert-mode rules, see 4.4).
- **404**: `not_found`; `item_not_found` (the managed item in `item_id` does not exist).
- **405**: `method_not_allowed`.
- **409**: `not_adopted` (jt-waf-mgr does not manage the rule files yet, so no change can be proposed),
  `invalid_state` (`details.state`), `rule_id_in_use`, `id_range_full`, `nothing_to_change`.
- **413** `payload_too_large`; **415** (code `bad_request`): the body is not `application/json`.
- **422**: `invalid_spec` (`details.field` and `details.reason`, for example `regex` / `too_broad`),
  `invalid_bundle` (`details.index`, `details.limit` or `details.reason`), `invalid_rule_ids`, `invalid_group`,
  `invalid_scope`, `scope_required`, `invalid_action`.
- **429** `too_many_attempts` with a `Retry-After` header: sign-in and one-time-code attempts. Wait that many
  seconds.
- **500** `internal_error`.

**Rate limits**: this version has no per-token request rate limit. Poll at a modest interval (the worked example
waits 10 seconds between polls) and honour `Retry-After` if you ever get a 429. A reverse proxy in front of
jt-waf-mgr may add its own limits.

## 4. Endpoints

Paths below are relative to `/api/v1`. "Scope" is the token scope required.

### 4.1 Meta and status

**`GET /meta`**: no authentication. Name, version, source code URL, node id.

```sh
curl -sS https://waf.example.com/api/v1/meta
```
```json
{"name": "jt-waf-mgr", "version": "0.4.22", "source_url": "https://...",
 "sso_enabled": false, "node_id": "waf1", "login_notice": "", "password_policy": {"min_length": 12, "...": "..."}}
```

**`GET /status`**: scope `status:read`. Engine mode, CRS settings, and the collector that reads the ModSecurity audit
log (use `collector.running`, `lag_seconds` and `last_event_at` for monitoring).

```sh
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/status
```
```json
{"version": "0.4.22", "node_id": "waf1", "engine_mode": "On", "external_threshold_block": true,
 "crs": {"version": "4.30.0", "paranoia_level": 1, "blocking_paranoia_level": 1, "inbound_threshold": 5,
         "outbound_threshold": 4},
 "collector": {"running": true, "error": null, "last_event_at": "2026-11-13T15:13:27+08:00", "lag_seconds": 0,
               "parse_errors": 0, "oversized": 0, "insert_errors": 0, "events_total": 1234, "...": "..."},
 "nginx": {"version": "1.22.1", "module_mismatch": null}}
```

### 4.2 Events

**`GET /events`**: scope `events:read`. Events, newest first. Parameters (all optional):

- `since`, `until`: RFC 3339.
- `host` (exact), `path_prefix`, `q` (text contained in the path).
- `src_ip`: an address, or a network such as `203.0.113.0/24`.
- `country`: two-letter code; external sources only, needs GeoIP.
- `rule_id`: events where this rule matched.
- `outcome`: `blocked` or `logged`. `origin`: `external` or `internal`.
- `decided_by`: `confident`, `score`, `fallback` or `other`.
- `family`: `protocol`, `lfi`, `rfi`, `rce`, `php`, `generic`, `xss`, `sqli`, `session`, `java`, `scanner`,
  `method`, `body`, `data_leak`, `local` or `other`.
- `limit` (default 100, at most 1000), `cursor`.

```sh
curl -sS -H "Authorization: Bearer $TOKEN" \
  'https://waf.example.com/api/v1/events?outcome=blocked&origin=external&since=2026-11-13T00:00:00%2B08:00&limit=1'
```
```json
{"items": [{"id": 1, "ts": "2026-11-13T15:13:27+08:00", "host": "app.example.com", "method": "GET",
            "path": "/.env", "query": "", "src_ip": "203.0.113.7", "origin": "external", "status": 403,
            "outcome": "blocked", "decided_by": "confident", "rule_ids": [10205, 949110], "families": ["local"],
            "message": "jt confident block: dotenv probe", "local_rule_ids": [10205], "src_geo": null}],
 "next_cursor": "1"}
```

**`GET /events/{id}`**: scope `events:read`. One event with its rule matches, anomaly score and connection details.

```sh
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/events/1
```
```json
{"id": 1, "...": "the fields of the list item, plus:", "unique_id": "...", "http_version": "1.1",
 "engine": "Enabled", "client_port": 51234, "server_port": 443, "anomaly_score": null,
 "matches": [{"rule_id": 10205, "message": "...", "severity": "CRITICAL", "data": "", "match": "...",
              "tags": [], "file": "...", "line": 50, "family": "local", "local": true}],
 "truncated": false}
```

**`GET /events/export`**: scope `events:read`. Incremental export for a SIEM, as NDJSON (one full event per line),
**oldest first**. `cursor` is the last event id you have (start with 0); `limit` default 1000, at most 5000. The
response headers carry `X-Next-Cursor` (store it for the next call) and `X-Content-SHA256` (the SHA-256 of the body).
An empty body means you are up to date. Filters do not apply here.

```sh
curl -sS -D headers.txt -H "Authorization: Bearer $TOKEN" \
  'https://waf.example.com/api/v1/events/export?cursor=0&limit=1000' > events.ndjson
grep -i '^x-next-cursor' headers.txt
```

**`GET /events/stats`**: scope `events:read`. Counts grouped by `group_by` = `host` (default), `rule`, `src_ip`,
`family` or `hour`, over `since` / `until` (default the last 24 hours).

```json
{"group_by": "rule", "items": [{"key": "10205", "msg": "...", "family": "local", "blocked": 1, "logged": 0}]}
```

**`GET /events/timeline`**: scope `events:read`. The same filters as `/events`; `since` / `until` default to the last
7 days, at most 31 days (`clamped: true` when shortened). Hourly buckets up to 7 days, daily beyond.

**`GET /overview`**: scope `events:read`. The dashboard numbers: `range` = `24h` (default), `7d`, or `custom` with
`since` and `until` (1 hour to 31 days), plus the event filters. Returns `totals`, `previous` (the window before),
`timeline`, `by_host`, `by_family`, `by_src`, `by_rule`, `by_country`, `by_asn` and more.

### 4.3 Alerts

Alerts are things a person should look at (an attack that may have got through, a likely false positive, an integrity
problem, a failed apply, and so on).

- **`GET /alerts`**: scope `changes:read`. `state` = `open` or `handled`; `limit` (default 50, at most 200);
  `cursor`. The answer includes `counts`.
- **`GET /alerts/counts`**: scope `changes:read`. `{"open": 3, "critical": 1}`.
- **`GET /alerts/{id}`**: scope `changes:read`.

`kind` is one of `attack_in_progress`, `attack_passed`, `false_positive`, `integrity`, `config_outside`,
`apply_failed`, `backup_failed`, `auth_attack`, `crs_update`, `other`; `severity` is `critical` or `warning`.

```sh
curl -sS -H "Authorization: Bearer $TOKEN" 'https://waf.example.com/api/v1/alerts?state=open&limit=20'
```
```json
{"items": [{"id": 12, "created_at": "2026-11-13T09:00:04+08:00", "last_seen": "2026-11-13T12:00:03+08:00",
            "source": "analyst", "kind": "attack_passed", "severity": "critical", "count": 2,
            "details": {"run_id": 40, "...": "..."}, "link": "...", "state": "open", "handled_by": null,
            "handled_at": null, "note": null, "summary": "..."}],
 "next_cursor": null, "counts": {"open": 1, "critical": 1}}
```

Marking an alert as handled is done by an approver in the web interface.

### 4.4 Changes

A change is a proposal to add, modify, disable, enable or delete one rule in jt-waf-mgr's managed rule files, or
several at once (a bundle). Proposing requires that jt-waf-mgr already manages the site's rule files (adoption,
done once by an admin); before that every proposal gets 409 `not_adopted`.

**`POST /changes/preview`**: scope `changes:propose`. Renders the rule without creating anything. Use it to validate a
`spec` before proposing. Validation errors come back as 200 with `ok: false`.

```sh
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind": "confident_block", "spec": {"target": "path", "regex": "^/\\.env$", "msg": "dotenv probe"}}' \
  https://waf.example.com/api/v1/changes/preview
```
```json
{"ok": true, "rule_id": 10204, "rule_text": "SecRule REQUEST_FILENAME \"@rx ^/\\.env$\" ...",
 "placement": "before", "direction": "tighten"}
```
```json
{"ok": false, "field": "regex", "reason": "matches_empty", "details": {}}
```

**`POST /changes`**: scope `changes:propose`. Body:

- `op`: `add` (default), `modify`, `disable`, `enable`, `delete`, or `bundle`.
- `kind`: for `add`: `confident_block`, `exclusion`, `country`, `redaction`, `plugin` or `raw`.
- `spec`: the fields of the kind (below). `modify` takes the complete new spec.
- `item_id`: for `modify`, `disable`, `enable`, `delete`: the managed item id (`items[].id` of `GET /managed`).
- `reason`: required, at most 2000 characters. Shown to the approver.
- `tests`: optional, at most 50 requests run in the sandbox: `{"host", "path", "expect": 200 | 403,
  "source": "external" | "internal", "method"?, "headers"?, "body"?, "src_ip"?}`. `src_ip` (with `external` only):
  a public address the request comes from, for example one of a country a country block refuses.

The answer is 202 with the change id; the checks run in the background:

```json
{"change_id": 2, "direction": "tighten", "state": "checking", "rule_id": 10204}
```

`direction` is `tighten` (blocks or inspects more) or `loosen` (less). Anything unclear counts as loosening.
Loosening always needs a person's approval.

**Kind `confident_block`** (block requests that are certainly attacks, regardless of the anomaly score):

- `target`: `path` (default; URL-decoded, normalized, lowercased), `uri` (path and query, lowercased), `ua`
  (User-Agent), `host`, or `header` (then `header` names it, for example `X-Api-Version`).
- `regex`: required, at most 1000 characters, no double quotes or line breaks. Refused when it matches the empty
  string (`matches_empty`), matches almost every ordinary request (`too_broad`), or looks open to catastrophic
  backtracking (`redos_shape`, `redos_runtime`).
- `msg`: required, at most 100 characters, no quotes or backslashes. The rule message becomes
  `jt confident block: <msg>`.
- `exceptions`: optional, up to 10 regexes on the path that are never blocked.
- `host`: optional, `{"mode": "any"}` (default), `{"mode": "exact", "value": "app.example.com"}` (`*.example.com`
  allowed), or `{"mode": "regex", "value": "..."}`.
- `reference`: optional, at most 200 characters (a ticket or advisory).
- `source`: `external` (default; internal addresses are never blocked) or `all` (internal addresses too, except the
  known scanners).

**Kind `exclusion`** (stop a rule from firing where it causes false positives; always loosening):

- `host` and/or `path` (at least one): `path` is `{"mode": "exact" | "prefix" | "regex", "value": "/search"}`.
- `method`: optional, for example `POST`. `source`: `all` (default), `external` or `internal`.
- `action`: `remove_target_by_id` (default; needs `rule_ids` and `targets`), `remove_target_by_tag` (`tag` and
  `targets`), `remove_rule` (`rule_ids`), `remove_tag` (`tag` and `confirm_tag: true`), `score_only`, or
  `body_processor` (`body_processor` = `JSON`, `XML`, `URLENCODED` or `MULTIPART`).
- `rule_ids`: up to 20. `targets`: up to 20 ModSecurity variables such as `ARGS:q` or `REQUEST_COOKIES:session`.

```sh
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "kind": "exclusion", "reason": "search box triggers 941100 for normal users",
  "spec": {"host": {"mode": "exact", "value": "app.example.com"}, "path": {"mode": "exact", "value": "/search"},
           "action": "remove_target_by_id", "rule_ids": [941100], "targets": ["ARGS:q"]}}' \
  https://waf.example.com/api/v1/changes
```
```json
{"change_id": 3, "direction": "loosen", "state": "checking", "rule_id": 10120}
```

**Kind `country`** (new in 0.4.27; limit one site by country; needs country blocks switched on in Settings and the
lists downloaded, otherwise 409 `countries_off` / `countries_no_data`):

- `host`: required, `{"mode": "exact", "value": "shop.example.com"}` (`*.example.com` allowed).
- `mode`: `allow` (only these countries) or `deny` (these countries are refused).
- `countries`: 1 to 50 ISO 3166 two-letter codes that have a list (422 `unknown_country` otherwise).
- `note`: optional, at most 160 characters.

The internal networks, the known scanners, the trusted proxies and the protected list are never refused. Three tests
are added for you (a request from an allowed and from a refused country, one from inside). The evidence check counts
from the access logs what the rule would have refused (`requests`, `refused`, `refused_sources`, `refused_success`,
`countries`); it is informational and never fails the change. A country block is never applied automatically.
`GET /countries` (any signed-in user; no token scope) lists the countries that have a list and the lists in use.
`GET /countries/sites` (scope `rules:read`) shows every nginx site with its country rules, the country changes on
their way, whether the WAF runs there and what the rules refused in the last 7 days.
The site of a rule is the Host header (also with a trailing dot or a port). A full URL in the request line is routed
by nginx but not visible to ModSecurity: keep a check in nginx where a country limit must hold against it.

**Kinds `redaction` and `plugin`**: `redaction` takes `fields` (up to 30 argument names that are not inspected, so
never copied into the audit log) and optional `host` / `path`; `plugin` takes `plugin` (the CRS plugin name) and
`host` (required) to switch a plugin on for one site.

**Kind `raw`** (expert mode: SecRule text as written): adding or modifying a raw rule is for an **admin in the web
interface only**. A token gets 403 `raw_admin_only`. (A token may disable, enable or delete an existing raw item.)

**Bundle** (`"op": "bundle"`): several operations as one change, checked, approved and applied together (one version,
one reload, one rollback). `ops` holds 1 to 100 operations of the form `{"op", "kind", "spec", "item_id"}`, with at
most 20 confident blocks. The bundle is tightening only when every operation is.

```sh
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "op": "bundle", "reason": "probes seen from 203.0.113.0/24 this morning",
  "ops": [{"op": "add", "kind": "confident_block", "spec": {"regex": "^/wp-config\\.php", "msg": "wp-config probe"}},
          {"op": "add", "kind": "confident_block", "spec": {"regex": "^/\\.git/", "msg": "git probe"}}]}' \
  https://waf.example.com/api/v1/changes
```
```json
{"change_id": 4, "direction": "tighten", "state": "checking", "rule_id": null}
```

**`POST /rules/toggle`**: scope `changes:propose`. Switch several rules, or a whole category, off or on as one change:
`{"action": "disable" | "enable", "rule_ids": [...] (up to 300) or "group": {"source": "crs" | "local", "key":
"<attack family or category>"}, "scope": {"mode": "hosts", "hosts": ["app.example.com"]}, "reason": "...",
"preview": true?}`. With `preview` only the plan comes back (`rule_ids`, `operations`, `by_kind`, `skipped`,
`strict`); otherwise 202 with `change_id`, `direction`, `state`, `operations`, `skipped`, `strict`. Switching CRS rules
off for every request (`"scope": {"mode": "all"}`) needs an expert rule, so a token gets 403 `raw_admin_only`.

**`GET /changes`**: scope `changes:read`. `state` = a state name, or `open` (every state that is not final);
`limit` (default 100, at most 1000); `cursor`.

**`GET /changes/{id}`**: scope `changes:read`. The change with `rule_text`, `checks` (static, evidence, sandbox, diff),
`tests`, `log` (who did what, when), `error` and `applied_version`.

```sh
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/changes/2
```
```json
{"id": 2, "op": "add", "kind": "confident_block", "rule_id": 10204, "direction": "tighten",
 "state": "pending_approval", "reason": "dotenv probes from outside", "proposed_by": "soar-playbook",
 "proposed_via": "api", "proposed_owner": "admin-a", "proposed_ip": "192.0.2.10",
 "created_at": "2026-11-13T15:13:48+08:00", "updated_at": "2026-11-13T15:13:49+08:00",
 "spec": {"target": "path", "regex": "^/\\.env$", "msg": "dotenv probe", "source": "external", "...": "..."},
 "summary": "path ~ ^/\\.env$", "error": null, "applied_version": null, "rule_text": "...",
 "checks": {"static": {"ok": true}, "evidence": {"ok": true, "complete": true, "external_hits": 41,
            "external_success": 0, "internal_other": 0, "...": "..."}, "sandbox": {"ok": true, "...": "..."},
            "diff": {"before": "..."}},
 "log": [{"ts": "2026-11-13T15:13:48+08:00", "actor": "soar-playbook", "action": "proposed", "note": "..."},
         {"ts": "2026-11-13T15:13:49+08:00", "actor": "system", "action": "checks_passed", "note": ""}]}
```

**`GET /versions`**: scope `changes:read`. Applied rule-file versions, newest first (`limit` default 50, at most 500):
`version`, `created_at`, `change_id`, `kind`, `state`, `summary`, `step`, `health`, `nginx_t`.

**Cancelling** a change is not available to tokens (403). In the web interface the proposer or an admin cancels it; for
a change proposed by a token, ask an admin.

### 4.5 Rules, sites and CRS

All with scope `rules:read`.

- **`GET /rules`**: loaded rules. `source` = `local` (default), `crs`, `plugin`, `vhost_inline`, `base` or `all`;
  `category`, `family`, `state` (`on`, `off`, `partial`, `inactive`), `q` (id, message, comment or host);
  `limit` (default 1000, at most 5000), `cursor`. Each item has `id`, `msg`, `source`, `state`, `provenance`,
  `hits_7d`, `hits_30d`, `last_hit` and more; the answer also has `total` and `summary` (counts per category).
- **`GET /rules/{id}`**: one rule, with its text and hits.
- **`GET /rules/{id}/hits`**: daily counts, `days` 1 to 365 (default 30):
  `{"items": [{"day": "2026-11-12", "blocked": 3, "logged": 0}]}`.
- **`GET /rules/removals`**: rules removed by `SecRuleRemoveById` and similar.
- **`GET /vhosts`**: the nginx sites and their WAF settings; `reach` (internal, country, limited, restricted, open) from
  nginx's own checks for the whole server block, `redirect_only`, `outside_7d`; `countries` lists each site's country rules (mode, countries,
  rule id, enabled) and `country_changes` the country changes still on their way.
- **`GET /crs`**: the CRS version, paranoia levels, thresholds, engine mode, plugins.
- **`GET /crs/updates`**: whether jt-waf-mgr keeps the CRS current, the versions on the host, the newest release.
- **`GET /waf/model`**: how a request is decided on each site (engine, scoring, thresholds, exclusions).
- **`GET /managed`**: the managed rule files and their items (`items[].id` is the `item_id` for changes).
- **`GET /managed/items/{id}`**: one managed item.
- **`GET /managed/files/{placement}`**: `placement` = `before` or `after`; the file as `text/plain`, or a stored version
  with `?version=N`.

```sh
curl -sS -H "Authorization: Bearer $TOKEN" 'https://waf.example.com/api/v1/rules?source=local&state=on&limit=50'
```

### 4.6 IP lookup

Scope `lookups:read`.

- **`GET /lookups/ip/{ip}`**: what jt-waf-mgr has seen from one address in the last 7 and 30 days.
- **`GET /geoip/{ip}`**: the GeoIP answer only (`available: false` when no GeoIP database is installed).

```sh
curl -sS -H "Authorization: Bearer $TOKEN" https://waf.example.com/api/v1/lookups/ip/198.51.100.23
```
```json
{"ip": "198.51.100.23", "origin": "external", "geo": {"scope": "external", "cc": "NL", "...": "..."},
 "d7": {"events": 12, "blocked": 9}, "d30": {"events": 40, "blocked": 31},
 "first_seen": "2026-10-20T03:11:09+08:00", "last_seen": "2026-11-13T15:13:27+08:00",
 "hosts": [{"key": "app.example.com", "events": 40}],
 "rules": [{"key": "941100", "events": 12, "msg": "XSS Attack Detected via libinjection", "family": "xss"}],
 "blocked_now": false, "blocks": []}
```

`blocked_now` is `true` while a temporary IP block (section 4.9) covers the address; `blocks` lists those entries.

### 4.7 Event analysis and regression samples

Scope `changes:read`.

- **`GET /analyst/status`**: whether the scheduled event analysis (with a local LLM) is enabled and ready, its
  settings, the next run and the last run.
- **`GET /analyst/runs`**: past runs (`limit` default 50, at most 200; `cursor`).
- **`GET /analyst/runs/{id}`**: one run with its candidates, proposals and alerts.
- **`GET /regression`**: the requests the sandbox replays for every change.

### 4.8 Audit log

The audit log (`GET /audit`, `GET /audit/export`) is for admins in a session; tokens get 403. To feed the audit log
into a SIEM, set up an outbound record destination (syslog and other formats) in the web interface settings and
include audit records.

### 4.9 Temporary IP blocks

For systems that see an attacker and want it shut out within a minute, without a change and its approval: for
example fail2ban on a mail server whose web mail sits behind the WAF. A block is temporary data, not configuration:
it ends by itself.

How it works: jt-waf-mgr keeps the list in its database, and its root apply program writes it to one nginx file
(`deny <address>;` lines, at most once every `reload_seconds`, 60 by default), tests nginx and reloads it. The
administrator includes that file once inside `http { }`; jt-waf-mgr never edits nginx's configuration itself. A
`deny` at the http level covers every site, also the ones without ModSecurity, except servers and locations with
`allow` / `deny` lines of their own (the Blocked IPs page lists them). A block applies to new requests and connections from the reload on; a connection that was already open when the address was blocked (a WebSocket, a long download) is not cut and lasts until it closes. Until the feature is switched on in Settings,
every call answers 409 `blocks_off`.

- **`POST /blocks`** (scope `blocks:write`): body `{"ip", "ttl", "source", "reason"}`.
  - `ip`: one address (IPv4 or IPv6). Ranges are for people in the web interface only (up to /24 or /64).
  - `ttl`: seconds, 60 to 7 days (settings `blocks.min_ttl`, `blocks.api_max_ttl`); default 24 hours.
  - `source`: who asks, `[A-Za-z0-9_.:@/+-]{1,64}`, for example `mail2/zimbra-webmail`.
  - `reason`: required, up to 300 characters.
  - The same address from the same source again extends the block (`extended` counts up) and never adds a
    second entry. Another source gets its own entry; the address stays blocked until the last entry ends.
  - Answers 201 with the entry: `{"id", "ip", "source", "reason", "state": "active", "created_at", "expires_at",
    "permanent", "created_by", "via": "token", "extended", "ended_at", "ended_by"}`.
  - A token never blocks permanently (`"ttl": "permanent"` is refused, 403 `admin_required`); an admin can, in the web
    interface. Blocking an address again never shortens a permanent block (its `expires_at` is null).
- **`DELETE /blocks/{ip}?source=`** (scope `blocks:write`): ends the token's own entries for that address (only the
  one source when `source` is given). Another token's entries are never touched: 404 `not_found`. Answers
  `{"removed": n}`.
- **`GET /blocks?state=active|all|removed|expired`** (scope `blocks:read`): the entries, and whether nginx really
  loads the file: `included` (true when the file is loaded inside `http { }`), `uncovered` (servers and locations
  it does not reach), `applied` (when the list was last written and whether that worked), `in_sync`, `limits`.

Refused, and the refusal audited (`block.refused`):

- 422 `not_public` (private, loopback, link-local, CGNAT, multicast), `protected` (the internal networks, the known
  scanners, the trusted proxies, or the protected list: for example a CDN in front of the sites), `invalid_ip`,
  `single_address_only`, `invalid_ttl`, `invalid_source`, `reason_required`;
- 429 `rate_limited` (more than `blocks.token_per_hour` new blocks from one token in an hour, 60 by default);
- 409 `too_many_blocks` (the list is full, `blocks.max_active`, 500 by default; an alert opens) or
  `too_many_for_token` (`blocks.max_per_token`, 200).

Every add, extension, removal, refusal and expiry is in the audit log and goes to the log servers:
`block.add`, `block.extend`, `block.remove`, `block.refused`, `block.expired`, and `block.applied` /
`block.apply_failed` for the file itself, with `ip`, `source`, `ttl`, `token_id`.

```sh
# fail2ban action: ban
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ip": "203.0.113.7", "ttl": 86400, "source": "mail2/zimbra-webmail", "reason": "4 failed logins in 24 h"}' \
  https://waf.example.com/api/v1/blocks
# fail2ban action: unban
curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" \
  'https://waf.example.com/api/v1/blocks/203.0.113.7?source=mail2/zimbra-webmail'
```

## 5. Session-only endpoints

These endpoints answer 403 to any token. They need a person, a session, and usually a role and a fresh one-time code.

- Change decisions: `POST /changes/{id}/approve`, `/reject`, `/cancel`, `/recheck` (evidence override),
  `POST /versions/{version}/rollback`, `POST /alerts/{id}/handle`. These are the human approval step; letting a token
  do them would let one machine credential both propose and accept a change.
- CRS: `POST /crs/updates/check`, `POST /crs/updates/propose`.
- Adoption and rules-file upload: `POST /managed/adopt`, `POST /managed/import/preview`, `POST /managed/import`.
- Accounts and tokens: `/auth/*`, `/users*`, `/tokens*`.
- Settings and operations: `/settings*`, `/workflow/settings`, `/notify/*`, `/llm/test`, `/geoip` and
  `/geoip/update`, `/backups*`, `/system/check`, `/compliance`, `/config-changes*`, `/analyst/run`,
  `POST /regression`, `DELETE /regression/{id}`, `POST /regression/collect`.
- Audit: `/audit`, `/audit/export`, `/audit/verify`.

## 6. Change workflow

### 6.1 States

```
checking -> pending_approval -> approved -> applying -> applied
    |              |                            \-> apply_failed (rolled back automatically)
    \-> failed     \-> rejected                 applied -> rolled_back (a later version restored)
checking or pending_approval -> cancelled
```

- `checking`: the checks are running in the background. A change can come back here when another version was applied
  in the meantime (it is checked again against the new files).
- `failed`: a check did not pass; `error` and `checks` say which.
- `pending_approval`: all checks passed; waiting for a person.
- `approved`: approved and queued (one apply at a time).
- `applying`: the separate root program writes the files, runs `nginx -t`, reloads and runs the health checks.
- `applied`: live; `applied_version` is the version number.
- `apply_failed`: something failed during apply and the previous files were restored.
- `rejected`, `cancelled`, `rolled_back`: final.

The final states are `applied`, `rejected`, `cancelled`, `failed`, `apply_failed` and `rolled_back`.

### 6.2 Checks

- **Static**: the rule renders from its template; every rule in the resulting files passes the expert-mode checks
  (no engine switch-off, no file-reading operators, no audit-log changes, and so on); no duplicate rule ids.
- **Evidence**: for a confident block, the access logs are scanned for requests the regex matches. It fails when an
  external request it would block got a 2xx/3xx answer on a normal site, when an internal address (other than the
  known scanners) would be blocked, or when the scan did not finish in time. For an exclusion, the last 30 days of events show what it would let through.
  A failed evidence check can only be overridden by a person with a written reason (recheck, in the web interface).
- **Sandbox**: a throwaway nginx with the production configuration plus the change replays the change's `tests` and
  the regression samples. When the host has no sandbox, the check passes only if the admin has made the sandbox
  optional.

### 6.3 Approval

- An approver or admin approves in the web interface (`/changes/<id>`). Loosening always needs this.
- A change proposed with a token belongs to the admin who created the token: that admin cannot approve it, unless
  "single admin mode" is on (then a loosening needs a fresh one-time code and a written reason).
- Automatic apply of tightening is **off by default**. When an admin turns it on, an `add` of a `confident_block` with
  `source: external` whose evidence shows no successful external request and no internal request may be applied
  without a person (with a daily limit). Your script should therefore also accept `approved`, `applying` and
  `applied` while it waits.

## 7. Worked example: propose a confident block from a script

The script proposes a block for `/.env` probes, waits until the checks are done, and prints the link for the approver.
It needs `curl`, `jq`, and a token with `changes:propose` and `changes:read`, restricted to the script's host.

```sh
#!/bin/sh
set -eu
BASE='https://waf.example.com/api/v1'
TOKEN='jwm_example00000_EXAMPLE-not-a-real-token'

# 1. validate the spec first (nothing is created)
SPEC='{"target": "path", "regex": "^/\\.env$", "msg": "dotenv probe", "source": "external"}'
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"kind\": \"confident_block\", \"spec\": $SPEC}" "$BASE/changes/preview" | jq -e '.ok' >/dev/null

# 2. propose it
CID=$(curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{
  \"kind\": \"confident_block\", \"spec\": $SPEC,
  \"reason\": \"SIEM case 4711: /.env probes from 203.0.113.0/24\",
  \"tests\": [{\"host\": \"app.example.com\", \"path\": \"/.env\", \"source\": \"external\", \"expect\": 403},
             {\"host\": \"app.example.com\", \"path\": \"/\", \"source\": \"external\", \"expect\": 200}]
}" "$BASE/changes" | jq -er '.change_id')
echo "change $CID proposed"

# 3. poll every 10 s, at most 10 minutes
i=0
while [ $i -lt 60 ]; do
  STATE=$(curl -sS -H "Authorization: Bearer $TOKEN" "$BASE/changes/$CID" | jq -r '.state')
  case "$STATE" in
    checking) sleep 10; i=$((i + 1)) ;;
    pending_approval) echo "checks passed; approve at https://waf.example.com/changes/$CID"; exit 0 ;;
    approved|applying|applied) echo "applied automatically (state $STATE)"; exit 0 ;;
    *) curl -sS -H "Authorization: Bearer $TOKEN" "$BASE/changes/$CID" | jq '{state, error, checks}'; exit 1 ;;
  esac
done
echo "still checking after 10 minutes"; exit 1
```

Then a person signs in to the web interface, opens **Changes** (or the link), reads the checks and the diff, and
approves or rejects. The script can keep polling `GET /changes/{id}` until it reaches a final state, or watch for
`applied` and `applied_version`.
