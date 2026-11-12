# jt-waf-mgr UI ↔ backend contract: compliance and integrity

Adds to `ui-api.md` and `ui-api-p2.md`, using the same conventions:
- the `/api/v1` prefix and error shape;
- CSRF header on writes;
- cursor lists;
- anything request-derived is rendered as text only.

All dates are ISO 8601 with offset; the UI shows them as `YYYY-MM-DD HH:mm`.

## Sign-in and own account

### `GET /api/v1/meta` (public)

Gains two fields:

```json
{"login_notice": "Authorised use only. Activity is recorded.",            // "" = none; plain text, keep line breaks
 "password_policy": {"min_length": 12, "min_classes": 3, "history": 3, "max_age_days": 0, "min_age_hours": 0}}
```

- Login page: show `login_notice` above the form when it is not empty. Render it as text only (`white-space: pre-line`).
- Change-password page: list the policy, e.g. "At least 12 characters, 3 of: lower case, upper case, digits, other; not one of the last 3 passwords".
- `min_classes` 0 means length only. `history` 0 means only "not the current one".

### `POST /api/v1/auth/login`

The response gains `previous_login`:

```json
{"user": {…}, "csrf_token": "…",
 "previous_login": {"at": "2026-11-10T09:12:00+08:00" | null, "ip": "192.0.2.5" | null, "failed_since": 2}}
```

- After sign-in, show a dismissible notice once: "Last sign-in: {at} from {ip}".
- If `failed_since` > 0, the notice is a warning: "{n} failed sign-in attempts since then".
- If `at` is null, show "First sign-in".
- Keep the notice in the store until it is dismissed or the user navigates twice. Do not persist it.

### New password errors

They return 400 with these codes (add i18n texts):
- `password_too_simple` (`details.min_classes`)
- `password_reused` (`details.history`)
- `password_too_recent` (`details.retry_after` seconds; show hours)

Existing codes stay: `password_too_short`, `password_same`.

A password older than `max_age_days` makes the server set `must_change_password` at sign-in. The existing flow then forces the change.

### `User` object

Gains these fields (all may be null):
- `locked` (bool)
- `last_login_ip`
- `expires_at`: account end date
- `password_changed_at`
- `password_expires_at`: null when there is no maximum age
- `dormant_at`: the date the account gets disabled if it does not sign in

### Own sessions

`GET /api/v1/auth/sessions` (session) returns:

```json
{"items": [{"id": "3f2a…16 hex", "current": true, "created_at": "…", "last_seen": "…", "src_ip": "192.0.2.5",
            "user_agent": "Mozilla/5.0 …"}]}
```

`POST /api/v1/auth/sessions/revoke-others` (session) returns 204.

On the Account page, add a section "Signed-in sessions":
- a table of sessions;
- the current one is marked;
- the user agent is shown shortened, as text;
- a button "Sign out all other sessions", with a confirm.

## Users (admin)

### `POST /api/v1/users`

Accepts an optional `expires_at` (ISO date-time) for a temporary account.

### `PATCH /api/v1/users/{u}`

Accepts:
- `expires_at`: ISO, or null to clear;
- `unlock: true`, which clears a lockout.

Errors: 400 `invalid_expiry` for a date in the past or a bad format.

### `POST /api/v1/users/{u}/signout`

Returns 204. It ends every session of that user. Show a confirm first.

### Users page

- New columns:
  - "Last sign-in" (date and IP);
  - "Expires" (date, or "—");
  - "Locked" badge with an Unlock button;
  - "Dormant on" (date, or "—").
- Create and edit dialogs get an optional "Account expires" date field.
- Edit gets a "Sign out everywhere" action.

### `GET /api/v1/users/review` (admin) — account review

This is the periodic access review. Calling it writes an audit row.

```json
{"generated_at": "…", "node_id": "waf1",
 "users": [User + {"days_since_activity": 12, "sessions": 1}],
 "tokens": [Token],                                  // active (not revoked) tokens
 "policy": {"password_min_length": 12, "password_min_classes": 3, "password_history": 3, "password_max_age_days": 0,
            "password_min_age_hours": 0, "dormant_days": 90, "require_totp_roles": ["approver","admin"],
            "lockout_threshold": 5, "lockout_minutes": 15}}
```

- Add a button "Account review" on the Users page. It opens a view with both tables and the policy.
- Offer two downloads, both built in the browser:
  - "Download CSV": users and tokens as two CSV files, or one file with a `type` column; UTF-8 with BOM so Excel opens it.
  - "Download JSON": the raw response.
- CSV escaping:
  - quote every field;
  - double any quote;
  - prefix `'` to any cell starting with `= + - @`, to prevent CSV formula injection.

## Audit log (admin)

### `GET /api/v1/audit`

Items gain `prev_hash` and `hash` (64 hex). Show:
- a short hash column: the first 10 characters in monospace, with the full hash in the title and a copy control;
- in a row's detail, both hashes in full.

### `POST /api/v1/audit/verify` (admin)

Checks the whole chain and all anchors. It returns the `ChainState` below. Add a "Verify chain" button.

```json
{"ok": true, "checked_at": "…", "full": true, "rows": 1234, "checked": 1234, "last_id": 1234,
 "reason": null | "prev_mismatch" | "hash_mismatch" | "triggers_missing" | "verified_tip_missing",
 "bad_id": null | 57,
 "anchor_problems": [{"reason": "anchored_row_missing" | "anchored_hash_changed" | "anchor_unreadable" |
                      "anchor_write_failed", "id": 900, "at": "…"}],
 "last_anchor": {"at": "…", "id": 1234, "hash": "…", "count": 1234} | null}
```

- If ok: a green result line "Chain intact: {rows} records, last anchor {at}".
- If not ok: a red box naming the reason (i18n) and `bad_id`.

### `GET /api/v1/audit/export?since=&until=` (admin)

- Downloads NDJSON, with `Content-Disposition` and an `X-Content-SHA256` header.
- Use an `<a href>` download, or fetch then a blob, and keep the file name from the header.
- After the download, show the SHA-256 and the hint "Verify offline: `jt-waf-mgr audit-verify FILE`".

## System check (admin) — new page "System check" (`/admin/system`)

### `GET /api/v1/system/check`

Returns `{"generated_at": "…", "items": [CheckItem]}`.

`POST /api/v1/system/check` reruns the program, the full chain, the configuration and the database checks, then returns the same shape. Add a button "Run checks now".

`CheckItem`:

```json
{"key": "program_integrity", "status": "ok|warn|fail|info", "details": {…}}
```

Render one card per item:
- a status badge: ok green, warn amber, fail red, info grey;
- an i18n title and a one-line explanation per key;
- the details as a definition list. Lists are shown comma-separated, and a hash is shortened with a copy control.

Keys, with their detail fields:

- `version`: `version`, `python`, `nginx`.
- `program_integrity`:
  - `status`: ok / failed / not_installed;
  - `reason`, `checked`, `changed[]`, `missing[]`, `extra[]`;
  - `signature`: valid / invalid / missing;
  - `key_fingerprint` (64 hex), `manifest_sha256`, `checked_at`.
  - If `not_installed`, explain: "Running from a source tree: no signed manifest".
- `audit_chain`: the `ChainState` above.
- `anchor_file`: `path`, `append_only` (true / false / null).
- `syslog`: `enabled`, `address`, `errors`, `last_error`.
- `time_sync`: `synced` (true / false / null), `source`, `ntp_enabled`.
- `disk`: `path`, `free_mb`, `min_free_mb`.
- `database`: `size` (bytes, shown as MB), `schema`, `quick_check`, `checked_at`.
- `backup`: `enabled`, `dir`, `keep_days`, `last_at`, `last_ok`, `error`, `copies`.
- `collector`: `audit_log`, `readable`, `running`, `error`, `last_read`.
- `apply`: `armed`, `adopted`, `drift`, `pending`.
- `config_changes`:
  - `files`, `last_outside_id`, `last_outside_at`;
  - a link to the configuration changes page.
- `accounts`:
  - `active`, `admins`, `without_totp[]`, `locked[]`;
  - `temporary_password_unused[]`: temporary password still unused after 7 days.
- `web`: `secure_cookies`, `listen`, `session_idle_minutes`, `session_max_hours`.

### Backups (on the System check page, a section "Database backups")

`GET /api/v1/backups` (admin) returns:

```json
{"items": [{"file": "jt-waf-mgr-20261111-030000.db", "size": 176128, "at": "…", "sha256": "…", "verified": null}],
 "last": {"at": "…", "file": "…", "ok": true, "sha256": "…", "size": 176128, "error": null},
 "enabled": true, "dir": "/var/lib/jt-waf-mgr/backups", "keep_days": 14, "hour": 3}
```

- `POST /api/v1/backups` (admin) runs a backup now. It returns 201 with the `last` shape, or 500 with `ok: false`.
- `POST /api/v1/backups/{file}/verify` (admin) returns `{"file", "sha256", "sha256_ok", "integrity_check", "ok"}`.
  - Show a Verify button per row and display the result inline.
- Explain under the list:
  - "Copies are kept {keep_days} days on this host. Copy them off the host (organisational measure).";
  - restore: stop the service, then copy the file over the database.

## Configuration changes (approver, admin) — new page "Configuration changes" (`/config-changes`)

`GET /api/v1/config-changes?cursor=&limit=` returns:

```json
{"items": [{"id": 7, "ts": "…", "digest": "…", "cause": "baseline|jt-waf-mgr|outside",
            "changes": {"added": ["/etc/nginx/…"], "removed": [], "changed": ["/etc/nginx/modsec/…"]}}],
 "next_cursor": "6" | null}
```

`GET /api/v1/config-changes/{id}` returns the same, plus `files`: `{path: sha256 | null}` (null means unreadable).

- What it is: every few minutes jt-waf-mgr fingerprints:
  - every nginx / ModSecurity / CRS file;
  - the nginx binary;
  - the ModSecurity module.
- Each change is recorded and attributed: `jt-waf-mgr` (an applied version) or `outside` (anything else, e.g. a manual edit or a package upgrade).
- List: date, a cause badge (`outside` amber, `jt-waf-mgr` blue, `baseline` grey), and the counts of added, removed and changed files. Expand a row to see the paths.
- Detail: all files with a short hash.

Add the menu entry for approver and admin.

## Compliance (admin) — new page "Compliance" (`/admin/compliance`)

`GET /api/v1/compliance` returns:

```json
{"level": "" | "low" | "medium" | "high", "generated_at": "…", "version": "0.2.0", "node_id": "waf1",
 "controls": [{"id": "authentication", "iso": ["A.5.17", "A.8.5"], "tw": ["ident.auth_mgmt"], "owasp": ["A07"],
               "status": "met|partial|gap|organisational", "needs": ["auth.password_max_age_days"],
               "values": {…}}]}
```

### Page layout

- Header:
  - the protection level, e.g. "Taiwan Cyber Security Management Act level: medium (set `[compliance] level` in config.toml)";
  - if the level is empty, "not set";
  - counts per status.
- A filter: All / Gaps / Partial / Organisational.
- One row per control, with:
  - the i18n title `compliance.ctl.<id>.title` and description `compliance.ctl.<id>.desc` (what jt-waf-mgr does for it);
  - reference chips: the ISO codes as is; the TW keys through i18n `compliance.tw.<key>`; the OWASP codes through `compliance.owasp.<code>`;
  - a status badge: met green, partial amber, gap red, organisational grey ("Organisational measure").
- `needs`: when not empty, show "To close this gap:" and the items in monospace (config keys or actions, not translated).
- `values`: a compact key/value list (keys shown as is).
- Footer note: "Computed from the live configuration. A gap marked organisational needs a procedure outside jt-waf-mgr. Mapping details: docs/COMPLIANCE.md".
- "Download JSON" button (browser-side).

### Control ids

Each id needs a title and a description:
- access: `account_management`, `least_privilege`, `segregation_of_duties`, `session_timeout`;
- authentication: `authentication`, `multi_factor`, `auth_feedback`;
- logging: `audit_logging`, `log_protection`, `log_failure_response`, `log_capacity`, `time_sync`, `siem_forwarding`, `evidence_export`;
- integrity and change: `software_integrity`, `configuration_management`, `change_management`, `backup`;
- data: `data_masking`, `data_at_rest`, `transport`, `retention`;
- development and operations: `secure_development`, `vulnerability_management`, `monitoring`.

### TW keys

These are the Taiwan Cyber Security Management Act baseline items, 資通系統防護基準. The zh-TW labels:
- `access.account`: 存取控制－帳號管理
- `access.least_privilege`: 存取控制－最小權限
- `ident.auth_mgmt`: 識別與鑑別－身分驗證管理
- `ident.internal_users`: 識別與鑑別－內部使用者之識別與鑑別
- `ident.feedback`: 識別與鑑別－鑑別資訊回饋
- `log.events`: 事件日誌與可歸責性－記錄事件
- `log.content`: 事件日誌與可歸責性－日誌紀錄內容
- `log.protection`: 事件日誌與可歸責性－日誌資訊之保護
- `log.failure`: 事件日誌與可歸責性－日誌處理失效之回應
- `log.capacity`: 事件日誌與可歸責性－日誌儲存容量
- `log.time`: 事件日誌與可歸責性－時戳及校時
- `monitor.system`: 系統與資訊完整性－資通系統監控
- `integrity.software`: 系統與資訊完整性－軟體及資訊完整性
- `integrity.patch`: 系統與資訊完整性－漏洞修復
- `acquisition.lifecycle`: 系統與服務獲得－系統發展生命週期
- `continuity.backup`: 營運持續計畫－系統備份
- `comm.storage`: 系統與通訊保護－資料儲存之安全
- `comm.transmission`: 系統與通訊保護－傳輸之機密性與完整性

The en and ja labels are translations of these.

### OWASP Top 10:2025 codes

- A01 Broken Access Control
- A02 Security Misconfiguration
- A03 Software Supply Chain Failures
- A04 Cryptographic Failures
- A05 Injection
- A06 Insecure Design
- A07 Authentication Failures
- A08 Software or Data Integrity Failures
- A09 Security Logging and Alerting Failures
- A10 Mishandling of Exceptional Conditions

## Audit action names (for the audit page filter and i18n of actions, if any)

New:
- integrity and checks: `integrity.audit_chain_failed`, `integrity.audit_chain_failed_recovered`, `integrity.program_failed`, `integrity.database_failed`, `integrity.checked`, `system.checked`;
- audit trail: `audit.verified`, `audit.exported`, `audit.purged`;
- configuration: `config.changed` (result `ok` or `outside`);
- backups: `backup.created`, `backup.failed`, `backup.verified`;
- accounts: `account.locked`, `user.disabled` (reason `dormant` / `expired`), `sessions.revoked`, `users.reviewed`;
- changes: `change.recheck` (with `evidence_override`), `change.approve_denied`, `change.reject_denied`, `change.cancel_denied`, `change.recheck_denied`, `change.rollback_denied`;
- regression samples: `regression.deleted`, `regression.collect_started`.

Results:
- `failed` and `outside` are shown amber or red, like `denied`;
- rows with action `integrity.*` that are not `_recovered` are red.

## Navigation

- Admin menu:
  - add "System check" and "Compliance";
  - keep Users, Tokens, Audit and Settings.
- Approver and admin: add "Configuration changes" next to Versions.
- Overview: if `/system/check` is readable (admin) and any item is `fail`, show a red banner "Integrity problem: {keys}" with a link to System check.
  - Fetch it once per page load, for admins only.

## Settings in the web interface (admin, 0.3.4)
- `GET /settings/ui` → `{"settings": {"<section.key>": {"type": "bool|int|str|list|secret|choice", "value": …,
  "source": "ui|file", "updated_by", "updated_at", "min", "max", "choices", "max_items"}}}`. Secrets have no `value`,
  only `"set": bool` and `"hint": "…abcd"`.
- `PATCH /settings/ui` with `{"<section.key>": value, …}`: validated against the whole configuration, stored,
  applied at once, audited `settings.changed` (secret values never). A secret: `""` clears, `null` keeps.
  Errors: 400 `unknown_setting`, `invalid_value` (`details.key`, `details.item`), `invalid_configuration`.
- `POST /llm/test` → 202 `{"requested_at"}`: the analysis unit makes the connection (the web service has no
  network access beyond localhost); `GET /llm/test` → `{"result": {"ok", "model", "models", "reply", "seconds",
  "error", "detail", "requested_at", "finished_at"} | null, "pending": bool}`. Audit `llm.test_requested`, `llm.tested`.

## Scheduled event analysis (0.3.4) — page "Analysis" (`/analysis`)
- `GET /analyst/status`, `GET /analyst/runs`, `GET /analyst/runs/{id}` (viewer, token scope `changes:read`).
- `POST /analyst/run` (admin): writes the request file the analysis unit watches; 409 `analyst_not_ready` when
  the LLM or the analysis is off or not configured. Audit `analyst.run_requested`, `analyst.run`.

