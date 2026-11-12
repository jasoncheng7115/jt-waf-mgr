# jt-waf-mgr UI ↔ backend contract: notifications and alerts (0.4.0)

Adds to `ui-api.md` (same conventions: `/api/v1`, error shape, CSRF header, cursor lists, text-only rendering of
anything request-derived).

## How it works

- Every audit row goes through `notify.on_audit`: when the action is a notification event (below) and
  notifications are on, one `notifications` row per chosen channel is queued and a request file
  (`notify.request` next to the database) is written. The web service never connects out.
- `jt-waf-mgr-notify.service` (path unit on the request file, one-minute timer) sends what is due, retries
  after 1, 5 and 15 minutes, then records the delivery as `failed` (audit `notify.failed`). Each channel sends at
  most `notify.max_per_hour` an hour; more are `suppressed`. The same event about the same thing (change,
  alert, account) is queued once per 10 minutes. Rows are kept 90 days.
- A message is rendered when it is sent, in `notify.language`, with a link built from `notify.base_url`.
  Values that come from requests or from the language model are always shown as code / escaped for the
  channel: never markup, never mentions (Discord `allowed_mentions: {parse: []}`), never links.
- Some events also open an **alert** (`alerts` table) that stays open until an approver marks it handled;
  open alerts are reminded every `notify.remind_hours`.

## Settings (`PATCH /settings/ui`, admin; secrets write-only)

`notify.enabled`, `notify.language` (zh-TW | en | ja), `notify.base_url`, `notify.max_per_hour` (1–1000),
`notify.remind_hours` (0–720, 0 = never), `notify.report_hour` (-1 = none, 0–23: the daily report), `notify.matrix` (`{event: [channel…]}`; an event not listed uses its
default), and per channel:

- e-mail: `email_enabled`, `smtp_host`, `smtp_port`, `smtp_tls` (starttls | tls | none), `smtp_username`,
  `smtp_password`*, `smtp_from`, `email_to` (list)
- Telegram: `telegram_enabled`, `telegram_token`*, `telegram_chat_id`
- Teams / Slack / Discord: `<channel>_enabled`, `<channel>_webhook`* (https)
- Zulip: `zulip_enabled`, `zulip_site`, `zulip_bot_email`, `zulip_api_key`*, `zulip_stream`, `zulip_topic`
- Nextcloud Talk: `nextcloud_enabled`, `nextcloud_url`, `nextcloud_token`, `nextcloud_secret`*
- webhook: `webhook_enabled`, `webhook_url`*, `webhook_secret`*, `webhook_token`*

`*` secret: reported only as set / last characters. Changing `zulip_site`, `nextcloud_url` or `smtp_host` while
the matching secret is stored is refused (`key_required_for_new_host`) unless the secret is entered again.

## Events

`alert.created`, `alert.reminder`, `integrity.audit_chain_failed[_recovered]`, `integrity.program_failed[_recovered]`,
`config.changed_outside`, `change.apply_blocked_drift`, `auth.step_up_locked`, `account.locked`, `totp.disabled`,
`change.awaiting_approval`, `change.check_failed`, `change.applied`, `change.apply_failed`, `change.rejected`
(off by default), `change.rollback_requested`, `analyst.proposals`, `analyst.failed`, `backup.failed`,
`system.version_changed`, `report.daily`, `user.created`, `token.created`, `settings.changed` (the last three off by default).

## Routes

`GET /notify/status` (admin)
```json
{"enabled": true, "last_run": "…", "pending": 0,
 "channels": [{"channel": "telegram", "enabled": true, "configured": true, "active": true,
               "last_24h": {"sent": 3, "failed": 0}}],
 "events": [{"event": "backup.failed", "category": "system", "severity": "critical", "default": true}],
 "matrix": {"backup.failed": ["email", "telegram"]}, "channel_list": ["email", "telegram", "…"]}
```
`POST /notify/test {"channel": "telegram"}` (admin) → 202 Delivery. Works while notifications are off; the
channel must be set up and saved (409 `channel_not_configured`). Audited `notify.test_requested`.

`GET /notify/preview?event=<event>&lang=zh-TW|en|ja` (admin) → the message the event sends, rendered from made-up
example data (never real records; nothing is queued or audited):
`{event, language, severity, title, text, facts: [{label, value}], link, plain}`. 404 `unknown_event`.

`GET /notify/deliveries?channel=&status=&cursor=&limit=` (admin) → `{items: [Delivery], next_cursor}`;
`GET /notify/deliveries/{id}` (admin) → Delivery
```json
{"id": 41, "created_at": "…", "event": "change.applied", "severity": "success", "channel": "webhook",
 "status": "pending|sending|sent|failed|suppressed|skipped", "attempts": 1, "error": null, "sent_at": "…",
 "test": false, "requested_by": null, "ref": {"change_id": 7}}
```

`GET /alerts?state=open|handled&cursor=&limit=` (viewer, token `changes:read`) →
`{items: [Alert], next_cursor, counts: {open, critical}}`; `GET /alerts/counts`; `GET /alerts/{id}`
```json
{"id": 3, "created_at": "…", "last_seen": "…", "source": "analyst|system",
 "kind": "attack_in_progress|attack_passed|false_positive|integrity|config_outside|apply_failed|backup_failed|auth_attack|other",
 "severity": "critical|warning", "count": 2, "details": {"host": "…", "path": "…", "reason": "…", "change_id": 9},
 "link": "/changes/9", "state": "open|handled", "handled_by": null, "handled_at": null, "note": "", "summary": "…"}
```
`POST /alerts/{id}/handle {"note": "…"}` (approver; note ≤ 1000) → Alert. 409 `not_open` when already handled.
Audited `alert.handled`.

## Generic webhook payload

`POST <webhook_url>`, `Content-Type: application/json`:
```json
{"app": "jt-waf-mgr", "version": "0.4.0", "node": "waf1", "event": "backup.failed", "severity": "critical",
 "title": "Database backup failed", "text": "", "facts": [{"label": "File", "value": "…"}],
 "link": "https://waf.example.com/admin/system", "id": 41, "audit_id": 812, "test": false, "ts": "…"}
```
Headers: `X-Jt-Waf-Mgr-Event`, `X-Jt-Waf-Mgr-Timestamp` (Unix seconds), and with a signing secret
`X-Jt-Waf-Mgr-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + raw body)>`; with a token
`Authorization: Bearer <token>`. Verify the signature over the raw body and refuse old timestamps, e.g.:

```python
import hashlib, hmac, time
def verify(secret, headers, body):
    ts = headers['X-Jt-Waf-Mgr-Timestamp']
    want = 'sha256=' + hmac.new(secret.encode(), ts.encode() + b'.' + body, hashlib.sha256).hexdigest()
    return abs(time.time() - int(ts)) < 300 and hmac.compare_digest(want, headers['X-Jt-Waf-Mgr-Signature'])
```

Redirects are not followed and proxy environment variables are ignored; an error response is recorded only as
its status and a short reason from a JSON body.

## Overview time range

`GET /overview?range=custom&since=<RFC 3339>&until=<RFC 3339>`: 1 hour to 31 days; the timeline counts hours up to
7 days and local days beyond (`bucket_seconds` in the answer).

`GET /events/timeline?<event filters>&since=&until=` (viewer, token `events:read`): the event list's timeline with the
same filters; default the last 7 days, at most 31 (`clamped: true` when cut), hours up to 7 days, local days beyond.
```json
{"since": "…", "until": "…", "bucket_seconds": 3600, "clamped": false, "max_days": 31,
 "timeline": [{"t": "…", "blocked": 2, "logged": 5, "external": 6, "internal": 1}]}
```

## Syslog (0.4.1)

Settings (`PATCH /settings/ui`, admin): `syslog.enabled`, `syslog.address` (`/dev/log` or `host:port`, port 1–65535),
`syslog.protocol` (`udp` | `tcp` | `tls`), `syslog.format` (`rfc3164` | `rfc5424`), `syslog.facility`. `[syslog] ca_file`
(a CA bundle for TLS) is set in config.toml only.

- Records are queued and sent by a background thread: a request never waits for the network. While the destination is
  unreachable they are kept (up to 5,000, then the oldest are dropped and counted) and retried every 30 seconds.
- RFC 5424: `<PRI>1 TIMESTAMP HOST jt-waf-mgr PID audit - {"jt_waf_mgr": {...}}`; over TCP / TLS with octet-counting
  framing (RFC 6587). RFC 3164 over TCP / TLS ends each record with a line feed. The JSON is ASCII-only (control
  characters and newlines escaped): one record is one line.
- A change of a `syslog.*` setting is audited before it applies and sent with the previous settings (switching syslog
  off is critical), so the SIEM always sees where its copy went.

