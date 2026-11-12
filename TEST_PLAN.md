# Test plan

**English** · [繁體中文](TEST_PLAN_zh-TW.md) · [日本語](TEST_PLAN_ja.md)

This plan applies to **every release**, however small (patch, UI wording, a single fix). A release is published
or installed only when every gate below has passed and the results are recorded. `TEST_CHECKLIST.md` is the
short form used while releasing; this document says what each gate covers, how it is run and what passes.

## 1. Scope

- The program: collector, web service and API, change workflow, root apply program, sandbox, integrity and
  compliance monitor, GeoIP updater, scheduled event analysis (local LLM), command line.
- The web interface: every page, both themes, three languages, phone and tablet widths.
- Installation, upgrade, automatic and manual rollback.
- Security of jt-waf-mgr itself (it must not become the way into the WAF).
- Not in scope: the protected sites themselves (their checks belong to the change workflow: evidence, sandbox,
  health URLs), nginx / ModSecurity / CRS (upstream).

## 2. Environments

- **Development host**: unit tests, builds, browser tests, scans. Shared host: heavy jobs one at a time, `nice`.
- **Synthetic environment** (`tools/e2e/setup.py`): documentation address ranges and example.com only; accounts
  for every role with one-time codes; events, GeoIP test databases, an API token. Used by the browser test, the
  security scan and the ZAP scan. Real data never enters the project tree.
- **Production Python** (the server's own `python3`, in a temporary directory that is removed afterwards).
- **Copy of the production database** (read-only dump, migrated outside production, deleted afterwards).

## 3. Test levels and gates

| Gate | Command | Passes when |
|---|---|---|
| G1 Unit and integration | `python3 -m unittest discover -s tests -t .` | all pass (also run by `make_release.sh`) |
| G2 Build | `tools/build_frontend.sh` | build OK; `check_i18n` (3 languages, no full-width slash, no product name); `check_ui` (icons on buttons and card titles, no native select / date, tables via DataTable) |
| G3 Publication | `python3 tools/preflight.py` | no private names, addresses or secrets in what is published (screenshots: no PNG text chunks); README in three languages with the version in the title and language links |
| G4 Browser end to end | `tools/e2e/run.sh <dir>` | every page in zh-TW and en, light and dark; theme / language menus; sorting, filtering, columns, paging; select box, date picker; charts and tooltips; guide; login page; no console errors, no raw i18n keys, no button without icon; every page also in Japanese (raw keys, layout); world map (land, bubbles, tooltip, country filter), notification preview (two languages, Escape); phone (375 px) and tablet (768 px): no sideways scroll, menu reaches every group |
| G5 Security checks | part of `tools/e2e/run.sh` (`tools/security_scan.py`) | 0 failed: headers, cookies, authentication on every route, authorisation (viewer, API token, source network), CSRF, methods, traversal, hostile input on every GET route (no 5xx), malformed bodies, login (same error, lockout, no open redirect, Host header) |
| G6 DAST (OWASP ZAP) | `tools/zap_scan.py` | logged-in passive and active scan of a disposable instance; URLs seen ≥ 40; no High / Medium / Low alert that is not accepted in `deploy/zap-baseline.conf` |
| G7 Visual review | screenshots of G4 | looked at by a person for UI changes, including 375 px and 768 px |
| G8 Release | `tools/make_release.sh` | signed; `openssl dgst -verify` says Verified OK |
| G9 Upgrade | `tools/test_upgrade.sh <previous> <new>` | install with data, refusals, `--check`, automatic rollback on a failed start, upgrade keeps data / accounts / audit trail / integrity, manual rollback, upgrade again |
| G10 Production Python | G1 and G9 on the server, temporary directory | all pass; the directory is removed |
| G11 Migration on real data | `jt-waf-mgr migrate` + `integrity` on a copy of the production database | migration OK, audit chain intact; the copy is deleted |
| G12 Real external data | once per feature that reads external data | e.g. a real GeoLite2 database, a real ModSecurity audit record, a real LLM answer |
| G13 Independent review | an agent or person who did not write the change | for changes to the apply program, the collector, authentication, integrity, the change workflow, anything handling secrets or attacker-controlled data |
| G14 After installing | `upgrade.sh --check`, `upgrade.sh`, `jt-waf-mgr doctor`, the web interface, site checks when nginx is involved | as in `TEST_CHECKLIST.md` §6 |

## 4. What the automated tests cover (G1)

- Collector: audit log parsing (incl. real-world records), rotation, redaction before storage, origin.
- Rule generation: every template, the static checks (forbidden directives, data files, regex breadth, ReDoS
  shape and runtime), raw rules, placement before a given rule, internal-source option.
- Change workflow: propose / check / approve / apply / result; single and bundle changes; evidence (one pass
  for several blocks); sandbox cases; stale base; drift; rollback; approval rules (own change, token owner,
  single-admin mode); auto-apply limits (external only, never analyst proposals); rule ids never reused.
- Apply program: spool handling (symlinks, permissions), per-rule validation, nginx -t / reload / health, restore.
- Authentication: passwords (scrypt, policy, history, age), one-time codes (replay), lockout, sessions, tokens
  (scope, source network, expiry), CSRF.
- Integrity and compliance: audit hash chain, append-only triggers, anchors, rewinds, program signature,
  configuration change attribution (incl. adoption and known automation), backups (schedule, verify, download
  with a one-time code), system check, controls.
- Settings in the web interface: validation, secrets write-only, overlay, legacy keys.
- Scheduled analysis: candidates, prompt hygiene, model output validation (ids, regex, ReDoS, breadth),
  fail-closed on LLM errors, interval, progress, LLM connection test through the unit; false-positive groups and
  the narrowest exclusion (always a person), alerts (attack answered with 2xx, false positive, model-raised
  attack in progress; unknown kinds and ids dropped), the analysis' own automatic-apply switch.
- Notifications: event mapping (no loop on its own failures), matrix and defaults, queueing from the audit trail
  (a queue problem never breaks the audited action), every channel's format and authentication against local
  fake endpoints (webhook and Nextcloud signatures, Zulip basic auth, Telegram, Slack, Teams card, Discord
  without mentions, SMTP multipart), untrusted values never markup / mentions / links, retries then failed with
  audit, redirects refused, secrets scrubbed from errors and audit, rate limit, obsolete approval requests
  skipped, settings validation and bound secrets, API roles. Alerts: dedup, handle once, reminders.
- Audit coverage: every write route audits (`TestAuditCoverage`).
- Syslog: RFC 3164 / 5424 over UDP and TCP (octet counting), requests never wait for the network, records kept and
  resent after an outage, a TLS / connection error never drops records, an unsendable record does not block the
  queue, a syslog settings change is sent with the previous settings, the CA file is not a web setting.
- Tests leave no temporary directory behind.

## 5. Security testing (G5, G6, G13)

- **G5** runs on every build of the browser test; it reads the route table from the code, so a new route is
  checked without editing the scan.
- **G12 for notifications**: each channel type in use is checked once with "Send a test" against the real
  service after installing (the release itself is tested against local fake endpoints).
- **G6** uses the ZAP package already on the build host (snap). Accepted alerts are listed with their reason in
  `deploy/zap-baseline.conf`; anything else fails the release. Reports are kept in `zap-reports/` (not published).
- **G13** findings are fixed or written down with the reason before release.
- Known limits (documented, not tested here): host hardening of the server, TLS of the reverse proxy (checked on
  the site with its own tools), LXC restrictions (no append-only flag, no IPAddressDeny).

## 6. Entry and exit criteria

- Entry: the change is complete, CHANGELOG updated, version bumped.
- Exit: G1–G13 passed (G7 for UI changes, G11 for schema changes or every release when in doubt, G12 once per
  feature); results recorded. One failed gate stops the release — "it is only a small change" is not an exception.

## 7. Records

- CHANGELOG entry, the release checksum, the gate results (counts, report file names), the production install
  time and result in the project notes.
- ZAP reports: `zap-reports/zap-<version>.{html,json,md}`; security scan: `security-report.json` next to the
  browser screenshots.
