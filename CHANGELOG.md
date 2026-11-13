# Changelog

**English** · [繁體中文](CHANGELOG_zh-TW.md) · [日本語](CHANGELOG_ja.md)

## 0.4.25 (2026-11-13)

- Chinese interface and documents: 「封鎖」 everywhere instead of 「阻擋」 (the confident block is now 「確定封鎖」); the
  interface check refuses the old word.
- Program rules for the event analysis (no LLM needed): a secret or configuration file name asked for from outside
  only, never answered 2xx and not used internally is proposed as a confident block by the program itself; such
  candidates are no longer sent to the model. Without an LLM the analysis now still runs, with these rules only
  (`analyst.rules`, on by default; the Analysis page says which mode runs).
- Automatic temporary IP blocks for sources that guess secret files (off by default; Settings > Temporary IP blocks): one
  external address asking for 5 different secret or configuration file names within 60 minutes is blocked for 24 hours
  on every site; at most 30 such blocks an hour; an address a person unblocked is left alone for 7 days.
- "Configuration changed outside" no longer fires for jt-waf-mgr's own apply: files equal to a version that is written
  but not yet reported (the apply program waits for old nginx workers) are jt-waf-mgr's.
- Interface: the AI tag is readable in light mode; toggled buttons are solid; the change workflow settings are laid
  out in rows like the others; health check URLs can be picked from the sites nginx serves; a timeline shows the
  scheduled analysis (interval and window) as the values change; the GeoIP card's buttons are full size; long
  summaries no longer push a horizontal scrollbar into the change and alert lists; missing labels in the
  configuration card.
- Rule authors: a setting for who wrote the rules imported at adoption (the site, or Jason Tools when Jason Tools
  wrote them before adoption).
- Project site: an alerts section and the change list next to the workflow steps (synthetic data).
- Temporary IP blocks, how to connect: the Blocked IPs page has the steps and a ready fail2ban action (with this
  server's address filled in); the README has the same action, and the project site an "Optional: temporary IP
  blocks" install block.

## 0.4.24 (2026-11-13)

- Temporary IP blocks (optional, off until switched on): other systems block a single address for a while through
  the API (`POST /api/v1/blocks`, scope `blocks:write`; `DELETE /api/v1/blocks/{ip}` ends the token's own), approvers
  block addresses or ranges up to /24 or /64 on the new Blocked IPs page. The root apply program writes one nginx file
  of `deny` lines (at most once a minute, tested with nginx -t, the old file put back on failure) that the
  administrator includes once inside http { }; it covers every site, also those without ModSecurity. The page shows
  whether the file is really loaded and which servers or locations it does not reach. Defaults 24 hours, at most 7
  days from a token and 30 days by hand, 500 active, 200 per token, 60 new per token and hour; internal networks,
  known scanners, trusted proxies and a protected list (for example a CDN) are never blocked, checked again by the
  root program. Every add, extension, removal, refusal and expiry is audited (`block.*`). The IP lookup shows whether
  an address is blocked now.
- The project site lists what is inside and who wrote it: the WAF engine and detection rules (not ours, with their
  licences), jt-waf-mgr, the rules Jason Tools writes, bundled third-party code and optional outside data.

## 0.4.23 (2026-11-13)

- Request volume (Events > Request volume): every request in the nginx access logs counted per site and hour (2xx,
  3xx, 4xx, 5xx, 403, 444, 429, external, bytes) next to what the WAF blocked and logged, so the WAF numbers have a
  denominator. Numbers only: no address, URL or user agent is kept. The web service reads the live logs where it
  stopped (inode and offset, stored with the counts in one transaction), finishes a renamed file through its inode,
  re-reads one truncated in place, takes the site from the file name and caps the sites a forged Host header can
  create. On by default; switched off, and its optional alerts (a site at N times its usual hour, or many 5xx
  answers) set, under Settings > Request volume. API: `GET /api/v1/traffic`.
- The rule list shows who wrote each rule: OWASP CRS, an OWASP CRS plugin, a third-party plugin, ModSecurity base
  settings, Jason Tools (rules generated from a form and the Jason Tools rule pack) or this site (hand-written), with
  a filter and counts. API: `author` on `GET /api/v1/rules`.
- API manual for integrations (docs/API.md, three languages): tokens and scopes, errors, every endpoint a token can
  call with examples, and a script that proposes a confident block.
- Documentation: connecting to the management interface (port, the example vhost, TLS certificate options, first
  login); jt-waf-mgr installs the OWASP CRS itself (a new host needs only nginx and ModSecurity) and never writes nginx
  configuration; the recommended LLM for the event analysis; account recovery commands.
- Wazuh rule drafts: rules for a failed CRS signature and a staged CRS release; refusals now match `token.denied` too.

## 0.4.22 (2026-11-13)

- OWASP CRS updates, step 3: a host without the CRS. The check stages the newest 4.x release that has waited; the CRS
  page offers "compare in the sandbox and propose installing CRS <version>" (the same requests without and with the
  CRS). Once approved, the root program installs crs-<version> next to the main ModSecurity file, links crs to it,
  creates crs-setup.conf from its example when there is none and adds the two Includes right after modsecurity.conf;
  nginx -t, reload and health checks, and any failure takes everything out again. The ModSecurity installation guide
  mentions this way.

## 0.4.21 (2026-11-13)

- OWASP CRS updates, step 2: on the CRS page an approver proposes switching to the downloaded and verified release, or
  back to a version kept on the host. It is a change: the sandbox runs the same recent requests (and the regression
  samples) through the CRS in use and the other version and lists what is newly blocked or no longer blocked; a person
  other than the proposer approves (never automatic). The root program then reads the staged tarball without
  following links, checks its SHA-256 and the CRS signature again, unpacks it itself, refuses it unless its files are
  exactly the ones compared, points the crs link at crs-<version> (a plain crs directory becomes crs-<version> + link
  on the first switch), tests and reloads nginx, checks health and switches back on any failure. The three newest
  versions are kept. When applied, the "CRS update ready" alert closes. API: `POST /api/v1/crs/updates/propose`.

## 0.4.20 (2026-11-13)

- OWASP CRS updates, step 1 (off by default; Settings or the CRS page: "Keep the CRS current from here"): a new
  sandboxed unit, jt-waf-mgr-crs (daily, or "check now"), takes the newest release of the major version in use once
  it has been out `crs.wait_days` (7), downloads its minimal tarball and signature, keeps it only when the signature
  is valid and made by the pinned CRS release key (shipped inside the signed program), unpacks plain files only into
  a staging area with a manifest, and opens a "CRS update ready" alert. Nothing in nginx changes yet: comparing it
  in the sandbox and switching to it (approved by a person) come next. A bad signature is audited as critical.
- CRS page: "CRS versions and updates" with the version in use, the versions on the host, the newest release and
  when it can be used, the downloaded and verified one, and a warning when another program also updates the CRS.
- API: `GET /api/v1/crs/updates`, `POST /api/v1/crs/updates/check`; CLI: `jt-waf-mgr crs-update`.

## 0.4.19 (2026-11-13)

- Log servers (syslog / SIEM): up to 8 destinations, each with its own address, protocol (local socket, UDP, TCP,
  TLS), record format (JSON, CEF, LEEF 2.0, GELF 1.1, key=value), syslog header and content (audit records, WAF
  events, alerts), its own queue, retries and counters. WAF events and alerts can now be sent too. "Send a test"
  sends one sample record as entered and shows exactly what went out. Destination 1 keeps the existing settings.
  API: `GET /settings/syslog`, `POST /settings/syslog/test`; settings `syslog.payload`, `syslog.content`, `syslog.more`.
- Tables: drag a column header's edge (or use the arrow keys on it) to set its width, remembered per table; a double
  click sizes the columns automatically again. Long one-line text in a table ends in "..." (hover shows it all).
- Changes: a proposal of the event analysis is marked "AI event analysis"; an API token's proposal shows whose token
  it is and the address it came from. Long summaries are cut, a click unfolds them.
- Page headers: their buttons have one size.
- Project site and READMEs: an offline installation and upgrade guide (`docs/OFFLINE*.md`), log servers.

## 0.4.18 (2026-11-13)

- Rules list: tick rules (or "select all listed") and switch them off or on as one change; or switch a whole category
  (CRS: an attack type) off or on. CRS rules switched off need a scope: chosen sites (exclusions, picked from the nginx
  server names) or every site (an expert rule, admins only, marked high risk). A whole CRS category switched off can
  only be approved by an administrator, with a one-time code and a written reason. A preview shows the operations and
  every rule that cannot be switched here, with the reason. API: `POST /api/v1/rules/toggle`.
- Rule states: CRS's own mechanics (sampling, the localhost exceptions) no longer make every CRS rule look "off for
  some"; a rule above the paranoia level shows "not in effect" before any exclusion.
- Alerts: the analysis page has a "handle" button per alert; `/alerts?id=N` selects that alert and opens its form.
- Overview: the navigation shows its icon; the country list beside the map is one line per country, with the first ten.
- Settings: the configuration file section is a card with its own title.
- Project site and READMEs: a calmer security headline, accounts and sign-in (TOTP, lockout, password policy) and
  recovery on the host (`jt-waf-mgr user unlock | reset | passwd | disable | enable`).

## 0.4.17 (2026-11-13)

- Rules list and CRS page show whether each rule runs: on, off (removed for every request, with where), off for some
  (an exclusion for some sites or paths) or not in effect (a CRS rule above the paranoia level). Totals per state, a
  state filter, and per category (CRS: per attack type) how many rules are in each state; a click lists them.
  Managed rules that are switched off are listed too. API: `state`, `state_detail`, `family`, `summary`.
- Rules in the managed files are no longer marked "not managed" (the flag was never set).
- A folded card next to an open one keeps its own height.
- Event analysis: a false-positive candidate judged an attack (or unsure) shows "stays blocked" instead of "not
  proposed": the requests were already blocked and stay so.

## 0.4.16 (2026-11-13)

- Overview, by source address: internal / external and the country are a column of their own, aligned from row to row.
- Rules list: a long description is cut with "..." (the table no longer runs off the right edge); hover shows it
  all, a click unfolds it and a second click folds it again.

## 0.4.15 (2026-11-13)

- Event analysis: the verdict history a "false positive" must agree with counts only runs that had candidates (the last
  six within 14 days). Quiet runs, which have nothing to judge, pushed earlier verdicts out within hours.

## 0.4.14 (2026-11-13)

- Event analysis is harder to fool, after a small model called the same probes an attack, then a false positive,
  then an attack again in three runs:
  - blocked requests for names attackers look for (secrets, backups, credentials, deployment, cloud and CI files)
    from a few outside sources only, or from sources that also tried other paths, are reconnaissance by the program's
    own rule: never proposed as a false positive, never an alert, not sent to the model;
  - a path called an attack in one of the last six runs is not loosened on a "false positive" verdict ("unstable");
  - the model also sees how many paths the sources tried, the attack families they triggered elsewhere and whether the
    name is a sensitive one, with explicit guidance; the analysis asks with temperature 0.
- A disclaimer on the analysis page, in the analysis settings, the READMEs and the project site: AI can be wrong in
  both directions; loosening always needs a person, only tightening that passed every check applies on its own.
- Adoption works on a fresh ModSecurity: a side without a site rule file gets its managed file included right before
  the first / after the last CRS rules Include (the root program checks the anchor is a CRS rules Include of the main
  file and that nothing is included twice). Before, adoption failed without site files, and with only one of the two a
  managed file was written but never loaded. The page explains it, or links the installation guide when no main file
  loads the CRS rules.
- ModSecurity installation guide (`docs/MODSECURITY*.md`, three languages); Ubuntu 22.04's libmodsecurity package is
  too old (3.0.9 or later needed).
- Tests: the notification tests no longer depend on the time of day (from 8 o'clock on, the daily report added one
  message and five of them failed).

## 0.4.13 (2026-11-13)

- Tabs and segmented controls (changes, alerts and others) are as wide as their buttons instead of the whole row.
- The country map lists the first six countries beside it, with "show all"; the map stays in view while the long
  list scrolls. The overview's source address and network owner cards span the full width; an address shows
  internal / external and its country on the same line.
- An open page notices when the server was upgraded (every few minutes and when the tab comes back to the front) and
  offers a reload; until then it kept running the version it had loaded.
- Traditional Chinese: 「收編」 is now 「納管」 (adopting the rule files) everywhere; the i18n checks reject the old word.
- The UI check rejects HTML sinks (`v-html`, `innerHTML` and the like) in the front end.
- Project site: light theme in the logo's colours with a palette per card, sharp thumbnails (taken at twice the
  resolution by the browser test, `tools/make_thumbs.py`), screenshots open large in the page with a close button,
  separate install, upgrade and uninstall blocks with a copy button. READMEs: an Uninstall section.
- Test environment: the synthetic network name no longer contains markup (it showed up in screenshots).
- Settings, focus sites: the site names nginx serves are offered as one-click choices (with a search when there are
  many); typing names by hand still works.
- The guide link moves to the right of Admin in the top bar. The alerts page tabs use the same segmented style as
  the other pages. Event analysis: the alerts of a run line up in columns.

## 0.4.12 (2026-11-13)

- Event analysis no longer mistakes a scanner for users hit by a false positive. An outside address blocked on 5 or
  more different paths in the window is probing: its paths are skipped as "scanner" and not sent to the model.
  Found on real data, where one address probing `/env.bak`, `/settings.py.bak`, `/static/config.json`... produced
  false-positive alerts.
- A false positive seen from only one or two outside addresses (no internal user) gets neither an exclusion nor an
  alert (before, the exclusion was already withheld but the alert was still opened).

## 0.4.11 (2026-11-13)

- Overview: without a GeoIP database, the source list says that countries, networks and the world map appear once
  GeoIP is set up (with a link to the setting for administrators). `/overview` reports `geoip`.
- Tests close every file and test server.

## 0.4.10 (2026-11-13)

- Notification settings: "Preview" on every event of the event matrix shows the message it sends (title, text,
  facts, link), from made-up example data, in any of the three languages. `GET /notify/preview?event=&lang=` (admin).

## 0.4.9 (2026-11-13)

- Filter by country: click a country on the world map or in the country list (overview, event list), or pick one in
  the event list's filters. Works for the overview, the event list and its timeline (`country=` in the API, external
  sources placed by GeoIP).
- The address lookup map marks the location even when the address has no events in the last 30 days.

## 0.4.8 (2026-11-13)

- World map of where requests come from (GeoIP): on the overview (every country, with the top 15 listed beside
  it), on the event list (the loaded events) and on the address lookup (the address's location). Drawn in the
  page from a bundled outline (loaded only when needed); no map service, nothing leaves the browser.
- Event timelines over several days are labelled once per day, at midnight.
- System check: "CA file unreadable" and "unencrypted remote" show green when they are false; the CA line is shown
  only when a CA file is set.
- Notification and LLM calls close the connection after an HTTP error response.

## 0.4.7 (2026-11-13)

- Timelines on list pages are titled for what they count (alerts, changes, audit records, versions, deliveries,
  configuration changes); alerts use the status colours (critical red, warning amber).
- Chinese interface: "封鎖" throughout instead of the colloquial "擋".
- Event analysis: duration column shown as minutes and seconds; guidance boxes no longer drawn inside a second frame.
- Notification settings: channels that are off are clearly dimmed in the event matrix.
- Tests: every page is also checked in Japanese.

## 0.4.6 (2026-11-13)

- Alerts can be acted on: "Draft an exclusion" (false positive) or "Draft a block" (attack) opens the change form
  filled from a recent event of that site and path.
- A false-positive alert is marked handled by itself (audited, with the change number) when the exclusion proposed
  for it is applied. An attack that may have passed still needs a person.

## 0.4.5 (2026-11-13)

- Daily report through the notification channels at a set hour (default 08:00, -1 = none): events, blocks and
  logged-only requests against the previous 24 hours, external sources, busiest sites and most matched rules, open
  alerts, changes applied, analysis proposals.
- Overview: a notice with the number of open alerts (and critical ones) and a link to them.

## 0.4.4 (2026-11-13)

- The guide's architecture diagram shows the event analysis, the notifications, the LLM server and the channels.
- Five overview tiles fit one row on a tablet.
- The browser test checks phone (375 px) and tablet (768 px) widths: no page scrolls sideways, the menu reaches every
  page group; screenshots for a visual check.
- Test plan, test checklist and changelog also in Traditional Chinese and Japanese (preflight checks every changelog
  has the release).

## 0.4.3 (2026-11-13)

- READMEs and the project site show the interface in the reader's language (English, Traditional Chinese and
  Japanese screenshots, all from the synthetic test environment); the browser test checks the Japanese pages too.
- A local or UDP syslog destination that cannot be reached no longer leaves a socket open on every retry.
- API and test plan documents: event timeline, syslog settings and behaviour.

## 0.4.2 (2026-11-13)

- Syslog over TLS can trust a SIEM's own certificate authority: `[syslog] ca_file` in config.toml (root only,
  never in the web interface).
- Timelines on the configuration change history (by cause: jt-waf-mgr, automation, outside) and the versions.
- The analysis page says the timer checks every five minutes (not hourly).
- Fix (independent review): with syslog over TLS, a certificate or handshake error made 0.4.1 drop the queued
  records one by one; now every connection, name or TLS error waits and retries, and only a record the server
  cannot take (too large) is dropped. A failed TLS handshake no longer leaves its socket open. The system check
  warns about an unreadable CA file, unencrypted remote syslog and dropped records.

## 0.4.1 (2026-11-13)

- Syslog in the web interface (Settings): on / off, destination (the local /dev/log, recommended, or host:port),
  protocol UDP, TCP or TLS (server certificate checked against the system CAs), format RFC 3164 or RFC 5424 (ISO
  time, host name, message id; octet-counting framing over TCP), facility. A TCP / TLS server that does not answer is
  retried after 30 seconds instead of slowing every request; failures show in the system check.
- Teams messages: a web address in a value is never turned into a link.
- Tests clean up every temporary directory they create.
- The analysis unit and guide describe the LLM server as configured (not local) and the batched requests.
- Browser test environment: a synthetic analysis run, so the analysis page and its summary are covered.

## 0.4.0 (2026-11-12)

- Notifications: e-mail (SMTP, text + HTML), Telegram, Microsoft Teams (Workflows, Adaptive Card), Slack,
  Discord, Zulip, Nextcloud Talk (signed bot) and a generic webhook (JSON, HMAC-SHA256 signature, optional
  bearer token). Set up in Settings > Notifications with a "send a test" per channel; a matrix decides which
  events go to which channel (security and integrity, changes awaiting approval / applied / failed, event
  analysis, backups, version changes, accounts). Messages in Traditional Chinese, English or Japanese, with a
  link back to the page. The web service only queues them; a new sandboxed one-shot unit
  (jt-waf-mgr-notify: request file + one-minute timer) sends them, retries (1, 5, 15 minutes), records
  failures, limits each channel per hour and keeps 90 days of delivery records. Values from requests are
  never markup, mentions or links in a message; secrets are write-only and never in errors or the audit trail.
- Alerts to follow up: what the event analysis or the system finds that someone has to look at (an attack the
  site may have answered with content, users hit by a false positive, an attack in progress, outside
  configuration changes, integrity problems, failed applies or backups, attacks on one-time codes) opens an
  alert, listed under Alerts with a count in the menu, notified at once and reminded until an approver marks
  it handled with a note (audited).
- Event analysis: also looks at requests the anomaly score blocked and proposes the narrowest exclusion for a
  false positive (one site, one path or path prefix, the rules and request parts that matched); exclusions
  always wait for a person. Confident blocks proposed by the analysis can apply by themselves when the new
  workflow switch is on (same conditions as other automatic tightening: external sources only, clean
  evidence, sandbox passed, daily limit). An attack probe the site answered with 2xx opens a critical alert;
  the model may flag an attack in progress.
- Overview: drag across the hourly timeline to look at that time range, or pick a custom range (1 hour to 31
  days; days instead of hours beyond a week); external sources show their country and network owner.
- Every card title can be folded (button or a click on the title band), remembered per page; cards with
  buttons in the title get the title band too; card titles fit on phones.
- Fixes: chart tooltips are no longer squeezed or cut off inside small cards; a link to a settings card keeps
  it at the top while the cards above it load.
- System check: notifications (on, channels in use, failures, stuck queue); Wazuh rule drafts for alerts and
  failed notifications. Schema 7.
- Event analysis page: a summary of the latest run (events analysed, how long it took, candidates, verdicts,
  proposals, alerts, the model's main points); every run records the number of events analysed and its duration.
- Timelines with drag-to-select on the event list and the address lookup (from the server, same filters) and on
  the audit trail, alerts, notification deliveries and changes (from the loaded rows).
- Top bar grouped into drop-downs (events, rules, changes, admin) with the open-alert and pending-approval
  counts on their group.
- Rules show where they come from: OWASP CRS (version, registered automation), a CRS plugin, imported at
  adoption, a change by a person / an API token / the event analysis (with the change), a vhost, an unmanaged
  site file, the ModSecurity base settings.
- Audit trail: the raw action name and a readable one in the reader's language; details open in a dialog with
  syntax-coloured JSON.
- Filter forms: applied conditions in colour; changed but not applied ones marked and the Apply button asks to be
  pressed.
- Overview tiles: icon, label, number, trend line and a full-width trend chart at the bottom.
- Layout: system check cards (status colour, problems first, no stretched cards, missing labels translated),
  the WAF model's scoring card and the lists of uninspected sites / locations, centred table rows, the guide's
  diagram line no longer on the group border, separated badges.
- Wording: 「封鎖」 instead of 「擋下」 in Traditional Chinese; the LLM is "self-hosted" (地端), not "local" (本機).
- From the independent review: exclusions proposed by the analysis are one exact path written one way (no case,
  ./ or ../ variants) and plain request parts read only from ModSecurity's own text; none from one or two outside
  addresses; approving one needs a one-time code and a note; at most five alerts of a kind per run; chat
  messages can never mention people; webhook token and secret bound to the webhook address (scheme, host, port);
  no SMTP password without TLS; no loopback / link-local notification targets; one dead channel does not hold
  up the others; rollback stops the analysis and notification units while the database is restored; the names
  analyst, system and cli are reserved.

## 0.3.5 (2026-11-12)

- Settings cards: two-column rows (name, explanation and where the value comes from on the left, the control
  on the right), on/off switches, database choices as chips, short number fields, unsaved rows marked, the
  save result next to the buttons.
- Notices keep a clear gap to the text before and after them, on every page.
- Local LLM settings in a clear order (address and key, test, model, switch on) with a step diagram: one
  "Save and test connection" button, and the model is chosen from ONE list filled by the last test (the
  separate text field and second list are gone). Reasoning models (a <think> block before the answer) work
  for the test and the analysis.
- The analysis interval is set in minutes (at least 10); the timer wakes the job every 5 minutes. A value
  stored in hours by 0.3.4 is read as minutes.
- Analysis page: live progress while a run is asked for or running (each step as it happens, also after
  leaving the page and coming back), then the result.
- Rule texts with syntax highlighting and a formatted view (one action per line, chained rules indented), the
  exact original one click away, copy button; also in diffs, the change preview and managed rules.
- Database backups can be downloaded (admin, fresh one-time code each time, audited). The nightly backup is
  no longer skipped after a backup made by hand the evening before.
- Long lists: one way to page through them -- "next" past the loaded rows loads the next batch (the separate
  "load more" button is gone).
- Overview: focus sites with events get a full-width card each, quiet ones share one line; rules chart full
  width with readable labels; trend lines show the value at the pointer; horizontal bars keep each label next
  to its bar; the source column stays on one line.
- Settings: the read-only configuration list refreshes after a save and no longer repeats what is set in the
  web interface; links to a settings card scroll to it.
- Flows with descriptions are a vertical timeline; every card title has an icon; theme and language are one
  icon menu each; compliance values as a labelled grid; paths aligned; audit record opens into view.
- Wording: two-factor authentication (雙因素驗證); API token is 「API 權杖」 in Traditional Chinese.
- Security: a number beyond the database range in a query parameter (e.g. cursor) answered 500; now 400.
- From an independent review of the backup download and schedule: one-time codes for sensitive actions
  (backup download, approving one's own loosening) are limited to 5 wrong codes per 10 minutes (then refused,
  recorded as critical) and a code can never be used twice, also by two requests at once; the backup is
  sent in pieces (not read into memory) and checked against its recorded SHA-256; a failing nightly backup is
  retried hourly (three times) and never removes good copies; the newest three backups are always kept; the
  monitor's timers use a monotonic clock; Wazuh rule drafts for downloads and repeated wrong codes.
- Release gates: TEST_PLAN.md; a security scan of every route on every browser test run
  (tools/security_scan.py); an OWASP ZAP passive + active scan of a logged-in disposable instance
  (tools/zap_scan.py, accepted findings with reasons in deploy/zap-baseline.conf).
- Adoption is no longer recorded as an outside configuration change: the site's old rule files leaving
  main.conf are part of jt-waf-mgr's own change. (The record made at the first site's adoption stays as it
  is; the system check stops warning about it after 7 days.)

## 0.3.4 (2026-11-12)

- Settings in the web interface (admin, audited, in effect at once, stored in the database and laid over
  the configuration file): GeoIP account and license key, the local LLM server, the scheduled event
  analysis, focus sites, known scanners, catch-all hosts, paths changed by known automation, login notice,
  compliance level, password and lockout policy. Secrets are write-only (only "set, ends with …" is shown)
  and never written to the audit trail. config.toml keeps only what the program needs to start.
- Scheduled event analysis with a local, OpenAI-compatible LLM (new page "Analysis", its own sandboxed unit
  with an hourly timer and "Run now"): recent external events that no confident rule blocked are grouped by
  path, the model judges which are attack probes, and every answer is validated by the program (ids,
  regex compiles, is narrow, matches every observed form, matches no common or legitimate path) before it
  becomes an ordinary confident-block proposal. The analysis never approves anything; its proposals always
  wait for a person, also when automatic apply of tightening changes is on. Any LLM error: nothing proposed.
- "Test connection" for the LLM server runs in the analysis unit (the web service keeps no network access
  beyond localhost).
- Several rule operations as one change ("bundle"): checked, approved and applied together - one version,
  one nginx reload, one rollback. Uploading a rules file can propose all differences as one change; new
  rules keep their place in the file.
- Confident blocks can also cover internal sources ("external and internal, known scanners excepted");
  such a rule is never applied automatically and its sandbox test expects the internal request refused.
- A new raw rule can be placed right before a given managed rule (e.g. before 10299).
- Configuration changes by known automation (e.g. the CRS update, country lists) are recorded as
  "automation" instead of "outside" when their paths are listed.
- GeoIP: switching it on or off in Settings takes effect without a restart.
- Charts: a distribution bar is one framed track; stacked horizontal bars no longer look like two pieces.
- Consecutive button rows no longer touch.
- From an independent review: rule ids of a bundle are reserved like any other; at most 20 confident blocks
  per bundle and one pass over the access logs for all of them; every confident block of a bundle needs its
  own matching 403 test; a change whose rules would differ at apply time from the checked ones (e.g. known
  scanners changed meanwhile) is checked and approved again; the analysis refuses a model regex that could
  backtrack catastrophically before it meets any request data; known scanners must be internal and no wider
  than /16; a new LLM server address needs the API key entered again; rule comments never end in a
  backslash; many rules inserted before one rule keep their order; the sandbox's internal test address is
  never a known scanner.

## 0.3.3 (2026-11-12)

- Adoption: the root apply program also validates rule by rule (it re-checks every request itself and
  refused the 37 KB site file as a whole); a failure names the rule. Verified end to end with the first
  site's real rule files: both checks pass and the 51 managed rules are identical to the originals.
- An adoption that failed its checks can be checked again (admin).
- "This change loosens the WAF" is shown only for loosening changes, not for neutral ones such as adoption.
- The changes page opens with the list; the workflow explanation is one click away.
- Hourly chart: the total and the time are shown right at the pointer.
- Rule charts (overview, IP lookup, rules) show what a rule is: "930120 · local file access", with the rule's message.
- `doctor` / system check from the command line judge the collector by the service's recorded progress
  (no more false warning).

## 0.3.2 (2026-11-12)

- Adoption of real-sized rule files: the static check now runs rule by rule (the per-rule length limit was
  applied to the whole 37 KB file and refused the adoption); a failure names the rule.
- `@pmFromFile` / `@ipMatchFromFile` are accepted for `.data` lists inside the ModSecurity configuration
  directories (e.g. the CRS's own scanner list); any other file, a path with `..` or a URL is refused.
- Overview: coloured stat tiles with an hourly trend and the change against the previous window; active
  filters are unmistakable (highlighted bar, filled chips, a banner over the numbers); the hourly chart uses
  the full width and its crosshair follows the pointer exactly.
- Tables wider than the screen get a floating horizontal scrollbar at the bottom of the window.
- Livelier light theme: tinted page, card headers with an accent bar, tinted guides and tiles, zebra rows; the
  architecture diagram, the role cards and the WAF decision summary are coloured by meaning.
- Spacing: a notice no longer touches the page title buttons; checkboxes sit next to their explanation; flow
  step labels no longer wrap.
- GeoIP setup text says to add the [geoip] section.

## 0.3.1 (2026-11-12)

Install and upgrade
- `upgrade.sh`: checks first (installed version, no apply in progress, disk space, the release verified by the
  installed code with the pinned key, the configuration accepted by the new code), then a backup (program,
  units, configuration, database), then the switch with an explicit database migration and checks after the
  start (the service answers with the new version, program integrity, audit chain). Any failure after the
  service was stopped rolls back automatically and starts the previous version again. `--check` runs the checks
  only; `--rollback` puts back what an upgrade saved.
- New commands: `jt-waf-mgr config-check`, `migrate`, `doctor`.
- The audit trail records every change of the program version (a downgrade at priority crit).
- `tools/test_upgrade.sh`: release gate that installs the previous release in a staging root with data,
  upgrades, rolls back on an injected failure, rolls back by hand and upgrades again.

## 0.3.0 (2026-11-12)

Interface
- Every button has an icon; the site's own dropdowns and date picker replace the browser's; every list table
  can be sorted, filtered, paged and its columns chosen; light / dark / system theme; slightly larger text.
- Charts wherever there are numbers; guidance flow diagrams on the pages that are part of a process; a new
  Guide page with an interactive architecture diagram, first steps, the change workflow and the roles.
- A logo, used for the favicon, the top bar and the login page.
- The overview can be filtered (origin, outcome, site, source, rule…) by clicking values; it names the focus
  sites section.
- GeoIP: country, city and network owner (ASN) next to every external address, by-country and by-ASN charts.
- Rules files can be downloaded (current, any version, or the site's original before adoption) and uploaded:
  an upload is compared rule by rule and turned into ordinary proposals, each checked, sandboxed and approved.
- WAF decision diagram (/waf), generated from the configuration: which mechanisms block, which only score or
  log, which loosen, for external and internal sources, with the anomaly-score scale and every rule involved.
  The CRS page states the effective behaviour next to the global engine mode.
- Tablet and phone layouts: the top bar folds into a menu when the links do not fit.
- System check lists where the program, configuration, data and records are.

Security
- The root apply program no longer follows links in the service user's spool, keeps its lock and snapshots in
  its own root-only directory and restores from memory (a compromised service could otherwise have reached
  root or written unchecked directives into nginx).
- An apply is refused when a managed file was edited outside jt-waf-mgr, instead of silently overwriting the
  edit; an approver can explicitly restore the files. A failed apply keeps its version number in the history.
- Login: at most four scrypt checks at once, atomic failure counting, IPv6 limits per /64, wrong current
  passwords on "change password" count toward the lockout; invalid Content-Length is refused.
- The creator of an API token cannot approve changes proposed through it.
- systemd: the web service and the apply program may only talk to the loopback; the apply program can write only
  /etc/nginx, its state directory and the spool.
- Syslog audit lines carry `"severity": "crit"` for integrity alerts (files drop the syslog priority).
- Draft Wazuh rules for the audit lines (deploy/wazuh).
- Collector: redaction runs in linear time on clipped input (one long parameter used to stall the collector for
  seconds to hours); oversized records are kept as truncated events instead of being dropped; long transaction
  ids no longer collide; every cookie and the Authorization / Cookie headers are always masked; copytruncate
  rotation no longer loses lines; one bad record no longer blocks the rest.
- Evidence checks use ModSecurity's own decoding (`+`, %u, path normalisation) and no longer skip DAV paths,
  so a block that would hit real traffic cannot pass (or be auto-applied); regression samples need several
  distinct sources and skip catch-all hosts and paths with WAF events.
- Integrity: the append-only triggers are compared word for word; a purge beyond the retention period (or any
  purge when keeping forever) is reported; the whole program directory is checked (a module shadowing the
  standard library, bytecode caches and links are found); upgrades are verified with the installed code.
- GeoIP reader: bounded decoding work per lookup and type checks on every value.

## 0.2.1 (2026-11-12)

- The interface uses a plain "/" instead of the full-width slash in Chinese and Japanese texts; the
  i18n check now rejects the full-width slash.
- The incremental and the daily full audit-chain checks no longer write two identical anchors when they
  fall due together.
- The installer and the compliance guide explain how to set the append-only flag on the anchor file
  from the host when jt-waf-mgr runs in a container (LXC).

## 0.2.0 (2026-11-11)

The change workflow.

- Adoption: the existing site rule files become jt-waf-mgr managed files, rule for rule (verified by a
  decision-equivalence sandbox run: the same requests give the same results before and after).
- Templates: exclusion (narrowest scope; remove a target, a rule, a tag; score only; body parser),
  confident block (external sources only, decided by CRS's 949110), redaction (not inspected, never
  logged), plugin toggle, and expert raw rules (admin only, forbidden-directive list).
- Static checks (regex sanity, too broad, ReDoS shape and runtime test, id ranges, never reused ids).
- Evidence: access-log scan for confident blocks (external 2xx/3xx, internal hits), alert impact for
  exclusions; an override needs a written justification and is never auto-applied.
- Sandbox: a throwaway nginx with the production configuration plus the change; user test cases,
  encoding / case / slash variants, internal-source check, per-site regression samples.
- Approval: proposer cannot approve (single-admin mode with OTP for one's own loosening); loosening
  always needs a person; optional auto-apply for qualifying tightening with a daily limit.
- Root apply program (systemd path unit): validates again, snapshot, nginx -t, reload, verifies new
  workers, waits for old ones, health check before/after, automatic restore on any failure;
  manual-edit detection; versions and one-click rollback.

Integrity and compliance:

- Audit trail hash chain (sha256 of the previous hash and the canonical row), append-only table
  (triggers), retention purge that keeps the chain verifiable; anchors every 5 minutes in an
  append-only file (chattr +a) and in syslog; every syslog line carries the row's id and hash;
  verification incremental / daily / on demand; NDJSON export with hashes, verifiable offline.
- Signed releases: release/MANIFEST.sha256 (every file) signed with the release key (RSA-3072); the
  installer verifies before installing and pins the key; the service (hourly) and the root apply
  program (every run, refusing on failure) check the installed files, units and wrapper;
  `jt-waf-mgr verify-release` before upgrades; CycloneDX SBOM.
- Configuration fingerprints (nginx / ModSecurity / CRS files, nginx binary, module) every 5 minutes;
  each change recorded and attributed (jt-waf-mgr or outside).
- Accounts: password character classes, history, optional maximum / minimum age; account expiry;
  dormant accounts disabled; session limit; own sessions list; sign out everywhere; previous sign-in
  and failed attempts shown after sign-in; login notice; account review export; lockouts audited
  as critical.
- Daily database backup with integrity check and SHA-256, verification on demand.
- System check page (program integrity, audit chain, anchors, syslog, time sync, disk, database,
  backups, collector, apply program, configuration changes, accounts, web settings) and Compliance
  page (ISO/IEC 27001:2022, Taiwan Cyber Security Management Act baseline, OWASP Top 10:2025),
  computed from the live configuration. docs/COMPLIANCE.md, SECURITY.md.
- Every write API route audits (enforced by a test); denied approvals and rollbacks are audited; the
  OTP for approving one's own loosening is replay-protected.

## 0.1.0 (unreleased)

First version: read-only.

- ModSecurity v3 JSON audit log collector with rotation handling and sensitive-field masking.
- Overview, events, event detail, rules, sites, CRS status, IP lookup.
- Local accounts with TOTP, roles, API tokens with scopes, audit trail to database and syslog.
- Read-only API: status, overview, events (filters, stats, NDJSON export with cursor and SHA-256),
  rules, removals, sites, CRS, IP lookup.
- UI in English, Traditional Chinese (Taiwan) and Japanese.
- Offline installer with a hardened systemd unit; no third-party Python packages.
