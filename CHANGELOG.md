# Changelog

## 0.3.0 (unreleased)

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
