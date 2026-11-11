# Changelog

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
