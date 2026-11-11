# Compliance mapping

What jt-waf-mgr does that supports common security controls, and what the organisation running it
still has to do. Only what the code actually does is listed. The **Compliance** page in the UI
(admin) computes the status of each control from the live configuration; this document explains the
mapping.

Frameworks referenced:
- **ISO/IEC 27001:2022** Annex A
- **Taiwan Cyber Security Management Act** (資通安全管理法): the protection baseline for information
  systems (資通系統防護基準, appendix 10 of 資通安全責任等級分級辦法). Item names follow that appendix.
  Which measures apply depends on the system's protection level (普 / 中 / 高). Check the current
  version published by the competent authority when you assess.
- **OWASP Top 10:2025**

Set the protection level in `/etc/jt-waf-mgr/config.toml`:

```toml
[compliance]
level = "medium"     # "", "low", "medium", "high"
```

It changes nothing in the behaviour; the Compliance page then shows which settings are below what
that level asks for.

## Access control

### account_management
ISO A.5.16, A.5.18 · 資安法 存取控制－帳號管理 · OWASP A01
- Local accounts with four roles. Accounts can be created with an end date (`expires_at`) and are
  disabled automatically after it.
- Accounts without a sign-in for `auth.dormant_days` (default 90) are disabled. The last active
  admin is never disabled.
- Account review: `GET /api/v1/users/review` and the *Account review* view list every account and
  every active API token with role, state, last sign-in (time and address) and days since activity.
  Each review is an audit row. Download as CSV or JSON for the review record.
- Every account change is audited: created, role, disabled / enabled, reset, unlock, expiry,
  sessions revoked.

### least_privilege
ISO A.5.15, A.8.2, A.8.3 · 資安法 存取控制－最小權限 · OWASP A01
- Roles:
  - viewer reads;
  - operator proposes;
  - approver approves and rolls back;
  - admin adopts and manages accounts, tokens and settings.
- API tokens carry scopes and allowed source networks. They can never approve, manage tokens or
  change settings.

### segregation_of_duties
ISO A.5.3, A.8.32 · OWASP A06
- The proposer of a change cannot approve it. Loosening changes always need a person; tokens can
  only propose.
- Single-admin mode (for one-person sites) is an explicit, audited setting. Approving one's own
  loosening then needs a fresh OTP and a written reason.

### session_timeout
ISO A.8.5 · 資安法 存取控制－帳號管理 · OWASP A07
- Idle timeout (`server.session_idle_minutes`, default 30) and absolute timeout
  (`server.session_max_hours`, default 12).
- Sessions per user are limited (`auth.max_sessions_per_user`).
- Users see and end their own sessions; admins can sign a user out everywhere.

## Identification and authentication

### authentication
ISO A.5.17, A.8.5 · 資安法 識別與鑑別－身分驗證管理 · OWASP A07
- Passwords are hashed with scrypt. Temporary passwords must be changed at first sign-in.
- Policy (all configurable under `[auth]`):
  - minimum length (12);
  - character classes (3 of 4);
  - not one of the last N passwords (3);
  - optional maximum age (forces a change at sign-in) and minimum age.
- Lockout after `lockout_threshold` failures for `lockout_minutes` (5 / 15). The lockout is audited
  at syslog priority crit. There is also a per-address rate limit.
- Medium / high level systems: set `password_max_age_days` and `password_min_age_hours`.

### multi_factor
ISO A.8.5 · 資安法 識別與鑑別－內部使用者之識別與鑑別 · OWASP A07
- TOTP (RFC 6238) with replay protection. It is required for approver and admin by default
  (`auth.require_totp_roles`).
- High level systems: require it for every role.

### auth_feedback
ISO A.8.5 · 資安法 識別與鑑別－鑑別資訊回饋 · OWASP A07
- Password and OTP inputs are masked.
- An unknown user and a wrong password give the same answer in the same time.
- After sign-in the user sees the previous sign-in (time, address) and the number of failed attempts
  since then.

## Logging and accountability

### audit_logging
ISO A.8.15 · 資安法 記錄事件、日誌紀錄內容 · OWASP A09
- Every action is an audit row with time, actor, actor type (user / token / system), source
  address, action, result and details:
  - sign-in, sign-out, failures and lockouts;
  - account, token and setting changes;
  - every change proposal, check, approval, rejection, application and rollback;
  - exports, reviews, backups and integrity results.
- The same record is sent to syslog as one JSON line (`jt-waf-mgr:` program name), with the row's id
  and hash.
- A test walks every write route of the API and fails if one does not audit.

### log_protection
ISO A.8.15, A.5.33 · 資安法 日誌資訊之保護 · OWASP A09
- Hash chain: each row stores `sha256(previous hash + canonical row)`. Changing, inserting or
  removing a row breaks it.
- The audit table is append-only (database triggers). The retention purge (`retention.audit_days`,
  default 0 = keep forever) removes only the oldest rows and keeps the chain verifiable.
- Anchors: every 5 minutes the newest (id, hash) is appended to
  `/var/lib/jt-waf-mgr/audit-anchors.jsonl` and sent to syslog. The file is append-only
  (`chattr +a`); the service user cannot change or remove lines. A chain rewritten from the
  database no longer matches the anchors.
  - Inside a container (LXC) the flag cannot be set: the container lacks CAP_LINUX_IMMUTABLE, and the
    installer warns. Set it from the host, e.g. on Proxmox:
    `chattr +a /proc/$(lxc-info -n <CTID> -p -H)/root/var/lib/jt-waf-mgr/audit-anchors.jsonl`.
    The flag is stored in the filesystem and survives restarts. Without it, the syslog anchors in the SIEM
    are the only independent copy.
- Verification: every 5 minutes (incremental), daily (full), on demand (*Verify chain* on the audit
  page), and from the command line (`jt-waf-mgr integrity`).
- A failure is an audit row `integrity.audit_chain_failed` at syslog priority crit.

### log_failure_response
ISO A.8.16 · 資安法 日誌處理失效之回應 · OWASP A09
- Syslog send errors are counted and shown on the System check page.
- Integrity failures, failed backups and lockouts are logged at priority crit, so the SIEM can alert
  on them. They are repeated every 12 hours while the problem stays.

### log_capacity
ISO A.8.6 · 資安法 日誌儲存容量
- Free space where the database lives is checked (`integrity.disk_min_free_mb`).
- Retention per data type is configurable:
  - `retention.events_days` (30);
  - `retention.stats_days` (365);
  - `retention.audit_days` (0 = forever).

### time_sync
ISO A.8.17 · 資安法 時戳及校時
- The System check page reports whether the clock is NTP-synchronised (systemd-timedated; works with
  systemd-timesyncd and chrony). All records carry timestamps with offsets.

### siem_forwarding
ISO A.8.16 · 資安法 資通系統監控
- Syslog (facility `local0` by default) carries every audit row and the anchors.
- Forwarding to the SIEM is configured in rsyslog / journald: an organisational measure.

### evidence_export
ISO A.5.28
- `GET /api/v1/audit/export` (admin): NDJSON with every row's hashes and a summary line with a
  SHA-256 over the lines.
- `jt-waf-mgr audit-verify FILE` verifies an export offline.
- Event exports (`/events/export`) also carry a SHA-256.

## Integrity, configuration and change

### software_integrity
ISO A.8.19, A.8.32 · 資安法 軟體及資訊完整性 · OWASP A08, A03
- The release contains `release/MANIFEST.sha256` (SHA-256 of every file), signed with the release key
  (RSA-3072). The installer verifies every file and the signature before installing, and pins the key
  on the first install.
- The service checks hourly, and the root apply program before every run, that the installed files
  (package, systemd units, command wrapper) match the signed manifest. Extra files in the package
  directory count as a failure. The apply program refuses to work when the check fails.
- Before an upgrade: `jt-waf-mgr verify-release <unpacked dir>`.
- SBOM: `sbom.cdx.json` (CycloneDX 1.5) in every release.

### configuration_management
ISO A.8.9 · OWASP A02
- Every 5 minutes these are fingerprinted (SHA-256):
  - every nginx / ModSecurity / CRS file;
  - the nginx binary;
  - the ModSecurity module.
- Each change is stored with its added / removed / changed files and attributed to jt-waf-mgr (an
  applied version) or outside. Outside changes are audited (`config.changed`, result `outside`) and
  listed under *Configuration changes*.
- The managed rule files carry a SHA-256 header. A manual edit is detected and the apply program
  refuses to overwrite it.

### change_management
ISO A.8.32, A.8.31 · 資安法 系統發展生命週期 · OWASP A06
- Every rule change goes through:
  - static checks (regex sanity, ReDoS, id ranges, forbidden directives);
  - evidence from the access logs;
  - a sandbox (a throwaway nginx with the production configuration plus the change, test cases and
    regression samples);
  - approval;
  - application by the root program with `nginx -t`, reload, verification, health check and
    automatic restore.
- Versions are kept and can be rolled back.

### backup
ISO A.8.13 · 資安法 營運持續計畫－系統備份
- The database is backed up daily (SQLite online backup, `integrity_check` on the copy, a SHA-256
  file, mode 0600) and kept `backup.keep_days` (14) days.
- Backups can be made and verified on demand (UI, `jt-waf-mgr backup`, `jt-waf-mgr backup --verify FILE`).
- The managed nginx files of every version are kept by the apply program (`spool/backups`).
- Copying backups off the host is an organisational measure.

## Data protection

### data_masking
ISO A.8.11, A.8.12 · 資安法 資料儲存之安全
- Values of sensitive request fields (`waf.sensitive_fields`: password, token, otp, secret…) are
  masked before anything is stored, in arguments, matched data and URLs. No API returns the original.

### data_at_rest
ISO A.8.24 · 資安法 資料儲存之安全
- The database is mode 0600 in a 0700 directory owned by the service user.
- It is not encrypted by jt-waf-mgr; the Python standard library has no AES. It contains no
  sensitive request values (see above).
- High level systems: use disk encryption (organisational measure).

### transport
ISO A.8.24, A.8.20 · 資安法 傳輸之機密性與完整性
- The service listens on loopback only.
- The management vhost terminates TLS (1.2 / 1.3, HSTS); see `deploy/nginx-vhost.conf.example`.
- Cookies are `Secure` with the `__Host-` prefix.

### retention
ISO A.8.10
- Events, statistics and audit rows are purged after their configured retention.
- Backups are removed after `backup.keep_days`.

## Development and operation

### secure_development
ISO A.8.25, A.8.26, A.8.28, A.8.29 · 資安法 系統發展生命週期 · OWASP A03, A05, A10
- No third-party Python packages. Strict CSP without `unsafe-inline`; no `v-html`.
- Parameterised SQL only; no `shell=True`.
- Unit and API tests, including authorization and audit coverage.
- The release preflight scans for private data and secrets.

### vulnerability_management
ISO A.8.8 · 資安法 漏洞修復
- nginx, CRS and ModSecurity versions are shown in the UI.
- Patching the operating system, nginx and CRS is an organisational measure.
- Report vulnerabilities in jt-waf-mgr as described in [SECURITY.md](../SECURITY.md).

### monitoring
ISO A.8.16, A.8.20 · 資安法 資通系統監控
- jt-waf-mgr collects and presents the WAF's own events.

## What the organisation must do

- Forward syslog to a separate SIEM with write-once storage, and alert on `integrity.*`,
  `backup.failed`, `account.locked` and `config.changed` with result `outside`.
- Review accounts periodically (Users → Account review) and keep the downloaded record.
- Copy the daily database backups off the host. Test a restore once a year.
- Keep the management vhost restricted to administration networks.
- Patch the operating system, nginx, libmodsecurity and CRS.
- Keep the host clock NTP-synchronised.
- Keep the private release key off production hosts. Only the public key is installed.

## How to verify

```sh
jt-waf-mgr integrity                        # program files (signed manifest) + audit chain + anchors
jt-waf-mgr verify-release ./jt-waf-mgr-X.Y.Z   # an unpacked release, with the pinned key
jt-waf-mgr audit-verify export.ndjson       # an audit export, offline
jt-waf-mgr backup --verify jt-waf-mgr-YYYYMMDD-HHMMSS.db
cd /usr/lib/jt-waf-mgr && sha256sum -c --ignore-missing release/MANIFEST.sha256
openssl dgst -sha256 -verify /etc/jt-waf-mgr/release-key.pem \
    -signature /usr/lib/jt-waf-mgr/release/MANIFEST.sha256.sig /usr/lib/jt-waf-mgr/release/MANIFEST.sha256
lsattr /var/lib/jt-waf-mgr/audit-anchors.jsonl   # shows the a (append-only) flag
```

Where the data is:
- Database: `/var/lib/jt-waf-mgr/jt-waf-mgr.db`. It holds events (masked), statistics, the audit
  trail, accounts, changes, versions and configuration snapshots.
- Anchors: `/var/lib/jt-waf-mgr/audit-anchors.jsonl`.
- Backups: `/var/lib/jt-waf-mgr/backups/`.
- Managed nginx files: `/etc/nginx/modsec/jt-waf-mgr/`. Their previous versions are in
  `/var/lib/jt-waf-mgr/spool/backups/`.
- Configuration: `/etc/jt-waf-mgr/config.toml`. Pinned release key: `/etc/jt-waf-mgr/release-key.pem`.
