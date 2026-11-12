# Security policy

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** for this repository (Security → Report a
vulnerability). Do not open a public issue.

- Acknowledgement: within 3 business days.
- A fix or a mitigation for confirmed high or critical issues: target 7 days. Others ship with the next release.
- You will be credited in the changelog unless you ask not to be.

Only the latest release is supported.

## Design summary

These are what the code does; the [compliance mapping](docs/COMPLIANCE.md) links each to the
controls it supports.

### Process and privilege separation

- The web service runs as the unprivileged `jtwaf` user and listens on loopback only.
- The systemd unit is hardened: `ProtectSystem=strict`, an empty capability set, a system call filter, and no new privileges.
- Only the apply program runs as root. It is started by a systemd path unit, never by the service, and it:
  - re-validates every request: an allowed-directive list, checksums, the rule-id range, and manual-edit detection;
  - writes only the managed files;
  - tests, reloads, verifies and health-checks every change, and restores the previous files on any failure;
  - never runs anything taken from a request (no `shell=True` anywhere);
  - refuses to work when the installed program does not match its signed manifest;
  - treats the spool as hostile (it belongs to the service user): the directory is opened once without
    following links, requests are opened with `O_NOFOLLOW` and checked after opening, results are written
    with exclusive create and renamed in place, so a planted link cannot redirect a root write;
  - keeps its lock and snapshots in its own root-only directory (`/var/lib/jt-waf-mgr-apply`), and restores
    from the contents it read into memory, never from files that could have been swapped;
  - refuses to apply when a managed file was changed outside jt-waf-mgr (drift) instead of overwriting the
    edit; an approver can explicitly restore the current version, which is recorded at priority crit;
  - runs boxed in by systemd: it can write only `/etc/nginx`, its state directory and the spool, has no
    devices, and may only talk to the loopback (the health check).
- The web service may only talk to the loopback (`IPAddressDeny=any`, `IPAddressAllow=localhost`): if it
  were ever taken over, it could not reach out. GeoIP downloads run in their own short-lived unit.

### Supply chain

- The backend uses the Python standard library only. There are no third-party Python packages at all.
- The UI bundle contains Vue and Vue Router. Their versions are listed in the release SBOM (`sbom.cdx.json`, CycloneDX 1.5).
- Every release carries `release/MANIFEST.sha256`, the SHA-256 of every file. It is signed with the project's release key (RSA-3072, SHA-256).
- The installer checks every file and the signature before it installs anything. On an upgrade it does so
  with the already installed (and itself verified) code; on a first install it can only use the code it
  ships, so verify the tarball first: `openssl dgst -sha256 -verify release-key.pem -signature …` (below)
  or, on an upgrade, `jt-waf-mgr verify-release <unpacked dir>`.
  - The first install pins the key in `/etc/jt-waf-mgr/release-key.pem`.
  - Later releases must be signed with the pinned key; a new key needs `--accept-new-key`.
- Before an upgrade, `jt-waf-mgr verify-release <unpacked dir>` checks the new release with the already installed, verified code.
- At runtime, the service checks hourly (and the apply program before every run) that the installed files match the signed manifest:
  - nothing changed, nothing missing, no extra file anywhere in /usr/lib/jt-waf-mgr (a module there would
    shadow the standard library), no bytecode cache, no symbolic link;
  - the systemd units and the command wrapper as well.
- The tarball itself also has a `.sha256` and a detached signature:

  ```sh
  openssl dgst -sha256 -verify release-key.pem -signature jt-waf-mgr-X.Y.Z.tar.gz.sig jt-waf-mgr-X.Y.Z.tar.gz
  ```

### Web

- The Content-Security-Policy has no `unsafe-inline` and no third-party origins.
- The other response headers are `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP / CORP and Permissions-Policy.
- Session cookies use the `__Host-` prefix and are `Secure`, `HttpOnly` and `SameSite=Lax`. Only the SHA-256 of a session id is stored.
- Every write needs a CSRF header and an Origin check.
- Attacker-controlled content (URLs, user agents, matched data, rule texts) is always rendered as text: no `v-html`, no `innerHTML`.
- Sensitive request values (passwords, tokens, OTPs…) are masked before anything is stored. No API can show the originals.

### Accounts

- Passwords are hashed with scrypt (N=2^15, r=8, p=1).
- Password policy: minimum length and character classes, history, and optional maximum and minimum age.
- TOTP (RFC 6238, replay-protected) is required for approver and admin.
- Lockout after repeated failures, counted atomically (simultaneous guesses each count), plus a per-address rate limit
  (IPv6 per /64). An unknown user gets the same error and timing as a wrong password.
- At most four password checks (scrypt, 32 MiB each) run at once, so a burst of logins cannot exhaust the
  service's memory; the rest are told to retry.
- A wrong current password on "change password" counts toward the lockout like a failed login.
- A change proposed through an API token belongs to the person who created the token: they cannot approve it.
- Accounts can expire and are disabled when dormant. There is a session limit per user, a list of one's own sessions, and an admin "sign out everywhere".
- API tokens:
  - only their SHA-256 is stored;
  - they are limited by scope and source network, with an optional expiry;
  - they can never approve a change, manage accounts or tokens, or change settings.

### Audit trail

- Every action is recorded in the audit table and as one JSON line in syslog.
- Each row stores `sha256(previous hash + canonical row)`. SQLite triggers make the table append-only; the retention purge removes only a prefix and keeps the chain verifiable.
- The triggers themselves are checked word for word (an empty trigger with the right name does not pass).
  Rows may only disappear through the retention purge, and only rows older than the retention period:
  with the default (keep forever) any purge is reported.
- Every few minutes, the newest (id, hash) is appended to an append-only file (`chattr +a`) and sent to syslog. A rewritten or truncated chain no longer matches these anchors, nor the hashes the SIEM received with every row.
- Audit exports are NDJSON with the hashes and a SHA-256 over the lines. They can be verified offline with `jt-waf-mgr audit-verify`.

### Limits of these protections

- In a container (LXC) the append-only flag must be set from the host; the container cannot set it.
- Root on the host can change anything. The anchors and the syslog copy make tampering detectable, not impossible.
  - Forward syslog to a separate SIEM with write-once storage.
  - Watch for the `integrity.*` audit actions; they are logged at syslog priority `crit`.
- The database is not encrypted at rest; the standard library has no AES. It is protected by file permissions (0600, directory 0700).
  - Sensitive request values never reach it.
  - Use disk encryption where your policy asks for it.
- The management vhost must stay restricted to internal networks (see `deploy/nginx-vhost.conf.example`).

## Accepted risks

- After a correct password the server asks for the TOTP code, which tells the client the password was
  right. This is the usual two-step sign-in; the lockout, the rate limits and the audit trail (with SIEM
  alerts on failed logins and lockouts) bound what an attacker can learn.

- The service runs the sandbox (a throwaway nginx on 127.0.0.1), so its unit cannot use `MemoryDenyWriteExecute`: PCRE JIT needs it, exactly as in the production nginx.
