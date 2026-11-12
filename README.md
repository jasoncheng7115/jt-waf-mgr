# jt-waf-mgr

Web management for **nginx + libmodsecurity v3 + OWASP CRS 4**.

libmodsecurity v3 has no management interface: rules, exclusions and blocks are configuration
files, and tuning means reading JSON audit logs and editing files by hand. jt-waf-mgr turns the
audit log into something you can read, and turns changes into an
evidence-checked, sandbox-tested, reversible workflow.

**Status: 0.2.** Read-only monitoring (0.1) plus the change workflow. Nothing touches nginx until an
administrator *adopts* the existing site rule files; from then on every change goes through
checks, evidence, a sandbox and an approval, and is written by a small root program that tests,
reloads, health-checks and restores on failure.

## What it does

- Collects the ModSecurity JSON audit log (handles copytruncate and rename rotation, oversized
  and malformed records), masks sensitive fields (passwords, tokens…) **before** storing anything.
- Overview: blocked / logged, by site, attack type, source and rule; **"blocked only by the CRS
  score"** first (the most likely false positives); cards for the sites you watch closely.
- Events with filters and a detail page with every matched rule; one click to draft an exclusion
  for a false positive or a block for an attack.
- Rules, sites (WAF state, bypassed locations, body limits, access restrictions), CRS status, IP lookup.
- **Change workflow**: templates (exclusion, confident block, redaction, plugin toggle, expert raw
  rule) → static checks (regex sanity, ReDoS) → evidence (access-log scan: did any external request
  matching the block succeed, does any internal source match?) → sandbox (a throwaway nginx with the
  production configuration plus the change, test cases, regression samples per site) → approval
  (the proposer cannot approve; loosening always needs a person) → apply (root program: snapshot,
  `nginx -t`, reload, verify, health check, automatic restore) → versions with one-click rollback.
- Local accounts (scrypt, TOTP required for approver / admin, lockout, password policy with history
  and optional ageing, account expiry, dormant-account disabling, account review), roles
  viewer / operator / approver / admin, API tokens with scopes (tokens can propose, never approve).
- **Integrity and compliance**: hash-chained, append-only audit trail with anchors in an append-only
  file and in syslog; signed release manifest checked by the installer, the service and the root apply
  program; fingerprints of every nginx / ModSecurity / CRS file with a record of each change; daily
  verified database backups; a System check page and a Compliance page (ISO/IEC 27001:2022, Taiwan's
  Cyber Security Management Act baseline, OWASP Top 10:2025) — see [docs/COMPLIANCE.md](docs/COMPLIANCE.md)
  and [SECURITY.md](SECURITY.md).
- UI in English, 繁體中文 and 日本語.

## Requirements

- Debian 12 / 13 or Ubuntu 22.04 / 24.04, Python 3.11 or newer (standard library only — no pip).
- nginx with the ModSecurity-nginx connector, libmodsecurity 3.0.9+, OWASP CRS 4.x.
- `SecAuditLogFormat JSON`. Rotate the audit log with `copytruncate` (libmodsecurity does not
  reopen it on reload).

## Install

```sh
sha256sum -c jt-waf-mgr-0.2.0.tar.gz.sha256
tar xzf jt-waf-mgr-0.2.0.tar.gz && cd jt-waf-mgr-0.2.0
sudo ./install.sh                             # verifies every file and the release signature first
sudo jt-waf-mgr check                         # parses the nginx / ModSecurity configuration
sudo jt-waf-mgr user add alice --role admin   # prints a temporary password
```

To let jt-waf-mgr change rules, arm the apply program (`sudo ./install.sh --enable-apply`, or
`systemctl enable --now jt-waf-mgr-apply.path`), set the health check URLs under Settings, and adopt
the existing rule files under Rules → Managed rules (an admin approves the adoption like any change).

Then add the management vhost (`/etc/jt-waf-mgr/nginx-vhost.conf.example`: internal networks
only, proxies to `127.0.0.1:8095`), `nginx -t`, reload, sign in, change the password and set up
TOTP. Older rotated audit logs can be imported: `sudo jt-waf-mgr import /var/log/modsecurity/modsec_audit.log.*.gz`.

Upgrades: verify the tarball (`openssl dgst -sha256 -verify /etc/jt-waf-mgr/release-key.pem -signature
jt-waf-mgr-X.Y.Z.tar.gz.sig jt-waf-mgr-X.Y.Z.tar.gz`), unpack it, then:

```sh
sudo ./upgrade.sh --check     # every check, nothing changed
sudo ./upgrade.sh             # backup, switch, checks; rolls back by itself on any failure
sudo ./upgrade.sh --rollback  # if needed later: back to the version (and database) before the upgrade
```

The upgrade verifies the new release with the installed program and the pinned key, refuses while a
change is being applied, keeps a backup in `/var/backups/jt-waf-mgr/` (the newest five) and records
every upgrade in the audit trail. `sudo jt-waf-mgr doctor` prints a health summary at any time.

The installer creates the `jtwaf` system user, `/usr/lib/jt-waf-mgr`, `/etc/jt-waf-mgr/config.toml`,
`/var/lib/jt-waf-mgr` and a hardened systemd unit. It does not change nginx. `./uninstall.sh`
removes the program and keeps data and configuration (`--purge` removes them too).

## Security

- The service listens on loopback only and runs unprivileged; only the apply program runs as root. It
  re-validates every request (allowed directives only, checksums, no manual edits on disk), writes only
  the managed files, and never runs anything taken from a request.
- Strict CSP without `unsafe-inline`; the UI renders attacker-controlled text (URLs, user agents,
  matched data) as text only.
- Sensitive values are masked before they reach the database; there is no way to see the original.
- API tokens can never approve changes, manage tokens or change settings.

## Development

```sh
python3 -m unittest discover -s tests -t .
tools/build_frontend.sh      # Vue 3 + Vite -> jtwafmgr/static/
tools/make_release.sh        # dist/jt-waf-mgr-<version>.tar.gz: SBOM, signed manifest, preflight
```

## License

AGPL-3.0. If you run a modified version as a network service, offer its source to its users
(the footer link does that for the unmodified version).
