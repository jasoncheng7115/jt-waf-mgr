# Release checklist

**English** · [繁體中文](TEST_CHECKLIST_zh-TW.md) · [日本語](TEST_CHECKLIST_ja.md)

Every release passes all of these before it is published or installed anywhere (a site, a test machine,
a customer). A failed item stops the release; "it is only a small change" is not an exception.
What each gate covers and how it passes: `TEST_PLAN.md`.

## 1. Code
- [ ] `python3 -m unittest discover -s tests -t .` — all pass (also run by `tools/make_release.sh`).
- [ ] `tools/build_frontend.sh` — build, `check_i18n` (three languages, no full-width slash) and `check_ui`
      (icons on buttons, no native select / date inputs, tables through DataTable) all OK.
- [ ] `python3 tools/preflight.py` — publication checks (private names, addresses, secrets) OK; it also checks that
      README.md / README_zh-TW.md / README_ja.md have the new version in their title (update them and docs/index.html).
- [ ] Any UI change: every README and project-site screenshot taken again from the browser test, three languages and the
      thumbnails (`docs/shots/{en,zh-TW,ja}/`, `thumb/`); none may be older than the release run.
- [ ] New features have their cases in the tests (see `TEST_PLAN.md` §4); a new kind of published file or a new
      way of publishing gets its check in `tests/test_publication.py`.

## 2. Browser
- [ ] `tools/e2e/run.sh` — every page in zh-TW and en, light and dark, the theme switch, sorting /
      filtering / column choice / paging, select box and date picker, charts with tooltips, the guide,
      the login page and favicon; no console errors, no raw i18n keys, no buttons without icons.
- [ ] The same run ends with `tools/security_scan.py`: `security scan: OK` (headers, cookies, authentication and
      authorisation on every route, CSRF, methods, traversal, hostile input, malformed bodies, login).
- [ ] For UI changes: look at the screenshots, including a phone width (375 px) and a tablet (768 px).
- [ ] `tools/zap_scan.py` — OWASP ZAP (passive + active) on a disposable logged-in instance: URLs seen ≥ 40 and
      no High / Medium / Low alert outside `deploy/zap-baseline.conf`. Keep the report (`zap-reports/`).

## 3. Install and upgrade
- [ ] `tools/make_release.sh` — signed release; `openssl dgst -sha256 -verify deploy/release-key.pem
      -signature dist/jt-waf-mgr-X.Y.Z.tar.gz.sig dist/jt-waf-mgr-X.Y.Z.tar.gz` says Verified OK.
- [ ] `tools/test_upgrade.sh dist/<previous>.tar.gz dist/<new>.tar.gz` — install of the previous release with
      data, refusals, `--check`, automatic rollback on a failed start, upgrade (data, accounts, audit
      trail, integrity), manual rollback, upgrade again.
- [ ] On the production Python version (the server's own python3), in a temporary directory: the unit tests and
      `tools/test_upgrade.sh`. Nothing outside the temporary directory is touched.
- [ ] The database migration on a copy of the production database (`jt-waf-mgr migrate` with a
      configuration pointing at the copy), then `integrity` on the copy.

## 4. Real data
- [ ] Features that read external data are tested with the real thing at least once (e.g. a real
      GeoLite2 database for the MMDB reader, a real ModSecurity audit record for the collector).

## 5. Security
- [ ] New write routes audited (`TestAuditCoverage`), new inputs validated, attacker-controlled text shown
      as text. Changes to the apply program, the collector, authentication or integrity get a review by
      someone (or an agent) who did not write them.

## 5a. Nothing private leaves (see `TEST_PLAN.md` §5a)
- [ ] `tools/sync_github.sh` — copies only the PUBLISH.txt paths and runs preflight on the result.
- [ ] Commit through the hooks (never `--no-verify`): no private names, addresses, mailboxes, keys or tokens; no
      `Claude-Session:` line; author and committer = the identity configured for the repository.
- [ ] Annotated tag (`git tag -a vX.Y.Z -m 'jt-waf-mgr vX.Y.Z'`); `git push` runs `check_push.py` on every commit and
      tag being pushed — a refusal is fixed by removing the private item, never by skipping the hook.
- [ ] `tools/gh_release.py` — the release notes are scanned before they are sent.
- [ ] Screenshots only from the synthetic environment; when a check changed, scan the whole history again.

## 6. Production install
- [ ] `sudo ./upgrade.sh --check` on the server first; then `sudo ./upgrade.sh`.
- [ ] After it: `sudo jt-waf-mgr doctor`, the web interface, and (when nginx is involved) the site checks.
- [ ] After a country rule or an nginx change: the sites page, the audit log (`jt-country-block` refusals of outside
      requests), internal access and the health URLs as before; the backup of every hand-edited file is kept.
- [ ] Record the version, time and result in the deployment notes.
