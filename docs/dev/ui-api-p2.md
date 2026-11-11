# jt-waf-mgr UI ↔ backend contract, P2 (change workflow)

Adds to `ui-api.md` (same conventions: `/api/v1`, error shape, CSRF header, cursor lists, text-only
rendering of anything request-derived — rule texts, diffs, paths, user agents included).

Roles: `viewer` reads; `operator` proposes, cancels own, rechecks, manages regression samples;
`approver` approves / rejects / rolls back; `admin` also adopts and edits workflow settings.
Raw (expert) rules: admin only.

## Managed files and adoption

`GET /api/v1/managed` (viewer)
```json
{"adopted": false, "dir": "/etc/nginx/modsec/jt-waf-mgr", "drift": false, "current_version": null,
 "files": {"before": {"path": "…/before-crs.conf", "exists": false, "sha256": null, "expected": null, "drift": false},
           "after":  {…}},
 "items": [ManagedItem],                      // empty until adopted
 "import": {"sources": {"before": {"path": "/etc/nginx/modsec/site-before-crs.conf", "sha256": "…"},
                        "after":  {"path": "…", "sha256": "…"}},
            "rules": 50, "comment_blocks": 6},     // only while not adopted
 "adoption_change": {"id": 3, "state": "checking"} | null}     // only while not adopted
```
`ManagedItem`
```json
{"id": 12, "rule_id": 10130, "kind": "exclusion|confident_block|redaction|plugin|raw",
 "category": "exclusion|confident_block|redaction|plugin_toggle|system|other",  // for imported raw items: guessed
 "placement": "before|after", "position": 12.0, "enabled": true, "deleted": false,
 "origin": "imported|created", "comment": "# …", "text": "SecRule …", "spec": {…},
 "msg": "…", "hosts": ["app.example.com"], "created_by": "alice", "created_at": "…", "updated_at": "…", "change_id": 7}
```
`POST /api/v1/managed/adopt` (admin) → 202 `{"change_id": 3, "state": "checking"}`.
Adoption is a change like any other (op `adopt`): its checks run a decision-equivalence test (same requests,
current vs. managed configuration, results must be identical), then an admin approves, then it is applied.
Errors: 409 `already_adopted`, 409 `adoption_pending` (`details.change_id`), 409 `nothing_to_import`.
Until adopted, `POST /changes` answers 409 `not_adopted`.

## Changes

`Change` (list form)
```json
{"id": 7, "op": "add|modify|disable|enable|delete|adopt|rollback", "kind": "exclusion|confident_block|redaction|plugin|raw|system",
 "item_id": null, "rule_id": 10130, "direction": "tighten|loosen|neutral",
 "state": "checking|failed|pending_approval|approved|applying|applied|apply_failed|rejected|cancelled|rolled_back",
 "reason": "…", "proposed_by": "alice", "proposed_via": "user|api", "created_at": "…", "updated_at": "…",
 "spec": {…}, "summary": "app.example.com ^ /api remove_target_by_id 930120 ARGS:q", "error": null, "applied_version": null}
```
Full form (`GET /changes/{id}`) adds:
```json
{"rule_text": "SecRule …", "tests": [Test], "evidence_override": null, "base_version": 4,
 "diff": {"before": "--- current/before\n+++ proposed/before\n@@ …", "after": "…"},   // unified diff text; keys only for changed files
 "checks": {"started_at": "…", "finished_at": "…",
            "static":   {"ok": true} | {"ok": false, "error": "invalid_spec|duplicate_rule_ids|…", "details": {}},
            "evidence": EvidenceResult,
            "sandbox":  SandboxResult},
 "log": [{"ts": "…", "actor": "alice|system|apply", "action": "proposed|checks_passed|checks_failed|approved|rejected|cancelled|recheck|stale|auto_approved|apply_requested|applied|apply_failed|rollback_requested", "note": "…"}]}
```
`EvidenceResult` — one of:
- confident block: `{"ok": bool, "complete": bool, "scanned": 123456, "files": 40, "external_hits": 12, "external_success": 0,
  "internal_other": 0, "internal_known": 3, "sites": [{"host","hits"}], "external_success_samples": [{"host","status","path","ua","count"}],
  "internal_samples": [{"host","status","ip","path","count"}], "external_samples": [{"host","status","path","count"}]}`
  `ok` = complete and no external 2xx/3xx and no unknown internal hits.
- exclusion / redaction: `{"ok": true, "days": 30, "affected_events": 40, "external": 5, "external_attack_like": 1,
  "attack_like_samples": [{"id","host","path","outcome","rules"}], "warning": true}` — show the warning prominently.
- disable / delete: `{"ok": true, "days": 30, "hits": 120, "blocked": 80}`
- `{"ok": true, "skipped": "reason"}` or `{"ok": false, "error": "…"}`

`SandboxResult`:
- change: `{"ok": bool, "cases": 14, "failed": 0, "regression_checked": 80,
  "results": [{"origin": "test|variant|internal-same|regression|smoke", "source": "external|internal", "host", "method", "path",
               "expect": 403|200|"not403", "status": 403|"error:…", "rules": [930120, 949110], "ok": bool, "note": "…"}]}`
  (failed cases first)
- adoption: `{"ok": bool, "requests": 300, "blocked_before": 40, "differences": [{"request": {…}, "before": [403, [ids]], "after": [200, [ids]]}]}`
- `{"ok": false, "error": "sandbox_failed|test_required", "message": "…"}`, or `{"ok": true, "skipped": "…"}`

`GET /api/v1/changes?state=open|<state>&limit&cursor` (viewer) → `{"items": [Change], "next_cursor"}`. `open` = not final.

`POST /api/v1/changes/preview` (operator) body `{"kind", "spec"}` → `{"ok": true, "rule_id": 10130, "rule_text": "…",
"placement": "before", "direction": "loosen"}` or `{"ok": false, "field": "regex", "reason": "too_broad", "details": {}}`.
Use it for live validation while the form is edited (debounce ~400 ms).

`POST /api/v1/changes` (operator; tokens with `changes:propose`) body
```json
{"op": "add", "kind": "confident_block", "spec": {…}, "reason": "why (required)", "tests": [Test], "item_id": null}
```
→ 202 `{"change_id", "direction", "state": "checking", "rule_id"}`. For `modify|disable|enable|delete` pass `item_id`
(and `spec` for modify). Errors: 422 `invalid_spec` with `details.field` and `details.reason` (same reasons as preview),
400 `reason_required`, 409 `not_adopted`, 404 `item_not_found`, 400 `no_effect`, 403 `raw_admin_only`, 409 `id_range_full`,
409 `rule_id_in_use`, 400 `invalid_tests`.

`Test` (sandbox test case)
```json
{"expect": 403|200, "source": "external|internal", "host": "app.example.com", "method": "GET", "path": "/x?y=1",
 "headers": {"User-Agent": "…"}, "body": "a=1", "absent_rules": [930120], "present_rules": []}
```
A confident block needs at least one `expect: 403` external case (sandbox `test_required` otherwise).
`absent_rules`: rule ids that must no longer match (use it for exclusions: replay the request, the excluded rule must be gone).

Actions (approver unless noted), all return the full Change:
- `POST /changes/{id}/approve` body `{"note": "", "totp": "123456"}`. 403 `own_change` (proposer cannot approve unless
  single-admin mode); in single-admin mode approving one's own *loosening* needs `totp` (403 `totp_required`) and a
  `note` of 10+ chars (400 `note_required`). 409 `invalid_state`.
- `POST /changes/{id}/reject` body `{"note": "required"}`.
- `POST /changes/{id}/cancel` (operator; own change, or admin) — before approval only.
- `POST /changes/{id}/recheck` (operator) body `{"evidence_override": "justification (optional)"}` — from `failed` or
  `pending_approval`; with an override, a failed evidence check no longer blocks (recorded; never auto-applied).

## Versions

`GET /api/v1/versions` (viewer) → `{"items": [{"version": 5, "created_at", "change_id", "kind": "change|adopt|rollback",
"state": "pending|applied|superseded|failed", "summary": "…", "step": "done|drift|nginx_t|reload|health|…",
"health": {"https://…": [200, 200]}, "nginx_t": "…"}]}`
`POST /api/v1/versions/{version}/rollback` (approver) body `{"note": "required"}` → 202 `{"change_id"}`.
Errors 409 `apply_in_progress`, 409 `already_current`.

## Workflow settings (admin)

`GET /api/v1/workflow/settings` → `{"settings": {"approval.single_admin_mode": false, "apply.auto_tighten": false,
"apply.auto_tighten_daily_limit": 10, "sandbox.required": true, "health.urls": ["https://app.example.com/"],
"apply.wait_old_workers_seconds": 120}, "sandbox_available": true}`
`PATCH /api/v1/workflow/settings` body: any subset → same shape. 400 `invalid_value` (`details.url` for a bad URL).

## Regression samples

`GET /api/v1/regression` (viewer) → `{"items": [{"id", "host", "method", "path", "source": "auto|user", "pinned", "note", "added_at"}], "collected_at"}`
`POST /api/v1/regression` (operator) body `{"host", "path", "method": "GET", "note"}` → list. `DELETE /api/v1/regression/{id}` → 204.
`POST /api/v1/regression/collect` (admin) → 202 (re-samples from the access logs in the background).

## Template specs (what the forms send)

Scope objects: `host = {"mode": "any|exact|regex", "value": "app.example.com"}`,
`path = {"mode": "any|exact|prefix|regex", "value": "/api/"}`.

- exclusion: `{"host", "path", "method": "" | "POST", "source": "all|internal|external",
  "action": "remove_target_by_id|remove_target_by_tag|remove_rule|remove_tag|score_only|body_processor",
  "rule_ids": [930120], "targets": ["ARGS:redirect_uri"], "tag": "OWASP_CRS", "confirm_tag": false,
  "body_processor": "JSON|XML|URLENCODED|MULTIPART"}`.
  Host or path required. `remove_target_by_id` (default, recommended) needs rule_ids + targets;
  `remove_target_by_tag` tag + targets; `remove_rule` rule_ids; `remove_tag` tag + confirm_tag (warn: whole class);
  `score_only` = keep logging and confident blocks, drop "over the threshold → block" here (for endpoints whose body is
  user-typed text: drafts, chat, mail); `body_processor` = parse the body as the given format (client sends a wrong Content-Type).
- confident_block: `{"target": "path|uri|ua|host|header", "header": "X-Name", "regex": "…", "exceptions": ["^/remote\\.php/dav"],
  "host": {…}, "msg": "short description", "reference": "CVE-… or URL"}`. External sources only, always.
  Path targets are decoded, normalized and lowercased before matching — write lowercase regexes.
- redaction: `{"fields": ["password", "otp"], "host": {…}, "path": {…}}`.
- plugin: `{"plugin": "wordpress-rule-exclusions", "host": {"mode": "exact", "value": "blog.example.com"}}`.
- raw (admin): `{"text": "SecRule … \"id:10140,…\"", "placement": "before|after"}`.

Validation reasons the UI should translate (`change.reason.<reason>`): `empty`, `too_long`, `forbidden_character`,
`invalid_regex`, `matches_empty`, `too_broad`, `redos_shape`, `redos_runtime`, `required`, `invalid_text`, `invalid_host`,
`invalid_mode`, `invalid_path`, `invalid_source`, `invalid_action`, `scope_required`, `invalid_method`, `invalid_rule_ids`,
`invalid_targets`, `rule_ids_and_targets_required`, `tag_and_targets_required`, `invalid_tag`, `confirmation_required`,
`no_threshold_rule`, `invalid_body_processor`, `invalid_target`, `invalid_header`, `invalid_exceptions`, `invalid_fields`,
`invalid_plugin`, `forbidden` (details.what), `directive_not_allowed`, `invalid_id`, `removes_system_rule`,
`id_out_of_range`, `one_rule_per_change`, `id_mismatch`, `invalid_placement`, `unknown_kind`, `id_range_full`.

## UI pages (P2)

- **Changes**: tabs Open / Pending approval / History; badge with the count pending approval in the nav.
- **New change** wizard: pick a kind (exclusion recommended for false positives, confident block for attacks), form with
  live preview (rule text in `<pre>`, direction badge, next rule id), test cases editor, reason (required), submit.
  Prefill from an event: the event detail page gets buttons "Create exclusion for this" (host exact, path exact, rule ids =
  the non-scoring matched rules, targets parsed from the matched data's variable names like `ARGS:q`, source = the event's
  origin; one test: replay the request with `absent_rules` = those ids) and "Create similar block" (target path, regex
  `^<escaped path>$` lowercased as a starting point, one external test expecting 403 with the event's path).
- **Change detail**: summary, state timeline (log), rule text, diff (colored +/- lines, text only), checks (static,
  evidence with samples and the warning, sandbox with failed cases first), buttons per role/state: approve (TOTP + note
  fields shown when needed), reject (note), cancel, recheck (with optional evidence override text).
- **Managed rules** (under Rules): not adopted → explanation + import summary + "Adopt" button (admin) and the adoption
  change status; adopted → items list (rule id, kind/category, hosts, msg, origin, enabled) with actions: disable / enable /
  delete / modify (opens the wizard prefilled; raw items admin only), and a drift warning banner if `drift`.
- **Versions**: list with state, summary, health results; "Restore this version" (approver, note required).
- **Settings** (admin): workflow settings form (single-admin mode with an explanation, auto-apply tightening + daily limit,
  sandbox required, wait seconds, health check URL list editor) and regression samples (list, add pinned, delete, re-collect).
