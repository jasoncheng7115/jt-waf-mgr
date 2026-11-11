#!/usr/bin/env python3
"""Check the UI dictionaries.

- en.json, zh-TW.json and ja.json have exactly the same keys;
- every literal key used in frontend/src (t('...'), tOr('...')) exists in en.json;
- every key with a dynamic prefix used in the code (t('family.' + x)) has its required members;
- the product name is never in a dictionary (it is not translated);
- no value is empty.
Exit status 1 on any problem. Standard library only.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'frontend', 'src')
I18N = os.path.join(SRC, 'i18n')
LANGS = ('en', 'zh-TW', 'ja')
PRODUCT = 'jt-waf-mgr'

# Members the backend can send for each dynamic prefix (docs/dev/ui-api.md).
REQUIRED = {
    'family.': ['protocol', 'lfi', 'rfi', 'rce', 'php', 'generic', 'xss', 'sqli', 'session', 'java',
                'scanner', 'method', 'body', 'data_leak', 'local', 'other'],
    'role.': ['viewer', 'operator', 'approver', 'admin'],
    'outcome.': ['blocked', 'logged'],
    'decided.': ['confident', 'score', 'fallback', 'other'],
    'origin.': ['external', 'internal'],
    'source.': ['local', 'crs', 'plugin', 'vhost_inline', 'base', 'all'],
    'category.': ['exclusion', 'confident_block', 'system', 'redaction', 'plugin_toggle', 'other'],
    'waf.': ['on', 'off', 'block', 'unknown'],
    'actor.': ['user', 'token', 'system'],
    'result.': ['ok', 'denied', 'error', 'failed', 'outside'],
    'scope.': ['status_read', 'events_read', 'rules_read', 'lookups_read', 'changes_read', 'changes_propose'],
    # P2 (docs/dev/ui-api-p2.md)
    'cstate.': ['checking', 'failed', 'pending_approval', 'approved', 'applying', 'applied', 'apply_failed',
                'rejected', 'cancelled', 'rolled_back'],
    'op.': ['add', 'modify', 'disable', 'enable', 'delete', 'adopt', 'rollback'],
    'kind.': ['exclusion', 'confident_block', 'redaction', 'plugin', 'raw', 'system'],
    'direction.': ['tighten', 'loosen', 'neutral', 'tighten_hint', 'loosen_hint', 'neutral_hint'],
    'placement.': ['before', 'after'],
    'scope_mode.': ['any', 'exact', 'prefix', 'regex'],
    'vstate.': ['pending', 'applied', 'superseded', 'failed'],
    'versions.kind_': ['change', 'adopt', 'rollback'],
    'managed.origin_': ['imported', 'created'],
    'managed.op_hint.': ['disable', 'enable', 'delete'],
    'change.in_progress.': ['checking', 'approved', 'applying'],
    'apply_step.': ['request', 'validate', 'preflight', 'drift', 'nginx_t', 'reload', 'health', 'internal', 'done'],
    'clog.': ['proposed', 'checks_passed', 'checks_failed', 'approved', 'rejected', 'cancelled', 'recheck', 'stale',
              'auto_approved', 'auto_apply_skipped', 'apply_requested', 'applied', 'apply_failed', 'rollback_requested'],
    'sandbox.origin.': ['test', 'variant', 'internal-same', 'regression', 'smoke'],
    'sandbox.error.': ['sandbox_failed', 'test_required'],
    'evidence.col.': ['host', 'status', 'path', 'ua', 'count', 'ip'],
    'wizard.kind_hint.': ['exclusion', 'confident_block', 'redaction', 'plugin', 'raw'],
    'wizard.source_opt.': ['all', 'internal', 'external'],
    'wizard.target_opt.': ['path', 'uri', 'ua', 'host', 'header'],
    'wizard.action_opt.': ['remove_target_by_id', 'remove_target_by_tag', 'remove_rule', 'remove_tag', 'score_only', 'body_processor'],
    'wizard.action_hint.': ['remove_target_by_id', 'remove_target_by_tag', 'remove_rule', 'remove_tag', 'score_only', 'body_processor'],
    'wizard.tests_hint.': ['block', 'other'],
    'wizard.field.': ['host', 'path', 'method', 'source', 'action', 'rule_ids', 'targets', 'tag', 'body_processor', 'target',
                      'header', 'regex', 'exceptions', 'msg', 'reference', 'fields', 'plugin', 'text', 'placement', 'kind'],
    'change.reason.': ['empty', 'too_long', 'forbidden_character', 'invalid_regex', 'matches_empty', 'too_broad', 'redos_shape',
                       'redos_runtime', 'required', 'invalid_text', 'invalid_host', 'invalid_mode', 'invalid_path',
                       'invalid_source', 'invalid_action', 'scope_required', 'invalid_method', 'invalid_rule_ids',
                       'invalid_targets', 'rule_ids_and_targets_required', 'tag_and_targets_required', 'invalid_tag',
                       'confirmation_required', 'no_threshold_rule', 'invalid_body_processor', 'invalid_target',
                       'invalid_header', 'invalid_exceptions', 'invalid_fields', 'invalid_plugin', 'forbidden',
                       'directive_not_allowed', 'invalid_id', 'removes_system_rule', 'id_out_of_range',
                       'one_rule_per_change', 'id_mismatch', 'invalid_placement', 'unknown_kind', 'id_range_full',
                       'duplicate_rule_ids'],
    # compliance and integrity (docs/dev/ui-api-compliance.md)
    'syscheck.k.': ['version', 'program_integrity', 'audit_chain', 'anchor_file', 'syslog', 'time_sync', 'disk', 'database',
                    'backup', 'collector', 'apply', 'config_changes', 'accounts', 'web'],
    'syscheck.d.': ['version', 'program_integrity', 'audit_chain', 'anchor_file', 'syslog', 'time_sync', 'disk', 'database',
                    'backup', 'collector', 'apply', 'config_changes', 'accounts', 'web'],
    'syscheck.status.': ['ok', 'warn', 'fail', 'info'],
    'chain.reason.': ['prev_mismatch', 'hash_mismatch', 'triggers_missing', 'verified_tip_missing', 'anchored_row_missing',
                      'anchored_hash_changed', 'anchor_unreadable', 'anchor_write_failed'],
    'cfgchg.cause.': ['baseline', 'jt-waf-mgr', 'outside'],
    'compliance.lv.': ['low', 'medium', 'high'],
    'compliance.f.': ['all', 'gap', 'partial', 'organisational', 'met'],
    'compliance.st.': ['met', 'partial', 'gap', 'organisational'],
    'compliance.tw.': ['access.account', 'access.least_privilege', 'ident.auth_mgmt', 'ident.internal_users', 'ident.feedback',
                       'log.events', 'log.content', 'log.protection', 'log.failure', 'log.capacity', 'log.time',
                       'monitor.system', 'integrity.software', 'integrity.patch', 'acquisition.lifecycle',
                       'continuity.backup', 'comm.storage', 'comm.transmission'],
    'compliance.owasp.': ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'],
    'compliance.ctl.': [c + s for c in (
        'account_management', 'least_privilege', 'segregation_of_duties', 'session_timeout', 'authentication',
        'multi_factor', 'auth_feedback', 'audit_logging', 'log_protection', 'log_failure_response', 'log_capacity',
        'time_sync', 'siem_forwarding', 'evidence_export', 'software_integrity', 'configuration_management',
        'change_management', 'backup', 'data_masking', 'data_at_rest', 'transport', 'retention', 'secure_development',
        'vulnerability_management', 'monitoring') for s in ('.title', '.desc')],
    'error.': [
        'not_authenticated', 'forbidden', 'invalid_credentials', 'totp_required', 'totp_invalid',
        'too_many_attempts', 'password_too_short', 'password_same', 'totp_required_for_role',
        'user_exists', 'invalid_username', 'cannot_modify_self', 'last_admin',
        'password_change_required', 'totp_setup_required', 'totp_already_enabled', 'totp_not_set_up',
        'password_too_long', 'invalid_role', 'invalid_name', 'invalid_scope', 'invalid_cidr',
        'invalid_expiry', 'invalid_token', 'token_source_not_allowed', 'not_found', 'bad_request',
        'internal_error', 'csrf_failed', 'method_not_allowed', 'payload_too_large',
        'network_error', 'unknown',
        'not_adopted', 'already_adopted', 'adoption_pending', 'nothing_to_import', 'invalid_spec', 'reason_required',
        'item_not_found', 'no_effect', 'raw_admin_only', 'id_range_full', 'rule_id_in_use', 'invalid_tests', 'own_change',
        'totp_required', 'note_required', 'invalid_state', 'apply_in_progress', 'already_current', 'invalid_value',
        'unknown_setting', 'invalid_op', 'invalid_kind',
        'password_too_simple', 'password_reused', 'password_too_recent'],
}

LITERAL = re.compile(r"""\b(?:t|tOr)\(\s*'([A-Za-z0-9_.\-]+)'\s*[,)]""")


def main():
    problems = []
    dicts = {}
    for lang in LANGS:
        path = os.path.join(I18N, lang + '.json')
        with open(path, encoding='utf-8') as fh:
            dicts[lang] = json.load(fh)
    en = set(dicts['en'])
    for lang in LANGS[1:]:
        keys = set(dicts[lang])
        for k in sorted(en - keys):
            problems.append('%s.json: missing %s' % (lang, k))
        for k in sorted(keys - en):
            problems.append('%s.json: extra key %s' % (lang, k))
    for lang, d in dicts.items():
        for k, v in d.items():
            if not isinstance(v, str) or not v.strip():
                problems.append('%s.json: %s is empty' % (lang, k))
            elif PRODUCT in v:
                problems.append('%s.json: %s contains the product name (never translated, keep it out)' % (lang, k))
            if isinstance(v, str) and '\uff0f' in v:
                problems.append('%s.json: %s uses a full-width slash; use "/"' % (lang, k))
            # placeholders must match the English ones
            if isinstance(v, str) and k in dicts['en']:
                want = set(re.findall(r'\{(\w+)\}', dicts['en'][k]))
                got = set(re.findall(r'\{(\w+)\}', v))
                if want != got:
                    problems.append('%s.json: %s placeholders %s != en %s' % (lang, k, sorted(got), sorted(want)))
    used = set()
    for dirpath, _, files in os.walk(SRC):
        if os.path.abspath(dirpath).startswith(os.path.abspath(I18N)):
            continue
        for name in files:
            if not name.endswith(('.vue', '.js')):
                continue
            with open(os.path.join(dirpath, name), encoding='utf-8') as fh:
                body = fh.read()
            for m in LITERAL.finditer(body):
                key = m.group(1)
                if key.endswith('.'):
                    continue  # dynamic prefix, checked through REQUIRED
                used.add(key)
                if key not in en:
                    problems.append('%s: key %s not in en.json' % (os.path.relpath(os.path.join(dirpath, name), ROOT), key))
    for prefix, members in REQUIRED.items():
        for m in members:
            if prefix + m not in en:
                problems.append('en.json: missing %s%s' % (prefix, m))
    if '--unused' in sys.argv:
        dyn = tuple(REQUIRED) + ('settings.',)
        for k in sorted(en - used):
            if not k.startswith(dyn):
                print('unused: ' + k)
    for p in problems:
        print(p)
    if problems:
        print('i18n check: %d problem(s)' % len(problems))
        return 1
    print('i18n check: OK (%d keys x %d languages, %d literal keys used)' % (len(en), len(LANGS), len(used)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
