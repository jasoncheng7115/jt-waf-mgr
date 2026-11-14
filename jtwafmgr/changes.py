"""The change workflow (SPEC 6).

  checking -> pending_approval -> approved -> applying -> applied
      |              |                            \\-> apply_failed (rolled back automatically)
      \\-> failed     \\-> rejected                 applied -> rolled_back (a later version restored)
  any state before "applying" -> cancelled

Checks run in a background worker: static (the rule renders and the whole file passes the
expert-mode checks), evidence (access log / event history), sandbox (a throwaway nginx with the
production configuration plus the change). Loosening always needs a person's approval; API tokens
can propose but never approve. Applying is done by the separate root program (apply.py): this
side only writes a request into the spool directory and reads the result back.
"""
import collections
import datetime
import hashlib
import ipaddress
import json
import re
import os
import threading
import time
import traceback

from . import rulegen, util
from .managed import Managed, sha256

FINAL = ('applied', 'rejected', 'cancelled', 'failed', 'apply_failed', 'rolled_back')
OPS = ('add', 'modify', 'disable', 'enable', 'delete')
DEFAULT_SETTINGS = {
    'approval.single_admin_mode': False,        # proposer may approve own change (audited, OTP for loosening)
    'apply.auto_tighten': False,                # tightening that passed every check applies without approval
    'apply.auto_tighten_daily_limit': 10,
    'apply.auto_tighten_analyst': False,        # the event analysis' confident blocks too (same conditions)
    'sandbox.required': True,
    'health.urls': [],                          # ["https://app.example.com/", ...] checked before/after apply
    'apply.wait_old_workers_seconds': 120,
}


class ChangeError(Exception):
    def __init__(self, code, status=400, **details):
        super().__init__(code)
        self.code, self.status, self.details = code, status, details


class Workflow:
    def __init__(self, app):
        self.app = app
        self.db = app.db
        self.cfg = app.cfg
        self.managed = Managed(app.db, app.cfg, app.site)
        self._wake = threading.Event()
        self._stop = threading.Event()
        self.sandbox = None     # set by app (sandbox.Sandbox) when available
        self.evidence = None    # set by app (evidence.Evidence)

    # --- settings -------------------------------------------------------------------------
    def setting(self, key):
        return self.managed.setting(key, DEFAULT_SETTINGS.get(key))

    def settings(self):
        return {k: self.setting(k) for k in DEFAULT_SETTINGS}

    def set_setting(self, key, value, actor):
        if key not in DEFAULT_SETTINGS:
            raise ChangeError('unknown_setting')
        d = DEFAULT_SETTINGS[key]
        if isinstance(d, bool) and not isinstance(value, bool):
            raise ChangeError('invalid_value')
        if isinstance(d, int) and not isinstance(d, bool) and (not isinstance(value, int) or isinstance(value, bool)
                                                               or not 0 <= value <= 10000):
            raise ChangeError('invalid_value')
        if key == 'health.urls':
            if not isinstance(value, list) or len(value) > 100:
                raise ChangeError('invalid_value')
            for u in value:
                if not isinstance(u, str) or not __import__('re').fullmatch(r'https?://[a-z0-9.-]+(?::\d{1,5})?/\S{0,500}', u):
                    raise ChangeError('invalid_value', url=str(u)[:100])
        self.managed.set_setting(key, value, actor)

    # --- reading --------------------------------------------------------------------------
    def get(self, cid):
        r = self.db.one('SELECT * FROM changes WHERE id=?', (cid,))
        if not r:
            raise ChangeError('not_found', 404)
        return r

    def _proposed_ip(self, cid):
        """Where the proposal came from: the source address in its audit row (an API caller's machine, a person's)."""
        try:
            row = self.db.one("SELECT src_ip FROM audit WHERE action IN ('change.proposed', 'change.bundle_proposed') "
                              "AND json_extract(details, '$.change_id')=? ORDER BY id LIMIT 1", (cid,))
        except Exception:       # noqa: BLE001 -- an old SQLite without JSON: just not shown
            return None
        return row['src_ip'] if row else None

    def public(self, r, full=False):
        d = {'id': r['id'], 'op': r['op'], 'kind': r['kind'], 'item_id': r['item_id'], 'rule_id': r['rule_id'],
             'direction': r['direction'], 'state': r['state'], 'reason': r['reason'], 'proposed_by': r['proposed_by'],
             'proposed_via': r['proposed_via'], 'created_at': util.iso(r['created_at']),
             'updated_at': util.iso(r['updated_at']), 'spec': json.loads(r['spec']),
             'summary': summarize(r['kind'], json.loads(r['spec']), r['op']), 'error': r['error'],
             'applied_version': r['applied_version'], 'proposed_owner': r['proposed_owner'],
             'proposed_ip': self._proposed_ip(r['id'])}
        if full:
            checks = json.loads(r['checks'] or '{}')
            d.update({'rule_text': r['rule_text'], 'checks': checks, 'tests': json.loads(r['tests'] or '[]'),
                      'evidence_override': r['evidence_override'], 'base_version': r['base_version'],
                      'log': [{'ts': util.iso(x['ts']), 'actor': x['actor'], 'action': x['action'], 'note': x['note']}
                              for x in self.db.q('SELECT * FROM change_log WHERE change_id=? ORDER BY id', (r['id'],))],
                      'diff': checks.get('diff')})
        return d

    def list(self, state=None, limit=100, before_id=None):
        sql, args = 'SELECT * FROM changes WHERE 1=1', []
        if state == 'open':
            sql += ' AND state NOT IN (%s)' % ','.join('?' * len(FINAL))
            args += list(FINAL)
        elif state:
            sql += ' AND state=?'
            args.append(state)
        if before_id:
            sql += ' AND id<?'
            args.append(before_id)
        rows = self.db.q(sql + ' ORDER BY id DESC LIMIT ?', args + [limit + 1])
        return [self.public(r) for r in rows[:limit]], (str(rows[limit - 1]['id']) if len(rows) > limit else None)

    def log(self, cid, actor, action, note=''):
        self.db.x('INSERT INTO change_log(change_id, ts, actor, action, note) VALUES (?,?,?,?,?)',
                  (cid, util.now(), actor, action, note[:2000]))

    def _state(self, cid, state, error=None, **cols):
        sets = ['state=?', 'updated_at=?', 'error=?'] + ['%s=?' % k for k in cols]
        self.db.x('UPDATE changes SET %s WHERE id=?' % ', '.join(sets),
                  [state, util.now(), error] + list(cols.values()) + [cid])

    # --- proposing ------------------------------------------------------------------------
    def _build_op(self, op, kind, spec, item_id, via, role, taken=None):
        """Validate one rule operation and build its rule text. Returns a dict (nothing saved).
        taken: rule ids already handed out (by earlier operations of the same bundle)."""
        if op not in OPS:
            raise ChangeError('invalid_op')
        spec = spec if isinstance(spec, dict) else {}
        taken = set(taken or ())
        item = None
        if op != 'add':
            item = self.managed.item(item_id) if item_id else None
            if not item or item['deleted'] or item['kind'] == 'comment':
                raise ChangeError('item_not_found', 404)
            kind = item['kind']
            if op in ('disable',) and not item['enabled'] or op == 'enable' and item['enabled']:
                raise ChangeError('no_effect')
        if kind not in rulegen.KINDS:
            raise ChangeError('invalid_kind')
        if kind == 'raw' and (via != 'user' or role != 'admin') and op in ('add', 'modify'):
            raise ChangeError('raw_admin_only', 403)
        rule_id = item['rule_id'] if item else None
        text = item['text'] if item else ''
        if op in ('add', 'modify'):
            if op == 'add':
                if kind == 'raw':
                    ids = rulegen.check_raw_text(spec.get('text') or '', cfg=self.cfg)
                    rule_id = ids[0] if ids else None
                    if rule_id is not None and (rule_id in self.managed.occupied_ids() or rule_id in taken):
                        raise ChangeError('rule_id_in_use', 409, rule_id=rule_id)
                else:
                    try:
                        rule_id = self.managed.next_rule_id(kind, extra=taken)
                    except ValueError:
                        raise ChangeError('id_range_full', 409)
            try:
                spec, text, _ = rulegen.build(kind, spec, rule_id, self.cfg)
            except rulegen.SpecError as e:
                raise ChangeError('invalid_spec', 422, field=e.field, reason=e.code, **e.details)
            if kind == 'country':
                self._country_ready(spec)
            if op == 'add' and spec.get('before_rule_id'):
                pl = spec.get('placement', 'before')
                if not any(it['rule_id'] == spec['before_rule_id'] and it['placement'] == pl
                           for it in self.managed.items()) and spec['before_rule_id'] not in taken:
                    raise ChangeError('invalid_spec', 422, field='before_rule_id', reason='anchor_not_found',
                                      rule_id=spec['before_rule_id'])
        else:
            spec = json.loads(item['spec'])
        return {'op': op, 'kind': kind, 'item_id': item_id if op != 'add' else None, 'rule_id': rule_id, 'spec': spec,
                'text': text, 'direction': rulegen.direction(op, kind, text)}

    def _start(self, reason, tests):
        reason = (reason or '').strip()
        if not reason or len(reason) > 2000:
            raise ChangeError('reason_required')
        if not self.managed.adopted():
            raise ChangeError('not_adopted', 409)
        tests = tests or []
        _check_tests(tests)
        return reason, tests

    def _country_ready(self, spec):
        """A country rule needs the feature on and staged lists for each of its countries (the root program builds
        its list file from them before the rule is applied)."""
        if not self.cfg['countries']['enabled']:
            raise ChangeError('countries_off', 409)
        from .countries import read_manifest
        man = read_manifest(self.cfg['countries']['dir'])
        if not man:
            raise ChangeError('countries_no_data', 409)
        missing = [c for c in spec['countries'] if c not in man['countries']]
        if missing:
            raise ChangeError('invalid_spec', 422, field='countries', reason='unknown_country', countries=missing[:10])

    def _country_tests(self, spec):
        """Sandbox tests of a country rule: a request from an address of a country that passes (200) and from one
        that is refused (403), plus the same site from inside (always passes)."""
        from .countries import Lookup
        if spec.get('host', {}).get('mode') != 'exact':
            return []
        host = spec['host']['value'].replace('*', 'www')
        listed = spec['countries']
        other = next((c for c in ('US', 'DE', 'BR', 'CN', 'RU', 'IN', 'FR', 'GB', 'JP', 'TW') if c not in listed), None)
        lk = Lookup(self.cfg['countries']['dir'], listed[:1] + ([other] if other else []))
        out = []
        a, b = lk.sample(listed[0]), lk.sample(other) if other else None
        inside, outside = (200, 403) if spec['mode'] == 'allow' else (403, 200)
        if a:
            out.append({'host': host, 'path': '/', 'method': 'GET', 'source': 'external', 'src_ip': a, 'expect': inside})
        if b:
            out.append({'host': host, 'path': '/', 'method': 'GET', 'source': 'external', 'src_ip': b, 'expect': outside})
        out.append({'host': host, 'path': '/', 'method': 'GET', 'source': 'internal', 'expect': 200})
        return out

    def _with_country_tests(self, built, tests):
        for b in built:
            if b['kind'] == 'country' and b['op'] in ('add', 'modify', 'enable'):
                tests = tests + self._country_tests(b['spec'])
        if len(tests) > 50:
            raise ChangeError('invalid_tests', reason='at most 50 tests (country rules add 3 each)')
        return tests

    def propose(self, op, kind, spec, reason, actor, via='user', item_id=None, tests=None, role=None, owner=None):
        if op not in OPS:
            raise ChangeError('invalid_op')
        reason, tests = self._start(reason, tests)
        b = self._build_op(op, kind, spec, item_id, via, role)
        tests = self._with_country_tests([b], tests)
        return self._insert(b['op'], b['kind'], b['item_id'], b['rule_id'], b['spec'], b['direction'], reason, actor, via,
                            b['text'], tests, owner)

    def _insert(self, op, kind, item_id, rule_id, spec, direction, reason, actor, via, text, tests, owner):
        t = util.now()
        with self.db.tx() as c:
            cur = c.execute('INSERT INTO changes(op, kind, item_id, rule_id, spec, direction, state, reason, proposed_by, '
                            'proposed_via, created_at, updated_at, rule_text, tests, proposed_owner) '
                            'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                            (op, kind, item_id, rule_id, json.dumps(spec), direction, 'checking', reason, actor, via, t, t,
                             text, json.dumps(tests), owner or (actor if via == 'user' else None)))
            cid = cur.lastrowid
        self.log(cid, actor, 'proposed', reason)
        self.app.audit.log('change.proposed', actor, 'token' if via == 'api' else 'user', None, 'ok', change_id=cid,
                           direction=direction, kind=kind, op=op, rule_id=rule_id)
        self._wake.set()
        return cid

    # --- several operations as one change ------------------------------------------------------
    BUNDLE_MAX = 100
    BUNDLE_MAX_BLOCKS = 20       # confident blocks per bundle (each one is checked against the logs and in the sandbox)

    def propose_bundle(self, ops, reason, actor, via='user', tests=None, role=None, owner=None):
        """Several rule operations as ONE change: checked (static, evidence for each, sandbox for the
        result), approved and applied together -- one version, one reload, one rollback.
        ops: [{'op', 'kind'?, 'spec'?, 'item_id'?}]. Tightening only when every operation tightens."""
        reason, tests = self._start(reason, tests)
        if not isinstance(ops, list) or not 1 <= len(ops) <= self.BUNDLE_MAX:
            raise ChangeError('invalid_bundle', 422, limit=self.BUNDLE_MAX)
        built, taken, items = [], set(), set()
        for i, o in enumerate(ops):
            if not isinstance(o, dict):
                raise ChangeError('invalid_bundle', 422, index=i)
            iid = o.get('item_id')
            if iid is not None and (not isinstance(iid, int) or isinstance(iid, bool)):
                raise ChangeError('invalid_bundle', 422, index=i, reason='item_id')
            try:
                b = self._build_op(str(o.get('op') or 'add'), str(o.get('kind') or ''), o.get('spec'), o.get('item_id'),
                                   via, role, taken)
            except ChangeError as e:
                e.details = dict(e.details or {}, index=i)
                raise
            if b['item_id'] is not None:
                if b['item_id'] in items:
                    raise ChangeError('invalid_bundle', 422, index=i, reason='item_twice')
                items.add(b['item_id'])
            if b['op'] == 'add' and b['rule_id'] is not None:
                taken.add(b['rule_id'])
            built.append(b)
        if sum(1 for b in built if b['kind'] == 'confident_block' and b['op'] in ('add', 'modify', 'enable')) > self.BUNDLE_MAX_BLOCKS:
            raise ChangeError('invalid_bundle', 422, reason='too_many_blocks', limit=self.BUNDLE_MAX_BLOCKS)
        direction = 'tighten' if all(b['direction'] == 'tighten' for b in built) else 'loosen'
        tests = self._with_country_tests(built, tests)
        text = '\n\n'.join('# %s %s %s\n%s' % (b['op'], b['kind'], b['rule_id'] or '', b['text'] or '')
                            for b in built)[:200000]
        spec = {'ops': [{k: b[k] for k in ('op', 'kind', 'item_id', 'rule_id', 'spec', 'direction')} for b in built]}
        return self._insert('bundle', 'bundle', None, None, spec, direction, reason, actor, via, text, tests, owner)

    # --- rules file upload: a batch of ordinary proposals, never a direct write ---------------
    MAX_UPLOAD_ITEMS = 500

    def import_diff(self, placement, text):
        """Compare an uploaded rules file with the managed rules of one placement, rule by rule (by id).
        Nothing is saved. Rows: new | changed | same | missing | invalid | conflict."""
        if placement not in ('before', 'after'):
            raise ChangeError('invalid_placement')
        if not isinstance(text, str) or not text.strip() or len(text) > 1024 * 1024 or '\x00' in text:
            raise ChangeError('invalid_file')
        if not self.managed.adopted():
            raise ChangeError('not_adopted', 409)
        from .managed import split_items
        parts = [it for it in split_items(text) if it['text']]
        if len(parts) > self.MAX_UPLOAD_ITEMS:
            raise ChangeError('too_many_rules', 422, limit=self.MAX_UPLOAD_ITEMS)
        current = {it['rule_id']: it for it in self.managed.items() if it['placement'] == placement and it['rule_id']}
        rows, seen = [], set()
        norm = lambda t: '\n'.join(l.rstrip() for l in (t or '').strip().splitlines())   # noqa: E731
        for it in parts:
            row = {'rule_id': it['rule_id'], 'text': it['text'], 'current_text': None, 'item_id': None, 'kind': None,
                   'status': None, 'error': None}
            try:
                rulegen.check_raw_text(it['text'], cfg=self.cfg)
            except rulegen.SpecError as e:
                row.update(status='invalid', error='%s%s' % (e.code, (': ' + str(e.details.get('what'))) if e.details.get('what') else ''))
                rows.append(row)
                continue
            if it['rule_id'] is None:
                row.update(status='invalid', error='no_rule_id')
            elif it['rule_id'] in seen:
                row.update(status='invalid', error='duplicate_rule_id')
            elif it['rule_id'] in current:
                cur = current[it['rule_id']]
                row.update(current_text=cur['text'], item_id=cur['id'], kind=cur['kind'])
                if norm(cur['text']) == norm(it['text']):
                    row['status'] = 'same'
                elif cur['kind'] != 'raw':
                    row.update(status='conflict', error='template_rule')   # edit template rules with the form
                else:
                    row['status'] = 'changed'
            elif it['rule_id'] in self.managed.occupied_ids():
                row.update(status='conflict', error='rule_id_in_other_file')
            else:
                row['status'] = 'new'
            if it['rule_id'] is not None:
                seen.add(it['rule_id'])
            rows.append(row)
        for rid, cur in current.items():
            if rid not in seen and cur['kind'] != 'comment':
                rows.append({'rule_id': rid, 'text': None, 'current_text': cur['text'], 'item_id': cur['id'],
                             'kind': cur['kind'], 'status': 'missing', 'error': None})
        return rows

    def import_propose(self, placement, text, reason, user, delete_missing=False, as_one=False):
        """One ordinary change per difference, each checked, sandboxed and approved on its own -- or, with
        as_one, all differences as one change (one approval, one apply). New rules keep their place in the
        uploaded file: each goes right before the next rule of the file that already exists."""
        rows = self.import_diff(placement, text)
        reason = (reason or '').strip()
        if not reason:
            raise ChangeError('reason_required')
        if as_one:
            ops, existing_after = [], {}
            nxt = None
            for r in reversed(rows):                    # the next existing rule (file order) of each new rule
                if r['status'] == 'new':
                    existing_after[id(r)] = nxt
                elif r['status'] in ('same', 'changed') and r['rule_id']:
                    nxt = r['rule_id']
            for r in rows:
                if r['status'] == 'new':
                    sp = {'text': r['text'], 'placement': placement}
                    if existing_after.get(id(r)):
                        sp['before_rule_id'] = existing_after[id(r)]
                    ops.append({'op': 'add', 'kind': 'raw', 'spec': sp})
                elif r['status'] == 'changed':
                    ops.append({'op': 'modify', 'kind': 'raw', 'item_id': r['item_id'],
                                'spec': {'text': r['text'], 'placement': placement}})
                elif r['status'] == 'missing' and delete_missing:
                    ops.append({'op': 'delete', 'kind': r['kind'], 'item_id': r['item_id']})
            if not ops:
                raise ChangeError('nothing_to_import', 409)
            cid = self.propose_bundle(ops, reason, user['username'], role=user['role'])
            self.app.audit.log('managed.import_proposed', user['username'], 'user', None, 'ok', placement=placement,
                               changes=[cid], operations=len(ops), as_one=True)
            return {'changes': [{'rule_id': None, 'status': 'bundle', 'change_id': cid, 'operations': len(ops)}],
                    'skipped': []}
        made, skipped = [], []
        for r in rows:
            try:
                if r['status'] == 'new':
                    cid = self.propose('add', 'raw', {'text': r['text'], 'placement': placement}, reason, user['username'],
                                       role=user['role'])
                elif r['status'] == 'changed':
                    cid = self.propose('modify', 'raw', {'text': r['text'], 'placement': placement}, reason,
                                       user['username'], item_id=r['item_id'], role=user['role'])
                elif r['status'] == 'missing' and delete_missing:
                    cid = self.propose('delete', r['kind'], {}, reason, user['username'], item_id=r['item_id'],
                                       role=user['role'])
                else:
                    continue
                made.append({'rule_id': r['rule_id'], 'status': r['status'], 'change_id': cid})
            except ChangeError as e:
                skipped.append({'rule_id': r['rule_id'], 'status': r['status'], 'error': e.code})
        self.app.audit.log('managed.import_proposed', user['username'], 'user', None, 'ok', placement=placement,
                           changes=[m['change_id'] for m in made], skipped=len(skipped))
        return {'changes': made, 'skipped': skipped}

    # --- switching rules on and off, several at once ------------------------------------------
    TOGGLE_MAX = 300
    REMOVE_CHUNK = 20          # rule ids per exclusion / removal line

    @staticmethod
    def _removed_ids(it):
        """The rule ids a managed item removes (exclusion 'remove_rule', or SecRuleRemoveById / ctl in raw text)."""
        try:
            spec = json.loads(it['spec'] or '{}')
        except ValueError:
            spec = {}
        out = set()
        if it['kind'] == 'exclusion' and spec.get('action') == 'remove_rule':
            out |= {i for i in spec.get('rule_ids') or [] if isinstance(i, int)}
        if it['kind'] == 'raw':
            text = it.get('text') or ''
            for line in re.findall(r'SecRuleRemoveById\s+([\d,\s-]+)', text) + re.findall(r'ruleRemoveById=([\d,-]+)', text):
                for part in re.split(r'[\s,]+', line.strip()):
                    if part.isdigit():
                        out.add(int(part))
                    elif re.fullmatch(r'\d+-\d+', part):
                        lo, hi = map(int, part.split('-'))
                        if hi - lo <= 100000:
                            out |= set(range(lo, hi + 1))
        return out

    def toggle_plan(self, action, rule_ids, scope=None):
        """What switching these rules on or off takes, as bundle operations (nothing is created):
        managed site rules are disabled / enabled; CRS rules are disabled by exclusions for the chosen sites
        (scope {'mode': 'hosts', 'hosts': [...]}) or by a removal for every request ({'mode': 'all'}, an expert rule:
        admin only), and enabled again by switching off the managed items that remove them. Rules that cannot be
        switched here are listed in 'skipped' with the reason."""
        if action not in ('disable', 'enable'):
            raise ChangeError('invalid_action', 422)
        if not isinstance(rule_ids, list) or not rule_ids or len(rule_ids) > self.TOGGLE_MAX or \
                not all(isinstance(i, int) and not isinstance(i, bool) for i in rule_ids):
            raise ChangeError('invalid_rule_ids', 422, limit=self.TOGGLE_MAX)
        if not self.managed.adopted():
            raise ChangeError('not_adopted', 409)
        _, m = self.app.site.load()
        states = m.rule_states()
        loaded = {r.id: r for r in m.rules if r.id is not None}
        items = [it for it in self.managed.items() if it['kind'] != 'comment']
        by_rule = {it['rule_id']: it for it in items if it['rule_id']}
        system = set(self.cfg['waf']['threshold_rule_ids']) | set(self.cfg['waf']['score_rule_ids']) | \
            set(self.cfg['waf']['fallback_rule_ids']) | util.SCORING_RULES
        ops, skipped, crs_off, crs_on = [], [], [], set()
        for rid in dict.fromkeys(rule_ids):
            it = by_rule.get(rid)
            if it is not None:                                  # a managed site rule
                if bool(it['enabled']) == (action == 'enable'):
                    skipped.append({'id': rid, 'reason': 'already'})
                else:
                    ops.append({'op': action, 'item_id': it['id']})
                continue
            r = loaded.get(rid)
            if r is None:
                skipped.append({'id': rid, 'reason': 'not_loaded'})
            elif m.source_of(r) != 'crs':
                skipped.append({'id': rid, 'reason': 'not_managed'})
            elif rid in system:
                skipped.append({'id': rid, 'reason': 'system_rule'})
            else:
                st = (states.get(rid) or {}).get('state', 'on')
                if action == 'disable':
                    if st == 'off':
                        skipped.append({'id': rid, 'reason': 'already'})
                    else:
                        crs_off.append(rid)
                elif st == 'on':
                    skipped.append({'id': rid, 'reason': 'already'})
                elif st == 'inactive':
                    skipped.append({'id': rid, 'reason': 'paranoia_level'})
                else:
                    crs_on.add(rid)
        if crs_off:
            scope = scope if isinstance(scope, dict) else {}
            chunks = [crs_off[i:i + self.REMOVE_CHUNK] for i in range(0, len(crs_off), self.REMOVE_CHUNK)]
            if scope.get('mode') == 'all':
                for c in chunks:
                    ops.append({'op': 'add', 'kind': 'raw', 'spec': {
                        'text': '# switched off for every request\nSecRuleRemoveById %s' % ' '.join(map(str, c)),
                        'placement': 'after'}})
            elif scope.get('mode') == 'hosts':
                hosts = scope.get('hosts')
                if not isinstance(hosts, list) or not 1 <= len(hosts) <= 20 or not all(isinstance(h, str) for h in hosts):
                    raise ChangeError('invalid_scope', 422)
                for h in dict.fromkeys(x.strip().lower() for x in hosts):
                    for c in chunks:
                        ops.append({'op': 'add', 'kind': 'exclusion', 'spec': {
                            'host': {'mode': 'exact', 'value': h}, 'path': {'mode': 'any'},
                            'action': 'remove_rule', 'rule_ids': c}})
            else:
                raise ChangeError('scope_required', 422)
        if crs_on:
            done = set()
            for it in items:
                if not it['enabled']:
                    continue
                rem = self._removed_ids(it) & (crs_on | set(loaded))
                hit = rem & crs_on
                if not hit:
                    continue
                if rem <= crs_on:                    # the item removes only rules being switched on: switch it off
                    ops.append({'op': 'disable', 'item_id': it['id']})
                    done |= hit
                else:
                    for rid in sorted(hit - done):
                        skipped.append({'id': rid, 'reason': 'shared_item', 'item_rule_id': it['rule_id']})
                    done |= hit
            for rid in sorted(crs_on - done):
                skipped.append({'id': rid, 'reason': 'removed_outside'})   # not by a managed rule (crs-setup, plugin...)
        if len(ops) > self.BUNDLE_MAX:
            raise ChangeError('invalid_bundle', 422, limit=self.BUNDLE_MAX)
        return {'ops': ops, 'skipped': skipped[:self.TOGGLE_MAX]}

    def propose_toggle(self, action, rule_ids, scope, reason, actor, via='user', role=None, owner=None, strict=False):
        """toggle_plan as ONE change. strict (a whole category of CRS rules switched off): only an admin may approve,
        with a fresh one-time code and a written reason."""
        plan = self.toggle_plan(action, rule_ids, scope)
        if not plan['ops']:
            raise ChangeError('nothing_to_change', 409, skipped=plan['skipped'][:50])
        cid = self.propose_bundle(plan['ops'], reason, actor, via, role=role, owner=owner)
        if strict:
            r = self.get(cid)
            spec = json.loads(r['spec'])
            spec['strict'] = True
            self.db.x('UPDATE changes SET spec=? WHERE id=?', (json.dumps(spec), cid))
        return cid, plan

    # --- OWASP CRS versions --------------------------------------------------------------------------------------
    def propose_crs(self, mode, version, reason, actor, role=None):
        """Switch the CRS in use to a staged release (install) or to a version on the host (rollback), as a change:
        compared in the sandbox, approved by a person (never automatic), switched by the root program."""
        from . import crsupdate
        if role not in ('approver', 'admin'):
            raise ChangeError('forbidden', 403)
        if mode not in ('install', 'rollback', 'first_install') or not crsupdate.vtuple(str(version or '')):
            raise ChangeError('invalid_crs_request', 422)
        reason = (reason or '').strip()
        if not reason or len(reason) > 2000:
            raise ChangeError('reason_required')
        open_ = self.db.one("SELECT id FROM changes WHERE op='crs' AND state NOT IN (%s)" % ','.join('?' * len(FINAL)), FINAL)
        if open_:
            raise ChangeError('crs_change_pending', 409, change_id=open_[0])
        loc = crsupdate.location(self.app.site)
        if mode == 'first_install':
            # no CRS yet: crs-<version> + a crs link next to the main ModSecurity file, its Includes after modsecurity.conf
            if loc:
                raise ChangeError('crs_in_use', 409)
            _, m = self.app.site.load()
            if not m.main_files:
                raise ChangeError('crs_not_found', 409)
            main = m.main_files[0]
            from .apply import Applier
            with open(main, encoding='utf-8', errors='replace') as fh:
                incs = Applier.includes(main, fh.read())
            anchor = next((p for p in sorted(incs, key=incs.get) if os.path.basename(p) == 'modsecurity.conf'), None)
            crs_path = os.path.join(os.path.dirname(main), 'crs')
            if os.path.lexists(crs_path):
                raise ChangeError('crs_path_exists', 409)
            spec = {'mode': mode, 'to': version, 'from': None, 'crs_path': crs_path, 'main_conf': main, 'anchor': anchor}
        else:
            if not loc or not loc['version']:
                raise ChangeError('crs_not_found', 409)
            if version == loc['version']:
                raise ChangeError('crs_in_use', 409)
            spec = {'mode': mode, 'to': version, 'from': loc['version'], 'crs_path': loc['path']}
        if mode in ('install', 'first_install'):
            staged = crsupdate.read_status(self.cfg).get('staged') or {}
            if staged.get('version') != version or not os.path.isdir(staged.get('path') or ''):
                raise ChangeError('crs_not_staged', 409)
            got = hashlib.sha256(json.dumps(crsupdate.manifest(staged['path']), sort_keys=True).encode()).hexdigest()
            if got != staged.get('manifest_sha256'):
                raise ChangeError('crs_stage_changed', 409)
            spec['staged'] = {k: staged[k] for k in ('path', 'tarball', 'tarball_sha256', 'manifest_sha256')}
            spec['staged']['tarball_path'] = os.path.join(os.path.dirname(staged['path']), staged['tarball'])
        elif version not in loc['versions']:
            raise ChangeError('crs_not_on_host', 409)
        t = util.now()
        with self.db.tx() as c:
            cid = c.execute('INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, created_at, updated_at) '
                            "VALUES ('crs', 'system', ?, 'loosen', 'checking', ?, ?, ?, ?)",
                            (json.dumps(spec), reason, actor, t, t)).lastrowid
        self.log(cid, actor, 'proposed', 'CRS %s -> %s (%s)' % (spec['from'] or 'none', version, mode))
        self.app.audit.log('change.proposed', actor, 'user', None, 'ok', change_id=cid, op='crs', mode=mode,
                           crs_from=spec['from'], crs_to=version)
        self._wake.set()
        return cid

    def _crs_checks(self, cid, r):
        """Static: the staged files are still the verified ones. Sandbox: the same requests through both versions."""
        from . import crsupdate
        spec = json.loads(r['spec'])
        checks = {'started_at': util.iso(util.now())}
        new_dir = spec['staged']['path'] if spec['mode'] != 'rollback' else os.path.join(os.path.dirname(spec['crs_path']),
                                                                                         'crs-%s' % spec['to'])
        if spec['mode'] != 'rollback':
            got = hashlib.sha256(json.dumps(crsupdate.manifest(new_dir), sort_keys=True).encode()).hexdigest() \
                if os.path.isdir(new_dir) else None
            if got != spec['staged']['manifest_sha256']:
                checks['static'] = {'ok': False, 'error': 'crs_stage_changed'}
                self._finish_checks(cid, checks, 'failed', 'the staged CRS files changed')
                return
        elif crsupdate.vstr(crsupdate.installed_version(new_dir)) != spec['to']:
            checks['static'] = {'ok': False, 'error': 'crs_not_on_host'}
            self._finish_checks(cid, checks, 'failed', 'crs-%s is not on the host' % spec['to'])
            return
        checks['static'] = {'ok': True}
        if self.sandbox is not None and self.sandbox.available():
            try:
                if spec['mode'] == 'first_install':
                    sb = self.sandbox.run_crs_first(spec['main_conf'], spec['anchor'], new_dir, self._crs_requests())
                else:
                    sb = self.sandbox.run_crs_compare(spec['crs_path'], new_dir, self._crs_requests())
            except Exception as e:      # noqa: BLE001
                traceback.print_exc()
                sb = {'ok': False, 'error': 'sandbox_error: %s' % type(e).__name__}
        else:
            sb = {'ok': not self.setting('sandbox.required'), 'skipped': 'sandbox not available on this host'}
        checks['sandbox'] = sb
        checks['finished_at'] = util.iso(util.now())
        if not sb.get('ok'):
            self._finish_checks(cid, checks, 'failed', 'sandbox test failed')
            return
        self._finish_checks(cid, checks, 'pending_approval', None)

    def _send_crs(self, cid, r):
        spec = json.loads(r['spec'])
        req = {'request_id': 'crs-c%d' % cid, 'action': 'crs_switch', 'change_id': cid, 'mode': spec['mode'],
               'to': spec['to'], 'crs_path': spec['crs_path'], 'health_urls': self.setting('health.urls'),
               'wait_old_workers': self.setting('apply.wait_old_workers_seconds')}
        if spec['mode'] != 'rollback':
            req.update(tarball=spec['staged']['tarball_path'], tarball_sha256=spec['staged']['tarball_sha256'],
                       manifest_sha256=spec['staged']['manifest_sha256'])
        if spec['mode'] == 'first_install':
            req.update(main_conf=spec['main_conf'], anchor=spec['anchor'])
        self._write_request(req)
        self._state(cid, 'applying')
        self.log(cid, 'system', 'apply_requested', 'CRS %s -> %s' % (spec['from'] or 'none', spec['to']))

    def _handle_crs_result(self, res, r):
        cid = r['id']
        ok = res.get('result') == 'ok'
        summary = str(res.get('summary', ''))[:1000]
        if ok:
            self._state(cid, 'applied')
            self.log(cid, 'system', 'applied', summary)
            spec = json.loads(r['spec'])
            try:
                from . import alerts
                self.db.x("UPDATE alerts SET state='handled', handled_by='system', handled_at=?, note=? "
                          "WHERE kind='crs_update' AND state='open'", (util.now(), 'CRS %s in use (change #%d)' % (spec['to'], cid)))
            except Exception:       # noqa: BLE001
                pass
        else:
            self._state(cid, 'apply_failed', summary)
            self.log(cid, 'system', 'apply_failed', summary)
        self.app.audit.log('change.applied' if ok else 'change.apply_failed', 'system', 'system', None,
                           'ok' if ok else 'failed', severity=None if ok else 'crit', change_id=cid, op='crs',
                           summary=summary[:300])

    def propose_adoption(self, actor):
        if self.managed.adopted():
            raise ChangeError('already_adopted', 409)
        open_ = self.db.one("SELECT id FROM changes WHERE op='adopt' AND state NOT IN (%s)" % ','.join('?' * len(FINAL)), FINAL)
        if open_:
            raise ChangeError('adoption_pending', 409, change_id=open_[0])
        items, sources = self.managed.import_preview()
        plan = self.managed.adopt_plan()
        if not plan:            # neither site rule files nor a main file that loads the CRS rules
            raise ChangeError('nothing_to_import', 409)
        t = util.now()
        with self.db.tx() as c:
            cur = c.execute('INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, created_at, updated_at) '
                            "VALUES ('adopt', 'system', ?, 'neutral', 'checking', ?, ?, ?, ?)",
                            (json.dumps({'sources': sources, 'items': len(items),
                                         'insert': {p: dict(w) for p, w in plan['insert'].items()}}),
                             'Adopt the existing site rule files as jt-waf-mgr managed files', actor, t, t))
            cid = cur.lastrowid
        self.log(cid, actor, 'proposed', 'adoption of %s' % (', '.join(s['path'] for s in sources.values())
                                                           or 'no site rule files (empty managed files next to the CRS rules)'))
        self.app.audit.log('change.proposed', actor, 'user', None, 'ok', change_id=cid, op='adopt')
        self._wake.set()
        return cid

    # --- the item list and files a change produces ----------------------------------------
    def _target_items(self, r):
        spec = json.loads(r['spec'])
        if r['op'] == 'adopt':
            items, _ = self.managed.import_preview()
            return items, None
        if r['op'] == 'bundle':
            items, touched = self.managed.items(include_deleted=True), []
            for b in spec['ops']:
                new = None
                if b['op'] in ('add', 'modify'):
                    _, text, placement = rulegen.build(b['kind'], b['spec'], b['rule_id'], self.cfg)
                    new = {'rule_id': b['rule_id'], 'kind': b['kind'], 'placement': placement, 'spec': b['spec'],
                           'text': text, 'comment': _comment(r), 'origin': 'created'}
                items, it = self.managed.with_op(b['op'], b['item_id'], new, items=items)
                touched.append(it)
            return items, touched
        new = None
        if r['op'] in ('add', 'modify'):
            _, text, placement = rulegen.build(r['kind'], spec, r['rule_id'], self.cfg)
            new = {'rule_id': r['rule_id'], 'kind': r['kind'], 'placement': placement, 'spec': spec, 'text': text,
                   'comment': _comment(r), 'origin': 'created'}
        return self.managed.with_op(r['op'], r['item_id'], new)

    def build_files(self, r, version):
        items, touched = self._target_items(r)
        return items, Managed.render(items, version), touched

    # --- checks ---------------------------------------------------------------------------
    def _crs_requests(self):
        """The requests a CRS switch is compared with, each from an address the site's country rules let through
        (a request every country limit refuses would look the same under both CRS versions)."""
        reqs = self.equivalence_requests()
        return self.sandbox.country_sources(reqs, self.managed.items()) if self.sandbox is not None else reqs

    def run_checks(self, cid):
        r = self.get(cid)
        if r['state'] != 'checking':
            return
        if r['op'] == 'crs':
            return self._crs_checks(cid, r)
        checks = {'started_at': util.iso(util.now())}
        cur = self.managed.current_version()
        base = cur['version'] if cur else 0
        try:
            items, files, _ = self.build_files(r, base + 1)
            # static: every rule of the resulting files passes the expert-mode checks, one rule at a time
            # (the per-rule limits apply to a rule, not to a whole file); a failure names the rule
            for it in items:
                if it.get('deleted') or not it.get('enabled', 1) or it.get('kind') == 'comment' or not (it.get('text') or '').strip():
                    continue
                try:
                    rulegen.check_raw_text(it['text'], cfg=self.cfg)
                except rulegen.SpecError as e:
                    e.details = dict(e.details or {}, rule_id=it.get('rule_id'), placement=it.get('placement'),
                                     excerpt=(it['text'] or '')[:160])
                    raise
            for p, text in files.items():
                if len(text) > 4 * 1024 * 1024:
                    raise ChangeError('file_too_large', file=p)
            ids = [it['rule_id'] for it in items if it.get('rule_id') and not it.get('deleted')]
            dup = sorted({i for i in ids if ids.count(i) > 1})
            if dup:
                raise ChangeError('duplicate_rule_ids', ids=dup)
            old = Managed.render(self.managed.items(include_deleted=True), base) if r['op'] != 'adopt' else {}
            checks['diff'] = _diff(old, files)
            checks['rules_sha256'] = _rules_hash(items)
            checks['static'] = {'ok': True}
        except (rulegen.SpecError, ChangeError, ValueError) as e:
            checks['static'] = {'ok': False, 'error': getattr(e, 'code', str(e)), 'details': getattr(e, 'details', {})}
            self._finish_checks(cid, checks, 'failed', 'static check failed')
            return
        # evidence
        try:
            ev = self.evidence.check(r) if self.evidence else {'ok': True, 'skipped': 'not available'}
        except Exception as e:
            traceback.print_exc()
            ev = {'ok': False, 'error': 'evidence_error: %s' % type(e).__name__}
        checks['evidence'] = ev
        # sandbox
        if self.sandbox is not None and self.sandbox.available():
            try:
                if r['op'] == 'adopt':
                    sb = self.sandbox.run_equivalence(files, self.managed, self.equivalence_requests())
                else:
                    sb = self.sandbox.run_change(r, files, json.loads(r['tests'] or '[]'), self.managed, self.samples(),
                                                 items)
            except Exception as e:
                traceback.print_exc()
                sb = {'ok': False, 'error': 'sandbox_error: %s' % type(e).__name__}
        else:
            sb = {'ok': not self.setting('sandbox.required'), 'skipped': 'sandbox not available on this host'}
        checks['sandbox'] = sb
        checks['finished_at'] = util.iso(util.now())
        if not sb.get('ok'):
            self._finish_checks(cid, checks, 'failed', 'sandbox test failed')
            return
        if not ev.get('ok') and not r['evidence_override']:
            self._finish_checks(cid, checks, 'failed', 'evidence check did not pass; resubmit with a justification to override')
            return
        self.db.x('UPDATE changes SET base_version=? WHERE id=?', (base, cid))
        self._finish_checks(cid, checks, 'pending_approval', None)
        self._maybe_auto_apply(cid)

    def _finish_checks(self, cid, checks, state, error):
        self.db.x('UPDATE changes SET checks=? WHERE id=?', (json.dumps(checks, ensure_ascii=False), cid))
        self._state(cid, state, error)
        self.log(cid, 'system', 'checks_' + ('passed' if state == 'pending_approval' else 'failed'), error or '')
        self.app.audit.log('change.checked', 'system', 'system', None, 'ok' if state == 'pending_approval' else 'error',
                           change_id=cid, state=state)

    def _maybe_auto_apply(self, cid):
        r = self.get(cid)
        analyst = r['proposed_by'] == 'analyst'
        on = self.setting('apply.auto_tighten_analyst' if analyst else 'apply.auto_tighten')
        if r['direction'] != 'tighten' or not on or r['evidence_override']:
            return
        if r['op'] != 'add' or r['kind'] != 'confident_block':
            return
        spec = json.loads(r['spec'])
        if spec.get('target') not in ('path', 'uri', 'ua', 'host', 'header'):
            return
        if (spec.get('source') or 'external') != 'external':     # blocking internal sources always needs a person
            return
        ev = json.loads(r['checks']).get('evidence', {})
        if not ev.get('ok') or ev.get('external_success', 1) or ev.get('internal_other', 1):
            return
        day = datetime.date.today().isoformat()
        n = self.db.one("SELECT COUNT(*) FROM change_log WHERE action='auto_approved' AND date(ts, 'unixepoch', 'localtime')=?",
                        (day,))[0]
        if n >= self.setting('apply.auto_tighten_daily_limit'):
            self.log(cid, 'system', 'auto_apply_skipped', 'daily limit reached')
            return
        self.log(cid, 'system', 'auto_approved', 'tightening, all checks passed')
        self.app.audit.log('change.approved', 'system', 'system', None, 'ok', change_id=cid, auto=True)
        self._queue_apply(cid, 'system')

    def samples(self, limit=400):
        rows = self.db.q('SELECT host, method, path FROM regression_samples ORDER BY pinned DESC, id DESC LIMIT ?', (limit,))
        return [dict(x) for x in rows]

    def equivalence_requests(self, limit=400):
        """Recent distinct requests from the event history (bodies are not logged) plus the samples."""
        rows = self.db.q('SELECT host, method, path, query, origin FROM events WHERE id IN (SELECT MAX(id) FROM events '
                         'GROUP BY host, method, path, origin) ORDER BY id DESC LIMIT ?', (limit,))
        out = [{'host': x['host'], 'method': x['method'] if x['method'] in ('GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE',
                                                                             'PATCH') else 'GET',
                'path': (x['path'] or '/') + ('?' + x['query'] if x['query'] else ''), 'source': x['origin']}
               for x in rows if (x['path'] or '/').startswith('/')]
        out += [dict(s, source='external') for s in self.samples(100)]
        return out

    # --- decisions ------------------------------------------------------------------------
    def approve(self, cid, user, totp=None, note=''):
        r = self.get(cid)
        if r['state'] != 'pending_approval':
            raise ChangeError('invalid_state', 409, state=r['state'])
        if r['op'] == 'adopt' and user['role'] != 'admin':
            raise ChangeError('forbidden', 403)
        # a change proposed through an API token belongs to the person who created that token
        own = (r['proposed_by'] == user['username'] and r['proposed_via'] == 'user') or \
            (r['proposed_via'] == 'api' and r['proposed_owner'] == user['username'])
        if own:
            if not self.setting('approval.single_admin_mode'):
                raise ChangeError('own_change', 403)
            if r['direction'] != 'tighten':
                # single admin approving their own loosening: fresh OTP and a written reason
                from .auth import AuthError
                try:
                    self.app.auth.step_up(user['username'], totp or '', 'change.approve_own')
                except AuthError as e:
                    raise ChangeError(e.code, e.status)
                if len((note or '').strip()) < 10:
                    raise ChangeError('note_required')
        if r['direction'] != 'tighten' and json.loads(r['spec'] or '{}').get('strict'):
            # a whole category of CRS rules switched off: an admin, a fresh one-time code and a written reason
            if user['role'] != 'admin':
                raise ChangeError('admin_required', 403)
            if not own:                     # one's own loosening above already took the code and the reason
                from .auth import AuthError
                try:
                    self.app.auth.step_up(user['username'], totp or '', 'change.approve_category_off')
                except AuthError as e:
                    raise ChangeError(e.code, e.status)
                if len((note or '').strip()) < 10:
                    raise ChangeError('note_required')
        elif r['proposed_by'] == 'analyst' and r['direction'] != 'tighten':
            # loosening suggested by the language model (from request data an outsider can shape): fresh OTP and a
            # written reason, like approving one's own loosening
            from .auth import AuthError
            try:
                self.app.auth.step_up(user['username'], totp or '', 'change.approve_analyst_loosen')
            except AuthError as e:
                raise ChangeError(e.code, e.status)
            if len((note or '').strip()) < 10:
                raise ChangeError('note_required')
        self.log(cid, user['username'], 'approved', note or '')
        self.app.audit.log('change.approved', user['username'], 'user', None, 'ok', change_id=cid,
                           direction=r['direction'], own=own)
        self._queue_apply(cid, user['username'])

    def reject(self, cid, user, note):
        r = self.get(cid)
        if r['state'] not in ('pending_approval',):
            raise ChangeError('invalid_state', 409, state=r['state'])
        if not (note or '').strip():
            raise ChangeError('note_required')
        self._state(cid, 'rejected')
        self.log(cid, user['username'], 'rejected', note)
        self.app.audit.log('change.rejected', user['username'], 'user', None, 'ok', change_id=cid)

    def cancel(self, cid, user):
        r = self.get(cid)
        if r['state'] in FINAL or r['state'] in ('applying', 'approved'):
            raise ChangeError('invalid_state', 409, state=r['state'])
        if r['proposed_by'] != user['username'] and user['role'] != 'admin':
            raise ChangeError('forbidden', 403)
        self._state(cid, 'cancelled')
        self.log(cid, user['username'], 'cancelled')
        self.app.audit.log('change.cancelled', user['username'], 'user', None, 'ok', change_id=cid)

    def recheck(self, cid, user, evidence_override=None):
        r = self.get(cid)
        if r['state'] not in ('failed', 'pending_approval'):
            raise ChangeError('invalid_state', 409, state=r['state'])
        if r['proposed_by'] != user['username'] and user['role'] != 'admin':
            raise ChangeError('forbidden', 403)
        ov = (evidence_override or '').strip() or None
        self.db.x('UPDATE changes SET evidence_override=? WHERE id=?', (ov, cid))
        self._state(cid, 'checking')
        self.log(cid, user['username'], 'recheck', ('evidence override: ' + ov) if ov else '')
        self.app.audit.log('change.recheck', user['username'], 'user', None, 'ok', change_id=cid,
                           evidence_override=ov)
        self._wake.set()

    # --- applying -------------------------------------------------------------------------
    def spool(self):
        d = self.cfg['managed']['spool']
        os.makedirs(d, mode=0o700, exist_ok=True)
        return d

    def _queue_apply(self, cid, actor):
        r = self.get(cid)
        cur = self.managed.current_version()
        base = cur['version'] if cur else 0
        if r['op'] not in ('adopt', 'crs') and (r['base_version'] or 0) != base:   # a CRS switch has no rule files
            # another change was applied meanwhile: check again against the new base
            self._state(cid, 'checking')
            self.log(cid, 'system', 'stale', 'version %s applied since the checks; checking again' % base)
            self._wake.set()
            return
        if self.db.one("SELECT 1 FROM changes WHERE state IN ('approved','applying')"):
            # one apply at a time; the worker picks this up when the other finishes
            self._state(cid, 'approved')
            return
        self._state(cid, 'approved')
        self._send(cid)

    def _next_version(self):
        """Never reuse a number: a failed apply keeps its row in the history."""
        r = self.db.one('SELECT MAX(version) m FROM versions')
        return (r['m'] or 0) + 1

    def _expected_disk(self, cur, files):
        """What the managed files must look like right before an apply: exactly what jt-waf-mgr wrote last
        (the current version's hashes). An edit made any other way is drift and stops the apply."""
        hashes = json.loads(cur['hashes']) if cur else {}
        return {p: hashes.get(p) for p in files}

    def _send(self, cid):
        r = self.get(cid)
        if r['op'] == 'crs':
            return self._send_crs(cid, r)
        cur = self.managed.current_version()
        version = self._next_version()
        if r['op'] != 'adopt':
            disk = self.managed.disk_state()
            if disk['drift']:
                bad = [f['path'] for f in disk['files'].values() if f['drift']]
                self._state(cid, 'apply_failed', 'drift: managed files were changed outside jt-waf-mgr: ' + ', '.join(bad))
                self.log(cid, 'system', 'apply_blocked', 'drift: ' + ', '.join(bad))
                self.app.audit.log('change.apply_blocked_drift', 'system', 'system', None, 'failed', severity='crit',
                                   change_id=cid, files=bad)
                return
        items, files, _ = self.build_files(r, version)
        approved = json.loads(r['checks'] or '{}').get('rules_sha256')
        if r['op'] != 'adopt' and approved and approved != _rules_hash(items):
            # the rules would differ from what was checked and approved (e.g. the known scanners written into a
            # rule were changed in Settings meanwhile): check again, approve again
            self._state(cid, 'checking')
            self.log(cid, 'system', 'stale', 'the rules to apply differ from the checked ones; checking again')
            self._wake.set()
            return
        req = {'request_id': 'v%d-c%d' % (version, cid), 'action': 'apply', 'version': version, 'change_id': cid,
               'dir': self.managed.dir, 'files': files, 'sha256': {p: sha256(t) for p, t in files.items()},
               'expected_disk': ({p: None for p in files} if r['op'] == 'adopt' else self._expected_disk(cur, files)),
               'health_urls': self.setting('health.urls'), 'nginx_bin': self.cfg['paths']['nginx_bin'],
               'wait_old_workers': self.setting('apply.wait_old_workers_seconds')}
        if r['op'] == 'adopt':
            req['adopt'] = self.managed.adopt_plan()
            if not req['adopt']:         # the main file changed since the proposal
                self._state(cid, 'apply_failed', 'adoption: no main ModSecurity file that loads the CRS rules any more')
                self.log(cid, 'system', 'apply_blocked', 'nothing to adopt')
                return
        self._write_version(version, cid, 'adopt' if r['op'] == 'adopt' else 'change', files, items, 'pending')
        self._write_request(req)
        self._state(cid, 'applying')
        self.log(cid, 'system', 'apply_requested', 'version %d' % version)

    def _write_version(self, version, cid, kind, files, items, state):
        self.db.x('INSERT OR REPLACE INTO versions(version, created_at, change_id, kind, files, hashes, state, result) '
                  'VALUES (?,?,?,?,?,?,?,?)',
                  (version, util.now(), cid, kind, json.dumps({'files': files, 'items': _plain(items)}),
                   json.dumps({p: sha256(t) for p, t in files.items()}), state, '{}'))

    def _write_request(self, req):
        d = self.spool()
        tmp = os.path.join(d, '.%s.tmp' % req['request_id'])
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(req, fh, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, os.path.join(d, req['request_id'] + '.req'))

    def rollback(self, version, user, note, overwrite_drift=False):
        """Back to an earlier version. With overwrite_drift (approver, explicit) also the way to put jt-waf-mgr's
        files back after an outside edit, including re-writing the current version."""
        v = self.db.one("SELECT * FROM versions WHERE version=? AND state IN ('applied','superseded')", (version,))
        if not v:
            raise ChangeError('not_found', 404)
        if self.db.one("SELECT 1 FROM changes WHERE state IN ('approved','applying')"):
            raise ChangeError('apply_in_progress', 409)
        if not (note or '').strip():
            raise ChangeError('note_required')
        cur = self.managed.current_version()
        disk = self.managed.disk_state()
        if disk['drift'] and not overwrite_drift:
            raise ChangeError('drift', 409, files=[f['path'] for f in disk['files'].values() if f['drift']])
        if cur and cur['version'] == version and not (overwrite_drift and disk['drift']):
            raise ChangeError('already_current', 409)
        data = json.loads(v['files'])
        new_version = self._next_version()
        t = util.now()
        with self.db.tx() as c:
            cid = c.execute("INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, created_at, updated_at, "
                            "base_version) VALUES ('rollback', 'system', ?, 'neutral', 'applying', ?, ?, ?, ?, ?)",
                            (json.dumps({'to_version': version}), note, user['username'], t, t,
                             cur['version'] if cur else 0)).lastrowid
        files = Managed.render(data['items'], new_version)
        self._write_version(new_version, cid, 'rollback', files, data['items'], 'pending')
        if disk['drift']:
            # the approver chose to overwrite the outside edit: expect the disk as it is now, and record it
            expected = {p: disk['files'][p]['sha256'] for p in files}
            self.app.audit.log('change.drift_overwritten', user['username'], 'user', None, 'ok', severity='crit',
                               to_version=version, files=[f['path'] for f in disk['files'].values() if f['drift']])
        else:
            expected = self._expected_disk(cur, files)
        self._write_request({'request_id': 'v%d-c%d' % (new_version, cid), 'action': 'apply', 'version': new_version,
                             'change_id': cid, 'dir': self.managed.dir, 'files': files,
                             'sha256': {p: sha256(x) for p, x in files.items()},
                             'expected_disk': expected,
                             'health_urls': self.setting('health.urls'), 'nginx_bin': self.cfg['paths']['nginx_bin'],
                             'wait_old_workers': self.setting('apply.wait_old_workers_seconds')})
        self.log(cid, user['username'], 'rollback_requested', 'to version %d: %s' % (version, note))
        self.app.audit.log('change.rollback_requested', user['username'], 'user', None, 'ok', to_version=version)
        return cid

    def collect_results(self):
        d = self.cfg['managed']['spool']
        try:
            names = sorted(n for n in os.listdir(d) if n.endswith('.result'))
        except OSError:
            return
        for n in names:
            path = os.path.join(d, n)
            try:
                with open(path, encoding='utf-8') as fh:
                    res = json.load(fh)
            except (OSError, ValueError):
                continue
            try:
                self._handle_result(res)
            finally:
                for suffix in ('.result', '.req'):
                    try:
                        os.unlink(os.path.join(d, n[:-len('.result')] + suffix))
                    except OSError:
                        pass

    def _handle_result(self, res):
        if res.get('action') == 'blocks':
            if getattr(self.app, 'blocks', None) is not None:
                self.app.blocks.handle_result(res)
            return
        if res.get('action') == 'countries':
            if getattr(self.app, 'countries', None) is not None:
                self.app.countries.handle_result(res)
            return
        version, cid = res.get('version'), res.get('change_id')
        r = self.db.one('SELECT * FROM changes WHERE id=?', (cid,))
        if res.get('action') == 'crs_switch':
            if r and r['op'] == 'crs' and r['state'] == 'applying':
                self._handle_crs_result(res, r)
            return
        v = self.db.one('SELECT * FROM versions WHERE version=?', (version,))
        if not r or not v:
            return
        ok = res.get('result') == 'ok'
        summary = res.get('summary', '')[:1000]
        if ok:
            data = json.loads(v['files'])
            with self.db.tx() as c:
                c.execute("UPDATE versions SET state='superseded' WHERE state='applied'")
                c.execute("UPDATE versions SET state='applied', result=? WHERE version=?", (json.dumps(res), version))
                if r['op'] in ('adopt', 'rollback'):
                    # the item list becomes the version's; rows missing from it stay as tombstones,
                    # so that no rule id is ever handed out again
                    keep = {it['id'] for it in data['items'] if it.get('id')}
                    for row in c.execute('SELECT id FROM managed_rules').fetchall():
                        if row[0] not in keep:
                            c.execute('UPDATE managed_rules SET deleted=1 WHERE id=?', (row[0],))
                    self.managed.save_items(c, data['items'], r['proposed_by'], cid)
                else:
                    # the touched rows, and any row whose position moved (a file renumbered to make room)
                    pos = {x[0]: x[1] for x in c.execute('SELECT id, position FROM managed_rules').fetchall()}
                    touched = [it for it in data['items'] if _touched(it, r) or
                               (it.get('id') in pos and pos[it['id']] != it.get('position'))]
                    self.managed.save_items(c, touched, r['proposed_by'], cid)
                # the snapshot keeps the database ids, so that a later rollback updates rows instead of duplicating them
                rows = [dict(x) for x in c.execute("SELECT * FROM managed_rules ORDER BY CASE placement WHEN 'before' THEN 0 ELSE 1 END, position").fetchall()]
                data['items'] = _plain(rows)
                c.execute('UPDATE versions SET files=? WHERE version=?', (json.dumps(data), version))
                c.execute('UPDATE changes SET state=?, updated_at=?, applied_version=?, error=NULL WHERE id=?',
                          ('applied', util.now(), version, cid))
                if r['op'] == 'rollback':
                    to = json.loads(r['spec'])['to_version']
                    c.execute("UPDATE changes SET state='rolled_back', updated_at=? WHERE state='applied' AND "
                              'applied_version>? AND applied_version<? AND id<>?', (util.now(), to, version, cid))
            if r['op'] == 'adopt':
                self.managed.set_setting('managed.adopted_version', version, r['proposed_by'])
            self.log(cid, 'apply', 'applied', summary)
            self.app.audit.log('change.applied', r['proposed_by'], 'user', None, 'ok', change_id=cid, version=version,
                               direction=r['direction'], kind=r['kind'], op=r['op'], rule_id=r['rule_id'])
            try:
                from .alerts import close_for_change
                close_for_change(self.db, self.app.audit, cid)
            except Exception:       # never let the alert bookkeeping break the apply result
                traceback.print_exc()
        else:
            self.db.x("UPDATE versions SET state='failed', result=? WHERE version=?", (json.dumps(res), version))
            self._state(cid, 'apply_failed', summary or res.get('result'))
            self.log(cid, 'apply', 'apply_failed', summary)
            self.app.audit.log('change.apply_failed', r['proposed_by'], 'user', None, 'error', change_id=cid,
                               version=version, step=res.get('step'))
        self._wake.set()   # the worker sends the next approved change, if any

    # --- worker ---------------------------------------------------------------------------
    def run(self):
        while not self._stop.is_set():
            try:
                self.collect_results()
                for row in self.db.q("SELECT id FROM changes WHERE state='checking' ORDER BY id"):
                    self.run_checks(row[0])
                    # an evidence check can take minutes: take an apply result in between, or the version applied
                    # meanwhile stays "pending" and the managed files look drifted until every check is done
                    self.collect_results()
                    if self._stop.is_set():
                        break
                if not self.db.one("SELECT 1 FROM changes WHERE state='applying'"):
                    nxt = self.db.one("SELECT id FROM changes WHERE state='approved' ORDER BY id LIMIT 1")
                    if nxt:
                        r = self.get(nxt[0])
                        cur = self.managed.current_version()
                        if r['op'] == 'adopt' or (r['base_version'] or 0) == (cur['version'] if cur else 0):
                            self._send(nxt[0])
                        else:
                            self._state(nxt[0], 'checking')
                            self.log(nxt[0], 'system', 'stale', 'checking again against the new version')
            except Exception:
                traceback.print_exc()
            self._wake.wait(2)
            self._wake.clear()

    def stop(self):
        self._stop.set()
        self._wake.set()


def _touched(it, r):
    if r['op'] == 'bundle':
        ops = json.loads(r['spec'])['ops']
        if it.get('id') is None:
            return it.get('rule_id') in {b['rule_id'] for b in ops if b['op'] == 'add'}
        return it.get('id') in {b['item_id'] for b in ops if b['op'] != 'add'}
    if r['op'] == 'add':
        return it.get('id') is None and it.get('rule_id') == r['rule_id']
    return it.get('id') == r['item_id']


def _rules_hash(items):
    """What the rules of a set of items say (order, text, on/off), without the comments and version header."""
    rows = sorted((it for it in items if not it.get('deleted') and it.get('kind') != 'comment'),
                  key=lambda it: (0 if it.get('placement') == 'before' else 1, it.get('position') or 0))
    return sha256('\n\x00'.join('%s|%s|%s' % (it.get('placement'), 1 if it.get('enabled', 1) else 0, (it.get('text') or '').strip())
                                  for it in rows))


def _plain(items):
    keys = ('id', 'rule_id', 'kind', 'placement', 'position', 'spec', 'text', 'comment', 'enabled', 'deleted', 'origin')
    out = []
    for it in items:
        d = {k: it.get(k) for k in keys}
        if isinstance(d['spec'], str):
            d['spec'] = json.loads(d['spec'])
        out.append(d)
    return out


def _comment(r):
    # one line, and no backslash: a trailing one could join the rule's first line to the comment
    reason = ' '.join(r['reason'].replace('\\', '/').split())[:300]
    when = datetime.date.today().isoformat()
    return '# %s jt-waf-mgr change %d (%s): %s' % (when, r['id'], r['proposed_by'], reason.replace('\n', ' '))


def _diff(old, new):
    import difflib
    out = {}
    for p in ('before', 'after'):
        a = (old.get(p) or '').splitlines()
        b = (new.get(p) or '').splitlines()
        # the header (version, time, hash) always differs: compare the rules only
        a = a[4:] if a[:1] and a[0].startswith('# Generated by jt-waf-mgr') else a
        b = b[4:] if b[:1] and b[0].startswith('# Generated by jt-waf-mgr') else b
        d = list(difflib.unified_diff(a, b, 'current/' + p, 'proposed/' + p, n=3, lineterm=''))
        if d:
            out[p] = '\n'.join(d[:4000])
    return out


def _check_tests(tests):
    if not isinstance(tests, list) or len(tests) > 50:
        raise ChangeError('invalid_tests')
    for t in tests:
        if not isinstance(t, dict):
            raise ChangeError('invalid_tests')
        if t.get('expect') not in (200, 403) or t.get('source') not in ('external', 'internal'):
            raise ChangeError('invalid_tests', reason='expect 200|403, source external|internal')
        if not isinstance(t.get('host'), str) or not isinstance(t.get('path'), str) or not t['path'].startswith('/'):
            raise ChangeError('invalid_tests', reason='host and path required')
        if len(t['path']) > 2048 or any(ord(ch) < 32 for ch in t['path'] + t['host']):
            raise ChangeError('invalid_tests', reason='path')
        hdr = t.get('headers') or {}
        if not isinstance(hdr, dict) or len(hdr) > 10 or any(
                not isinstance(k, str) or not isinstance(v, str) or '\n' in k + v or '\r' in k + v for k, v in hdr.items()):
            raise ChangeError('invalid_tests', reason='headers')
        if t.get('src_ip') is not None:
            try:
                a = ipaddress.ip_address(t['src_ip'])
            except (ValueError, TypeError):
                raise ChangeError('invalid_tests', reason='src_ip')
            if t.get('source') != 'external' or not a.is_global:
                raise ChangeError('invalid_tests', reason='src_ip: a public address, with source external')
        if t.get('method', 'GET') not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
            raise ChangeError('invalid_tests', reason='method')
        if len(t.get('body') or '') > 65536:
            raise ChangeError('invalid_tests', reason='body')


def summarize(kind, spec, op):
    if op == 'crs':
        if spec.get('mode') == 'first_install':
            return 'OWASP CRS %s: first installation' % spec.get('to')
        return 'OWASP CRS %s -> %s%s' % (spec.get('from'), spec.get('to'), ' (rollback)' if spec.get('mode') == 'rollback' else '')
    return _summarize(kind, spec, op)


def _summarize(kind, spec, op):
    def scope():
        parts = []
        h, p = spec.get('host') or {}, spec.get('path') or {}
        if h.get('mode') not in (None, 'any'):
            parts.append(h.get('value', ''))
        if p.get('mode') not in (None, 'any'):
            parts.append(('= ' if p['mode'] == 'exact' else '^ ' if p['mode'] == 'prefix' else '~ ') + p.get('value', ''))
        return ' '.join(parts)
    if op == 'adopt':
        return 'adopt %d existing items' % spec.get('items', 0)
    if op == 'rollback':
        return 'restore version %s' % spec.get('to_version')
    if op == 'bundle':
        ops = spec.get('ops') or []
        n = collections.Counter(b['op'] for b in ops)
        ids = ','.join(str(b['rule_id']) for b in ops if b.get('rule_id'))
        return ('%d operations (%s): %s' % (len(ops), ', '.join('%s %d' % kv for kv in sorted(n.items())), ids))[:200]
    if kind == 'confident_block':
        return '%s ~ %s' % (spec.get('target'), spec.get('regex', ''))[:200]
    if kind == 'exclusion':
        what = ','.join(str(i) for i in spec.get('rule_ids') or []) or spec.get('tag') or spec.get('action')
        tg = ','.join(spec.get('targets') or [])
        return ('%s %s %s %s' % (scope(), spec.get('action'), what, tg)).strip()[:200]
    if kind == 'redaction':
        return ('%s %s' % (scope(), ','.join(spec.get('fields') or []))).strip()[:200]
    if kind == 'plugin':
        return '%s %s' % (spec.get('plugin'), (spec.get('host') or {}).get('value', ''))
    return (spec.get('text') or '').split('\n', 1)[0][:200]
