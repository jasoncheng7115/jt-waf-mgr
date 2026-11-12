"""Managed rule files: the only nginx/ModSecurity files jt-waf-mgr writes.

  <managed.dir>/before-crs.conf   loaded before the CRS rules (exclusions, confident blocks, ...)
  <managed.dir>/after-crs.conf    loaded after them (configure-time directives, threshold / fallback rules)

The database holds the items (rules, and comment blocks kept from imported files) in file order;
the files are rendered from it. A rule enters the database only once it is on disk (after a
successful apply), so the database always describes what nginx runs.
"""
import hashlib
import json
import os
import re

from . import __version__, util
from .modsecconf import split_actions, split_args

PLACEMENTS = ('before', 'after')
FILES = {'before': 'before-crs.conf', 'after': 'after-crs.conf'}


def sha256(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def split_items(text):
    """A rules file -> [{'comment', 'text', 'rule_id', 'directive'}], keeping chains together and
    comment blocks (separated from a rule by a blank line) as items of their own."""
    items = []
    comment = []
    lines = text.splitlines()
    i = 0
    pending = None   # item whose last rule had 'chain'

    def flush_comment():
        nonlocal comment
        if comment:
            items.append({'comment': '\n'.join(comment), 'text': '', 'rule_id': None, 'directive': None})
            comment = []

    while i < len(lines):
        raw = lines[i]
        st = raw.strip()
        if not st:
            if pending is None:
                flush_comment()
            i += 1
            continue
        if st.startswith('#'):
            comment.append(raw.rstrip())
            i += 1
            continue
        block = [raw.rstrip()]
        while block[-1].endswith('\\') and i + 1 < len(lines):
            i += 1
            block.append(lines[i].rstrip())
        i += 1
        logical = '\n'.join(l[:-1] if l.endswith('\\') else l for l in block)
        words = split_args(logical)
        d = words[0] if words else ''
        acts = []
        if d == 'SecRule' and len(words) > 3:
            acts = split_actions(words[3])
        elif d == 'SecAction' and len(words) > 1:
            acts = split_actions(words[1])
        chained = any(k == 'chain' for k, _ in acts)
        if pending is not None:
            if comment:
                pending['text'] += '\n' + '\n'.join(comment)
                comment = []
            pending['text'] += '\n' + '\n'.join(block)
            if not chained:
                pending = None
            continue
        rid = None
        for k, v in acts:
            if k == 'id':
                try:
                    rid = int(v.strip("'\""))
                except ValueError:
                    pass
        item = {'comment': '\n'.join(comment), 'text': '\n'.join(block), 'rule_id': rid, 'directive': d}
        comment = []
        items.append(item)
        if chained:
            pending = item
    flush_comment()
    return items


class Managed:
    def __init__(self, db, cfg, site=None):
        self.db = db
        self.cfg = cfg
        self.site = site
        self.dir = cfg['managed']['dir']

    # --- paths and state ------------------------------------------------------------------
    def path(self, placement):
        return os.path.join(self.dir, FILES[placement])

    def adopted(self):
        return self.setting('managed.adopted_version') is not None

    def setting(self, key, default=None):
        r = self.db.one('SELECT value FROM settings WHERE key=?', (key,))
        return json.loads(r[0]) if r else default

    def set_setting(self, key, value, actor=None):
        self.db.x('INSERT OR REPLACE INTO settings(key, value, updated_by, updated_at) VALUES (?,?,?,?)',
                  (key, json.dumps(value), actor, util.now()))

    def current_version(self):
        return self.db.one("SELECT * FROM versions WHERE state='applied' ORDER BY version DESC LIMIT 1")

    def disk_state(self):
        """On-disk hashes of the managed files and whether they still match the last applied version."""
        cur = self.current_version()
        expected = json.loads(cur['hashes']) if cur else {}
        out = {'adopted': self.adopted(), 'files': {}, 'drift': False}
        for p in PLACEMENTS:
            path = self.path(p)
            try:
                with open(path, 'rb') as fh:          # bytes: a newline-only or non-UTF-8 edit is drift too
                    h = hashlib.sha256(fh.read()).hexdigest()
                exists = True
            except OSError:
                h, exists = None, False
            drift = bool(cur) and expected.get(p) != h
            out['files'][p] = {'path': path, 'exists': exists, 'sha256': h, 'expected': expected.get(p), 'drift': drift}
            out['drift'] = out['drift'] or drift
        return out

    # --- items ----------------------------------------------------------------------------
    def items(self, include_deleted=False):
        sql = 'SELECT * FROM managed_rules' + ('' if include_deleted else ' WHERE deleted=0') + " ORDER BY CASE placement WHEN 'before' THEN 0 ELSE 1 END, position"
        return [dict(r) for r in self.db.q(sql)]

    def item(self, item_id):
        r = self.db.one('SELECT * FROM managed_rules WHERE id=?', (item_id,))
        return dict(r) if r else None

    def item_by_rule(self, rule_id):
        r = self.db.one('SELECT * FROM managed_rules WHERE rule_id=?', (rule_id,))
        return dict(r) if r else None

    @staticmethod
    def render(items, version, when=None):
        """items (dicts) -> {'before': text, 'after': text}; disabled and deleted items are left out."""
        out = {}
        for p in PLACEMENTS:
            parts = []
            for it in sorted((x for x in items if x['placement'] == p), key=lambda x: x['position']):
                if it.get('deleted') or not it.get('enabled', 1):
                    continue
                block = '\n'.join(x for x in (it.get('comment') or '', it.get('text') or '') if x)
                if block:
                    parts.append(block)
            body = '\n\n'.join(parts) + '\n'
            head = ('# Generated by jt-waf-mgr %s -- do not edit by hand; make changes in jt-waf-mgr.\n'
                    '# %s, version %d, %s\n'
                    '# sha256 of the rules below: %s\n\n') % (
                __version__, FILES[p], version, util.iso(when or util.now()), sha256(body))
            out[p] = head + body
        return out

    # --- rule ids -------------------------------------------------------------------------
    def occupied_ids(self):
        ids = set()
        if self.site is not None:
            _, m = self.site.load()
            ids.update(r.id for r in m.rules if r.id is not None)
        ids.update(r[0] for r in self.db.q('SELECT rule_id FROM managed_rules WHERE rule_id IS NOT NULL'))
        ids.update(r[0] for r in self.db.q('SELECT rule_id FROM changes WHERE rule_id IS NOT NULL'))
        return ids

    def range_for(self, kind):
        w = self.cfg['waf']
        if kind == 'confident_block':
            return w['confident_range']
        if kind == 'plugin':
            return w['system_range']
        return w['exclusion_range']

    def next_rule_id(self, kind):
        lo, hi = self.range_for(kind)
        used = [i for i in self.occupied_ids() if lo <= i <= hi]
        n = (max(used) + 1) if used else lo   # never reuse an id, not even a deleted one
        if n > hi:
            raise ValueError('id_range_full')
        return n

    # --- import (adoption) ----------------------------------------------------------------
    def detect_import_files(self):
        """The local rule files of the main ModSecurity file: last local Include before the CRS rules,
        first local Include after them (plugins excluded)."""
        b, a = self.cfg['managed']['import_before'], self.cfg['managed']['import_after']
        if b or a:
            return b or None, a or None
        if self.site is None:
            return None, None
        _, m = self.site.load()
        for main in m.main_files:
            try:
                with open(main, encoding='utf-8', errors='replace') as fh:
                    incs = [split_args(l)[1] for l in fh if re.match(r'\s*Include\s+\S', l, re.I)]
            except OSError:
                continue
            incs = [p if os.path.isabs(p) else os.path.join(os.path.dirname(main), p) for p in incs]
            crs = [i for i, p in enumerate(incs) if re.search(r'/rules/\*\.conf$|REQUEST-\d', p)]
            if not crs:
                continue

            def local(p):
                return not re.search(r'/plugins/|crs-setup|modsecurity\.conf$|/rules/|\*', p) and \
                    not p.startswith(self.dir)
            before = [p for p in incs[:crs[0]] if local(p)]
            after = [p for p in incs[crs[-1] + 1:] if local(p)]
            return (before[-1] if before else None), (after[0] if after else None)
        return None, None

    def import_preview(self):
        """Items that adoption would create from the existing local files (not saved)."""
        b, a = self.detect_import_files()
        out = []
        sources = {}
        for placement, path in (('before', b), ('after', a)):
            if not path:
                continue
            with open(path, encoding='utf-8', errors='replace') as fh:
                text = fh.read()
            sources[placement] = {'path': path, 'sha256': sha256(text)}
            for n, it in enumerate(split_items(text)):
                out.append({'placement': placement, 'position': float(n), 'rule_id': it['rule_id'],
                            'kind': 'raw' if it['text'] else 'comment', 'comment': it['comment'], 'text': it['text'],
                            'spec': {'text': it['text'], 'placement': placement, 'imported_from': path},
                            'enabled': 1, 'deleted': 0, 'origin': 'imported'})
        return out, sources

    def save_items(self, c, items, actor, change_id=None):
        """Insert or update items inside a transaction (c = connection)."""
        t = util.now()
        for it in items:
            if it.get('id'):
                c.execute('UPDATE managed_rules SET kind=?, placement=?, position=?, spec=?, text=?, comment=?, enabled=?, '
                          'deleted=?, updated_at=?, change_id=? WHERE id=?',
                          (it['kind'], it['placement'], it['position'], json.dumps(it['spec']), it['text'], it.get('comment', ''),
                           it.get('enabled', 1), it.get('deleted', 0), t, change_id, it['id']))
            else:
                c.execute('INSERT INTO managed_rules(rule_id, kind, placement, position, spec, text, comment, enabled, deleted, '
                          'origin, created_by, created_at, updated_at, change_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                          (it.get('rule_id'), it['kind'], it['placement'], it['position'], json.dumps(it['spec']), it['text'],
                           it.get('comment', ''), it.get('enabled', 1), it.get('deleted', 0), it.get('origin', 'created'),
                           actor, t, t, change_id))

    # --- applying an operation to the item list -------------------------------------------
    def with_op(self, op, item_id=None, new_item=None):
        """Current items with one operation applied (nothing saved). Returns (items, touched item)."""
        items = self.items(include_deleted=True)
        if op == 'add':
            pl = new_item['placement']
            pos = max([x['position'] for x in items if x['placement'] == pl] or [0.0]) + 1.0
            it = dict(new_item, position=pos, enabled=1, deleted=0)
            items.append(it)
            return items, it
        target = next((x for x in items if x['id'] == item_id), None)
        if target is None or target['deleted']:
            raise ValueError('item_not_found')
        if op == 'modify':
            target.update({k: new_item[k] for k in ('kind', 'spec', 'text', 'comment') if k in new_item})
        elif op == 'disable':
            target['enabled'] = 0
        elif op == 'enable':
            target['enabled'] = 1
        elif op == 'delete':
            target['deleted'] = 1
        else:
            raise ValueError('invalid_op')
        return items, target
