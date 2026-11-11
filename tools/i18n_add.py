#!/usr/bin/env python3
"""Add or update UI strings in all three dictionaries at once (safe when several people run it).

  tools/i18n_add.py FILE.json      FILE: {"key": {"en": "...", "zh-TW": "...", "ja": "..."}, ...}

zh-TW: Taiwan usage; never the full-width slash. Placeholders ({name}) must match in all three.
"""
import collections
import fcntl
import json
import os
import re
import sys
import tempfile

DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'frontend', 'src', 'i18n')
LANGS = ('en', 'zh-TW', 'ja')


def main(path):
    new = json.load(open(path, encoding='utf-8'))
    for k, v in new.items():
        if set(v) != set(LANGS):
            sys.exit('%s: needs exactly %s' % (k, ', '.join(LANGS)))
        ph = [sorted(re.findall(r'\{(\w+)\}', v[l])) for l in LANGS]
        if ph[0] != ph[1] or ph[0] != ph[2]:
            sys.exit('%s: placeholders differ between languages' % k)
        if '／' in v['zh-TW'] + v['ja']:
            sys.exit('%s: full-width slash; use "/"' % k)
    with open(os.path.join(tempfile.gettempdir(), 'jt-waf-mgr-i18n.lock'), 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for lang in LANGS:
            p = os.path.join(DIR, lang + '.json')
            d = json.load(open(p, encoding='utf-8'), object_pairs_hook=collections.OrderedDict)
            for k, v in new.items():
                d[k] = v[lang]
            tmp = p + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                fh.write(json.dumps(collections.OrderedDict(sorted(d.items())), ensure_ascii=False, indent=1) + '\n')
            os.replace(tmp, p)
    print('added %d keys' % len(new))


if __name__ == '__main__':
    main(sys.argv[1])
