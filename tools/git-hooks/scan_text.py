#!/usr/bin/env python3
"""Shared by the git hooks: refuse text (commit messages, tag messages) that names private hosts,
addresses or mailboxes (the private denylist, see tools/preflight.py) or carries a session link."""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import preflight  # noqa: E402

FORBIDDEN_LINES = (re.compile(r'^Claude-Session:', re.M),)


def problems(text):
    out = []
    for rx in FORBIDDEN_LINES:
        if rx.search(text):
            out.append('contains a "%s" line' % rx.pattern.strip('^:'))
    low = text.lower()
    for d, rx in preflight.load_denylist():
        if rx.search(low):
            out.append('names a private item from the denylist')
    for rx in getattr(preflight, 'GENERIC_TEXT_PATTERNS', ()):
        if rx.search(text):
            out.append('matches %s' % rx.pattern)
    return out


if __name__ == '__main__':
    text = open(sys.argv[1], encoding='utf-8', errors='replace').read() if len(sys.argv) > 1 else sys.stdin.read()
    text = '\n'.join(l for l in text.splitlines() if not l.startswith('#'))
    p = problems(text)
    for x in p:
        print('refused: message %s' % x, file=sys.stderr)
    sys.exit(1 if p else 0)
