#!/usr/bin/env python3
"""Shared by the git hooks and the release tool: refuse text (commit messages, tag messages, release notes) that
names private hosts, addresses or mailboxes (the private denylist and the generic checks of tools/preflight.py),
carries a key or token, or a session link."""
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
    deny = preflight.load_denylist(required=True)
    if deny is None:
        return ['cannot be checked: no private denylist (%s); set JT_WAF_DENYLIST to it, or to an empty file'
                % preflight.DENYLIST]
    for d, rx in deny:
        if rx.search(low):
            out.append('names a private item from the denylist')
    # the same generic checks as published files: private addresses (test placeholders aside), mailboxes other
    # than example.com and the co-author line, private keys and tokens
    before = len(preflight.failures)
    preflight.scan_text('message', text, [], allow_marker=False)
    out += [f.split('] ', 1)[-1].replace('message:', 'line ', 1) for f in preflight.failures[before:]]
    del preflight.failures[before:]
    return out


if __name__ == '__main__':
    text = open(sys.argv[1], encoding='utf-8', errors='replace').read() if len(sys.argv) > 1 else sys.stdin.read()
    text = '\n'.join(l for l in text.splitlines() if not l.startswith('#'))
    p = problems(text)
    for x in p:
        print('refused: message %s' % x, file=sys.stderr)
    sys.exit(1 if p else 0)
