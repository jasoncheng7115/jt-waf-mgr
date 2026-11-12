#!/usr/bin/env python3
"""Release checks. Exits non-zero if anything fails.

  python3 tools/preflight.py            check the working tree (files listed in PUBLISH.txt)
  python3 tools/preflight.py --tar F    also scan a built release tarball

Privacy: published files must not name real hosts, addresses or mailboxes. Generic patterns
are built in; site-specific names come from a private denylist outside the project
(JT_WAF_DENYLIST, default /opt/jt-waf-mgr-internal/denylist.txt), which is never published.
"""
import argparse
import fnmatch
import os
import re
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DENYLIST = os.environ.get('JT_WAF_DENYLIST', '/opt/jt-waf-mgr-internal/denylist.txt')
ALLOW_MARKER = 'preflight' + ':allow'
failures = []


def fail(kind, msg):
    failures.append('[%s] %s' % (kind, msg))


def publish_list():
    pats = []
    with open(os.path.join(ROOT, 'PUBLISH.txt')) as fh:
        for line in fh:
            line = line.split('#', 1)[0].strip()
            if line:
                pats.append(line)
    files = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in ('.git', '__pycache__', 'node_modules', 'dist')]
        for f in filenames:
            rel = os.path.relpath(os.path.join(dirpath, f), ROOT)
            if any(fnmatch.fnmatch(rel, p) or rel.startswith(p.rstrip('/') + '/') for p in pats):
                files.append(rel)
    return sorted(files)


_OCTET = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
PRIVATE_IP = re.compile(
    r'(?<![\w.])(?:192\.168\.' + _OCTET + r'\.' + _OCTET + r'|10\.' + _OCTET + r'\.' + _OCTET + r'\.' + _OCTET +
    r'|172\.(?:1[6-9]|2\d|3[01])\.' + _OCTET + r'\.' + _OCTET + r')(?![\w.]|/\d)')
MAILBOX = re.compile(r'\b[\w.+-]*[\w+-]@(?!(?:[\w-]+\.)*example\.(?:com|net|org)\b)[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b')
SECRET = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|jwm_[a-z0-9]{12}_[A-Za-z0-9_-]{32,}')
# placeholders used by tests and examples (documentation-ish private addresses; 192.168.77.0/24 is the
# test network of this project)
PLACEHOLDER_IPS = {'192.168.77.50', '10.0.0.50', '192.168.0.1', '10.0.0.1', '172.16.0.1', '172.31.255.254', '10.255.255.255',
                   '192.168.77.5'}


def load_denylist():
    try:
        with open(DENYLIST) as fh:
            items = [l.strip().lower() for l in fh if l.strip() and not l.startswith('#')]
    except OSError:
        print('note: no private denylist at %s (generic checks only)' % DENYLIST)
        return []
    out = []
    for d in items:
        # host-like names match as whole words (a short host name must not hit "Log4Shell");
        # entries ending in "." or "@" are prefixes (an address range, a mailbox).
        if d[-1] in '.@':
            rx = re.compile(r'(?<![\w.])' + re.escape(d))
        elif '.' in d:
            # a domain: its subdomains count too (sso.<domain>)
            rx = re.compile(r'(?<![\w-])' + re.escape(d) + r'(?![\w-])')
        else:
            rx = re.compile(r'(?<![\w.-])' + re.escape(d) + r'(?![\w-])')
        out.append((d, rx))
    return out


def scan_text(name, text, deny):
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARKER in line:
            continue
        low = line.lower()
        for d, rx in deny:
            if rx.search(low):
                fail('privacy', '%s:%d contains a denylisted name (%s…)' % (name, n, d[:3]))
        for m in PRIVATE_IP.finditer(line):
            if m.group(0) not in PLACEHOLDER_IPS and not m.group(0).startswith('192.168.77.'):
                fail('privacy', '%s:%d private address %s' % (name, n, m.group(0)))
        if MAILBOX.search(line) and 'noreply@anthropic.com' not in line:
            fail('privacy', '%s:%d mailbox %s' % (name, n, MAILBOX.search(line).group(0)))
        if SECRET.search(line):
            fail('secret', '%s:%d looks like a private key or token' % (name, n))


def is_text(data):
    return b'\0' not in data[:8192]


def check_privacy(files, deny):
    for rel in files:
        with open(os.path.join(ROOT, rel), 'rb') as fh:
            data = fh.read()
        if rel.startswith('tests/fixtures/') or is_text(data):
            scan_text(rel, data.decode('utf-8', 'replace'), deny)
        elif data.startswith(b'\x89PNG\r\n\x1a\n'):
            check_png(rel, data, deny)
        else:
            low = data.lower()
            for d, rx in deny:
                if rx.search(low.decode('latin-1')):
                    fail('privacy', '%s (binary) contains a denylisted name' % rel)


def check_png(rel, data, deny):
    """Screenshots: the pixels are compressed bytes (a short name matches them by chance), so only the chunks that
    can carry text are looked at, and a published PNG must not have any (no tool names, paths or comments)."""
    import struct
    i = 8
    while i + 8 <= len(data):
        n, kind = struct.unpack('>I4s', data[i:i + 8])
        if kind in (b'tEXt', b'iTXt', b'zTXt', b'eXIf'):
            body = data[i + 8:i + 8 + n]
            if kind == b'zTXt':
                import zlib
                try:
                    body = body.split(b'\x00', 1)[0] + b' ' + zlib.decompress(body.split(b'\x00', 1)[1][1:])
                except (zlib.error, IndexError):
                    pass
            fail('privacy', '%s: PNG with a %s chunk (strip metadata from screenshots)' % (rel, kind.decode()))
            scan_text(rel + ':' + kind.decode(), body.decode('latin-1'), deny)
        i += 12 + n


def check_tar(path, deny):
    with tarfile.open(path) as tf:
        names = {m.name.split('/', 1)[-1] for m in tf.getmembers()}
        for need in ('release/MANIFEST.sha256', 'release/MANIFEST.sha256.sig', 'sbom.cdx.json',
                     'deploy/release-key.pem', 'SECURITY.md', 'docs/COMPLIANCE.md'):
            if need not in names:
                fail('tar', '%s missing from the release' % need)
        for m in tf.getmembers():
            if not m.isfile():
                continue
            if any(p in m.name for p in ('internal', '.db', 'CLAUDE.md', '__pycache__', '.pyc')):
                fail('tar', '%s should not be in the release' % m.name)
            data = tf.extractfile(m).read()
            if is_text(data):
                scan_text('tar:' + m.name, data.decode('utf-8', 'replace'), deny)


def check_version():
    sys.path.insert(0, ROOT)
    import jtwafmgr
    v = jtwafmgr.__version__
    if not re.fullmatch(r'\d+\.\d+\.\d+', v):
        fail('version', 'bad version %r' % v)
    for f in ('CHANGELOG.md', 'CHANGELOG_zh-TW.md', 'CHANGELOG_ja.md'):
        p = os.path.join(ROOT, f)
        if os.path.exists(p):
            with open(p) as fh:
                head = fh.read(4000)
            if '## %s' % v not in head and '## v%s' % v not in head:
                fail('version', '%s has no section for %s' % (f, v))
    # the READMEs carry the version in their title and link to each other
    for f in ('README.md', 'README_zh-TW.md', 'README_ja.md'):
        p = os.path.join(ROOT, f)
        if not os.path.exists(p):
            fail('version', '%s is missing (three languages)' % f)
            continue
        with open(p, encoding='utf-8') as fh:
            head = fh.read(600)
        if not head.startswith('# jt-waf-mgr v%s\n' % v):
            fail('version', '%s: the title must be "# jt-waf-mgr v%s"' % (f, v))
        for other in ('README.md', 'README_zh-TW.md', 'README_ja.md'):
            if other != f and '(%s)' % other not in head:
                fail('version', '%s: no language link to %s right under the title' % (f, other))
    return v


def check_frontend():
    idx = os.path.join(ROOT, 'jtwafmgr', 'static', 'index.html')
    if not os.path.exists(idx):
        fail('frontend', 'jtwafmgr/static/index.html missing: run tools/build_frontend.sh')
        return
    with open(idx) as fh:
        html = fh.read()
    if re.search(r'<script(?![^>]*\bsrc=)[^>]*>', html) or '<style' in html or ' style=' in html:
        fail('frontend', 'inline script or style in index.html (CSP forbids it)')
    for src in re.findall(r'(?:src|href)="(/assets/[^"]+)"', html):
        if not os.path.exists(os.path.join(ROOT, 'jtwafmgr', 'static', src.lstrip('/'))):
            fail('frontend', 'index.html references missing %s' % src)
    newest_src = max(os.path.getmtime(os.path.join(d, f)) for d, _, fs in os.walk(os.path.join(ROOT, 'frontend'))
                     for f in fs)
    if newest_src > os.path.getmtime(idx) + 1:
        fail('frontend', 'frontend sources are newer than the build: run tools/build_frontend.sh')
    r = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'check_i18n.py')], capture_output=True, text=True)
    if r.returncode:
        fail('i18n', r.stdout.strip() + r.stderr.strip())


def run_tests():
    r = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-t', '.'], cwd=ROOT,
                       capture_output=True, text=True)
    last = (r.stderr.strip().splitlines() or ['?'])[-1]
    if r.returncode:
        fail('tests', last + '\n' + r.stderr[-3000:])
    return last


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tar')
    ap.add_argument('--no-tests', action='store_true')
    a = ap.parse_args()
    deny = load_denylist()
    v = check_version()
    files = publish_list()
    check_privacy(files, deny)
    check_frontend()
    tests = 'skipped' if a.no_tests else run_tests()
    if a.tar:
        check_tar(a.tar, deny)
    print('jt-waf-mgr %s: %d published files scanned, tests: %s' % (v, len(files), tests))
    if failures:
        print('\nFAILED (%d):' % len(failures))
        for f in failures:
            print('  ' + f)
        return 1
    print('preflight OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
