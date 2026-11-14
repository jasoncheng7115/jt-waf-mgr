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


_OCTET = r'(?:0{0,2}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))'
# a private address, also at the end of a sentence ("... on 192.168.x.y.") and with a prefix length (a network);
# the generic RFC 1918 blocks themselves (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are documentation, not secrets
PRIVATE_IP = re.compile(
    r'(?<![\w.])((?:192\.168\.' + _OCTET + r'\.' + _OCTET + r'|10\.' + _OCTET + r'\.' + _OCTET + r'\.' + _OCTET +
    r'|172\.(?:1[6-9]|2\d|3[01])\.' + _OCTET + r'\.' + _OCTET + r'))(/\d{1,2})?(?!\w|\.\d)')
GENERIC_PRIVATE_NETS = {'10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'}
# an IPv6 unique local address with a site's own prefix (fd, two hex digits, then more groups); "fc00::/7" and
# "fd00::/8" are documentation
PRIVATE_IP6 = re.compile(r'(?<![\w:])fd[0-9a-f]{2}:[0-9a-f]{1,4}:[0-9a-f:]*', re.I)
MAILBOX = re.compile(r'\b[\w.+-]*[\w+-]@(?!(?:[\w-]+\.)*example\.(?:com|net|org)\b)[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b', re.I)
CO_AUTHOR = 'noreply@anthropic.com'
SECRET = re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|jwm_[a-z0-9]{12}_[A-Za-z0-9_-]{32,}'
                    r'|\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bAKIA[0-9A-Z]{16}\b'
                    r'|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bsk-[A-Za-z0-9_-]{32,}')
# placeholders used by tests and examples (documentation-ish private addresses; 192.168.77.0/24 is the
# test network of this project)
PLACEHOLDER_IPS = {'192.168.77.50', '10.0.0.50', '192.168.0.1', '10.0.0.1', '172.16.0.1', '172.31.255.254', '10.255.255.255',
                   '192.168.77.5'}


def load_denylist(required=False):
    """The private names to keep out. required (the git hooks, the release tool): a missing list is None, so the
    caller refuses instead of publishing with the generic checks only."""
    try:
        with open(DENYLIST) as fh:
            items = [l.strip().lower() for l in fh if l.strip() and not l.startswith('#')]
    except OSError:
        if required:
            return None
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


def scan_text(name, text, deny, allow_marker=True):
    """allow_marker: a line carrying the marker may name a private-looking address or mailbox on purpose (a test of
    these checks); denylisted names, keys and tokens are refused on every line. Messages never honour it."""
    for n, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        for d, rx in deny:
            if rx.search(low):
                fail('privacy', '%s:%d contains a denylisted name (%s…)' % (name, n, d[:3]))
        if SECRET.search(line):
            fail('secret', '%s:%d looks like a private key or token' % (name, n))
        if allow_marker and ALLOW_MARKER in line:
            continue
        for m in PRIVATE_IP.finditer(line):
            addr, prefix = m.group(1), m.group(2)
            if prefix and int(prefix[1:]) > 32:
                continue                            # not a network (a test of a bad prefix length)
            if prefix:
                if addr + prefix not in GENERIC_PRIVATE_NETS and not addr.startswith('192.168.77.'):
                    fail('privacy', '%s:%d private network %s%s' % (name, n, addr, prefix))
            elif addr not in PLACEHOLDER_IPS and not addr.startswith('192.168.77.'):
                fail('privacy', '%s:%d private address %s' % (name, n, addr))
        m6 = PRIVATE_IP6.search(line)
        if m6:
            fail('privacy', '%s:%d private IPv6 address %s' % (name, n, m6.group(0)))
        mb = MAILBOX.search(line.replace(CO_AUTHOR, ''))
        if mb:
            fail('privacy', '%s:%d mailbox %s' % (name, n, mb.group(0)))


def is_text(data):
    return b'\0' not in data[:8192]


def check_privacy(files, deny):
    for rel in files:
        with open(os.path.join(ROOT, rel), 'rb') as fh:
            check_blob(rel, fh.read(), deny)


def _utf16(data):
    """Text in UTF-16 (a byte-order mark, or a zero byte in every other place): decoded, else None."""
    head = data[:4096]
    if head[:2] in (b'\xff\xfe', b'\xfe\xff'):
        enc = 'utf-16'
    elif len(head) >= 8 and head[1::2].count(0) > len(head) // 2 * 0.9:
        enc = 'utf-16-le'
    elif len(head) >= 8 and head[0::2].count(0) > len(head) // 2 * 0.9:
        enc = 'utf-16-be'
    else:
        return None
    try:
        return data.decode(enc)
    except UnicodeDecodeError:
        return None


def check_blob(rel, data, deny):
    """One published file's content (from the working tree, a release or a commit being pushed). Text is scanned
    line by line; screenshots by their metadata; any other binary file (an archive, a database, compiled code)
    cannot be scanned, so it is refused."""
    if rel.startswith('tests/fixtures/') or is_text(data):
        scan_text(rel, data.decode('utf-8', 'replace'), deny)
    elif data.startswith(b'\x89PNG\r\n\x1a\n'):
        check_png(rel, data, deny)
    elif data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        check_webp(rel, data, deny)
    elif _utf16(data) is not None:
        scan_text(rel, _utf16(data), deny)
    else:
        fail('privacy', '%s: a binary file that cannot be checked (only PNG and WebP images are published)' % rel)
        low = data.lower().decode('latin-1')
        for d, rx in deny:
            if rx.search(low):
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


def check_webp(rel, data, deny):
    """WebP thumbnails: like PNG, the image chunks are compressed bytes a short name matches by chance; only the
    metadata chunks can carry text, and a published WebP must not have any."""
    import struct
    i = 12
    while i + 8 <= len(data):
        kind, n = struct.unpack('<4sI', data[i:i + 8])
        if kind in (b'EXIF', b'XMP '):
            fail('privacy', '%s: WebP with a %s chunk (strip metadata from screenshots)' % (rel, kind.decode().strip()))
            scan_text(rel + ':' + kind.decode().strip(), data[i + 8:i + 8 + n].decode('latin-1'), deny)
        elif kind not in (b'VP8 ', b'VP8L', b'VP8X', b'ALPH', b'ICCP', b'ANIM', b'ANMF'):
            fail('privacy', '%s: WebP with an unknown %r chunk' % (rel, kind))
        i += 8 + n + (n & 1)


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
