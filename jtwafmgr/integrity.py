"""Integrity: the audit trail's hash chain and anchors, the signed program manifest, configuration
fingerprints and the time-sync check.

What each part proves, and what it cannot:

- Audit hash chain: every row stores sha256(previous hash + canonical row). Changing, inserting or
  removing a row in the middle breaks the chain. SQLite has no database roles, so whoever can write
  the database file (root, or the service user) could rewrite the whole chain; that is what the
  anchors are for: every few minutes the newest (id, hash) is appended to an append-only file
  (chattr +a, the service user cannot remove the flag) and sent to syslog / the SIEM. A rewritten or
  truncated chain no longer matches the anchors.
- Program manifest: the release lists the SHA-256 of every file it ships and is signed with the
  project's release key (RSA-3072, PKCS#1 v1.5, SHA-256). The installer pins the key on the first
  install; the service and the root apply program check the installed files against the signed list.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import time

from . import util

# --- canonical form ---------------------------------------------------------------------------

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def file_sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# --- audit hash chain -------------------------------------------------------------------------

AUDIT_FIELDS = ('id', 'ts', 'action', 'actor', 'actor_type', 'src_ip', 'result', 'details')


def new_genesis():
    return secrets.token_hex(32)


def audit_row_hash(prev, row):
    """row: mapping with AUDIT_FIELDS (details as the stored JSON text)."""
    rec = {k: row[k] for k in AUDIT_FIELDS}
    rec['ts'] = repr(float(rec['ts']))
    return sha256_hex(prev + '\n' + canonical(rec))


# The append-only triggers, exactly. verify() compares the stored SQL with these (a trigger with the same
# name but an empty body must not pass).
AUDIT_TRIGGERS = {
    'audit_no_update': "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit "
                       "BEGIN SELECT RAISE(ABORT, 'audit trail is append-only'); END",
    'audit_no_delete': "CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit "
                       "WHEN (SELECT value FROM meta WHERE key='audit_purge_open') IS NOT '1' "
                       "BEGIN SELECT RAISE(ABORT, 'audit trail is append-only'); END",
}


def _norm_sql(s):
    return ' '.join((s or '').split()).lower()


class AuditChain:
    def __init__(self, db):
        self.db = db

    def base(self, c=None):
        """(id of the last purged row or 0, hash the first remaining row must point to)."""
        one = (c.execute if c else self.db.conn().execute)
        rows = dict(one("SELECT key, value FROM meta WHERE key IN ('audit_genesis', 'audit_base_id', 'audit_base_hash')").fetchall())
        if rows.get('audit_base_hash'):
            return int(rows.get('audit_base_id') or 0), rows['audit_base_hash']
        return 0, rows.get('audit_genesis') or ''

    def append(self, ts, action, actor, actor_type, src_ip, result, details):
        """Inserts one chained row; returns (id, hash). Runs in its own transaction."""
        with self.db.tx() as c:
            last = c.execute('SELECT this_hash FROM audit ORDER BY id DESC LIMIT 1').fetchone()
            prev = last[0] if last else self.base(c)[1]
            nid = (c.execute("SELECT seq FROM sqlite_sequence WHERE name='audit'").fetchone() or [0])[0] + 1
            row = {'id': nid, 'ts': ts, 'action': action, 'actor': actor, 'actor_type': actor_type,
                   'src_ip': src_ip, 'result': result, 'details': details}
            h = audit_row_hash(prev, row)
            c.execute('INSERT INTO audit(id, ts, action, actor, actor_type, src_ip, result, details, prev_hash, this_hash) '
                      'VALUES (?,?,?,?,?,?,?,?,?,?)',
                      (nid, ts, action, actor, actor_type, src_ip, result, details, prev, h))
        return nid, h

    def verify(self, after_id=None, expected_prev=None, batch=5000):
        """Walks the chain. Returns a dict: ok, checked, last_id, last_hash, and on failure
        bad_id + reason (prev_mismatch | hash_mismatch | triggers_missing)."""
        out = {'ok': True, 'checked': 0, 'last_id': None, 'last_hash': None, 'bad_id': None, 'reason': None}
        trig = {r[0]: r[1] for r in self.db.q("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'")}
        if any(_norm_sql(trig.get(k)) != _norm_sql(v) for k, v in AUDIT_TRIGGERS.items()):
            out.update(ok=False, reason='triggers_missing')
            return out
        if after_id is None:
            after_id, prev = self.base()
        else:
            prev = expected_prev
        cur = after_id
        while True:
            rows = self.db.q('SELECT * FROM audit WHERE id > ? ORDER BY id LIMIT ?', (cur, batch))
            if not rows:
                break
            for r in rows:
                if r['prev_hash'] != prev:
                    out.update(ok=False, bad_id=r['id'], reason='prev_mismatch')
                    return out
                if not hmac.compare_digest(audit_row_hash(prev, r), r['this_hash'] or ''):
                    out.update(ok=False, bad_id=r['id'], reason='hash_mismatch')
                    return out
                prev = r['this_hash']
                cur = r['id']
                out['checked'] += 1
            out['last_id'], out['last_hash'] = cur, prev
        if out['last_id'] is None:
            out['last_id'], out['last_hash'] = cur, prev
        return out

    def purge_before(self, ts):
        """Retention: removes rows older than ts (a prefix of the chain). The hash of the last removed row
        becomes the chain's base, so the remaining rows still verify. Returns the number removed."""
        with self.db.tx() as c:
            last = c.execute('SELECT id, this_hash FROM audit WHERE ts < ? ORDER BY id DESC LIMIT 1', (ts,)).fetchone()
            if not last:
                return 0
            c.execute("UPDATE meta SET value='1' WHERE key='audit_purge_open'")
            n = c.execute('DELETE FROM audit WHERE id <= ?', (last['id'],)).rowcount
            c.execute("UPDATE meta SET value='0' WHERE key='audit_purge_open'")
            c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('audit_base_id', ?)", (str(last['id']),))
            c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('audit_base_hash', ?)", (last['this_hash'],))
        return n


class Anchors:
    """Append-only JSON lines file: {"at","id","hash","count"}. One line every few minutes."""

    def __init__(self, path):
        self.path = path

    def append(self, audit_id, h, count, base_id=0):
        rec = {'at': util.iso(time.time()), 'id': audit_id, 'hash': h, 'count': count, 'base_id': base_id}
        line = json.dumps(rec, separators=(',', ':')) + '\n'
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)
        return rec

    def read(self, last=None):
        try:
            with open(self.path, encoding='utf-8') as fh:
                lines = fh.readlines()
        except FileNotFoundError:
            return []
        if last:
            lines = lines[-last:]
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except ValueError:
                out.append({'invalid': ln[:200]})
        return out

    def append_only(self):
        """True / False when the append-only flag is known, None when it cannot be read."""
        try:
            r = subprocess.run(['lsattr', '-d', self.path], capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0 or not r.stdout:
            return None
        return 'a' in r.stdout.split()[0]

    def check(self, db, anchors, retention_days=0):
        """Compares anchors with the database. Returns a list of problems (empty = fine).
        Rows below the chain's base were removed by the retention purge — but only rows older than the
        retention period may be gone: an anchor written within it must still find its row (with
        retention 0 = keep forever, nothing may ever be purged)."""
        problems = []
        base_id = int(db.get_meta('audit_base_id', 0) or 0)
        if base_id and not retention_days:
            problems.append({'reason': 'purged_without_retention', 'id': base_id})
        limit = time.time() - (retention_days + 1) * 86400 if retention_days else None
        for a in anchors:
            if 'invalid' in a:
                problems.append({'reason': 'anchor_unreadable'})
                continue
            if a['id'] is None:
                continue
            if a['id'] <= base_id:
                try:
                    at = util.parse_iso(a.get('at') or '')
                except ValueError:
                    at = None
                if limit is not None and at is not None and at < limit:
                    continue  # purged by retention
                problems.append({'reason': 'anchored_row_purged_early', 'id': a['id'], 'at': a.get('at')})
                continue
            r = db.one('SELECT this_hash FROM audit WHERE id=?', (a['id'],))
            if not r:
                problems.append({'reason': 'anchored_row_missing', 'id': a['id'], 'at': a['at']})
            elif r[0] != a['hash']:
                problems.append({'reason': 'anchored_hash_changed', 'id': a['id'], 'at': a['at']})
        return problems


# --- release signature (RSA PKCS#1 v1.5 + SHA-256, verified with the standard library) ---------

class SignatureError(Exception):
    pass


def _der(data, pos):
    tag = data[pos]
    ln = data[pos + 1]
    pos += 2
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + k], 'big')
        pos += k
    return tag, data[pos:pos + ln], pos + ln


def load_public_key(pem):
    """PEM 'PUBLIC KEY' (SubjectPublicKeyInfo, rsaEncryption) -> (n, e)."""
    m = re.search(r'-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----', pem, re.S)
    if not m:
        raise SignatureError('not a PEM public key')
    der = base64.b64decode(''.join(m.group(1).split()))
    tag, spki, _ = _der(der, 0)
    tag, alg, p = _der(spki, 0)
    if b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01' not in alg:
        raise SignatureError('not an RSA key')
    tag, bits, _ = _der(spki, p)
    if tag != 0x03:
        raise SignatureError('bad key')
    tag, seq, _ = _der(bits[1:], 0)
    tag, n, p = _der(seq, 0)
    tag, e, _ = _der(seq, p)
    n, e = int.from_bytes(n, 'big'), int.from_bytes(e, 'big')
    if n.bit_length() < 3072:
        raise SignatureError('key shorter than 3072 bits')
    return n, e


def key_fingerprint(pem):
    """SHA-256 of the DER key, as `openssl pkey -pubin -outform DER | sha256sum` prints it."""
    load_public_key(pem)
    m = re.search(r'-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----', pem, re.S)
    return sha256_hex(base64.b64decode(''.join(m.group(1).split())))


_SHA256_DIGEST_INFO = bytes.fromhex('3031300d060960864801650304020105000420')


def verify_signature(pem, data, sig):
    n, e = load_public_key(pem)
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, 'big'), e, n).to_bytes(k, 'big')
    t = _SHA256_DIGEST_INFO + hashlib.sha256(data).digest()
    expected = b'\x00\x01' + b'\xff' * (k - len(t) - 3) + b'\x00' + t
    return hmac.compare_digest(em, expected)


# --- manifest ---------------------------------------------------------------------------------

MANIFEST = 'MANIFEST.sha256'
_MANIFEST_LINE = re.compile(r'^([0-9a-f]{64})  ([^\0\n]+)$')


def parse_manifest(text):
    out = {}
    for ln in text.splitlines():
        if not ln.strip():
            continue
        m = _MANIFEST_LINE.match(ln)
        if not m or m.group(2).startswith('/') or '..' in m.group(2).split('/'):
            raise SignatureError('malformed manifest line')
        out[m.group(2)] = m.group(1)
    return out


def make_manifest(root, paths):
    """sha256sum-compatible lines for the given relative paths."""
    return ''.join('%s  %s\n' % (file_sha256(os.path.join(root, p)), p) for p in sorted(paths))


def verify_tree(root, manifest, prefixes, ignore_dirs=('__pycache__',), whole=False, allowed_dirs=()):
    """Checks every manifest entry under the given prefixes, and that nothing else exists that Python could
    import. Symbolic links are never accepted (a linked directory would be importable, yet invisible to a
    plain file walk). With whole=True the entire root is walked (an installed program: PYTHONPATH points
    at it, so a planted re.py next to the package would shadow the standard library), only allowed_dirs
    (e.g. release/) may hold other files, and __pycache__ is not ignored (bytecode is never written there;
    a planted .pyc would run instead of the verified source). Returns a result dict."""
    changed, missing, extra = [], [], []
    wanted = {p: h for p, h in manifest.items() if any(p == x or p.startswith(x.rstrip('/') + '/') for x in prefixes)}
    for p, h in sorted(wanted.items()):
        fp = os.path.join(root, p)
        try:
            if os.path.islink(fp):
                changed.append(p + ' (link)')
            elif not hmac.compare_digest(file_sha256(fp), h):
                changed.append(p)
        except FileNotFoundError:
            missing.append(p)
        except OSError:
            missing.append(p)
    bases = [root] if whole else [os.path.join(root, x) for x in prefixes]
    ignore = () if whole else ignore_dirs
    for base in bases:
        if os.path.islink(base):
            extra.append(os.path.relpath(base, root) + ' (link)')
            continue
        if not os.path.isdir(base):
            continue
        for d, dirs, files in os.walk(base):
            keep = []
            for z in dirs:
                rel = os.path.relpath(os.path.join(d, z), root)
                if os.path.islink(os.path.join(d, z)):
                    extra.append(rel + ' (link)')
                elif z in ignore:
                    continue
                elif whole and d == root and z in allowed_dirs:
                    for f2 in os.listdir(os.path.join(d, z)):          # release/: data files only, no links
                        if os.path.islink(os.path.join(d, z, f2)) or not os.path.isfile(os.path.join(d, z, f2)):
                            extra.append(os.path.join(z, f2) + ' (not a plain file)')
                else:
                    keep.append(z)
            dirs[:] = keep
            for f in files:
                rel = os.path.relpath(os.path.join(d, f), root)
                if os.path.islink(os.path.join(d, f)):
                    extra.append(rel + ' (link)')
                elif rel not in manifest:
                    extra.append(rel)
    return {'ok': not (changed or missing or extra), 'checked': len(wanted), 'changed': changed,
            'missing': missing, 'extra': sorted(extra)}


def program_dir():
    """Directory holding the jtwafmgr package (/usr/lib/jt-waf-mgr when installed)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


INSTALLED_PREFIXES = ('jtwafmgr', 'LICENSE')
INSTALL_DIR = '/usr/lib/jt-waf-mgr'
# Files install.sh copies out of the release (release path -> installed path), checked as well.
SYSTEM_FILES = {
    'deploy/jt-waf-mgr.sh': '/usr/bin/jt-waf-mgr',
    'deploy/jt-waf-mgr.service': '/etc/systemd/system/jt-waf-mgr.service',
    'deploy/jt-waf-mgr-apply.service': '/etc/systemd/system/jt-waf-mgr-apply.service',
    'deploy/jt-waf-mgr-apply.path': '/etc/systemd/system/jt-waf-mgr-apply.path',
    'deploy/jt-waf-mgr-geoip.service': '/etc/systemd/system/jt-waf-mgr-geoip.service',
    'deploy/jt-waf-mgr-geoip.timer': '/etc/systemd/system/jt-waf-mgr-geoip.timer',
    'deploy/jt-waf-mgr-geoip.path': '/etc/systemd/system/jt-waf-mgr-geoip.path',
}


def verify_release(src, key_pem):
    """An unpacked release directory: signature over release/MANIFEST.sha256 with the given key, and
    every file of the directory listed with the right hash (nothing missing, nothing extra)."""
    mpath = os.path.join(src, 'release', MANIFEST)
    res = {'dir': src, 'ok': False}
    try:
        with open(mpath, 'rb') as fh:
            raw = fh.read()
        with open(mpath + '.sig', 'rb') as fh:
            sig = fh.read()
    except OSError as e:
        res['reason'] = 'manifest_missing: %s' % e.strerror
        return res
    res['key_fingerprint'] = key_fingerprint(key_pem)
    if not verify_signature(key_pem, raw, sig):
        res['reason'] = 'signature_invalid'
        return res
    manifest = parse_manifest(raw.decode('utf-8'))
    tops = sorted({p.split('/')[0] for p in manifest})
    tree = verify_tree(src, manifest, tops)
    res.update(tree)
    if not tree['ok']:
        res['reason'] = 'files_differ'
    return res


def verify_program(lib=None, key_path='/etc/jt-waf-mgr/release-key.pem'):
    """Checks the installed program against the signed release manifest.
    status: ok | failed | not_installed (running from a source tree, no manifest)."""
    lib = lib or program_dir()
    mpath = os.path.join(lib, 'release', MANIFEST)
    res = {'status': 'not_installed', 'checked_at': util.iso(time.time()), 'dir': lib}
    if not os.path.exists(mpath):
        return res
    try:
        with open(mpath, 'rb') as fh:
            raw = fh.read()
        manifest = parse_manifest(raw.decode('utf-8'))
    except (OSError, UnicodeDecodeError, SignatureError):
        res.update(status='failed', reason='manifest_unreadable')
        return res
    res['manifest_sha256'] = sha256_hex(raw)
    try:
        with open(key_path, encoding='ascii') as fh:
            pem = fh.read()
        with open(mpath + '.sig', 'rb') as fh:
            sig = fh.read()
        res['key_fingerprint'] = key_fingerprint(pem)
        res['signature'] = 'valid' if verify_signature(pem, raw, sig) else 'invalid'
    except FileNotFoundError:
        res['signature'] = 'missing'
    except (OSError, SignatureError, ValueError):
        res['signature'] = 'invalid'
    tree = verify_tree(lib, manifest, INSTALLED_PREFIXES, whole=True, allowed_dirs=('release',))
    if lib == INSTALL_DIR:
        for rel, installed in SYSTEM_FILES.items():
            if rel not in manifest:
                continue
            try:
                if not hmac.compare_digest(file_sha256(installed), manifest[rel]):
                    tree['changed'].append(installed)
            except OSError:
                tree['missing'].append(installed)
        tree['checked'] += len(SYSTEM_FILES)
        tree['ok'] = not (tree['changed'] or tree['missing'] or tree['extra'])
    res.update(tree)
    res['status'] = 'ok' if tree['ok'] and res['signature'] == 'valid' else 'failed'
    if res['status'] == 'failed' and not res.get('reason'):
        res['reason'] = 'signature_%s' % res['signature'] if res['signature'] != 'valid' else 'files_differ'
    return res


# --- configuration fingerprint ----------------------------------------------------------------

def fingerprint(paths):
    """{path: sha256 or None (unreadable)} and an overall digest."""
    files = {}
    for p in sorted(set(paths)):
        try:
            files[p] = file_sha256(p)
        except OSError:
            files[p] = None
    return files, sha256_hex(canonical(files))


def diff_fingerprints(old, new):
    return {'added': sorted(set(new) - set(old)), 'removed': sorted(set(old) - set(new)),
            'changed': sorted(p for p in set(old) & set(new) if old[p] != new[p])}


# --- time synchronisation ---------------------------------------------------------------------

def time_sync():
    """Asks systemd-timedated (works with timesyncd and chrony). Returns synced True/False/None."""
    out = {'synced': None, 'source': None}
    try:
        r = subprocess.run(['timedatectl', 'show', '-p', 'NTPSynchronized', '-p', 'NTP'],
                           capture_output=True, text=True, timeout=10)
        vals = dict(ln.split('=', 1) for ln in r.stdout.splitlines() if '=' in ln) if r.returncode == 0 else {}
        if 'NTPSynchronized' in vals:
            out.update(synced=vals['NTPSynchronized'] == 'yes', ntp_enabled=vals.get('NTP') == 'yes', source='timedatectl')
            return out
    except (OSError, subprocess.SubprocessError):
        pass
    if os.path.exists('/run/systemd/timesync/synchronized'):
        out.update(synced=True, source='timesyncd')
    return out
