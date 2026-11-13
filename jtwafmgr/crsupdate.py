"""OWASP CRS updates, step 1: check, download, verify and stage (nothing in nginx changes here).

Run by jt-waf-mgr-crs.service (user jtwaf, daily timer, or "check now" from the CRS page through a request file):
  1. asks GitHub for the CRS releases;
  2. takes the newest release of the major version in use once it has been out for crs.wait_days (default 7), so
     upstream can fix a bad release first (a new major version is only reported);
  3. downloads its "minimal" tarball and .asc and keeps it only if the signature is valid and made by the pinned
     CRS release key (gpg with a throw-away home; the key ships inside this package, under the release signature);
  4. unpacks it (plain files and directories only) into <crs dir>/stage/crs-<version>, with a manifest;
  5. writes status.json for the web service and opens an alert ("a CRS update is ready").
Switching nginx to a staged version is a change like any other (sandbox comparison, a person approves, the root
apply program switches the crs link): see the CRS page. Does nothing unless crs.manage is on in Settings.
The approach follows jt-crs-update (jt-modsecurity, same author).
"""
import calendar
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request

from . import util

PINNED_FPR = '36006F0E0BA167832158821138EEACA1AB8A6E72'     # OWASP CRS release key (coreruleset.org)
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'crs-signing-key.asc')
API = 'https://api.github.com/repos/coreruleset/coreruleset/releases?per_page=40'
MAX_DOWNLOAD = 20 * 1024 * 1024
MAX_FILES = 2000
MAX_UNPACKED = 80 * 1024 * 1024
ALLOW_HTTP = False          # tests only: asset links on a local http server
STATUS = 'status.json'
REQUEST = 'check.request'


def vtuple(v):
    m = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)', v or '')
    return tuple(int(x) for x in m.groups()) if m else None


def vstr(t):
    return '%d.%d.%d' % tuple(t) if t else None


def installed_version(path):
    """The version a CRS directory holds: the ver:'OWASP_CRS/x.y.z' its rules carry (comments do not count)."""
    rules = os.path.join(path, 'rules')
    seen = {}
    try:
        names = sorted(n for n in os.listdir(rules) if n.endswith('.conf'))
    except OSError:
        return None
    for name in names:
        try:
            with open(os.path.join(rules, name), encoding='utf-8', errors='replace') as fh:
                for v in re.findall(r"ver:'OWASP_CRS/(\d+\.\d+\.\d+)'", fh.read()):
                    seen[v] = seen.get(v, 0) + 1
        except OSError:
            continue
    return vtuple(max(seen, key=seen.get)) if seen else None


def location(site):
    """Where the CRS in use lives: {'path' (the directory main.conf includes), 'link' (is it a symlink),
    'target', 'version', 'versions' (crs-<x.y.z> directories next to it)}; None without a CRS rules Include."""
    _, m = site.load()
    for main in m.main_files:
        try:
            with open(main, encoding='utf-8', errors='replace') as fh:
                text = fh.read()
        except OSError:
            continue
        for line in text.splitlines():
            mm = re.match(r'\s*Include\s+"?([^"\s]+)"?\s*$', line, re.I)
            if not mm:
                continue
            p = mm.group(1) if os.path.isabs(mm.group(1)) else os.path.join(os.path.dirname(main), mm.group(1))
            if re.search(r'/rules/\*\.conf$', p):
                path = os.path.dirname(os.path.dirname(p))
                target = os.path.realpath(path)
                parent, base = os.path.split(path.rstrip('/'))
                versions = {}
                try:
                    for name in os.listdir(parent):
                        vm = re.fullmatch(re.escape(base) + r'-(\d+\.\d+\.\d+)', name)
                        full = os.path.join(parent, name)
                        if vm and os.path.isdir(full) and not os.path.islink(full):
                            versions[vm.group(1)] = full
                except OSError:
                    pass
                return {'path': path, 'link': os.path.islink(path), 'target': target,
                        'version': vstr(installed_version(target)), 'versions': versions}
    return None


def fetch(url, limit, accept='application/octet-stream'):
    req = urllib.request.Request(url, headers={'User-Agent': 'jt-waf-mgr', 'Accept': accept})
    with urllib.request.urlopen(req, timeout=60) as r:       # nosec: https only (the API and its asset links)
        data = r.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError('%s is larger than %d bytes' % (url, limit))
    return data


def releases(api=API):
    """Published, non-prerelease releases: [(version, published epoch, {asset name: url})]."""
    out = []
    for r in json.loads(fetch(api, 5 * 1024 * 1024, 'application/vnd.github+json')):
        v = vtuple(r.get('tag_name', ''))
        if not v or r.get('draft') or r.get('prerelease') or not r.get('published_at'):
            continue
        ts = calendar.timegm(time.strptime(r['published_at'][:19], '%Y-%m-%dT%H:%M:%S'))
        assets = {a['name']: a['browser_download_url'] for a in r.get('assets', [])
                  if isinstance(a.get('browser_download_url'), str)
                  and (a['browser_download_url'].startswith('https://') or ALLOW_HTTP)}
        out.append((v, ts, assets))
    return out


def choose(cur, rels, wait_days, now):
    """('ready' | 'waiting' | 'current', release or None, newest release of a newer major version or None)."""
    same = sorted((r for r in rels if r[0][0] == cur[0] and r[0] > cur), reverse=True)
    major = max((r for r in rels if r[0][0] > cur[0]), default=None)
    if not same:
        return 'current', None, major
    for r in same:                       # the newest release that has waited long enough
        if now - r[1] >= wait_days * 86400:
            return 'ready', r, major
    return 'waiting', same[0], major


def verify(tarball, asc, keyfile=None, fpr=None):
    """True when asc is a valid signature of tarball made by the pinned primary key (or one of its subkeys)."""
    keyfile, fpr = keyfile or KEY_FILE, (fpr or PINNED_FPR).upper()
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        base = ['gpg', '--homedir', home, '--batch', '--no-tty', '--quiet', '--no-autostart']
        imp = subprocess.run(base + ['--import', keyfile], capture_output=True, timeout=60)
        if imp.returncode != 0:
            raise RuntimeError('cannot import the CRS release key')
        res = subprocess.run(base + ['--status-fd', '1', '--verify', asc, tarball], capture_output=True, text=True,
                             timeout=60)
    for line in res.stdout.splitlines():
        f = line.split()
        # [GNUPG:] VALIDSIG <signing key fpr> <date> <ts> <exp> <ver> <res> <pk> <hash> <cls> <primary fpr>
        if len(f) >= 12 and f[1] == 'VALIDSIG' and f[-1].upper() == fpr:
            return res.returncode == 0
    return False


def safe_extract(tarball, dest, top):
    """Unpack plain files and directories under top/ only (no links, devices, absolute paths or ..); limits on the
    number of files and the unpacked size. Returns the unpacked directory."""
    with tarfile.open(tarball, 'r:gz') as tf:
        members = tf.getmembers()
        if len(members) > MAX_FILES:
            raise RuntimeError('too many entries in the tarball')
        total = 0
        for m in members:
            name = m.name[2:] if m.name.startswith('./') else m.name
            if (not (name.rstrip('/') == top or name.startswith(top + '/')) or '..' in m.name.split('/')
                    or os.path.isabs(m.name) or not (m.isfile() or m.isdir())):
                raise RuntimeError('unexpected entry in the tarball: %r' % m.name[:200])
            total += m.size
        if total > MAX_UNPACKED:
            raise RuntimeError('the tarball unpacks to more than %d bytes' % MAX_UNPACKED)
        for m in members:
            target = os.path.join(dest, m.name)
            if m.isdir():
                os.makedirs(target, mode=0o755, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
            src = tf.extractfile(m)
            with open(target, 'wb') as fh:
                shutil.copyfileobj(src, fh)
            os.chmod(target, 0o644)
    return os.path.join(dest, top)


def manifest(path):
    """sha256 of every file under path, relative names sorted: what the root program checks before it installs."""
    out = {}
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for f in sorted(files):
            full = os.path.join(root, f)
            with open(full, 'rb') as fh:
                out[os.path.relpath(full, path)] = hashlib.sha256(fh.read()).hexdigest()
    return out


def status_path(cfg):
    return os.path.join(cfg['crs']['dir'], STATUS)


def read_status(cfg):
    try:
        with open(status_path(cfg), encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _write_status(cfg, st):
    d = cfg['crs']['dir']
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, '.status.tmp')
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(st, fh, indent=1)
    os.replace(tmp, status_path(cfg))


def request_check(cfg):
    """From the web service: ask jt-waf-mgr-crs.service to check now (it runs when the file appears)."""
    d = cfg['crs']['dir']
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, REQUEST), 'w', encoding='utf-8') as fh:
        fh.write(str(int(time.time())))


def external_updater():
    """Another program that updates the CRS on this host (two updaters must not run at once)."""
    for p in ('/etc/cron.d/jt-crs-update', '/usr/local/sbin/jt-crs-update'):
        if os.path.exists(p):
            return p
    return None


def run(app, force=False, log=print, api=API, now=None, keyfile=None, fpr=None):
    """One check. Returns the status written to status.json."""
    cfg = app.cfg
    now = now or time.time()
    d = cfg['crs']['dir']
    os.makedirs(d, mode=0o750, exist_ok=True)
    try:
        os.unlink(os.path.join(d, REQUEST))
    except OSError:
        pass
    st = {'checked_at': util.iso(now), 'managed': bool(cfg['crs']['manage']), 'wait_days': cfg['crs']['wait_days'],
          'external_updater': external_updater()}
    if not cfg['crs']['manage'] and not force:
        st['state'] = 'off'
        _write_status(cfg, st)
        log('crs: managed elsewhere (crs.manage is off)')
        return st
    loc = location(app.site)
    st['location'] = {k: loc[k] for k in ('path', 'link', 'target', 'version')} if loc else None
    if not loc or not loc['version']:
        st.update(state='error', error='no CRS in use found (a main ModSecurity file including <crs>/rules/*.conf)')
        _write_status(cfg, st)
        return st
    cur = vtuple(loc['version'])
    try:
        rels = releases(api)
    except Exception as e:      # noqa: BLE001 -- offline, rate limit, proxy: reported, tried again tomorrow
        st.update(state='error', error='cannot read the CRS releases: %s' % str(e)[:200], installed=loc['version'])
        _write_status(cfg, st)
        log('crs: ' + st['error'])
        return st
    action, rel, major = choose(cur, rels, cfg['crs']['wait_days'], now)
    st.update(installed=loc['version'], state=action, newer_major=vstr(major[0]) if major else None)
    if rel:
        st['candidate'] = {'version': vstr(rel[0]), 'published_at': util.iso(rel[1]),
                           'ready_at': util.iso(rel[1] + cfg['crs']['wait_days'] * 86400)}
    old = read_status(cfg).get('staged')
    if action == 'ready':
        ver = vstr(rel[0])
        stage = os.path.join(d, 'stage')
        if old and old.get('version') == ver and os.path.isdir(old.get('path', '')):
            st['staged'] = old              # already downloaded and verified
        else:
            name = 'coreruleset-%s-minimal.tar.gz' % ver
            if name not in rel[2] or name + '.asc' not in rel[2]:
                st.update(state='error', error='release %s has no %s and .asc' % (ver, name))
                _write_status(cfg, st)
                return st
            with tempfile.TemporaryDirectory(dir=d) as tmp:
                tb, asc = os.path.join(tmp, name), os.path.join(tmp, name + '.asc')
                try:
                    with open(tb, 'wb') as fh:
                        fh.write(fetch(rel[2][name], MAX_DOWNLOAD))
                    with open(asc, 'wb') as fh:
                        fh.write(fetch(rel[2][name + '.asc'], 64 * 1024))
                    good = verify(tb, asc, keyfile, fpr)
                except Exception as e:      # noqa: BLE001
                    st.update(state='error', error='download or verification failed: %s' % str(e)[:200])
                    _write_status(cfg, st)
                    return st
                if not good:
                    st.update(state='error', error='the signature of %s is not valid or not by the CRS release key' % name)
                    app.audit.log('crs.signature_bad', 'crs-update', 'system', None, 'failed', severity='crit', version=ver)
                    _write_status(cfg, st)
                    return st
                with open(tb, 'rb') as fh:
                    tsha = hashlib.sha256(fh.read()).hexdigest()
                shutil.rmtree(stage, ignore_errors=True)
                os.makedirs(stage, mode=0o750)
                try:
                    top = safe_extract(tb, stage, 'coreruleset-%s' % ver)
                    path = os.path.join(stage, 'crs-%s' % ver)
                    os.rename(top, path)
                    shutil.copy(asc, os.path.join(stage, name + '.asc'))
                    shutil.copy(tb, os.path.join(stage, name))
                except Exception as e:      # noqa: BLE001 -- a bad tarball leaves nothing staged
                    shutil.rmtree(stage, ignore_errors=True)
                    st.update(state='error', error=str(e)[:200])
                    _write_status(cfg, st)
                    return st
            got = installed_version(path)
            if vstr(got) != ver:
                st.update(state='error', error='the staged rules say version %s, not %s' % (vstr(got), ver))
                _write_status(cfg, st)
                return st
            files = manifest(path)
            st['staged'] = {'version': ver, 'path': path, 'tarball': name, 'tarball_sha256': tsha,
                            'manifest_sha256': hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
                            'files': len(files), 'verified_at': util.iso(now)}
            app.audit.log('crs.staged', 'crs-update', 'system', None, 'ok', severity='warning', version=ver,
                          installed=loc['version'], tarball_sha256=tsha)
            try:
                from . import alerts
                alerts.raise_alert(app.db, app.audit, 'system', 'crs_update', 'warning', 'crs_update:%s' % ver,
                                   {'version': ver, 'installed': loc['version'],
                                    'reason': 'OWASP CRS %s is downloaded and verified; compare it in the sandbox and '
                                              'approve it on the CRS page' % ver}, link='/crs')
            except Exception:       # noqa: BLE001
                pass
            log('crs: %s staged (installed %s)' % (ver, loc['version']))
    elif old and os.path.isdir(old.get('path', '')) and vtuple(old.get('version')) and vtuple(old['version']) > cur:
        st['staged'] = old
    _write_status(cfg, st)
    return st
