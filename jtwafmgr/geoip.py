"""GeoIP: country, city and network owner (ASN) of an address, from MaxMind databases (GeoLite2 or GeoIP2).

Reading: a small MaxMind DB (.mmdb) reader in pure Python (standard library only), memory-mapped, with a
bounded cache. Internal addresses (config [network] internal, plus private / loopback / link-local ranges)
are never looked up.

Updating is NOT done by the web service (it has no reason to reach the internet). A separate, sandboxed
one-shot unit (jt-waf-mgr-geoip.service, user jtwaf) runs `jt-waf-mgr geoip-update`:
  - on a daily timer (it downloads only when the files are older than [geoip] update_days), or
  - when an admin asks for it in the UI: the web service only creates geoip/update.request, which a
    systemd path unit turns into a run.
Each download is checked against MaxMind's SHA-256, unpacked in memory (only the one .mmdb member,
size-limited), opened and test-read, and only then moved into place atomically.
"""
import base64
import functools
import hashlib
import io
import ipaddress
import json
import mmap
import os
import re
import struct
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import util

METADATA_MARKER = b'\xab\xcd\xefMaxMind.com'
DOWNLOAD = 'https://download.maxmind.com/geoip/databases/%s/download?suffix=%s'
EDITIONS = ('GeoLite2-City', 'GeoLite2-Country', 'GeoLite2-ASN', 'GeoIP2-City', 'GeoIP2-Country', 'GeoIP2-ISP')
MAX_ARCHIVE = 200 * 1024 * 1024
MAX_MMDB = 400 * 1024 * 1024
REQUEST_FILE = 'update.request'
STATUS_FILE = 'status.json'
ALWAYS_LOCAL = [ipaddress.ip_network(n) for n in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
    '224.0.0.0/4', '240.0.0.0/4', '::1/128', '::/128', 'fc00::/7', 'fe80::/10', 'ff00::/8')]


class MMDBError(ValueError):
    pass


class MMDB:
    """Read-only MaxMind DB reader (format 2.x)."""

    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as fh:
            self.size = os.fstat(fh.fileno()).st_size
            if self.size < 64 or self.size > MAX_MMDB:
                raise MMDBError('bad size')
            self.buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        pos = self.buf.rfind(METADATA_MARKER, max(0, self.size - 128 * 1024))
        if pos < 0:
            raise MMDBError('no metadata')
        meta, _ = self._decode(pos + len(METADATA_MARKER), pos + len(METADATA_MARKER), depth=0)
        if not isinstance(meta, dict) or meta.get('binary_format_major_version') != 2:
            raise MMDBError('unsupported format')
        self.meta = meta
        self.node_count = int(meta['node_count'])
        self.record_size = int(meta['record_size'])
        if self.record_size not in (24, 28, 32):
            raise MMDBError('unsupported record size')
        self.node_bytes = self.record_size // 4
        self.tree_size = self.node_count * self.node_bytes
        self.data_start = self.tree_size + 16
        if self.data_start > pos:
            raise MMDBError('truncated')
        self.ip_version = int(meta['ip_version'])
        self._v4_start = None

    def close(self):
        try:
            self.buf.close()
        except (BufferError, ValueError):
            pass

    @property
    def database_type(self):
        return str(self.meta.get('database_type', ''))

    @property
    def build_epoch(self):
        return int(self.meta.get('build_epoch', 0))

    # --- search tree --------------------------------------------------------------------------
    def _record(self, node, bit):
        off = node * self.node_bytes
        b = self.buf
        if self.record_size == 24:
            o = off + 3 * bit
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if self.record_size == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
            return ((b[off + 3] & 0x0F) << 24) | (b[off + 4] << 16) | (b[off + 5] << 8) | b[off + 6]
        return struct.unpack_from('>I', b, off + 4 * bit)[0]

    def _ipv4_start(self):
        if self._v4_start is None:
            node = 0
            if self.ip_version == 6:
                for _ in range(96):
                    if node >= self.node_count:
                        break
                    node = self._record(node, 0)
            self._v4_start = node
        return self._v4_start

    def lookup(self, ip):
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and self.ip_version == 4:
            return None
        if addr.version == 4:
            node, bits, n = self._ipv4_start(), 32, int(addr)
        else:
            node, bits, n = 0, 128, int(addr)
        for i in range(bits - 1, -1, -1):
            if node >= self.node_count:
                break
            node = self._record(node, (n >> i) & 1)
        if node == self.node_count:
            return None
        if node < self.node_count:
            raise MMDBError('invalid tree')
        off = self.data_start + (node - self.node_count) - 16
        if off < self.data_start or off >= self.size:
            raise MMDBError('bad pointer')
        self._budget = 5000          # decoded nodes per lookup: pointer graphs cannot blow up
        return self._decode(off, self.data_start, depth=0)[0]

    # --- data section -------------------------------------------------------------------------
    _budget = 100000

    def _decode(self, off, base, depth):
        if depth > 32:
            raise MMDBError('too deep')
        self._budget -= 1
        if self._budget < 0:
            raise MMDBError('record too large')
        b = self.buf
        ctrl = b[off]
        off += 1
        typ = ctrl >> 5
        if typ == 1:                                   # pointer
            ss, v = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                p, off = (v << 8) | b[off], off + 1
            elif ss == 1:
                p, off = ((v << 16) | (b[off] << 8) | b[off + 1]) + 2048, off + 2
            elif ss == 2:
                p, off = ((v << 24) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]) + 526336, off + 3
            else:
                p, off = struct.unpack_from('>I', b, off)[0], off + 4
            val, _ = self._decode(base + p, base, depth + 1)
            return val, off
        if typ == 0:                                   # extended type
            typ = 7 + b[off]
            off += 1
        size = ctrl & 0x1F
        if size == 29:
            size, off = 29 + b[off], off + 1
        elif size == 30:
            size, off = 285 + ((b[off] << 8) | b[off + 1]), off + 2
        elif size == 31:
            size, off = 65821 + ((b[off] << 16) | (b[off + 1] << 8) | b[off + 2]), off + 3
        if typ == 2:
            return bytes(b[off:off + size]).decode('utf-8', 'replace'), off + size
        if typ == 3:
            return struct.unpack_from('>d', b, off)[0], off + 8
        if typ == 4:
            return bytes(b[off:off + size]), off + size
        if typ in (5, 6, 9, 10):
            return int.from_bytes(b[off:off + size], 'big'), off + size
        if typ == 7:
            out = {}
            for _ in range(size):
                k, off = self._decode(off, base, depth + 1)
                if not isinstance(k, str):
                    raise MMDBError('map key is not a string')
                v, off = self._decode(off, base, depth + 1)
                out[k] = v
            return out, off
        if typ == 8:
            return int.from_bytes(b[off:off + size], 'big', signed=True) if size else 0, off + size
        if typ == 11:
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base, depth + 1)
                arr.append(v)
            return arr, off
        if typ == 14:
            return bool(size), off
        if typ == 15:
            return struct.unpack_from('>f', b, off)[0], off + 4
        raise MMDBError('unknown type %d' % typ)


def _names(d, lang='en'):
    n = d.get('names') if isinstance(d, dict) else None
    v = (n.get(lang) or n.get('en')) if isinstance(n, dict) else None
    return v if isinstance(v, str) else None


class GeoIP:
    """Lookups for the web service. Re-opens a database when its file changes (after an update)."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.dir = cfg['geoip']['dir']
        self._dbs = {}                    # edition -> (mtime, MMDB)
        self._lock = threading.Lock()
        self._checked = 0.0
        self._cached = functools.lru_cache(maxsize=20000)(self._lookup)

    # Read from the configuration every time: an administrator can change these in the web interface.
    @property
    def enabled(self):
        return bool(self.cfg['geoip'].get('enabled'))

    @property
    def internal(self):
        return getattr(self.cfg, 'internal_networks', [])

    def _path(self, edition):
        return os.path.join(self.dir, edition + '.mmdb')

    def _refresh(self):
        now = time.time()
        if now - self._checked < 30:
            return
        with self._lock:
            self._checked = now
            changed = False
            for ed in self.cfg['geoip']['editions']:
                p = self._path(ed)
                try:
                    mt = os.stat(p).st_mtime
                except OSError:
                    if ed in self._dbs:
                        self._dbs.pop(ed)[1].close()
                        changed = True
                    continue
                cur = self._dbs.get(ed)
                if cur and cur[0] == mt:
                    continue
                try:
                    db = MMDB(p)
                except (OSError, MMDBError, KeyError, ValueError):
                    continue
                if cur:
                    cur[1].close()
                self._dbs[ed] = (mt, db)
                changed = True
            if changed:
                self._cached.cache_clear()

    def available(self):
        self._refresh()
        return bool(self._dbs)

    def is_local(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if any(a in n for n in ALWAYS_LOCAL if n.version == a.version):
            return True
        return util.ip_in(ip, self.internal)

    def lookup(self, ip):
        """{'scope': 'internal'} | {'scope': 'external', 'cc', 'country', 'city', 'asn', 'org'} | None."""
        if not ip:
            return None
        if self.is_local(ip):
            return {'scope': 'internal'}
        if not self.enabled:
            return None
        self._refresh()
        if not self._dbs:
            return None
        return self._cached(str(ipaddress.ip_address(ip)))

    def _lookup(self, ip):
        out = {'scope': 'external', 'cc': None, 'country': None, 'city': None, 'asn': None, 'org': None}
        for ed, (_, db) in list(self._dbs.items()):
            try:
                r = db.lookup(ip)
            except Exception:              # an untrusted file must never break a page
                continue
            if not isinstance(r, dict):
                continue
            if 'autonomous_system_number' in r:
                out['asn'] = r.get('autonomous_system_number')
                out['org'] = r.get('autonomous_system_organization')
            if 'isp' in r and not out['org']:
                out['org'] = r.get('isp')
            c = r.get('country') or r.get('registered_country')
            if isinstance(c, dict) and not out['cc'] and isinstance(c.get('iso_code'), str):
                out['cc'] = c['iso_code'][:2].upper()
                out['country'] = _names(c)
            if isinstance(r.get('city'), dict) and not out['city']:
                out['city'] = _names(r['city'])
        for k in ('org', 'country', 'city'):
            if out[k] is not None and not isinstance(out[k], str):
                out[k] = None
            elif out[k]:
                out[k] = out[k][:200]
        if out['asn'] is not None and not isinstance(out['asn'], int):
            out['asn'] = None
        return out

    def status(self):
        self._refresh()
        st = read_status(self.dir)
        eds = []
        for ed in self.cfg['geoip']['editions']:
            p = self._path(ed)
            info = {'edition': ed, 'present': os.path.exists(p), 'size': None, 'built_at': None, 'database_type': None}
            cur = self._dbs.get(ed)
            if info['present']:
                info['size'] = os.path.getsize(p)
            if cur:
                info['built_at'] = util.iso(cur[1].build_epoch) if cur[1].build_epoch else None
                info['database_type'] = cur[1].database_type
            info['last_error'] = ((st.get('editions') or {}).get(ed) or {}).get('error')
            eds.append(info)
        g = self.cfg['geoip']
        acc, key = credentials(g)
        return {'enabled': self.enabled, 'configured': bool(acc and key),
                'editions': eds, 'update_days': g['update_days'], 'last_run': st.get('finished_at'),
                'last_ok': st.get('ok'), 'requested': os.path.exists(os.path.join(self.dir, REQUEST_FILE))}

    def request_update(self):
        """Called by the web service: the path unit starts the sandboxed updater."""
        os.makedirs(self.dir, mode=0o750, exist_ok=True)
        fd = os.open(os.path.join(self.dir, REQUEST_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        try:
            os.write(fd, util.iso(time.time()).encode())
        finally:
            os.close(fd)


def credentials(g):
    """(account id, license key): from the web interface (written to the GeoIP directory by the service, which
    this restricted updater can read) or, for older installs, from the configuration file."""
    account, key = g.get('account_id') or '', g.get('license_key') or ''
    try:
        with open(os.path.join(g['dir'], 'account.json'), encoding='utf-8') as fh:
            acc = json.load(fh)
        account = account or str(acc.get('account_id') or '')
    except (OSError, ValueError):
        pass
    if not key:
        for path in (os.path.join(g['dir'], 'license.key'), g.get('license_key_file') or ''):
            try:
                with open(path, encoding='utf-8') as fh:
                    key = fh.read().strip()
            except OSError:
                continue
            if key:
                break
    return account, key


def _key_present(path):
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False


def read_status(d):
    try:
        with open(os.path.join(d, STATUS_FILE), encoding='utf-8') as fh:
            v = json.load(fh)
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


# --- updater (runs in jt-waf-mgr-geoip.service, never in the web service) ---------------------------

class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """MaxMind redirects to a pre-signed storage URL: never send the account credentials there."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            if urllib.parse.urlsplit(newurl).scheme != 'https':
                raise urllib.error.HTTPError(newurl, code, 'refusing a non-HTTPS redirect', headers, fp)
            if urllib.parse.urlsplit(newurl).hostname != urllib.parse.urlsplit(req.full_url).hostname:
                new.remove_header('Authorization')
        return new


def _fetch(url, auth, limit, timeout=120):
    opener = urllib.request.build_opener(_NoAuthOnRedirect())
    req = urllib.request.Request(url, headers={'Authorization': 'Basic ' + auth, 'User-Agent': 'jt-waf-mgr geoip-update'})
    with opener.open(req, timeout=timeout) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError('download larger than %d bytes' % limit)
    return data


def _extract(archive, edition):
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tf:
        for m in tf.getmembers():
            base = m.name.rsplit('/', 1)[-1]
            if base == edition + '.mmdb' and m.isreg() and '..' not in m.name.split('/'):
                if m.size > MAX_MMDB:
                    raise ValueError('database larger than allowed')
                fh = tf.extractfile(m)
                return fh.read(MAX_MMDB + 1)
    raise ValueError('archive has no %s.mmdb' % edition)


def update(cfg, force=False, fetch=None, log=print):
    """Download the configured editions when they are older than update_days (or force). Returns the status."""
    g = cfg['geoip']
    d = g['dir']
    os.makedirs(d, mode=0o750, exist_ok=True)
    req = os.path.join(d, REQUEST_FILE)
    if os.path.exists(req):
        force = True
        try:
            os.unlink(req)
        except OSError:
            pass
    st = {'started_at': util.iso(time.time()), 'editions': {}, 'ok': True}
    if not g['enabled']:
        st.update(ok=None, note='disabled')
        return _write_status(d, st)
    account, key = credentials(g)
    if not account or not key:
        st.update(ok=None, note='not configured: set the MaxMind account and license key in Settings')
        return _write_status(d, st)
    auth = base64.b64encode(('%s:%s' % (account, key)).encode()).decode()
    fetch = fetch or _fetch
    for ed in g['editions']:
        target = os.path.join(d, ed + '.mmdb')
        rec = {}
        try:
            if not force and os.path.exists(target) and time.time() - os.path.getmtime(target) < g['update_days'] * 86400:
                rec['skipped'] = 'fresh'
                st['editions'][ed] = rec
                continue
            sha_line = fetch(DOWNLOAD % (ed, 'tar.gz.sha256'), auth, 4096).decode('ascii', 'replace').split()
            if not sha_line or not re.fullmatch(r'[0-9a-f]{64}', sha_line[0]):
                raise ValueError('no SHA-256 from the download site')
            archive = fetch(DOWNLOAD % (ed, 'tar.gz'), auth, MAX_ARCHIVE)
            if hashlib.sha256(archive).hexdigest() != sha_line[0]:
                raise ValueError('SHA-256 mismatch')
            data = _extract(archive, ed)
            tmp = target + '.new'
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            try:
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                db = MMDB(tmp)
                kind, built = db.database_type, db.build_epoch
                db.lookup('1.1.1.1')
                db.close()
                if kind != ed:
                    raise ValueError('unexpected database type %s' % kind[:60])
            except Exception:
                os.unlink(tmp)
                raise
            os.replace(tmp, target)
            rec.update(updated_at=util.iso(time.time()), sha256=sha_line[0], built_at=util.iso(built) if built else None,
                       size=len(data))
            log('%s: updated (%d bytes)' % (ed, len(data)))
        except (OSError, ValueError, urllib.error.URLError, tarfile.TarError, MMDBError) as e:
            rec['error'] = '%s: %s' % (type(e).__name__, str(e)[:200])
            st['ok'] = False
            log('%s: %s' % (ed, rec['error']))
        st['editions'][ed] = rec
    return _write_status(d, st)


def _write_status(d, st):
    st['finished_at'] = util.iso(time.time())
    tmp = os.path.join(d, STATUS_FILE + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(st, fh)
    os.chmod(tmp, 0o640)
    os.replace(tmp, os.path.join(d, STATUS_FILE))
    return st
