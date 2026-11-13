"""Country address lists for per-site country blocks.

Where the lists come from: the five regional Internet registries publish every allocation and assignment, with
its country, in their "delegated" statistics files (public, no account, updated daily). jt-waf-mgr-countries.service
(user jtwaf, the only part that reaches the internet for this) downloads the five files, checks each against the
registry's own MD5 file and against the record counts in the file's summary lines, and only when all five pass,
writes one list per country into <dir>/data (one CIDR per line) plus manifest.json. A registry that fails keeps
the previous data in place for every country (all or nothing: never half a world).

How the lists reach ModSecurity: a country rule (rulegen kind "country") reads one list file with @ipMatchFromFile,
/etc/nginx/modsec/jt-waf-mgr/countries/<SET>.data, where SET is its countries joined by "-" (JP-TW). Only the root
apply program writes there: the web service queues the sets in use (the rules applied and the ones waiting in the
workflow), the root program builds each set from the staged country files, checks every line, tests nginx and
reloads. The registries' data is data, not configuration: refreshing it does not go through the change workflow
(the rules that use it do).

Known limits: registry data says where an address block was registered, not where its user is (a VPN, a cloud
provider's region or a roaming phone can be elsewhere); good enough for "only Taiwan" style limits, not for
attribution.
"""
import bisect
import collections
import hashlib
import ipaddress
import json
import os
import re
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request

from . import util

REGISTRIES = (
    ('apnic', 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest'),
    ('arin', 'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest'),
    ('ripencc', 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest'),
    ('lacnic', 'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest'),
    ('afrinic', 'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest'),
)
MAX_FILE = 64 * 1024 * 1024
MAX_LIST = 16 * 1024 * 1024           # one country's list file (the root program refuses bigger)
CC_RE = re.compile(r'[A-Z]{2}')
SET_RE = re.compile(r'[A-Z]{2}(?:-[A-Z]{2}){0,49}')
MAX_COUNTRIES = 50                    # per rule
MIN_RATIO = 0.8                       # a registry may not shrink below 80 % of its previous record count
REQUEST_FILE = 'update.request'
ENABLED_FILE = 'enabled'              # written by the web service: the updater runs only while country rules are on
STATUS_FILE = 'status.json'
MANIFEST = 'manifest.json'


class DataError(ValueError):
    pass


def set_name(countries):
    """The list file name of a set of countries: sorted, unique, joined by "-"."""
    cc = sorted({str(c).upper() for c in countries or []})
    name = '-'.join(cc)
    if not cc or len(cc) > MAX_COUNTRIES or not SET_RE.fullmatch(name):
        raise DataError('countries: 1-%d two-letter codes' % MAX_COUNTRIES)
    return name


def set_path(cfg, countries):
    return os.path.join(cfg['countries']['rules_dir'], set_name(countries) + '.data')


# --- parsing the registries' files ------------------------------------------------------------------

def parse(text, registry):
    """One delegated file -> ({cc: [networks]}, {'ipv4': records, 'ipv6': records}). Every ipv4 / ipv6 record is
    counted (also the reserved and available ones) and the counts must equal the file's summary lines: a cut or
    damaged download never passes."""
    by_cc = collections.defaultdict(list)
    counts = {'ipv4': 0, 'ipv6': 0}
    summary = {}
    head = False
    for line in text.splitlines():
        if not line or line[0] == '#':
            continue
        f = line.split('|')
        if not head:
            # version line: 2|apnic|20261113|58392|19830613|20261112|+1000
            if len(f) < 4 or not re.fullmatch(r'\d+(?:\.\d+)?', f[0]) or f[1].lower() != registry:
                raise DataError('%s: no version line for this registry' % registry)
            head = True
            continue
        if len(f) >= 6 and f[1] == '*' and f[5].strip() == 'summary':
            if f[2] in counts:
                try:
                    summary[f[2]] = int(f[4])
                except ValueError:
                    raise DataError('%s: bad summary line' % registry)
            continue
        if len(f) < 7 or f[2] not in counts:
            continue
        counts[f[2]] += 1
        cc, start, value, status = f[1].upper(), f[3], f[4], f[6].strip().lower()
        if status not in ('allocated', 'assigned') or not CC_RE.fullmatch(cc) or cc in ('ZZ', 'EU', 'AP'):
            continue
        try:
            if f[2] == 'ipv4':
                n = int(value)
                if not 1 <= n <= 2 ** 24:
                    raise ValueError
                first = ipaddress.IPv4Address(start)
                by_cc[cc].extend(ipaddress.summarize_address_range(first, first + (n - 1)))
            else:
                p = int(value)
                if not 8 <= p <= 128:
                    raise ValueError
                by_cc[cc].append(ipaddress.IPv6Network('%s/%d' % (start, p)))
        except (ValueError, ipaddress.AddressValueError, OverflowError):
            raise DataError('%s: bad %s record %s' % (registry, f[2], util.clip(line, 80)))
    if not head:
        raise DataError('%s: empty file' % registry)
    for k in counts:
        if summary.get(k) != counts[k]:
            raise DataError('%s: %s records %d, summary says %s (cut or damaged download)'
                            % (registry, k, counts[k], summary.get(k)))
    if not counts['ipv4']:
        raise DataError('%s: no ipv4 records' % registry)
    return by_cc, counts


def md5_of(text):
    """The digest from a registry's .md5 file: 'MD5 (file) = <hex>' or '<hex>  file'."""
    m = re.search(r'\b([0-9a-f]{32})\b', text or '', re.I)
    if not m:
        raise DataError('no MD5 in the checksum file')
    return m.group(1).lower()


# --- the updater (jt-waf-mgr-countries.service, never the web service) ------------------------------------

def _fetch(url, limit, timeout=180):
    req = urllib.request.Request(url, headers={'User-Agent': 'jt-waf-mgr countries-update'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if urllib.parse.urlsplit(r.geturl()).scheme != 'https':
            raise DataError('refusing a non-HTTPS redirect')
        data = r.read(limit + 1)
    if len(data) > limit:
        raise DataError('download larger than %d bytes' % limit)
    return data


def update(cfg, force=False, fetch=None, log=print):
    """Download, check and stage the country lists. Runs only while country rules are switched on (the web
    service keeps the "enabled" marker) or when asked (force / the request file). Returns the status."""
    d = cfg['countries']['dir']
    os.makedirs(d, mode=0o750, exist_ok=True)
    req = os.path.join(d, REQUEST_FILE)
    if os.path.exists(req):
        force = True
        try:
            os.unlink(req)
        except OSError:
            pass
    st = {'started_at': util.iso(time.time()), 'registries': {}, 'ok': True}
    if not force and not os.path.exists(os.path.join(d, ENABLED_FILE)):
        st.update(ok=None, note='country blocks are off')
        return _write_status(d, st)
    old = read_manifest(d)
    if not force and old and time.time() - (old.get('generated_epoch') or 0) < cfg['countries']['update_hours'] * 3600 - 600:
        st.update(ok=None, note='fresh')
        return _write_status(d, st)
    fetch = fetch or _fetch
    merged = collections.defaultdict(list)
    for name, url in REGISTRIES:
        rec = {}
        try:
            digest = md5_of(fetch(url + '.md5', 4096).decode('ascii', 'replace'))
            raw = fetch(url, MAX_FILE)
            if hashlib.md5(raw).hexdigest() != digest:
                raise DataError('MD5 mismatch')
            by_cc, counts = parse(raw.decode('ascii', 'replace'), name)
            prev = ((old or {}).get('registries') or {}).get(name) or {}
            if prev.get('ipv4') and counts['ipv4'] < prev['ipv4'] * MIN_RATIO:
                raise DataError('ipv4 records fell from %d to %d' % (prev['ipv4'], counts['ipv4']))
            for cc, nets in by_cc.items():
                merged[cc].extend(nets)
            rec.update(counts, md5=digest, size=len(raw), countries=len(by_cc))
            log('%s: %d ipv4, %d ipv6 records, %d countries' % (name, counts['ipv4'], counts['ipv6'], len(by_cc)))
        except (OSError, ValueError, urllib.error.URLError) as e:
            rec['error'] = '%s: %s' % (type(e).__name__, util.clip(str(e), 200))
            st['ok'] = False
            log('%s: %s' % (name, rec['error']))
        st['registries'][name] = rec
    if not st['ok']:
        st['note'] = 'kept the previous lists: every registry must pass'
        return _write_status(d, st)
    man = _stage(d, merged, st['registries'])
    st['countries'] = len(man['countries'])
    st['manifest_sha256'] = manifest_sha(d)
    log('staged %d countries' % st['countries'])
    return _write_status(d, st)


def _stage(d, merged, registries):
    """Write data.new/<CC>.txt and manifest.json, then swap it for data/ (the previous one is removed)."""
    new, cur, oldd = os.path.join(d, 'data.new'), os.path.join(d, 'data'), os.path.join(d, 'data.old')
    shutil.rmtree(new, ignore_errors=True)
    os.makedirs(new, mode=0o750)
    countries = {}
    for cc in sorted(merged):
        v4 = list(ipaddress.collapse_addresses(n for n in merged[cc] if n.version == 4))
        v6 = list(ipaddress.collapse_addresses(n for n in merged[cc] if n.version == 6))
        body = ''.join('%s\n' % n for n in v4 + v6).encode()
        with open(os.path.join(new, cc + '.txt'), 'wb') as fh:
            fh.write(body)
        countries[cc] = {'v4': len(v4), 'v6': len(v6), 'sha256': hashlib.sha256(body).hexdigest(),
                         'v4_addresses': sum(n.num_addresses for n in v4)}
    man = {'generated_at': util.iso(time.time()), 'generated_epoch': time.time(), 'registries': registries,
           'countries': countries}
    with open(os.path.join(new, MANIFEST), 'w', encoding='utf-8') as fh:
        json.dump(man, fh, indent=0, sort_keys=True)
    for root, dirs, files in os.walk(new):
        for f in files:
            os.chmod(os.path.join(root, f), 0o640)
    shutil.rmtree(oldd, ignore_errors=True)
    if os.path.isdir(cur):
        os.rename(cur, oldd)
    os.rename(new, cur)
    shutil.rmtree(oldd, ignore_errors=True)
    return man


def _write_status(d, st):
    st['finished_at'] = util.iso(time.time())
    tmp = os.path.join(d, STATUS_FILE + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(st, fh)
    os.chmod(tmp, 0o640)
    os.replace(tmp, os.path.join(d, STATUS_FILE))
    return st


# --- reading the staged data (web service, sandbox, root program) -------------------------------------

def read_manifest(d):
    try:
        with open(os.path.join(d, 'data', MANIFEST), encoding='utf-8') as fh:
            v = json.load(fh)
        return v if isinstance(v, dict) and isinstance(v.get('countries'), dict) else None
    except (OSError, ValueError):
        return None


def manifest_sha(d):
    try:
        with open(os.path.join(d, 'data', MANIFEST), 'rb') as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def read_status(d):
    try:
        with open(os.path.join(d, STATUS_FILE), encoding='utf-8') as fh:
            v = json.load(fh)
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def read_country(d, cc, opener=None):
    """The networks of one staged country, every line checked. opener: the root program passes its own
    no-follow reader."""
    if not CC_RE.fullmatch(cc or ''):
        raise DataError('bad country code')
    p = os.path.join(d, 'data', cc + '.txt')
    raw = opener(p, MAX_LIST) if opener else _read(p, MAX_LIST)
    out = []
    for i, line in enumerate(raw.decode('ascii', 'strict').splitlines()):
        if not line:
            continue
        try:
            out.append(ipaddress.ip_network(line, strict=True))
        except ValueError:
            raise DataError('%s line %d: not a network' % (cc, i + 1))
    return out


def _read(p, limit):
    with open(p, 'rb') as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise DataError('%s: too large' % os.path.basename(p))
    return data


def build_set(d, countries, opener=None):
    """The text of one set file: the union of its countries, IPv4 first, collapsed."""
    nets = []
    for cc in sorted({c.upper() for c in countries}):
        nets.extend(read_country(d, cc, opener))
    v4 = ipaddress.collapse_addresses(n for n in nets if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in nets if n.version == 6)
    return ''.join('%s\n' % n for n in list(v4) + list(v6))


class Lookup:
    """Which staged country an address belongs to (sorted ranges and bisect; built once per check)."""

    def __init__(self, d, countries=None):
        man = read_manifest(d) or {'countries': {}}
        ccs = countries or sorted(man['countries'])
        self.starts = {4: [], 6: []}
        rng = {4: [], 6: []}
        for cc in ccs:
            try:
                for n in read_country(d, cc):
                    rng[n.version].append((int(n.network_address), int(n.broadcast_address), cc))
            except (OSError, DataError):
                continue
        for v in (4, 6):
            rng[v].sort()
            self.starts[v] = [r[0] for r in rng[v]]
        self.ranges = rng

    def country(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        v, x = a.version, int(a)
        i = bisect.bisect_right(self.starts[v], x) - 1
        if i >= 0 and self.ranges[v][i][0] <= x <= self.ranges[v][i][1]:
            return self.ranges[v][i][2]
        return None

    def sample(self, cc):
        """One address of a country (for the sandbox tests of a country rule)."""
        for r in self.ranges[4]:
            if r[2] == cc and r[1] > r[0] + 2:
                return str(ipaddress.IPv4Address(r[0] + 1))
        return None


# --- the web service's side ---------------------------------------------------------------------------

META_APPLIED = 'countries.applied'
META_PENDING = 'countries.pending'


class Countries:
    def __init__(self, app):
        self.app = app
        self.cfg = app.cfg
        self.db = app.db

    @property
    def dir(self):
        return self.cfg['countries']['dir']

    def _meta(self, key):
        try:
            return json.loads(self.db.get_meta(key) or 'null')
        except ValueError:
            return None

    def manifest(self):
        return read_manifest(self.dir)

    def available(self):
        man = self.manifest()
        return sorted(man['countries']) if man else []

    def desired_sets(self):
        """The sets the country rules need: applied ones and those waiting in the workflow (their list file must
        exist before nginx -t of their own apply)."""
        sets = set()
        for it in self.app.workflow.managed.items():
            if it['kind'] == 'country' and not it.get('deleted'):
                sp = it['spec'] if isinstance(it['spec'], dict) else json.loads(it['spec'] or '{}')
                if sp.get('countries'):
                    sets.add(set_name(sp['countries']))
        for (op, kind, spec) in self.db.q("SELECT op, kind, spec FROM changes WHERE state IN "
                                          "('checking', 'pending_approval', 'approved', 'applying')"):
            try:
                sp = json.loads(spec or '{}')
            except ValueError:
                continue
            ops = sp.get('ops', []) if op == 'bundle' else [{'kind': kind, 'spec': sp}]
            for o in ops:
                if o.get('kind') == 'country' and (o.get('spec') or {}).get('countries'):
                    try:
                        sets.add(set_name(o['spec']['countries']))
                    except DataError:
                        continue
        return sorted(sets)

    def sync(self, force=False, now=None):
        """Queue the sets for the root program when they or the staged data changed. Returns the request id."""
        now = now or time.time()
        self._marker()
        sha = manifest_sha(self.dir)
        sets = self.desired_sets()
        if not sha:
            return None
        want = hashlib.sha256(json.dumps([sha, sets]).encode()).hexdigest()
        applied = self._meta(META_APPLIED) or {}
        pending = self._meta(META_PENDING)
        if pending and now - pending.get('at', 0) < 600:
            return None
        if not force and applied.get('want') == want and applied.get('ok'):
            return None
        if not force and not applied.get('ok') and now - (applied.get('at') or 0) < 300:
            return None          # a failed write is retried every five minutes, not in a tight loop
        rid = 'countries-%d' % int(now * 1000)
        self.app.workflow._write_request({'request_id': rid, 'action': 'countries',
                                          'sets': {s: s.split('-') for s in sets}, 'manifest_sha256': sha,
                                          'want': want})
        self.db.set_meta(META_PENDING, json.dumps({'request_id': rid, 'want': want, 'at': now}))
        return rid

    def _marker(self):
        """The updater downloads only while country blocks are on and some rule (or a pending one) uses them."""
        p = os.path.join(self.dir, ENABLED_FILE)
        on = bool(self.cfg['countries']['enabled'])
        try:
            if on and not os.path.exists(p):
                os.makedirs(self.dir, mode=0o750, exist_ok=True)
                with open(p, 'w') as fh:
                    fh.write(util.iso(time.time()))
            elif not on and os.path.exists(p):
                os.unlink(p)
        except OSError:
            pass

    def handle_result(self, res):
        pending = self._meta(META_PENDING) or {}
        if pending.get('request_id') and pending['request_id'] != res.get('request_id'):
            return
        ok = res.get('result') == 'ok'
        self.db.set_meta(META_APPLIED, json.dumps({'want': res.get('want') if ok else None, 'at': time.time(), 'ok': ok,
                                                   'sets': res.get('sets'), 'summary': util.clip(str(res.get('summary') or ''), 500)}))
        self.db.set_meta(META_PENDING, 'null')
        self.app.audit.log('countries.applied' if ok else 'countries.apply_failed', 'system', 'system', None,
                           'ok' if ok else 'error', severity=None if ok else 'crit', sets=res.get('sets'),
                           summary=util.clip(str(res.get('summary') or ''), 300))
        if not ok:
            from . import alerts
            alerts.raise_alert(self.db, self.app.audit, 'countries', 'apply_failed', 'critical', 'countries_apply_failed',
                               {'reason': 'the country lists could not be written: %s' % util.clip(str(res.get('summary')), 300)},
                               link='/admin/settings#uiset-countries')

    def request_update(self):
        os.makedirs(self.dir, mode=0o750, exist_ok=True)
        fd = os.open(os.path.join(self.dir, REQUEST_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        try:
            os.write(fd, util.iso(time.time()).encode())
        finally:
            os.close(fd)

    def status(self):
        man = self.manifest() or {}
        st = read_status(self.dir)
        applied = self._meta(META_APPLIED) or {}
        age = time.time() - man['generated_epoch'] if man.get('generated_epoch') else None
        return {'enabled': bool(self.cfg['countries']['enabled']), 'rules_dir': self.cfg['countries']['rules_dir'],
                'generated_at': man.get('generated_at'), 'stale': age is not None and age > self.cfg['countries']['max_age_days'] * 86400,
                'countries': {cc: {'v4': c.get('v4'), 'v6': c.get('v6'), 'v4_addresses': c.get('v4_addresses')}
                              for cc, c in (man.get('countries') or {}).items()},
                'registries': {k: {x: v.get(x) for x in ('ipv4', 'ipv6', 'countries', 'size')}
                               for k, v in (man.get('registries') or {}).items()},
                'last_run': st.get('finished_at'), 'last_ok': st.get('ok'), 'last_note': st.get('note'),
                'last_errors': {k: v['error'] for k, v in (st.get('registries') or {}).items() if v.get('error')},
                'requested': os.path.exists(os.path.join(self.dir, REQUEST_FILE)),
                'sets': self.desired_sets(),
                'applied': {'at': util.iso(applied['at']) if applied.get('at') else None, 'ok': applied.get('ok'),
                            'summary': applied.get('summary')},
                'pending': bool(self._meta(META_PENDING))}

    def run(self, stop, interval=30):
        while not stop.is_set():
            try:
                if self.cfg['countries']['enabled']:
                    self.sync()
                else:
                    self._marker()
            except Exception as e:      # noqa: BLE001
                print('countries: %s' % util.clip(str(e), 300), flush=True)
            stop.wait(interval)
