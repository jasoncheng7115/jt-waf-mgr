"""DNS check and reverse lookups, run by jt-waf-mgr-dns.service (never by the web service, which does not connect out).

1. Which site names each DNS server knows. The person enters internal DNS servers and external DNS servers (several of
   each). Every site name nginx serves is asked of every server (A, AAAA; a CNAME is followed in the answer). A name the
   internal servers know and no external one does is "internal DNS only": hiding a name is no protection by itself (anyone
   who reaches the server can ask for it), so the pages put that next to who nginx lets in.
   A wildcard record on the external side would make every name look public: a random label of each zone is asked first,
   and a name whose external answer is that wildcard's answer is "wildcard only".
2. The PTR name of outside addresses (from the events and the IP blocks), with a forward check: the name must lead back
   to the address, else it is shown as "not confirmed" (anyone can write any PTR for their own addresses).

The web service writes what to ask into <dir>/targets.json; this job writes <dir>/results.json and <dir>/ptr.json.
Standard library only: a small DNS client over UDP, TCP when the answer is cut.
"""
import ipaddress
import json
import os
import random
import re
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from . import util

A, AAAA, CNAME, PTR = 1, 28, 5, 12
RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}
NAME_RE = re.compile(r'(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.?$', re.I)
TARGETS, RESULTS, PTRS, REQUEST = 'targets.json', 'results.json', 'ptr.json', 'update.request'
MAX_SERVERS, MAX_NAMES, MAX_PTR_PER_RUN = 10, 500, 400
PTR_TTL, PTR_NEG_TTL = 7 * 86400, 86400


class DnsError(Exception):
    pass


def dns_dir(cfg):
    """The job's folder: [dns] dir, else "dns" next to the database (a test's temporary database takes it along, so a
    test never writes into a real system path)."""
    return cfg['dns'].get('dir') or os.path.join(os.path.dirname(cfg['paths']['db']), 'dns')


# addresses that never belong to the outside world (a public DNS answer with one of these leaks an internal address; a
# PTR question about one is never sent out)
INTERNAL_NETS = [ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16',
                                                   '100.64.0.0/10', '0.0.0.0/8', '::1/128', 'fc00::/7', 'fe80::/10', '::/128')]


def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_multicast or any(a.version == n.version and a in n for n in INTERNAL_NETS)


def parse_server(s):
    """'192.0.2.53', '192.0.2.53:5353', '[2001:db8::53]:53', '2001:db8::53' -> (address, port)."""
    s = str(s).strip()
    m = re.fullmatch(r'\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?', s)
    if m:
        host, port = m.group(1), m.group(2)
    elif s.count(':') == 1:
        host, port = s.split(':')
    else:
        host, port = s, None
    addr = ipaddress.ip_address(host)              # a name would need a resolver to find the resolver: addresses only
    port = int(port) if port else 53
    if not 1 <= port <= 65535:
        raise ValueError('port')
    return str(addr), port


# --- the wire format ----------------------------------------------------------------------------------------------
def build_query(name, qtype, qid):
    out = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)        # recursion desired, one question
    for label in name.rstrip('.').split('.'):
        b = label.encode('ascii')
        if not 0 < len(b) < 64:
            raise DnsError('bad name')
        out += bytes([len(b)]) + b
    return out + b'\x00' + struct.pack('>HH', qtype, 1)


def _name(data, off, depth=0):
    labels, jumped, end = [], False, None
    for _ in range(128):
        if off >= len(data):
            raise DnsError('truncated name')
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DnsError('truncated pointer')
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            if ptr >= len(data) or depth > 20:
                raise DnsError('bad pointer')
            off, depth = ptr, depth + 1
            continue
        labels.append(data[off + 1:off + 1 + n].decode('ascii', 'replace'))
        off += 1 + n
    else:
        raise DnsError('name too long')
    return '.'.join(labels).lower(), (end if jumped else off)


def parse_response(data, qid):
    """-> (rcode name, truncated, [(type, value)])"""
    if len(data) < 12:
        raise DnsError('short answer')
    rid, flags, qd, an, _, _ = struct.unpack('>HHHHHH', data[:12])
    if rid != qid or not flags & 0x8000:
        raise DnsError('not our answer')
    off = 12
    for _ in range(qd):
        _, off = _name(data, off)
        off += 4
    out = []
    for _ in range(an):
        _, off = _name(data, off)
        if off + 10 > len(data):
            raise DnsError('truncated record')
        t, _, _, ln = struct.unpack('>HHIH', data[off:off + 10])
        off += 10
        rd = data[off:off + ln]
        if len(rd) != ln:
            raise DnsError('truncated data')
        if t == A and ln == 4:
            out.append((A, str(ipaddress.IPv4Address(rd))))
        elif t == AAAA and ln == 16:
            out.append((AAAA, str(ipaddress.IPv6Address(rd))))
        elif t in (CNAME, PTR):
            out.append((t, _name(data, off)[0]))
        off += ln
    return RCODES.get(flags & 0x0F, str(flags & 0x0F)), bool(flags & 0x0200), out


def query(server, name, qtype, timeout=2.0, tries=2):
    """One question to one server: {'rcode', 'answers': [(type, value)]} or {'error': text}."""
    addr, port = server
    fam = socket.AF_INET6 if ':' in addr else socket.AF_INET
    last = 'no answer'
    for _ in range(tries):
        qid = random.SystemRandom().randrange(1, 65536)
        q = build_query(name, qtype, qid)
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(q, (addr, port))
                for _ in range(5):                       # ignore stray datagrams (another id, another sender)
                    data, src = s.recvfrom(4096)
                    if src[0] != addr:
                        continue
                    try:
                        rcode, tc, ans = parse_response(data, qid)
                    except DnsError:
                        continue
                    break
                else:
                    raise DnsError('no matching answer')
            if tc:
                with socket.create_connection((addr, port), timeout=timeout) as s:
                    s.sendall(struct.pack('>H', len(q)) + q)
                    head = _recv(s, 2)
                    rcode, _, ans = parse_response(_recv(s, struct.unpack('>H', head)[0]), qid)
            return {'rcode': rcode, 'answers': ans}
        except (OSError, DnsError) as e:
            last = 'timeout' if isinstance(e, socket.timeout) else type(e).__name__ if isinstance(e, OSError) else str(e)
    return {'error': last}


def _recv(s, n):
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DnsError('closed')
        buf += chunk
    return buf


def resolve(server, name, timeout=2.0):
    """A and AAAA of a name on one server: {'rcode', 'addrs', 'cname'} or {'error'}."""
    out = {'addrs': [], 'cname': []}
    for qt in (A, AAAA):
        r = query(server, name, qt, timeout)
        if 'error' in r:
            if qt == A:
                return {'error': r['error']}
            continue
        out.setdefault('rcode', r['rcode'])
        for t, v in r['answers']:
            if t in (A, AAAA) and v not in out['addrs']:
                out['addrs'].append(v)
            elif t == CNAME and v not in out['cname']:
                out['cname'].append(v)
    return out


# --- the check ------------------------------------------------------------------------------------------------------
def _zone(name):
    parts = name.split('.')
    return '.'.join(parts[1:]) if len(parts) > 2 else None


def classify(internal, external, wildcard):
    """One name: what the internal and the external servers answered -> 'internal_only' | 'public' | 'wildcard' |
    'not_found' | 'error'."""
    def found(rs):
        return [r for r in rs.values() if r.get('addrs') or r.get('cname')]

    def errors(rs):
        return rs and all('error' in r for r in rs.values())
    if errors(internal) and errors(external):
        return 'error'
    ext = found(external)
    if ext:
        if wildcard and all(sorted(r.get('addrs') or []) == sorted(wildcard.get(srv) or []) and wildcard.get(srv)
                            for srv, r in external.items() if r.get('addrs') or r.get('cname')):
            return 'wildcard'
        return 'public'
    if found(internal):
        return 'internal_only'
    return 'not_found'


def check_names(names, internal, external, timeout=2.0, workers=8):
    """{name: {'internal': {server: result}, 'external': {...}, 'class'}}, and the wildcard answers per zone."""
    isrv = [(s, parse_server(s)) for s in internal][:MAX_SERVERS]
    esrv = [(s, parse_server(s)) for s in external][:MAX_SERVERS]
    jobs = [(n, side, label, srv) for n in names for side, lst in (('internal', isrv), ('external', esrv)) for label, srv in lst]
    zones = sorted({z for z in (_zone(n) for n in names) if z})
    probe = {z: 'jtwaf-%08x.%s' % (random.SystemRandom().getrandbits(32), z) for z in zones}
    wild = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        res = list(pool.map(lambda j: (j, resolve(j[3], j[0], timeout)), jobs))
        wres = list(pool.map(lambda zj: (zj, resolve(zj[1][1], probe[zj[0]], timeout)),
                             [(z, s) for z in zones for s in esrv]))
    for (z, (label, _)), r in wres:
        if r.get('addrs') or r.get('cname'):
            wild.setdefault(z, {})[label] = r.get('addrs') or r.get('cname')
    out = {n: {'internal': {}, 'external': {}} for n in names}
    for (n, side, label, _), r in res:
        out[n][side][label] = r
    for n, d in out.items():
        d['class'] = classify(d['internal'], d['external'], wild.get(_zone(n) or ''))
        # a public answer with a private address: the external DNS tells everyone an internal address
        d['public_private'] = any(is_internal(a) for r in d['external'].values() for a in r.get('addrs') or [])
    return out, wild


def ptr_lookup(ip, servers, timeout=2.0):
    """{'name', 'confirmed'} | {'name': None} (none) | {'error'}: the PTR, then the name forward to see it returns ip."""
    rev = ipaddress.ip_address(ip).reverse_pointer
    last = None
    for label, srv in servers:
        r = query(srv, rev, PTR, timeout)
        if 'error' in r:
            last = r['error']
            continue
        names = [v for t, v in r['answers'] if t == PTR]
        if not names:
            return {'name': None, 'rcode': r['rcode']}
        name = names[0]
        f = resolve(srv, name, timeout) if NAME_RE.match(name) else {}
        return {'name': name, 'confirmed': ip in (f.get('addrs') or [])}
    return {'error': last or 'no server'}


def system_resolvers(path='/etc/resolv.conf'):
    out = []
    try:
        with open(path) as fh:
            for line in fh:
                p = line.split()
                if len(p) >= 2 and p[0] == 'nameserver':
                    try:
                        out.append(str(ipaddress.ip_address(p[1].split('%')[0])))
                    except ValueError:
                        continue
    except OSError:
        pass
    return out


# --- the job --------------------------------------------------------------------------------------------------------
def _read(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _write(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, ensure_ascii=False)
    os.replace(tmp, path)


def valid_targets(t):
    """The web service's request, checked again here: addresses for servers, plain names, public addresses for PTR."""
    out = {'check_hours': 24, 'internal': [], 'external': [], 'names': [], 'ptr': False, 'ptr_servers': [], 'ips': []}
    if not isinstance(t, dict):
        return out
    for side in ('internal', 'external', 'ptr_servers'):
        for s in (t.get(side) or [])[:MAX_SERVERS]:
            try:
                parse_server(s)
                out[side].append(str(s))
            except (ValueError, TypeError):
                continue
    out['names'] = sorted({str(n).lower().rstrip('.') for n in (t.get('names') or []) if isinstance(n, str) and NAME_RE.match(n)})[:MAX_NAMES]
    out['ptr'] = bool(t.get('ptr'))
    ips = []
    for x in (t.get('ips') or [])[:5000]:
        try:
            a = ipaddress.ip_address(str(x))
        except ValueError:
            continue
        if not is_internal(str(a)):
            ips.append(str(a))
    out['ips'] = ips
    try:
        out['check_hours'] = max(1, min(168, int(t.get('check_hours') or 24)))
    except (TypeError, ValueError):
        pass
    return out


def run(d, now=None, log=print, timeout=2.0):
    """One run of the job: the names check when due (or asked for), then PTR for addresses not in the cache yet."""
    now = now or time.time()
    t = valid_targets(_read(os.path.join(d, TARGETS), {}))
    asked = os.path.exists(os.path.join(d, REQUEST))
    st = {'ran_at': util.iso(now)}
    prev = _read(os.path.join(d, RESULTS), {})
    due = not prev.get('checked_epoch') or now - prev['checked_epoch'] >= t['check_hours'] * 3600
    if t['names'] and (t['internal'] or t['external']) and (due or asked):
        names, wild = check_names(t['names'], t['internal'], t['external'], timeout)
        _write(os.path.join(d, RESULTS), {'checked_at': util.iso(now), 'checked_epoch': now, 'internal': t['internal'],
                                          'external': t['external'], 'wildcards': wild, 'names': names})
        st['names'] = len(names)
        log('dns check: %d names, %d internal and %d external servers' % (len(names), len(t['internal']), len(t['external'])))
    if t['ptr'] and t['ips']:
        servers = [(s, parse_server(s)) for s in (t['ptr_servers'] or t['internal'] or system_resolvers())][:MAX_SERVERS]
        cache = _read(os.path.join(d, PTRS), {})
        todo = [ip for ip in t['ips'] if ip not in cache or now - cache[ip].get('at', 0) >= (
            PTR_TTL if cache[ip].get('name') else PTR_NEG_TTL)][:MAX_PTR_PER_RUN]
        if servers and todo:
            with ThreadPoolExecutor(max_workers=8) as pool:
                for ip, r in zip(todo, pool.map(lambda ip: ptr_lookup(ip, servers, timeout), todo)):
                    cache[ip] = dict(r, at=now)
            # keep the cache bounded: the newest 20000 lookups
            if len(cache) > 20000:
                cache = dict(sorted(cache.items(), key=lambda kv: -kv[1].get('at', 0))[:20000])
            _write(os.path.join(d, PTRS), cache)
        st['ptr'] = len(todo)
        log('ptr: %d looked up, %d in the cache' % (len(todo), len(cache)))
    try:
        os.unlink(os.path.join(d, REQUEST))
    except OSError:
        pass
    _write(os.path.join(d, 'status.json'), dict(st, ok=True))
    return st


# --- the web service's side -------------------------------------------------------------------------------------------
class Dns:
    """Writes what the job should ask (site names, servers, outside addresses) and reads what it found."""

    def __init__(self, app):
        self.app = app
        self.cfg = app.cfg
        self.db = app.db
        self._cache = {}                 # file name -> (mtime, data)
        self._wanted = []                # addresses someone looked at, asked first
        self._asked_at = 0

    @property
    def dir(self):
        return dns_dir(self.cfg)

    def _load(self, name):
        p = os.path.join(self.dir, name)
        try:
            m = os.path.getmtime(p)
        except OSError:
            return {}
        c = self._cache.get(name)
        if c and c[0] == m:
            return c[1]
        data = _read(p, {})
        self._cache[name] = (m, data)
        return data

    def site_names(self):
        n, _ = self.app.site.load()
        out = set()
        for s in n.servers():
            for x in s.get('server_names') or []:
                x = x.lower().rstrip('.')
                if x and x != '_' and not x.startswith(('~', '*', '.')) and NAME_RE.match(x) and '.' in x:
                    out.add(x)
        return sorted(out)

    def outside_addresses(self, days=3, limit=3000):
        rows = self.db.q("SELECT src_ip, MAX(ts) t FROM events WHERE ts>=? AND origin='external' GROUP BY src_ip ORDER BY t DESC LIMIT ?",
                         (time.time() - days * 86400, limit))
        ips = [r['src_ip'] for r in rows]
        ips += [r['ip'] for r in self.db.q("SELECT ip FROM ip_blocks WHERE state='active' AND ip NOT LIKE '%/%'")]
        seen, out = set(), []
        for ip in self._wanted + ips:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out

    def targets(self):
        d = self.cfg['dns']
        return {'check_hours': d['check_hours'], 'internal': list(d['internal_servers']) if d['enabled'] else [],
                'external': list(d['external_servers']) if d['enabled'] else [],
                'names': self.site_names() if d['enabled'] else [], 'ptr': bool(d['ptr']),
                'ptr_servers': list(d['ptr_servers']), 'ips': self.outside_addresses() if d['ptr'] else []}

    def write_targets(self):
        t = self.targets()
        p = os.path.join(self.dir, TARGETS)
        if _read(p, None) == t:
            return False
        if not os.path.isdir(os.path.dirname(self.dir.rstrip('/'))):
            return False                  # the database's folder is not there: nothing to write next to it
        os.makedirs(self.dir, mode=0o750, exist_ok=True)
        _write(p, t)
        return True

    def request(self):
        """Ask the job to run now (the "check now" button, or an address someone is looking at)."""
        self.write_targets()
        with open(os.path.join(self.dir, REQUEST), 'w') as fh:
            fh.write(util.iso(time.time()))

    def want_ptr(self, ip):
        """An address someone hovers that is not in the cache: asked at the next run, the job started at most twice a
        minute."""
        if ip in self._wanted or not self.cfg['dns']['ptr']:
            return
        self._wanted = ([ip] + self._wanted)[:200]
        if time.time() - self._asked_at > 30:
            self._asked_at = time.time()
            try:
                self.request()
            except OSError:
                pass

    def ptr(self, ip):
        return self._load(PTRS).get(ip)

    def names(self):
        return self._load(RESULTS)

    def name_info(self, name):
        r = self.names().get('names', {}).get((name or '').lower().rstrip('.'))
        if not r:
            return None
        return {'class': r['class'], 'public_private': r.get('public_private', False)}

    def status(self):
        res = self.names()
        st = self._load('status.json')
        d = self.cfg['dns']
        return {'enabled': bool(d['enabled']), 'ptr': bool(d['ptr']), 'internal_servers': d['internal_servers'],
                'external_servers': d['external_servers'], 'ptr_servers': d['ptr_servers'] or d['internal_servers'] or system_resolvers(),
                'check_hours': d['check_hours'], 'checked_at': res.get('checked_at'), 'ran_at': st.get('ran_at'),
                'requested': os.path.exists(os.path.join(self.dir, REQUEST)), 'wildcards': res.get('wildcards', {}),
                'names': res.get('names', {}), 'ptr_cached': len(self._load(PTRS))}

    def run(self, stop, interval=60):
        while not stop.is_set():
            try:
                self.write_targets()
            except Exception:              # noqa: BLE001 -- the next minute tries again
                pass
            stop.wait(interval)
