"""Small shared helpers: time, addresses, redaction, rule families."""
import datetime
import ipaddress
import re
import time

MONTHS = {m: i for i, m in enumerate(
    ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}


def now():
    return time.time()


def iso(ts):
    """Epoch seconds -> RFC 3339 with the local offset."""
    if ts is None:
        return None
    return datetime.datetime.fromtimestamp(ts).astimezone().isoformat(timespec='seconds')


def parse_iso(s):
    """RFC 3339 (or a bare date) -> epoch seconds. Raises ValueError."""
    s = s.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    d = datetime.datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.astimezone()
    return d.timestamp()


def parse_modsec_time(s, tz=None):
    """libmodsecurity's time_stamp, e.g. 'Mon Nov 10 10:21:00 2026', written in the server's
    local time without a zone. Locale independent (strptime %a/%b would follow LC_TIME)."""
    parts = s.split()
    if len(parts) != 5:
        raise ValueError('bad time_stamp')
    _, mon, day, hms, year = parts
    h, m, sec = (int(x) for x in hms.split(':'))
    d = datetime.datetime(int(year), MONTHS[mon], int(day), h, m, sec)
    if tz is not None:
        return d.replace(tzinfo=tz).timestamp()
    return d.astimezone().timestamp()


def ip_in(ip, networks):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return any(a in n for n in networks if n.version == a.version)


# --- Redaction --------------------------------------------------------------------------
# ModSecurity v3 has no sanitise* actions: whatever a rule matched is copied into the audit
# log, passwords included. Everything stored or shown goes through here first.

REDACTED = '***'
# Every free-text field is cut to this many characters before any regex sees it (a 1 MB attack
# parameter must not stall the single-threaded collector); the stored copy is clipped shorter.
PRE_CLIP = 4096
# Variable references ("found within ARGS:password") are looked for in a larger window: the
# reference follows the matched text, which may itself be long.
REF_SCAN = 65536
REF_LIMIT = 1000
_VAR_RE = re.compile(r'\b(ARGS|ARGS_GET|ARGS_POST|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|'
                     r'REQUEST_HEADERS|FILES|FILES_NAMES|XML|JSON)([:.])([^\s:\'"`,)]+)', re.I)
# Bare cookie collections ("found within REQUEST_COOKIES: <value>") have no name to judge.
_COOKIE_VAR_RE = re.compile(r'\bREQUEST_COOKIES(?:_NAMES)?\b', re.I)
# Headers whose value is a credential whatever the parameter names inside it are.
_SECRET_HEADERS = ('cookie', 'set-cookie', 'authorization', 'proxy-authorization')
# The regexes below are linear: names can only start at the beginning of a run (lookbehind) and
# use possessive quantifiers, so a long run is never re-scanned from every position.
_KV_RE = re.compile(r'(?<![\w.\-\[\]])([\w.\-\[\]]++)(\s*+=\s*+)([^&\s;]++)')
_JSON_KV_RE = re.compile(r'"([\w.\-]++)"(\s*+:\s*+)"(?:[^"\\]|\\.)*+"?')
# masks to the end of the line (was: only on the last line of the text)
_HEADER_RE = re.compile(r'(?i)\b(authorization|cookie)(\s*+:\s*+)(\S[^\r\n]*+)')
# multipart/form-data part header: Content-Disposition: form-data; name="password"
_PART_RE = re.compile(r'(?i)\bname\s{0,8}+=\s{0,8}+"([^"\r\n]{0,256}+)"')
_PART_END_RE = re.compile(r'(?:\r?\n|\\r\\n|\\n)--')


class Redactor:
    def __init__(self, sensitive):
        self.words = set(w.lower() for w in sensitive)

    def is_sensitive(self, name):
        n = name.lower().strip()
        if not n:
            return False
        # json.user.password, data[password], user_password, X-Auth-Token ...
        tokens = [t for t in re.split(r'[^a-z0-9]+', n) if t]
        if any(t in self.words for t in tokens):
            return True
        if n in _SECRET_HEADERS:
            return True
        return any(len(w) >= 5 and w in n for w in self.words)

    def is_sensitive_var(self, collection, name):
        """A ModSecurity variable such as ARGS:password or REQUEST_COOKIES:PHPSESSID.
        Cookies are always secret: session cookies have no recognisable names (PHPSESSID,
        KEYCLOAK_IDENTITY, wordpress_logged_in_*, connect.sid ...)."""
        c = collection.upper()
        if c in ('REQUEST_COOKIES', 'REQUEST_COOKIES_NAMES'):
            return True
        if c == 'REQUEST_HEADERS' and name.lower().strip() in _SECRET_HEADERS:
            return True
        return self.is_sensitive(name)

    def query(self, q):
        """Mask values of sensitive parameters in a query string; keep the names."""
        if not q:
            return q
        out = []
        for part in q.split('&'):
            name, eq, _ = part.partition('=')
            if eq and self.is_sensitive(_unquote(name)):
                out.append(name + '=' + REDACTED)
            else:
                out.append(part)
        return '&'.join(out)

    def references_sensitive(self, *texts):
        """The first sensitive variable a rule message refers to, or None. Looks at the first
        REF_SCAN characters of each text with a linear regex; a text stuffed with more than
        REF_LIMIT different variable names counts as sensitive (fail closed)."""
        seen = 0
        for t in texts:
            if not t:
                continue
            t = t[:REF_SCAN]
            # findall + dict.fromkeys: matching and de-duplication happen in C
            for coll, sep, name in dict.fromkeys(_VAR_RE.findall(t)):
                seen += 1
                if seen > REF_LIMIT or self.is_sensitive_var(coll, name):
                    return coll + sep + name
            m = _COOKIE_VAR_RE.search(t)
            if m:
                return m.group(0)
        return None

    def text(self, t, limit=PRE_CLIP):
        """Mask key=value / "key": "value" pairs with sensitive keys inside free text.
        The input is cut to `limit` characters first (clipping only removes a suffix, so every
        value still visible keeps the name in front of it)."""
        if not t:
            return t
        t = clip(t, limit)
        t = _KV_RE.sub(lambda m: m.group(1) + m.group(2) + REDACTED if self.is_sensitive(m.group(1)) else m.group(0), t)
        t = _JSON_KV_RE.sub(lambda m: '"%s"%s"%s"' % (m.group(1), m.group(2), REDACTED) if self.is_sensitive(m.group(1)) else m.group(0), t)
        t = _HEADER_RE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, t)
        return self._multipart(t)

    def _multipart(self, t):
        out, pos = [], 0
        for m in _PART_RE.finditer(t):
            if m.start() < pos or not self.is_sensitive(m.group(1)):
                continue
            end = _PART_END_RE.search(t, m.end())
            stop = end.start() if end else len(t)
            out.append(t[pos:m.end()])
            out.append(REDACTED)
            pos = stop
        if not out:
            return t
        out.append(t[pos:])
        return ''.join(out)


def _unquote(s):
    from urllib.parse import unquote_plus
    try:
        return unquote_plus(s)
    except Exception:
        return s


# --- Rule families -----------------------------------------------------------------------

SCORING_RULES = {949110, 959100, 980170, 980130, 980140, 980145, 949111, 959101, 980099}

_FAMILY_BY_PREFIX = [
    (911, 'method'), (913, 'scanner'), (920, 'protocol'), (921, 'protocol'), (922, 'protocol'),
    (930, 'lfi'), (931, 'rfi'), (932, 'rce'), (933, 'php'), (934, 'generic'), (941, 'xss'),
    (942, 'sqli'), (943, 'session'), (944, 'java'), (950, 'data_leak'), (951, 'data_leak'),
    (952, 'data_leak'), (953, 'data_leak'), (954, 'data_leak'), (955, 'data_leak'), (956, 'data_leak'),
]
FAMILIES = ('protocol', 'lfi', 'rfi', 'rce', 'php', 'generic', 'xss', 'sqli', 'session', 'java',
            'scanner', 'method', 'body', 'data_leak', 'local', 'other')


def family_of(rule_id, local_range):
    if rule_id in SCORING_RULES:
        return None
    if local_range[0] <= rule_id <= local_range[1]:
        return 'local'
    if 200000 <= rule_id <= 200099:
        return 'body'
    if 900000 <= rule_id <= 999999:
        p = rule_id // 1000
        for prefix, fam in _FAMILY_BY_PREFIX:
            if p == prefix:
                return fam
        if p in (901, 905, 949, 959, 980, 999):
            return None
    return 'other'


CONTROL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def clip(s, n):
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n] + '…'
