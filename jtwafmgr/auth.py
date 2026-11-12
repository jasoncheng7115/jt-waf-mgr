"""Local accounts: scrypt password hashes, TOTP (RFC 6238), lockout, sessions, API tokens."""
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import struct
import threading
import time
import urllib.parse

from . import util
from .config import ROLES

USERNAME_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{1,31}$')
# names the program itself acts under (audit actor, proposer): never an account or a token
RESERVED_NAMES = ('analyst', 'system', 'cli')
TOKEN_RE = re.compile(r'^jwm_([a-z0-9]{12})_([A-Za-z0-9_-]{32,64})$')
SCOPES_P1 = ('status:read', 'events:read', 'rules:read', 'lookups:read', 'changes:read', 'changes:propose')
LANGUAGES = ('en', 'zh-TW', 'ja')

# scrypt parameters: n=2**15, r=8, p=1 -> 32 MiB, ~0.1 s per check.
_N, _R, _P = 2 ** 15, 8, 1


def _rate_key(ip):
    """Per-address login limits; IPv6 by /64, since one host usually has a whole /64 to rotate through."""
    try:
        a = ipaddress.ip_address(ip or '')
    except ValueError:
        return '?'
    return str(ipaddress.ip_network('%s/64' % a, strict=False)) if a.version == 6 else str(a)


class AuthError(Exception):
    def __init__(self, code, status=401, **details):
        super().__init__(code)
        self.code = code
        self.status = status
        self.details = details


# Each scrypt check takes 32 MiB: never run more than a few at once (a burst of logins must not exhaust
# the service's memory); callers that cannot get a slot quickly are told to retry.
_SCRYPT_SLOTS = threading.BoundedSemaphore(4)


def _scrypt(pw, salt, n, r, p, dklen):
    if not _SCRYPT_SLOTS.acquire(timeout=5):
        raise AuthError('too_many_attempts', 429, retry_after=5)
    try:
        return hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, maxmem=64 * 1024 * 1024, dklen=dklen)
    finally:
        _SCRYPT_SLOTS.release()


def hash_password(pw):
    salt = secrets.token_bytes(16)
    dk = _scrypt(pw.encode('utf-8'), salt, _N, _R, _P, 32)
    return 'scrypt$%d$%d$%d$%s$%s' % (_N, _R, _P, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(pw, stored):
    try:
        alg, n, r, p, salt, dk = stored.split('$')
        if alg != 'scrypt':
            return False
        got = _scrypt(pw.encode('utf-8'), base64.b64decode(salt), int(n), int(r), int(p), len(base64.b64decode(dk)))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = None


def _dummy_hash():
    # A real hash to verify against when the user does not exist, so timing does not tell.
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_hex(8))
    return _DUMMY_HASH


def generate_password(n=16):
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(n))


# --- TOTP -------------------------------------------------------------------------------

def totp_new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def totp_code(secret, step):
    key = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return '%06d' % ((struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_match(secret, code, at=None, window=1):
    """Returns the matching time step, or None. One step of clock skew either way."""
    code = (code or '').strip().replace(' ', '')
    if not re.fullmatch(r'\d{6}', code):
        return None
    step = int((at if at is not None else time.time()) // 30)
    for s in range(step - window, step + window + 1):
        if hmac.compare_digest(totp_code(secret, s), code):
            return s
    return None


def totp_uri(secret, username, issuer='jt-waf-mgr'):
    label = urllib.parse.quote('%s:%s' % (issuer, username))
    return 'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30' % (
        label, secret, urllib.parse.quote(issuer))


def _sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


class Auth:
    def __init__(self, db, cfg, audit):
        self.db = db
        self.cfg = cfg
        self.audit = audit
        self._ip_attempts = {}
        self._lock = threading.Lock()

    # --- users ---------------------------------------------------------------------------
    STEP_UP_LIMIT = 5            # wrong one-time codes per user ...
    STEP_UP_WINDOW = 600         # ... within this many seconds, then refused for the rest of the window

    def step_up(self, username, code, purpose, src_ip=None):
        """A fresh one-time code for a sensitive action (backup download, approving one's own loosening).
        Wrong codes are counted (audit trail) and limited; a code is used at most once, also when two requests
        race. Raises AuthError('too_many_attempts', 429) or AuthError('totp_required', 403)."""
        since = time.time() - self.STEP_UP_WINDOW
        n = self.db.one("SELECT COUNT(*) FROM audit WHERE action='auth.step_up_failed' AND actor=? AND ts>=?",
                        (username, since))[0]
        if n >= self.STEP_UP_LIMIT:
            self.audit.log('auth.step_up_locked', username, src_ip=src_ip, result='failed', severity='crit',
                           purpose=purpose, failures=n)
            raise AuthError('too_many_attempts', 429, retry_after=self.STEP_UP_WINDOW)
        u = self.user_row(username)
        step = totp_match(u['totp_secret'], code or '') if u and u['totp_enabled'] else None
        used = False
        if step is not None:
            cur = self.db.x('UPDATE users SET totp_last_step=? WHERE username=? AND (totp_last_step IS NULL OR totp_last_step<?)',
                            (step, username, step))
            used = cur.rowcount == 1
        if not used:
            self.audit.log('auth.step_up_failed', username, src_ip=src_ip, result='failed', purpose=purpose,
                           failures=n + 1)
            raise AuthError('totp_required', 403)
        return step

    def user_row(self, username):
        return self.db.one('SELECT * FROM users WHERE username=?', (username,))

    def user_public(self, r):
        a = self.cfg['auth']
        t = util.now()
        pw_exp = (r['pw_changed_at'] or r['created_at']) + 86400 * a['password_max_age_days'] \
            if a['password_max_age_days'] else None
        dormant_at = (r['activity_at'] or r['created_at']) + 86400 * a['dormant_days'] if a['dormant_days'] else None
        return {'username': r['username'], 'display_name': r['display_name'], 'role': r['role'],
                'totp_enabled': bool(r['totp_enabled']), 'must_change_password': bool(r['must_change']),
                'totp_setup_required': self.totp_missing(r),
                'language': r['language'], 'disabled': bool(r['disabled']),
                'locked': r['locked_until'] > t,
                'last_login': util.iso(r['last_login']), 'last_login_ip': r['last_login_ip'],
                'created_at': util.iso(r['created_at']), 'expires_at': util.iso(r['expires_at']),
                'password_changed_at': util.iso(r['pw_changed_at']), 'password_expires_at': util.iso(pw_exp),
                'dormant_at': util.iso(dormant_at)}

    def create_user(self, username, role, display_name='', password=None, expires_at=None):
        username = (username or '').strip().lower()
        if not USERNAME_RE.match(username) or username in RESERVED_NAMES:
            raise AuthError('invalid_username', 400)
        if role not in ROLES:
            raise AuthError('invalid_role', 400)
        if self.user_row(username):
            raise AuthError('user_exists', 409)
        temp = password or generate_password()
        t = util.now()
        self.db.x('INSERT INTO users(username, display_name, role, pw_hash, must_change, created_at, pw_changed_at, '
                  'activity_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)',
                  (username, (display_name or '')[:64], role, hash_password(temp), 0 if password else 1, t, t, t,
                   self._expiry(expires_at)))
        return temp

    @staticmethod
    def _expiry(value):
        if value in (None, ''):
            return None
        try:
            exp = util.parse_iso(value) if isinstance(value, str) else float(value)
        except (TypeError, ValueError):
            raise AuthError('invalid_expiry', 400)
        if exp <= util.now():
            raise AuthError('invalid_expiry', 400)
        return exp

    def set_expiry(self, username, value):
        self.db.x('UPDATE users SET expires_at=? WHERE username=?', (self._expiry(value), username))

    @staticmethod
    def password_classes(pw):
        return sum(bool(re.search(p, pw)) for p in (r'[a-z]', r'[A-Z]', r'[0-9]', r'[^a-zA-Z0-9]'))

    def check_new_password(self, pw, username=None, by_user=True):
        """Password policy. by_user=False (an admin's reset or the CLI) skips the minimum age."""
        a = self.cfg['auth']
        n = a['password_min_length']
        if len(pw or '') < n:
            raise AuthError('password_too_short', 400, min_length=n)
        if len(pw) > 256:
            raise AuthError('password_too_long', 400)
        if self.password_classes(pw) < a['password_min_classes']:
            raise AuthError('password_too_simple', 400, min_classes=a['password_min_classes'])
        r = self.user_row(username) if username else None
        if not r:
            return
        if verify_password(pw, r['pw_hash']):
            raise AuthError('password_same', 400)
        if a['password_history']:
            for h in self.db.q('SELECT pw_hash FROM password_history WHERE username=? ORDER BY id DESC LIMIT ?',
                               (username, a['password_history'])):
                if verify_password(pw, h[0]):
                    raise AuthError('password_reused', 400, history=a['password_history'])
        if by_user and a['password_min_age_hours'] and not r['must_change']:
            wait = (r['pw_changed_at'] or 0) + 3600 * a['password_min_age_hours'] - util.now()
            if wait > 0:
                raise AuthError('password_too_recent', 400, retry_after=int(wait) + 1)

    def _remember(self, r):
        keep = self.cfg['auth']['password_history']
        if not keep:
            return
        self.db.x('INSERT INTO password_history(username, pw_hash, changed_at) VALUES (?,?,?)',
                  (r['username'], r['pw_hash'], util.now()))
        self.db.x('DELETE FROM password_history WHERE username=? AND id NOT IN '
                  '(SELECT id FROM password_history WHERE username=? ORDER BY id DESC LIMIT ?)',
                  (r['username'], r['username'], keep))

    def set_password(self, username, pw, must_change=False, by_user=True):
        r = self.user_row(username)
        self.check_new_password(pw, username, by_user)
        if r:
            self._remember(r)
        self.db.x('UPDATE users SET pw_hash=?, must_change=?, failed_count=0, locked_until=0, pw_changed_at=? '
                  'WHERE username=?', (hash_password(pw), 1 if must_change else 0, util.now(), username))
        self.drop_sessions(username)

    def reset_password(self, username):
        temp = generate_password()
        r = self.user_row(username)
        if r:
            self._remember(r)
        t = util.now()
        self.db.x('UPDATE users SET pw_hash=?, must_change=1, totp_enabled=0, totp_secret=NULL, failed_count=0, '
                  'locked_until=0, pw_changed_at=?, activity_at=? WHERE username=?', (hash_password(temp), t, t, username))
        self.drop_sessions(username)
        return temp

    def set_disabled(self, username, disabled):
        self.db.x('UPDATE users SET disabled=?, activity_at=CASE WHEN ? THEN activity_at ELSE ? END WHERE username=?',
                  (1 if disabled else 0, 1 if disabled else 0, util.now(), username))
        if disabled:
            self.drop_sessions(username)

    def expire_accounts(self):
        """Disables expired accounts and accounts without a sign-in for dormant_days. Never the last
        active admin. Returns [(username, reason)]."""
        t = util.now()
        out = []
        days = self.cfg['auth']['dormant_days']
        for r in self.db.q('SELECT * FROM users WHERE disabled=0 ORDER BY username'):
            reason = None
            if r['expires_at'] and r['expires_at'] <= t:
                reason = 'expired'
            elif days and (r['activity_at'] or r['created_at']) + 86400 * days <= t:
                reason = 'dormant'
            if not reason:
                continue
            if r['role'] == 'admin' and self.admins_active() <= 1:
                continue
            self.set_disabled(r['username'], True)
            out.append((r['username'], reason))
        return out

    def admins_active(self):
        return self.db.one("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0")[0]

    # --- login ---------------------------------------------------------------------------
    def _ip_limited(self, ip):
        limit = self.cfg['auth']['ip_attempts_per_10min']
        t = time.time()
        with self._lock:
            lst = [x for x in self._ip_attempts.get(ip, []) if t - x < 600]
            self._ip_attempts[ip] = lst
            if len(lst) >= limit:
                return int(600 - (t - lst[0])) + 1
            lst.append(t)
            if len(self._ip_attempts) > 10000:
                self._ip_attempts = {k: v for k, v in self._ip_attempts.items() if v and t - v[-1] < 600}
        return 0

    def login(self, username, password, totp, src_ip, user_agent=None):
        username = (username or '').strip().lower()[:64]
        wait = self._ip_limited(_rate_key(src_ip))
        if wait:
            self.audit.log('login.failed', username, src_ip=src_ip, result='denied', reason='ip_rate_limit')
            raise AuthError('too_many_attempts', 429, retry_after=wait)
        r = self.user_row(username) if USERNAME_RE.match(username) else None
        t = util.now()
        if r and r['locked_until'] > t:
            verify_password(password or '', _dummy_hash())
            self.audit.log('login.failed', username, src_ip=src_ip, result='denied', reason='locked')
            raise AuthError('too_many_attempts', 429, retry_after=int(r['locked_until'] - t) + 1)
        ok = verify_password(password or '', r['pw_hash'] if r else _dummy_hash())
        if r and ok and not r['disabled'] and r['expires_at'] and r['expires_at'] <= t:
            self.set_disabled(username, True)
            self.audit.log('user.disabled', 'system', 'system', None, 'ok', target=username, reason='expired')
            r = self.user_row(username)
        if not r or not ok or r['disabled']:
            if r and not r['disabled']:
                self._failed(r, src_ip, t)
            self.audit.log('login.failed', username, src_ip=src_ip, result='denied',
                           reason='disabled' if r and ok else 'bad_credentials')
            raise AuthError('invalid_credentials')
        if r['totp_enabled']:
            if not totp:
                raise AuthError('totp_required')
            step = totp_match(r['totp_secret'], totp)
            if step is None or step <= r['totp_last_step']:
                self._failed(r, src_ip, t)
                self.audit.log('login.failed', username, src_ip=src_ip, result='denied', reason='totp')
                raise AuthError('totp_invalid')
            self.db.x('UPDATE users SET totp_last_step=? WHERE username=?', (step, username))
        previous = {'at': util.iso(r['last_login']), 'ip': r['last_login_ip'], 'failed_since': r['failed_since_login']}
        a = self.cfg['auth']
        expired = bool(a['password_max_age_days']) and \
            (r['pw_changed_at'] or r['created_at']) + 86400 * a['password_max_age_days'] <= t
        self.db.x('UPDATE users SET failed_count=0, locked_until=0, last_login=?, last_login_ip=?, activity_at=?, '
                  'failed_since_login=0, must_change=CASE WHEN ? THEN 1 ELSE must_change END WHERE username=?',
                  (t, src_ip, t, 1 if expired else 0, username))
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        self.db.x('INSERT INTO sessions(id_hash, username, csrf, created_at, last_seen, src_ip, user_agent) '
                  'VALUES (?,?,?,?,?,?,?)', (_sha256(sid), username, csrf, t, t, src_ip, (user_agent or '')[:200]))
        self._limit_sessions(username)
        self.audit.log('login', username, src_ip=src_ip, **({'password_expired': True} if expired else {}))
        return sid, csrf, self.user_row(username), previous

    def _failed(self, r, src_ip, t):
        """One failure, counted atomically: concurrent wrong guesses each count (no lost update)."""
        a = self.cfg['auth']
        with self.db.tx() as c:
            row = c.execute('UPDATE users SET failed_count=failed_count+1, failed_since_login=failed_since_login+1 '
                            'WHERE username=? RETURNING failed_count', (r['username'],)).fetchone()
            n = row[0] if row else 0
            lock = t + 60 * a['lockout_minutes'] if n >= a['lockout_threshold'] else 0
            if lock:
                c.execute('UPDATE users SET failed_count=0, locked_until=? WHERE username=?', (lock, r['username']))
        if lock:
            self.audit.log('account.locked', r['username'], src_ip=src_ip, result='denied', severity='crit',
                           minutes=a['lockout_minutes'], failures=n)

    def _limit_sessions(self, username):
        n = self.cfg['auth']['max_sessions_per_user']
        if n:
            self.db.x('DELETE FROM sessions WHERE username=? AND id_hash NOT IN '
                      '(SELECT id_hash FROM sessions WHERE username=? ORDER BY created_at DESC LIMIT ?)',
                      (username, username, n))

    def sessions_of(self, username, current_sid=None):
        cur = _sha256(current_sid) if current_sid else None
        return [{'id': r['id_hash'][:16], 'current': r['id_hash'] == cur, 'created_at': util.iso(r['created_at']),
                 'last_seen': util.iso(r['last_seen']), 'src_ip': r['src_ip'], 'user_agent': r['user_agent'] or ''}
                for r in self.db.q('SELECT * FROM sessions WHERE username=? ORDER BY last_seen DESC', (username,))]

    def session(self, sid):
        """Returns (user row, csrf) for a live session, else None. Slides the idle timer."""
        if not sid or len(sid) > 100:
            return None
        h = _sha256(sid)
        s = self.db.one('SELECT * FROM sessions WHERE id_hash=?', (h,))
        if not s:
            return None
        t = util.now()
        idle = 60 * self.cfg['server']['session_idle_minutes']
        maxage = 3600 * self.cfg['server']['session_max_hours']
        if t - s['last_seen'] > idle or t - s['created_at'] > maxage:
            self.db.x('DELETE FROM sessions WHERE id_hash=?', (h,))
            return None
        u = self.user_row(s['username'])
        if not u or u['disabled']:
            self.db.x('DELETE FROM sessions WHERE id_hash=?', (h,))
            return None
        if t - s['last_seen'] > 15:
            self.db.x('UPDATE sessions SET last_seen=? WHERE id_hash=?', (t, h))
        return u, s['csrf']

    def logout(self, sid):
        if sid:
            self.db.x('DELETE FROM sessions WHERE id_hash=?', (_sha256(sid),))

    def drop_sessions(self, username, keep_sid=None):
        if keep_sid:
            self.db.x('DELETE FROM sessions WHERE username=? AND id_hash<>?', (username, _sha256(keep_sid)))
        else:
            self.db.x('DELETE FROM sessions WHERE username=?', (username,))

    def purge_sessions(self):
        t = util.now()
        self.db.x('DELETE FROM sessions WHERE last_seen < ? OR created_at < ?',
                  (t - 60 * self.cfg['server']['session_idle_minutes'], t - 3600 * self.cfg['server']['session_max_hours']))

    # --- TOTP management ----------------------------------------------------------------
    def totp_setup(self, username):
        secret = totp_new_secret()
        self.db.x('UPDATE users SET totp_secret=?, totp_enabled=0 WHERE username=? AND totp_enabled=0', (secret, username))
        r = self.user_row(username)
        if r['totp_enabled']:
            raise AuthError('totp_already_enabled', 409)
        return secret, totp_uri(secret, username)

    def totp_enable(self, username, code):
        r = self.user_row(username)
        if r['totp_enabled']:
            raise AuthError('totp_already_enabled', 409)
        if not r['totp_secret']:
            raise AuthError('totp_not_set_up', 400)
        step = totp_match(r['totp_secret'], code)
        if step is None:
            raise AuthError('totp_invalid', 400)
        self.db.x('UPDATE users SET totp_enabled=1, totp_last_step=? WHERE username=?', (step, username))

    def totp_disable(self, username, password, code):
        r = self.user_row(username)
        if r['role'] in self.cfg['auth']['require_totp_roles']:
            raise AuthError('totp_required_for_role', 400)
        if not verify_password(password or '', r['pw_hash']):
            raise AuthError('invalid_credentials')
        if r['totp_enabled'] and totp_match(r['totp_secret'], code) is None:
            raise AuthError('totp_invalid', 400)
        self.db.x('UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE username=?', (username,))

    def totp_missing(self, r):
        """True when the user's role requires TOTP and it is not set up yet."""
        return r['role'] in self.cfg['auth']['require_totp_roles'] and not r['totp_enabled']

    # --- API tokens ----------------------------------------------------------------------
    def create_token(self, name, scopes, allowed_cidrs, expires_at, created_by):
        name = (name or '').strip()
        if not re.fullmatch(r'[\w .:@-]{1,64}', name) or name.lower() in RESERVED_NAMES:
            raise AuthError('invalid_name', 400)
        if not scopes or any(s not in SCOPES_P1 for s in scopes):
            raise AuthError('invalid_scope', 400, allowed=list(SCOPES_P1))
        cidrs = []
        for c in allowed_cidrs or []:
            try:
                cidrs.append(str(ipaddress.ip_network(c, strict=False)))
            except ValueError:
                raise AuthError('invalid_cidr', 400, value=str(c)[:64])
        exp = None
        if expires_at:
            try:
                exp = util.parse_iso(expires_at)
            except ValueError:
                raise AuthError('invalid_expiry', 400)
            if exp <= util.now():
                raise AuthError('invalid_expiry', 400)
        tid = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(12))
        secret = secrets.token_urlsafe(32)
        self.db.x('INSERT INTO tokens(id, name, secret_hash, scopes, allowed_cidrs, expires_at, created_by, created_at) '
                  'VALUES (?,?,?,?,?,?,?,?)',
                  (tid, name, _sha256(secret), json.dumps(sorted(set(scopes))), json.dumps(cidrs), exp, created_by, util.now()))
        return tid, 'jwm_%s_%s' % (tid, secret)

    @staticmethod
    def token_public(r):
        return {'id': r['id'], 'name': r['name'], 'scopes': json.loads(r['scopes']),
                'allowed_cidrs': json.loads(r['allowed_cidrs']), 'expires_at': util.iso(r['expires_at']),
                'created_by': r['created_by'], 'created_at': util.iso(r['created_at']),
                'last_used_at': util.iso(r['last_used_at']), 'revoked': bool(r['revoked'])}

    def token(self, bearer, src_ip):
        """Returns the token row for a valid bearer token, else raises AuthError."""
        m = TOKEN_RE.match(bearer or '')
        if not m:
            raise AuthError('invalid_token')
        r = self.db.one('SELECT * FROM tokens WHERE id=?', (m.group(1),))
        if not r or not hmac.compare_digest(r['secret_hash'], _sha256(m.group(2))):
            raise AuthError('invalid_token')
        if r['revoked'] or (r['expires_at'] and r['expires_at'] < util.now()):
            raise AuthError('invalid_token')
        cidrs = [ipaddress.ip_network(c) for c in json.loads(r['allowed_cidrs'])]
        if cidrs and not util.ip_in(src_ip, cidrs):
            self.audit.log('token.denied', r['name'], 'token', src_ip, 'denied', reason='source_not_allowed')
            raise AuthError('token_source_not_allowed', 403)
        t = util.now()
        if not r['last_used_at'] or t - r['last_used_at'] > 60:
            self.db.x('UPDATE tokens SET last_used_at=? WHERE id=?', (t, r['id']))
        return r
