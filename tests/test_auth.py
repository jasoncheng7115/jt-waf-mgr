import time
import unittest

from jtwafmgr import auth
from jtwafmgr.audit import Audit
from jtwafmgr.db import Database
from tests.helpers import TempEnv


class TestPrimitives(unittest.TestCase):
    def test_password_hash(self):
        h = auth.hash_password('correct horse battery')
        self.assertTrue(h.startswith('scrypt$'))
        self.assertTrue(auth.verify_password('correct horse battery', h))
        self.assertFalse(auth.verify_password('wrong', h))
        self.assertFalse(auth.verify_password('x', 'garbage'))
        self.assertNotEqual(h, auth.hash_password('correct horse battery'))  # salted

    def test_totp_rfc6238(self):
        # RFC 6238 appendix B, SHA1, secret "12345678901234567890", T=59 -> 94287082 (last 6 digits)
        import base64
        secret = base64.b32encode(b'12345678901234567890').decode()
        self.assertEqual(auth.totp_code(secret, 59 // 30), '287082')
        self.assertEqual(auth.totp_code(secret, 1111111109 // 30), '081804')
        self.assertEqual(auth.totp_match(secret, '287082', at=59), 1)
        self.assertEqual(auth.totp_match(secret, '287 082', at=59 + 30), 1)   # one step of skew
        self.assertIsNone(auth.totp_match(secret, '287082', at=59 + 90))
        self.assertIsNone(auth.totp_match(secret, 'abcdef', at=59))

    def test_generated_password(self):
        p = auth.generate_password()
        self.assertEqual(len(p), 16)
        self.assertNotIn('l', p)


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(auth={'lockout_threshold': 3, 'lockout_minutes': 1})
        self.db = Database(self.env.cfg['paths']['db'])
        self.a = auth.Auth(self.db, self.env.cfg, Audit(self.db, self.env.cfg))

    def tearDown(self):
        self.env.cleanup()

    def test_create_and_login(self):
        temp = self.a.create_user('alice', 'viewer')
        sid, csrf, row, _ = self.a.login('Alice', temp, None, '192.0.2.5')
        self.assertTrue(row['must_change'])
        u, c = self.a.session(sid)
        self.assertEqual(u['username'], 'alice')
        self.assertEqual(c, csrf)
        self.a.logout(sid)
        self.assertIsNone(self.a.session(sid))

    def test_bad_username(self):
        for n in ('', 'a', 'Bad Name', '../x', 'x' * 40):
            with self.assertRaises(auth.AuthError):
                self.a.create_user(n, 'viewer')
        self.a.create_user('bob', 'viewer')
        with self.assertRaises(auth.AuthError) as cm:
            self.a.create_user('bob', 'viewer')
        self.assertEqual(cm.exception.code, 'user_exists')

    def test_lockout(self):
        self.a.create_user('carol', 'viewer', password='long enough password')
        for _ in range(3):
            with self.assertRaises(auth.AuthError) as cm:
                self.a.login('carol', 'nope', None, '192.0.2.5')
            self.assertEqual(cm.exception.code, 'invalid_credentials')
        with self.assertRaises(auth.AuthError) as cm:
            self.a.login('carol', 'long enough password', None, '192.0.2.5')
        self.assertEqual(cm.exception.code, 'too_many_attempts')

    def test_unknown_user_same_error(self):
        with self.assertRaises(auth.AuthError) as cm:
            self.a.login('nobody', 'x', None, '192.0.2.5')
        self.assertEqual(cm.exception.code, 'invalid_credentials')

    def test_disabled(self):
        self.a.create_user('dave', 'viewer', password='long enough password')
        self.db.x("UPDATE users SET disabled=1 WHERE username='dave'")
        with self.assertRaises(auth.AuthError):
            self.a.login('dave', 'long enough password', None, '192.0.2.5')

    def test_totp_flow_and_replay(self):
        self.a.create_user('erin', 'admin', password='long enough password')
        secret, uri = self.a.totp_setup('erin')
        self.assertIn('otpauth://totp/', uri)
        self.a.totp_enable('erin', auth.totp_code(secret, int(time.time() // 30)))
        with self.assertRaises(auth.AuthError) as cm:
            self.a.login('erin', 'long enough password', None, '192.0.2.5')
        self.assertEqual(cm.exception.code, 'totp_required')
        code = auth.totp_code(secret, int(time.time() // 30) + 1)
        self.a.login('erin', 'long enough password', code, '192.0.2.5')
        with self.assertRaises(auth.AuthError) as cm:  # same code again: replay
            self.a.login('erin', 'long enough password', code, '192.0.2.5')
        self.assertEqual(cm.exception.code, 'totp_invalid')
        with self.assertRaises(auth.AuthError) as cm:
            self.a.totp_disable('erin', 'long enough password', code)
        self.assertEqual(cm.exception.code, 'totp_required_for_role')

    def test_session_idle(self):
        self.a.create_user('fay', 'viewer', password='long enough password')
        sid, _, _, _ = self.a.login('fay', 'long enough password', None, '192.0.2.5')
        self.db.x('UPDATE sessions SET last_seen=?', (time.time() - 3600,))
        self.assertIsNone(self.a.session(sid))

    def test_password_rules(self):
        self.a.create_user('gus', 'viewer', password='long enough password')
        with self.assertRaises(auth.AuthError) as cm:
            self.a.set_password('gus', 'short')
        self.assertEqual(cm.exception.code, 'password_too_short')
        with self.assertRaises(auth.AuthError) as cm:
            self.a.set_password('gus', 'long enough password')
        self.assertEqual(cm.exception.code, 'password_same')

    def test_tokens(self):
        tid, secret = self.a.create_token('ipam', ['lookups:read'], ['192.0.2.0/24'], None, 'admin')
        self.assertTrue(secret.startswith('jwm_%s_' % tid))
        self.assertEqual(self.a.token(secret, '192.0.2.9')['name'], 'ipam')
        with self.assertRaises(auth.AuthError) as cm:
            self.a.token(secret, '198.51.100.1')
        self.assertEqual(cm.exception.code, 'token_source_not_allowed')
        with self.assertRaises(auth.AuthError):
            self.a.token(secret[:-1] + ('A' if secret[-1] != 'A' else 'B'), '192.0.2.9')
        with self.assertRaises(auth.AuthError):
            self.a.create_token('x', ['changes:approve'], [], None, 'admin')
        self.db.x('UPDATE tokens SET revoked=1')
        with self.assertRaises(auth.AuthError):
            self.a.token(secret, '192.0.2.9')


if __name__ == '__main__':
    unittest.main()
