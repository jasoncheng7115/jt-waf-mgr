"""Nothing private leaves this machine: the publication checks (tools/preflight.py), the text checks shared by the
git hooks and the release tool (tools/git-hooks/scan_text.py) and the pre-push check of what is actually pushed
(tools/git-hooks/check_push.py). The private-looking values are put together at run time, so this file itself
passes the checks it tests."""
import io
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zlib

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(TOP, 'tools', 'git-hooks')
sys.path.insert(0, os.path.join(TOP, 'tools'))
sys.path.insert(0, HOOKS)
import preflight  # noqa: E402
import scan_text  # noqa: E402

PRIV_IP = '.'.join(('10', '20', '30', '40'))
LAN_IP = '.'.join(('192', '168', '5', '9'))
PLACEHOLDER = '.'.join(('192', '168', '77', '5'))
MAILBOX = 'ops' + '@' + 'corp-mail.' + 'test'
KEY = '-----BEGIN ' + 'PRIVATE KEY-----'
SESSION = 'Claude-' + 'Session: https://claude.ai/code/session_x'
SECRET_NAME = 'acme' + 'intranet'          # stands in for a private host name on the denylist
COAUTHOR = 'Co-Authored-By: Claude <noreply@anthropic.com>'


def png(chunks=()):
    def chunk(kind, body):
        return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body))
    out = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0))
    for kind, body in chunks:
        out += chunk(kind, body)
    return out + chunk(b'IDAT', zlib.compress(b'\x00\x00')) + chunk(b'IEND', b'')


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='jtwaf-test-pub-')
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.deny_file = os.path.join(self.dir, 'denylist.txt')
        with open(self.deny_file, 'w') as fh:
            fh.write('# private names\n%s\n' % SECRET_NAME)
        old = preflight.DENYLIST
        preflight.DENYLIST = self.deny_file
        self.addCleanup(setattr, preflight, 'DENYLIST', old)
        self.deny = preflight.load_denylist()
        del preflight.failures[:]
        self.addCleanup(lambda: preflight.failures.__delitem__(slice(None)))

    def blob(self, rel, data):
        before = len(preflight.failures)
        preflight.check_blob(rel, data, self.deny)
        return preflight.failures[before:]


class TestFiles(Base):
    def test_text(self):
        self.assertEqual(self.blob('README.md', b'docs.example.com 192.0.2.1 198.51.100.7 203.0.113.9 ' +
                                   PLACEHOLDER.encode() + b' user@example.com ' + COAUTHOR.encode()), [])
        for bad in (PRIV_IP, LAN_IP, MAILBOX, KEY, 'see %s.example.com' % SECRET_NAME, SECRET_NAME.upper()):
            self.assertTrue(self.blob('docs/x.md', ('line one\n' + bad + '\n').encode()), bad)
        self.assertEqual(self.blob('docs/x.md', ('%s  # %s\n' % (PRIV_IP, 'preflight' + ':allow')).encode()), [])
        self.assertIn(':2 ', self.blob('docs/x.md', ('ok\n' + PRIV_IP + '\n').encode())[0])     # names the line

    def test_detectors_found_in_review(self):
        net = '.'.join(('192', '168', '5', '0')) + '/24'
        for bad in ('ends a sentence on %s.' % LAN_IP, 'the office network ' + net, MAILBOX.upper(),
                    '-----BEGIN ' + 'PGP PRIVATE KEY BLOCK-----', '-----BEGIN ' + 'ENCRYPTED PRIVATE KEY-----',
                    'token ' + 'ghp_' + 'a' * 36, 'token ' + 'github_pat_' + 'b' * 30, 'key ' + 'AKIA' + 'C' * 16,
                    'host ' + 'fd' + '12:3456:' + '789a::1', '0'.join(('192.168.', '05.9'))):
            self.assertTrue(self.blob('docs/x.md', (bad + '\n').encode()), bad)
        # the generic private blocks, the documentation ranges and the IPv6 ones are documentation, not secrets
        self.assertEqual(self.blob('docs/x.md', b'10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, fd00::/8, 192.0.2.0/24\n'), [])
        # the co-author line does not exempt another mailbox on the same line
        self.assertTrue(self.blob('docs/x.md', (COAUTHOR + ' cc ' + MAILBOX + '\n').encode()))
        # the allow marker lets an address through on purpose, never a denylisted name or a key
        mark = '  # ' + 'preflight' + ':allow'
        self.assertEqual(self.blob('docs/x.md', (PRIV_IP + mark + '\n').encode()), [])
        self.assertTrue(self.blob('docs/x.md', (SECRET_NAME + mark + '\n').encode()))
        self.assertTrue(self.blob('docs/x.md', (KEY + mark + '\n').encode()))
        self.assertTrue(scan_text.problems('subject ' + PRIV_IP + mark))         # never in a message

    def test_text_in_utf16_and_other_binaries(self):
        for enc in ('utf-16', 'utf-16-le', 'utf-16-be'):
            self.assertTrue(self.blob('docs/x.txt', ('reach it on %s\n' % LAN_IP).encode(enc)), enc)
            self.assertEqual(self.blob('docs/x.txt', 'nothing here\n'.encode(enc)), [], enc)
        gz = io.BytesIO()
        with tarfile.open(fileobj=gz, mode='w:gz'):
            pass
        for data in (gz.getvalue(), b'SQLite format 3\x00' + b'\x00' * 100, b'\x00\x01\x02\x03' * 50):
            self.assertTrue(any('cannot be checked' in f for f in self.blob('docs/x.bin', data)))

    def test_screenshots_and_binaries(self):
        self.assertEqual(self.blob('docs/shots/a.png', png()), [])
        got = self.blob('docs/shots/a.png', png([(b'tEXt', b'Software\x00' + SECRET_NAME.encode())]))
        self.assertTrue(any('tEXt' in g for g in got) and any('denylisted' in g for g in got), got)
        self.assertTrue(self.blob('docs/shots/a.png', png([(b'eXIf', b'MM\x00*')])))
        webp = b'RIFF' + struct.pack('<I', 4 + 8 + 4) + b'WEBP' + b'EXIF' + struct.pack('<I', 4) + b'MM\x00*'
        self.assertTrue(any('EXIF' in g for g in self.blob('docs/shots/thumb/a.webp', webp)))
        self.assertTrue(self.blob('x.bin', b'\x00\x01' + SECRET_NAME.encode() + b'\x00'))

    def test_release_tarball(self):
        tar = os.path.join(self.dir, 'r.tar.gz')
        with tarfile.open(tar, 'w:gz') as tf:
            for name, data in (('jt-waf-mgr-9.9.9/README.md', b'fine'), ('jt-waf-mgr-9.9.9/CLAUDE.md', b'notes'),
                               ('jt-waf-mgr-9.9.9/docs/a.md', LAN_IP.encode())):
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        before = len(preflight.failures)
        preflight.check_tar(tar, self.deny)
        got = ' '.join(preflight.failures[before:])
        self.assertIn('CLAUDE.md should not be in the release', got)
        self.assertIn('release/MANIFEST.sha256 missing', got)
        self.assertIn('private address', got)

    def test_the_publish_whitelist_leaves_private_paths_out(self):
        if not os.path.exists(os.path.join(TOP, 'PUBLISH.txt')):
            self.skipTest('not a full source tree (no PUBLISH.txt)')
        files = preflight.publish_list()
        for rel in files:
            self.assertFalse(rel.startswith(('internal', 'zap-reports', 'dist/', 'github/')) or rel == 'CLAUDE.md'
                             or rel.endswith(('.db', '.pem.key')), rel)
        self.assertIn('tools/preflight.py', files)
        self.assertNotIn('tools/gh_release.py', files)          # reads the private token path; never published


class TestText(Base):
    def test_messages_and_release_notes(self):
        self.assertEqual(scan_text.problems('jt-waf-mgr 1.2.3: a fix\n\nOn app.example.com.\n\n' + COAUTHOR), [])
        for bad in (SESSION, 'from ' + PRIV_IP, 'mail ' + MAILBOX, KEY, 'the %s box' % SECRET_NAME):
            self.assertTrue(scan_text.problems('subject\n\n' + bad + '\n'), bad)
        self.assertEqual(preflight.failures, [])                 # the checks leave no failure behind

    def test_commit_msg_hook(self):
        f = os.path.join(self.dir, 'msg')
        env = dict(os.environ, JT_WAF_DENYLIST=self.deny_file)
        for text, code in (('fine\n\n' + COAUTHOR + '\n', 0), ('fine\n\n' + SESSION + '\n', 1),
                           ('# a comment line: %s\nfine\n' % PRIV_IP, 0), ('fine %s\n' % SECRET_NAME, 1)):
            with open(f, 'w') as fh:
                fh.write(text)
            r = subprocess.run([sys.executable, os.path.join(HOOKS, 'scan_text.py'), f], env=env, capture_output=True)
            self.assertEqual(r.returncode, code, text)


    def test_a_missing_denylist_stops_the_hooks(self):
        f = os.path.join(self.dir, 'msg')
        with open(f, 'w') as fh:
            fh.write('fine\n')
        env = dict(os.environ, JT_WAF_DENYLIST=os.path.join(self.dir, 'nothing-here.txt'))
        r = subprocess.run([sys.executable, os.path.join(HOOKS, 'scan_text.py'), f], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn('no private denylist', r.stderr)


@unittest.skipUnless(shutil.which('git'), 'git not installed')
class TestPush(Base):
    """The pre-push check on a scratch repository: commits as they would be pushed."""

    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.dir, 'repo')
        os.makedirs(self.repo)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'release bot')
        self.git('config', 'user.email', 'bot@example.com')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('config', 'core.hooksPath', '/dev/null')
        self.write('PUBLISH.txt', 'PUBLISH.txt\nREADME.md\ndocs/\n')
        self.write('README.md', 'hello\n')
        self.base = self.commit('first\n\n' + COAUTHOR)

    def git(self, *args, env=None):
        return subprocess.run(('git',) + args, cwd=self.repo, check=True, capture_output=True, text=True,
                              env=dict(os.environ, **(env or {}))).stdout.strip()

    def write(self, rel, data):
        p = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as fh:
            fh.write(data.encode() if isinstance(data, str) else data)

    def commit(self, msg, env=None):
        self.git('add', '-A')
        self.git('commit', '-q', '--no-verify', '-m', msg, env=env)
        return self.git('rev-parse', 'HEAD')

    def push(self, since=None, ref='refs/heads/main', sha=None):
        line = '%s %s %s %s\n' % (ref, sha or self.git('rev-parse', 'HEAD'), ref, since or '0' * 40)
        r = subprocess.run([sys.executable, os.path.join(HOOKS, 'check_push.py')], cwd=self.repo, input=line, text=True,
                           capture_output=True, env=dict(os.environ, JT_WAF_DENYLIST=self.deny_file))
        return r.returncode, r.stderr

    def test_clean_history_passes(self):
        self.write('docs/a.md', 'see https://app.example.com and 192.0.2.10\n')
        self.write('docs/shot.png', png())
        self.commit('docs\n\n' + COAUTHOR)
        self.assertEqual(self.push(), (0, ''))

    def test_each_kind_of_leak_is_refused(self):
        cases = [
            ('docs/a.md', 'reach it on %s\n' % LAN_IP, 'docs', None, 'private address'),
            ('docs/a.md', 'host %s.example.com\n' % SECRET_NAME, 'docs', None, 'denylisted'),
            ('docs/a.md', 'write to %s\n' % MAILBOX, 'docs', None, 'mailbox'),
            ('docs/k.pem', KEY + '\n', 'key', None, 'private key'),
            ('docs/s.png', png([(b'tEXt', b'Comment\x00made on my laptop')]), 'shot', None, 'tEXt'),
            ('CLAUDE.md', 'notes\n', 'notes', None, 'not on the PUBLISH.txt whitelist'),
            ('docs/a.md', 'fine\n', 'fine\n\n' + SESSION, None, 'Session'),
            ('docs/a.md', 'fine\n', 'from %s' % PRIV_IP, None, 'private address'),
            ('docs/a.md', 'fine again\n', 'fine', {'GIT_AUTHOR_EMAIL': 'someone@example.net'}, 'author is not'),
            ('docs/a.md', 'fine too\n', 'fine', {'GIT_COMMITTER_NAME': 'Someone Else'}, 'committer is not'),
        ]
        for rel, data, msg, env, why in cases:
            self.git('reset', '-q', '--hard', self.base)
            self.write(rel, data)
            self.commit(msg, env=env)
            code, err = self.push(since=self.base)
            self.assertEqual(code, 1, (rel, why, err))
            self.assertIn(why, err, (rel, why))

    def test_only_the_commits_pushed_and_tags(self):
        self.write('docs/a.md', 'reach it on %s\n' % LAN_IP)
        self.commit('leak')
        self.write('docs/a.md', 'fixed\n')
        fixed = self.commit('fix')
        self.assertEqual(self.push()[0], 1)                       # the leaking commit is still in what is pushed
        self.assertEqual(self.push(since=self.git('rev-parse', 'HEAD~1'))[0], 0)   # only the fix is new
        os.unlink(os.path.join(self.repo, 'docs', 'a.md'))
        self.commit('remove the file')
        self.assertEqual(self.push(since=fixed)[0], 0)           # a deletion carries nothing to check
        self.git('tag', '-a', 'v1', '-m', 'release for %s' % SECRET_NAME)
        code, err = self.push(since=fixed, ref='refs/tags/v1', sha=self.git('rev-parse', 'v1'))
        self.assertEqual(code, 1)
        self.assertIn('tag message', err)
        self.git('tag', '-d', 'v1')
        self.git('tag', '-a', 'v1', '-m', 'jt-waf-mgr v1')
        self.assertEqual(self.push(since=fixed, ref='refs/tags/v1', sha=self.git('rev-parse', 'v1'))[0], 0)

    def test_what_a_merge_brings_in(self):
        self.git('checkout', '-q', '-b', 'side')
        self.write('docs/side.md', 'side\n')
        self.commit('side')
        self.git('checkout', '-q', 'main')
        self.write('docs/main.md', 'main\n')
        self.commit('main')
        self.git('merge', '-q', '--no-ff', '--no-commit', 'side')
        self.write('docs/merge.md', 'resolved on %s\n' % LAN_IP)
        self.git('add', '-A')
        self.git('commit', '-q', '--no-verify', '-m', 'merge')
        code, err = self.push(since=self.base)
        self.assertEqual(code, 1, err)
        self.assertIn('private address', err)

    def test_a_tag_by_someone_else(self):
        self.git('tag', '-a', 'v2', '-m', 'jt-waf-mgr v2', env={'GIT_COMMITTER_NAME': 'Someone Else'})
        code, err = self.push(since=self.base, ref='refs/tags/v2', sha=self.git('rev-parse', 'v2'))
        self.assertEqual(code, 1)
        self.assertIn('tagger is not', err)

    def test_a_commit_cannot_widen_its_own_whitelist(self):
        self.write('PUBLISH.txt', 'PUBLISH.txt\nREADME.md\ndocs/\nnotes/\n')
        self.write('notes/private.md', 'meeting notes\n')
        self.commit('more files')
        self.write('PUBLISH.txt', 'PUBLISH.txt\nREADME.md\ndocs/\n')       # what is checked out here
        code, err = self.push(since=self.base)
        self.assertEqual(code, 1)
        self.assertIn('notes/private.md is not on the PUBLISH.txt whitelist', err)

    def test_a_missing_denylist_refuses_the_push(self):
        self.write('docs/a.md', 'fine\n')
        self.commit('fine')
        line = 'refs/heads/main %s refs/heads/main %s\n' % (self.git('rev-parse', 'HEAD'), self.base)
        r = subprocess.run([sys.executable, os.path.join(HOOKS, 'check_push.py')], cwd=self.repo, input=line, text=True,
                           capture_output=True, env=dict(os.environ, JT_WAF_DENYLIST=os.path.join(self.dir, 'none.txt')))
        self.assertEqual(r.returncode, 1)
        self.assertIn('no private denylist', r.stderr)

    def test_needs_a_configured_identity(self):
        self.git('config', '--unset', 'user.email')
        r = subprocess.run([sys.executable, os.path.join(HOOKS, 'check_push.py')], cwd=self.repo, input='', text=True,
                           capture_output=True, env=dict(os.environ, JT_WAF_DENYLIST=self.deny_file, HOME=self.dir,
                                                         GIT_CONFIG_NOSYSTEM='1'))
        self.assertEqual(r.returncode, 1)
        self.assertIn('no user.name', r.stderr)


if __name__ == '__main__':
    unittest.main()
