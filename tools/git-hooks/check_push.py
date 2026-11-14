#!/usr/bin/env python3
"""The last check before anything leaves this machine (called by the pre-push hook with its standard input:
"<local ref> <local sha> <remote ref> <remote sha>" per line). For every commit being pushed:

- its message passes the text checks (private names from the denylist, private addresses, mailboxes, keys, no
  session link);
- author and committer are the identity configured for this repository (user.name / user.email), so a commit made
  elsewhere with a personal or work identity does not slip out;
- every file it adds or changes is on the PUBLISH.txt whitelist of that commit and passes the same privacy scan as
  the release (text, screenshot metadata, binaries against the denylist);
and every annotated tag being pushed has a clean message. The pre-commit hook already ran these on the working
tree; this repeats them on what is actually pushed (a commit made with --no-verify, an amended or rebased one).
"""
import fnmatch
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import preflight  # noqa: E402
import scan_text  # noqa: E402

ZERO = '0' * 40
ALWAYS = ('.gitignore',)          # repository housekeeping, not part of the release


def git(*args, binary=False):
    r = subprocess.run(('git',) + args, capture_output=True, check=True)
    return r.stdout if binary else r.stdout.decode('utf-8', 'replace')


def whitelist(commit):
    try:
        text = git('show', '%s:PUBLISH.txt' % commit)
    except subprocess.CalledProcessError:
        return None
    return [l.split('#', 1)[0].strip() for l in text.splitlines() if l.split('#', 1)[0].strip()]


def listed(path, pats):
    return path in ALWAYS or any(fnmatch.fnmatch(path, p) or path.startswith(p.rstrip('/') + '/') for p in pats)


def changed_files(commit):
    """Files a commit adds or changes (all files of a first commit; for a merge, against each parent, so what the
    merge itself brings in is checked too); deleted files are gone, nothing to check."""
    out = git('diff-tree', '-m', '--root', '--no-commit-id', '-r', '-z', '--diff-filter=d', '--name-only', commit)
    return sorted({p for p in out.split('\0') if p})


def check_commit(commit, identity, deny, local=None):
    problems = []
    msg = git('log', '-1', '--format=%B', commit)
    problems += ['message: %s' % p for p in scan_text.problems(msg)]
    who = git('log', '-1', '--format=%an <%ae>%n%cn <%ce>', commit).splitlines()
    for role, w in zip(('author', 'committer'), who):
        if identity and w != identity:
            problems.append('%s is not the identity configured for this repository' % role)
    pats = whitelist(commit)
    if pats is None:
        problems.append('no PUBLISH.txt in the commit')
        pats = []
    # a commit cannot widen its own whitelist: the path must also be on the PUBLISH.txt checked out here
    local = local if local is not None else pats
    before = len(preflight.failures)
    for path in changed_files(commit):
        if not (listed(path, pats) and listed(path, local)):
            problems.append('%s is not on the PUBLISH.txt whitelist' % path)
            continue
        data = git('cat-file', 'blob', '%s:%s' % (commit, path), binary=True)
        preflight.check_blob(path, data, deny)
    problems += preflight.failures[before:]
    return problems


def check_tag(ref, identity=None):
    if git('cat-file', '-t', ref).strip() != 'tag':
        return []
    head, _, body = git('cat-file', '-p', ref).partition('\n\n')
    out = ['tag message: %s' % p for p in scan_text.problems(body)]
    tagger = next((l[len('tagger '):] for l in head.splitlines() if l.startswith('tagger ')), '')
    if identity and tagger.rsplit('>', 1)[0] + '>' != identity:
        out.append('the tagger is not the identity configured for this repository')
    return out


def local_whitelist():
    try:
        with open(os.path.join(git('rev-parse', '--show-toplevel').strip(), 'PUBLISH.txt'), encoding='utf-8') as fh:
            return [l.split('#', 1)[0].strip() for l in fh if l.split('#', 1)[0].strip()]
    except OSError:
        return []


def identity():
    try:
        return '%s <%s>' % (git('config', 'user.name').strip(), git('config', 'user.email').strip())
    except subprocess.CalledProcessError:
        return None


def main(lines, remote='origin'):
    deny = preflight.load_denylist(required=True)
    if deny is None:
        print('refused: no private denylist (%s); set JT_WAF_DENYLIST to it, or to an empty file if there is '
              'nothing private to keep out' % preflight.DENYLIST, file=sys.stderr)
        return 1
    local = local_whitelist()
    me = identity()
    if not me:
        print('refused: no user.name / user.email configured for this repository', file=sys.stderr)
        return 1
    bad = False
    for line in lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        lref, lsha, _rref, rsha = parts
        if lsha == ZERO:                          # deleting a remote ref sends nothing
            continue
        # a new branch or tag: the commits this remote does not have yet (other remotes do not count)
        rng = [lsha, '--not', '--remotes=%s' % remote] if rsha == ZERO else ['%s..%s' % (rsha, lsha)]
        for c in git('rev-list', *rng).split():
            for p in check_commit(c, me, deny, local):
                print('refused: commit %s: %s' % (c[:12], p), file=sys.stderr)
                bad = True
        for p in check_tag(lref, me):
            print('refused: %s: %s' % (lref, p), file=sys.stderr)
            bad = True
    return 1 if bad else 0


if __name__ == '__main__':
    # git runs pre-push with the remote's name and URL as arguments
    sys.exit(main(sys.stdin.read().splitlines(), sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else 'origin'))
