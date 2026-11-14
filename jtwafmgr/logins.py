"""Who was logged in to this host when a configuration file changed outside jt-waf-mgr.

jt-waf-mgr cannot see who edits a file by hand. The host's authentication log (/var/log/auth.log on Debian,
/var/log/secure on Red Hat; readable by the adm group the service runs with) says who was logged in, from where and
how, and which commands were run with sudo or su. This is a lead for the person who follows up the alert, not proof:
a session open at that time is not necessarily the one that made the change, and a change by a local process (a
package update, a cron job) leaves no login at all.

Only lines of sshd (accepted logins, session ends), sudo (the command) and su are read; everything else is skipped.
Values are text and are shown as text.
"""
import datetime
import gzip
import os
import re

SYSLOG_TS = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) \S+ ')
ISO_TS = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-]\d{2}:?\d{2}|Z)? \S+ ')
MONTHS = {m: i for i, m in enumerate(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}
ACCEPTED = re.compile(r'sshd\[(\d+)\]: Accepted (\S+) for (\S+) from (\S+) port \d+(?: \w+)?(?:: (\S+) (\S+))?')
CLOSED = re.compile(r'sshd\[(\d+)\]: pam_unix\(sshd:session\): session closed for user (\S+)')
SUDO = re.compile(r'sudo(?:\[\d+\])?: +(\S+) : (?:.*?; )?(?:PWD=([^;]*) ; )?USER=(\S+) ; COMMAND=(.*)$')
SU = re.compile(r'\bsu(?:\[\d+\])?: \(to (\S+)\) (\S+) on (\S+)')
MAX_BYTES = 32 * 1024 * 1024        # never read more than this from one file
MAX_SESSIONS = 20


def _when(line, year):
    m = ISO_TS.match(line)
    if m:
        try:
            ts = datetime.datetime.fromisoformat(m.group(1) + (m.group(2) or ''))
            return ts.timestamp() if ts.tzinfo else ts.replace(tzinfo=None).timestamp()
        except ValueError:
            return None
    m = SYSLOG_TS.match(line)
    if not m or m.group(1) not in MONTHS:
        return None
    try:
        return datetime.datetime(year, MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)),
                                 int(m.group(5))).timestamp()
    except ValueError:
        return None


def _lines(path):
    opener = gzip.open if path.endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
        n = 0
        for line in fh:
            n += len(line)
            if n > MAX_BYTES:
                return
            yield line.rstrip('\n')


def _files(paths):
    """The configured logs and their first rotation (auth.log, auth.log.1), oldest first."""
    out = []
    for p in paths:
        for q in (p + '.1', p):
            if os.path.isfile(q) and os.access(q, os.R_OK):
                out.append(q)
    return out


def sessions(paths, since, until, now=None, slack=300):
    """Logins that were open at some moment in [since - slack, until], newest first, with the sudo / su commands run
    in that window: [{'user', 'from', 'method', 'key', 'start', 'end', 'commands': [...]}]. Missing or unreadable
    logs give an empty list, never an error."""
    now = now or until
    year_now = datetime.datetime.fromtimestamp(now).year
    since -= slack
    open_by_pid, done, commands = {}, [], []
    for path in _files(paths):
        try:
            for line in _lines(path):
                ts = _when(line, year_now)
                if ts is None:
                    continue
                if ts > now + 86400:              # a December line read in January: last year
                    ts = _when(line, year_now - 1) or ts
                if ts > until:
                    continue
                m = ACCEPTED.search(line)
                if m:
                    open_by_pid[m.group(1)] = {'user': m.group(3), 'from': m.group(4), 'method': m.group(2),
                                               'key': (m.group(5) + ' ' + m.group(6)) if m.group(6) else '',
                                               'start': ts, 'end': None, 'commands': []}
                    continue
                m = CLOSED.search(line)
                if m and m.group(1) in open_by_pid:
                    s = open_by_pid.pop(m.group(1))
                    s['end'] = ts
                    if ts >= since:
                        done.append(s)
                    continue
                if ts < since:
                    continue
                m = SUDO.search(line)
                if m:
                    commands.append({'at': ts, 'by': m.group(1), 'as': m.group(3), 'command': m.group(4)[:300]})
                    continue
                m = SU.search(line)
                if m:
                    commands.append({'at': ts, 'by': m.group(2), 'as': m.group(1), 'command': 'su (%s)' % m.group(3)[:40]})
        except OSError:
            continue
    found = done + [s for s in open_by_pid.values()]           # still open at the end of the window
    found = [s for s in found if s['start'] <= until and (s['end'] is None or s['end'] >= since)]
    found.sort(key=lambda s: -s['start'])
    found = found[:MAX_SESSIONS]
    for s in found:
        s['commands'] = [c for c in commands if c['by'] == s['user'] and c['at'] >= s['start'] and
                         (s['end'] is None or c['at'] <= s['end'])][:20]
    # sudo / su outside any session found (a console login, a session that started before the logs)
    loose = [c for c in commands if not any(c in s['commands'] for s in found)][:20]
    return found, loose


def summary(found):
    """One line for an alert: "root from 192.0.2.10 (publickey) x5 14:36-14:37; ..." -- the sessions of one account from
    one address with one method together (a script runs one short session per command), at most three groups."""
    def hm(t):
        return datetime.datetime.fromtimestamp(t).strftime('%H:%M') if isinstance(t, (int, float)) else '…'
    groups = {}
    for s in found:
        g = groups.setdefault((s['user'], s['from'], s['method']), {'n': 0, 'start': s['start'], 'end': s['end']})
        g['n'] += 1
        g['start'] = min(g['start'], s['start'])
        g['end'] = None if (g['end'] is None or s['end'] is None) else max(g['end'], s['end'])
    parts = ['%s from %s (%s)%s %s-%s' % (u, f, m, ' x%d' % g['n'] if g['n'] > 1 else '', hm(g['start']), hm(g['end']))
             for (u, f, m), g in list(groups.items())[:3]]
    return '; '.join(parts) + (' …' if len(groups) > 3 else '')
