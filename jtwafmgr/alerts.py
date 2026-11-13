"""Alerts to follow up: what the event analysis or the system found that a person has to look at and mark as
handled (an attack that may have passed, users hit by a false positive, an outside configuration change...).

- One open alert per thing (dedup key): seeing it again only counts it, it does not notify again.
- Open alerts are reminded every notify.remind_hours (notify.remind) until someone marks them handled.
- Opening an alert and handling one are audited (alert.created, alert.handled).
"""
import json

from . import util

KINDS = ('attack_in_progress', 'attack_passed', 'false_positive', 'integrity', 'config_outside', 'apply_failed',
         'backup_failed', 'auth_attack', 'crs_update', 'traffic_spike', 'traffic_errors', 'other')
SEVERITIES = ('critical', 'warning')
STATES = ('open', 'handled')


class AlertError(Exception):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


def raise_alert(db, audit, source, kind, severity, dedup, details, link='', notify=True):
    """Open an alert, or count one more sighting of the same open alert. Returns the alert id."""
    kind = kind if kind in KINDS else 'other'
    severity = severity if severity in SEVERITIES else 'warning'
    now = util.now()
    dedup = util.clip(dedup or kind, 300)
    r = db.one("SELECT id, details FROM alerts WHERE dedup=? AND state='open' ORDER BY id DESC LIMIT 1", (dedup,))
    if r:
        try:
            old = json.loads(r['details'] or '{}')
        except ValueError:
            old = {}
        old.update(details or {})
        db.x('UPDATE alerts SET count=count+1, last_seen=?, details=?, severity=CASE WHEN severity=? THEN severity ELSE ? END '
             'WHERE id=?', (now, json.dumps(old, ensure_ascii=False, default=str)[:20000], 'critical', severity, r['id']))
        return r['id']
    aid = db.x('INSERT INTO alerts(created_at, last_seen, source, kind, severity, dedup, details, link) VALUES (?,?,?,?,?,?,?,?)',
               (now, now, source, kind, severity, dedup, json.dumps(details or {}, ensure_ascii=False, default=str)[:20000],
                link or '')).lastrowid
    d = details or {}
    audit.log('alert.created', 'analyst' if source == 'analyst' else 'system', 'system', None, 'ok',
              severity='crit' if severity == 'critical' else 'warning', alert_id=aid, kind=kind, alert_severity=severity,
              source=source, notify=notify, link=link or '/alerts',
              **{k: d[k] for k in ('host', 'path', 'reason', 'change_id', 'run_id', 'count') if k in d})
    try:
        audit.alert(aid, kind, severity, source, d, link)
    except Exception:       # noqa: BLE001 -- an alert is never lost because a log server is not there
        pass
    return aid


def summary(r):
    try:
        d = json.loads(r['details'] or '{}')
    except ValueError:
        d = {}
    parts = [str(d[k]) for k in ('host', 'path') if d.get(k)]
    if not parts and d.get('event'):
        parts.append(str(d['event']))
    return util.clip(' '.join(parts), 120)


def public(r):
    try:
        d = json.loads(r['details'] or '{}')
    except ValueError:
        d = {}
    return {'id': r['id'], 'created_at': util.iso(r['created_at']), 'last_seen': util.iso(r['last_seen']),
            'source': r['source'], 'kind': r['kind'], 'severity': r['severity'], 'count': r['count'], 'details': d,
            'link': r['link'], 'state': r['state'], 'handled_by': r['handled_by'],
            'handled_at': util.iso(r['handled_at']) if r['handled_at'] else None, 'note': r['note'],
            'summary': summary(r)}


def get(db, aid):
    r = db.one('SELECT * FROM alerts WHERE id=?', (aid,))
    if not r:
        raise AlertError('not_found', 404)
    return r


def handle(db, audit, aid, user, note, src_ip=None):
    note = (note or '').strip()
    if len(note) > 1000 or '\x00' in note:
        raise AlertError('invalid_note')
    r = get(db, aid)
    if r['state'] != 'open':
        raise AlertError('not_open', 409)
    n = db.x("UPDATE alerts SET state='handled', handled_by=?, handled_at=?, note=? WHERE id=? AND state='open'",
             (user, util.now(), note, aid)).rowcount
    if n != 1:
        raise AlertError('not_open', 409)
    audit.log('alert.handled', user, src_ip=src_ip, alert_id=aid, kind=r['kind'], note=util.clip(note, 300))
    return public(get(db, aid))


def counts(db):
    out = {'open': 0, 'critical': 0}
    for r in db.q("SELECT severity, COUNT(*) AS c FROM alerts WHERE state='open' GROUP BY severity"):
        out['open'] += r['c']
        if r['severity'] == 'critical':
            out['critical'] += r['c']
    return out


def listing(db, state=None, limit=50, cursor=None):
    sql, args = 'SELECT * FROM alerts WHERE 1=1', []
    if state:
        sql += ' AND state=?'
        args.append(state)
    if cursor:
        sql += ' AND id<?'
        args.append(cursor)
    rows = db.q(sql + ' ORDER BY id DESC LIMIT ?', args + [limit + 1])
    return {'items': [public(r) for r in rows[:limit]], 'next_cursor': str(rows[limit - 1]['id']) if len(rows) > limit else None,
            'counts': counts(db)}


# alerts that the applied change settles by itself: users hit by a false positive get the exclusion that was proposed
# for them. (An attack that may have passed is not settled by a block: someone still has to look at what it got.)
SETTLED_BY_CHANGE = ('false_positive',)


def close_for_change(db, audit, change_id):
    """Mark the open alerts that point at this change handled (audited). Returns their ids."""
    done = []
    for r in db.q("SELECT id, kind, details FROM alerts WHERE state='open' AND kind IN (%s)" % ','.join('?' * len(SETTLED_BY_CHANGE)),
                  SETTLED_BY_CHANGE):
        try:
            d = json.loads(r['details'] or '{}')
        except ValueError:
            continue
        if d.get('change_id') != change_id:
            continue
        note = 'change #%d applied' % change_id
        if db.x("UPDATE alerts SET state='handled', handled_by='system', handled_at=?, note=? WHERE id=? AND state='open'",
                (util.now(), note, r['id'])).rowcount == 1:
            audit.log('alert.handled', 'system', 'system', None, 'ok', alert_id=r['id'], kind=r['kind'], note=note,
                      change_id=change_id)
            done.append(r['id'])
    return done

