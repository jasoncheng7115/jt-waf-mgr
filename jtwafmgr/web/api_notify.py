"""Notifications (admin) and alerts to follow up.

- Settings of the channels are ordinary web-interface settings (PATCH /settings/ui, secrets write-only).
- "Send a test" only queues a message for one channel; the notify unit sends it (the web service never connects
  out). Its result is read with GET /notify/deliveries/{id}.
- Alerts: everyone who may read changes sees them; marking one handled needs an approver (audited, with a note).
"""
from .. import alerts, notify
from .server import ApiError, json_response

V = '/api/v1'


def _page(req, maxlimit=200):
    try:
        limit = max(1, min(int(req.query.get('limit', 50)), maxlimit))
        cursor = int(req.query['cursor']) if req.query.get('cursor') else None
        if cursor is not None and not 0 <= cursor < 2 ** 62:
            raise ValueError('cursor')
    except ValueError:
        raise ApiError(400, 'bad_request', 'limit and cursor must be numbers')
    return limit, cursor


def notify_status(app, req):
    return json_response(200, notify.status(app))


def notify_test(app, req):
    b = req.body()
    ch = b.get('channel') if isinstance(b, dict) else None
    if ch not in notify.CHANNELS:
        raise ApiError(400, 'invalid_channel', 'one of ' + ', '.join(notify.CHANNELS))
    if not notify.configured(app.cfg['notify'], ch):
        app.audit.log('notify.test_requested', req.user['username'], src_ip=req.client_ip, result='refused', channel=ch,
                      reason='not_configured')
        raise ApiError(409, 'channel_not_configured', 'save the settings of this channel first', channel=ch)
    ids = notify.enqueue(app.db, app.cfg, notify.TEST_EVENT, {'channel': ch}, channels=[ch], test=True,
                         by=req.user['username'])
    app.audit.log('notify.test_requested', req.user['username'], src_ip=req.client_ip, channel=ch, notification=ids[0])
    r = app.db.one('SELECT * FROM notifications WHERE id=?', (ids[0],))
    return json_response(202, notify.delivery(r))


def notify_preview(app, req):
    ev = req.query.get('event', '')
    try:
        out = notify.preview(app.cfg, ev, req.query.get('lang'))
    except KeyError:
        raise ApiError(404, 'unknown_event')
    return json_response(200, out)


def notify_deliveries(app, req):
    limit, cursor = _page(req)
    sql, args = 'SELECT * FROM notifications WHERE 1=1', []
    for k in ('channel', 'status'):
        v = req.query.get(k)
        if v:
            sql += ' AND %s=?' % k
            args.append(v[:40])
    if cursor:
        sql += ' AND id<?'
        args.append(cursor)
    rows = app.db.q(sql + ' ORDER BY id DESC LIMIT ?', args + [limit + 1])
    return json_response(200, {'items': [notify.delivery(r) for r in rows[:limit]],
                               'next_cursor': str(rows[limit - 1]['id']) if len(rows) > limit else None})


def _id(req):
    try:
        v = int(req.params['id'])
        if not 0 < v < 2 ** 62:
            raise ValueError
        return v
    except ValueError:
        raise ApiError(404, 'not_found')


def notify_delivery(app, req):
    r = app.db.one('SELECT * FROM notifications WHERE id=?', (_id(req),))
    if not r:
        raise ApiError(404, 'not_found')
    return json_response(200, notify.delivery(r))


def alert_list(app, req):
    limit, cursor = _page(req)
    state = req.query.get('state') or None
    if state and state not in alerts.STATES:
        raise ApiError(400, 'bad_request', 'state: open or handled')
    return json_response(200, alerts.listing(app.db, state, limit, cursor))


def alert_counts(app, req):
    return json_response(200, alerts.counts(app.db))


def alert_get(app, req):
    try:
        return json_response(200, alerts.public(alerts.get(app.db, _id(req))))
    except alerts.AlertError as e:
        raise ApiError(e.status, e.code)


def alert_handle(app, req):
    b = req.body()
    note = b.get('note') if isinstance(b, dict) else None
    if note is not None and not isinstance(note, str):
        raise ApiError(400, 'invalid_note')
    try:
        return json_response(200, alerts.handle(app.db, app.audit, _id(req), req.user['username'], note or '',
                                                src_ip=req.client_ip))
    except alerts.AlertError as e:
        raise ApiError(e.status, e.code)


def register(router):
    R = router.add
    admin = ('admin',)
    R('GET', V + '/notify/status', notify_status, admin)
    R('POST', V + '/notify/test', notify_test, admin)
    R('GET', V + '/notify/preview', notify_preview, admin)
    R('GET', V + '/notify/deliveries', notify_deliveries, admin)
    R('GET', V + '/notify/deliveries/{id}', notify_delivery, admin)
    R('GET', V + '/alerts', alert_list, ('role', 'viewer', 'changes:read'))
    R('GET', V + '/alerts/counts', alert_counts, ('role', 'viewer', 'changes:read'))
    R('GET', V + '/alerts/{id}', alert_get, ('role', 'viewer', 'changes:read'))
    R('POST', V + '/alerts/{id}/handle', alert_handle, ('role', 'approver', None))
