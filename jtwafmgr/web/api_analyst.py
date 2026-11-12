"""Event analysis with the local LLM (analyst.py): status, runs, "run now".

Reading needs the same access as the change list (viewer, or a token with changes:read): a run holds
only what the event and change pages show already (paths, counts, rule ids, the proposals), and no
setting of the LLM server except the model name. Asking for a run is for admins; it only writes a request
file that the separate, sandboxed jt-waf-mgr-analyst unit picks up.
"""
from .. import analyst
from .server import ApiError, json_response

V = '/api/v1'


def analyst_status(app, req):
    return json_response(200, analyst.status(app))


def analyst_runs(app, req):
    try:
        limit = max(1, min(int(req.query.get('limit', 50)), 200))
        cursor = int(req.query['cursor']) if req.query.get('cursor') else None
        if cursor is not None and not 0 <= cursor < 2 ** 62:
            raise ValueError('cursor')
    except ValueError:
        raise ApiError(400, 'bad_request', 'limit and cursor must be numbers')
    sql, args = 'SELECT * FROM analyst_runs', []
    if cursor:
        sql += ' WHERE id<?'
        args.append(cursor)
    rows = app.db.q(sql + ' ORDER BY id DESC LIMIT ?', args + [limit + 1])
    return json_response(200, {'items': [analyst.run_summary(r) for r in rows[:limit]],
                               'next_cursor': str(rows[limit - 1]['id']) if len(rows) > limit else None})


def analyst_run_get(app, req):
    try:
        rid = int(req.params['id'])
    except ValueError:
        raise ApiError(404, 'not_found')
    r = app.db.one('SELECT * FROM analyst_runs WHERE id=?', (rid,))
    if not r:
        raise ApiError(404, 'not_found')
    return json_response(200, analyst.run_detail(app, r))


def analyst_run_request(app, req):
    """Admin: queue a run now (the interval is not waited for)."""
    why = analyst.readiness(app.cfg)
    if why:
        app.audit.log('analyst.run_requested', req.user['username'], src_ip=req.client_ip, result='refused', reason=why)
        raise ApiError(409, 'analyst_not_ready', why.replace('_', ' '), reason=why)
    try:
        analyst.request_run(app.cfg)
    except OSError as e:
        raise ApiError(500, 'analyst_request_failed', 'could not queue the run', error=e.strerror)
    app.audit.log('analyst.run_requested', req.user['username'], src_ip=req.client_ip)
    return json_response(202, analyst.status(app))


def register(router):
    R = router.add
    R('GET', V + '/analyst/status', analyst_status, ('role', 'viewer', 'changes:read'))
    R('GET', V + '/analyst/runs', analyst_runs, ('role', 'viewer', 'changes:read'))
    R('GET', V + '/analyst/runs/{id}', analyst_run_get, ('role', 'viewer', 'changes:read'))
    R('POST', V + '/analyst/run', analyst_run_request, ('admin',))
