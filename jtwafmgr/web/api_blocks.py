"""Temporary IP blocks (blocks.py).

- GET  /blocks                 viewer; token scope blocks:read
- POST /blocks                 approver (ranges up to /24 or /64, up to ui_max_ttl); token scope blocks:write
                               (single addresses, up to api_max_ttl, a per-token hourly limit)
- DELETE /blocks/{ip}?source=  token scope blocks:write: ends the token's own entries for that address
- POST /blocks/{id}/remove     approver, with a note: ends one entry, whoever made it
Every add, extension, removal and refusal is audited (block.add / extend / remove / refused / expired).
"""
import urllib.parse

from ..blocks import BlockError
from .server import ApiError, json_response

V = '/api/v1'


def _err(e):
    return ApiError(e.status, e.code, e.code, **e.extra)


def _caller(req):
    if req.user is not None:
        return req.user['username'], 'user', None, req.user['role']
    return req.token['name'], 'token', req.token['id'], None


def block_list(app, req):
    state = req.query.get('state', 'active')
    try:
        items = app.blocks.listing(state)
    except BlockError as e:
        raise _err(e)
    from . import api
    for it in items:                      # the country of the address (of the first address of a range)
        it['geo'] = api.geo(it['ip'].split('/')[0])
    return json_response(200, dict(app.blocks.status(), items=items))


def block_add(app, req):
    b = req.body()
    actor, via, tid, role = _caller(req)
    try:
        item = app.blocks.add(b.get('ip'), b.get('ttl'), b.get('source'), b.get('reason'), actor, via=via, token_id=tid,
                              role=role, src_ip=req.client_ip)
    except BlockError as e:
        raise _err(e)
    return json_response(201, item)


def block_delete(app, req):
    if req.user is not None:
        raise ApiError(400, 'bad_request', 'people end a block with POST /blocks/{id}/remove and a note')
    actor, via, tid, _ = _caller(req)
    ip = urllib.parse.unquote(req.params['ip'])
    try:
        n = app.blocks.remove(actor, via='token', ip=ip, source=req.query.get('source') or None, token_id=tid,
                              src_ip=req.client_ip)
    except BlockError as e:
        raise _err(e)
    return json_response(200, {'removed': n})


def block_remove(app, req):
    b = req.body()
    try:
        bid = int(req.params['id'])
    except ValueError:
        raise ApiError(404, 'not_found')
    try:
        n = app.blocks.remove(req.user['username'], via='user', block_id=bid, note=b.get('note'), src_ip=req.client_ip)
    except BlockError as e:
        raise _err(e)
    return json_response(200, {'removed': n})


def block_extend(app, req):
    """A person sets a later end for an active block (approver: up to the interface maximum; admin: "permanent")."""
    b = req.body()
    try:
        bid = int(req.params['id'])
    except ValueError:
        raise ApiError(404, 'not_found')
    ttl = b.get('ttl')
    if ttl != 'permanent' and not isinstance(ttl, int):
        raise ApiError(422, 'invalid_ttl', 'ttl: seconds or "permanent"')
    try:
        item = app.blocks.extend(bid, ttl, b.get('reason'), req.user['username'], req.user['role'], src_ip=req.client_ip)
    except BlockError as e:
        raise _err(e)
    return json_response(200, item)


def register(router):
    R = router.add
    R('GET', V + '/blocks', block_list, ('role', 'viewer', 'blocks:read'))
    R('POST', V + '/blocks', block_add, ('role', 'approver', 'blocks:write'))
    R('DELETE', V + '/blocks/{ip}', block_delete, ('role', 'approver', 'blocks:write'))
    R('POST', V + '/blocks/{id}/remove', block_remove, ('role', 'approver', None))
    R('POST', V + '/blocks/{id}/extend', block_extend, ('role', 'approver', None))
