"""What jt-waf-mgr sends to log servers, in the format each one reads: JSON (one line, the original format), CEF,
LEEF 2.0, GELF 1.1 and key=value. Four kinds of record: audit (an audit row with its hash), notice (anchors, periodic
checks), event (a WAF event: blocked or logged request) and alert (an alert opened).

Values come partly from requests (paths, host names, user agents in messages), so every format escapes or replaces
whatever could end a record or fake a field: line breaks, its separators, its escape character. Standard library only.
"""
import json
import re

FORMATS = ('json', 'cef', 'leef', 'gelf', 'kv')
KINDS = ('audit', 'event', 'alert')          # what a destination can choose to receive (notices go with audit)

_CTRL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
# syslog level -> CEF / LEEF severity (0-10)
_SEV = {0: 10, 1: 10, 2: 10, 3: 8, 4: 6, 5: 4, 6: 3, 7: 1}


def _s(v, n=2000):
    """A value as one clean string (no control characters except the line breaks each format escapes itself)."""
    if v is None:
        return ''
    if isinstance(v, (dict, list)):
        v = json.dumps(v, ensure_ascii=False, separators=(',', ':'), default=str)
    s = _CTRL.sub('?', str(v))
    return s if len(s) <= n else s[:n - 1] + '…'


def fields(kind, rec):
    """The record as (signature id, name, ordered [(field, value)]) in neutral names; every format maps from these."""
    f = []

    def add(k, v):
        if v not in (None, '', [], {}):
            f.append((k, v))
    add('time', rec.get('ts'))
    add('node', rec.get('node_id'))
    if kind == 'event':
        add('src', rec.get('src_ip'))
        add('host', rec.get('host'))
        add('method', rec.get('method'))
        add('path', rec.get('path'))
        add('query', rec.get('query'))
        add('status', rec.get('status'))
        add('outcome', rec.get('outcome'))
        add('decided_by', rec.get('decided_by'))
        add('score', rec.get('anomaly_score'))
        add('rules', ','.join(str(r) for r in rec.get('rule_ids') or []))
        add('families', ','.join(rec.get('families') or []))
        add('origin', rec.get('origin'))
        add('message', rec.get('message'))
        add('unique_id', rec.get('unique_id'))
        sig = 'waf.' + str(rec.get('outcome') or 'event')
        name = rec.get('message') or ('WAF ' + str(rec.get('outcome') or 'event'))
    elif kind == 'alert':
        add('alert_id', rec.get('alert_id'))
        add('alert_kind', rec.get('kind'))
        add('severity', rec.get('severity'))
        add('alert_source', rec.get('source'))
        add('host', rec.get('host'))
        add('path', rec.get('path'))
        add('reason', rec.get('reason'))
        add('link', rec.get('link'))
        sig = 'alert.' + str(rec.get('kind') or 'other')
        name = rec.get('summary') or ('alert ' + str(rec.get('kind') or ''))
    else:
        known = ('v', 'ts', 'node_id', 'action', 'actor', 'actor_type', 'src_ip', 'result', 'audit_id', 'hash', 'severity',
                 'kind', 'type')
        add('action', rec.get('action') or rec.get('kind'))
        add('actor', rec.get('actor'))
        add('actor_type', rec.get('actor_type'))
        add('src', rec.get('src_ip'))
        add('result', rec.get('result'))
        add('severity', rec.get('severity'))
        add('audit_id', rec.get('audit_id'))
        add('hash', rec.get('hash'))
        rest = {k: v for k, v in rec.items() if k not in known}
        add('details', rest)
        sig = str(rec.get('action') or ('notice.' + str(rec.get('kind') or '')))
        name = sig
    return _s(sig, 100), _s(name, 512), f


# --- CEF (ArcSight Common Event Format) ----------------------------------------------------------------------------
_CEF_KEYS = {'time': None, 'node': 'dvchost', 'src': 'src', 'host': 'dhost', 'method': 'requestMethod', 'path': 'request',
             'outcome': 'outcome', 'result': 'outcome', 'actor': 'suser', 'action': 'act', 'message': 'msg', 'reason': 'msg',
             'status': ('cn2', 'status'), 'score': ('cn1', 'anomaly_score'), 'rules': ('cs1', 'rule_ids'),
             'families': ('cs2', 'families'), 'hash': ('cs3', 'audit_hash'), 'origin': ('cs4', 'origin'),
             'unique_id': ('cs5', 'unique_id'), 'details': ('cs6', 'details'), 'audit_id': ('cn3', 'audit_id'),
             'alert_id': ('cn3', 'alert_id'), 'alert_kind': ('cs4', 'alert_kind'), 'severity': ('cs5', 'severity'),
             'link': ('cs6', 'link'), 'query': ('cs6', 'query'), 'decided_by': ('cs4', 'decided_by'),
             'actor_type': ('cs4', 'actor_type'), 'alert_source': ('cs5', 'alert_source')}


def _cef_head(v):
    return _s(v, 512).replace('\\', '\\\\').replace('|', '\\|').replace('\r', ' ').replace('\n', ' ')


def _cef_val(v):
    return _s(v).replace('\\', '\\\\').replace('=', '\\=').replace('\r', '\\r').replace('\n', '\\n')


def cef(kind, rec, level, version, epoch_ms=None):
    sig, name, f = fields(kind, rec)
    ext, used = [], set()
    if epoch_ms is not None:
        ext.append('rt=%d' % epoch_ms)
    for k, v in f:
        m = _CEF_KEYS.get(k)
        if m is None:
            continue
        if isinstance(m, tuple):
            key, label = m
            if key in used:                 # each custom slot once per record
                continue
            used.add(key)
            ext.append('%sLabel=%s' % (key, _cef_val(label)))
            ext.append('%s=%s' % (key, _cef_val(v)))
        elif m not in used:
            used.add(m)
            ext.append('%s=%s' % (m, _cef_val(v)))
    return 'CEF:0|jt-waf-mgr|jt-waf-mgr|%s|%s|%s|%d|%s' % (_cef_head(version), _cef_head(sig), _cef_head(name),
                                                          _SEV.get(level, 3), ' '.join(ext))


# --- LEEF 2.0 (IBM QRadar) ------------------------------------------------------------------------------------------
_LEEF_KEYS = {'node': 'identHostName', 'src': 'src', 'host': 'dstHost', 'method': 'method', 'path': 'url',
              'actor': 'usrName', 'action': 'cat', 'outcome': 'action', 'result': 'result'}


def _leef_val(v):
    # LEEF has no escape: the separator (tab) and line breaks become spaces
    return _s(v).replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')


def leef(kind, rec, level, version):
    sig, name, f = fields(kind, rec)
    attrs = ['sev=%d' % _SEV.get(level, 3)]
    if rec.get('ts'):
        attrs += ['devTime=%s' % _leef_val(rec['ts']), "devTimeFormat=yyyy-MM-dd'T'HH:mm:ssX"]
    for k, v in f:
        if k == 'time':
            continue
        attrs.append('%s=%s' % (_LEEF_KEYS.get(k, k), _leef_val(v)))
    return 'LEEF:2.0|jt-waf-mgr|jt-waf-mgr|%s|%s|x09|%s' % (_cef_head(version), _cef_head(sig), '\t'.join(attrs))


# --- key=value --------------------------------------------------------------------------------------------------------
def _kv_val(v):
    s = _s(v).replace('\\', '\\\\').replace('"', '\\"').replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')
    return s if s and re.fullmatch(r'[\w.:/@,+-]+', s) else '"%s"' % s


def kv(kind, rec, level):
    sig, _name, f = fields(kind, rec)
    out = ['type=%s' % kind, 'event=%s' % _kv_val(sig), 'level=%d' % level]
    out += ['%s=%s' % (k, _kv_val(v)) for k, v in f]
    return ' '.join(out)


# --- JSON (the original: one line, {"jt_waf_mgr": {...}}) --------------------------------------------------------------
def json_line(kind, rec):
    if kind in ('event', 'alert') and 'type' not in rec:
        rec = dict(rec, type=kind)
    # ensure_ascii escapes every control character and line break: one record is one line whatever a request carried
    return json.dumps({'jt_waf_mgr': rec}, ensure_ascii=True, separators=(',', ':'), default=str)


# --- GELF 1.1 (Graylog) --------------------------------------------------------------------------------------------------
_GELF_NAME = re.compile(r'[^\w.\-]')


def gelf(kind, rec, level, host, when):
    sig, name, f = fields(kind, rec)
    g = {'version': '1.1', 'host': _s(host or rec.get('node_id') or '-', 255), 'short_message': name,
         'timestamp': round(when, 3), 'level': level, '_jt_type': kind, '_jt_event': sig}
    for k, v in f:
        if k in ('time',):
            continue
        key = '_' + _GELF_NAME.sub('_', k)
        if key == '_id':
            key = '_jt_id'
        g[key] = v if isinstance(v, (int, float)) and not isinstance(v, bool) else _s(v, 8000)
    return json.dumps(g, ensure_ascii=True, separators=(',', ':'), default=str).encode('ascii')


GELF_CHUNK = 8000           # UDP payload per chunk (under the usual 8192 limit, with the 12-byte header)
GELF_MAX_CHUNKS = 128


def gelf_udp_chunks(payload, msg_id):
    """One datagram, or GELF chunks (magic 0x1e0f, 8-byte id, sequence, count) when it is too big; None when even 128
    chunks are not enough (the record is dropped and counted)."""
    if len(payload) <= GELF_CHUNK:
        return [payload]
    parts = [payload[i:i + GELF_CHUNK] for i in range(0, len(payload), GELF_CHUNK)]
    if len(parts) > GELF_MAX_CHUNKS:
        return None
    return [b'\x1e\x0f' + msg_id + bytes([i, len(parts)]) + p for i, p in enumerate(parts)]
