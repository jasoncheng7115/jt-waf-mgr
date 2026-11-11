"""Tiny MaxMind DB writer for tests (record size 24, IPv6 tree with IPv4 under ::/96). Test data only."""
import ipaddress
import struct

MARKER = b'\xab\xcd\xefMaxMind.com'


def _ctrl(typ, size):
    if size < 29:
        sb, extra = size, b''
    elif size < 285:
        sb, extra = 29, bytes([size - 29])
    else:
        sb, extra = 30, struct.pack('>H', size - 285)
    if typ <= 7:
        return bytes([(typ << 5) | sb]) + extra
    return bytes([sb, typ - 7]) + extra


def encode(v):
    if isinstance(v, bool):
        return bytes([v & 1, 14 - 7])
    if isinstance(v, str):
        b = v.encode()
        return _ctrl(2, len(b)) + b
    if isinstance(v, int):
        if v < 0:
            raise ValueError
        b = v.to_bytes((v.bit_length() + 7) // 8, 'big') if v else b''
        if len(b) <= 2:
            return _ctrl(5, len(b)) + b
        if len(b) <= 4:
            return _ctrl(6, len(b)) + b
        return _ctrl(9, len(b)) + b
    if isinstance(v, float):
        return _ctrl(3, 8) + struct.pack('>d', v)
    if isinstance(v, dict):
        out = _ctrl(7, len(v))
        for k, x in v.items():
            out += encode(k) + encode(x)
        return out
    if isinstance(v, list):
        out = _ctrl(11, len(v))
        for x in v:
            out += encode(x)
        return out
    raise TypeError(type(v))


def write(path, networks, database_type='GeoLite2-City', build_epoch=1790000000):
    """networks: {cidr: record dict}. IPv4 networks are stored under ::/96 as MaxMind does."""
    root = {}
    data = b''
    offsets = []
    for cidr, rec in networks.items():
        n = ipaddress.ip_network(cidr)
        if n.version == 4:
            bits, plen = int(n.network_address), n.prefixlen + 96
        else:
            bits, plen = int(n.network_address), n.prefixlen
        offsets.append(len(data))
        data += encode(rec)
        node = root
        for i in range(plen):
            b = (bits >> (127 - i)) & 1
            if i == plen - 1:
                node[b] = ('data', offsets[-1])
            else:
                nxt = node.get(b)
                if not isinstance(nxt, dict):
                    nxt = {}
                    node[b] = nxt
                node = nxt
    nodes = []
    index = {}

    def number(n):
        index[id(n)] = len(nodes)
        nodes.append(n)
        for b in (0, 1):
            if isinstance(n.get(b), dict):
                number(n[b])
    number(root)
    count = len(nodes)
    tree = b''
    for n in nodes:
        recs = []
        for b in (0, 1):
            x = n.get(b)
            if x is None:
                recs.append(count)
            elif isinstance(x, dict):
                recs.append(index[id(x)])
            else:
                recs.append(count + 16 + x[1])
        tree += recs[0].to_bytes(3, 'big') + recs[1].to_bytes(3, 'big')
    meta = {'binary_format_major_version': 2, 'binary_format_minor_version': 0, 'build_epoch': build_epoch,
            'database_type': database_type, 'description': {'en': 'test'}, 'ip_version': 6,
            'languages': ['en'], 'node_count': count, 'record_size': 24}
    with open(path, 'wb') as fh:
        fh.write(tree + b'\x00' * 16 + data + MARKER + encode(meta))
