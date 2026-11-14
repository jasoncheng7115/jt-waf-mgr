"""Read-only nginx configuration parser.

Reads the files directly (following include globs) instead of running `nginx -T`, which needs
root to read the TLS keys. Produces a tree of directives with file and line, and from it the
server blocks with their WAF state.
"""
import glob
import os
import ipaddress
import re


class Directive:
    __slots__ = ('name', 'args', 'children', 'file', 'line', 'comment')

    def __init__(self, name, args, file, line, comment=''):
        self.name = name
        self.args = args
        self.children = None
        self.file = file
        self.line = line
        self.comment = comment

    def __repr__(self):
        return 'Directive(%r, %r)' % (self.name, self.args)


class ParseError(Exception):
    pass


def tokenize(text):
    """Yields (token, line, quoted) and ('#', line, comment_text) for comments."""
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == '\n':
            line += 1
            i += 1
        elif c in ' \t\r':
            i += 1
        elif c == '#':
            j = text.find('\n', i)
            j = n if j < 0 else j
            yield ('#', line, text[i + 1:j])
            i = j
        elif c in '{};':
            yield (c, line, False)
            i += 1
        elif c in '"\'':
            q, j, buf, start = c, i + 1, [], line
            while j < n and text[j] != q:
                if text[j] == '\\' and j + 1 < n:
                    buf.append(text[j:j + 2] if text[j + 1] not in (q, '\\') else text[j + 1])
                    j += 2
                    continue
                if text[j] == '\n':
                    line += 1
                buf.append(text[j])
                j += 1
            yield (''.join(buf), start, True)
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in ' \t\r\n;{}' and not (text[j] == '#' and j == i):
                if text[j] == '\\' and j + 1 < n:
                    j += 2
                    continue
                # ${var} inside a token
                if text[j] == '$' and j + 1 < n and text[j + 1] == '{':
                    k = text.find('}', j)
                    j = k + 1 if k > 0 else j + 1
                    continue
                j += 1
            yield (text[i:j], line, False)
            i = j


class NginxConfig:
    def __init__(self, main_path, max_files=2000):
        self.main = main_path
        self.prefix = os.path.dirname(main_path)
        self.files = {}      # path -> mtime
        self.errors = []
        self.max_files = max_files
        self.tree = self._parse_file(main_path, depth=0)

    def _resolve(self, pattern):
        if not os.path.isabs(pattern):
            pattern = os.path.join(self.prefix, pattern)
        if glob.has_magic(pattern):
            return sorted(glob.glob(pattern))
        return [pattern]

    def _parse_file(self, path, depth):
        if depth > 20 or len(self.files) >= self.max_files:
            self.errors.append('include depth or file limit reached at %s' % path)
            return []
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                text = fh.read()
            self.files[path] = os.stat(path).st_mtime
        except OSError as e:
            self.errors.append('%s: %s' % (path, e.strerror))
            return []
        toks = list(tokenize(text))
        pos = [0]
        try:
            return self._block(toks, pos, path, depth, top=True)
        except ParseError as e:
            self.errors.append('%s: %s' % (path, e))
            return []

    def _block(self, toks, pos, path, depth, top=False):
        out = []
        cur, line, comments = [], None, []
        while pos[0] < len(toks):
            tok, ln, quoted = toks[pos[0]]
            pos[0] += 1
            if tok == '#':
                if not cur:
                    comments.append(quoted.strip())
                continue
            if not quoted and tok == '}':
                if cur:
                    raise ParseError('line %d: unexpected }' % ln)
                if top:
                    raise ParseError('line %d: unbalanced }' % ln)
                return out
            if not quoted and tok in (';', '{'):
                if not cur:
                    if tok == ';':
                        continue
                    raise ParseError('line %d: block without name' % ln)
                d = Directive(cur[0], cur[1:], path, line, '\n'.join(comments[-10:]))
                comments = []
                if tok == '{':
                    d.children = self._block(toks, pos, path, depth)
                    out.append(d)
                elif d.name == 'include' and d.args:
                    for f in self._resolve(d.args[0]):
                        # the include itself stays as a marker (args: the resolved file), so callers can tell where
                        # a file is loaded even when it holds no directives (an empty IP block list)
                        out.append(Directive('include', [f], path, line))
                        out.extend(self._parse_file(f, depth + 1))
                else:
                    out.append(d)
                cur, line = [], None
                continue
            if not cur:
                line = ln
            cur.append(tok)
        if not top:
            raise ParseError('unexpected end of file, missing }')
        if cur:
            raise ParseError('unexpected end of file after %r' % cur[0])
        return out

    # --- queries ------------------------------------------------------------------------
    def http(self):
        for d in self.tree:
            if d.name == 'http' and d.children is not None:
                return d
        return None

    def http_directives(self):
        h = self.http()
        return h.children if h else self.tree

    def modsec_rules_files(self):
        """(path, file, line) of every modsecurity_rules_file, and the server blocks that have one."""
        out = []
        for d, ctx in walk(self.tree):
            if d.name == 'modsecurity_rules_file' and d.args:
                out.append((d.args[0], d.file, d.line, ctx))
        return out

    def servers(self):
        h = self.http()
        if not h:
            return []
        http_waf = _flag(h.children, 'modsecurity')
        http_body = _value(h.children, 'client_max_body_size')
        http_realip = any(d.name == 'set_real_ip_from' for d in h.children)
        variables = _variables(h.children)
        out = []
        for s in h.children:
            if s.name != 'server' or s.children is None:
                continue
            names = []
            listen = []
            for d in s.children:
                if d.name == 'server_name':
                    names.extend(d.args)
                elif d.name == 'listen':
                    listen.append(' '.join(d.args))
            waf_flag = _flag(s.children, 'modsecurity')
            waf = waf_flag if waf_flag is not None else http_waf
            inline_ids, block_mode = [], False
            for d in s.children:
                if d.name == 'modsecurity_rules' and d.args:
                    txt = d.args[0]
                    if re.search(r'(?im)^\s*SecRuleEngine\s+On\b', txt):
                        block_mode = True
                    inline_ids.extend(int(x) for x in re.findall(r'\bid:\s*\'?(\d+)', txt))
            state = 'unknown' if waf is None else ('off' if not waf else ('block' if block_mode else 'on'))
            bypass, restrictions, upstreams = [], [], []
            _scan_locations(s.children, waf, bypass, restrictions, upstreams, prefix='')
            for d in s.children:
                if d.name in ('allow', 'deny'):
                    restrictions.append('%s %s' % (d.name, ' '.join(d.args)))
                elif d.name == 'if' and d.children is not None:
                    for c in d.children:
                        if c.name == 'return' and c.args and c.args[0] in ('403', '404', '444'):
                            restrictions.append('if (%s) { return %s; }' % (' '.join(d.args).strip('()').strip(), c.args[0]))
            body = _value(s.children, 'client_max_body_size') or http_body
            realip = http_realip or any(d.name == 'set_real_ip_from' for d in s.children)
            scope, scope_by = _reach(s.children, variables)
            out.append({'server_names': names, 'listen': listen, 'file': s.file, 'line': s.line, 'waf': state,
                        'inline_rule_ids': inline_ids, 'bypass': bypass, 'body_limit': body,
                        'restrictions': _dedupe(restrictions), 'realip': realip, 'upstreams': _dedupe(upstreams),
                        'reach': scope, 'reach_by': scope_by, 'redirect_only': _redirect_only(s.children)})
        return out

    def inline_rules(self):
        """modsecurity_rules strings anywhere: (text, file, line, context)."""
        out = []
        for d, ctx in walk(self.tree):
            if d.name == 'modsecurity_rules' and d.args:
                out.append((d.args[0], d.file, d.line, ctx))
        return out


def walk(tree, ctx=()):
    for d in tree:
        yield d, ctx
        if d.children is not None:
            label = d.name + (' ' + ' '.join(d.args) if d.args else '')
            yield from walk(d.children, ctx + (label,))


def _flag(children, name):
    v = None
    for d in children:
        if d.name == name and d.args:
            v = d.args[0] == 'on'
    return v


def _value(children, name):
    v = None
    for d in children:
        if d.name == name and d.args:
            v = d.args[0]
    return v


def _scan_locations(children, waf, bypass, restrictions, upstreams, prefix):
    for d in children:
        if d.name == 'proxy_pass' and d.args:
            upstreams.append(d.args[0])
        if d.name != 'location' or d.children is None:
            continue
        loc = ' '.join(d.args)
        flag = _flag(d.children, 'modsecurity')
        here = waf if flag is None else flag
        if waf and flag is False:
            bypass.append({'location': loc, 'file': d.file, 'line': d.line})
        for c in d.children:
            if c.name == 'return' and c.args and c.args[0] in ('403', '404', '444') and loc:
                restrictions.append('location %s { return %s; }' % (loc, c.args[0]))
        _scan_locations(d.children, here, bypass, restrictions, upstreams, prefix + loc)


# --- who can reach a server block: the source checks nginx makes for the whole block ------------------------------
_PRIVATE = [ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '100.64.0.0/10',
                                               '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10')]


def _net(x):
    try:
        return ipaddress.ip_network(x, strict=False)
    except ValueError:
        return None


def _private(n):
    return any(n.version == p.version and n.subnet_of(p) for p in _PRIVATE)


def _variables(http_children):
    """geo and map variables of the http block: {name: ('geo', default, [(network, value)]) |
    ('map', source, default, {value: value}) | None (a form not understood)}."""
    out = {}
    for d in http_children:
        if d.children is None or d.name not in ('geo', 'map'):
            continue
        if d.name == 'geo':
            if len(d.args) != 1:                     # geo $source $var: not the client address, not understood
                if len(d.args) == 2 and d.args[0] in ('$remote_addr', '$binary_remote_addr'):
                    pass
                else:
                    out[d.args[-1].lstrip('$')] = None
                    continue
            default, entries, ok = '', [], True
            for e in d.children:
                if e.name == 'default' and e.args:
                    default = e.args[0]
                elif e.name in ('include', 'ranges', 'delete', 'proxy', 'proxy_recursive'):
                    if e.name in ('ranges', 'proxy', 'proxy_recursive'):
                        ok = False
                elif e.args:
                    n = _net(e.name)
                    if n is None:
                        ok = False
                    else:
                        entries.append((n, e.args[0]))
            out[d.args[-1].lstrip('$')] = ('geo', default, entries) if ok else None
        elif len(d.args) == 2:
            table, default, ok = {}, '', True
            for e in d.children:
                if e.name == 'default' and e.args:
                    default = e.args[0]
                elif e.name in ('hostnames', 'volatile', 'include'):
                    continue
                elif e.name.startswith('~') or not e.args:
                    ok = False
                else:
                    table[e.name.strip('"\'')] = e.args[0].strip('"\'')
            out[d.args[1].lstrip('$')] = ('map', d.args[0].lstrip('$'), default, table) if ok else None
    return out


def _values(variables, name, depth=0):
    """The value a geo variable (or a map of one) takes: (default, [(network, value)]) or None."""
    v = variables.get(name)
    if not v or depth > 3:
        return None
    if v[0] == 'geo':
        return v[1], v[2]
    src = _values(variables, v[1], depth + 1)
    if src is None:
        return None
    default, entries = src
    m, d = v[3], v[2]
    return m.get(default.strip('"\''), d), [(n, m.get(val.strip('"\''), d)) for n, val in entries]


def _passing(default, entries, refused):
    """The networks whose value is not refused, and whether everything else passes too (the default)."""
    nets = [n for n, val in entries if not refused(val)]
    return nets, not refused(default)


def _reach(children, variables):
    """Who can reach a server block, from the checks it makes for every request (location checks do not count):
    'internal' (private networks only), 'country' (lists of public networks, as from a registry), 'limited' (a few
    public addresses), 'open' (no check), 'restricted' (a check that is not understood). Returns (scope, text)."""
    checks, texts = [], []
    allows, denied_all = [], False
    for d in children:
        if d.name == 'allow' and d.args:
            allows.append(d.args[0])
        elif d.name == 'deny' and d.args and d.args[0] == 'all':
            denied_all = True
        elif d.name == 'if' and d.children is not None and any(
                c.name == 'return' and c.args and c.args[0] in ('403', '404', '444') for c in d.children):
            cond = ' '.join(d.args).strip()
            texts.append('if %s' % cond)
            m = re.fullmatch(r'\(\s*\$(\w+)\s*(=|!=)\s*"?([^"\s)]*)"?\s*\)', cond)
            vals = _values(variables, m.group(1)) if m else None
            if not m or vals is None:
                checks.append(None)
                continue
            want = m.group(3)
            refused = (lambda val, w=want: val == w) if m.group(2) == '=' else (lambda val, w=want: val != w)
            checks.append(_passing(vals[0], vals[1], refused))
    if denied_all:
        texts.append('allow %s; deny all' % ' '.join(allows) if allows else 'deny all')
        nets = [n for n in (_net(a) for a in allows) if n is not None]
        checks.append((nets, False) if len(nets) == len(allows) else None)
    if not checks:
        return 'open', ''
    known = [c for c in checks if c is not None]
    closed = [c for c in known if not c[1]]          # a check whose default refuses: only its networks pass
    if not closed:
        return 'restricted', '; '.join(texts)
    # a request must pass every check: the narrowest closed one decides
    best = min(closed, key=lambda c: len(c[0]))
    nets = best[0]
    if all(_private(n) for n in nets):
        return 'internal', '; '.join(texts)
    public = [n for n in nets if not _private(n)]
    return ('country' if len(public) > 50 else 'limited'), '; '.join(texts)


def _redirect_only(children):
    """A block that only sends clients elsewhere (an http -> https redirect): nothing in it to protect."""
    ret = [d for d in children if d.name == 'return' and d.args and d.args[0] in ('301', '302', '303', '307', '308')]
    serving = {'location', 'proxy_pass', 'root', 'alias', 'fastcgi_pass', 'uwsgi_pass', 'grpc_pass', 'try_files', 'index'}
    return bool(ret) and not any(d.name in serving for d in children)


def _dedupe(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
