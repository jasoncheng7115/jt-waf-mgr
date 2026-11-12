// ModSecurity rule text -> coloured pieces, for RuleText.vue and DiffView.vue.
// Pure functions, no DOM: the pieces are rendered with v-for as text (never as HTML).
//
// Every character of the input gets a class (or '' = plain); the raw pieces are runs of the
// input, so joining them gives back the input exactly. Anything the scanner does not
// understand stays plain. The "formatted" view is derived from the same scan, for display only.

const DIRECTIVE = /^(?:Sec[A-Za-z0-9]+|Include|IncludeOptional)$/
const DENY = new Set(['deny', 'block', 'drop', 'redirect', 'proxy'])
const PASS = new Set(['pass', 'allow'])

// argument roles per directive (lower case); the last role repeats for extra arguments
const ROLES = {
  secrule: ['vars', 'operator', 'actions'],
  secaction: ['actions'],
  secdefaultaction: ['actions'],
  secruleupdateactionbyid: ['ids', 'actions'],
  secruleremovebyid: ['ids'],
  secruleremovebytag: ['str'],
  secruleremovebymsg: ['str'],
  secruleupdatetargetbyid: ['ids', 'vars'],
  secruleupdatetargetbytag: ['str', 'vars'],
  secruleupdatetargetbymsg: ['str', 'vars'],
  secmarker: ['str'],
}

// fewest arguments per directive: a rule shown with its continuation backslashes already removed
// (the rules list API does that) goes on while it has fewer and the next line starts with a quote
const MIN_ARGS = { secrule: 3, secaction: 1, secdefaultaction: 1, secruleupdateactionbyid: 2,
  secruleupdatetargetbyid: 2, secruleupdatetargetbytag: 2, secruleupdatetargetbymsg: 2 }

const isSpace = (c) => c === ' ' || c === '\t'
// length of the line break at i (0 when there is none)
const nlLen = (s, i) => (s[i] === '\n' ? 1 : s[i] === '\r' && s[i + 1] === '\n' ? 2 : 0)
// first non-blank text of the line after the break at i
function nextLine(s, i) {
  let p = i + nlLen(s, i)
  while (p < s.length && isSpace(s[p])) p++
  const e = s.indexOf('\n', p)
  return s.slice(p, e < 0 ? s.length : e).replace(/\r$/, '')
}
// length of a backslash-newline continuation starting at i (0 when there is none)
function contLen(s, i) {
  if (s[i] !== '\\') return 0
  if (s[i + 1] === '\n') return 2
  if (s[i + 1] === '\r' && s[i + 2] === '\n') return 3
  return 0
}

// --- sub-scanners over the logical text of one argument (continuations removed) -------------
// They return spans [{c, a, b}] in logical positions; gaps stay plain.

function macros(L, a, b, base, out) {
  const re = /%\{[^}\n]*\}/g
  re.lastIndex = a
  let p = a
  let m
  while ((m = re.exec(L)) && m.index < b) {
    const e = Math.min(m.index + m[0].length, b)
    if (m.index > p) out.push({ c: base, a: p, b: m.index })
    out.push({ c: 'macro', a: m.index, b: e })
    p = e
  }
  if (p < b) out.push({ c: base, a: p, b })
}

function scanVars(L) {
  const out = []
  const n = L.length
  let i = 0
  while (i < n) {
    const c = L[i]
    if (isSpace(c)) { i++; continue }
    if (c === '|' || c === ',') { out.push({ c: 'punct', a: i, b: i + 1 }); i++; continue }
    if (c === '!' || c === '&') { out.push({ c: 'neg', a: i, b: i + 1 }); i++; continue }
    const m = /^[A-Za-z_][A-Za-z0-9_.-]*/.exec(L.slice(i))
    if (!m) { i++; continue }
    out.push({ c: 'var', a: i, b: i + m[0].length })
    i += m[0].length
    if (L[i] === ':') {
      out.push({ c: 'punct', a: i, b: i + 1 })
      i++
      const s = i
      if (L[i] === '/' || L[i] === "'") {
        const q = L[i]
        i++
        while (i < n && L[i] !== q) i += L[i] === '\\' ? 2 : 1
        i = Math.min(i + 1, n)
      }
      while (i < n && L[i] !== '|' && !isSpace(L[i])) i++
      if (i > s) out.push({ c: 'sel', a: s, b: i })
    }
  }
  return out
}

function scanOperator(L) {
  const out = []
  const n = L.length
  let i = 0
  while (i < n && isSpace(L[i])) i++
  if (L[i] === '!') { out.push({ c: 'op', a: i, b: i + 1 }); i++ }
  const m = /^@[A-Za-z0-9_]+/.exec(L.slice(i))
  if (m) {
    out.push({ c: 'op', a: i, b: i + m[0].length })
    i += m[0].length
    while (i < n && isSpace(L[i])) i++
  }
  if (i < n) macros(L, i, n, 'oparg', out)
  return out
}

// -> { spans, actions: [{ a, b, name }] }
function scanActions(L) {
  const out = []
  const actions = []
  const n = L.length
  let i = 0
  while (i < n) {
    const c = L[i]
    if (c === ',') { out.push({ c: 'punct', a: i, b: i + 1 }); i++; continue }
    if (isSpace(c) || c === '\n' || c === '\r') { i++; continue }
    const start = i
    const m = /^[A-Za-z_][A-Za-z0-9_-]*/.exec(L.slice(i))
    const name = m ? m[0] : ''
    if (m) {
      const lo = name.toLowerCase()
      out.push({ c: DENY.has(lo) ? 'act-deny' : PASS.has(lo) ? 'act-pass' : lo === 'chain' ? 'act-chain' : 'act', a: i, b: i + name.length })
      i += name.length
    }
    if (L[i] === ':') {
      out.push({ c: 'punct', a: i, b: i + 1 })
      i++
      if (L[i] === "'") {
        const s = i
        i++
        while (i < n && L[i] !== "'") i += L[i] === '\\' ? 2 : 1
        i = Math.min(i + 1, n)
        macros(L, s, i, 'str', out)
      }
      const s = i
      while (i < n && L[i] !== ',') {
        if (L[i] === "'") {          // quoted part later in the value
          i++
          while (i < n && L[i] !== "'") i += L[i] === '\\' ? 2 : 1
          i = Math.min(i + 1, n)
        } else i++
      }
      if (i > s) {
        const v = L.slice(s, i)
        if (name.toLowerCase() === 'id') out.push({ c: 'id', a: s, b: i })
        else if (/^\s*\d+\s*$/.test(v)) out.push({ c: 'num', a: s, b: i })
        else macros(L, s, i, 'val', out)
      }
    } else {
      while (i < n && L[i] !== ',') i++    // unexpected text: leave it plain up to the next comma
    }
    if (i === start) i++
    actions.push({ a: start, b: i, name: name.toLowerCase() })
  }
  return { spans: out, actions }
}

function scanIds(L) {
  const out = []
  const re = /\d+/g
  let m
  while ((m = re.exec(L))) out.push({ c: 'id', a: m.index, b: m.index + m[0].length })
  return out
}

function scanWhole(base) {
  return (L) => { const out = []; if (L.length) macros(L, 0, L.length, base, out); return out }
}

const SCAN = { vars: scanVars, operator: scanOperator, ids: scanIds, str: scanWhole('str'), val: scanWhole('val') }

// --- the scanner ---------------------------------------------------------------------------

// -> { cls: [class per char], stmts: [...] }
export function parse(s) {
  s = String(s ?? '')
  const n = s.length
  const cls = new Array(n).fill('')
  const stmts = []
  let line = 1
  let i = 0
  const soft = new Set()
  const dirName = (words) => {
    const w = words[0]
    const d = w && !w.quoted ? s.slice(w.a, w.b) : ''
    return DIRECTIVE.test(d) ? d : ''
  }
  while (i < n) {
    const ls = i
    const startLine = line
    while (i < n && isSpace(s[i])) i++
    if (i >= n) break
    if (s[i] === '\n' || (s[i] === '\r' && s[i + 1] === '\n')) {
      stmts.push({ type: 'blank', a: ls, b: i, line: startLine })
      i += s[i] === '\n' ? 1 : 2
      line++
      continue
    }
    if (s[i] === '#') {
      let j = s.indexOf('\n', i)
      if (j < 0) j = n
      let e = j
      if (e > i && s[e - 1] === '\r') e--
      for (let k = i; k < e; k++) cls[k] = 'comment'
      stmts.push({ type: 'comment', a: ls, b: e, text: s.slice(i, e), line: startLine })
      i = j < n ? j + 1 : n
      line++
      continue
    }
    // a statement: words up to the end of the (continued) line
    const words = []
    for (;;) {
      for (;;) {
        const cl = contLen(s, i)
        if (cl) { cls[i] = 'cont'; i += cl; line++; continue }
        if (i < n && isSpace(s[i])) { i++; continue }
        break
      }
      if (i < n && nlLen(s, i) && dirName(words) && words.length - 1 < (MIN_ARGS[dirName(words).toLowerCase()] || 0) &&
          nextLine(s, i)[0] === '"') {
        soft.add(i)                     // continued without a backslash
        i += nlLen(s, i)
        line++
        continue
      }
      if (i >= n || nlLen(s, i)) break
      const w = { a: i }
      if (s[i] === '"') {
        i++
        w.ca = i
        for (;;) {
          if (i >= n || s[i] === '"') break
          if (nlLen(s, i)) {
            // an open quote continued without a backslash, unless the next line is clearly something else
            const nx = nextLine(s, i)
            if (!dirName(words) || !nx || nx[0] === '#' || DIRECTIVE.test(nx.split(/[ \t]/)[0])) break
            soft.add(i)
            i += nlLen(s, i)
            line++
            continue
          }
          const cl = contLen(s, i)
          if (cl) { i += cl; line++; continue }
          i += s[i] === '\\' && s[i + 1] !== '\n' && i + 1 < n ? 2 : 1
        }
        w.ce = i
        w.closed = s[i] === '"'
        if (w.closed) i++
        w.quoted = true
      } else {
        w.ca = i
        while (i < n && !isSpace(s[i]) && s[i] !== '\n' && !(s[i] === '\r' && s[i + 1] === '\n') && !contLen(s, i)) i++
        w.ce = i
      }
      w.b = i
      words.push(w)
    }
    const st = { type: 'stmt', a: ls, b: i, words, line: startLine }
    stmts.push(st)
    const w0 = words[0]
    const name = w0 && !w0.quoted ? s.slice(w0.a, w0.b) : ''
    if (DIRECTIVE.test(name)) {
      st.directive = name
      for (let k = w0.a; k < w0.b; k++) cls[k] = 'dir'
      const roles = ROLES[name.toLowerCase()] || ['val']
      words.slice(1).forEach((w, k) => {
        w.role = roles[Math.min(k, roles.length - 1)]
        if (w.quoted) {
          cls[w.a] = 'q'
          if (w.closed) cls[w.b - 1] = 'q'
        }
        // logical text: continuations (and the indentation after them) left out
        let L = ''
        const idx = []
        for (let p = w.ca; p < w.ce;) {
          const cl = contLen(s, p)
          if (cl || soft.has(p)) {
            if (cl) cls[p] = 'cont'
            p += cl || nlLen(s, p)
            while (p < w.ce && isSpace(s[p])) p++
            continue
          }
          L += s[p]
          idx.push(p)
          p++
        }
        w.L = L
        if (w.role === 'actions') {
          const r = scanActions(L)
          w.spans = r.spans
          w.actions = r.actions
        } else w.spans = SCAN[w.role](L)
        for (const sp of w.spans) for (let p = sp.a; p < sp.b; p++) cls[idx[p]] = sp.c
      })
      const act = words.find((w) => w.role === 'actions')
      st.chain = name.toLowerCase() === 'secrule' && !!act && act.actions.some((x) => x.name === 'chain')
    }
    if (s[i] === '\r' && s[i + 1] === '\n') i += 2
    else if (s[i] === '\n') i++
    line++
  }
  return { cls, stmts, src: s }
}

// runs of equal class over [a, b)
function runs(s, cls, a, b) {
  const out = []
  let p = a
  for (let k = a + 1; k <= b; k++) {
    if (k === b || cls[k] !== cls[p]) {
      out.push({ cls: cls[p], text: s.slice(p, k) })
      p = k
    }
  }
  return out
}

// Exact pieces of the whole input.
export function tokenize(text) {
  const { cls, src } = parse(text)
  return src.length ? runs(src, cls, 0, src.length) : []
}

// Exact pieces split into lines (the '\n' characters themselves are dropped; joining the lines
// with '\n' gives back the input).
export function tokenizeLines(text) {
  const { cls, src } = parse(text)
  const lines = []
  let a = 0
  for (;;) {
    const j = src.indexOf('\n', a)
    const e = j < 0 ? src.length : j
    lines.push(e > a ? runs(src, cls, a, e) : [])
    if (j < 0) break
    a = j + 1
  }
  return lines
}

// pieces of the logical text of one word, [a, b) in logical positions
function wordPieces(w, a, b) {
  const L = w.L
  const c = new Array(L.length).fill('')
  for (const sp of w.spans) for (let p = sp.a; p < sp.b; p++) c[p] = sp.c
  return b > a ? runs(L, c, a, b) : []
}

const IND = '    '

// Display-only layout: one rule head per line, then its actions one per line, chained rules
// indented one more step. Lines: [{ n: raw line number or null, pieces: [{cls, text}] }].
export function formatLines(text) {
  const { cls, stmts, src } = parse(text)
  const lines = []
  let chained = false
  for (const st of stmts) {
    if (st.type === 'blank') { lines.push({ n: st.line, pieces: [] }); continue }
    if (st.type === 'comment') {
      lines.push({ n: st.line, pieces: [...(chained ? [{ cls: '', text: IND }] : []), { cls: 'comment', text: st.text }] })
      continue
    }
    if (!st.directive) {
      // not a directive we know: shown as it is
      const raw = src.slice(st.a, st.b).split('\n')
      let p = st.a
      raw.forEach((l, k) => {
        lines.push({ n: k ? null : st.line, pieces: l.length ? runs(src, cls, p, p + l.length) : [] })
        p += l.length + 1
      })
      continue
    }
    const ind = chained ? IND : ''
    const head = []
    if (ind) head.push({ cls: '', text: ind })
    head.push({ cls: 'dir', text: st.directive })
    const acts = []
    for (const w of st.words.slice(1)) {
      if (w.role === 'actions') {
        for (const a of w.actions) acts.push(wordPieces(w, a.a, a.b))
        continue
      }
      head.push({ cls: '', text: ' ' })
      if (w.quoted) head.push({ cls: 'q', text: '"' })
      head.push(...wordPieces(w, 0, w.L.length))
      if (w.quoted && w.closed) head.push({ cls: 'q', text: '"' })
    }
    lines.push({ n: st.line, pieces: head })
    for (const a of acts) lines.push({ n: null, pieces: [{ cls: '', text: ind + IND }, ...a] })
    chained = st.chain
  }
  return lines
}
