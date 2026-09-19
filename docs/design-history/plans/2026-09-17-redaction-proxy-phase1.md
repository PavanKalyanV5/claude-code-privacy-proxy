# Redaction Proxy — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local HTTP proxy that Claude Code routes through, which replaces the user's personal data with keyed labels and their username/hostname/project-roots with reversible aliases on the way out, and reverses those aliases inside tool-call inputs on the way back — so every tool keeps working.

**Architecture:** A single long-lived Node process listens on `127.0.0.1`, forwards everything to `api.anthropic.com`, and transforms only `POST /v1/messages*`. Outbound, it walks `system` and `messages` (never `tools`, never signed `thinking` blocks), applying HMAC-keyed PII labels and static path aliases, memoizing per message block so per-turn cost is proportional to new content rather than total context. Inbound, it parses the SSE stream and un-aliases `tool_use` inputs at block completion.

**Tech Stack:** Node.js v24 (`http`, `https`, `crypto`, `node:test`). **Zero runtime dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-17-api-redaction-proxy-design.md`

## Global Constraints

- **Zero runtime dependencies.** Node stdlib only. Tests use `node:test`.
- **Bind `127.0.0.1` only, never `0.0.0.0`.** The proxy accepts unauthenticated plaintext HTTP and forwards it with the user's credentials attached.
- **Never log credentials.** Log presence and length only, never the value of `x-api-key` or `authorization`.
- **Never log personal data.** The audit log carries counts by category only.
- **Labels must be deterministic:** same key + same value → byte-identical label, or prompt caching breaks.
- **Label format:** `[PII:<category>:<16 hex>]` where the hex is `HMAC-SHA256(k_label, value)` truncated to 16 hex chars.
- **Never bare-hash personal data.** HMAC with the local master key only.
- **`tools[]`, `metadata`, `thinking` and `redacted_thinking` are passed through byte-identical.** Thinking blocks are cryptographically signed; altering one byte makes the API reject the request.
- **Fail open on transform errors, fail closed on key errors.** A malformed body is forwarded unmodified; an unreadable master key refuses to start.
- **Phase 1 does not resolve PII labels.** An Edit touching a redacted line fails with "string not found". That is intended, documented behavior until Phase 2.
- Target platform: Windows 11, Git Bash shell, Node v24.18.0.

---

### Task 1: Repository setup and key management

`proxy/keys.js` owns the master key and derives purpose-separated subkeys. Reusing one key across HMAC and AES is poor hygiene, so every consumer gets its own via HKDF.

**Files:**
- Create: `proxy/keys.js`
- Create: `proxy/test/keys.test.js`
- Create: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `loadMaster(keyPath?: string) -> Buffer` (32 bytes; creates the file if absent, throws if present and not 32 bytes)
  - `subkey(master: Buffer, purpose: string) -> Buffer` (32 bytes)
  - `KEY_PATH: string`, `KEY_BYTES: number`

- [ ] **Step 1: Initialise the repository**

This directory is not yet a git repo, and the plan commits after every task.

```bash
cd "c:/Users/SOMEONE/Desktop/games/files"
git init
printf '_user-id.txt\nnode_modules/\n*.log\nredact-cache.enc\n' > .gitignore
git add .gitignore docs temp redact-rules.json
git commit -m "chore: initialise repo with spec, plan and archived hooks"
```

- [ ] **Step 2: Write the failing test**

Create `proxy/test/keys.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadMaster, subkey, KEY_BYTES } = require('../keys');

function tmpKey() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'keys-')), 'redact.key');
}

test('creates a 32-byte key when absent', () => {
  const p = tmpKey();
  const k = loadMaster(p);
  assert.strictEqual(k.length, KEY_BYTES);
  assert.strictEqual(fs.readFileSync(p).length, KEY_BYTES);
});

test('returns the same key on a second call', () => {
  const p = tmpKey();
  assert.deepStrictEqual(loadMaster(p), loadMaster(p));
});

test('refuses a key file of the wrong length', () => {
  const p = tmpKey();
  fs.writeFileSync(p, Buffer.alloc(16));
  assert.throws(() => loadMaster(p), /expected 32/);
});

test('subkeys differ by purpose and are stable', () => {
  const m = Buffer.alloc(32, 7);
  const a = subkey(m, 'label');
  const b = subkey(m, 'cache');
  assert.strictEqual(a.length, 32);
  assert.notDeepStrictEqual(a, b);
  assert.deepStrictEqual(a, subkey(m, 'label'));
});

test('subkeys differ when the master differs', () => {
  assert.notDeepStrictEqual(
    subkey(Buffer.alloc(32, 1), 'label'),
    subkey(Buffer.alloc(32, 2), 'label')
  );
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `node --test proxy/test/keys.test.js`
Expected: FAIL — `Cannot find module '../keys'`

- [ ] **Step 4: Write the implementation**

Create `proxy/keys.js`:

```js
'use strict';

// Master key plus purpose-separated subkeys.
//
// The master key is a 32-byte file with ACLs restricted to the current user.
// It is generated locally and never transmitted. Losing it invalidates every
// label (and, from Phase 2, every cache entry), so rotation is a deliberate
// manual act rather than something scheduled.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const KEY_PATH = path.join(os.homedir(), '.claude', 'redact.key');
const KEY_BYTES = 32;

// Node's `mode` option is largely inert on Windows, so tighten the real ACL.
function restrictAcl(target) {
  if (process.platform !== 'win32') {
    try { fs.chmodSync(target, 0o600); } catch (e) { /* best effort */ }
    return;
  }
  const who = process.env.USERNAME || process.env.USER;
  if (!who) return;
  try {
    execFileSync('icacls', [target, '/inheritance:r', '/grant:r', `${who}:F`], {
      stdio: 'ignore',
    });
  } catch (e) {
    /* best effort; the caller warns if this matters */
  }
}

function loadMaster(keyPath = KEY_PATH) {
  try {
    const buf = fs.readFileSync(keyPath);
    if (buf.length !== KEY_BYTES) {
      throw new Error(
        `master key at ${keyPath} is ${buf.length} bytes, expected ${KEY_BYTES}. ` +
          'Refusing to start rather than fall back to unkeyed hashing.'
      );
    }
    return buf;
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }

  const key = crypto.randomBytes(KEY_BYTES);
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  fs.writeFileSync(keyPath, key, { mode: 0o600 });
  restrictAcl(keyPath);
  return key;
}

function subkey(master, purpose) {
  return Buffer.from(
    crypto.hkdfSync('sha256', master, Buffer.alloc(0), Buffer.from(purpose, 'utf8'), 32)
  );
}

module.exports = { loadMaster, subkey, restrictAcl, KEY_PATH, KEY_BYTES };
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `node --test proxy/test/keys.test.js`
Expected: PASS, 5 tests

- [ ] **Step 6: Commit**

```bash
git add proxy/keys.js proxy/test/keys.test.js
git commit -m "feat(proxy): master key with HKDF purpose-separated subkeys"
```

---

### Task 2: Rules compiler with word boundaries and pattern validation

Ports the compiler from the archived `temp/redact-mirror.js`, with two changes the spec requires: literals get word boundaries, and every pattern is screened for catastrophic backtracking before use.

Screening must run the candidate in a **separate process with a hard timeout** — a catastrophic regex never returns, so timing it in-process would hang the proxy at startup.

**Files:**
- Create: `proxy/rules.js`
- Create: `proxy/test/rules.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `load(rulesPath?: string) -> object` (parsed `redact-rules.json`)
  - `compile(rules: object, warn?: (msg: string) => void) -> { regexes: Array<{re: RegExp, labels: Record<string,string>}>, literalCount: number }`
  - `isPatternSafe(source: string, flags: string) -> { ok: boolean, why?: string }`
  - `boundedLiteral(literal: string) -> string`
  - `RULES_PATH: string`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/rules.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile, isPatternSafe, boundedLiteral } = require('../rules');

// Helper: does any compiled regex match this text?
function matches(compiled, text) {
  return compiled.regexes.some((r) => {
    r.re.lastIndex = 0;
    return r.re.test(text);
  });
}

test('word-bounded literal does not match inside a longer word', () => {
  const c = compile({ literals: ['Jane'], patterns: [] });
  assert.ok(matches(c, 'call Jane today'));
  assert.ok(!matches(c, 'class JaneAdapter {}'));
});

test('boundary:false literal matches inside a word', () => {
  const c = compile({ literals: [{ value: 'Jane', boundary: false }], patterns: [] });
  assert.ok(matches(c, 'class JaneAdapter {}'));
});

test('literals with punctuation edges still match', () => {
  // Deliberately NOT the full '+1-555-000-0000': that exact string is in
  // PLACEHOLDERS, so it compiles to zero literals and the test would pass
  // vacuously-false. A shorter prefix still exercises the leading-punctuation
  // boundary, which is the point.
  const c = compile({ literals: ['+1-555'], patterns: [] });
  assert.ok(matches(c, 'tel +1-555 ok'));
});

test('patterns are ordered before literals in the alternation', () => {
  const c = compile({
    literals: ['Jane'],
    patterns: [{ name: 'email', regex: '[a-z.]+@[a-z.]+', flags: 'gi' }],
  });
  const gi = c.regexes.find((r) => r.re.flags.includes('i'));
  const firstLabel = gi.labels[Object.keys(gi.labels)[0]];
  assert.strictEqual(firstLabel, 'email');
});

test('literals shorter than 3 chars and placeholders are dropped', () => {
  const c = compile({ literals: ['ab', 'Your Full Name'], patterns: [] });
  assert.strictEqual(c.literalCount, 0);
});

test('a catastrophic pattern is rejected, not run', () => {
  const v = isPatternSafe('^(a+)+$', 'g');
  assert.strictEqual(v.ok, false);
  assert.match(v.why, /backtracking|exceeded/i);
});

test('a sane pattern with lookbehind is accepted', () => {
  const v = isPatternSafe('(?<![\\d.])\\d{3}[ .-]\\d{4}(?![\\d.])', 'g');
  assert.strictEqual(v.ok, true);
});

test('an invalid pattern is rejected without throwing', () => {
  assert.strictEqual(isPatternSafe('([unclosed', 'g').ok, false);
});

test('a rejected pattern is warned about and skipped, others survive', () => {
  const warnings = [];
  const c = compile(
    {
      literals: [],
      patterns: [
        { name: 'bad', regex: '^(a+)+$', flags: 'g' },
        { name: 'good', regex: 'zzz', flags: 'g' },
      ],
    },
    (m) => warnings.push(m)
  );
  assert.strictEqual(warnings.length, 1);
  assert.match(warnings[0], /bad/);
  assert.ok(matches(c, 'xx zzz xx'));
});

test('boundedLiteral wraps word-edged literals only', () => {
  assert.strictEqual(boundedLiteral('Jane'), '(?<!\\w)Jane(?!\\w)');
  // Starts with '+' and ends with a digit, so only the trailing side is
  // bounded. Note '-' needs no escaping outside a character class.
  assert.strictEqual(boundedLiteral('+1-555'), '\\+1-555(?!\\w)');
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/rules.test.js`
Expected: FAIL — `Cannot find module '../rules'`

- [ ] **Step 3: Write the implementation**

Create `proxy/rules.js`:

```js
'use strict';

// Loads and compiles redact-rules.json.
//
// Two behaviors matter and are easy to get wrong:
//
//   * Category patterns go FIRST in the alternation. Alternation is
//     leftmost-first, so a short literal like "Jane" would otherwise match
//     inside "jane.test@example.org" and leave the rest of the address exposed.
//   * Literals are word-boundary matched. A bare-substring literal "Jane"
//     would rewrite "JaneAdapter" throughout a codebase. Literals whose edges
//     are not word characters get no boundary on that side, so "+1-555-..."
//     still matches.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const RULES_PATH = path.join(__dirname, '..', 'redact-rules.json');
const PROBE_TIMEOUT_MS = 500;

// The values shipped in the template. Matching these would redact the literal
// word "Your" out of every file, so they are ignored until replaced.
const PLACEHOLDERS = new Set([
  'your full name',
  'your.email@example.com',
  '+1-555-000-0000',
  'your street address',
]);

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function boundedLiteral(literal) {
  const pre = /^\w/.test(literal) ? '(?<!\\w)' : '';
  const post = /\w$/.test(literal) ? '(?!\\w)' : '';
  return pre + escapeRegex(literal) + post;
}

// A catastrophic regex never returns, so it cannot be timed in-process -- the
// proxy would hang at startup. Run it in a child with a hard timeout instead.
// One-off cost at load: ~50ms per pattern.
function isPatternSafe(source, flags) {
  try {
    new RegExp(source, flags);
  } catch (e) {
    return { ok: false, why: `invalid regex: ${e.message}` };
  }

  const probe = [
    'const re = new RegExp(process.argv[1], process.argv[2]);',
    'const probes = [',
    "  'a'.repeat(60) + '!', '1'.repeat(60) + 'x', 'ab'.repeat(30) + '!',",
    "  '('.repeat(60), ' '.repeat(60), 'a1'.repeat(30) + '@',",
    '];',
    'for (const p of probes) { re.lastIndex = 0; re.test(p); }',
  ].join('\n');

  try {
    execFileSync(process.execPath, ['-e', probe, source, flags], {
      timeout: PROBE_TIMEOUT_MS,
      stdio: 'ignore',
    });
    return { ok: true };
  } catch (e) {
    if (e.killed || e.code === 'ETIMEDOUT' || e.signal) {
      return {
        ok: false,
        why: `pattern exceeded ${PROBE_TIMEOUT_MS}ms on adversarial input: catastrophic backtracking`,
      };
    }
    return { ok: false, why: e.message };
  }
}

function compile(rules, warn = () => {}) {
  const buckets = new Map();
  let n = 0;

  const add = (insensitive, source, label) => {
    const flags = insensitive ? 'gi' : 'g';
    let b = buckets.get(flags);
    if (!b) {
      b = { parts: [], labels: {} };
      buckets.set(flags, b);
    }
    const name = `r${n++}`;
    b.parts.push(`(?<${name}>${source})`);
    b.labels[name] = label;
  };

  // Patterns FIRST -- see the header note on alternation order.
  for (const p of rules.patterns || []) {
    if (!p || typeof p.regex !== 'string') continue;
    const verdict = isPatternSafe(p.regex, p.flags || 'g');
    if (!verdict.ok) {
      warn(`pattern "${p.name || '?'}" disabled: ${verdict.why}`);
      continue;
    }
    add(/i/.test(p.flags || ''), p.regex, p.name || 'pattern');
  }

  const literals = [];
  for (const entry of rules.literals || []) {
    const value = typeof entry === 'string' ? entry : entry && entry.value;
    if (typeof value !== 'string') continue;
    const v = value.trim();
    if (v.length < 3 || PLACEHOLDERS.has(v.toLowerCase())) continue;
    const boundary = typeof entry === 'string' ? true : entry.boundary !== false;
    literals.push({ v, boundary });
  }
  // Longest first, so "Jane Smith" wins over a bare "Jane".
  literals.sort((a, b) => b.v.length - a.v.length);
  for (const l of literals) {
    add(true, l.boundary ? boundedLiteral(l.v) : escapeRegex(l.v), 'personal');
  }

  const regexes = [];
  for (const [flags, b] of buckets) {
    try {
      regexes.push({ re: new RegExp(b.parts.join('|'), flags), labels: b.labels });
    } catch (e) {
      warn(`combined regex for flags "${flags}" failed to compile: ${e.message}`);
    }
  }

  return { regexes, literalCount: literals.length };
}

function load(rulesPath = RULES_PATH) {
  return JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
}

module.exports = { load, compile, isPatternSafe, boundedLiteral, RULES_PATH };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/rules.test.js`
Expected: PASS, 10 tests

- [ ] **Step 5: Verify the user's real rules compile cleanly**

Run: `node -e "const r=require('./proxy/rules');const w=[];const c=r.compile(r.load(),m=>w.push(m));console.log('regexes',c.regexes.length,'literals',c.literalCount,'warnings',w)"`
Expected: `regexes 2 literals 7 warnings []`

- [ ] **Step 6: Commit**

```bash
git add proxy/rules.js proxy/test/rules.test.js
git commit -m "feat(proxy): rules compiler with word boundaries and backtracking screen"
```

---

### Task 3: Span-tracking redactor

Produces redacted text **plus an offset map**. Phase 1 only needs the text, but the span map is what Phase 2's derived resolution depends on, and building it now means the redaction path is written once.

Matches from all compiled regexes are collected against the **original** text and overlaps resolved, rather than applying regexes sequentially to each other's output. That prevents double-redaction and preserves pattern-before-literal priority.

**Files:**
- Create: `proxy/spans.js`
- Create: `proxy/test/spans.test.js`

**Interfaces:**
- Consumes: `compile()` output from Task 2 (`{ regexes, labels }`).
- Produces:
  - `makeLabel(kLabel: Buffer, category: string, value: string) -> string`
  - `redactWithSpans(text: string, compiled: object, kLabel: Buffer) -> { text: string, spans: Array<{realStart, realEnd, redStart, redEnd, value, category}>, counts: Record<string, number> }`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/spans.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile } = require('../rules');
const { redactWithSpans, makeLabel } = require('../spans');

const K = Buffer.alloc(32, 9);
const RULES = compile({
  literals: ['Jane Q. Testerson', 'Jane'],
  patterns: [
    { name: 'email', regex: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', flags: 'gi' },
    { name: 'phone', regex: '(?<![\\d.])\\d{3}[ .-]\\d{3}[ .-]\\d{4}(?![\\d.])', flags: 'g' },
  ],
});

const red = (s) => redactWithSpans(s, RULES, K);

test('label is deterministic and correctly shaped', () => {
  const a = makeLabel(K, 'email', 'x@y.com');
  assert.match(a, /^\[PII:email:[0-9a-f]{16}\]$/);
  assert.strictEqual(a, makeLabel(K, 'email', 'x@y.com'));
});

test('a different key yields a different label', () => {
  assert.notStrictEqual(
    makeLabel(K, 'email', 'x@y.com'),
    makeLabel(Buffer.alloc(32, 1), 'email', 'x@y.com')
  );
});

test('redacts and records an accurate span', () => {
  const r = red('owner: Jane Q. Testerson done');
  assert.strictEqual(r.spans.length, 1);
  const s = r.spans[0];
  assert.strictEqual(s.value, 'Jane Q. Testerson');
  assert.strictEqual('owner: Jane Q. Testerson done'.slice(s.realStart, s.realEnd), s.value);
  assert.strictEqual(r.text.slice(s.redStart, s.redEnd), makeLabel(K, 'personal', s.value));
});

test('broad pattern beats a short literal on overlap', () => {
  const r = red('mail jane.test@example.org now');
  assert.strictEqual(r.spans.length, 1);
  assert.strictEqual(r.spans[0].category, 'email');
  assert.ok(!r.text.includes('test@example.org'));
});

test('leaves ordinary numbers alone', () => {
  for (const s of [
    'const id = 1234567890;',
    'version 2.10.1234567890',
    'IPv4 192.168.100.1000',
    'sha 9f8e7d6c5b4a39281706',
  ]) {
    assert.strictEqual(red(s).text, s, s);
  }
});

test('spans survive multi-byte characters before a match', () => {
  const text = 'héllo → Jane Q. Testerson';
  const r = red(text);
  const s = r.spans[0];
  assert.strictEqual(text.slice(s.realStart, s.realEnd), 'Jane Q. Testerson');
});

test('handles a match at position 0 and at end of input', () => {
  const r = red('Jane Q. Testerson');
  assert.strictEqual(r.spans.length, 1);
  assert.strictEqual(r.spans[0].realStart, 0);
  assert.strictEqual(r.spans[0].realEnd, 17);
  assert.strictEqual(r.text, makeLabel(K, 'personal', 'Jane Q. Testerson'));
});

test('handles adjacent matches', () => {
  const r = red('Jane Q. Testerson Jane Q. Testerson');
  assert.strictEqual(r.spans.length, 2);
  assert.ok(r.spans[0].realEnd < r.spans[1].realStart);
});

test('counts by category', () => {
  const r = red('a@b.com c@d.com call 555-123-4567');
  assert.deepStrictEqual(r.counts, { email: 2, phone: 1 });
});

test('property: every span slice equals its recorded value', () => {
  const frags = ['Jane Q. Testerson', 'x@y.co', '555-123-4567', 'plain', ' ', '42', 'é→'];
  for (let i = 0; i < 200; i++) {
    let text = '';
    const n = 1 + (i % 7);
    for (let j = 0; j < n; j++) text += frags[(i * 7 + j * 3) % frags.length] + ' ';
    const r = red(text);
    for (const s of r.spans) {
      assert.strictEqual(text.slice(s.realStart, s.realEnd), s.value);
      assert.strictEqual(r.text.slice(s.redStart, s.redEnd), makeLabel(K, s.category, s.value));
    }
  }
});

test('redacting twice is a no-op', () => {
  const once = red('owner jane@x.com').text;
  assert.strictEqual(red(once).text, once);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/spans.test.js`
Expected: FAIL — `Cannot find module '../spans'`

- [ ] **Step 3: Write the implementation**

Create `proxy/spans.js`:

```js
'use strict';

// Redaction that also reports WHERE it redacted.
//
// Matches from every compiled regex are gathered against the ORIGINAL text and
// overlaps resolved, rather than applying regexes one after another to each
// other's output. Two reasons: no double-redaction, and the span offsets stay
// meaningful relative to the real text -- which is what Phase 2's derived
// resolution needs in order to translate an edit back onto the real file.

const crypto = require('crypto');

function makeLabel(kLabel, category, value) {
  const mac = crypto
    .createHmac('sha256', kLabel)
    .update(value, 'utf8')
    .digest('hex')
    .slice(0, 16);
  return `[PII:${category}:${mac}]`;
}

function labelOf(match, labels) {
  const groups = match.groups;
  if (groups) {
    for (const name of Object.keys(groups)) {
      if (groups[name] !== undefined) return labels[name];
    }
  }
  return 'personal';
}

function redactWithSpans(text, compiled, kLabel) {
  const found = [];

  for (const { re, labels } of compiled.regexes || []) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++; // guard against zero-width loops
        continue;
      }
      found.push({
        start: m.index,
        end: m.index + m[0].length,
        value: m[0],
        category: labelOf(m, labels),
      });
    }
  }

  if (found.length === 0) return { text, spans: [], counts: {} };

  // Earliest first; on a tie the longest wins, which is what makes a broad
  // category pattern beat a short literal starting at the same offset.
  found.sort((a, b) => a.start - b.start || b.end - a.end);

  const spans = [];
  const counts = {};
  let out = '';
  let cursor = 0;

  for (const f of found) {
    if (f.start < cursor) continue; // overlaps an already-accepted match
    const label = makeLabel(kLabel, f.category, f.value);
    out += text.slice(cursor, f.start);
    const redStart = out.length;
    out += label;
    spans.push({
      realStart: f.start,
      realEnd: f.end,
      redStart,
      redEnd: out.length,
      value: f.value,
      category: f.category,
    });
    counts[f.category] = (counts[f.category] || 0) + 1;
    cursor = f.end;
  }
  out += text.slice(cursor);

  return { text: out, spans, counts };
}

module.exports = { redactWithSpans, makeLabel };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/spans.test.js`
Expected: PASS, 11 tests

- [ ] **Step 5: Commit**

```bash
git add proxy/spans.js proxy/test/spans.test.js
git commit -m "feat(proxy): span-tracking redactor with HMAC-keyed labels"
```

---

### Task 4: Bidirectional identity aliases

Aliases are the only reversible transform in the system. They exist because a `[PII:...]` label inside a path would break every tool — the path would not exist on disk — whereas `C:\Users\anon\...` still looks like a path the model can reason about.

Matching is case-insensitive and separator-agnostic, because Windows paths arrive in both `\` and `/` forms and in mixed case.

**Files:**
- Create: `proxy/aliases.js`
- Create: `proxy/test/aliases.test.js`
- Modify: `redact-rules.json` (add the `aliases` block)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `compileAliases(list: Array<{real: string, alias: string}>) -> Array<{real, alias, toAlias: RegExp, toReal: RegExp}>`
  - `toAlias(text: string, compiled) -> { text: string, count: number }`
  - `toReal(text: string, compiled) -> { text: string, count: number }`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/aliases.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compileAliases, toAlias, toReal } = require('../aliases');

const A = compileAliases([
  { real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' },
  { real: 'work\\AcmeCorp', alias: 'work\\clientA' },
  { real: 'MYBOX', alias: 'host' },
]);

test('replaces the real identity with the alias', () => {
  const r = toAlias('open C:\\Users\\SOMEONE\\Desktop\\a.js', A);
  assert.strictEqual(r.text, 'open C:\\Users\\anon\\Desktop\\a.js');
  assert.strictEqual(r.count, 1);
});

test('reverses the alias back to the real identity', () => {
  assert.strictEqual(
    toReal('open C:\\Users\\anon\\Desktop\\a.js', A).text,
    'open C:\\Users\\SOMEONE\\Desktop\\a.js'
  );
});

test('round trip is lossless', () => {
  const original = 'C:\\Users\\SOMEONE\\work\\AcmeCorp\\src on MYBOX';
  assert.strictEqual(toReal(toAlias(original, A).text, A).text, original);
});

test('matches case-insensitively', () => {
  assert.strictEqual(
    toAlias('c:\\users\\someone\\x', A).text,
    'C:\\Users\\anon\\x'
  );
});

test('matches forward-slash paths too', () => {
  // Only the matched prefix is normalized to the configured form; separators
  // after it are left as they were. Windows resolves mixed separators fine,
  // and the reverse regex is separator-agnostic, so this still round-trips.
  assert.strictEqual(toAlias('C:/Users/SOMEONE/x', A).text, 'C:\\Users\\anon/x');
  assert.strictEqual(toReal(toAlias('C:/Users/SOMEONE/x', A).text, A).text, 'C:\\Users\\SOMEONE/x');
});

test('longer aliases are applied first', () => {
  const B = compileAliases([
    { real: 'C:\\Users\\SOMEONE\\work', alias: 'W' },
    { real: 'C:\\Users\\SOMEONE', alias: 'U' },
  ]);
  assert.strictEqual(toAlias('C:\\Users\\SOMEONE\\work\\x', B).text, 'W\\x');
});

test('text with no identity is unchanged and counts zero', () => {
  const r = toAlias('nothing here', A);
  assert.strictEqual(r.text, 'nothing here');
  assert.strictEqual(r.count, 0);
});

test('entries that are too short or malformed are dropped', () => {
  const C = compileAliases([{ real: 'ab', alias: 'x' }, { real: 'ok' }, null]);
  assert.strictEqual(C.length, 0);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/aliases.test.js`
Expected: FAIL — `Cannot find module '../aliases'`

- [ ] **Step 3: Write the implementation**

Create `proxy/aliases.js`:

```js
'use strict';

// Static bidirectional identity aliases: OS username, hostname, project roots.
//
// Deliberately narrow. This is the only reverse transform in the system, and
// every entry added here is something that can be turned back into real data,
// so it covers only identifiers that MUST round-trip for tools to work.
//
// Matching is case-insensitive and separator-agnostic, because Windows paths
// arrive as both C:\Users\SOMEONE and c:/users/someone. Replacements normalize to the
// configured form, which keeps the output a valid path.

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Treat any run of slashes or backslashes as interchangeable.
function separatorAgnostic(s) {
  return s
    .split(/[\\/]+/)
    .map(escapeRegex)
    .join('[\\\\/]+');
}

function compileAliases(list) {
  return (list || [])
    .filter(
      (a) =>
        a &&
        typeof a.real === 'string' &&
        typeof a.alias === 'string' &&
        a.real.trim().length >= 3 &&
        a.alias.trim().length >= 1
    )
    // Longest real value first, so a nested root is aliased before its parent.
    .sort((a, b) => b.real.length - a.real.length)
    .map((a) => ({
      real: a.real,
      alias: a.alias,
      toAlias: new RegExp(separatorAgnostic(a.real), 'gi'),
      toReal: new RegExp(separatorAgnostic(a.alias), 'gi'),
    }));
}

function replaceAll(text, compiled, fromKey, toKey) {
  let out = text;
  let count = 0;
  for (const a of compiled) {
    out = out.replace(a[fromKey], () => {
      count++;
      return a[toKey];
    });
  }
  return { text: out, count };
}

const toAlias = (text, compiled) => replaceAll(text, compiled, 'toAlias', 'alias');
const toReal = (text, compiled) => replaceAll(text, compiled, 'toReal', 'real');

module.exports = { compileAliases, toAlias, toReal };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/aliases.test.js`
Expected: PASS, 8 tests

- [ ] **Step 5: Add the aliases block to the live config**

Add to `redact-rules.json`, as a sibling of `literals` (replace `<HOSTNAME>` with the output of `hostname`):

```json
  "aliases": [
    { "real": "C:\\Users\\SOMEONE", "alias": "C:\\Users\\anon" },
    { "real": "<HOSTNAME>", "alias": "host" }
  ],
  "proxy": { "port": 47113 }
```

Run: `hostname` to get the value, then verify the file still parses:
`node -e "console.log(require('./redact-rules.json').aliases.length)"`
Expected: `2`

- [ ] **Step 6: Commit**

```bash
git add proxy/aliases.js proxy/test/aliases.test.js redact-rules.json
git commit -m "feat(proxy): bidirectional identity aliases for username and hostname"
```

---

### Task 5: Outbound body walker with per-block memoization

Walks only the fields that carry user data, and memoizes per message block. Memoization is what keeps this viable at 1M context: the conversation is re-uploaded every turn, so without it a 4 MB body costs ~400 ms per turn; with it, only new blocks are transformed.

**Files:**
- Create: `proxy/walk.js`
- Create: `proxy/test/walk.test.js`

**Interfaces:**
- Consumes: `redactWithSpans` (Task 3), `toAlias`/`compileAliases` (Task 4), `compile` (Task 2).
- Produces:
  - `makeContext({kLabel, kMemo, rules, aliases, memoMax?}) -> ctx` (ctx carries `stats` and `memo`)
  - `transformBody(body: object, ctx) -> object` (new object; input untouched)
  - `resetStats(ctx) -> void`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/walk.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile } = require('../rules');
const { compileAliases } = require('../aliases');
const { makeContext, transformBody, resetStats } = require('../walk');

function ctx() {
  return makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: ['Jane Q. Testerson'], patterns: [] }),
    aliases: compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]),
  });
}

test('redacts messages given as a bare string', () => {
  const out = transformBody(
    { messages: [{ role: 'user', content: 'hi Jane Q. Testerson' }] },
    ctx()
  );
  assert.match(out.messages[0].content, /\[PII:personal:[0-9a-f]{16}\]/);
});

test('redacts messages given as a block array', () => {
  const out = transformBody(
    {
      messages: [
        { role: 'user', content: [{ type: 'text', text: 'hi Jane Q. Testerson' }] },
      ],
    },
    ctx()
  );
  assert.match(out.messages[0].content[0].text, /\[PII:personal:/);
});

test('redacts tool_result content and tool_use input', () => {
  const out = transformBody(
    {
      messages: [
        {
          role: 'user',
          content: [{ type: 'tool_result', content: 'owner Jane Q. Testerson' }],
        },
        {
          role: 'assistant',
          content: [
            { type: 'tool_use', name: 'Edit', input: { old_string: 'Jane Q. Testerson' } },
          ],
        },
      ],
    },
    ctx()
  );
  assert.match(out.messages[0].content[0].content, /\[PII:personal:/);
  assert.match(out.messages[1].content[0].input.old_string, /\[PII:personal:/);
});

test('aliases paths in system text', () => {
  const out = transformBody(
    { system: [{ type: 'text', text: 'cwd is C:\\Users\\SOMEONE\\proj' }] },
    ctx()
  );
  assert.strictEqual(out.system[0].text, 'cwd is C:\\Users\\anon\\proj');
});

test('leaves tools untouched byte for byte', () => {
  const tools = [{ name: 'Edit', description: 'edit C:\\Users\\SOMEONE and Jane Q. Testerson' }];
  const out = transformBody({ tools, messages: [] }, ctx());
  assert.deepStrictEqual(out.tools, tools);
});

test('leaves signed thinking blocks untouched byte for byte', () => {
  const block = {
    role: 'assistant',
    content: [
      { type: 'thinking', thinking: 'about Jane Q. Testerson', signature: 'sig' },
      { type: 'redacted_thinking', data: 'C:\\Users\\SOMEONE' },
    ],
  };
  const out = transformBody({ messages: [block] }, ctx());
  assert.deepStrictEqual(out.messages[0].content, block.content);
});

test('leaves metadata untouched', () => {
  const metadata = { user_id: '{"device_id":"abc"}' };
  const out = transformBody({ metadata, messages: [] }, ctx());
  assert.deepStrictEqual(out.metadata, metadata);
});

test('memoizes repeated blocks and matches non-memoized output', () => {
  const c = ctx();
  const block = { role: 'user', content: 'hi Jane Q. Testerson' };
  const first = transformBody({ messages: [block] }, c);
  resetStats(c);
  const second = transformBody({ messages: [block] }, c);
  assert.deepStrictEqual(second.messages[0], first.messages[0]);
  assert.strictEqual(c.stats.memoHit, 1);
  assert.strictEqual(c.stats.memoMiss, 0);
});

test('only new blocks are transformed as history grows', () => {
  const c = ctx();
  const history = [{ role: 'user', content: 'a Jane Q. Testerson' }];
  transformBody({ messages: history }, c);
  history.push({ role: 'assistant', content: 'b' });
  resetStats(c);
  transformBody({ messages: history }, c);
  assert.strictEqual(c.stats.memoHit, 1);
  assert.strictEqual(c.stats.memoMiss, 1);
});

test('memo store holds no plaintext personal data', () => {
  const c = ctx();
  transformBody({ messages: [{ role: 'user', content: 'Jane Q. Testerson' }] }, c);
  const dump = JSON.stringify([...c.memo.entries()]);
  assert.ok(!dump.includes('Jane Q. Testerson'));
});

test('does not mutate the input body', () => {
  const body = { messages: [{ role: 'user', content: 'Jane Q. Testerson' }] };
  const snapshot = JSON.stringify(body);
  transformBody(body, ctx());
  assert.strictEqual(JSON.stringify(body), snapshot);
});

test('identical bodies redact byte-identically (prompt caching depends on it)', () => {
  const body = {
    system: [{ type: 'text', text: 'cwd C:\\Users\\SOMEONE' }],
    messages: [{ role: 'user', content: 'Jane Q. Testerson' }],
  };
  // Separate contexts, so this proves determinism rather than memo reuse.
  const a = JSON.stringify(transformBody(body, ctx()));
  const b = JSON.stringify(transformBody(body, ctx()));
  assert.strictEqual(a, b);
});

test('memo evicts past memoMax', () => {
  const c = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }),
    aliases: [],
    memoMax: 2,
  });
  for (let i = 0; i < 5; i++) transformBody({ messages: [{ role: 'user', content: `m${i}` }] }, c);
  assert.ok(c.memo.size <= 2);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/walk.test.js`
Expected: FAIL — `Cannot find module '../walk'`

- [ ] **Step 3: Write the implementation**

Create `proxy/walk.js`:

```js
'use strict';

// Outbound body transform.
//
// Walks ONLY the fields that carry user data. `tools[]` is skipped because it is
// static product documentation and ~45% of the body -- skipping it is the single
// largest performance decision here. Signed thinking blocks are skipped because
// altering one byte invalidates their signature and the API rejects the request;
// that is safe, since the model only ever saw labels, so its thinking contains
// labels rather than personal data.
//
// Per-block memoization is what makes this scale. The whole conversation is
// re-uploaded every turn, so without it a 4MB body at 1M context costs ~400ms
// per turn. History is append-only and redaction is deterministic, so a block
// transformed last turn transforms identically this turn.

const crypto = require('crypto');
const { redactWithSpans } = require('./spans');
const { toAlias } = require('./aliases');

// Signed by the API; must travel byte-identical.
const SKIP_BLOCK_TYPES = new Set(['thinking', 'redacted_thinking']);

function freshStats() {
  return { counts: {}, aliased: 0, memoHit: 0, memoMiss: 0, walkedChars: 0 };
}

function makeContext({ kLabel, kMemo, rules, aliases, memoMax = 2000 }) {
  return {
    kLabel,
    kMemo,
    rules,
    aliases,
    memoMax,
    memo: new Map(),
    stats: freshStats(),
  };
}

function resetStats(ctx) {
  ctx.stats = freshStats();
}

function transformString(s, ctx) {
  ctx.stats.walkedChars += s.length;
  const r = redactWithSpans(s, ctx.rules, ctx.kLabel);
  for (const [k, v] of Object.entries(r.counts)) {
    ctx.stats.counts[k] = (ctx.stats.counts[k] || 0) + v;
  }
  const a = toAlias(r.text, ctx.aliases);
  ctx.stats.aliased += a.count;
  return a.text;
}

function transformNode(node, ctx) {
  if (typeof node === 'string') return transformString(node, ctx);
  if (Array.isArray(node)) return node.map((n) => transformNode(n, ctx));
  if (node && typeof node === 'object') {
    if (SKIP_BLOCK_TYPES.has(node.type)) return node;
    const out = {};
    for (const k of Object.keys(node)) out[k] = transformNode(node[k], ctx);
    return out;
  }
  return node;
}

// Keyed rather than plain hash: the key is derived from the master key, so the
// memo keys reveal nothing even though they are computed over raw content.
function memoKey(ctx, block) {
  return crypto
    .createHmac('sha256', ctx.kMemo)
    .update(JSON.stringify(block))
    .digest('hex');
}

function memoized(block, ctx) {
  const key = memoKey(ctx, block);
  if (ctx.memo.has(key)) {
    const hit = ctx.memo.get(key);
    ctx.memo.delete(key); // refresh LRU position
    ctx.memo.set(key, hit);
    ctx.stats.memoHit++;
    return hit;
  }
  ctx.stats.memoMiss++;
  const out = transformNode(block, ctx);
  ctx.memo.set(key, out);
  if (ctx.memo.size > ctx.memoMax) {
    ctx.memo.delete(ctx.memo.keys().next().value);
  }
  return out;
}

function transformBody(body, ctx) {
  const out = Object.assign({}, body);

  if (Array.isArray(body.system)) out.system = body.system.map((b) => memoized(b, ctx));
  else if (typeof body.system === 'string') out.system = memoized(body.system, ctx);

  if (Array.isArray(body.messages)) out.messages = body.messages.map((m) => memoized(m, ctx));

  // tools, metadata and everything else pass through untouched.
  return out;
}

module.exports = { makeContext, transformBody, resetStats, SKIP_BLOCK_TYPES };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/walk.test.js`
Expected: PASS, 13 tests

- [ ] **Step 5: Commit**

```bash
git add proxy/walk.js proxy/test/walk.test.js
git commit -m "feat(proxy): outbound body walker with per-block memoization"
```

---

### Task 6: SSE transformer with inbound alias reversal

The discovery pass confirmed **every** response is `text/event-stream`, so there is no non-streaming branch to write.

`tool_use` inputs arrive as `input_json_delta` fragments. An alias split across two fragments cannot be matched in isolation, so fragments are buffered per block index and emitted as one corrected delta at `content_block_stop`. `text_delta` is passed through untouched — deliberately, so the on-disk transcript inherits only labels.

**PII labels are NOT resolved here.** That is Phase 2.

**Files:**
- Create: `proxy/sse.js`
- Create: `proxy/test/sse.test.js`

**Interfaces:**
- Consumes: `toReal` (Task 4).
- Produces:
  - `createSseTransformer({aliases, stats}) -> { push(chunk: string) -> string, flush() -> string }`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/sse.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compileAliases } = require('../aliases');
const { createSseTransformer } = require('../sse');

const A = compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]);
const ev = (type, obj) => `event: ${type}\ndata: ${JSON.stringify(obj)}\n\n`;

function run(chunks) {
  const stats = { resolvedAliases: 0 };
  const t = createSseTransformer({ aliases: A, stats });
  let out = '';
  for (const c of chunks) out += t.push(c);
  out += t.flush();
  return { out, stats };
}

// Pull the emitted tool inputs out and PARSE them. Do not substring-match the
// raw stream: partial_json is JSON-escaped once inside the tool input and again
// by the enclosing event, so a path appears as C:\\\\Users\\\\SOMEONE and a naive
// includes() on C:\\Users\\SOMEONE fails even when the value is correct.
function toolInputs(out) {
  const inputs = [];
  for (const block of out.split('\n\n')) {
    const line = block.split('\n').find((l) => l.startsWith('data:'));
    if (!line) continue;
    let payload;
    try {
      payload = JSON.parse(line.slice(5).trim());
    } catch (e) {
      continue;
    }
    if (payload.delta && payload.delta.type === 'input_json_delta') {
      try {
        inputs.push(JSON.parse(payload.delta.partial_json));
      } catch (e) {
        inputs.push(payload.delta.partial_json);
      }
    }
  }
  return inputs;
}

test('text_delta passes through untouched', () => {
  const s = ev('content_block_delta', {
    type: 'content_block_delta',
    index: 0,
    delta: { type: 'text_delta', text: 'see C:\\Users\\anon\\x' },
  });
  assert.strictEqual(run([s]).out, s);
});

test('tool_use input is un-aliased at block stop', () => {
  const { out } = run([
    ev('content_block_start', {
      type: 'content_block_start',
      index: 0,
      content_block: { type: 'tool_use', id: 't1', name: 'Read', input: {} },
    }),
    ev('content_block_delta', {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: '{"file_path":"C:\\\\Users\\\\anon' },
    }),
    ev('content_block_delta', {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: '\\\\a.js"}' },
    }),
    ev('content_block_stop', { type: 'content_block_stop', index: 0 }),
  ]);
  assert.deepStrictEqual(toolInputs(out), [{ file_path: 'C:\\Users\\SOMEONE\\a.js' }]);
  assert.ok(!out.includes('anon'), out);
});

test('an alias split across two deltas is still reversed', () => {
  const { out } = run([
    ev('content_block_start', {
      type: 'content_block_start',
      index: 0,
      content_block: { type: 'tool_use', id: 't1', name: 'Read', input: {} },
    }),
    ev('content_block_delta', {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: '{"p":"C:\\\\Users\\\\an' },
    }),
    ev('content_block_delta', {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: 'on\\\\z"}' },
    }),
    ev('content_block_stop', { type: 'content_block_stop', index: 0 }),
  ]);
  assert.ok(out.includes('SOMEONE'), out);
});

test('two concurrent tool_use blocks stay separate', () => {
  const { out } = run([
    ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'Read', input: {} } }),
    ev('content_block_start', { type: 'content_block_start', index: 1, content_block: { type: 'tool_use', name: 'Read', input: {} } }),
    ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"a":"C:\\\\Users\\\\anon"}' } }),
    ev('content_block_delta', { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: '{"b":"plain"}' } }),
    ev('content_block_stop', { type: 'content_block_stop', index: 1 }),
    ev('content_block_stop', { type: 'content_block_stop', index: 0 }),
  ]);
  const got = toolInputs(out);
  assert.ok(got.some((i) => i.b === 'plain'), JSON.stringify(got));
  assert.ok(got.some((i) => i.a === 'C:\\Users\\SOMEONE'), JSON.stringify(got));
});

test('mcp__ tool inputs are NOT un-aliased', () => {
  const { out } = run([
    ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'mcp__zen__chat', input: {} } }),
    ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"p":"C:\\\\Users\\\\anon\\\\x"}' } }),
    ev('content_block_stop', { type: 'content_block_stop', index: 0 }),
  ]);
  assert.ok(out.includes('anon'), out);
  assert.ok(!out.includes('SOMEONE'), out);
});

test('malformed event data is forwarded unchanged', () => {
  const bad = 'event: x\ndata: {not json\n\n';
  assert.strictEqual(run([bad]).out, bad);
});

test('events split mid-line across chunks are reassembled', () => {
  const s = ev('message_stop', { type: 'message_stop' });
  const mid = Math.floor(s.length / 2);
  assert.strictEqual(run([s.slice(0, mid), s.slice(mid)]).out, s);
});

test('unterminated trailing data is emitted by flush', () => {
  const t = createSseTransformer({ aliases: A, stats: {} });
  assert.strictEqual(t.push('event: partial\ndata: {}'), '');
  assert.strictEqual(t.flush(), 'event: partial\ndata: {}');
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/sse.test.js`
Expected: FAIL — `Cannot find module '../sse'`

- [ ] **Step 3: Write the implementation**

Create `proxy/sse.js`:

```js
'use strict';

// Inbound SSE transform.
//
// Only one thing happens here in Phase 1: reversing identity aliases inside
// tool_use inputs, so tools receive real paths. PII label resolution is Phase 2.
//
// tool_use inputs arrive as a sequence of input_json_delta fragments. An alias
// can be split across two fragments, where it cannot be matched at all, so
// fragments are held per block index and emitted as ONE corrected delta at
// content_block_stop. Buffering to the block boundary removes every
// partial-match edge case.
//
// text_delta is passed through untouched on purpose: Claude's prose keeps its
// labels, which means the on-disk transcript inherits no personal data.

const { toReal } = require('./aliases');

// MCP tools keep the alias -- a third-party server has no business learning the
// real username, and cannot use a local path anyway.
function shouldUnalias(toolName) {
  return typeof toolName === 'string' && !toolName.startsWith('mcp__');
}

// Un-alias by parsing the accumulated JSON and walking its string values --
// NEVER by string-replacing in the raw JSON text. A real path contains single
// backslashes, which are invalid unescaped inside a JSON string literal, so a
// raw replacement would emit `"C:\Users\SOMEONE"` and corrupt the payload.
function unaliasNode(node, aliases, stats) {
  if (typeof node === 'string') {
    const r = toReal(node, aliases);
    stats.resolvedAliases = (stats.resolvedAliases || 0) + r.count;
    return r.text;
  }
  if (Array.isArray(node)) return node.map((n) => unaliasNode(n, aliases, stats));
  if (node && typeof node === 'object') {
    const out = {};
    for (const k of Object.keys(node)) out[k] = unaliasNode(node[k], aliases, stats);
    return out;
  }
  return node;
}

function createSseTransformer({ aliases, stats = {} }) {
  let buf = '';
  const blocks = new Map(); // index -> { name, json }

  function emitEvent(rawEvent) {
    const dataLines = [];
    for (const line of rawEvent.split('\n')) {
      if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
    }
    if (dataLines.length === 0) return rawEvent;

    let payload;
    try {
      payload = JSON.parse(dataLines.join('\n'));
    } catch (e) {
      return rawEvent; // not ours to understand; forward verbatim
    }

    const idx = payload.index;

    if (payload.type === 'content_block_start') {
      const cb = payload.content_block || {};
      if (cb.type === 'tool_use') blocks.set(idx, { name: cb.name, json: '' });
      return rawEvent;
    }

    if (
      payload.type === 'content_block_delta' &&
      payload.delta &&
      payload.delta.type === 'input_json_delta' &&
      blocks.has(idx)
    ) {
      blocks.get(idx).json += payload.delta.partial_json || '';
      return ''; // held until the block closes
    }

    if (payload.type === 'content_block_stop' && blocks.has(idx)) {
      const block = blocks.get(idx);
      blocks.delete(idx);
      let json = block.json;
      if (shouldUnalias(block.name)) {
        try {
          json = JSON.stringify(unaliasNode(JSON.parse(json), aliases, stats));
        } catch (e) {
          // Incomplete or non-JSON accumulation: forward as-is rather than
          // risk corrupting the tool input.
        }
      }
      const delta = {
        type: 'content_block_delta',
        index: idx,
        delta: { type: 'input_json_delta', partial_json: json },
      };
      return (
        `event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n` + rawEvent
      );
    }

    return rawEvent;
  }

  return {
    push(chunk) {
      buf += chunk;
      let out = '';
      let i;
      while ((i = buf.indexOf('\n\n')) !== -1) {
        const rawEvent = buf.slice(0, i + 2);
        buf = buf.slice(i + 2);
        out += emitEvent(rawEvent);
      }
      return out;
    },
    flush() {
      const rest = buf;
      buf = '';
      return rest;
    },
  };
}

module.exports = { createSseTransformer, shouldUnalias };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/sse.test.js`
Expected: PASS, 8 tests

- [ ] **Step 5: Commit**

```bash
git add proxy/sse.js proxy/test/sse.test.js
git commit -m "feat(proxy): SSE transformer with inbound alias reversal"
```

---

### Task 7: Audit log

Counts only, never values, never credentials. This is how a literal that fires too aggressively gets noticed.

**Files:**
- Create: `proxy/audit.js`
- Create: `proxy/test/audit.test.js`

**Interfaces:**
- Consumes: `stats` shape from Task 5 (`{counts, aliased, memoHit, memoMiss, walkedChars}`).
- Produces:
  - `formatLine({method, url, bytes, stats, resolvedAliases}) -> string`
  - `createLogger(logPath: string) -> { line(entry: object): void, warn(msg: string): void }`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/audit.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { formatLine } = require('../audit');

test('renders counts, never values', () => {
  const line = formatLine({
    method: 'POST',
    url: '/v1/messages?beta=true',
    bytes: 94705,
    stats: { counts: { email: 3, phone: 1 }, aliased: 7, memoHit: 41, memoMiss: 2, walkedChars: 30100 },
    resolvedAliases: 2,
  });
  assert.match(line, /POST \/v1\/messages/);
  assert.match(line, /body=92\.5KB/);
  assert.match(line, /walked=29\.4KB/);
  assert.match(line, /memo=41\/43/);
  assert.match(line, /email=3/);
  assert.match(line, /phone=1/);
  assert.match(line, /aliased=7/);
  assert.match(line, /unaliased=2/);
});

test('renders a clean line when nothing was found', () => {
  const line = formatLine({
    method: 'HEAD',
    url: '/api/hello',
    bytes: 0,
    stats: { counts: {}, aliased: 0, memoHit: 0, memoMiss: 0, walkedChars: 0 },
    resolvedAliases: 0,
  });
  assert.match(line, /HEAD \/api\/hello/);
  assert.match(line, /redacted=none/);
});

test('never contains anything that looks like a credential', () => {
  const line = formatLine({
    method: 'POST',
    url: '/v1/messages',
    bytes: 10,
    stats: { counts: { email: 1 }, aliased: 0, memoHit: 0, memoMiss: 1, walkedChars: 10 },
    resolvedAliases: 0,
  });
  assert.ok(!/sk-|x-api-key|authorization|bearer/i.test(line));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/audit.test.js`
Expected: FAIL — `Cannot find module '../audit'`

- [ ] **Step 3: Write the implementation**

Create `proxy/audit.js`:

```js
'use strict';

// Per-request audit line. Counts only -- never values, never credentials.
// Under-redaction and over-redaction are both invisible without this.

const fs = require('fs');

const kb = (n) => `${(n / 1024).toFixed(1)}KB`;

function formatLine({ method, url, bytes, stats, resolvedAliases = 0 }) {
  const s = stats || {};
  const counts = s.counts || {};
  const cats = Object.keys(counts).sort();
  const redacted = cats.length ? cats.map((c) => `${c}=${counts[c]}`).join(' ') : 'redacted=none';
  const total = (s.memoHit || 0) + (s.memoMiss || 0);
  const t = new Date().toISOString().slice(11, 19);
  return (
    `[${t}] ${method} ${url} body=${kb(bytes)} walked=${kb(s.walkedChars || 0)} ` +
    `memo=${s.memoHit || 0}/${total} | ${redacted} ` +
    `aliased=${s.aliased || 0} unaliased=${resolvedAliases}`
  );
}

function createLogger(logPath) {
  const write = (text) => {
    try {
      fs.appendFileSync(logPath, text + '\n');
    } catch (e) {
      /* logging must never break a request */
    }
    process.stdout.write(text + '\n');
  };
  return {
    line: (entry) => write(formatLine(entry)),
    warn: (msg) => write(`[warn] ${msg}`),
  };
}

module.exports = { formatLine, createLogger };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/audit.test.js`
Expected: PASS, 3 tests

- [ ] **Step 5: Commit**

```bash
git add proxy/audit.js proxy/test/audit.test.js
git commit -m "feat(proxy): audit log with counts only"
```

---

### Task 8: The proxy server

Binds loopback, forwards everything, transforms only `POST /v1/messages*`. Anything it does not understand is a transparent pipe — including the `HEAD /api/hello` preflight the discovery pass observed.

**Files:**
- Create: `proxy/server.js`
- Create: `proxy/start.js`
- Create: `proxy/test/server.test.js`

**Interfaces:**
- Consumes: everything from Tasks 1–7.
- Produces:
  - `createServer({ctx, aliases, logger, upstream?, upstreamPort?}) -> http.Server`
  - `start() -> Promise<http.Server>` (from `start.js`, wires real keys, rules and config)

- [ ] **Step 1: Write the failing test**

Create `proxy/test/server.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { compile } = require('../rules');
const { compileAliases } = require('../aliases');
const { makeContext } = require('../walk');
const { createServer } = require('../server');

function fakeUpstream(onReq) {
  const s = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => onReq(req, Buffer.concat(chunks), res));
  });
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r(s)));
}

function startProxy(upstreamPort) {
  const ctx = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: ['Jane Q. Testerson'], patterns: [] }),
    aliases: compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]),
  });
  const logger = { line: () => {}, warn: () => {} };
  const srv = createServer({
    ctx,
    aliases: ctx.aliases,
    logger,
    upstream: '127.0.0.1',
    upstreamPort,
    insecure: true,
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv)));
}

function post(port, path, body) {
  return new Promise((resolve) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json' } },
      (res) => {
        const c = [];
        res.on('data', (d) => c.push(d));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString() }));
      }
    );
    req.end(body);
  });
}

test('binds loopback only', async () => {
  const up = await fakeUpstream((r, b, res) => res.end('ok'));
  const proxy = await startProxy(up.address().port);
  assert.strictEqual(proxy.address().address, '127.0.0.1');
  proxy.close();
  up.close();
});

test('redacts the body before it reaches upstream', async () => {
  let seen = null;
  const up = await fakeUpstream((r, b, res) => {
    seen = b.toString();
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n');
  });
  const proxy = await startProxy(up.address().port);
  await post(
    proxy.address().port,
    '/v1/messages?beta=true',
    JSON.stringify({ messages: [{ role: 'user', content: 'hi Jane Q. Testerson at C:\\Users\\SOMEONE' }] })
  );
  assert.ok(!seen.includes('Jane Q. Testerson'), seen);
  assert.ok(!seen.includes('SOMEONE'), seen);
  assert.match(seen, /\[PII:personal:/);
  assert.ok(seen.includes('anon'));
  proxy.close();
  up.close();
});

test('non-/v1/messages paths pass through unmodified', async () => {
  let seen = null;
  const up = await fakeUpstream((r, b, res) => {
    seen = b.toString();
    res.end('ok');
  });
  const proxy = await startProxy(up.address().port);
  const raw = JSON.stringify({ note: 'Jane Q. Testerson' });
  await post(proxy.address().port, '/v1/other', raw);
  assert.strictEqual(seen, raw);
  proxy.close();
  up.close();
});

test('un-aliases tool_use input on the way back', async () => {
  const up = await fakeUpstream((r, b, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    const start = { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'Read', input: {} } };
    const delta = { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"file_path":"C:\\\\Users\\\\anon\\\\a.js"}' } };
    const stop = { type: 'content_block_stop', index: 0 };
    res.end(
      `event: content_block_start\ndata: ${JSON.stringify(start)}\n\n` +
        `event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n` +
        `event: content_block_stop\ndata: ${JSON.stringify(stop)}\n\n`
    );
  });
  const proxy = await startProxy(up.address().port);
  const r = await post(proxy.address().port, '/v1/messages', JSON.stringify({ messages: [] }));
  assert.ok(r.body.includes('SOMEONE'), r.body);
  proxy.close();
  up.close();
});

test('a malformed body is forwarded unmodified', async () => {
  let seen = null;
  const up = await fakeUpstream((r, b, res) => {
    seen = b.toString();
    res.end('ok');
  });
  const proxy = await startProxy(up.address().port);
  await post(proxy.address().port, '/v1/messages', '{not json');
  assert.strictEqual(seen, '{not json');
  proxy.close();
  up.close();
});

test('/_health answers without contacting upstream', async () => {
  const up = await fakeUpstream(() => assert.fail('should not be called'));
  const proxy = await startProxy(up.address().port);
  const r = await new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port: proxy.address().port, path: '/_health' }, (res) => {
      const c = [];
      res.on('data', (d) => c.push(d));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString() }));
    });
  });
  assert.strictEqual(r.status, 200);
  assert.match(r.body, /"ok":true/);
  proxy.close();
  up.close();
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/server.test.js`
Expected: FAIL — `Cannot find module '../server'`

- [ ] **Step 3: Write the server**

Create `proxy/server.js`:

```js
'use strict';

// The proxy. Binds loopback, forwards everything, transforms only
// POST /v1/messages*.
//
// Loopback binding is a hard requirement, not a default: this accepts
// unauthenticated plaintext HTTP and forwards it with the user's credentials
// attached, so exposing it on another interface would hand anyone on the
// network an authenticated channel to the API.

const http = require('http');
const https = require('https');
const { transformBody, resetStats } = require('./walk');
const { createSseTransformer } = require('./sse');

const MESSAGES_PATH = /^\/v1\/messages/;

function createServer({
  ctx,
  aliases,
  logger,
  upstream = 'api.anthropic.com',
  upstreamPort = 443,
  insecure = false,
}) {
  const agent = insecure ? http : https;

  return http.createServer((req, res) => {
    if (req.url === '/_health') {
      const payload = JSON.stringify({ ok: true, pid: process.pid, memo: ctx.memo.size });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(payload);
      return;
    }

    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = Buffer.concat(chunks);
      const isMessages = req.method === 'POST' && MESSAGES_PATH.test(req.url);
      resetStats(ctx);

      if (isMessages && body.length) {
        try {
          const parsed = JSON.parse(body.toString('utf8'));
          body = Buffer.from(JSON.stringify(transformBody(parsed, ctx)), 'utf8');
        } catch (e) {
          // Fail open: a parse failure must never break the session.
          logger.warn(`body not transformed (${e.message}); forwarded unmodified`);
        }
      }

      const headers = Object.assign({}, req.headers, { host: upstream });
      delete headers['content-length'];
      if (body.length) headers['content-length'] = String(body.length);

      const sseStats = { resolvedAliases: 0 };
      const upstreamReq = agent.request(
        { hostname: upstream, port: upstreamPort, path: req.url, method: req.method, headers },
        (ur) => {
          const streaming = (ur.headers['content-type'] || '').includes('text/event-stream');
          res.writeHead(ur.statusCode, ur.headers);

          if (!streaming || !isMessages) {
            ur.pipe(res);
            ur.on('end', () =>
              logger.line({ method: req.method, url: req.url, bytes: body.length, stats: ctx.stats, resolvedAliases: 0 })
            );
            return;
          }

          const t = createSseTransformer({ aliases, stats: sseStats });
          ur.setEncoding('utf8');
          ur.on('data', (chunk) => {
            const outChunk = t.push(chunk);
            if (outChunk) res.write(outChunk);
          });
          ur.on('end', () => {
            const tail = t.flush();
            if (tail) res.write(tail);
            res.end();
            logger.line({
              method: req.method,
              url: req.url,
              bytes: body.length,
              stats: ctx.stats,
              resolvedAliases: sseStats.resolvedAliases,
            });
          });
        }
      );

      upstreamReq.on('error', (e) => {
        logger.warn(`upstream error: ${e.message}`);
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
        res.end('redaction proxy: upstream error');
      });

      if (body.length) upstreamReq.write(body);
      upstreamReq.end();
    });
  });
}

module.exports = { createServer, MESSAGES_PATH };
```

- [ ] **Step 4: Write the entry point**

Create `proxy/start.js`:

```js
#!/usr/bin/env node
'use strict';

// Entry point. Wires real keys, rules and config, then listens on loopback.

const path = require('path');
const os = require('os');
const { loadMaster, subkey } = require('./keys');
const { load, compile } = require('./rules');
const { compileAliases } = require('./aliases');
const { makeContext } = require('./walk');
const { createLogger } = require('./audit');
const { createServer } = require('./server');

const LOG_PATH = path.join(os.homedir(), '.claude', 'redact-proxy.log');

function start() {
  const logger = createLogger(LOG_PATH);

  // Fail closed on key problems: never fall back to unkeyed hashing.
  const master = loadMaster();
  const kLabel = subkey(master, 'label');
  const kMemo = subkey(master, 'memo');

  const rules = load();
  const compiled = compile(rules, (m) => logger.warn(m));
  const aliases = compileAliases(rules.aliases);
  const port = (rules.proxy && rules.proxy.port) || 47113;

  if (compiled.literalCount === 0) {
    logger.warn(
      'redact-rules.json has no effective literals; only category patterns will apply'
    );
  }
  if (aliases.length === 0) {
    logger.warn('no aliases configured; the OS username will appear in every request');
  }

  const ctx = makeContext({ kLabel, kMemo, rules: compiled, aliases });
  const server = createServer({ ctx, aliases, logger });

  server.listen(port, '127.0.0.1', () => {
    logger.warn(
      `listening on http://127.0.0.1:${port} -> https://api.anthropic.com ` +
        `(literals=${compiled.literalCount} patterns=${compiled.regexes.length} aliases=${aliases.length})`
    );
  });
  return server;
}

if (require.main === module) start();
module.exports = { start, LOG_PATH };
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `node --test proxy/test/server.test.js`
Expected: PASS, 6 tests

- [ ] **Step 6: Run the whole suite**

Run: `node --test proxy/test/*.test.js`
Expected: PASS, 64 tests total (keys 5, rules 10, spans 11, aliases 8, walk 13, sse 8, audit 3, server 6), 0 failures

- [ ] **Step 7: Commit**

```bash
git add proxy/server.js proxy/start.js proxy/test/server.test.js
git commit -m "feat(proxy): loopback server with outbound redaction and inbound un-aliasing"
```

---

### Task 9: Wire into Claude Code and verify end to end

Points Claude Code at the proxy, adds the liveness assertion, registers autostart, and proves the whole thing works against the real API.

**Files:**
- Create: `proxy/liveness-hook.js`
- Create: `proxy/install-autostart.ps1`
- Modify: `C:\Users\SOMEONE\.claude\settings.json`

**Interfaces:**
- Consumes: `/_health` (Task 8), `rules.proxy.port` (Task 4).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the liveness hook**

All enforcement sits in one process, so its absence must be loud. The dangerous case is not "proxy down" (that fails closed with a visible error) — it is `ANTHROPIC_BASE_URL` being unset, where everything appears to work and nothing is redacted.

Create `proxy/liveness-hook.js`:

```js
#!/usr/bin/env node
'use strict';

// SessionStart hook. Verifies Claude Code is actually routed through the proxy.
// Silent unprotected operation is the specific failure this guards against.

const http = require('http');
const { load } = require('./rules');

function emit(msg) {
  process.stdout.write(msg ? JSON.stringify({ systemMessage: msg }) : '{}');
  process.exit(0);
}

let port = 47113;
try {
  const r = load();
  if (r.proxy && r.proxy.port) port = r.proxy.port;
} catch (e) {
  /* fall back to the default */
}

const expected = `http://127.0.0.1:${port}`;
const actual = process.env.ANTHROPIC_BASE_URL || '';

if (actual.replace(/\/$/, '') !== expected) {
  emit(
    `REDACTION INACTIVE: ANTHROPIC_BASE_URL is "${actual || '(unset)'}", expected "${expected}". ` +
      'Requests are going directly to the API and nothing is being redacted.'
  );
}

const req = http.get({ host: '127.0.0.1', port, path: '/_health', timeout: 2000 }, (res) => {
  const chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => {
    try {
      if (JSON.parse(Buffer.concat(chunks).toString()).ok === true) return emit(null);
    } catch (e) {
      /* fall through */
    }
    emit(`REDACTION PROXY UNHEALTHY on port ${port}: /_health did not report ok.`);
  });
});
req.on('timeout', () => { req.destroy(); emit(`REDACTION PROXY NOT RESPONDING on port ${port}.`); });
req.on('error', (e) => emit(`REDACTION PROXY NOT RUNNING on port ${port} (${e.code}).`));
```

- [ ] **Step 2: Verify the hook detects a missing proxy**

Run: `ANTHROPIC_BASE_URL=http://127.0.0.1:47113 node proxy/liveness-hook.js`
Expected: JSON containing `REDACTION PROXY NOT RUNNING`

Run: `node proxy/liveness-hook.js`
Expected: JSON containing `REDACTION INACTIVE`

- [ ] **Step 3: Start the proxy and confirm the hook goes quiet**

```bash
node proxy/start.js &
sleep 2
ANTHROPIC_BASE_URL=http://127.0.0.1:47113 node proxy/liveness-hook.js
```
Expected: exactly `{}`

- [ ] **Step 4: End-to-end test against the real API**

Create a file containing PII and drive a real session through the proxy. Replace `<YOUR-LITERAL>` with one of the literals from `redact-rules.json`.

```bash
printf 'owner: <YOUR-LITERAL>\nmail: probe@example.org\n' > /tmp/e2e.txt
ANTHROPIC_BASE_URL=http://127.0.0.1:47113 \
  claude -p "Read /tmp/e2e.txt and reply with only the number of lines."
```

Expected: the model answers `2`, proving the Read tool got a working path through the alias round trip.

Then confirm from the audit log that the model never saw the real values:

```bash
tail -5 ~/.claude/redact-proxy.log
```
Expected: a line showing `personal=1 email=1` (or similar non-zero counts) and `aliased=` greater than zero.

- [ ] **Step 5: Confirm Grep and Bash still work through the alias**

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:47113 \
  claude -p "Use Glob to count .js files under proxy/, then run 'node --version' with Bash. Report both."
```
Expected: a correct file count and the real Node version — proving aliased paths reverse correctly for both tools.

- [ ] **Step 6: Register autostart**

The base URL is read at Claude Code startup and the first request follows within seconds, so the proxy cannot start on demand.

Create `proxy/install-autostart.ps1`:

```powershell
# Registers the redaction proxy to start at logon.
$node = (Get-Command node).Source
$script = Join-Path $PSScriptRoot 'start.js'
$action = New-ScheduledTaskAction -Execute $node -Argument "`"$script`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'ClaudeRedactionProxy' -Action $action -Trigger $trigger -Settings $settings -Force
Write-Host 'Registered. Verify with: Get-ScheduledTask ClaudeRedactionProxy'
```

Run: `powershell -ExecutionPolicy Bypass -File proxy/install-autostart.ps1`
Expected: `Registered.`

- [ ] **Step 7: Wire settings.json**

Replace the entire `hooks` block in `C:\Users\SOMEONE\.claude\settings.json`, and add the env var. The old hook entries are retired here; their files stay in `temp/`.

```json
  "env": {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:47113"
  },
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node",
            "args": ["C:\\Users\\SOMEONE\\Desktop\\games\\files\\proxy\\liveness-hook.js"],
            "timeout": 10
          }
        ]
      }
    ]
  }
```

Verify: `node -e "const s=require('C:/Users/SOMEONE/.claude/settings.json');console.log(s.env.ANTHROPIC_BASE_URL, Object.keys(s.hooks))"`
Expected: `http://127.0.0.1:47113 [ 'SessionStart' ]`

- [ ] **Step 8: Retire the working-tree hook copies**

Only now, with the proxy verified — there must be no window with neither mechanism active.

```bash
cd "c:/Users/SOMEONE/Desktop/games/files"
rm -f redact-mirror.js redact-hook.js bash-hook.js redact-stream.js warm-mirror.js \
      test-rules.js test-mirror.js test-hooks.js test-bash.js
ls temp/   # confirm the archive is intact: 10 files
```

- [ ] **Step 9: Full suite and commit**

```bash
node --test proxy/test/*.test.js
git add -A
git commit -m "feat(proxy): wire into Claude Code, add liveness assertion and autostart

Retires the hook-based redaction suite from the working tree; the archive
in temp/ is unchanged. Phase 1 complete: outbound PII labels and identity
aliases, with inbound alias reversal so every tool keeps working."
```

---

## Phase 1 completion criteria

- [ ] `node --test proxy/test/*.test.js` passes with zero failures
- [ ] `/_health` returns `{"ok":true,...}`
- [ ] Liveness hook is silent when routed correctly, loud when not
- [ ] A real `claude -p` performing Read, Glob and Bash succeeds through aliased paths
- [ ] The audit log shows non-zero redaction counts for a file containing PII
- [ ] `temp/` still holds all ten archived hook files

## Known Phase 1 behavior (not defects)

- **An Edit touching a line containing PII fails** with "string not found". Phase 2 fixes this via derived resolution. It is a visible error, never silent corruption.
- **Labels in Bash commands do not resolve.** Phase 2's cache addresses it.
- **Timezone, OS build string and git remote URLs are not yet normalized.** Phase 3.
- **The real IP is still used.** Phase 3's optional egress tunnel addresses it.
- `device_id` is unmodified by default, by design.

## Deferred to later phases

| Item | Phase |
|---|---|
| Derived label resolution, span-based edit rewriting | 2 |
| Encrypted 30-day TTL cache | 2 |
| Timezone / OS / git-remote normalization | 3 |
| Upstream SOCKS5/VPN egress, fail-closed | 3 |
| `randomizeDeviceId` | 3 |
| Worker-thread runtime regex watchdog (load-time screening ships in Task 2) | 3 |
| Watching `redact-rules.json` for changes (the spec calls for it; Phase 1 picks up edits on proxy restart, which the autostart task makes a one-line operation) | 3 |
