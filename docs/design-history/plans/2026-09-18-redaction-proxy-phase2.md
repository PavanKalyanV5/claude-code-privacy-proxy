# Redaction Proxy — Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make edits work on lines containing personal data, by reconstructing the label→value mapping on demand from the file on disk — never from a stored copy.

**Architecture:** When a `tool_use` for a file-editing tool streams back, the proxy re-reads the target file and re-redacts it. Redaction is deterministic, so this reproduces byte-for-byte what the model saw, along with a span map of real↔redacted offsets. The model's `old_string` is located in the redacted text, its offsets translated back through the span map, and the tool input rewritten with real values before Claude Code acts on it. A separate encrypted TTL cache covers the one case derivation cannot serve: labels in `Bash` commands, where there is no target file to derive from.

**Tech Stack:** Node.js v24 (`crypto`, `fs`, `node:test`). **Zero runtime dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-17-api-redaction-proxy-design.md` (Mechanism A2)

## Global Constraints

- **Zero runtime dependencies.** Node stdlib only. Tests use `node:test`.
- **Derivation is authoritative for file edits.** Never use the cache to supply offsets for an Edit — a stale entry could write personal data back into a file it was removed from. Cache is for `Bash` and as a last-resort fallback only.
- **Never guess.** If `old_string` is not found, is ambiguous (more than one match), or either boundary falls *inside* a redacted span, pass the input through unchanged so the Edit fails visibly. A wrong offset corrupts a user file.
- **Never write a label into a file.** If any `[PII:` marker survives rehydration, treat the input as unresolvable and pass it through unchanged.
- **Cache is encrypted at rest** with AES-256-GCM under `k_cache = subkey(master, 'cache')`, 30-day TTL, at `~/.claude/redaction/redact-cache.enc`. A corrupt or undecryptable cache rebuilds empty and never fails a request.
- **`redact-rules.json` is owned by the user and off limits to every task.** Use `redact-rules.example.json` for a config shape. Tests define rules inline.
- Preserve every Phase 1 guarantee: loopback-only binding; no credential logging; `tools`/`metadata`/`thinking`/`redacted_thinking`/`image`/`document` byte-identical; label determinism (same key + value → identical label, prompt caching depends on it); HMAC not bare hash; Unicode literal boundaries; alias word boundaries.
- Whole-suite command is `node --test proxy/test/*.test.js` **with the glob**. Plain `node --test proxy/test/` fails on this setup.
- Target platform: Windows 11, Git Bash, Node v24.18.0. Current baseline: 94 tests passing.

---

### Task 1: Encrypted TTL cache

Covers the case derivation cannot: a label appearing in a `Bash` command, where there is no file to derive from. Encryption is not about defeating a local attacker — the proxy, the key and the cache are all readable by the same user. It prevents **accidental** exposure: the file being swept into a cloud sync, a backup, or a support bundle.

**Files:**
- Create: `proxy/cache.js`
- Create: `proxy/test/cache.test.js`

**Interfaces:**
- Consumes: `subkey(master, purpose) -> Buffer(32)` from `proxy/keys.js`.
- Produces:
  - `createCache({ key, path?, ttlMs?, maxEntries? }) -> cache`
  - `cache.get(label: string) -> string | undefined`
  - `cache.set(label: string, value: string) -> void`
  - `cache.save() -> void` (atomic; tmp + rename)
  - `cache.size() -> number`
  - `CACHE_PATH: string`, `DEFAULT_TTL_MS: number`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/cache.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createCache, DEFAULT_TTL_MS } = require('../cache');

const KEY = Buffer.alloc(32, 11);
const tmpPath = () =>
  path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cache-')), 'redact-cache.enc');

test('round-trips a value through disk', () => {
  const p = tmpPath();
  const a = createCache({ key: KEY, path: p });
  a.set('[PII:email:aaaa]', 'real@example.org');
  a.save();

  const b = createCache({ key: KEY, path: p });
  assert.strictEqual(b.get('[PII:email:aaaa]'), 'real@example.org');
});

test('the file on disk is not plaintext', () => {
  const p = tmpPath();
  const c = createCache({ key: KEY, path: p });
  c.set('[PII:email:bbbb]', 'secret@example.org');
  c.save();
  const raw = fs.readFileSync(p, 'utf8');
  assert.ok(!raw.includes('secret@example.org'), 'plaintext value on disk');
  assert.ok(!raw.includes('[PII:email:bbbb]'), 'plaintext label on disk');
});

test('a different key cannot read it, and fails soft', () => {
  const p = tmpPath();
  const a = createCache({ key: KEY, path: p });
  a.set('[PII:email:cccc]', 'real@example.org');
  a.save();

  const b = createCache({ key: Buffer.alloc(32, 99), path: p });
  assert.strictEqual(b.get('[PII:email:cccc]'), undefined);
  assert.strictEqual(b.size(), 0);
});

test('tampering is detected and the cache rebuilds empty', () => {
  const p = tmpPath();
  const c = createCache({ key: KEY, path: p });
  c.set('[PII:email:dddd]', 'real@example.org');
  c.save();

  const raw = fs.readFileSync(p, 'utf8');
  const flipped = raw.slice(0, -6) + (raw.slice(-6, -5) === 'a' ? 'b' : 'a') + raw.slice(-5);
  fs.writeFileSync(p, flipped);

  const d = createCache({ key: KEY, path: p });
  assert.strictEqual(d.size(), 0);
  assert.strictEqual(d.get('[PII:email:dddd]'), undefined);
});

test('entries past the TTL are dropped on load', () => {
  const p = tmpPath();
  const c = createCache({ key: KEY, path: p, ttlMs: 50 });
  c.set('[PII:email:eeee]', 'real@example.org');
  c.save();

  const past = Date.now() + 1000;
  const revived = createCache({ key: KEY, path: p, ttlMs: 50, now: () => past });
  assert.strictEqual(revived.get('[PII:email:eeee]'), undefined);
});

test('a fresh entry survives a load within the TTL', () => {
  const p = tmpPath();
  const c = createCache({ key: KEY, path: p, ttlMs: 60000 });
  c.set('[PII:email:ffff]', 'real@example.org');
  c.save();
  assert.strictEqual(createCache({ key: KEY, path: p, ttlMs: 60000 }).get('[PII:email:ffff]'), 'real@example.org');
});

test('a missing file loads as an empty cache without throwing', () => {
  const p = path.join(os.tmpdir(), 'definitely-absent-' + Date.now(), 'c.enc');
  const c = createCache({ key: KEY, path: p });
  assert.strictEqual(c.size(), 0);
});

test('evicts oldest past maxEntries', () => {
  const c = createCache({ key: KEY, path: tmpPath(), maxEntries: 3 });
  for (let i = 0; i < 6; i++) c.set(`[PII:x:${i}]`, `v${i}`);
  assert.ok(c.size() <= 3, `size ${c.size()}`);
  assert.strictEqual(c.get('[PII:x:5]'), 'v5');
});

test('default TTL is 30 days', () => {
  assert.strictEqual(DEFAULT_TTL_MS, 30 * 24 * 60 * 60 * 1000);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/cache.test.js`
Expected: FAIL — `Cannot find module '../cache'`

- [ ] **Step 3: Write the implementation**

Create `proxy/cache.js`:

```js
'use strict';

// Encrypted, TTL-bounded label -> value cache.
//
// Derivation from the file on disk is authoritative for file edits; this exists
// only for the case derivation cannot serve -- a label inside a Bash command,
// where there is no target file.
//
// On encryption: the proxy, the key and this file are all readable by the same
// user, so this does not defeat a local attacker. What it prevents is
// ACCIDENTAL exposure -- the file being swept into a cloud sync, a backup or a
// support bundle. That is the realistic threat for a file of this shape.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const CACHE_PATH = path.join(os.homedir(), '.claude', 'redaction', 'redact-cache.enc');
const DEFAULT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_MAX_ENTRIES = 5000;
const IV_BYTES = 12;

function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${tag.toString('base64')}.${enc.toString('base64')}`;
}

function decrypt(key, blob) {
  const [ivB64, tagB64, dataB64] = String(blob).split('.');
  if (!ivB64 || !tagB64 || !dataB64) throw new Error('malformed cache blob');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(dataB64, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

function createCache({
  key,
  path: cachePath = CACHE_PATH,
  ttlMs = DEFAULT_TTL_MS,
  maxEntries = DEFAULT_MAX_ENTRIES,
  now = () => Date.now(),
} = {}) {
  // label -> { v: value, t: epoch ms }
  let entries = new Map();

  try {
    const raw = fs.readFileSync(cachePath, 'utf8');
    const obj = JSON.parse(decrypt(key, raw));
    const cutoff = now() - ttlMs;
    for (const [label, rec] of Object.entries(obj)) {
      if (rec && typeof rec.v === 'string' && typeof rec.t === 'number' && rec.t > cutoff) {
        entries.set(label, rec);
      }
    }
  } catch (e) {
    // Missing, corrupt, tampered, or written under a different key. Rebuild
    // empty -- a cache must never fail a request.
    entries = new Map();
  }

  return {
    get(label) {
      const rec = entries.get(label);
      if (!rec) return undefined;
      if (rec.t <= now() - ttlMs) {
        entries.delete(label);
        return undefined;
      }
      return rec.v;
    },
    set(label, value) {
      if (typeof label !== 'string' || typeof value !== 'string') return;
      entries.delete(label); // refresh insertion order
      entries.set(label, { v: value, t: now() });
      while (entries.size > maxEntries) entries.delete(entries.keys().next().value);
    },
    save() {
      try {
        fs.mkdirSync(path.dirname(cachePath), { recursive: true });
        const obj = {};
        for (const [label, rec] of entries) obj[label] = rec;
        const tmp = `${cachePath}.${process.pid}.tmp`;
        fs.writeFileSync(tmp, encrypt(key, JSON.stringify(obj)), { mode: 0o600 });
        fs.renameSync(tmp, cachePath);
      } catch (e) {
        // Persistence is best-effort; an in-memory cache still works.
      }
    },
    size() {
      return entries.size;
    },
  };
}

module.exports = { createCache, CACHE_PATH, DEFAULT_TTL_MS };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/cache.test.js`
Expected: PASS, 9 tests

- [ ] **Step 5: Commit**

```bash
git add proxy/cache.js proxy/test/cache.test.js
git commit -m "feat(proxy): encrypted TTL cache for labels with no derivable source"
```

---

### Task 2: Derived resolution

The heart of Phase 2. Offset arithmetic here decides whether a user's file is edited correctly or corrupted, so the failure mode is "refuse and let the Edit fail visibly", never "guess".

**Files:**
- Create: `proxy/resolve.js`
- Create: `proxy/test/resolve.test.js`

**Interfaces:**
- Consumes: `redactWithSpans(text, compiled, kLabel) -> { text, spans, counts }` and `makeLabel(kLabel, category, value) -> string` from `proxy/spans.js`. Span shape: `{ realStart, realEnd, redStart, redEnd, value, category }`.
- Produces:
  - `mapOffset(redOffset: number, spans: Array) -> number | null` (null = offset falls inside a redacted span)
  - `rehydrate(text: string, spans: Array, kLabel: Buffer) -> string | null` (null = a `[PII:` marker survived)
  - `translateEdit({ realText, redacted, oldString, newString, kLabel }) -> { oldString, newString } | null`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/resolve.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile } = require('../rules');
const { redactWithSpans, makeLabel } = require('../spans');
const { mapOffset, rehydrate, translateEdit } = require('../resolve');

const K = Buffer.alloc(32, 13);
const RULES = compile({
  literals: ['Jane Q. Testerson'],
  patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', flags: 'gi' }],
});
const red = (t) => redactWithSpans(t, RULES, K);

test('mapOffset is identity before any span', () => {
  const r = red('xx jane.test@example.org yy');
  assert.strictEqual(mapOffset(0, r.spans), 0);
  assert.strictEqual(mapOffset(3, r.spans), 3);
});

test('mapOffset shifts by the length delta after a span', () => {
  const real = 'xx jane.test@example.org yy';
  const r = red(real);
  const s = r.spans[0];
  // The redacted end of the span maps to the real end of the span.
  assert.strictEqual(mapOffset(s.redEnd, r.spans), s.realEnd);
  // One char further on each side stays in step.
  assert.strictEqual(mapOffset(s.redEnd + 1, r.spans), s.realEnd + 1);
});

test('mapOffset refuses an offset strictly inside a span', () => {
  const r = red('xx jane.test@example.org yy');
  const s = r.spans[0];
  assert.strictEqual(mapOffset(s.redStart + 3, r.spans), null);
});

test('mapOffset accepts the exact span boundaries', () => {
  const r = red('xx jane.test@example.org yy');
  const s = r.spans[0];
  assert.strictEqual(mapOffset(s.redStart, r.spans), s.realStart);
  assert.strictEqual(mapOffset(s.redEnd, r.spans), s.realEnd);
});

test('rehydrate restores a label to its real value', () => {
  const real = 'contact jane.test@example.org here';
  const r = red(real);
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  assert.strictEqual(rehydrate(`x ${label} y`, r.spans, K), 'x jane.test@example.org y');
});

test('rehydrate returns null when an unknown label survives', () => {
  const r = red('nothing here');
  assert.strictEqual(rehydrate('x [PII:email:deadbeefdeadbeef] y', r.spans, K), null);
});

test('rehydrate passes through text with no labels', () => {
  const r = red('nothing here');
  assert.strictEqual(rehydrate('plain text', r.spans, K), 'plain text');
});

test('translateEdit rewrites an edit spanning a redacted value', () => {
  const realText = 'const OWNER = "jane.test@example.org";\nconst X = 1;\n';
  const r = red(realText);
  const label = makeLabel(K, 'email', 'jane.test@example.org');

  const out = translateEdit({
    realText,
    redacted: r,
    oldString: `const OWNER = "${label}";`,
    newString: `const MAINTAINER = "${label}";`,
    kLabel: K,
  });

  assert.ok(out, 'expected a translation');
  assert.strictEqual(out.oldString, 'const OWNER = "jane.test@example.org";');
  assert.strictEqual(out.newString, 'const MAINTAINER = "jane.test@example.org";');
  // And it must actually apply to the real file.
  assert.ok(realText.includes(out.oldString));
});

test('translateEdit handles an edit with no redacted content', () => {
  const realText = 'const A = 1;\nconst B = 2;\n';
  const r = red(realText);
  const out = translateEdit({
    realText, redacted: r, oldString: 'const B = 2;', newString: 'const B = 3;', kLabel: K,
  });
  assert.ok(out);
  assert.strictEqual(out.oldString, 'const B = 2;');
  assert.strictEqual(out.newString, 'const B = 3;');
});

test('translateEdit refuses when old_string is not found', () => {
  const realText = 'const A = 1;\n';
  assert.strictEqual(
    translateEdit({ realText, redacted: red(realText), oldString: 'NOPE', newString: 'x', kLabel: K }),
    null
  );
});

test('translateEdit refuses when old_string is ambiguous', () => {
  const realText = 'dup\ndup\n';
  assert.strictEqual(
    translateEdit({ realText, redacted: red(realText), oldString: 'dup', newString: 'x', kLabel: K }),
    null
  );
});

test('translateEdit refuses when a boundary falls inside a redacted span', () => {
  const realText = 'mail jane.test@example.org now';
  const r = red(realText);
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  // Slice into the middle of the label.
  const partial = label.slice(4);
  assert.strictEqual(
    translateEdit({ realText, redacted: r, oldString: partial, newString: 'x', kLabel: K }),
    null
  );
});

test('translateEdit refuses when new_string carries an unknown label', () => {
  const realText = 'const A = 1;\n';
  assert.strictEqual(
    translateEdit({
      realText, redacted: red(realText),
      oldString: 'const A = 1;',
      newString: 'const A = "[PII:email:0000000000000000]";',
      kLabel: K,
    }),
    null
  );
});

test('translateEdit survives multi-byte characters before the edit', () => {
  const realText = 'héllo → contact jane.test@example.org done';
  const r = red(realText);
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  const out = translateEdit({
    realText, redacted: r,
    oldString: `contact ${label} done`,
    newString: `reach ${label} done`,
    kLabel: K,
  });
  assert.ok(out);
  assert.strictEqual(out.oldString, 'contact jane.test@example.org done');
  assert.ok(realText.includes(out.oldString));
});

test('property: a translated edit always applies cleanly to the real text', () => {
  const bodies = [
    'a jane.test@example.org b',
    'Jane Q. Testerson at jane.test@example.org',
    'line1\nline2 jane.test@example.org\nline3',
    'é jane.test@example.org é',
  ];
  for (const realText of bodies) {
    const r = red(realText);
    for (const s of r.spans) {
      const label = makeLabel(K, s.category, s.value);
      const out = translateEdit({
        realText, redacted: r, oldString: label, newString: 'REPLACED', kLabel: K,
      });
      assert.ok(out, `no translation for ${label} in ${realText}`);
      assert.ok(realText.includes(out.oldString), `old_string not in real text: ${out.oldString}`);
      assert.strictEqual(out.oldString, s.value);
    }
  }
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/resolve.test.js`
Expected: FAIL — `Cannot find module '../resolve'`

- [ ] **Step 3: Write the implementation**

Create `proxy/resolve.js`:

```js
'use strict';

// Derived resolution: turn an edit expressed against REDACTED text into one
// expressed against the REAL file, without ever storing the mapping.
//
// Redaction is deterministic, so re-redacting the file on disk reproduces
// byte-for-byte what the model saw, plus a span map of real<->redacted offsets.
// The mapping therefore exists for the duration of one function call and is
// derived entirely from a file the caller already has.
//
// Every ambiguity refuses. A wrong offset corrupts a user's file, so "pass it
// through and let the Edit fail visibly" is always the better outcome.

const { makeLabel } = require('./spans');

const LABEL_RE = /\[PII:[a-z0-9_-]+:[0-9a-f]{16}\]/gi;

// Translate an offset in the REDACTED text to the corresponding offset in the
// REAL text. Returns null when the offset falls strictly inside a replaced
// span, where no single real offset corresponds.
function mapOffset(redOffset, spans) {
  let delta = 0;
  for (const s of spans) {
    if (redOffset <= s.redStart) break; // at or before this span: done
    if (redOffset < s.redEnd) return null; // strictly inside: ambiguous
    delta += (s.realEnd - s.realStart) - (s.redEnd - s.redStart);
  }
  return redOffset + delta;
}

// Replace every label in `text` with its real value, using only values present
// in THIS file's spans. Returns null if any label remains unresolved -- writing
// a literal [PII:...] marker into a file would be worse than failing.
function rehydrate(text, spans, kLabel) {
  if (typeof text !== 'string') return text;
  const byLabel = new Map();
  for (const s of spans) byLabel.set(makeLabel(kLabel, s.category, s.value), s.value);

  let out = text;
  for (const [label, value] of byLabel) {
    if (out.includes(label)) out = out.split(label).join(value);
  }

  LABEL_RE.lastIndex = 0;
  if (LABEL_RE.test(out)) return null; // an unknown label survived
  return out;
}

/**
 * @param realText  the file's true contents
 * @param redacted  the result of redactWithSpans(realText, ...)
 * @param oldString the model's old_string, expressed against redacted text
 * @param newString the model's new_string, may contain labels
 * @param kLabel    HMAC key, to recompute labels from span values
 * @returns { oldString, newString } against the REAL text, or null to refuse
 */
function translateEdit({ realText, redacted, oldString, newString, kLabel }) {
  if (typeof oldString !== 'string' || oldString.length === 0) return null;

  const hay = redacted.text;
  const idx = hay.indexOf(oldString);
  if (idx === -1) return null; // not found
  if (hay.indexOf(oldString, idx + 1) !== -1) return null; // ambiguous

  const realStart = mapOffset(idx, redacted.spans);
  const realEnd = mapOffset(idx + oldString.length, redacted.spans);
  if (realStart === null || realEnd === null) return null; // boundary inside a span

  const realOld = realText.slice(realStart, realEnd);
  const realNew = rehydrate(newString, redacted.spans, kLabel);
  if (realNew === null) return null; // unknown label in new_string

  return { oldString: realOld, newString: realNew };
}

module.exports = { mapOffset, rehydrate, translateEdit, LABEL_RE };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/resolve.test.js`
Expected: PASS, 15 tests

- [ ] **Step 5: Commit**

```bash
git add proxy/resolve.js proxy/test/resolve.test.js
git commit -m "feat(proxy): derived label resolution via span-offset translation"
```

---

### Task 3: Wire resolution into the inbound path

Two changes. Outbound, every minted label is offered to the cache so `Bash` can resolve one later. Inbound, file-editing tool inputs get resolved against the file on disk.

Order matters inside the inbound handler: **un-alias first, then resolve.** The `file_path` must be a real path before the file can be read.

**Files:**
- Modify: `proxy/walk.js` (feed the cache when labels are minted)
- Modify: `proxy/sse.js` (resolve tool inputs at `content_block_stop`)
- Modify: `proxy/server.js` (pass the resolver through)
- Modify: `proxy/start.js` (create the cache, save it on exit)
- Modify: `proxy/test/sse.test.js` (add resolution tests)

**Interfaces:**
- Consumes: `createCache(...)` (Task 1); `translateEdit`, `rehydrate` (Task 2); `redactWithSpans` from `proxy/spans.js`.
- Produces: `createSseTransformer({ aliases, stats, resolver? })` — `resolver` is optional so every existing Phase 1 test keeps passing unchanged. Resolver shape: `{ resolveToolInput(name: string, input: object) -> object }`.

- [ ] **Step 1: Write the failing test**

Append to `proxy/test/sse.test.js`:

```js
test('Edit tool input is resolved against the file on disk', () => {
  const calls = [];
  const resolver = {
    resolveToolInput(name, input) {
      calls.push(name);
      if (name !== 'Edit') return input;
      return Object.assign({}, input, { old_string: 'REAL', new_string: 'REAL2' });
    },
  };
  const stats = {};
  const t = createSseTransformer({ aliases: A, stats, resolver });
  let out = '';
  out += t.push(ev('content_block_start', {
    type: 'content_block_start', index: 0,
    content_block: { type: 'tool_use', name: 'Edit', input: {} },
  }));
  out += t.push(ev('content_block_delta', {
    type: 'content_block_delta', index: 0,
    delta: { type: 'input_json_delta', partial_json: JSON.stringify({ file_path: 'x.js', old_string: 'LBL', new_string: 'LBL2' }) },
  }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();

  assert.deepStrictEqual(calls, ['Edit']);
  assert.deepStrictEqual(toolInputs(out), [{ file_path: 'x.js', old_string: 'REAL', new_string: 'REAL2' }]);
});

test('a resolver that throws never breaks the stream', () => {
  const resolver = { resolveToolInput() { throw new Error('boom'); } };
  const t = createSseTransformer({ aliases: A, stats: {}, resolver });
  let out = '';
  out += t.push(ev('content_block_start', {
    type: 'content_block_start', index: 0,
    content_block: { type: 'tool_use', name: 'Edit', input: {} },
  }));
  out += t.push(ev('content_block_delta', {
    type: 'content_block_delta', index: 0,
    delta: { type: 'input_json_delta', partial_json: JSON.stringify({ file_path: 'x.js', old_string: 'LBL' }) },
  }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();
  // Passes through unchanged rather than dropping the block.
  assert.deepStrictEqual(toolInputs(out), [{ file_path: 'x.js', old_string: 'LBL' }]);
});

test('no resolver behaves exactly as Phase 1 did', () => {
  const t = createSseTransformer({ aliases: A, stats: {} });
  let out = '';
  out += t.push(ev('content_block_start', {
    type: 'content_block_start', index: 0,
    content_block: { type: 'tool_use', name: 'Edit', input: {} },
  }));
  out += t.push(ev('content_block_delta', {
    type: 'content_block_delta', index: 0,
    delta: { type: 'input_json_delta', partial_json: JSON.stringify({ file_path: 'x.js', old_string: 'LBL' }) },
  }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();
  assert.deepStrictEqual(toolInputs(out), [{ file_path: 'x.js', old_string: 'LBL' }]);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/sse.test.js`
Expected: FAIL — the resolver is never called, so `calls` is empty.

- [ ] **Step 3: Add the resolver hook to `proxy/sse.js`**

In `createSseTransformer`, accept `resolver` in the options object:

```js
function createSseTransformer({ aliases, stats = {}, resolver = null }) {
```

Then in the `content_block_stop` branch, **after** the existing un-alias block and before the delta is built, insert:

```js
      // Resolution runs AFTER un-aliasing: file_path must be a real path
      // before the file can be read. A resolver failure must never break the
      // stream, so anything thrown leaves the input exactly as it arrived.
      if (resolver && json) {
        try {
          const parsed = JSON.parse(json);
          const resolved = resolver.resolveToolInput(block.name, parsed);
          if (resolved && typeof resolved === 'object') json = JSON.stringify(resolved);
        } catch (e) {
          /* leave `json` as-is */
        }
      }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/sse.test.js`
Expected: PASS, 11 tests

- [ ] **Step 5: Create the resolver and feed the cache**

Create `proxy/resolver.js`:

```js
'use strict';

// Binds derived resolution to the filesystem and the cache.
//
// Derivation is authoritative for file edits: offsets must reflect the file as
// it is NOW. A stale cache entry could write personal data back into a file it
// had been removed from, so the cache is never consulted for Edit offsets --
// only for tools with no file to derive from.

const fs = require('fs');
const { redactWithSpans } = require('./spans');
const { translateEdit, rehydrate, LABEL_RE } = require('./resolve');

// Tools whose input carries a path we can derive from.
const FILE_TOOLS = {
  Edit: 'file_path',
  MultiEdit: 'file_path',
  Write: 'file_path',
  NotebookEdit: 'notebook_path',
};

function createResolver({ rules, kLabel, cache = null, stats = {} }) {
  function bump(k) {
    stats[k] = (stats[k] || 0) + 1;
  }

  function fromCache(text) {
    if (!cache || typeof text !== 'string') return text;
    LABEL_RE.lastIndex = 0;
    if (!LABEL_RE.test(text)) return text;
    return text.replace(LABEL_RE, (label) => {
      const v = cache.get(label);
      if (v === undefined) return label;
      bump('cacheHit');
      return v;
    });
  }

  return {
    resolveToolInput(name, input) {
      if (!input || typeof input !== 'object') return input;

      const field = FILE_TOOLS[name];
      if (!field) {
        // No file to derive from (Bash and friends): cache only.
        if (name === 'Bash' && typeof input.command === 'string') {
          return Object.assign({}, input, { command: fromCache(input.command) });
        }
        return input;
      }

      const filePath = input[field];
      if (typeof filePath !== 'string') return input;

      let realText;
      try {
        realText = fs.readFileSync(filePath, 'utf8');
      } catch (e) {
        bump('noFile');
        return input; // new file, or unreadable: nothing to derive
      }

      const redacted = redactWithSpans(realText, rules, kLabel);
      if (redacted.spans.length === 0) {
        bump('noSpans');
        return input; // nothing was redacted in this file; input is already real
      }

      if (name === 'Write') {
        const content = rehydrate(input.content, redacted.spans, kLabel);
        if (content === null) {
          bump('refused');
          return input;
        }
        bump('resolved');
        return Object.assign({}, input, { content });
      }

      const edits = name === 'MultiEdit' && Array.isArray(input.edits) ? input.edits : null;
      if (edits) {
        const out = [];
        for (const e of edits) {
          const t = translateEdit({
            realText, redacted, oldString: e.old_string, newString: e.new_string, kLabel,
          });
          if (!t) {
            bump('refused');
            return input; // all-or-nothing: a partial MultiEdit is worse
          }
          out.push(Object.assign({}, e, { old_string: t.oldString, new_string: t.newString }));
        }
        bump('resolved');
        return Object.assign({}, input, { edits: out });
      }

      const srcOld = name === 'NotebookEdit' ? input.new_source : input.old_string;
      if (typeof srcOld !== 'string') return input;

      if (name === 'NotebookEdit') {
        const s = rehydrate(input.new_source, redacted.spans, kLabel);
        if (s === null) {
          bump('refused');
          return input;
        }
        bump('resolved');
        return Object.assign({}, input, { new_source: s });
      }

      const t = translateEdit({
        realText, redacted, oldString: input.old_string, newString: input.new_string, kLabel,
      });
      if (!t) {
        bump('refused');
        return input;
      }
      bump('resolved');
      return Object.assign({}, input, { old_string: t.oldString, new_string: t.newString });
    },
  };
}

module.exports = { createResolver, FILE_TOOLS };
```

- [ ] **Step 6: Feed the cache from the outbound path**

In `proxy/walk.js`, `makeContext` gains an optional `cache`, and `transformString` records every minted label. Change `makeContext` to accept and store `cache = null`, then in `transformString`, immediately after the `redactWithSpans` call and before the alias step, add:

```js
  if (ctx.cache) {
    for (const s of r.spans) {
      ctx.cache.set(makeLabel(ctx.kLabel, s.category, s.value), s.value);
    }
  }
```

Add `makeLabel` to the existing `require('./spans')` destructuring at the top of `proxy/walk.js`.

- [ ] **Step 7: Wire it together in `proxy/server.js` and `proxy/start.js`**

In `proxy/server.js`, accept `resolver = null` in `createServer({...})` and pass it into the transformer:

```js
          const t = createSseTransformer({ aliases, stats: sseStats, resolver });
```

In `proxy/start.js`, build the cache and resolver and hand them over:

```js
const { createCache } = require('./cache');
const { createResolver } = require('./resolver');

  const kCache = subkey(master, 'cache');
  const cache = createCache({ key: kCache });
  const ctx = makeContext({ kLabel, kMemo, rules: compiled, aliases, cache });
  const resolveStats = {};
  const resolver = createResolver({ rules: compiled, kLabel, cache, stats: resolveStats });
  const server = createServer({ ctx, aliases, logger, resolver });

  // Persist the cache periodically and on exit; losing it costs only the
  // Bash-label fallback, never correctness.
  const flush = setInterval(() => cache.save(), 60000);
  if (flush.unref) flush.unref();
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => { cache.save(); process.exit(0); });
  }
```

- [ ] **Step 8: Run the whole suite**

Run: `node --test proxy/test/*.test.js`
Expected: PASS, 121 tests (94 baseline + 9 cache + 15 resolve + 3 sse), 0 failures

- [ ] **Step 9: Commit**

```bash
git add proxy/resolver.js proxy/sse.js proxy/walk.js proxy/server.js proxy/start.js proxy/test/sse.test.js
git commit -m "feat(proxy): resolve file-tool inputs from disk, cache for Bash labels"
```

---

### Task 4: End-to-end resolution test

Proves the pieces compose: a real file containing personal data, redacted outbound, edited by a simulated model response, and the edit landing correctly on the real file.

**Files:**
- Create: `proxy/test/e2e-resolve.test.js`

**Interfaces:**
- Consumes: everything from Tasks 1–3.
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

Create `proxy/test/e2e-resolve.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { compile } = require('../rules');
const { redactWithSpans, makeLabel } = require('../spans');
const { createResolver } = require('../resolver');
const { createCache } = require('../cache');

const K = Buffer.alloc(32, 17);
const RULES = compile({
  literals: ['Jane Q. Testerson'],
  patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', flags: 'gi' }],
});

function fixture(contents) {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-')), 'f.js');
  fs.writeFileSync(p, contents);
  return p;
}

test('an Edit on a line containing PII lands correctly on the real file', () => {
  const real = 'const OWNER = "jane.test@example.org";\nconst KEEP = 1;\n';
  const p = fixture(real);
  const r = redactWithSpans(real, RULES, K);
  const label = makeLabel(K, 'email', 'jane.test@example.org');

  const resolver = createResolver({ rules: RULES, kLabel: K });
  const out = resolver.resolveToolInput('Edit', {
    file_path: p,
    old_string: `const OWNER = "${label}";`,
    new_string: `const MAINTAINER = "${label}";`,
  });

  assert.strictEqual(out.old_string, 'const OWNER = "jane.test@example.org";');
  // Apply it exactly as the Edit tool would.
  assert.ok(real.includes(out.old_string));
  const after = real.replace(out.old_string, out.new_string);
  fs.writeFileSync(p, after);
  const onDisk = fs.readFileSync(p, 'utf8');
  assert.ok(onDisk.includes('jane.test@example.org'), 'PII must survive the edit');
  assert.ok(onDisk.includes('MAINTAINER'), 'the rename must have applied');
  assert.ok(!onDisk.includes('[PII:'), 'no label may reach the file');
});

test('an Edit on a clean line in a PII-bearing file still works', () => {
  const real = 'const OWNER = "jane.test@example.org";\nconst KEEP = 1;\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const out = resolver.resolveToolInput('Edit', {
    file_path: p, old_string: 'const KEEP = 1;', new_string: 'const KEEP = 2;',
  });
  assert.strictEqual(out.old_string, 'const KEEP = 1;');
  assert.strictEqual(out.new_string, 'const KEEP = 2;');
});

test('an unresolvable Edit is passed through untouched so it fails visibly', () => {
  const real = 'const A = 1;\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const input = { file_path: p, old_string: 'NOT PRESENT', new_string: 'x' };
  assert.deepStrictEqual(resolver.resolveToolInput('Edit', input), input);
});

test('a missing file is passed through, not invented', () => {
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const input = { file_path: path.join(os.tmpdir(), 'nope-' + Date.now() + '.js'), old_string: 'a', new_string: 'b' };
  assert.deepStrictEqual(resolver.resolveToolInput('Edit', input), input);
});

test('a Bash label resolves from the cache', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 19), path: cachePath });
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  cache.set(label, 'jane.test@example.org');

  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const out = resolver.resolveToolInput('Bash', { command: `grep "${label}" f.txt` });
  assert.strictEqual(out.command, 'grep "jane.test@example.org" f.txt');
});

test('a Bash label with no cache entry is left alone', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc2-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 19), path: cachePath });
  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const cmd = 'grep "[PII:email:ffffffffffffffff]" f.txt';
  assert.strictEqual(resolver.resolveToolInput('Bash', { command: cmd }).command, cmd);
});

test('mcp__ tools are never resolved', () => {
  const real = 'const OWNER = "jane.test@example.org";\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const input = { file_path: p, old_string: 'anything' };
  assert.deepStrictEqual(resolver.resolveToolInput('mcp__thing__do', input), input);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/e2e-resolve.test.js`
Expected: FAIL — `Cannot find module '../resolver'` if Task 3 is incomplete, otherwise assertion failures.

- [ ] **Step 3: Make it pass**

No new implementation should be required — this task exercises Tasks 1–3. If a test fails, fix the module it exercises, not the test, unless the test is provably wrong.

- [ ] **Step 4: Run the whole suite**

Run: `node --test proxy/test/*.test.js`
Expected: PASS, 128 tests (121 + 7 e2e), 0 failures

- [ ] **Step 5: Commit**

```bash
git add proxy/test/e2e-resolve.test.js
git commit -m "test(proxy): end-to-end derived resolution against real files"
```

---

## Phase 2 completion criteria

- [ ] `node --test proxy/test/*.test.js` passes with zero failures
- [ ] An Edit on a line containing personal data lands correctly on the real file
- [ ] An unresolvable Edit is passed through untouched (fails visibly, never corrupts)
- [ ] No `[PII:` marker can reach a file
- [ ] The cache file on disk contains no plaintext value or label
- [ ] Every Phase 1 guarantee still holds (94 baseline tests unchanged)

## Explicitly out of scope (Phase 3)

| Item | Why deferred |
|---|---|
| Timezone / OS-build / git-remote normalization | Independent of resolution |
| Upstream SOCKS5/VPN egress | Independent of resolution |
| `randomizeDeviceId` | Account-level risk, needs its own decision |
| Worker-thread regex watchdog | Load-time screening already ships |
| Watching `redact-rules.json` for changes | Restart picks it up |
