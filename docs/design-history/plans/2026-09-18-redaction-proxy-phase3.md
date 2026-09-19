# Redaction Proxy — Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the environment fingerprints that survive Phases 1–2 — the timezone that pins the user's region, the exact OS build that identifies the machine, the git remote that names an employer, and the persistent `device_id` that links sessions.

**Architecture:** Two different mechanisms, deliberately. **Redaction** turns a value into a label and is reversible for local tools (so it suits org and repo names, which the model may need to use in commands). **Normalization** rewrites a value to a coarser one with no label and no reverse (so it suits a timezone offset or an OS build string, which nothing needs to round-trip). Git remotes therefore need no code at all — they are two `patterns` entries using lookbehind, inheriting labels, cache-feeding and resolution for free. Only timezone and OS build need a new module.

**Tech Stack:** Node.js v24 (`crypto`, `node:test`). **Zero runtime dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-17-api-redaction-proxy-design.md` (Mechanisms C and D)

## Global Constraints

- **Zero runtime dependencies.** Node stdlib only. Tests use `node:test`.
- **Normalization is one-way and unlabelled.** A timezone or OS build must not become a `[PII:...]` label — nothing needs to reverse it, and a label there would be noise the model has to reason around.
- **Never mangle ordinary content.** A normalization rule that fires on a version number, an ID, or an IP address is worse than the leak it closes. Every rule ships with negative tests.
- **Fail soft.** If a datetime cannot be parsed, leave it untouched rather than emit a wrong instant — but still blank a bare offset, so the zone never survives.
- **`redact-rules.json` is owned by the user and off limits to every task.** Use `redact-rules.example.json`. Tests define rules inline.
- **`metadata.user_id` is not touched unless explicitly enabled.** Default off. Altering it risks account-level abuse checks, which is a different class of consequence from a local bug.
- Preserve every Phase 1–2 guarantee: loopback-only bind; no credential logging; `tools`/`metadata`/`thinking`/`redacted_thinking`/`image`/`document` byte-identical (except `metadata` when `randomizeDeviceId` is on); label determinism; HMAC not bare hash; derivation authoritative for file edits; `remoteTools` policy.
- Whole-suite command is `node --test proxy/test/*.test.js` **with the glob**. Plain `node --test proxy/test/` fails on this setup.
- Windows 11, Git Bash, Node v24.18.0. Baseline: 158 tests passing.
- **Write test scripts with the Write tool, never `node -e` or a heredoc** — both strip backslashes here and silently produce fixtures that match nothing.

## Deliberately out of scope

| Item | Why |
|---|---|
| Egress tunnel (SOCKS5 / HTTP CONNECT) | Independently deliverable and the riskiest piece — a hand-rolled SOCKS5 handshake under the zero-dependency rule. Gets its own plan (Phase 3b) so a bug there cannot destabilise this. |
| Worker-thread regex watchdog | Load-time screening already rejects catastrophic patterns in a child process. Memoization keeps per-call input to a few KB, which bounds polynomial blowup. Cost exceeds the residual risk. |
| Watching `redact-rules.json` for changes | A restart picks it up, and the logon launcher makes a restart one command. |

---

### Task 1: Normalization module

**Files:**
- Create: `proxy/normalize.js`
- Create: `proxy/test/normalize.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `compileNormalizers(cfg) -> { timezone: boolean, rewrites: Array<{re: RegExp, replace: string, name: string}> }`
  - `normalize(text: string, compiled) -> { text: string, count: number }`
  - `toUtc(text: string) -> { text: string, count: number }`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/normalize.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compileNormalizers, normalize, toUtc } = require('../normalize');

const OS_RULE = {
  name: 'os-build',
  regex: 'Windows (\\d+)(?: [A-Za-z]+)? \\d+\\.\\d+\\.\\d+',
  flags: 'g',
  replace: 'Windows $1',
};
const C = compileNormalizers({ timezone: true, rewrites: [OS_RULE] });

test('git-style timestamp is converted to UTC', () => {
  // +0530 is IST; 21:08:56 local is 15:38:56Z
  const r = toUtc('commit at 2026-09-17 21:08:56 +0530 done');
  assert.match(r.text, /2026-09-17T15:38:56Z/);
  assert.ok(!r.text.includes('+0530'), r.text);
  assert.strictEqual(r.count, 1);
});

test('ISO timestamp with a colon offset is converted', () => {
  const r = toUtc('at 2026-09-17T21:08:56+05:30 ok');
  assert.match(r.text, /2026-09-17T15:38:56Z/);
  assert.ok(!r.text.includes('05:30'), r.text);
});

test('a negative offset is converted the other way', () => {
  // -0700 is PDT; 08:00:00 local is 15:00:00Z
  const r = toUtc('at 2026-09-17 08:00:00 -0700 ok');
  assert.match(r.text, /2026-09-17T15:00:00Z/);
});

test('fractional seconds survive conversion', () => {
  const r = toUtc('at 2026-09-17T21:08:56.250+05:30 ok');
  assert.match(r.text, /2026-09-17T15:38:56\.250Z/);
});

test('a UTC timestamp is already normal and is left alone', () => {
  const s = 'at 2026-09-17T15:38:56Z ok';
  assert.strictEqual(toUtc(s).text, s);
});

test('a bare offset with no datetime is blanked, so the zone never survives', () => {
  const r = toUtc('TZ is +0530 here');
  assert.ok(!r.text.includes('+0530'), r.text);
  assert.match(r.text, /\+0000/);
});

test('multiple timestamps in one string all convert', () => {
  const r = toUtc('a 2026-01-02 03:04:05 +0530 b 2026-01-02 03:04:05 +0530 c');
  assert.strictEqual(r.count, 2);
  assert.ok(!r.text.includes('+0530'), r.text);
});

test('does NOT touch version numbers, IDs, hex or IPs', () => {
  for (const s of [
    'version 2.10.1234567890',
    'const id = 1234567890;',
    'sha 9f8e7d6c5b4a39281706',
    'IPv4 192.168.100.1000',
    'range 2026-2030',
    'offset +5 items',
    'balance -0700.50 usd',
  ]) {
    assert.strictEqual(toUtc(s).text, s, s);
  }
});

test('an unparseable datetime is left alone rather than made wrong', () => {
  const s = 'at 2026-13-45 99:99:99 +0530 ok';
  const r = toUtc(s);
  // The date is nonsense, so no instant can be computed. The offset must still
  // not survive.
  assert.ok(!r.text.includes('+0530'), r.text);
});

test('OS build string is generalized', () => {
  const r = normalize('OS Version: Windows 11 Pro 10.0.26200', C);
  assert.strictEqual(r.text, 'OS Version: Windows 11');
  assert.strictEqual(r.count, 1);
});

test('OS build generalization handles the editionless form', () => {
  assert.strictEqual(normalize('Windows 10 10.0.19045', C).text, 'Windows 10');
});

test('win32 is retained because tools branch on it', () => {
  const s = 'Platform: win32';
  assert.strictEqual(normalize(s, C).text, s);
});

test('normalize applies both timezone and rewrites, and counts both', () => {
  const r = normalize('Windows 11 Pro 10.0.26200 at 2026-09-17 21:08:56 +0530', C);
  assert.match(r.text, /^Windows 11 at 2026-09-17T15:38:56Z$/);
  assert.strictEqual(r.count, 2);
});

test('timezone can be disabled independently', () => {
  const off = compileNormalizers({ timezone: false, rewrites: [OS_RULE] });
  const s = 'at 2026-09-17 21:08:56 +0530';
  assert.strictEqual(normalize(s, off).text, s);
});

test('an invalid rewrite regex is skipped, not fatal', () => {
  const warn = [];
  const c = compileNormalizers(
    { timezone: false, rewrites: [{ name: 'bad', regex: '([unclosed', flags: 'g', replace: 'x' }, OS_RULE] },
    (m) => warn.push(m)
  );
  assert.strictEqual(warn.length, 1);
  assert.strictEqual(normalize('Windows 11 Pro 10.0.26200', c).text, 'Windows 11');
});

test('empty config is a no-op', () => {
  const c = compileNormalizers({});
  const s = 'Windows 11 Pro 10.0.26200 at 2026-09-17 21:08:56 +0530';
  assert.strictEqual(normalize(s, c).text, s);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/normalize.test.js`
Expected: FAIL — `Cannot find module '../normalize'`

- [ ] **Step 3: Write the implementation**

Create `proxy/normalize.js`:

```js
'use strict';

// One-way environment normalization.
//
// Distinct from redaction on purpose. Redaction turns a value into a label and
// is reversible for local tools, which suits anything the model might need to
// use in a command. Normalization rewrites a value to a coarser one with no
// label and no reverse, which suits a timezone offset or an OS build string --
// nothing round-trips them, and a label there would just be noise the model has
// to reason around.
//
// The hazard here is over-matching. A rule that fires on a version number, an
// ID or an IP address is worse than the leak it closes, so every pattern is
// anchored tightly and the test suite carries negative cases.

// A full datetime with a trailing offset. Requires a real date AND time, so a
// bare "2026-2030" or "+5" cannot match.
const DATETIME_OFFSET =
  /(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?\s?([+-])(\d{2}):?(\d{2})\b/g;

// A bare offset not attached to a datetime. Must be preceded by whitespace or
// '=' and be exactly 4 digits, so "+5 items" and "-0700.50" do not match.
const BARE_OFFSET = /(^|[\s=])([+-])(\d{2})(\d{2})(?![\d.])/g;

function toUtc(text) {
  let count = 0;

  let out = text.replace(
    DATETIME_OFFSET,
    (m, y, mo, d, h, mi, s, frac, sign, oh, om) => {
      const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}${frac || ''}${sign}${oh}:${om}`;
      const ms = Date.parse(iso);
      if (!Number.isFinite(ms)) {
        // Nonsense date: no instant can be computed, but the zone must still
        // not survive. Blank the offset and leave the rest as written.
        count++;
        return `${y}-${mo}-${d}T${h}:${mi}:${s}${frac || ''}+0000`;
      }
      count++;
      const u = new Date(ms).toISOString(); // e.g. 2026-09-17T15:38:56.250Z
      return frac ? u : u.replace(/\.\d{3}Z$/, 'Z');
    }
  );

  out = out.replace(BARE_OFFSET, (m, pre) => {
    count++;
    return `${pre}+0000`;
  });

  return { text: out, count };
}

function compileNormalizers(cfg = {}, warn = () => {}) {
  const rewrites = [];
  for (const r of cfg.rewrites || []) {
    if (!r || typeof r.regex !== 'string') continue;
    try {
      const flags = r.flags && r.flags.includes('g') ? r.flags : `${r.flags || ''}g`;
      rewrites.push({
        name: r.name || 'rewrite',
        re: new RegExp(r.regex, flags),
        replace: typeof r.replace === 'string' ? r.replace : '',
      });
    } catch (e) {
      warn(`normalize rewrite "${r.name || '?'}" disabled: ${e.message}`);
    }
  }
  return { timezone: cfg.timezone === true, rewrites };
}

function normalize(text, compiled) {
  if (typeof text !== 'string' || !compiled) return { text, count: 0 };
  let out = text;
  let count = 0;

  for (const r of compiled.rewrites) {
    r.re.lastIndex = 0;
    out = out.replace(r.re, (...args) => {
      count++;
      // Build the replacement with $1..$9 support, without re-running the regex.
      return r.replace.replace(/\$(\d)/g, (_, n) => args[Number(n)] ?? '');
    });
  }

  if (compiled.timezone) {
    const t = toUtc(out);
    out = t.text;
    count += t.count;
  }

  return { text: out, count };
}

module.exports = { compileNormalizers, normalize, toUtc };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/normalize.test.js`
Expected: PASS, 16 tests

- [ ] **Step 5: Commit**

```bash
git add proxy/normalize.js proxy/test/normalize.test.js
git commit -m "feat(proxy): one-way environment normalization for timezone and OS build"
```

---

### Task 2: Wire normalization in, and add git-remote patterns

Normalization runs **after** redaction and aliasing. Order matters: redaction must see the original text so its spans stay meaningful for Phase 2 derivation, and a normalized timestamp must not then be scanned as a phone number.

Git remotes need no code — two `patterns` entries with lookbehind.

**Files:**
- Modify: `proxy/walk.js` (call `normalize` in `transformString`, accept `normalizers` in `makeContext`)
- Modify: `proxy/start.js` (compile from config, pass through)
- Modify: `redact-rules.example.json` (add `normalize` block and the two git patterns)
- Modify: `proxy/test/walk.test.js` (add wiring tests)

**Interfaces:**
- Consumes: `compileNormalizers`, `normalize` (Task 1).
- Produces: `makeContext({ ..., normalizers = null })`; `ctx.stats.normalized` counter.

- [ ] **Step 1: Write the failing test**

Append to `proxy/test/walk.test.js`:

```js
test('normalization runs on message content', () => {
  const { compileNormalizers } = require('../normalize');
  const c = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }),
    aliases: [],
    normalizers: compileNormalizers({
      timezone: true,
      rewrites: [{ name: 'os', regex: 'Windows (\\d+)(?: [A-Za-z]+)? \\d+\\.\\d+\\.\\d+', flags: 'g', replace: 'Windows $1' }],
    }),
  });
  const out = transformBody(
    { messages: [{ role: 'user', content: 'Windows 11 Pro 10.0.26200 at 2026-09-17 21:08:56 +0530' }] },
    c
  );
  assert.strictEqual(out.messages[0].content, 'Windows 11 at 2026-09-17T15:38:56Z');
  assert.ok(c.stats.normalized >= 2, `normalized=${c.stats.normalized}`);
});

test('normalization leaves tools[] and thinking blocks alone', () => {
  const { compileNormalizers } = require('../normalize');
  const c = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }),
    aliases: [],
    normalizers: compileNormalizers({ timezone: true, rewrites: [] }),
  });
  const tools = [{ name: 'X', description: 'at 2026-09-17 21:08:56 +0530' }];
  const th = { type: 'thinking', thinking: 'at 2026-09-17 21:08:56 +0530', signature: 'S' };
  const out = transformBody({ tools, messages: [{ role: 'assistant', content: [th] }] }, c);
  assert.deepStrictEqual(out.tools, tools);
  assert.strictEqual(out.messages[0].content[0], th);
});

test('no normalizers configured is a no-op', () => {
  const c = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }),
    aliases: [],
  });
  const s = 'at 2026-09-17 21:08:56 +0530';
  assert.strictEqual(transformBody({ messages: [{ role: 'user', content: s }] }, c).messages[0].content, s);
});

test('git remote org and repo are redacted by pattern, not normalization', () => {
  const rules = compile({
    literals: [],
    patterns: [
      { name: 'git-org', regex: '(?<=(?:github|gitlab|bitbucket)\\.(?:com|org)[/:])[A-Za-z0-9._-]+', flags: 'g' },
      { name: 'git-repo', regex: '(?<=(?:github|gitlab|bitbucket)\\.(?:com|org)[/:][A-Za-z0-9._-]{1,64}/)[A-Za-z0-9._-]+', flags: 'g' },
    ],
  });
  const c = makeContext({ kLabel: Buffer.alloc(32, 3), kMemo: Buffer.alloc(32, 4), rules, aliases: [] });
  const out = transformBody(
    { messages: [{ role: 'user', content: 'origin  git@github.com:acme-corp/billing.git' }] },
    c
  );
  const got = out.messages[0].content;
  assert.ok(!got.includes('acme-corp'), got);
  assert.ok(!got.includes('billing'), got);
  assert.match(got, /\[PII:git-org:[0-9a-f]{16}\]/);
  assert.match(got, /\[PII:git-repo:[0-9a-f]{16}\]/);
  assert.ok(got.includes('github.com'), 'the host itself is not secret');
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/walk.test.js`
Expected: FAIL — `normalizers` is ignored, so the content comes back unchanged.

- [ ] **Step 3: Wire it into `proxy/walk.js`**

Add to the requires at the top:

```js
const { normalize } = require('./normalize');
```

Add `normalized: 0` to the object returned by `freshStats()`.

Change the `makeContext` signature to accept `normalizers`:

```js
function makeContext({ kLabel, kMemo, rules, aliases, cache = null, normalizers = null, memoMax = 2000 }) {
```

and include `normalizers` in the returned context object.

In `transformString`, add normalization as the LAST step, after aliasing:

```js
  // Normalization runs last. Redaction must see the ORIGINAL text so its spans
  // stay meaningful for Phase 2 derivation, and a timestamp rewritten to UTC
  // must not then be re-scanned as a phone number.
  if (ctx.normalizers) {
    const n = normalize(a.text, ctx.normalizers);
    ctx.stats.normalized += n.count;
    return n.text;
  }
  return a.text;
```

- [ ] **Step 4: Wire it into `proxy/start.js`**

```js
const { compileNormalizers } = require('./normalize');

  const normalizers = compileNormalizers(rules.normalize, (m) => logger.warn(m));
  const ctx = makeContext({ kLabel, kMemo, rules: compiled, aliases, cache, normalizers });
```

Add the rewrite count to the existing startup log line.

- [ ] **Step 5: Add the config to `redact-rules.example.json`**

Add two `patterns` entries (git remotes) and a `normalize` block:

```json
    {
      "_comment": "Git remote org name. Lookbehind anchors it to a known forge host so it cannot fire on arbitrary text. Redacted rather than normalized because the model may need to use the real name in a command, and a label resolves back for local tools.",
      "name": "git-org",
      "regex": "(?<=(?:github|gitlab|bitbucket)\\.(?:com|org)[/:])[A-Za-z0-9._-]+",
      "flags": "g"
    },
    {
      "_comment": "Git remote repository name, anchored the same way.",
      "name": "git-repo",
      "regex": "(?<=(?:github|gitlab|bitbucket)\\.(?:com|org)[/:][A-Za-z0-9._-]{1,64}/)[A-Za-z0-9._-]+",
      "flags": "g"
    }
```

```json
  "_normalize_comment": "One-way rewrites with no label and no reverse, for fingerprints nothing needs to round-trip. `timezone` converts any datetime carrying an offset to UTC and blanks bare offsets, because a +0530 in git log output pins your region. `rewrites` are regex replacements supporting $1..$9.",
  "normalize": {
    "timezone": true,
    "rewrites": [
      {
        "name": "os-build",
        "regex": "Windows (\\d+)(?: [A-Za-z]+)? \\d+\\.\\d+\\.\\d+",
        "flags": "g",
        "replace": "Windows $1"
      }
    ]
  },
```

- [ ] **Step 6: Run the whole suite**

Run: `node --test proxy/test/*.test.js`
Expected: PASS, 178 tests (158 + 16 normalize + 4 walk), 0 failures

- [ ] **Step 7: Verify the example config compiles cleanly**

Run: `node -e "const r=require('./proxy/rules');const n=require('./proxy/normalize');const w=[];const c=r.compile(r.load('./redact-rules.example.json'),m=>w.push(m));const nn=n.compileNormalizers(require('./redact-rules.example.json').normalize,m=>w.push(m));console.log('regexes',c.regexes.length,'literals',c.literalCount,'rewrites',nn.rewrites.length,'tz',nn.timezone,'warnings',w)"`
Expected: `regexes 7 literals 5 rewrites 1 tz true warnings []`

`regexes` is 7, not 9: Phase 2 gave each literal its own compiled regex (5), and
the patterns group into two flag buckets — `email` is `gi`, while `phone`,
`git-org` and `git-repo` are all `g` and share one. Verified against the current
config before this plan was written.

- [ ] **Step 8: Commit**

```bash
git add proxy/walk.js proxy/start.js proxy/test/walk.test.js redact-rules.example.json
git commit -m "feat(proxy): wire normalization into the outbound walk, add git-remote patterns"
```

---

### Task 3: `device_id` — opt-in, off by default

`metadata.user_id` is a JSON string holding `{ device_id, account_uuid, session_id }`. `device_id` is a stable SHA-256 machine fingerprint that persists across every session, so it links sessions to one machine even though the account is already known.

This is the one change with **account-level** rather than local consequences — it plausibly feeds abuse detection — so it stays off unless the user turns it on, and offers a middle setting rather than only all-or-nothing.

**Files:**
- Create: `proxy/device.js`
- Create: `proxy/test/device.test.js`
- Modify: `proxy/walk.js` (apply to `metadata` when enabled)
- Modify: `proxy/start.js` (read config, derive the key)
- Modify: `redact-rules.example.json`

**Interfaces:**
- Consumes: `subkey(master, purpose)` from `proxy/keys.js`.
- Produces:
  - `makeDeviceRewriter({ mode, kDevice, sessionId? }) -> null | ((metadata: object) => object)`
  - modes: `"off"` (returns null), `"stable"`, `"session"`

- [ ] **Step 1: Write the failing test**

Create `proxy/test/device.test.js`:

```js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { makeDeviceRewriter } = require('../device');

const K = Buffer.alloc(32, 61);
const REAL = 'a'.repeat(64);
const md = () => ({ user_id: JSON.stringify({ device_id: REAL, account_uuid: '', session_id: 'S1' }) });

test('off returns null so metadata is never touched', () => {
  assert.strictEqual(makeDeviceRewriter({ mode: 'off', kDevice: K }), null);
  assert.strictEqual(makeDeviceRewriter({ kDevice: K }), null);
});

test('stable replaces device_id with a different value', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  const out = JSON.parse(f(md()).user_id);
  assert.notStrictEqual(out.device_id, REAL);
  assert.match(out.device_id, /^[0-9a-f]{64}$/, 'must keep the same shape');
});

test('stable is deterministic across calls and processes', () => {
  const a = JSON.parse(makeDeviceRewriter({ mode: 'stable', kDevice: K })(md()).user_id);
  const b = JSON.parse(makeDeviceRewriter({ mode: 'stable', kDevice: K })(md()).user_id);
  assert.strictEqual(a.device_id, b.device_id);
});

test('stable differs under a different key', () => {
  const a = JSON.parse(makeDeviceRewriter({ mode: 'stable', kDevice: K })(md()).user_id);
  const b = JSON.parse(makeDeviceRewriter({ mode: 'stable', kDevice: Buffer.alloc(32, 62) })(md()).user_id);
  assert.notStrictEqual(a.device_id, b.device_id);
});

test('session differs between rewriters but is stable within one', () => {
  const f = makeDeviceRewriter({ mode: 'session', kDevice: K });
  const g = makeDeviceRewriter({ mode: 'session', kDevice: K });
  const a1 = JSON.parse(f(md()).user_id).device_id;
  const a2 = JSON.parse(f(md()).user_id).device_id;
  const b1 = JSON.parse(g(md()).user_id).device_id;
  assert.strictEqual(a1, a2, 'stable within one rewriter');
  assert.notStrictEqual(a1, b1, 'differs across rewriters');
});

test('session_id and account_uuid are preserved untouched', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  const out = JSON.parse(f(md()).user_id);
  assert.strictEqual(out.session_id, 'S1');
  assert.strictEqual(out.account_uuid, '');
});

test('other metadata keys are preserved', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  const out = f({ user_id: md().user_id, other: 'keep' });
  assert.strictEqual(out.other, 'keep');
});

test('metadata without a parseable user_id is returned unchanged', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  const bad = { user_id: 'not json' };
  assert.deepStrictEqual(f(bad), bad);
  assert.deepStrictEqual(f({}), {});
});

test('the real device_id never appears in the output', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  assert.ok(!JSON.stringify(f(md())).includes(REAL));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test proxy/test/device.test.js`
Expected: FAIL — `Cannot find module '../device'`

- [ ] **Step 3: Write the implementation**

Create `proxy/device.js`:

```js
'use strict';

// Optional rewriting of metadata.user_id's device_id.
//
// device_id is a stable SHA-256 machine fingerprint sent on every request. The
// account is already identified by the API key, so this adds a persistent
// MACHINE identity on top -- which is what makes cross-session correlation to
// one computer possible.
//
// Off by default, and deliberately so: unlike everything else in this proxy, a
// change here has ACCOUNT-level consequences rather than local ones. A device
// fingerprint that changes every session plausibly looks like abuse.
//
//   "stable"  -- HMAC(k_device, real_id): a different value, but consistent
//                forever. Hides the real fingerprint without looking like a new
//                machine each time. The sensible middle.
//   "session" -- random per proxy start. Maximum unlinkability, highest chance
//                of tripping something.

const crypto = require('crypto');

function makeDeviceRewriter({ mode = 'off', kDevice, sessionId } = {}) {
  if (mode !== 'stable' && mode !== 'session') return null;

  const sessionValue =
    mode === 'session' ? (sessionId || crypto.randomBytes(32).toString('hex')) : null;

  return function rewrite(metadata) {
    if (!metadata || typeof metadata !== 'object') return metadata;
    if (typeof metadata.user_id !== 'string') return metadata;

    let inner;
    try {
      inner = JSON.parse(metadata.user_id);
    } catch (e) {
      return metadata; // shape we do not recognise: leave it alone
    }
    if (!inner || typeof inner.device_id !== 'string') return metadata;

    const replacement =
      mode === 'session'
        ? sessionValue
        : crypto.createHmac('sha256', kDevice).update(inner.device_id, 'utf8').digest('hex');

    return Object.assign({}, metadata, {
      user_id: JSON.stringify(Object.assign({}, inner, { device_id: replacement })),
    });
  };
}

module.exports = { makeDeviceRewriter };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test proxy/test/device.test.js`
Expected: PASS, 9 tests

- [ ] **Step 5: Apply it in `proxy/walk.js`**

`metadata` is currently passed through untouched by `transformBody`. Add, after the `messages` handling and before the return:

```js
  // metadata is otherwise passed through byte-identical; this is the single
  // exception, and only when explicitly enabled.
  if (ctx.deviceRewriter && body.metadata) out.metadata = ctx.deviceRewriter(body.metadata);
```

Accept `deviceRewriter = null` in `makeContext` and store it on the context.

Add a test to `proxy/test/walk.test.js`:

```js
test('metadata is untouched unless a device rewriter is configured', () => {
  const metadata = { user_id: JSON.stringify({ device_id: 'd'.repeat(64), account_uuid: '', session_id: 'S' }) };
  const plain = makeContext({
    kLabel: Buffer.alloc(32, 3), kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }), aliases: [],
  });
  assert.deepStrictEqual(transformBody({ metadata, messages: [] }, plain).metadata, metadata);

  const { makeDeviceRewriter } = require('../device');
  const withRw = makeContext({
    kLabel: Buffer.alloc(32, 3), kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }), aliases: [],
    deviceRewriter: makeDeviceRewriter({ mode: 'stable', kDevice: Buffer.alloc(32, 9) }),
  });
  const out = transformBody({ metadata, messages: [] }, withRw).metadata;
  assert.ok(!JSON.stringify(out).includes('d'.repeat(64)));
});
```

- [ ] **Step 6: Wire `proxy/start.js`**

```js
const { makeDeviceRewriter } = require('./device');

  const kDevice = subkey(master, 'device');
  const deviceRewriter = makeDeviceRewriter({
    mode: (rules.deviceId && rules.deviceId.mode) || 'off',
    kDevice,
  });
  // ...pass deviceRewriter into makeContext alongside normalizers
  if (deviceRewriter) logger.warn('device_id rewriting is ENABLED; if the API starts rejecting requests, set deviceId.mode back to "off"');
```

- [ ] **Step 7: Add the config to `redact-rules.example.json`**

```json
  "_deviceId_comment": "metadata.user_id carries a stable SHA-256 machine fingerprint. The account is already identified by your API key, so this adds a persistent MACHINE identity on top. OFF by default because, unlike everything else here, changing it has account-level rather than local consequences. \"stable\" = a different but consistent value (hides the real fingerprint without looking like a new machine each session). \"session\" = random per proxy start (maximum unlinkability, highest chance of tripping abuse checks).",
  "deviceId": { "mode": "off" },
```

- [ ] **Step 8: Run the whole suite and commit**

Run: `node --test proxy/test/*.test.js`
Expected: PASS, 188 tests (178 + 9 device + 1 walk), 0 failures

```bash
git add proxy/device.js proxy/test/device.test.js proxy/walk.js proxy/start.js proxy/test/walk.test.js redact-rules.example.json
git commit -m "feat(proxy): opt-in device_id rewriting, off by default"
```

---

## Phase 3 completion criteria

- [ ] `node --test proxy/test/*.test.js` passes with zero failures
- [ ] A git-style timestamp reaches the model as UTC with no offset
- [ ] `Windows 11 Pro 10.0.26200` reaches the model as `Windows 11`, while `win32` survives
- [ ] A git remote's org and repo are labelled, while the host is not
- [ ] Version numbers, IDs, hex strings and IP addresses are provably untouched
- [ ] `metadata` stays byte-identical with `deviceId.mode: "off"`
- [ ] All 158 Phase 1–2 tests still pass unchanged

## Deferred to Phase 3b and Phase 4

| Item | Phase |
|---|---|
| Egress tunnel (SOCKS5 / HTTP CONNECT), fail-closed | 3b |
| Local residue: transcripts, `file-history/`, cache retention | 4 |
