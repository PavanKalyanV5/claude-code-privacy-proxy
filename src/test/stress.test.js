'use strict';

// Stress and resilience tests.
//
// Scope: integrity first (personal data must never escape, files must never be
// corrupted), then availability (it must not crash, hang, or leak), then
// resilience (it must degrade predictably when things fail).
//
// These are permanent tests rather than one-off scripts, because every failure
// this project has actually produced was silent: a stale tunnel decision that
// kept reporting "protected", a status line claiming a tunnel it was not
// using, a pipeline divergence that corrupted edits, an alias that rewrote
// source files on write. Nothing here checks that a happy path works -- the
// unit suite does that. Everything here checks that a BAD path is loud.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const { compile } = require('../rules');
const { compileAliases } = require('../aliases');
const { compileNormalizers } = require('../normalize');
const { compileHeaderPolicy } = require('../headers');
const { makeContext, transformBody, resetStats } = require('../walk');
const { createResolver } = require('../resolver');
const { createServer } = require('../server');
const { renderForModel } = require('../pipeline');

const K = Buffer.alloc(32, 200);
const NAME = 'Jane Q. Testerson';
const MAIL = 'janeqtest@gmail.com';
const RULES = compile({
  literals: [NAME, MAIL],
  patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}', flags: 'gi' }],
});
const ALIASES = compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\SOMEONE' }]);
const NORM = compileNormalizers({ timezone: true, rewrites: [] });
const PIPE = { rules: RULES, kLabel: K, aliases: ALIASES, normalizers: NORM };

const ctx = () => makeContext({ kLabel: K, kMemo: Buffer.alloc(32, 201), rules: RULES, aliases: ALIASES, normalizers: NORM });
const LABEL_RE = /\[PII:[a-z0-9-]+:[0-9a-f]{16}\]/;

function through(text, c = ctx()) {
  return transformBody({ messages: [{ role: 'user', content: text }] }, c).messages[0].content;
}

// ===================================================== INTEGRITY: no leaks

test('integrity: 2000 varied messages never leak a literal', () => {
  const c = ctx();
  const shapes = [
    (v) => v,
    (v) => `prefix ${v}`,
    (v) => `${v} suffix`,
    (v) => `(${v})`,
    (v) => `"${v}"`,
    (v) => `${v},${v}`,
    (v) => `${v}${v}`,
    (v) => `<<${v}>>`,
    (v) => `\n${v}\n`,
    (v) => `\t${v};`,
    (v) => `[${v}]`,
    (v) => `${v}.`,
    (v) => `-${v}-`,
    (v) => `${v}\u0000tail`,
    (v) => `${'x'.repeat(500)}${v}${'y'.repeat(500)}`,
  ];
  for (let i = 0; i < 2000; i++) {
    const v = i % 2 === 0 ? NAME : MAIL;
    const out = through(shapes[i % shapes.length](v), c);
    assert.ok(!out.includes(v), `leaked at shape ${i % shapes.length}: ${JSON.stringify(out.slice(0, 120))}`);
  }
});

test('integrity: memoization never returns another block\'s result', () => {
  // The memo is keyed by content HMAC. A key bug would serve one message's
  // redaction for a different message -- the worst possible failure, because
  // the output would look perfectly well-formed.
  const c = ctx();
  const seen = new Set();
  for (let i = 0; i < 3000; i++) {
    const out = through(`user ${i} is ${NAME} at box-${i}`, c);
    assert.ok(out.includes(`user ${i} `), `block ${i} got another block's text`);
    assert.ok(out.includes(`box-${i}`), `block ${i} lost its unique suffix`);
    assert.ok(!out.includes(NAME));
    assert.ok(!seen.has(out), `duplicate output for distinct inputs at ${i}`);
    seen.add(out);
  }
});

test('integrity: memo stays bounded and evicts', () => {
  const c = makeContext({ kLabel: K, kMemo: Buffer.alloc(32, 201), rules: RULES, aliases: ALIASES, normalizers: NORM, memoMax: 100 });
  for (let i = 0; i < 5000; i++) through(`unique block ${i} ${NAME}`, c);
  assert.ok(c.memo.size <= 101, `memo grew to ${c.memo.size}; unbounded growth is a leak`);
});

test('integrity: determinism holds across 500 repeats (prompt caching depends on it)', () => {
  const body = { messages: [{ role: 'user', content: `${NAME} at ${MAIL}` }] };
  const first = JSON.stringify(transformBody(body, ctx()));
  for (let i = 0; i < 500; i++) {
    assert.strictEqual(JSON.stringify(transformBody(body, ctx())), first, `diverged on repeat ${i}`);
  }
});

// ============================================ INTEGRITY: offset arithmetic

test('integrity: astral-plane characters do not corrupt a resolved edit', () => {
  // Emoji are surrogate pairs in JS strings. If any stage mixed code points
  // with code units, offsets would drift and a resolved edit would slice
  // through a character -- silent file corruption.
  //
  // An earlier version asserted that NO mapped offset ever lands on a low
  // surrogate. That was wrong: mapping an arbitrary index through an identity
  // region legitimately returns the same index, and index 1 of a string
  // starting with an emoji IS mid-pair. Nothing slices there, because
  // old_string boundaries come from indexOf of a model-supplied substring,
  // which cannot start mid-pair. The property that matters is below: a
  // resolved edit lands on text that exists, and applying it leaves no
  // orphaned surrogate.
  const emoji = '\u{1F468}\u200D\u{1F469}\u200D\u{1F467}\u{1F389}';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'astral-'));
  const resolver = createResolver({ rules: RULES, kLabel: K, aliases: ALIASES, normalizers: NORM });
  const bodies = [
    `${emoji} ${NAME} ${emoji}`,
    `${NAME}${emoji}`,
    `${emoji}${MAIL}`,
    `a${emoji}b${NAME}c${emoji}d`,
    `${'\u{1F389}'.repeat(200)}${NAME}`,
  ];
  let applied = 0;

  bodies.forEach((body, i) => {
    const real = body + '\n';
    const f = path.join(dir, `a${i}.txt`);
    fs.writeFileSync(f, real);
    const seen = renderForModel(real, PIPE);
    assert.ok(!seen.text.includes(NAME), 'leaked next to astral chars');

    const line = seen.text.split('\n')[0];
    const out = resolver.resolveToolInput('Edit', { file_path: f, old_string: line, new_string: 'REPLACED' });
    if (!out || out.old_string === line) return; // refusal is safe

    assert.ok(real.includes(out.old_string), `case ${i}: resolved text is not in the file`);
    const result = real.replace(out.old_string, out.new_string);
    for (let j = 0; j < result.length; j++) {
      const code = result.charCodeAt(j);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = result.charCodeAt(j + 1);
        assert.ok(next >= 0xdc00 && next <= 0xdfff, `case ${i}: high surrogate at ${j} with nothing after it`);
        j++;
      } else {
        assert.ok(!(code >= 0xdc00 && code <= 0xdfff), `case ${i}: orphaned low surrogate at ${j}`);
      }
    }
    applied++;
  });

  assert.ok(applied > 0, 'no astral case resolved, so nothing was actually exercised');
});

test('integrity: combining marks and RTL text survive the pipeline', () => {
  const tricky = ['e\u0301', '\u0645\u0631\u062D\u0628\u0627', '\u05E2\u05D1\u05E8\u05D9\u05EA', 'a\u200bb', '\uFEFFbom'];
  for (const t of tricky) {
    const out = through(`${t} ${NAME} ${t}`);
    assert.ok(!out.includes(NAME), `leaked around ${JSON.stringify(t)}`);
    assert.ok(out.includes(t), `mangled ${JSON.stringify(t)}: ${JSON.stringify(out)}`);
  }
});

test('integrity: edits on unique lines resolve, and refusals never corrupt', () => {
  // Property: whatever the model sees must resolve to text that exists
  // verbatim on disk. A refusal is always acceptable -- it fails the edit
  // loudly. What must never happen is a resolved old_string that is NOT in
  // the file, because that either fails confusingly or matches the wrong
  // place.
  //
  // Lines are unique on purpose. An earlier version generated repeating lines
  // and measured 57% refusals, which looked alarming but was the fixture's
  // fault: identical rendered lines are genuinely ambiguous, and refusing
  // ambiguity is correct. Unique lines measure whether ordinary edits work.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'stress-'));
  const resolver = createResolver({ rules: RULES, kLabel: K, aliases: ALIASES, normalizers: NORM });
  const pieces = [NAME, MAIL, 'C:\\Users\\SOMEONE\\x', '2026-09-18T10:00:00Z', 'plain text', 'const x = 1;'];
  let resolved = 0;
  let refused = 0;
  const ITER = 600;

  for (let i = 0; i < ITER; i++) {
    const n = 1 + (i % 5);
    const lines = [];
    for (let j = 0; j < n; j++) {
      lines.push(`L${i}_${j} uid${i * 17 + j} ${pieces[(i + j) % pieces.length]} end${i}_${j}`);
    }
    const real = lines.join('\n') + '\n';
    const f = path.join(dir, `f${i}.txt`);
    fs.writeFileSync(f, real);

    const seen = renderForModel(real, PIPE).text;
    const seenLine = seen.split('\n')[i % n];
    if (!seenLine) continue;

    const out = resolver.resolveToolInput('Edit', { file_path: f, old_string: seenLine, new_string: 'REPLACED' });
    // An unchanged old_string is only a REFUSAL when the line actually needed
    // translating. When the model's view of the line is byte-identical to disk
    // -- a line with nothing redactable in it -- returning it unchanged is the
    // correct answer, not a failure. An earlier version of this test counted
    // those as refusals and reported a 43% failure rate for what was in fact
    // 100% correct behaviour.
    const diskLine = real.split('\n')[i % n];
    const neededTranslation = seenLine !== diskLine;
    if (!out) {
      refused++;
      continue;
    }
    if (out.old_string === seenLine) {
      if (neededTranslation) refused++;
      else resolved++;
      continue;
    }
    assert.ok(real.includes(out.old_string), `iteration ${i}: resolved old_string is not in the file: ${JSON.stringify(out.old_string)}`);
    assert.notStrictEqual(real.replace(out.old_string, out.new_string), real, `iteration ${i}: edit applied as a no-op`);
    resolved++;
  }

  const rate = resolved / (resolved + refused);
  assert.ok(rate > 0.9, `only ${(rate * 100).toFixed(1)}% of unambiguous edits resolved (${resolved} ok, ${refused} refused)`);
});

// ================================================= AVAILABILITY: big input

test('availability: a large body is transformed in reasonable time', () => {
  const big = `${NAME} and ${MAIL} and filler `.repeat(20000); // ~1MB
  const t0 = Date.now();
  const out = through(big);
  const ms = Date.now() - t0;
  assert.ok(!out.includes(NAME));
  assert.ok(ms < 20000, `took ${ms}ms, too slow to be usable`);
});

test('availability: 5000 message blocks in one body', () => {
  const messages = [];
  for (let i = 0; i < 5000; i++) messages.push({ role: 'user', content: `msg ${i}: ${NAME}` });
  const out = transformBody({ messages }, ctx());
  assert.strictEqual(out.messages.length, 5000);
  assert.ok(!JSON.stringify(out).includes(NAME));
});

test('availability: deeply nested structures do not take the process down', () => {
  let node = { content: NAME };
  for (let i = 0; i < 5000; i++) node = { nested: node };
  let threw = null;
  try {
    transformBody({ messages: [{ role: 'user', content: [node] }] }, ctx());
  } catch (e) {
    threw = e;
  }
  // Either outcome is fine. What matters is that a throw is treated as
  // fail-closed by the server, asserted separately below.
  assert.ok(threw === null || threw instanceof Error);
});

// ================================== AVAILABILITY: concurrency through HTTP

function startProxy(cb) {
  const received = [];
  const upstream = http.createServer((ur, ures) => {
    const chunks = [];
    ur.on('data', (c) => chunks.push(c));
    ur.on('end', () => {
      received.push(Buffer.concat(chunks).toString('utf8'));
      ures.writeHead(200, { 'content-type': 'application/json' });
      ures.end('{"ok":true}');
    });
  });
  upstream.listen(0, '127.0.0.1', () => {
    const c = ctx();
    const proxy = createServer({
      ctx: c,
      aliases: ALIASES,
      logger: { warn: () => {}, line: () => {} },
      resolver: createResolver({ render: c.render }),
      upstream: '127.0.0.1',
      upstreamPort: upstream.address().port,
      insecure: true,
      headerPolicy: compileHeaderPolicy({}),
    });
    proxy.listen(0, '127.0.0.1', () => cb({ proxy, upstream, port: proxy.address().port, received }));
  });
}

// 30s rather than 15s. Verified in isolation that every adversarial shape in
// this file answers in under 20ms, so a timeout here is never the proxy
// thinking -- it is Windows ephemeral-port pressure after the 200-concurrent
// test has filled TIME_WAIT, which delays establishing later connections. A
// shorter timeout made this file fail intermittently for a reason that had
// nothing to do with the code under test.
function post(port, body, timeoutMs = 30000, agent) {
  return new Promise((resolve, reject) => {
    const r = http.request(
      { hostname: '127.0.0.1', port, path: '/v1/messages', method: 'POST', agent, headers: { 'content-type': 'application/json' } },
      (res) => {
        let out = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (out += c));
        res.on('end', () => resolve({ status: res.statusCode, body: out }));
      }
    );
    r.setTimeout(timeoutMs, () => r.destroy(new Error('client timeout')));
    r.on('error', reject);
    r.end(body);
  });
}

// NOTE ON ORDER: this runs BEFORE the 200-concurrent test on purpose.
// Two hundred simultaneous connections fill the Windows ephemeral-port
// table with TIME_WAIT entries, and every test after it pays seconds of
// connect latency. This test verified in isolation that all 15 shapes
// answer in under 20ms, so a timeout here never means the proxy is
// thinking -- it means it is queued behind port exhaustion. Ordering it
// first removes the flake without weakening either test.
test('resilience: adversarial JSON shapes do not stop the proxy serving', async () => {
  const env = await new Promise(startProxy);
  // One socket for all 13 requests: see the note on post().
  const keepAlive = new http.Agent({ keepAlive: true, maxSockets: 1 });
  const shapes = [
    '{}',
    '[]',
    'null',
    '{"messages":null}',
    '{"messages":[]}',
    '{"messages":[{"content":null}]}',
    '{"messages":[{"content":[]}]}',
    '{"messages":[{"content":[{"type":"thinking"}]}]}',
    '{"messages":[{"content":' + JSON.stringify('x'.repeat(100000)) + '}]}',
    '{"messages":[{"content":{"deeply":{"nested":{"but":"fine"}}}}]}',
    '{"tools":[{"name":"x"}],"messages":[]}',
    '{"metadata":{"user_id":"' + 'a'.repeat(1000) + '"},"messages":[]}',
  ];
  try {
    for (const s of shapes) {
      const res = await post(env.port, s, 30000, keepAlive);
      assert.ok(res.status === 200 || res.status === 502, `shape ${s.slice(0, 40)} gave ${res.status}`);
    }
    const ok = await post(env.port, JSON.stringify({ messages: [{ role: 'user', content: NAME }] }), 30000, keepAlive);
    assert.strictEqual(ok.status, 200, 'proxy stopped serving after adversarial input');
  } finally {
    env.proxy.close();
    env.upstream.close();
  }
});

test('availability: 200 concurrent requests all redact, none leak, none mix up', async () => {
  const env = await new Promise(startProxy);
  try {
    const reqs = [];
    for (let i = 0; i < 200; i++) {
      reqs.push(post(env.port, JSON.stringify({ messages: [{ role: 'user', content: `req ${i} from ${NAME} <${MAIL}>` }] })));
    }
    const results = await Promise.all(reqs);
    for (const r of results) assert.strictEqual(r.status, 200, `got ${r.status}`);
    assert.strictEqual(env.received.length, 200, `upstream saw ${env.received.length} of 200`);

    for (let i = 0; i < env.received.length; i++) {
      assert.ok(!env.received[i].includes(NAME), `request ${i} leaked the name under concurrency`);
      assert.ok(!env.received[i].includes(MAIL), `request ${i} leaked the email under concurrency`);
      assert.match(env.received[i], LABEL_RE, `request ${i} was forwarded with no labels at all`);
    }
    const ids = env.received.map((b) => (/req (\d+) from/.exec(b) || [])[1]).filter(Boolean);
    assert.strictEqual(new Set(ids).size, 200, 'request bodies were mixed up under concurrency');
  } finally {
    env.proxy.close();
    env.upstream.close();
  }
});

test('resilience: a transform crash fails CLOSED, forwarding nothing', async () => {
  // The most dangerous failure: crashing after finding redactable content.
  // Forwarding the original body would leak exactly what the transform choked
  // on.
  let forwarded = 0;
  const upstream = http.createServer((ur, ures) => {
    forwarded++;
    ur.resume();
    ures.writeHead(200);
    ures.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));

  const broken = ctx();
  broken.render = null; // renderForModel dereferences this and throws

  const proxy = createServer({
    ctx: broken,
    aliases: ALIASES,
    logger: { warn: () => {}, line: () => {} },
    upstream: '127.0.0.1',
    upstreamPort: upstream.address().port,
    insecure: true,
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));

  try {
    const res = await post(proxy.address().port, JSON.stringify({ messages: [{ role: 'user', content: NAME }] }));
    assert.strictEqual(res.status, 502, 'a transform failure must refuse, not forward');
    assert.strictEqual(forwarded, 0, 'the original body reached upstream -- that is a leak');
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('resilience: non-JSON bodies pass through without breaking the session', async () => {
  const env = await new Promise(startProxy);
  try {
    const res = await post(env.port, 'this is not json at all');
    assert.strictEqual(res.status, 200);
  } finally {
    env.proxy.close();
    env.upstream.close();
  }
});


test('resilience: a dead upstream errors rather than hanging', async () => {
  const upstream = http.createServer((ur, ures) => {
    ur.resume();
    ur.on('end', () => ures.destroy());
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const c = ctx();
  const proxy = createServer({
    ctx: c,
    aliases: ALIASES,
    logger: { warn: () => {}, line: () => {} },
    upstream: '127.0.0.1',
    upstreamPort: upstream.address().port,
    insecure: true,
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  try {
    const res = await Promise.race([
      post(proxy.address().port, JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }), 5000).catch(() => ({ status: 'client-error' })),
      new Promise((r) => setTimeout(() => r({ status: 'HUNG' }), 9000)),
    ]);
    assert.notStrictEqual(res.status, 'HUNG', 'a dead upstream must not hang the request');
  } finally {
    proxy.close();
    upstream.close();
  }
});

test('resilience: stats are not mixed between successive requests', () => {
  // resetStats/transform/snapshot is synchronous today, so counts cannot
  // interleave. This pins that: if anyone makes the path async, the audit log
  // silently starts attributing one request's redactions to another.
  const c = ctx();
  resetStats(c);
  transformBody({ messages: [{ role: 'user', content: `${NAME} ${MAIL}` }] }, c);
  const a = JSON.parse(JSON.stringify(c.stats));
  resetStats(c);
  transformBody({ messages: [{ role: 'user', content: 'nothing here' }] }, c);
  assert.ok(Object.keys(a.counts).length > 0, 'first request recorded nothing');
  assert.strictEqual(Object.keys(c.stats.counts).length, 0, 'second request inherited the first request\'s counts');
});

// ============================================== SOAK: no unbounded growth

test('soak: 10000 transforms do not grow memory without bound', () => {
  const c = ctx();
  const before = process.memoryUsage().heapUsed;
  for (let i = 0; i < 10000; i++) through(`soak ${i}: ${NAME} <${MAIL}>`, c);
  const grewMb = (process.memoryUsage().heapUsed - before) / (1024 * 1024);
  assert.ok(c.memo.size <= c.memoMax + 1, `memo unbounded at ${c.memo.size}`);
  // Generous: without --expose-gc this is noisy. A real leak shows as
  // hundreds of MB, not tens.
  assert.ok(grewMb < 400, `heap grew ${grewMb.toFixed(0)}MB over 10k transforms`);
});
