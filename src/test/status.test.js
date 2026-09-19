'use strict';

// Status propagation tests.
//
// The rule these exist to protect: anything we cannot verify renders as NOT
// protected. Every other bug here is cosmetic; that one is silent, and a
// status line that wrongly says "protected" is worse than no status line at
// all because it actively discourages looking.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createStatusWriter, readStatus, render, STALE_MS, MAX_NOTICES } = require('../status');

const tmpPath = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'st-')), 'status.json');
const plain = (s) => render(s, { color: false });

// A healthy snapshot: redaction loaded, egress verified as masking.
const healthy = {
  redaction: { literals: 5, patterns: 4, aliases: 2 },
  egress: { configured: ['socks5://x:1080'], masking: true, apparentCountry: 'ES', fellBackDirect: 0 },
};

// ------------------------------------------------- the fail-loud guarantees

test('a missing status file reads as not protected', () => {
  const s = readStatus(path.join(os.tmpdir(), 'definitely-not-here-' + Math.random(), 's.json'));
  assert.strictEqual(s.ok, false);
  assert.match(plain(s), /REDACTION OFF/);
  assert.match(plain(s), /not running/);
});

test('a corrupt status file reads as not protected, and does not throw', () => {
  const p = tmpPath();
  fs.writeFileSync(p, '{ this is not json');
  const s = readStatus(p);
  assert.strictEqual(s.ok, false);
  assert.match(plain(s), /REDACTION OFF/);
});

test('a stale status file reads as not protected', () => {
  const p = tmpPath();
  const w = createStatusWriter({ statusPath: p, now: () => 1000 });
  w.publish(healthy);
  // Just inside the window is still believed.
  assert.strictEqual(readStatus(p, 1000 + STALE_MS - 1).ok, true);
  // Past it, the proxy has stopped writing, which in practice means it died.
  const s = readStatus(p, 1000 + STALE_MS + 1);
  assert.strictEqual(s.ok, false);
  assert.match(plain(s), /not responding/);
});

test('a status file with no timestamp is not believed', () => {
  const p = tmpPath();
  fs.writeFileSync(p, JSON.stringify({ redaction: { literals: 9 } }));
  assert.strictEqual(readStatus(p).ok, false);
});

test('running with zero rules does not render as protected', () => {
  // The proxy is up and forwarding, but redacting nothing. That must not look
  // the same as working.
  const s = { ok: true, state: { redaction: { literals: 0, patterns: 0 }, egress: { configured: [] } } };
  assert.match(plain(s), /NO RULES/);
  assert.ok(!/redacted/.test(plain(s)));
});

// ------------------------------------------------------------- egress states

test('verified masking shows the exit country', () => {
  assert.match(plain({ ok: true, state: healthy }), /ip ES/);
});

test('a transparent proxy renders as not masked', () => {
  const state = { redaction: { literals: 1 }, egress: { configured: ['x'], masking: false, fellBackDirect: 0 } };
  assert.match(plain({ ok: true, state }), /IP NOT MASKED/);
});

test('a direct fallback outranks everything else in the line', () => {
  // Having gone out unmasked is the most important thing on the line, even
  // though redaction is fine and the tunnel may since have recovered.
  const state = {
    redaction: { literals: 5, patterns: 4 },
    egress: { configured: ['x'], masking: true, apparentCountry: 'ES', fellBackDirect: 3 },
  };
  const out = plain({ ok: true, state });
  assert.match(out, /IP EXPOSED x3/);
  assert.ok(!/ip ES/.test(out), 'must not also claim a masked exit');
});

test('unverified egress is distinguished from verified', () => {
  const state = { redaction: { literals: 1 }, egress: { configured: ['x'], masking: null, fellBackDirect: 0 } };
  assert.match(plain({ ok: true, state }), /unverified/);
});

test('no egress configured means the line says nothing about ip', () => {
  const state = { redaction: { literals: 5, patterns: 4 }, egress: { configured: [] } };
  const out = plain({ ok: true, state });
  assert.match(out, /redacted/);
  assert.ok(!/ip|MASK/i.test(out), 'should not imply an ip verdict that was never asked for: ' + out);
});

// ------------------------------------------------------------------ notices

test('notices are capped and newest-first', () => {
  const w = createStatusWriter({ statusPath: tmpPath(), now: () => 1 });
  for (let i = 0; i < 10; i++) w.note('warn', 'msg' + i);
  const s = w.publish(healthy);
  assert.strictEqual(s.notices.length, MAX_NOTICES);
  assert.strictEqual(s.notices[0].text, 'msg9');
});

test('an error notice is surfaced ahead of a newer warning', () => {
  const state = {
    redaction: { literals: 1 },
    egress: { configured: [] },
    notices: [
      { level: 'warn', text: 'just a warning', ts: 2 },
      { level: 'error', text: 'something REFUSED', ts: 1 },
    ],
  };
  assert.match(plain({ ok: true, state }), /something REFUSED/);
});

test('info notices are not shown', () => {
  const state = {
    redaction: { literals: 1 },
    egress: { configured: [] },
    notices: [{ level: 'info', text: 'nothing to see', ts: 1 }],
  };
  assert.ok(!/nothing to see/.test(plain({ ok: true, state })));
});

// ------------------------------------------------------------------ writing

test('publish writes atomically and leaves no temp file behind', () => {
  const p = tmpPath();
  const w = createStatusWriter({ statusPath: p, now: () => 5 });
  w.publish(healthy);
  assert.ok(fs.existsSync(p));
  assert.ok(!fs.existsSync(p + '.tmp'), 'a leftover temp file means the rename did not happen');
  assert.strictEqual(JSON.parse(fs.readFileSync(p, 'utf8')).ts, 5);
});

test('publish into an unwritable location does not throw', () => {
  // The proxy must keep serving requests even if it cannot report status.
  const w = createStatusWriter({ statusPath: path.join(os.tmpdir(), 'st-file-as-dir', 'x', 'y', 'z', 's.json') });
  assert.doesNotThrow(() => w.publish(healthy));
});

test('colour is emitted by default and suppressed on request', () => {
  const s = { ok: true, state: healthy };
  assert.ok(render(s, { color: true }).includes('['), 'expected ANSI codes');
  assert.ok(!render(s, { color: false }).includes('['), 'expected no ANSI codes');
});

// --- the tunnel decision outranks a stale masking result ---

test('auto mode deciding not to tunnel is reported as direct, not as masked', () => {
  // In auto mode the startup probe tunnels BEFORE the decision is made, so a
  // masking:true from that probe can sit alongside tunnelling:false. Reporting
  // the masking result there claimed the proxy's exit country while traffic was
  // actually going out directly -- the status line lying about the live path.
  const state = {
    redaction: { literals: 10, patterns: 12 },
    egress: {
      configured: ['socks5://a:1080'],
      masking: true,
      apparentCountry: 'ID',
      directCountry: 'NL',
      tunnelling: false,
      fellBackDirect: 0,
    },
  };
  const line = plain({ ok: true, state });
  assert.match(line, /direct NL/, line);
  assert.ok(!/ip ID/.test(line), 'must not claim a tunnel exit while going direct: ' + line);
});

test('an actual direct fallback still outranks the tunnel decision', () => {
  const state = {
    redaction: { literals: 10, patterns: 12 },
    egress: { configured: ['x'], masking: true, apparentCountry: 'ID', directCountry: 'NL', tunnelling: false, fellBackDirect: 2 },
  };
  assert.match(plain({ ok: true, state }), /IP EXPOSED x2/);
});

test('tunnelling true with confirmed masking still shows the exit country', () => {
  const state = {
    redaction: { literals: 10, patterns: 12 },
    egress: { configured: ['x'], masking: true, apparentCountry: 'ID', directCountry: 'IN', tunnelling: true, fellBackDirect: 0 },
  };
  assert.match(plain({ ok: true, state }), /ip ID/);
});
