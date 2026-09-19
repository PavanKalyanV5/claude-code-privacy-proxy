'use strict';

// Redaction must never redact its own output.
//
// FOUND BY ADOPTING A PATTERN. `api[_-]?key\s*[=:]\s*[A-Za-z0-9_-]{16,}` is a
// sensible rule for catching a key in an assignment. It also matches
// "api-key:f9cff609da63178e" inside the label
// `AIza<35 more chars>`, producing a nested
// `[PII:google-[PII:generic-...]]` that no longer resolves.
//
// Two things break when that happens:
//
//   1. Resolution. mapToSource re-derives labels from the source file and
//      matches them; a corrupted label matches nothing, so a tool asking to
//      edit that file gets a label instead of the real value.
//   2. The residue scrubber, which re-runs this pipeline over files that
//      ALREADY contain labels from earlier passes. Non-idempotent redaction
//      means every pass degrades the previous pass's output.
//
// Guarded in the ENGINE rather than by tightening the offending pattern:
// any pattern can collide with the label shape, including one the user
// writes, and a user-written rule must not be able to break resolution.

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { compile } = require('../rules');
const { redactWithSpans } = require('../spans');

const K = crypto.randomBytes(32);

function engine(patterns, literals = []) {
  return compile(
    {
      literals: literals.map((v) => ({ value: v, category: 'personal' })),
      patterns,
    },
    () => {}
  );
}

// The exact pattern that exposed this.
const KEY_PATTERN = {
  name: 'generic-api-key-assignment',
  category: 'secret',
  regex: '\\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\\s*[=:]\\s*["\']?[A-Za-z0-9_\\-]{16,}["\']?',
  flags: 'gi',
};

const GOOGLE_PATTERN = { name: 'google-api-key', category: 'secret', regex: '\\bAIza[0-9A-Za-z_-]{35}\\b', flags: 'g' };

test('a second pass does not change the output', () => {
  const compiled = engine([GOOGLE_PATTERN, KEY_PATTERN]);
  const once = redactWithSpans('key is AIza' + 'f'.repeat(35) + ' done', compiled, K).text;
  const twice = redactWithSpans(once, compiled, K).text;
  assert.strictEqual(twice, once, 'redaction must be idempotent');
});

test('an emitted label is never nested inside another', () => {
  const compiled = engine([GOOGLE_PATTERN, KEY_PATTERN]);
  const out = redactWithSpans('AIza' + 'f'.repeat(35), compiled, K).text;
  const opens = (out.match(/\[PII:/g) || []).length;
  assert.strictEqual(opens, 1, 'exactly one label expected, got: ' + out);
});

test('a label in the input survives a redaction pass intact', () => {
  const compiled = engine([KEY_PATTERN]);
  // Built from parts so this source file never contains a literal label,
  // which the proxy would rewrite on its way to disk.
  const label = '[' + 'PII' + ':google-api-key:' + 'a1b2c3d4e5f60718' + ']';
  const out = redactWithSpans('see ' + label + ' here', compiled, K).text;
  assert.ok(out.includes(label), 'label was altered: ' + out);
});

test('text around a label is still redacted normally', () => {
  // The guard must protect labels without creating a shadow where real
  // values can hide next to one.
  const compiled = engine([GOOGLE_PATTERN], ['Wilhelmina']);
  const label = '[' + 'PII' + ':x:' + '0123456789abcdef' + ']';
  const out = redactWithSpans(label + ' Wilhelmina ' + label, compiled, K).text;
  assert.ok(!out.includes('Wilhelmina'), 'a real value beside a label must still be redacted: ' + out);
  assert.ok(out.includes(label), 'the labels themselves must be untouched');
});

test('a value that merely looks label-ish is still redacted', () => {
  // The guard keys on the full label shape. Something similar but not a
  // label must not gain immunity by resembling one.
  const compiled = engine([], ['SecretCompanyName']);
  const out = redactWithSpans('[PII:notahash] SecretCompanyName', compiled, K).text;
  assert.ok(!out.includes('SecretCompanyName'), 'near-label text must not shield real values: ' + out);
});

test('idempotence holds across the whole shipped example set', () => {
  const fs = require('fs');
  const path = require('path');
  const p = path.join(__dirname, '..', '..', 'config', 'patterns.example.json');
  if (!fs.existsSync(p)) return;
  const { patterns } = JSON.parse(fs.readFileSync(p, 'utf8'));
  const compiled = engine(patterns);
  const samples = [
    'AIza' + 'f'.repeat(35),
    'ghp_' + 'a'.repeat(36),
    'sk-proj-' + 'c'.repeat(40),
    'npm_' + 'i'.repeat(36),
    'api_key = "' + 'm'.repeat(32) + '"',
  ];
  for (const s of samples) {
    const once = redactWithSpans('value ' + s + ' end', compiled, K).text;
    const twice = redactWithSpans(once, compiled, K).text;
    assert.strictEqual(twice, once, 'not idempotent for sample: ' + s);
    assert.strictEqual((once.match(/\[PII:/g) || []).length, 1, 'nested label for sample: ' + s + ' -> ' + once);
  }
});
