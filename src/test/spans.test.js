'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile } = require('../rules');
const { redactWithSpans, makeLabel } = require('../spans');

const K = Buffer.alloc(32, 9);
const RULES = compile({
  literals: ['Jane Q. Testerson', 'Jane'],
  patterns: [
    { name: 'email', regex: '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}', flags: 'gi' },
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

test('CRITICAL 2: a crossing match does not drop its uncovered tail (no cleartext leak)', () => {
  // The two candidates must come from DIFFERENT compiled buckets (one
  // pattern, one literal) so they are found by two independent exec() scans
  // and can genuinely overlap in `found`. Two literals of the same
  // case-sensitivity share one combined regex, and a single regex object's
  // exec() loop can never report two overlapping matches against itself --
  // that would not exercise the crossing-match code path at all.
  const crossing = compile({
    patterns: [{ name: 'crossing-head', regex: 'abcdefPHONE1234567', flags: 'gi' }],
    literals: [{ value: 'PHONE1234567SECRETXYZ', boundary: false }],
  });
  const r = redactWithSpans('xx abcdefPHONE1234567SECRETXYZ yy', crossing, K);
  assert.ok(!r.text.includes('SECRETXYZ'), r.text);
  assert.ok(!r.text.includes('PHONE1234567'), r.text);
  assert.ok(!r.text.includes('abcdef'), r.text);
  assert.ok(r.text.includes(' yy'), r.text);
});

test('FIX1: two literals that cross each other both get redacted (no cleartext leak)', () => {
  // Both candidates are LITERALS. Under the old compile(), all literals of the
  // same case-sensitivity were merged into one combined regex, so a single
  // exec() loop could never report two overlapping matches against itself --
  // the second literal was never even found. Each literal must now compile to
  // its own regex entry so both candidates reach spans.js's crossing-clip
  // logic.
  const rules = compile({
    literals: [
      { value: 'abcdefPHONE1234567', boundary: false },
      { value: 'PHONE1234567SECRETXYZ', boundary: false },
    ],
    patterns: [],
  });
  const r = redactWithSpans('xx abcdefPHONE1234567SECRETXYZ yy', rules, K);
  assert.ok(!r.text.includes('SECRETXYZ'), r.text);
  assert.ok(!r.text.includes('PHONE1234567'), r.text);
  assert.ok(r.text.includes(' yy'), r.text);
});

test('FIX1: overlapping address literals leave no cleartext tail', () => {
  const rules = compile({
    literals: ['123 Main', 'Main Street Apt 4'],
    patterns: [],
  });
  const r = redactWithSpans('address: 123 Main Street Apt 4 done', rules, K);
  assert.ok(!r.text.includes('Street Apt 4'), r.text);
  assert.ok(!r.text.includes('123 Main'), r.text);
  assert.ok(r.text.includes('address:'), r.text);
  assert.ok(r.text.includes('done'), r.text);
});

test('redacting twice is a no-op', () => {
  const once = red('owner jane@x.com').text;
  assert.strictEqual(red(once).text, once);
});
