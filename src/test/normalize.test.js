'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compileNormalizers, normalize, normalizeWithSpans, toUtc } = require('../normalize');

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

// FIX 2 (phase 3): normalize must report the same offset-map shape spans.js
// does, so the outbound pipeline can be composed uniformly.

test('FIX2: normalizeWithSpans produces the same text as normalize', () => {
  const s = 'Windows 11 Pro 10.0.26200 at 2026-09-17 21:08:56 +0530';
  assert.strictEqual(normalizeWithSpans(s, C).text, normalize(s, C).text);
});

test('FIX2: normalizeWithSpans reports an accurate span for an OS build rewrite', () => {
  const s = 'OS Version: Windows 11 Pro 10.0.26200';
  const r = normalizeWithSpans(s, C);
  assert.strictEqual(r.count, 1);
  assert.strictEqual(r.spans.length, 1);
  const sp = r.spans[0];
  assert.strictEqual(s.slice(sp.srcStart, sp.srcEnd), 'Windows 11 Pro 10.0.26200');
  assert.strictEqual(r.text.slice(sp.outStart, sp.outEnd), 'Windows 11');
});

test('FIX2: normalizeWithSpans reports an accurate span for a timezone rewrite', () => {
  const s = 'commit at 2026-09-17 21:08:56 +0530 done';
  const r = normalizeWithSpans(s, C);
  assert.strictEqual(r.spans.length, 1);
  const sp = r.spans[0];
  assert.strictEqual(s.slice(sp.srcStart, sp.srcEnd), '2026-09-17 21:08:56 +0530');
  assert.strictEqual(r.text.slice(sp.outStart, sp.outEnd), '2026-09-17T15:38:56Z');
});

test('FIX2: normalizeWithSpans reports both spans, ascending and non-overlapping, when OS build and timezone both fire', () => {
  const s = 'Windows 11 Pro 10.0.26200 at 2026-09-17 21:08:56 +0530';
  const r = normalizeWithSpans(s, C);
  assert.strictEqual(r.spans.length, 2);
  assert.strictEqual(r.count, 2);
  for (let i = 1; i < r.spans.length; i++) {
    assert.ok(r.spans[i - 1].srcEnd <= r.spans[i].srcStart, 'spans must be ascending and non-overlapping (src)');
    assert.ok(r.spans[i - 1].outEnd <= r.spans[i].outStart, 'spans must be ascending and non-overlapping (out)');
  }
  for (const sp of r.spans) {
    assert.ok(sp.srcStart < sp.srcEnd);
    assert.ok(sp.outStart <= sp.outEnd);
  }
});

test('FIX2: normalizeWithSpans reports no spans and count 0 when nothing fires', () => {
  const s = 'nothing to see here';
  const r = normalizeWithSpans(s, C);
  assert.strictEqual(r.text, s);
  assert.strictEqual(r.count, 0);
  assert.deepStrictEqual(r.spans, []);
});

test('FIX2: normalizeWithSpans is a no-op when compiled is falsy', () => {
  const r = normalizeWithSpans('anything', null);
  assert.strictEqual(r.text, 'anything');
  assert.strictEqual(r.count, 0);
  assert.deepStrictEqual(r.spans, []);
});
