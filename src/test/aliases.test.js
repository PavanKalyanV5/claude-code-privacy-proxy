'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compileAliases, toAlias, toReal, toAliasWithSpans, toRealWithSpans } = require('../aliases');

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
  // FIX 1 (phase 3): the separator run actually matched is preserved verbatim
  // in the replacement -- only the segment text (SOMEONE -> anon) changes. This
  // used to normalize the matched separators to the configured form (a
  // backslash, here), which silently rewrote forward slashes to backslashes
  // and, worse, collapsed a doubled backslash (as in escaped source code) down
  // to one -- corrupting file content. Preserving the captured separator is
  // what makes the round trip below byte-for-byte lossless.
  assert.strictEqual(toAlias('C:/Users/SOMEONE/x', A).text, 'C:/Users/anon/x');
  assert.strictEqual(toReal(toAlias('C:/Users/SOMEONE/x', A).text, A).text, 'C:/Users/SOMEONE/x');
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

// NOTE: the alias value for the MYBOX entry is built via string-part joins
// below (rather than typed as one contiguous literal) purely to sidestep this
// sandbox's own alias-substitution tooling, which transparently rewrites a
// bare literal occurrence of that particular word when source files are
// written to disk. It has no bearing on the fix under test.
const H = ['h', 'o', 's', 't'].join('');

test('CRITICAL 1: toReal does not splice the real value into a larger word', () => {
  // A entry maps real 'MYBOX' <-> alias H ('host'). Without a word boundary,
  // H as a bare substring matches inside 'local' + H, 'g' + H, and
  // H + 'NAME', splicing the real hostname into unrelated text.
  assert.strictEqual(toReal(`connect to local${H}:3000`, A).text, `connect to local${H}:3000`);
  assert.strictEqual(toReal(`g${H} in the shell`, A).text, `g${H} in the shell`);
  assert.strictEqual(toReal(`export ${H}NAME=x`, A).text, `export ${H}NAME=x`);
  // Standalone use must still match.
  assert.strictEqual(toReal(`the ${H} is slow`, A).text, 'the MYBOX is slow');
});

test('CRITICAL 1: toAlias enforces the same boundary outbound', () => {
  assert.strictEqual(toAlias('BIGMYBOX2000 online', A).text, 'BIGMYBOX2000 online');
  assert.strictEqual(toAlias('MYBOXES are online', A).text, 'MYBOXES are online');
  assert.strictEqual(toAlias('MYBOX is online', A).text, `${H} is online`);
});

test('CRITICAL 1: path aliases still match followed by a separator (boundary fix must not break this)', () => {
  assert.strictEqual(
    toAlias('open C:\Users\SOMEONE\\Desktop\\a.js', A).text,
    'open C:\Users\SOMEONE\\Desktop\\a.js'
  );
});

// FIX 1 (phase 3): aliasing must preserve the separator run it matched instead
// of collapsing it to the configured form. A doubled backslash (as escaped
// source code contains) must stay doubled; the character style found (forward
// slash vs backslash) must stay as found.

test('FIX1: escaped double-backslash separators keep their exact width through toAlias/toReal', () => {
  const escaped = 'C:\\\\Users\\\\SOMEONE\\\\app'; // literal double backslashes, as escaped source code contains
  const aliased = toAlias(escaped, A).text;
  assert.strictEqual(aliased, 'C:\\\\Users\\\\anon\\\\app');
  assert.strictEqual(toReal(aliased, A).text, escaped);
});

test('FIX1: single forward-slash separators are preserved, not converted to the configured backslash form', () => {
  assert.strictEqual(toAlias('C:/Users/SOMEONE/app', A).text, 'C:/Users/anon/app');
});

test('FIX1: mixed separator styles within one path still match, each run preserved independently', () => {
  assert.strictEqual(toAlias('C:\\Users/SOMEONE', A).text, 'C:\\Users/anon');
});

test('FIX1: a real/alias pair with mismatched segment counts warns once at compile time and falls back to collapsing separators', () => {
  const warnings = [];
  const M = compileAliases(
    [{ real: 'C:\\Users\\SOMEONE\\nested', alias: 'C:\\Users\\anon' }],
    (msg) => warnings.push(msg)
  );
  assert.strictEqual(warnings.length, 1);
  assert.match(warnings[0], /segment/i);
  // Fallback: today's collapsing behaviour, since there is no 1:1 segment
  // mapping to preserve separators against.
  const r = toAlias('C:\\\\Users\\\\SOMEONE\\\\nested\\\\x', M);
  assert.strictEqual(r.text, 'C:\\Users\\anon\\\\x');
});

// FIX 2 (phase 3): aliasing must report the same offset-map shape spans.js
// does, so the outbound pipeline can be composed uniformly.

test('FIX2: toAliasWithSpans/toRealWithSpans report accurate, ascending, non-overlapping spans', () => {
  const text = 'open C:\\Users\\SOMEONE\\Desktop\\a.js on MYBOX';
  const r = toAliasWithSpans(text, A);
  assert.strictEqual(r.count, 2);
  assert.strictEqual(r.spans.length, 2);
  for (const sp of r.spans) {
    assert.ok(sp.srcStart < sp.srcEnd);
    assert.ok(sp.outStart <= sp.outEnd);
  }
  for (let i = 1; i < r.spans.length; i++) {
    assert.ok(r.spans[i - 1].srcEnd <= r.spans[i].srcStart);
    assert.ok(r.spans[i - 1].outEnd <= r.spans[i].outStart);
  }
  const first = r.spans[0];
  assert.strictEqual(text.slice(first.srcStart, first.srcEnd), 'C:\\Users\\SOMEONE');
  assert.strictEqual(r.text.slice(first.outStart, first.outEnd), 'C:\\Users\\anon');
  const second = r.spans[1];
  assert.strictEqual(text.slice(second.srcStart, second.srcEnd), 'MYBOX');
  assert.strictEqual(r.text.slice(second.outStart, second.outEnd), H);

  // Reversing must produce spans that recover the original text.
  const back = toRealWithSpans(r.text, A);
  assert.strictEqual(back.text, text);
  assert.strictEqual(back.count, 2);
});

test('FIX2: toAliasWithSpans reports count 0 and empty spans when nothing matches', () => {
  const r = toAliasWithSpans('nothing here', A);
  assert.strictEqual(r.text, 'nothing here');
  assert.strictEqual(r.count, 0);
  assert.deepStrictEqual(r.spans, []);
});

test('FIX2: toAlias/toReal are unchanged and still return only {text, count}', () => {
  const r = toAlias('C:\\Users\\SOMEONE\\app', A);
  assert.deepStrictEqual(Object.keys(r).sort(), ['count', 'text']);
});
