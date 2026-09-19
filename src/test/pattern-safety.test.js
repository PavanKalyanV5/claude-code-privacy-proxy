'use strict';

// Regression tests for the catastrophic-backtracking screen itself.
//
// The screen runs each candidate pattern in a killable child process, because
// the whole point is to survive a pattern that would hang the parent. How the
// pattern REACHES that child turned out to matter: passed as a command-line
// argument, any pattern starting with "-" was parsed by node as an option, so
// the child exited non-zero and the screen reported catastrophic backtracking.
//
// That is a bad failure in a specific way. It does not let something dangerous
// through -- it rejects something SAFE, and explains the rejection with a
// reason that is not true, sending the user off to rewrite a regex that was
// never the problem. `-----BEGIN PRIVATE KEY-----`, a pattern any secret
// scanner wants, was rejected on exactly these grounds.

const { test } = require('node:test');
const assert = require('node:assert');
const { isPatternSafe } = require('../rules');

test('a pattern starting with a dash is not mistaken for a node option', () => {
  const verdict = isPatternSafe('-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', 'g');
  assert.strictEqual(verdict.ok, true, verdict.why || 'should be accepted');
});

test('other leading-dash shapes are accepted too', () => {
  for (const src of ['--verbose', '-e', '-{2,}BEGIN', '--[a-z]+=']) {
    const v = isPatternSafe(src, 'g');
    assert.strictEqual(v.ok, true, src + ' rejected: ' + (v.why || ''));
  }
});

test('a genuinely catastrophic pattern is still rejected', () => {
  // Nested unbounded quantifier with a failing tail: every prefix is retried.
  // If the env-var change had broken the screen, this is what would slip
  // through, so it is asserted alongside the fix rather than assumed.
  const v = isPatternSafe('(a+)+$', 'g');
  assert.strictEqual(v.ok, false, 'a quadratic pattern must still be refused');
  assert.match(v.why || '', /backtrack|exceeded/i);
});

test('an invalid regex is refused rather than thrown', () => {
  const v = isPatternSafe('([unclosed', 'g');
  assert.strictEqual(v.ok, false);
});

test('flags reach the child correctly', () => {
  // Case-insensitivity has to survive the trip, or a pattern would be
  // screened under different semantics than it runs under.
  assert.strictEqual(isPatternSafe('[A-Z]{3}', 'gi').ok, true);
  assert.strictEqual(isPatternSafe('\\bAKIA[0-9A-Z]{16}\\b', 'g').ok, true);
});

test('the shipped example patterns all pass the screen', () => {
  // config/patterns.example.json is recommended to users verbatim. Shipping
  // one that the loader would silently disable would mean advertising
  // protection that never loads.
  const path = require('path');
  const fs = require('fs');
  const p = path.join(__dirname, '..', '..', 'config', 'patterns.example.json');
  if (!fs.existsSync(p)) return; // optional file
  const { patterns } = JSON.parse(fs.readFileSync(p, 'utf8'));
  for (const pat of patterns) {
    const v = isPatternSafe(pat.regex, pat.flags || 'g');
    assert.strictEqual(v.ok, true, pat.name + ' would be disabled at load: ' + (v.why || ''));
  }
});
