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

test('a linear pattern survives a machine too slow to start a process quickly', () => {
  // The screen used to budget 500ms for the whole probe CHILD, so node's own
  // startup (74-153ms idle, far more under load) counted against the regex.
  // On a loaded CI runner a linear pattern ran out of budget, was reported
  // as catastrophic, and was silently disabled -- which is not a flaky test
  // but a redaction failure: that category stops being redacted, on exactly
  // the machines most likely to be busy.
  //
  // The budget is now measured inside the child, around the matching only.
  // This asserts the SHAPE of that fix rather than trying to reproduce load:
  // a hang must be reported as a hang, and slowness as a measured time.
  const { isPatternSafe } = require('../rules');
  // Assembled from parts. Written as one literal, the `\.` is eaten twice
  // over -- once by a shell heredoc and once by a JS string literal -- which
  // is the same class of bug this file documents, and it silently changes
  // the pattern under test from "a literal dot" to "any character".
  const DOT = '\\' + '.';
  const linear = '(?<=(?:github|gitlab)' + DOT + '(?:com|org)[/:][A-Za-z0-9._-]{1,64}/)[A-Za-z0-9._-]+';
  assert.strictEqual(isPatternSafe(linear, 'g').ok, true);

  const evil = isPatternSafe('^(a+)+$', 'g');
  assert.strictEqual(evil.ok, false);
  // The message must say WHICH failure it was. "rejected" alone sends
  // someone off to rewrite a regex that may not be the problem.
  assert.match(evil.why, /did not return within \d+ms|took \d+ms/);
});
