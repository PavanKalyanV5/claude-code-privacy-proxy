'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile, isPatternSafe, boundedLiteral, RULES_PATH } = require('../rules');
const { redactWithSpans } = require('../spans');

// Helper: does any compiled regex match this text?
function matches(compiled, text) {
  return compiled.regexes.some((r) => {
    r.re.lastIndex = 0;
    return r.re.test(text);
  });
}

test('word-bounded literal does not match inside a longer word', () => {
  const c = compile({ literals: ['Jane'], patterns: [] });
  assert.ok(matches(c, 'call Jane today'));
  assert.ok(!matches(c, 'class JaneAdapter {}'));
});

test('boundary:false literal matches inside a word', () => {
  const c = compile({ literals: [{ value: 'Jane', boundary: false }], patterns: [] });
  assert.ok(matches(c, 'class JaneAdapter {}'));
});

test('literals with punctuation edges still match', () => {
  const c = compile({ literals: ['+1-555'], patterns: [] });
  assert.ok(matches(c, 'tel +1-555 ok'));
});

// FIX1: literals now compile to their own regex entries instead of being
// merged into the pattern alternation, so "ordered before in the alternation"
// no longer applies. The guarantee it protected -- a broad category pattern
// beats a short literal that starts at the same offset -- still holds, but
// now comes from spans.js's sort (start ascending, then length descending),
// not from alternation order. Assert it at that level instead.
test('a broad pattern still wins over a short literal at the same start', () => {
  const c = compile({
    literals: ['Jane'],
    patterns: [{ name: 'email', regex: '[a-z.]{1,64}@[a-z.]{1,255}', flags: 'gi' }],
  });
  const r = redactWithSpans('mail jane.test@example.org now', c, Buffer.alloc(32, 9));
  assert.strictEqual(r.spans.length, 1);
  assert.strictEqual(r.spans[0].category, 'email');
});

test('literals shorter than 3 chars and placeholders are dropped', () => {
  const c = compile({ literals: ['ab', 'Your Full Name'], patterns: [] });
  assert.strictEqual(c.literalCount, 0);
});

test('a catastrophic pattern is rejected, not run', () => {
  const v = isPatternSafe('^(a+)+$', 'g');
  assert.strictEqual(v.ok, false);
  assert.match(v.why, /backtracking|exceeded/i);
});

test('a sane pattern with lookbehind is accepted', () => {
  const v = isPatternSafe('(?<![\\d.])\\d{3}[ .-]\\d{4}(?![\\d.])', 'g');
  assert.strictEqual(v.ok, true);
});

test('an invalid pattern is rejected without throwing', () => {
  assert.strictEqual(isPatternSafe('([unclosed', 'g').ok, false);
});

test('a rejected pattern is warned about and skipped, others survive', () => {
  const warnings = [];
  const c = compile(
    {
      literals: [],
      patterns: [
        { name: 'bad', regex: '^(a+)+$', flags: 'g' },
        { name: 'good', regex: 'zzz', flags: 'g' },
      ],
    },
    (m) => warnings.push(m)
  );
  assert.strictEqual(warnings.length, 1);
  assert.match(warnings[0], /bad/);
  assert.ok(matches(c, 'xx zzz xx'));
});

test('boundedLiteral wraps word-edged literals only', () => {
  // Use plain word-edged / punctuation-edged literals here (rather than a
  // bracketed [PII:...] placeholder) so this test is about the boundary
  // logic itself, not about what a literal's own text happens to look like.
  //
  // Each boundary is satisfied by a non-word character OR by another
  // occurrence of the value. The second clause closes a real bypass: with
  // only the first, "<value><value>" matched nothing at all, because the
  // leading copy failed its trailing check and the trailing copy failed its
  // leading one, so a repeated literal went out verbatim.
  assert.strictEqual(
    boundedLiteral('AcmeCorp2024'),
    '(?:(?<![\\p{L}\\p{N}_])|(?<=AcmeCorp2024))AcmeCorp2024(?:(?![\\p{L}\\p{N}_])|(?=AcmeCorp2024))'
  );
  // Starts with '+' and ends with a digit, so only the trailing side is
  // bounded. Note '-' needs no escaping outside a character class.
  assert.strictEqual(
    boundedLiteral('+1-555'),
    '\\+1-555(?:(?![\\p{L}\\p{N}_])|(?=\\+1-555))'
  );
});

test('CRITICAL 4: a Unicode literal gets a boundary on its non-ASCII edge too', () => {
  const c = compile({ literals: ['José'], patterns: [] });
  assert.ok(matches(c, 'call José now'));
  assert.ok(!matches(c, 'Josésito was here'));
});

test('CRITICAL 4: every shipped pattern is still accepted after the Unicode fix', () => {
  // Reads the patterns from the shipped config instead of retyping them.
  //
  // The previous version passed them as single-quoted JS string literals,
  // where `\.` collapses to `.` and `\d` collapses to `d`. So a test named
  // "shipped email/phone patterns" was actually asserting that
  // `(?<![d.])d{3}[ .-]d{3}[ .-]d{4}(?![d.])` is safe -- a pattern this
  // project has never shipped, matching the letter d rather than a digit.
  // CodeQL flagged it as a useless escape; it was a test checking the wrong
  // thing entirely.
  //
  // Reading the real file removes the escaping problem AND widens the test:
  // it now covers every pattern in the template, not the two someone
  // remembered to copy.
  const fs = require('fs');
  const path = require('path');
  const cfg = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', '..', 'config', 'redact-rules.example.json'), 'utf8')
  );
  const patterns = cfg.patterns || [];
  assert.ok(patterns.length >= 2, 'expected the template to ship patterns');

  for (const p of patterns) {
    const verdict = isPatternSafe(p.regex, p.flags || 'g');
    assert.strictEqual(verdict.ok, true, (p.name || '?') + ' rejected: ' + (verdict.why || ''));
  }

  // The two that motivated this test are still specifically present, so
  // deleting them from the template cannot quietly empty the loop above.
  const names = patterns.map((p) => p.name);
  assert.ok(names.includes('email'), 'the email pattern is missing from the template');
  assert.ok(names.includes('phone'), 'the phone pattern is missing from the template');
});


test('RULES_PATH lives under ~/.claude/redaction, never in the repo', () => {
  assert.ok(RULES_PATH.includes('redaction'), RULES_PATH);
  assert.ok(!RULES_PATH.includes('games'), 'live config must not live in the project tree');
});
