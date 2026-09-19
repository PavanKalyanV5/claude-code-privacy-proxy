'use strict';

// Tests for the dangerous-alias guard.
//
// This exists because of real damage. The shipped example config aliased the
// machine hostname to a short common word. Inbound un-aliasing replaces the
// alias with the real value EVERYWHERE it appears, so every standalone
// occurrence of that word -- in an options object, in prose, in a comment --
// was rewritten to the real machine name on write. It corrupted source
// comments and test fixtures across the repo, and reached git history, before
// anyone noticed.
//
// The word-boundary guard was working correctly the entire time: compound
// forms were properly left alone. The defect was that the alias VALUE was a
// word that legitimately appears in code on its own. No amount of boundary
// correctness can save that, so the value itself has to be rejected.

const { test } = require('node:test');
const assert = require('node:assert');
const { aliasRisk } = require('../aliases');

// Built at runtime: writing this token literally would itself be un-aliased
// into the machine name on the way to disk, which is how the first repair
// script silently became a no-op.
const RISKY = 'h' + 'o' + 's' + 't';

test('the exact alias that caused the damage is rejected', () => {
  const r = aliasRisk(RISKY);
  assert.ok(r, 'must be rejected');
  assert.match(r, /common word|short plain word/);
});

test('common code identifiers are rejected', () => {
  for (const a of ['server', 'machine', 'box', 'pc', 'home', 'user', 'name', 'local', 'dev', 'test', 'prod', 'app', 'src', 'tmp', 'data', 'path', 'dir', 'admin', 'root', 'node', 'main']) {
    assert.ok(aliasRisk(a), `"${a}" should be rejected as an alias`);
  }
});

test('case does not let a risky alias through', () => {
  assert.ok(aliasRisk(RISKY.toUpperCase()));
  assert.ok(aliasRisk('Server'));
});

test('short plain words are rejected even when not on the list', () => {
  // The list cannot be exhaustive, so length plus "purely alphabetic" catches
  // the rest. Anything a person would type by accident is short and wordlike.
  for (const a of ['zap', 'wibble', 'foo', 'bar', 'kite']) {
    assert.ok(aliasRisk(a), `"${a}" should be rejected: short and wordlike`);
  }
});

test('empty and non-string aliases are rejected', () => {
  assert.ok(aliasRisk(''));
  assert.ok(aliasRisk(null));
  assert.ok(aliasRisk(undefined));
  assert.ok(aliasRisk(42));
});

test('distinctive aliases are accepted', () => {
  // These are safe because nothing would type them by accident: they mix
  // case classes, digits or separators.
  for (const a of ['MACHINE-A1', 'C:\Users\SOMEONE', 'WKSTN-7391', 'my-box-alias', 'anon-machine-01']) {
    assert.strictEqual(aliasRisk(a), null, `"${a}" should be accepted but was rejected: ${aliasRisk(a)}`);
  }
});

test('a long plain word is accepted (length is the discriminator)', () => {
  assert.strictEqual(aliasRisk('unmistakablealias'), null);
});

test('the path alias shipped in the example config is safe', () => {
  // Regression: the example's username alias must not itself be risky, or
  // the proxy would refuse to start on a fresh install.
  const example = require('../../config/redact-rules.example.json');
  for (const a of example.aliases) {
    assert.strictEqual(aliasRisk(a.alias), null, `example config ships a risky alias: ${a.alias} -- ${aliasRisk(a.alias)}`);
  }
});
