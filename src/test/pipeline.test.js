'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile } = require('../rules');
const { compileAliases } = require('../aliases');
const { compileNormalizers } = require('../normalize');
const { renderForModel, mapToSource } = require('../pipeline');

const K = Buffer.alloc(32, 5);
const RULES = compile({ literals: ['Jane Q. Testerson'], patterns: [] });
const ALIASES = compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]);
const NORM = compileNormalizers({
  timezone: true,
  rewrites: [{ name: 'os', regex: 'Windows (\\d+)(?: [A-Za-z]+)? \\d+\\.\\d+\\.\\d+', flags: 'g', replace: 'Windows $1' }],
});

function opts(over = {}) {
  return Object.assign({ rules: RULES, kLabel: K, aliases: ALIASES, normalizers: NORM }, over);
}

test('renderForModel composes redact -> alias -> normalize in order', () => {
  const text = 'Jane Q. Testerson at C:\\Users\\SOMEONE on Windows 11 Pro 10.0.26200 at 2026-09-17 21:08:56 +0530';
  const r = renderForModel(text, opts());
  assert.match(r.text, /\[PII:personal:[0-9a-f]{16}\]/);
  assert.ok(r.text.includes('C:\\Users\\anon'), r.text);
  assert.ok(r.text.includes('Windows 11'), r.text);
  assert.ok(!r.text.includes('10.0.26200'), r.text);
  assert.ok(r.text.includes('2026-09-17T15:38:56Z'), r.text);
  assert.strictEqual(r.stages.length, 3);
  assert.strictEqual(r.aliased, 1);
  assert.strictEqual(r.normalized, 2);
});

test('renderForModel with no aliases/normalizers behaves like redaction alone', () => {
  const text = 'plain C:\\Users\\SOMEONE text';
  const r = renderForModel(text, { rules: RULES, kLabel: K, aliases: [], normalizers: null });
  assert.strictEqual(r.text, text);
  assert.strictEqual(r.aliased, 0);
  assert.strictEqual(r.normalized, 0);
});

test('mapToSource maps the boundaries around an alias replacement back to the real value', () => {
  const text = 'const P = "C:\\Users\\SOMEONE\\app";';
  const r = renderForModel(text, opts());
  // The alias replacement starts where "C:\Users\anon" begins and ends right
  // after "anon" -- those boundaries are NOT strictly inside the span, so
  // they must map back cleanly to the boundaries of "C:\Users\SOMEONE".
  const outStart = r.text.indexOf('C:\\Users\\anon');
  const outEnd = outStart + 'C:\\Users\\anon'.length;
  const srcStart = mapToSource(outStart, r.stages);
  const srcEnd = mapToSource(outEnd, r.stages);
  assert.notStrictEqual(srcStart, null);
  assert.notStrictEqual(srcEnd, null);
  assert.strictEqual(text.slice(srcStart, srcEnd), 'C:\\Users\\SOMEONE');
});

test('mapToSource returns null when the offset falls strictly inside a replaced span', () => {
  const text = 'owner Jane Q. Testerson done';
  const r = renderForModel(text, opts());
  const labelStart = r.text.indexOf('[PII:');
  // A couple of characters into the label -- strictly inside the redaction span.
  assert.strictEqual(mapToSource(labelStart + 3, r.stages), null);
});

test('mapToSource refuses an offset strictly inside an ALIAS span', () => {
  const text = 'const P = "C:\\Users\\SOMEONE\\app";';
  const r = renderForModel(text, opts());
  const anonIdx = r.text.indexOf('anon');
  // Two characters into "anon" -- strictly inside the alias replacement.
  assert.strictEqual(mapToSource(anonIdx + 2, r.stages), null);
});

test('mapToSource refuses an offset strictly inside a NORMALIZE span', () => {
  const text = 'const W = "2026-09-17 21:08:56 +0530";';
  const r = renderForModel(text, opts());
  const isoIdx = r.text.indexOf('2026-09-17T');
  // A few characters into the normalized ISO timestamp.
  assert.strictEqual(mapToSource(isoIdx + 5, r.stages), null);
});

test('mapToSource is the identity through untouched text with all three stages configured', () => {
  const text = 'const A = 1;';
  const r = renderForModel(text, opts());
  assert.strictEqual(r.text, text);
  for (let i = 0; i <= text.length; i++) {
    assert.strictEqual(mapToSource(i, r.stages), i);
  }
});

// --- the shared-config guarantee ---
// The walk and the resolver drifted twice because each built its own idea of
// the pipeline. makeContext now builds one frozen config and the resolver is
// meant to be handed that same object; these tests keep it that way.

const { makeContext } = require('../walk');
const { createResolver } = require('../resolver');
const { makeRenderConfig } = require('../pipeline');

test('makeContext exposes a frozen render config carrying every stage', () => {
  const ctx = makeContext({ kLabel: K, kMemo: K, rules: RULES, aliases: ALIASES, normalizers: NORM });
  assert.ok(Object.isFrozen(ctx.render), 'must be frozen so no caller can mutate one side only');
  assert.strictEqual(ctx.render.rules, RULES);
  assert.strictEqual(ctx.render.kLabel, K);
  assert.strictEqual(ctx.render.aliases, ALIASES);
  assert.strictEqual(ctx.render.normalizers, NORM);
});

test('a resolver given ctx.render shares the object, not a copy', () => {
  const ctx = makeContext({ kLabel: K, kMemo: K, rules: RULES, aliases: ALIASES, normalizers: NORM });
  // Same reference in means the two cannot be configured differently.
  const r = createResolver({ render: ctx.render });
  assert.ok(r && typeof r.resolveToolInput === 'function');
  const rendered = renderForModel('C:\\Users\\SOMEONE x', ctx.render);
  assert.match(rendered.text, /anon/);
});

test('render config takes precedence over loose params', () => {
  // If both are supplied, the shared object wins -- otherwise a stale loose
  // param could silently reintroduce the drift this whole module prevents.
  const shared = makeRenderConfig({ rules: RULES, kLabel: K, aliases: ALIASES, normalizers: NORM });
  const r = createResolver({ rules: RULES, kLabel: Buffer.alloc(32, 9), aliases: [], normalizers: null, render: shared });
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pcfg-'));
  const f = path.join(d, 'a.js');
  const real = 'const W = "2026-09-17 21:08:56 +0530";\n';
  fs.writeFileSync(f, real);
  const seen = renderForModel(real, shared).text.split('\n')[0];
  const out = r.resolveToolInput('Edit', { file_path: f, old_string: seen, new_string: 'const W = "X";' });
  assert.ok(real.includes(out.old_string), 'normalization must be reversed via the shared config');
});

test('makeRenderConfig tolerates a missing alias list', () => {
  const c = makeRenderConfig({ rules: RULES, kLabel: K });
  assert.deepStrictEqual(c.aliases, []);
  assert.strictEqual(c.normalizers, null);
});
