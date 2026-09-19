'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { compile } = require('../rules');
const { redactWithSpans, makeLabel } = require('../spans');
const { compileAliases } = require('../aliases');
const { compileNormalizers } = require('../normalize');
const { renderForModel } = require('../pipeline');
const { createResolver } = require('../resolver');
const { createCache } = require('../cache');

const K = Buffer.alloc(32, 17);
const RULES = compile({
  literals: ['Jane Q. Testerson'],
  patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}', flags: 'gi' }],
});

function fixture(contents) {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-')), 'f.js');
  fs.writeFileSync(p, contents);
  return p;
}

test('an Edit on a line containing PII lands correctly on the real file', () => {
  const real = 'const OWNER = "jane.test@example.org";\nconst KEEP = 1;\n';
  const p = fixture(real);
  const r = redactWithSpans(real, RULES, K);
  const label = makeLabel(K, 'email', 'jane.test@example.org');

  const resolver = createResolver({ rules: RULES, kLabel: K });
  const out = resolver.resolveToolInput('Edit', {
    file_path: p,
    old_string: `const OWNER = "${label}";`,
    new_string: `const MAINTAINER = "${label}";`,
  });

  assert.strictEqual(out.old_string, 'const OWNER = "jane.test@example.org";');
  // Apply it exactly as the Edit tool would.
  assert.ok(real.includes(out.old_string));
  const after = real.replace(out.old_string, out.new_string);
  fs.writeFileSync(p, after);
  const onDisk = fs.readFileSync(p, 'utf8');
  assert.ok(onDisk.includes('jane.test@example.org'), 'PII must survive the edit');
  assert.ok(onDisk.includes('MAINTAINER'), 'the rename must have applied');
  assert.ok(!onDisk.includes('[PII:'), 'no label may reach the file');
});

test('an Edit on a clean line in a PII-bearing file still works', () => {
  const real = 'const OWNER = "jane.test@example.org";\nconst KEEP = 1;\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const out = resolver.resolveToolInput('Edit', {
    file_path: p, old_string: 'const KEEP = 1;', new_string: 'const KEEP = 2;',
  });
  assert.strictEqual(out.old_string, 'const KEEP = 1;');
  assert.strictEqual(out.new_string, 'const KEEP = 2;');
});

test('an unresolvable Edit is passed through untouched so it fails visibly', () => {
  const real = 'const A = 1;\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const input = { file_path: p, old_string: 'NOT PRESENT', new_string: 'x' };
  assert.deepStrictEqual(resolver.resolveToolInput('Edit', input), input);
});

test('a missing file is passed through, not invented', () => {
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const input = { file_path: path.join(os.tmpdir(), 'nope-' + Date.now() + '.js'), old_string: 'a', new_string: 'b' };
  assert.deepStrictEqual(resolver.resolveToolInput('Edit', input), input);
});

test('a Bash label resolves from the cache', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 19), path: cachePath });
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  cache.set(label, 'jane.test@example.org');

  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const out = resolver.resolveToolInput('Bash', { command: `grep "${label}" f.txt` });
  assert.strictEqual(out.command, 'grep "jane.test@example.org" f.txt');
});

test('a Bash label with no cache entry is left alone', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc2-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 19), path: cachePath });
  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const cmd = 'grep "[PII:email:ffffffffffffffff]" f.txt';
  assert.strictEqual(resolver.resolveToolInput('Bash', { command: cmd }).command, cmd);
});

test('mcp__ tools are never resolved', () => {
  const real = 'const OWNER = "jane.test@example.org";\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const input = { file_path: p, old_string: 'anything' };
  assert.deepStrictEqual(resolver.resolveToolInput('mcp__thing__do', input), input);
});

test('Write to a file WITH spans resolves content correctly', () => {
  const real = 'const OWNER = "jane.test@example.org";\nconst DATA = "ignore";\n';
  const p = fixture(real);
  const label = makeLabel(K, 'email', 'jane.test@example.org');

  const resolver = createResolver({ rules: RULES, kLabel: K });
  const out = resolver.resolveToolInput('Write', {
    file_path: p,
    content: `const NEW = "${label}";\n`,
  });

  assert.strictEqual(out.content, `const NEW = "jane.test@example.org";\n`, 'content with label should be resolved');
  // Verify it can be written without containing [PII:
  assert.ok(!out.content.includes('[PII:'), 'no label should reach the write');
});

test('Write to a NEW file resolves a label from the cache', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc3-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 19), path: cachePath });
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  cache.set(label, 'jane.test@example.org');

  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const target = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'write-')), 'new.js');
  const out = resolver.resolveToolInput('Write', {
    file_path: target,
    content: `const M = "${label}";\n`,
  });

  assert.strictEqual(out.content, `const M = "jane.test@example.org";\n`, 'cache should have resolved the label');
});

test('Write to an existing CLEAN file resolves a label from the cache', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc4-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 20), path: cachePath });
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  cache.set(label, 'jane.test@example.org');

  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const p = fixture('const X = 1;\n'); // no redactable content
  const out = resolver.resolveToolInput('Write', {
    file_path: p,
    content: `const M = "${label}";\n`,
  });

  assert.strictEqual(out.content, `const M = "jane.test@example.org";\n`, 'cache should have resolved on clean file path');
});

test('Write with a label resolvable from neither spans nor cache calls warn and leaves it', () => {
  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    warn: (msg) => {
      // Verify the warning was called and contains expected context
      assert.ok(msg.includes('Write'), 'warn message should mention the tool name');
      assert.ok(msg.includes('[PII:'), 'warn message should mention the label');
    },
  });

  const target = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'warn-')), 'new.js');
  const unknownLabel = '[PII:email:ffffffffffffffff]';
  const input = {
    file_path: target,
    content: `const M = "${unknownLabel}";\n`,
  };

  const out = resolver.resolveToolInput('Write', input);
  // The label should survive (not resolved)
  assert.ok(out.content.includes(unknownLabel), 'unresolvable label should survive');
  assert.strictEqual(out.content, input.content, 'output should match input when label unresolvable');
});

test('NotebookEdit resolves new_source from spans', () => {
  const real = 'cell1 content\njaneqtest@gmail.com\nmore content\n';
  const p = fixture(real);
  const label = makeLabel(K, 'email', 'janeqtest@gmail.com');

  const resolver = createResolver({ rules: RULES, kLabel: K });
  const out = resolver.resolveToolInput('NotebookEdit', {
    notebook_path: p,
    cell_id: 'some_cell',
    new_source: `updated\n${label}\nstuff\n`,
  });

  assert.strictEqual(out.new_source, `updated\njaneqtest@gmail.com\nstuff\n`, 'new_source should be resolved from spans');
});

test('NotebookEdit resolves new_source from cache on new-file path', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc5-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 21), path: cachePath });
  const label = makeLabel(K, 'email', 'janeqtest@gmail.com');
  cache.set(label, 'janeqtest@gmail.com');

  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const target = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'nb-')), 'notebook.ipynb');

  const out = resolver.resolveToolInput('NotebookEdit', {
    notebook_path: target,
    cell_id: 'cell1',
    new_source: `code\n${label}\n`,
  });

  assert.strictEqual(out.new_source, `code\njaneqtest@gmail.com\n`, 'cache should resolve label on new-file path');
});

test('Edit on a no-spans file with clean old_string and cache-resolvable new_string label resolves the label', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc6-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 22), path: cachePath });
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  cache.set(label, 'jane.test@example.org');

  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const p = fixture('const A = 1;\n'); // no redactable content - noSpans path
  const out = resolver.resolveToolInput('Edit', {
    file_path: p,
    old_string: 'const A = 1;',
    new_string: `const A = "${label}";`,
  });

  assert.strictEqual(out.old_string, 'const A = 1;');
  assert.strictEqual(out.new_string, 'const A = "jane.test@example.org";', 'label should be resolved from cache on noSpans path');
});

test('Edit on a no-spans file with unresolvable new_string label warns and leaves it', () => {
  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    warn: (msg) => {
      assert.ok(msg.includes('Edit'), 'warn message should mention Edit tool');
    },
  });
  const p = fixture('const A = 1;\n');
  const unknownLabel = '[PII:email:ffffffffffffffff]';
  const input = {
    file_path: p,
    old_string: 'const A = 1;',
    new_string: `const A = "${unknownLabel}";`,
  };

  const out = resolver.resolveToolInput('Edit', input);
  assert.strictEqual(out.new_string, input.new_string, 'unresolvable label should survive on noSpans path');
});

test('Edit on a missing file with cache-resolvable new_string label resolves the label', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc7-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 23), path: cachePath });
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  cache.set(label, 'jane.test@example.org');

  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const target = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'missing-')), 'newfile.js');
  const out = resolver.resolveToolInput('Edit', {
    file_path: target,
    old_string: 'const A = 1;',
    new_string: `const A = "${label}";`,
  });

  assert.strictEqual(out.new_string, 'const A = "jane.test@example.org";', 'label should be resolved from cache on noFile path');
});

test('Edit on a missing file with unresolvable new_string label warns and leaves it', () => {
  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    warn: (msg) => {
      assert.ok(msg.includes('Edit'), 'warn message should mention Edit tool');
    },
  });
  const target = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'missing2-')), 'newfile.js');
  const unknownLabel = '[PII:email:ffffffffffffffff]';
  const input = {
    file_path: target,
    old_string: 'const A = 1;',
    new_string: `const A = "${unknownLabel}";`,
  };

  const out = resolver.resolveToolInput('Edit', input);
  assert.strictEqual(out.new_string, input.new_string, 'unresolvable label should survive on noFile path');
});

test('MultiEdit where one edit new_string has cache-resolvable label resolves it', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc8-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 24), path: cachePath });
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  cache.set(label, 'jane.test@example.org');

  const real = 'line1\nline2\nline3\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const out = resolver.resolveToolInput('MultiEdit', {
    file_path: p,
    edits: [
      { old_string: 'line1', new_string: 'LINE1' },
      { old_string: 'line2', new_string: `line2-${label}` },
    ],
  });

  assert.strictEqual(out.edits[1].new_string, 'line2-jane.test@example.org', 'MultiEdit should resolve label in new_string');
});

test('Edit on a spans-file with new_string label from cache (different file source)', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bc9-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 25), path: cachePath });
  // Different email from what's in the file
  const label = makeLabel(K, 'email', 'other@example.org');
  cache.set(label, 'other@example.org');

  const real = 'const OWNER = "jane.test@example.org";\nconst X = 1;\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K, cache });
  const out = resolver.resolveToolInput('Edit', {
    file_path: p,
    old_string: 'const X = 1;',
    new_string: `const Y = "${label}";`,
  });

  // Should resolve from cache even though it's a different email
  assert.strictEqual(out.new_string, 'const Y = "other@example.org";', 'should resolve from cache for different-file labels');
});

// ---------------------------------------------------------------------------
// FIX 3 (phase 3): the resolver must reverse EVERY outbound stage (redact ->
// alias -> normalize), not just redaction, or a line touched by aliasing or
// normalization can never be edited. These reproduce the two DIVERGES rows
// from scope-divergence.js directly against createResolver.
// ---------------------------------------------------------------------------

test('FIX3: an Edit on a line containing an ALIASED username path resolves and applies to the real file', () => {
  const aliases = compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]);
  const real = 'const P = "C:\\Users\\SOMEONE\\app";\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K, aliases });
  const line = real.split('\n')[0];
  const rendered = renderForModel(line, { rules: RULES, kLabel: K, aliases, normalizers: null });

  const out = resolver.resolveToolInput('Edit', {
    file_path: p, old_string: rendered.text, new_string: 'const P = "X";',
  });

  assert.strictEqual(out.old_string, line, 'old_string must resolve to the exact real line, alias undone');
  assert.ok(real.includes(out.old_string), 'resolved old_string must exist verbatim in the real file');
});

test('FIX3: an Edit on a line containing a NORMALIZED timezone offset resolves and applies to the real file', () => {
  const normalizers = compileNormalizers({ timezone: true, rewrites: [] });
  const real = 'const W = "2026-09-17 21:08:56 +0530";\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K, normalizers });
  const line = real.split('\n')[0];
  const rendered = renderForModel(line, { rules: RULES, kLabel: K, aliases: [], normalizers });

  const out = resolver.resolveToolInput('Edit', {
    file_path: p, old_string: rendered.text, new_string: 'const W = "X";',
  });

  assert.strictEqual(out.old_string, line, 'old_string must resolve to the exact real line, normalization undone');
  assert.ok(real.includes(out.old_string), 'resolved old_string must exist verbatim in the real file');
});

test('FIX3 REFUSAL: an old_string boundary landing inside a redaction label is refused, not corrupted', () => {
  const real = 'const N = "Jane Q. Testerson";\n';
  const p = fixture(real);
  const label = makeLabel(K, 'personal', 'Jane Q. Testerson');
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const input = { file_path: p, old_string: `const N = "${label.slice(0, -3)}`, new_string: 'x' };
  assert.deepStrictEqual(resolver.resolveToolInput('Edit', input), input);
});

test('FIX3 REFUSAL: an old_string boundary landing inside an alias replacement is refused, not corrupted', () => {
  const aliases = compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]);
  const real = 'const P = "C:\\Users\\SOMEONE\\app";\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K, aliases });
  // "C:\Users\an" -- boundary lands strictly inside the "anon" replacement.
  const input = { file_path: p, old_string: 'const P = "C:\\Users\\an', new_string: 'x' };
  assert.deepStrictEqual(resolver.resolveToolInput('Edit', input), input);
});

test('FIX3 REFUSAL: an old_string boundary landing inside a normalized timestamp is refused, not corrupted', () => {
  const normalizers = compileNormalizers({ timezone: true, rewrites: [] });
  const real = 'const W = "2026-09-17 21:08:56 +0530";\n';
  const p = fixture(real);
  const resolver = createResolver({ rules: RULES, kLabel: K, normalizers });
  // "2026-09-17T15:38" -- boundary lands strictly inside the ISO timestamp.
  const input = { file_path: p, old_string: 'const W = "2026-09-17T15:38', new_string: 'x' };
  assert.deepStrictEqual(resolver.resolveToolInput('Edit', input), input);
});

test('FIX3 PROPERTY: every model-visible line resolves to a byte-exact old_string in the real file, across PII/alias/normalize combinations and orders', () => {
  const K2 = Buffer.alloc(32, 31);
  const RULES2 = compile({ literals: ['Jane Q. Testerson'], patterns: [] });
  const ALIASES2 = compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]);
  const NORM2 = compileNormalizers({
    timezone: true,
    rewrites: [{ name: 'os', regex: 'Windows (\\d+)(?: [A-Za-z]+)? \\d+\\.\\d+\\.\\d+', flags: 'g', replace: 'Windows $1' }],
  });

  const pii = 'Jane Q. Testerson';
  const singleSep = 'C:\\Users\\SOMEONE\\app'; // one literal backslash per separator
  const doubleSep = 'C:\\\\Users\\\\SOMEONE\\\\app'; // two literal backslashes, as escaped source code contains
  const tz = '2026-09-17 21:08:56 +0530';
  const osBuild = 'Windows 11 Pro 10.0.26200';

  const lines = [
    `const N = "${pii}"; // path ${singleSep}`,
    `const N2 = "${pii}"; // path ${doubleSep}`,
    `path ${singleSep} at ${tz} on ${osBuild}`,
    `on ${osBuild} at ${tz} path ${doubleSep} owner ${pii}`,
    `${tz} ${osBuild} ${singleSep} ${pii}`,
    `${osBuild}`,
    `${tz}`,
    `${singleSep}`,
    `${doubleSep}`,
    `${pii}`,
    'const KEEP = 1;',
  ];

  const resolver = createResolver({ rules: RULES2, kLabel: K2, aliases: ALIASES2, normalizers: NORM2 });

  // Each corpus entry gets its own file (plus a per-file control line) so a
  // combination that happens to share model-visible text with ANOTHER corpus
  // entry (e.g. two different lines both containing "Windows 11" after
  // normalization) cannot manufacture a cross-line ambiguity that has nothing
  // to do with the fix under test -- the resolver's "refuse on ambiguous
  // match" rule is exercised on its own elsewhere in this file.
  for (const line of lines) {
    const control = 'const KEEP_' + Math.abs(line.length) + ' = 1;';
    const real = `${line}\n${control}\n`;
    const p = fixture(real);

    const rendered = renderForModel(line, { rules: RULES2, kLabel: K2, aliases: ALIASES2, normalizers: NORM2 });
    const out = resolver.resolveToolInput('Edit', {
      file_path: p, old_string: rendered.text, new_string: 'REPLACED',
    });

    assert.strictEqual(out.old_string, line, `line did not resolve byte-exact: ${JSON.stringify(line)}`);
    assert.ok(real.includes(out.old_string), `old_string not found verbatim in the real file: ${JSON.stringify(line)}`);

    const after = real.replace(out.old_string, out.new_string);
    assert.ok(!after.includes('[PII:'), `no PII label may survive applying the edit for line: ${JSON.stringify(line)}`);
    // No user data lost: the untouched control line must survive.
    assert.ok(after.includes(control), `control line lost after editing: ${JSON.stringify(line)}`);
  }
});
