'use strict';
// A path or search pattern the model composes carries LABELS, because labels
// are all it ever saw. The resolver used to resolve file CONTENT but never the
// destination, so a Write to a new file created a directory literally named
// "[PII:...]" while reporting success.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { compile } = require('../rules');
const { makeLabel } = require('../spans');
const { createResolver } = require('../resolver');
const { createSseTransformer } = require('../sse');

const K = Buffer.alloc(32, 29);
const RULES = compile({ literals: ['Acme'] });
const LABEL = makeLabel(K, 'personal', 'Acme');

function setup({ cached = { [LABEL]: 'Acme' } } = {}) {
  const map = new Map(Object.entries(cached));
  const stats = {};
  const warns = [];
  const resolver = createResolver({
    rules: RULES, kLabel: K, cache: { get: (l) => map.get(l), set() {} }, stats, warn: (m) => warns.push(m),
  });
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'rp-'));
  fs.mkdirSync(path.join(base, 'Acme'));
  fs.writeFileSync(path.join(base, 'Acme', 'old.txt'), 'hello world\n');
  return { resolver, stats, warns, base, map };
}
const labelled = (base, ...rest) => path.join(base, LABEL, ...rest);
const real = (base, ...rest) => path.join(base, 'Acme', ...rest);

test('Write to a NEW file under a labelled directory resolves the path and the content', () => {
  const { resolver, base, warns } = setup();
  const out = resolver.resolveToolInput('Write', {
    file_path: labelled(base, 'new.txt'), content: `owner: ${LABEL}`,
  });
  assert.strictEqual(out.file_path, real(base, 'new.txt'));
  assert.strictEqual(out.content, 'owner: Acme');
  assert.strictEqual(warns.length, 0);
  assert.ok(!out.file_path.includes('[PII:'));
});

test('Write to a labelled directory that does not exist yet still resolves', () => {
  const { resolver, base } = setup();
  const out = resolver.resolveToolInput('Write', { file_path: labelled(base, 'sub', 'deep', 'n.txt'), content: 'x' });
  assert.strictEqual(out.file_path, real(base, 'sub', 'deep', 'n.txt'));
});

test('Edit on an existing file at a labelled path is found and derived, not refused', () => {
  const { resolver, base } = setup();
  const out = resolver.resolveToolInput('Edit', {
    file_path: labelled(base, 'old.txt'), old_string: 'hello', new_string: 'bye',
  });
  assert.strictEqual(out.file_path, real(base, 'old.txt'));
  assert.strictEqual(out.old_string, 'hello');
  assert.strictEqual(out.new_string, 'bye');
});

test('MultiEdit resolves the path and each edit', () => {
  const { resolver, base } = setup();
  const out = resolver.resolveToolInput('MultiEdit', {
    file_path: labelled(base, 'old.txt'),
    edits: [{ old_string: 'hello', new_string: `hi ${LABEL}` }],
  });
  assert.strictEqual(out.file_path, real(base, 'old.txt'));
  assert.strictEqual(out.edits[0].new_string, 'hi Acme');
});

test('NotebookEdit and NotebookRead resolve notebook_path', () => {
  const { resolver, base } = setup();
  for (const name of ['NotebookEdit', 'NotebookRead']) {
    const out = resolver.resolveToolInput(name, { notebook_path: labelled(base, 'n.ipynb'), new_source: 'x' });
    assert.strictEqual(out.notebook_path, real(base, 'n.ipynb'), name);
  }
});

test('Read and LS resolve their path', () => {
  const { resolver, base } = setup();
  assert.strictEqual(resolver.resolveToolInput('Read', { file_path: labelled(base, 'old.txt') }).file_path, real(base, 'old.txt'));
  assert.strictEqual(resolver.resolveToolInput('LS', { path: labelled(base) }).path, real(base));
});

test('Glob resolves path and pattern', () => {
  const { resolver, base } = setup();
  const out = resolver.resolveToolInput('Glob', { path: labelled(base), pattern: `**/${LABEL}-*.js` });
  assert.strictEqual(out.path, real(base));
  assert.strictEqual(out.pattern, '**/Acme-*.js');
});

test('Grep resolves path, pattern and glob', () => {
  const { resolver, base } = setup();
  const out = resolver.resolveToolInput('Grep', { path: labelled(base), pattern: `class ${LABEL}`, glob: `${LABEL}/*.ts`, output_mode: 'content' });
  assert.strictEqual(out.path, real(base));
  assert.strictEqual(out.pattern, 'class Acme');
  assert.strictEqual(out.glob, 'Acme/*.ts');
  assert.strictEqual(out.output_mode, 'content', 'unrelated fields are untouched');
});

test('an input with no label is returned unchanged, by reference', () => {
  const { resolver, base } = setup();
  const input = { file_path: real(base, 'old.txt') };
  assert.strictEqual(resolver.resolveToolInput('Read', input), input);
});

test('a label that cannot be resolved leaves the path alone, and says so', () => {
  // Not a configured literal and not cached: genuinely underivable.
  const { resolver, base, warns, stats } = setup({ cached: {} });
  const input = { file_path: path.join(base, '[PII:email:0123456789abcdef]', 'new.txt'), content: 'x' };
  const out = resolver.resolveToolInput('Write', input);
  assert.strictEqual(out.file_path, input.file_path);
  assert.strictEqual(stats.pathLabelUnresolved, 1);
  assert.ok(warns.some((w) => /Write\.file_path/.test(w)), 'must warn, not stay silent');
});

test('a path with one resolvable and one unresolvable label is left whole, not half-resolved', () => {
  const { resolver, base, stats } = setup();
  const other = '[PII:personal:0000000000000000]';
  const p = path.join(base, LABEL, other, 'f.txt');
  const out = resolver.resolveToolInput('Write', { file_path: p, content: 'x' });
  assert.strictEqual(out.file_path, p);
  assert.strictEqual(stats.pathLabelUnresolved, 1);
});

test('a cached value that would escape the directory is refused', () => {
  const { resolver, base, warns, stats } = setup({ cached: { [LABEL]: '../../etc' } });
  const p = labelled(base, 'new.txt');
  const out = resolver.resolveToolInput('Write', { file_path: p, content: 'x' });
  assert.strictEqual(out.file_path, p);
  assert.strictEqual(stats.pathUnsafe, 1);
  assert.ok(warns.length >= 1);
});

test('a ".." the model typed itself is not blamed on the label', () => {
  const { resolver, base } = setup();
  const p = path.join(base, 'x', '..', LABEL, 'new.txt');
  const out = resolver.resolveToolInput('Write', { file_path: p, content: 'x' });
  assert.strictEqual(out.file_path, path.join(base, 'x', '..', 'Acme', 'new.txt'));
});

test('a value containing a path separator is allowed (a git org/repo label stands for one)', () => {
  const { resolver, base } = setup({ cached: { [LABEL]: 'org/repo' } });
  const out = resolver.resolveToolInput('Write', { file_path: labelled(base, 'f.txt'), content: 'x' });
  // Substituted verbatim: a label stands for text, and the text keeps its own
  // separator. (path.join would normalise it to a backslash on Windows.)
  assert.strictEqual(out.file_path, labelled(base, 'f.txt').replace(LABEL, 'org/repo'));
});

test('through the SSE transformer: the tool_use the CLIENT receives has a real path', () => {
  const { resolver, base } = setup();
  const t = createSseTransformer({ aliases: [], resolver });
  const input = JSON.stringify({ file_path: labelled(base, 'new.txt'), content: `by ${LABEL}` });
  const ev = (o) => `event: ${o.type}\ndata: ${JSON.stringify(o)}\n\n`;
  let out = '';
  out += t.push(ev({ type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'Write', id: 't1' } }));
  out += t.push(ev({ type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: input } }));
  out += t.push(ev({ type: 'content_block_stop', index: 0 }));
  const deltas = [...out.matchAll(/data: (\{"type":"content_block_delta".*?\})\n/g)].map((m) => JSON.parse(m[1]));
  const final = JSON.parse(deltas[deltas.length - 1].delta.partial_json);
  assert.strictEqual(final.file_path, real(base, 'new.txt'));
  assert.strictEqual(final.content, 'by Acme');
  assert.ok(!out.includes('[PII:'), 'no label may reach the client');
});

// ---- labels derivable from the rules need no cache ----

test('a literal resolves with an EMPTY cache: derived from the rules and the key', () => {
  const { resolver, base, stats, warns } = setup({ cached: {} });
  const out = resolver.resolveToolInput('Write', { file_path: labelled(base, 'new.txt'), content: `by ${LABEL}` });
  assert.strictEqual(out.file_path, real(base, 'new.txt'));
  assert.strictEqual(out.content, 'by Acme');
  assert.ok(stats.literalDerived >= 2);
  assert.strictEqual(warns.length, 0);
});

test('it also works with no cache object at all', () => {
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const out = resolver.resolveToolInput('Read', { file_path: `/x/${LABEL}/f` });
  assert.strictEqual(out.file_path, '/x/Acme/f');
});

test('common case spellings of a literal resolve to the spelling that was matched', () => {
  const rules = compile({ literals: ['Acme Corp'] });
  const resolver = createResolver({ rules, kLabel: K });
  for (const spelling of ['Acme Corp', 'acme corp', 'ACME CORP']) {
    const label = makeLabel(K, 'personal', spelling);
    assert.strictEqual(resolver.resolveToolInput('Read', { file_path: `/x/${label}` }).file_path, `/x/${spelling}`, spelling);
  }
});

test('a pattern category (email) is NOT derivable: it needs the cache, and warns without it', () => {
  const rules = compile({ literals: ['Acme'], patterns: [{ name: 'email', regex: '[a-z]{1,20}@[a-z]{1,20}\\.com', flags: 'gi' }] });
  const label = makeLabel(K, 'email', 'a@b.com');
  const warns = [];
  const stats = {};
  const bare = createResolver({ rules, kLabel: K, stats, warn: (m) => warns.push(m) });
  assert.strictEqual(bare.resolveToolInput('Read', { file_path: `/x/${label}` }).file_path, `/x/${label}`);
  assert.strictEqual(stats.pathLabelUnresolved, 1);
  assert.strictEqual(warns.length, 1);
  const cached = createResolver({ rules, kLabel: K, cache: { get: (l) => (l === label ? 'a@b.com' : undefined), set() {} } });
  assert.strictEqual(cached.resolveToolInput('Read', { file_path: `/x/${label}` }).file_path, '/x/a@b.com');
});

test('a label for a value that is NOT a configured literal is not invented', () => {
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const stranger = makeLabel(K, 'personal', 'Stranger');
  assert.strictEqual(resolver.resolveToolInput('Read', { file_path: `/x/${stranger}` }).file_path, `/x/${stranger}`);
});

test('a label made under a DIFFERENT key does not resolve', () => {
  const resolver = createResolver({ rules: RULES, kLabel: K });
  const foreign = makeLabel(Buffer.alloc(32, 99), 'personal', 'Acme');
  assert.strictEqual(resolver.resolveToolInput('Read', { file_path: `/x/${foreign}` }).file_path, `/x/${foreign}`);
});

test('Bash also benefits: a literal label in a command resolves without the cache', () => {
  const resolver = createResolver({ rules: RULES, kLabel: K });
  assert.strictEqual(resolver.resolveToolInput('Bash', { command: `ls /srv/${LABEL}` }).command, 'ls /srv/Acme');
});

test('a listed literal that a category pattern also matches resolves under the pattern category', () => {
  const { renderForModel, makeRenderConfig } = require('../pipeline');
  const addr = 'jane@example.com';
  const rules = compile({
    literals: [addr],
    patterns: [{ name: 'email', regex: '[a-z]{1,20}@[a-z]{1,20}\\.com', flags: 'gi' }],
  });
  const render = makeRenderConfig({ rules, kLabel: K, aliases: [], normalizers: null });
  // What the model actually sees: the PATTERN wins the overlap.
  const seen = renderForModel(`/x/${addr}/f`, render).text;
  assert.match(seen, /\[PII:email:[0-9a-f]{16}\]/, 'precondition: labelled under the email category, not personal');
  const resolver = createResolver({ rules, kLabel: K, render });
  assert.strictEqual(resolver.resolveToolInput('Read', { file_path: seen }).file_path, `/x/${addr}/f`);
});
