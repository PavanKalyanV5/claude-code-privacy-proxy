'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { compile } = require('../rules');
const { makeLabel } = require('../spans');
const { createResolver } = require('../resolver');
const { createCache } = require('../cache');

const K = Buffer.alloc(32, 17);
const RULES = compile({
  literals: ['Jane Q. Testerson'],
  patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}', flags: 'gi' }],
});

function fixture(contents) {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-')), 'f.js');
  fs.writeFileSync(p, contents);
  return p;
}

test('a local MCP tool with cache-resolvable label in string input resolves it', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-cache1-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 26), path: cachePath });
  const label = makeLabel(K, 'email', 'test@example.org');
  cache.set(label, 'test@example.org');

  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    cache,
    remoteTools: [],
  });

  const out = resolver.resolveToolInput('mcp__filesystem__read_file', {
    path: `/some/path`,
    name: `read-${label}`,
  });

  assert.strictEqual(out.name, 'read-test@example.org', 'local MCP tool should resolve label');
  assert.strictEqual(out.path, '/some/path', 'path should remain unchanged');
});

test('a local MCP tool resolves label in nested object', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-cache2-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 27), path: cachePath });
  const label = makeLabel(K, 'email', 'nested@example.org');
  cache.set(label, 'nested@example.org');

  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    cache,
    remoteTools: [],
  });

  const out = resolver.resolveToolInput('mcp__custom__tool', {
    config: {
      nested: {
        email: label,
      },
    },
  });

  assert.strictEqual(out.config.nested.email, 'nested@example.org', 'nested label should be resolved');
});

test('a local MCP tool resolves label in array elements', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-cache3-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 28), path: cachePath });
  const label1 = makeLabel(K, 'email', 'first@example.org');
  const label2 = makeLabel(K, 'email', 'second@example.org');
  cache.set(label1, 'first@example.org');
  cache.set(label2, 'second@example.org');

  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    cache,
    remoteTools: [],
  });

  const out = resolver.resolveToolInput('mcp__array__tool', {
    recipients: [label1, label2, 'plain@text'],
  });

  assert.deepStrictEqual(out.recipients, ['first@example.org', 'second@example.org', 'plain@text'], 'array labels should be resolved');
});

test('a remote MCP tool keeps input completely unmodified with remoteTools', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-cache4-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 29), path: cachePath });
  const label = makeLabel(K, 'email', 'remote@example.org');
  cache.set(label, 'remote@example.org');

  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    cache,
    remoteTools: ['mcp__zen__'],
  });

  const input = {
    query: label,
    config: {
      nested: label,
    },
  };

  const out = resolver.resolveToolInput('mcp__zen__chat', input);

  assert.deepStrictEqual(out, input, 'remote MCP tool input should be unchanged');
  assert.ok(out.query.includes('[PII:'), 'label should be preserved in remote tool input');
});

test('a remote MCP tool keeps alias unreversed (already verified in sse tests)', () => {
  // This is primarily tested in sse.test.js, but we verify resolver handles the alias correctly
  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    remoteTools: ['mcp__zen__'],
  });

  // The alias would have been kept by shouldUnalias, and resolver must pass it through
  const input = { path: 'C:\\Users\\anon\\file.js' };
  const out = resolver.resolveToolInput('mcp__zen__chat', input);
  assert.deepStrictEqual(out, input, 'remote tool alias and input unchanged together');
});

test('a local MCP tool with unresolvable label calls warn and leaves it unchanged', () => {
  let warnCalled = false;
  let warnMsg = '';
  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    remoteTools: [],
    warn: (msg) => {
      warnCalled = true;
      warnMsg = msg;
    },
  });

  const unknownLabel = '[PII:email:ffffffffffffffff]';
  const input = {
    data: unknownLabel,
    nested: { value: unknownLabel },
  };

  const out = resolver.resolveToolInput('mcp__custom__tool', input);

  assert.ok(warnCalled, 'warn should be called for unresolvable label in MCP tool');
  assert.ok(warnMsg.includes('mcp__custom__tool'), 'warn message should mention tool name');
  assert.deepStrictEqual(out, input, 'input should be unchanged when label unresolvable');
});

test('remoteTools is read from config (passed to resolver)', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-cache5-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 30), path: cachePath });
  const label = makeLabel(K, 'email', 'test@example.org');
  cache.set(label, 'test@example.org');

  // Create resolver with explicit remoteTools list
  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    cache,
    remoteTools: ['mcp__zen__', 'mcp__anthropic__'],
  });

  // mcp__zen__ is remote, should not resolve
  const zOut = resolver.resolveToolInput('mcp__zen__chat', { q: label });
  assert.ok(zOut.q.includes('[PII:'), 'listed remote tool should not resolve');

  // mcp__custom__ is local, should resolve
  const cOut = resolver.resolveToolInput('mcp__custom__tool', { q: label });
  assert.strictEqual(cOut.q, 'test@example.org', 'unlisted MCP tool should resolve');
});

test('Bash tool continues to resolve from cache-only', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-cache6-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 31), path: cachePath });
  const label = makeLabel(K, 'email', 'bash@example.org');
  cache.set(label, 'bash@example.org');

  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    cache,
    remoteTools: ['mcp__zen__'],
  });

  const out = resolver.resolveToolInput('Bash', {
    command: `grep "${label}" file.txt`,
    other: label,
  });

  // Only command is resolved for Bash, not other fields
  assert.strictEqual(out.command, 'grep "bash@example.org" file.txt', 'Bash command should be resolved');
  assert.strictEqual(out.other, label, 'Bash other fields should not be resolved');
});

test('local file tools (Edit/Write/Read) continue working unchanged', () => {
  const real = 'const DATA = "jane.test@example.org";\n';
  const p = fixture(real);

  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    remoteTools: ['mcp__zen__'],
  });

  const out = resolver.resolveToolInput('Read', {
    file_path: p,
  });

  // Read should pass through (no input to resolve)
  assert.deepStrictEqual(out, { file_path: p }, 'Read tool should work as before');
});

test('complex nested structure in local MCP resolves deeply', () => {
  const cachePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-cache7-')), 'c.enc');
  const cache = createCache({ key: Buffer.alloc(32, 32), path: cachePath });
  const label = makeLabel(K, 'email', 'deep@example.org');
  cache.set(label, 'deep@example.org');

  const resolver = createResolver({
    rules: RULES,
    kLabel: K,
    cache,
    remoteTools: [],
  });

  const out = resolver.resolveToolInput('mcp__complex__tool', {
    level1: {
      level2: {
        level3: [
          { email: label },
          { data: 'plain', sub: { email: label } },
        ],
      },
    },
  });

  assert.strictEqual(out.level1.level2.level3[0].email, 'deep@example.org', 'deeply nested label should resolve');
  assert.strictEqual(out.level1.level2.level3[1].sub.email, 'deep@example.org', 'nested in sub should resolve');
});
