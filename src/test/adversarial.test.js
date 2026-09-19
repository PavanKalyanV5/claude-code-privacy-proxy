'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile } = require('../rules');
const { compileAliases } = require('../aliases');
const { makeContext, transformBody } = require('../walk');
const { createSseTransformer } = require('../sse');

const rules = compile({
  literals: ['Marcus Delacroix', 'acme-holdings'],
  patterns: [
    { name: 'email', regex: '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}', flags: 'gi' },
    { name: 'phone', regex: '(?<![\\d.])\\d{3}[ .-]\\d{3}[ .-]\\d{4}(?![\\d.])', flags: 'g' },
  ],
});
const aliases = compileAliases([{ real: 'D:\\proj\\acme', alias: 'D:\\proj\\clientX' }]);
const mk = () =>
  makeContext({ kLabel: Buffer.alloc(32, 21), kMemo: Buffer.alloc(32, 22), rules, aliases });

const SIGNED = {
  role: 'assistant',
  content: [
    { type: 'thinking', thinking: 'Marcus Delacroix lives at acme-holdings', signature: 'SIG123' },
    { type: 'redacted_thinking', data: 'D:\\proj\\acme\\x' },
  ],
};
const TOOLS = [{ name: 'Edit', description: 'Marcus Delacroix at m@acme-holdings.com in D:\\proj\\acme' }];

const body = {
  model: 'claude-opus-5',
  tools: TOOLS,
  metadata: { user_id: '{"device_id":"abc"}' },
  system: [{ type: 'text', text: 'cwd D:\\proj\\acme and call 555-987-6543' }],
  messages: [
    SIGNED,
    { role: 'user', content: 'reach Marcus Delacroix at m.d@acme-holdings.com' },
    { role: 'user', content: [{ type: 'tool_result', content: 'owner acme-holdings, D:\\proj\\acme\\a.js' }] },
  ],
};

const out = transformBody(body, mk());

test('signed thinking blocks are the SAME OBJECTS (byte-identical)', () => {
  assert.strictEqual(out.messages[0].content[0], SIGNED.content[0]);
  assert.strictEqual(out.messages[0].content[1], SIGNED.content[1]);
});

test('tools[] untouched despite containing PII and a path', () => {
  assert.deepStrictEqual(out.tools, TOOLS);
  assert.ok(out.tools[0].description.includes('Marcus Delacroix'));
});

test('metadata untouched', () => assert.deepStrictEqual(out.metadata, body.metadata));

test('no literal PII survives anywhere outside tools/thinking/metadata', () => {
  const scrubbed = JSON.stringify({ system: out.system, msgs: out.messages.slice(1) });
  for (const bad of ['Marcus Delacroix', 'acme-holdings', 'm.d@', '555-987-6543']) {
    assert.ok(!scrubbed.includes(bad), `leaked: ${bad}`);
  }
});

test('paths aliased outbound', () => {
  assert.ok(JSON.stringify(out.system).includes('clientX'));
  assert.ok(!JSON.stringify(out.system).includes('proj\\\\acme'));
});

test('input body not mutated', () => {
  assert.ok(body.messages[1].content.includes('Marcus Delacroix'));
});

test('determinism: two fresh contexts give byte-identical output', () => {
  assert.strictEqual(
    JSON.stringify(transformBody(body, mk())),
    JSON.stringify(transformBody(body, mk()))
  );
});

test('memo holds no REDACTABLE personal data (thinking passes through by design)', () => {
  const c = mk();
  transformBody(body, c);
  const dump = JSON.stringify([...c.memo.entries()]);
  // Values the rules match are stored in label form.
  for (const bad of ['m.d@acme-holdings.com', '555-987-6543']) {
    assert.ok(!dump.includes(bad), `memo leaked redactable value: ${bad}`);
  }
  // A signed thinking block is cached verbatim -- expected, and no new
  // exposure: the same text is already in the request body, the memo is never
  // persisted, and it dies with the process.
  assert.ok(dump.includes('SIG123'));
});

test('memoization actually reuses unchanged blocks', () => {
  const c = mk();
  transformBody(body, c);
  const before = c.stats.memoMiss;
  const grown = Object.assign({}, body, { messages: body.messages.concat([{ role: 'user', content: 'new' }]) });
  c.stats.memoHit = 0;
  c.stats.memoMiss = 0;
  transformBody(grown, c);
  assert.strictEqual(c.stats.memoMiss, 1, `expected 1 new block, got ${c.stats.memoMiss}`);
  assert.ok(c.stats.memoHit >= 3, `expected >=3 reused, got ${c.stats.memoHit}`);
  assert.ok(before > 0);
});

test('SSE un-aliasing emits parseable JSON with single backslashes', () => {
  const ev = (t, o) => `event: ${t}\ndata: ${JSON.stringify(o)}\n\n`;
  const t = createSseTransformer({ aliases, stats: {} });
  let s = '';
  s += t.push(ev('content_block_start', {
    type: 'content_block_start', index: 0,
    content_block: { type: 'tool_use', name: 'Edit', input: {} },
  }));
  s += t.push(ev('content_block_delta', {
    type: 'content_block_delta', index: 0,
    delta: { type: 'input_json_delta', partial_json: JSON.stringify({ file_path: 'D:\\proj\\clientX\\a.js' }) },
  }));
  s += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  s += t.flush();

  let found = null;
  for (const blk of s.split('\n\n')) {
    const line = blk.split('\n').find((l) => l.startsWith('data:'));
    if (!line) continue;
    const p = JSON.parse(line.slice(5).trim()); // must not throw
    if (p.delta && p.delta.type === 'input_json_delta') found = JSON.parse(p.delta.partial_json);
  }
  assert.ok(found, 'no tool input emitted');
  assert.strictEqual(found.file_path, 'D:\\proj\\acme\\a.js');
});
