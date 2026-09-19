'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile } = require('../rules');
const { compileAliases } = require('../aliases');
const { makeContext, transformBody, resetStats } = require('../walk');

function ctx() {
  return makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: ['Jane Q. Testerson'], patterns: [] }),
    aliases: compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]),
  });
}

test('redacts messages given as a bare string', () => {
  const out = transformBody(
    { messages: [{ role: 'user', content: 'hi Jane Q. Testerson' }] },
    ctx()
  );
  assert.match(out.messages[0].content, /\[PII:personal:[0-9a-f]{16}\]/);
});

test('redacts messages given as a block array', () => {
  const out = transformBody(
    {
      messages: [
        { role: 'user', content: [{ type: 'text', text: 'hi Jane Q. Testerson' }] },
      ],
    },
    ctx()
  );
  assert.match(out.messages[0].content[0].text, /\[PII:personal:/);
});

test('redacts tool_result content and tool_use input', () => {
  const out = transformBody(
    {
      messages: [
        {
          role: 'user',
          content: [{ type: 'tool_result', content: 'owner Jane Q. Testerson' }],
        },
        {
          role: 'assistant',
          content: [
            { type: 'tool_use', name: 'Edit', input: { old_string: 'Jane Q. Testerson' } },
          ],
        },
      ],
    },
    ctx()
  );
  assert.match(out.messages[0].content[0].content, /\[PII:personal:/);
  assert.match(out.messages[1].content[0].input.old_string, /\[PII:personal:/);
});

test('aliases paths in system text', () => {
  const out = transformBody(
    { system: [{ type: 'text', text: 'cwd is C:\\Users\\SOMEONE\\proj' }] },
    ctx()
  );
  assert.strictEqual(out.system[0].text, 'cwd is C:\\Users\\anon\\proj');
});

test('leaves tools untouched byte for byte', () => {
  const tools = [{ name: 'Edit', description: 'edit C:\\Users\\SOMEONE and Jane Q. Testerson' }];
  const out = transformBody({ tools, messages: [] }, ctx());
  assert.deepStrictEqual(out.tools, tools);
});

test('leaves signed thinking blocks untouched byte for byte', () => {
  const block = {
    role: 'assistant',
    content: [
      { type: 'thinking', thinking: 'about Jane Q. Testerson', signature: 'sig' },
      { type: 'redacted_thinking', data: 'C:\\Users\\SOMEONE' },
    ],
  };
  const out = transformBody({ messages: [block] }, ctx());
  assert.deepStrictEqual(out.messages[0].content, block.content);
});

test('CRITICAL 3: image blocks with base64 data pass through byte-identical', () => {
  const block = {
    role: 'user',
    content: [
      {
        type: 'image',
        source: {
          type: 'base64',
          media_type: 'image/png',
          // boundary chars '/' and '+' either side make this a valid
          // boundedLiteral hit if the walker were to touch it.
          data: 'AAA/[PII:personal:711e9e343efbe85c]+BBB=',
        },
      },
    ],
  };
  const out = transformBody({ messages: [block] }, ctx());
  assert.strictEqual(out.messages[0].content[0], block.content[0]);
});

test('CRITICAL 3: document blocks with base64 data pass through byte-identical', () => {
  const block = {
    role: 'user',
    content: [
      {
        type: 'document',
        source: {
          type: 'base64',
          media_type: 'application/pdf',
          data: 'AAA/[PII:personal:711e9e343efbe85c]+BBB=',
        },
      },
    ],
  };
  const out = transformBody({ messages: [block] }, ctx());
  assert.strictEqual(out.messages[0].content[0], block.content[0]);
});

test('leaves metadata untouched', () => {
  const metadata = { user_id: '{"device_id":"abc"}' };
  const out = transformBody({ metadata, messages: [] }, ctx());
  assert.deepStrictEqual(out.metadata, metadata);
});

test('memoizes repeated blocks and matches non-memoized output', () => {
  const c = ctx();
  const block = { role: 'user', content: 'hi Jane Q. Testerson' };
  const first = transformBody({ messages: [block] }, c);
  resetStats(c);
  const second = transformBody({ messages: [block] }, c);
  assert.deepStrictEqual(second.messages[0], first.messages[0]);
  assert.strictEqual(c.stats.memoHit, 1);
  assert.strictEqual(c.stats.memoMiss, 0);
});

test('only new blocks are transformed as history grows', () => {
  const c = ctx();
  const history = [{ role: 'user', content: 'a Jane Q. Testerson' }];
  transformBody({ messages: history }, c);
  history.push({ role: 'assistant', content: 'b' });
  resetStats(c);
  transformBody({ messages: history }, c);
  assert.strictEqual(c.stats.memoHit, 1);
  assert.strictEqual(c.stats.memoMiss, 1);
});

test('memo store holds no plaintext personal data', () => {
  const c = ctx();
  transformBody({ messages: [{ role: 'user', content: 'Jane Q. Testerson' }] }, c);
  const dump = JSON.stringify([...c.memo.entries()]);
  assert.ok(!dump.includes('Jane Q. Testerson'));
});

test('does not mutate the input body', () => {
  const body = { messages: [{ role: 'user', content: 'Jane Q. Testerson' }] };
  const snapshot = JSON.stringify(body);
  transformBody(body, ctx());
  assert.strictEqual(JSON.stringify(body), snapshot);
});

test('identical bodies redact byte-identically (prompt caching depends on it)', () => {
  const body = {
    system: [{ type: 'text', text: 'cwd C:\\Users\\SOMEONE' }],
    messages: [{ role: 'user', content: 'Jane Q. Testerson' }],
  };
  // Separate contexts, so this proves determinism rather than memo reuse.
  const a = JSON.stringify(transformBody(body, ctx()));
  const b = JSON.stringify(transformBody(body, ctx()));
  assert.strictEqual(a, b);
});

test('memo evicts past memoMax', () => {
  const c = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }),
    aliases: [],
    memoMax: 2,
  });
  for (let i = 0; i < 5; i++) transformBody({ messages: [{ role: 'user', content: `m${i}` }] }, c);
  assert.ok(c.memo.size <= 2);
});

test('normalization runs on message content', () => {
  const { compileNormalizers } = require('../normalize');
  const c = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }),
    aliases: [],
    normalizers: compileNormalizers({
      timezone: true,
      rewrites: [{ name: 'os', regex: 'Windows (\\d+)(?: [A-Za-z]+)? \\d+\\.\\d+\\.\\d+', flags: 'g', replace: 'Windows $1' }],
    }),
  });
  const out = transformBody(
    { messages: [{ role: 'user', content: 'Windows 11 Pro 10.0.26200 at 2026-09-17 21:08:56 +0530' }] },
    c
  );
  assert.strictEqual(out.messages[0].content, 'Windows 11 at 2026-09-17T15:38:56Z');
  assert.ok(c.stats.normalized >= 2, `normalized=${c.stats.normalized}`);
});

test('normalization leaves tools[] and thinking blocks alone', () => {
  const { compileNormalizers } = require('../normalize');
  const c = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }),
    aliases: [],
    normalizers: compileNormalizers({ timezone: true, rewrites: [] }),
  });
  const tools = [{ name: 'X', description: 'at 2026-09-17 21:08:56 +0530' }];
  const th = { type: 'thinking', thinking: 'at 2026-09-17 21:08:56 +0530', signature: 'S' };
  const out = transformBody({ tools, messages: [{ role: 'assistant', content: [th] }] }, c);
  assert.deepStrictEqual(out.tools, tools);
  assert.strictEqual(out.messages[0].content[0], th);
});

test('no normalizers configured is a no-op', () => {
  const c = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }),
    aliases: [],
  });
  const s = 'at 2026-09-17 21:08:56 +0530';
  assert.strictEqual(transformBody({ messages: [{ role: 'user', content: s }] }, c).messages[0].content, s);
});

test('git remote org and repo are redacted by pattern, not normalization', () => {
  const rules = compile({
    literals: [],
    patterns: [
      { name: 'git-org', regex: '(?<=(?:github|gitlab|bitbucket)\\.(?:com|org)[/:])[A-Za-z0-9._-]+', flags: 'g' },
      { name: 'git-repo', regex: '(?<=(?:github|gitlab|bitbucket)\\.(?:com|org)[/:][A-Za-z0-9._-]{1,64}/)[A-Za-z0-9._-]+', flags: 'g' },
    ],
  });
  const c = makeContext({ kLabel: Buffer.alloc(32, 3), kMemo: Buffer.alloc(32, 4), rules, aliases: [] });
  const out = transformBody(
    { messages: [{ role: 'user', content: 'origin  git@github.com:acme-corp/billing.git' }] },
    c
  );
  const got = out.messages[0].content;
  assert.ok(!got.includes('acme-corp'), got);
  assert.ok(!got.includes('billing'), got);
  assert.match(got, /\[PII:git-org:[0-9a-f]{16}\]/);
  assert.match(got, /\[PII:git-repo:[0-9a-f]{16}\]/);
  assert.ok(got.includes('github.com'), 'the host itself is not secret');
});

test('metadata is untouched unless a device rewriter is configured', () => {
  const metadata = { user_id: JSON.stringify({ device_id: 'd'.repeat(64), account_uuid: '', session_id: 'S' }) };
  const plain = makeContext({
    kLabel: Buffer.alloc(32, 3), kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }), aliases: [],
  });
  assert.deepStrictEqual(transformBody({ metadata, messages: [] }, plain).metadata, metadata);

  const { makeDeviceRewriter } = require('../device');
  const withRw = makeContext({
    kLabel: Buffer.alloc(32, 3), kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: [], patterns: [] }), aliases: [],
    deviceRewriter: makeDeviceRewriter({ mode: 'stable', kDevice: Buffer.alloc(32, 9) }),
  });
  const out = transformBody({ metadata, messages: [] }, withRw).metadata;
  assert.ok(!JSON.stringify(out).includes('d'.repeat(64)));
});
