'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compileAliases } = require('../aliases');
const { createSseTransformer, shouldUnalias } = require('../sse');

const A = compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]);
const ev = (type, obj) => `event: ${type}\ndata: ${JSON.stringify(obj)}\n\n`;

function run(chunks) {
  const stats = { resolvedAliases: 0 };
  const t = createSseTransformer({ aliases: A, stats });
  let out = '';
  for (const c of chunks) out += t.push(c);
  out += t.flush();
  return { out, stats };
}

// Pull the emitted tool inputs out and PARSE them. Do not substring-match the
// raw stream: partial_json is JSON-escaped once inside the tool input and again
// by the enclosing event, so a path appears as C:\\\\Users\\\\SOMEONE and a naive
// includes() on C:\\Users\\SOMEONE fails even when the value is correct.
function toolInputs(out) {
  const inputs = [];
  for (const block of out.split('\n\n')) {
    const line = block.split('\n').find((l) => l.startsWith('data:'));
    if (!line) continue;
    let payload;
    try {
      payload = JSON.parse(line.slice(5).trim());
    } catch (e) {
      continue;
    }
    if (payload.delta && payload.delta.type === 'input_json_delta') {
      try {
        inputs.push(JSON.parse(payload.delta.partial_json));
      } catch (e) {
        inputs.push(payload.delta.partial_json);
      }
    }
  }
  return inputs;
}

test('text_delta passes through untouched', () => {
  const s = ev('content_block_delta', {
    type: 'content_block_delta',
    index: 0,
    delta: { type: 'text_delta', text: 'see C:\\Users\\anon\\x' },
  });
  assert.strictEqual(run([s]).out, s);
});

test('tool_use input is un-aliased at block stop', () => {
  const { out } = run([
    ev('content_block_start', {
      type: 'content_block_start',
      index: 0,
      content_block: { type: 'tool_use', id: 't1', name: 'Read', input: {} },
    }),
    ev('content_block_delta', {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: '{"file_path":"C:\\\\Users\\\\anon' },
    }),
    ev('content_block_delta', {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: '\\\\a.js"}' },
    }),
    ev('content_block_stop', { type: 'content_block_stop', index: 0 }),
  ]);
  assert.deepStrictEqual(toolInputs(out), [{ file_path: 'C:\\Users\\SOMEONE\\a.js' }]);
  assert.ok(!out.includes('anon'), out);
});

test('an alias split across two deltas is still reversed', () => {
  const { out } = run([
    ev('content_block_start', {
      type: 'content_block_start',
      index: 0,
      content_block: { type: 'tool_use', id: 't1', name: 'Read', input: {} },
    }),
    ev('content_block_delta', {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: '{"p":"C:\\\\Users\\\\an' },
    }),
    ev('content_block_delta', {
      type: 'content_block_delta',
      index: 0,
      delta: { type: 'input_json_delta', partial_json: 'on\\\\z"}' },
    }),
    ev('content_block_stop', { type: 'content_block_stop', index: 0 }),
  ]);
  assert.ok(out.includes('SOMEONE'), out);
});

test('two concurrent tool_use blocks stay separate', () => {
  const { out } = run([
    ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'Read', input: {} } }),
    ev('content_block_start', { type: 'content_block_start', index: 1, content_block: { type: 'tool_use', name: 'Read', input: {} } }),
    ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"a":"C:\\\\Users\\\\anon"}' } }),
    ev('content_block_delta', { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: '{"b":"plain"}' } }),
    ev('content_block_stop', { type: 'content_block_stop', index: 1 }),
    ev('content_block_stop', { type: 'content_block_stop', index: 0 }),
  ]);
  const got = toolInputs(out);
  assert.ok(got.some((i) => i.b === 'plain'), JSON.stringify(got));
  assert.ok(got.some((i) => i.a === 'C:\\Users\\SOMEONE'), JSON.stringify(got));
});

test('mcp__ tool inputs are NOT un-aliased when listed in exclude', () => {
  // Default changed in phase 2: MCP tools ARE un-aliased by default, but can be
  // excluded. This test verifies the exclude path still works for remote servers.
  const stats = { resolvedAliases: 0 };
  const t = createSseTransformer({
    aliases: A,
    stats,
    remoteTools: ['mcp__zen__'],
  });
  let out = '';
  out += t.push(ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'mcp__zen__chat', input: {} } }));
  out += t.push(ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"p":"C:\\\\Users\\\\anon\\\\x"}' } }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();
  assert.ok(out.includes('anon'), out);
  assert.ok(!out.includes('SOMEONE'), out);
});

test('malformed event data is forwarded unchanged', () => {
  const bad = 'event: x\ndata: {not json\n\n';
  assert.strictEqual(run([bad]).out, bad);
});

test('events split mid-line across chunks are reassembled', () => {
  const s = ev('message_stop', { type: 'message_stop' });
  const mid = Math.floor(s.length / 2);
  assert.strictEqual(run([s.slice(0, mid), s.slice(mid)]).out, s);
});

test('unterminated trailing data is emitted by flush', () => {
  const t = createSseTransformer({ aliases: A, stats: {} });
  assert.strictEqual(t.push('event: partial\ndata: {}'), '');
  assert.strictEqual(t.flush(), 'event: partial\ndata: {}');
});

test('Edit tool input is resolved against the file on disk', () => {
  const calls = [];
  const resolver = {
    resolveToolInput(name, input) {
      calls.push(name);
      if (name !== 'Edit') return input;
      return Object.assign({}, input, { old_string: 'REAL', new_string: 'REAL2' });
    },
  };
  const stats = {};
  const t = createSseTransformer({ aliases: A, stats, resolver });
  let out = '';
  out += t.push(ev('content_block_start', {
    type: 'content_block_start', index: 0,
    content_block: { type: 'tool_use', name: 'Edit', input: {} },
  }));
  out += t.push(ev('content_block_delta', {
    type: 'content_block_delta', index: 0,
    delta: { type: 'input_json_delta', partial_json: JSON.stringify({ file_path: 'x.js', old_string: 'LBL', new_string: 'LBL2' }) },
  }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();

  assert.deepStrictEqual(calls, ['Edit']);
  assert.deepStrictEqual(toolInputs(out), [{ file_path: 'x.js', old_string: 'REAL', new_string: 'REAL2' }]);
});

test('a resolver that throws never breaks the stream', () => {
  const resolver = { resolveToolInput() { throw new Error('boom'); } };
  const t = createSseTransformer({ aliases: A, stats: {}, resolver });
  let out = '';
  out += t.push(ev('content_block_start', {
    type: 'content_block_start', index: 0,
    content_block: { type: 'tool_use', name: 'Edit', input: {} },
  }));
  out += t.push(ev('content_block_delta', {
    type: 'content_block_delta', index: 0,
    delta: { type: 'input_json_delta', partial_json: JSON.stringify({ file_path: 'x.js', old_string: 'LBL' }) },
  }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();
  // Passes through unchanged rather than dropping the block.
  assert.deepStrictEqual(toolInputs(out), [{ file_path: 'x.js', old_string: 'LBL' }]);
});

test('no resolver behaves exactly as Phase 1 did', () => {
  const t = createSseTransformer({ aliases: A, stats: {} });
  let out = '';
  out += t.push(ev('content_block_start', {
    type: 'content_block_start', index: 0,
    content_block: { type: 'tool_use', name: 'Edit', input: {} },
  }));
  out += t.push(ev('content_block_delta', {
    type: 'content_block_delta', index: 0,
    delta: { type: 'input_json_delta', partial_json: JSON.stringify({ file_path: 'x.js', old_string: 'LBL' }) },
  }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();
  assert.deepStrictEqual(toolInputs(out), [{ file_path: 'x.js', old_string: 'LBL' }]);
});

test('mcp__filesystem__read_file input IS un-aliased by default', () => {
  const stats = { resolvedAliases: 0 };
  const t = createSseTransformer({ aliases: A, stats, remoteTools: [] });
  let out = '';
  out += t.push(ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'mcp__filesystem__read_file', input: {} } }));
  out += t.push(ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"path":"C:\\\\Users\\\\anon\\\\file.js"}' } }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();
  assert.deepStrictEqual(toolInputs(out), [{ path: 'C:\\Users\\SOMEONE\\file.js' }]);
  assert.ok(!out.includes('anon'), out);
});

test('mcp__zen__chat input is NOT un-aliased when excluded', () => {
  const stats = { resolvedAliases: 0 };
  const t = createSseTransformer({
    aliases: A,
    stats,
    remoteTools: ['mcp__zen__'],
  });
  let out = '';
  out += t.push(ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'mcp__zen__chat', input: {} } }));
  out += t.push(ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"p":"C:\\\\Users\\\\anon\\\\x"}' } }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();
  assert.deepStrictEqual(toolInputs(out), [{ p: 'C:\\Users\\anon\\x' }]);
});

test('non-MCP tool is still un-aliased with exclude list present', () => {
  const stats = { resolvedAliases: 0 };
  const t = createSseTransformer({
    aliases: A,
    stats,
    remoteTools: ['mcp__zen__'],
  });
  let out = '';
  out += t.push(ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'Read', input: {} } }));
  out += t.push(ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"file_path":"C:\\\\Users\\\\anon\\\\x.js"}' } }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();
  assert.deepStrictEqual(toolInputs(out), [{ file_path: 'C:\\Users\\SOMEONE\\x.js' }]);
});

test('empty exclude list un-aliases everything including MCP', () => {
  const stats = { resolvedAliases: 0 };
  const t = createSseTransformer({ aliases: A, stats, remoteTools: [] });
  let out = '';
  out += t.push(ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'mcp__x__y', input: {} } }));
  out += t.push(ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"p":"C:\\\\Users\\\\anon"}' } }));
  out += t.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
  out += t.flush();
  assert.deepStrictEqual(toolInputs(out), [{ p: 'C:\\Users\\SOMEONE' }]);
});

test('shouldUnalias returns true with no exclude list', () => {
  assert.strictEqual(shouldUnalias('mcp__x__y'), true);
  assert.strictEqual(shouldUnalias('Read'), true);
});

test('shouldUnalias returns false for excluded tool prefixes', () => {
  assert.strictEqual(shouldUnalias('mcp__x__y', ['mcp__x__']), false);
  assert.strictEqual(shouldUnalias('mcp__zen__chat', ['mcp__zen__']), false);
  assert.strictEqual(shouldUnalias('Read', ['mcp__x__']), true);
});
