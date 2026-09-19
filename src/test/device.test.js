'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { makeDeviceRewriter } = require('../device');

const K = Buffer.alloc(32, 61);
const REAL = 'a'.repeat(64);
const md = () => ({ user_id: JSON.stringify({ device_id: REAL, account_uuid: '', session_id: 'S1' }) });

test('off returns null so metadata is never touched', () => {
  assert.strictEqual(makeDeviceRewriter({ mode: 'off', kDevice: K }), null);
  assert.strictEqual(makeDeviceRewriter({ kDevice: K }), null);
});

test('stable replaces device_id with a different value', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  const out = JSON.parse(f(md()).user_id);
  assert.notStrictEqual(out.device_id, REAL);
  assert.match(out.device_id, /^[0-9a-f]{64}$/, 'must keep the same shape');
});

test('stable is deterministic across calls and processes', () => {
  const a = JSON.parse(makeDeviceRewriter({ mode: 'stable', kDevice: K })(md()).user_id);
  const b = JSON.parse(makeDeviceRewriter({ mode: 'stable', kDevice: K })(md()).user_id);
  assert.strictEqual(a.device_id, b.device_id);
});

test('stable differs under a different key', () => {
  const a = JSON.parse(makeDeviceRewriter({ mode: 'stable', kDevice: K })(md()).user_id);
  const b = JSON.parse(makeDeviceRewriter({ mode: 'stable', kDevice: Buffer.alloc(32, 62) })(md()).user_id);
  assert.notStrictEqual(a.device_id, b.device_id);
});

test('session differs between rewriters but is stable within one', () => {
  const f = makeDeviceRewriter({ mode: 'session', kDevice: K });
  const g = makeDeviceRewriter({ mode: 'session', kDevice: K });
  const a1 = JSON.parse(f(md()).user_id).device_id;
  const a2 = JSON.parse(f(md()).user_id).device_id;
  const b1 = JSON.parse(g(md()).user_id).device_id;
  assert.strictEqual(a1, a2, 'stable within one rewriter');
  assert.notStrictEqual(a1, b1, 'differs across rewriters');
});

test('session_id and account_uuid are preserved untouched', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  const out = JSON.parse(f(md()).user_id);
  assert.strictEqual(out.session_id, 'S1');
  assert.strictEqual(out.account_uuid, '');
});

test('other metadata keys are preserved', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  const out = f({ user_id: md().user_id, other: 'keep' });
  assert.strictEqual(out.other, 'keep');
});

test('metadata without a parseable user_id is returned unchanged', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  const bad = { user_id: 'not json' };
  assert.deepStrictEqual(f(bad), bad);
  assert.deepStrictEqual(f({}), {});
});

test('the real device_id never appears in the output', () => {
  const f = makeDeviceRewriter({ mode: 'stable', kDevice: K });
  assert.ok(!JSON.stringify(f(md())).includes(REAL));
});
