'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { formatLine } = require('../audit');

test('renders counts, never values', () => {
  const line = formatLine({
    method: 'POST',
    url: '/v1/messages?beta=true',
    bytes: 94705,
    stats: { counts: { email: 3, phone: 1 }, aliased: 7, memoHit: 41, memoMiss: 2, walkedChars: 30100 },
    resolvedAliases: 2,
  });
  assert.match(line, /POST \/v1\/messages/);
  assert.match(line, /body=92\.5KB/);
  assert.match(line, /walked=29\.4KB/);
  assert.match(line, /memo=41\/43/);
  assert.match(line, /email=3/);
  assert.match(line, /phone=1/);
  assert.match(line, /aliased=7/);
  assert.match(line, /unaliased=2/);
});

test('renders a clean line when nothing was found', () => {
  const line = formatLine({
    method: 'HEAD',
    url: '/api/hello',
    bytes: 0,
    stats: { counts: {}, aliased: 0, memoHit: 0, memoMiss: 0, walkedChars: 0 },
    resolvedAliases: 0,
  });
  assert.match(line, /HEAD \/api\/hello/);
  assert.match(line, /redacted=none/);
});

test('never contains anything that looks like a credential', () => {
  const line = formatLine({
    method: 'POST',
    url: '/v1/messages',
    bytes: 10,
    stats: { counts: { email: 1 }, aliased: 0, memoHit: 0, memoMiss: 1, walkedChars: 10 },
    resolvedAliases: 0,
  });
  assert.ok(!/sk-|x-api-key|authorization|bearer/i.test(line));
});
