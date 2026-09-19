'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadMaster, subkey, restrictAcl, KEY_BYTES, KEY_PATH } = require('../keys');

function tmpKey() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'keys-')), 'redact.key');
}

test('creates a 32-byte key when absent', () => {
  const p = tmpKey();
  const k = loadMaster(p);
  assert.strictEqual(k.length, KEY_BYTES);
  assert.strictEqual(fs.readFileSync(p).length, KEY_BYTES);
});

test('returns the same key on a second call', () => {
  const p = tmpKey();
  assert.deepStrictEqual(loadMaster(p), loadMaster(p));
});

test('refuses a key file of the wrong length', () => {
  const p = tmpKey();
  fs.writeFileSync(p, Buffer.alloc(16));
  assert.throws(() => loadMaster(p), /expected 32/);
});

test('subkeys differ by purpose and are stable', () => {
  const m = Buffer.alloc(32, 7);
  const a = subkey(m, 'label');
  const b = subkey(m, 'cache');
  assert.strictEqual(a.length, 32);
  assert.notDeepStrictEqual(a, b);
  assert.deepStrictEqual(a, subkey(m, 'label'));
});

test('subkeys differ when the master differs', () => {
  assert.notDeepStrictEqual(
    subkey(Buffer.alloc(32, 1), 'label'),
    subkey(Buffer.alloc(32, 2), 'label')
  );
});

test('CRITICAL 6: restrictAcl reports its own success or failure', () => {
  const missing = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'keys-')), 'nope', 'redact.key');
  // Target's parent dir does not exist, so the OS-level ACL/chmod call fails.
  assert.strictEqual(restrictAcl(missing), false);

  const p = tmpKey();
  fs.writeFileSync(p, Buffer.alloc(KEY_BYTES));
  assert.strictEqual(restrictAcl(p), true);
});

test('CRITICAL 6: loadMaster warns on stderr when the ACL could not be restricted', () => {
  if (process.platform !== 'win32') return; // this path only fires on win32
  const p = tmpKey();
  const prevUsername = process.env.USERNAME;
  const prevUser = process.env.USER;
  delete process.env.USERNAME;
  delete process.env.USER;
  const chunks = [];
  const origWrite = process.stderr.write;
  process.stderr.write = (s) => {
    chunks.push(s);
    return true;
  };
  try {
    loadMaster(p);
  } finally {
    process.stderr.write = origWrite;
    if (prevUsername !== undefined) process.env.USERNAME = prevUsername;
    if (prevUser !== undefined) process.env.USER = prevUser;
  }
  assert.ok(
    chunks.some((c) => c.includes(p) && /acl|permission|inherit/i.test(c)),
    chunks.join('')
  );
});

test('KEY_PATH lives under ~/.claude/redaction, never in the repo', () => {
  assert.ok(KEY_PATH.includes('redaction'), KEY_PATH);
  assert.ok(!KEY_PATH.includes('games'), 'key must not live in the project tree');
});
