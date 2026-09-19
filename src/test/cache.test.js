'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createCache, DEFAULT_TTL_MS } = require('../cache');

const KEY = Buffer.alloc(32, 11);
const tmpPath = () =>
  path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cache-')), 'redact-cache.enc');

test('round-trips a value through disk', () => {
  const p = tmpPath();
  const a = createCache({ key: KEY, path: p });
  a.set('[PII:email:aaaa]', 'real@example.org');
  a.save();

  const b = createCache({ key: KEY, path: p });
  assert.strictEqual(b.get('[PII:email:aaaa]'), 'real@example.org');
});

test('the file on disk is not plaintext', () => {
  const p = tmpPath();
  const c = createCache({ key: KEY, path: p });
  c.set('[PII:email:bbbb]', 'secret@example.org');
  c.save();
  const raw = fs.readFileSync(p, 'utf8');
  assert.ok(!raw.includes('secret@example.org'), 'plaintext value on disk');
  assert.ok(!raw.includes('[PII:email:bbbb]'), 'plaintext label on disk');
});

test('a different key cannot read it, and fails soft', () => {
  const p = tmpPath();
  const a = createCache({ key: KEY, path: p });
  a.set('[PII:email:cccc]', 'real@example.org');
  a.save();

  const b = createCache({ key: Buffer.alloc(32, 99), path: p });
  assert.strictEqual(b.get('[PII:email:cccc]'), undefined);
  assert.strictEqual(b.size(), 0);
});

test('tampering is detected and the cache rebuilds empty', () => {
  const p = tmpPath();
  const c = createCache({ key: KEY, path: p });
  c.set('[PII:email:dddd]', 'real@example.org');
  c.save();

  const raw = fs.readFileSync(p, 'utf8');
  const flipped = raw.slice(0, -6) + (raw.slice(-6, -5) === 'a' ? 'b' : 'a') + raw.slice(-5);
  fs.writeFileSync(p, flipped);

  const d = createCache({ key: KEY, path: p });
  assert.strictEqual(d.size(), 0);
  assert.strictEqual(d.get('[PII:email:dddd]'), undefined);
});

test('entries past the TTL are dropped on load', () => {
  const p = tmpPath();
  const c = createCache({ key: KEY, path: p, ttlMs: 50 });
  c.set('[PII:email:eeee]', 'real@example.org');
  c.save();

  const past = Date.now() + 1000;
  const revived = createCache({ key: KEY, path: p, ttlMs: 50, now: () => past });
  assert.strictEqual(revived.get('[PII:email:eeee]'), undefined);
});

test('a fresh entry survives a load within the TTL', () => {
  const p = tmpPath();
  const c = createCache({ key: KEY, path: p, ttlMs: 60000 });
  c.set('[PII:email:ffff]', 'real@example.org');
  c.save();
  assert.strictEqual(createCache({ key: KEY, path: p, ttlMs: 60000 }).get('[PII:email:ffff]'), 'real@example.org');
});

test('a missing file loads as an empty cache without throwing', () => {
  const p = path.join(os.tmpdir(), 'definitely-absent-' + Date.now(), 'c.enc');
  const c = createCache({ key: KEY, path: p });
  assert.strictEqual(c.size(), 0);
});

test('evicts oldest past maxEntries', () => {
  const c = createCache({ key: KEY, path: tmpPath(), maxEntries: 3 });
  for (let i = 0; i < 6; i++) c.set(`[PII:x:${i}]`, `v${i}`);
  assert.ok(c.size() <= 3, `size ${c.size()}`);
  assert.strictEqual(c.get('[PII:x:5]'), 'v5');
});

test('default TTL is 30 days', () => {
  assert.strictEqual(DEFAULT_TTL_MS, 30 * 24 * 60 * 60 * 1000);
});

test('a hit refreshes the TTL timestamp (not measured from creation)', () => {
  // Create a cache with a tight TTL. Add an entry, then pass time,
  // then read it. If the hit refreshes the timestamp, it survives another read.
  // If the bug exists (TTL measured from creation), the second get() would
  // return undefined even though we got it back via the first get().
  let now = 1000;
  const c = createCache({
    key: KEY,
    path: tmpPath(),
    ttlMs: 100,
    now: () => now,
  });
  c.set('[PII:email:idle1]', 'value1');
  assert.strictEqual(c.get('[PII:email:idle1]'), 'value1');

  now += 80; // advance time to 80ms later. Still within TTL from creation.
  // Read it again. This HIT should refresh the timestamp to 'now'.
  assert.strictEqual(c.get('[PII:email:idle1]'), 'value1');

  now += 80; // advance another 80ms. Total 160ms from creation (past TTL),
  // but only 80ms from the refresh-at-hit.
  // If refresh works, this should still return the value. If not, undefined.
  assert.strictEqual(c.get('[PII:email:idle1]'), 'value1', 'hit did not refresh TTL');
});

test('a hit moves an entry to the end (LRU on eviction)', () => {
  // When we hit the maxEntries cap, the oldest entry is evicted.
  // But "oldest" should be "oldest by last access", not "oldest by insertion".
  // Add three entries: A, B, C. Then read B (refresh its timestamp).
  // Then add D (should hit the cap). The evicted entry should be A, not B.
  const c = createCache({
    key: KEY,
    path: tmpPath(),
    maxEntries: 3,
    now: () => Date.now(),
  });

  c.set('[PII:x:a]', 'va');
  c.set('[PII:x:b]', 'vb');
  c.set('[PII:x:c]', 'vc');
  assert.strictEqual(c.size(), 3);

  // Read B, which should move it to the end and update its timestamp.
  assert.strictEqual(c.get('[PII:x:b]'), 'vb');

  // Now add D. The eviction should remove A (oldest by insertion),
  // NOT B (which was just refreshed).
  c.set('[PII:x:d]', 'vd');
  assert.strictEqual(c.size(), 3);

  // A should be gone, B and C should be present.
  assert.strictEqual(c.get('[PII:x:a]'), undefined, 'A should have been evicted');
  assert.strictEqual(c.get('[PII:x:b]'), 'vb', 'B should survive (was refreshed)');
  assert.strictEqual(c.get('[PII:x:c]'), 'vc', 'C should survive (insertion order)');
});
