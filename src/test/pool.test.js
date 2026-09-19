'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createPool } = require('../pool');

const tmpCachePath = () =>
  path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pool-')), 'proxy-pool.json');

// A testCandidate that always succeeds with a fixed apparent IP, distinct
// from the direct IP, and a fixed latency. Good enough for tests that only
// care about parsing/dedup/concurrency, not ranking.
function alwaysPass({ latencyMs = 10 } = {}) {
  return (cand, cb) => cb(null, { latencyMs, apparentIp: '9.9.9.9' });
}

const directIpOk = (testUrl, timeoutMs, cb) => cb(null, '1.1.1.1');

// node:test only waits for a test if it returns a promise. Every case here
// drives an async callback API, so assertions inside that callback must be
// wired to resolve/reject the promise the test function returns -- otherwise
// a failing assertion inside the callback would be silently swallowed
// instead of failing the test.
function asyncTest(fn) {
  return () =>
    new Promise((resolve, reject) => {
      try {
        fn(resolve, reject);
      } catch (e) {
        reject(e);
      }
    });
}

test(
  'parses host:port and scheme://host:port, skips junk, dedupes',
  asyncTest((resolve, reject) => {
    const text = [
      '1.2.3.4:1080',
      'socks5://5.6.7.8:1080',
      'http://9.10.11.12:3128',
      '', // blank
      '# a comment',
      'not a proxy line at all',
      'DOWNLOAD', // bare word, no port -- must not become a candidate
      '1.2.3.4:1080', // duplicate of the first line
    ].join('\n');

    const pool = createPool({
      sources: [{ url: 'http://example.invalid/list.txt', kind: 'socks5' }],
      cachePath: tmpCachePath(),
      want: 10,
      concurrency: 4,
      fetchList: (url, cb) => cb(null, text),
      testCandidate: alwaysPass(),
      getDirectIp: directIpOk,
    });

    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        const hosts = list.map((e) => `${e.host}:${e.port}`).sort();
        assert.deepStrictEqual(hosts, ['1.2.3.4:1080', '5.6.7.8:1080', '9.10.11.12:3128']);
        const httpEntry = list.find((e) => e.host === '9.10.11.12');
        assert.strictEqual(httpEntry.kind, 'connect');
        const socksEntry = list.find((e) => e.host === '5.6.7.8');
        assert.strictEqual(socksEntry.kind, 'socks5');
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'one failing source does not fail the refresh',
  asyncTest((resolve, reject) => {
    const goodText = '1.2.3.4:1080\n5.6.7.8:1080\n';
    const pool = createPool({
      sources: [
        { url: 'http://dead.invalid/list.txt', kind: 'socks5' },
        { url: 'http://ok.invalid/list.txt', kind: 'socks5' },
      ],
      cachePath: tmpCachePath(),
      want: 10,
      concurrency: 4,
      fetchList: (url, cb) => {
        if (url.includes('dead')) return cb(new Error('source is down'));
        cb(null, goodText);
      },
      testCandidate: alwaysPass(),
      getDirectIp: directIpOk,
      warn: () => {}, // silence the expected warning about the dead source
    });

    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 2);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'concurrency is genuinely bounded',
  asyncTest((resolve, reject) => {
    const lines = [];
    for (let i = 0; i < 60; i++) lines.push(`10.0.0.${i}:1080`);

    let inFlight = 0;
    let maxInFlight = 0;
    const testCandidate = (cand, cb) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      setImmediate(() => {
        inFlight--;
        cb(null, { latencyMs: 10, apparentIp: '9.9.9.9' });
      });
    };

    const pool = createPool({
      sources: [{ url: 'http://ok.invalid/list.txt', kind: 'socks5' }],
      cachePath: tmpCachePath(),
      want: 1000, // unreachable -- forces the whole list to be tested
      concurrency: 3,
      fetchList: (url, cb) => cb(null, lines.join('\n')),
      testCandidate,
      getDirectIp: directIpOk,
    });

    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 60);
        assert.ok(maxInFlight <= 3, `max in-flight was ${maxInFlight}, expected <= 3`);
        assert.ok(maxInFlight > 0);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'early exit: stops well before testing all candidates once want is met',
  asyncTest((resolve, reject) => {
    const lines = [];
    for (let i = 0; i < 100; i++) lines.push(`10.1.0.${i}:1080`);

    let testedCount = 0;
    const testCandidate = (cand, cb) => {
      testedCount++;
      setImmediate(() => cb(null, { latencyMs: 10, apparentIp: '9.9.9.9' }));
    };

    const pool = createPool({
      sources: [{ url: 'http://ok.invalid/list.txt', kind: 'socks5' }],
      cachePath: tmpCachePath(),
      want: 2,
      concurrency: 24,
      fetchList: (url, cb) => cb(null, lines.join('\n')),
      testCandidate,
      getDirectIp: directIpOk,
    });

    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 2);
        assert.ok(testedCount < 100, `tested ${testedCount} candidates, expected far fewer than 100`);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'a candidate whose apparent IP equals the direct IP is rejected (transparent proxy)',
  asyncTest((resolve, reject) => {
    const lines = ['20.0.0.1:1080', '20.0.0.2:1080'];
    const testCandidate = (cand, cb) => {
      // The .1 proxy is transparent: apparent IP equals the direct IP.
      if (cand.host === '20.0.0.1') return cb(null, { latencyMs: 10, apparentIp: '1.1.1.1' });
      cb(null, { latencyMs: 10, apparentIp: '9.9.9.9' });
    };

    const pool = createPool({
      sources: [{ url: 'http://ok.invalid/list.txt', kind: 'socks5' }],
      cachePath: tmpCachePath(),
      want: 10,
      concurrency: 4,
      fetchList: (url, cb) => cb(null, lines.join('\n')),
      testCandidate,
      getDirectIp: directIpOk, // '1.1.1.1'
    });

    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 1);
        assert.strictEqual(list[0].host, '20.0.0.2');
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'ranking puts lowest latency first',
  asyncTest((resolve, reject) => {
    const testCandidate = (cand, cb) => {
      if (cand.host === '30.0.0.1') return cb(null, { latencyMs: 200, apparentIp: '9.9.9.1' }); // socks5, slow
      if (cand.host === '30.0.0.2') return cb(null, { latencyMs: 100, apparentIp: '9.9.9.2' }); // socks5, fastest
      return cb(null, { latencyMs: 110, apparentIp: '9.9.9.3' }); // connect
    };

    const pool = createPool({
      sources: [
        { url: 'http://socks.invalid/list.txt', kind: 'socks5' },
        { url: 'http://http.invalid/list.txt', kind: 'connect' },
      ],
      cachePath: tmpCachePath(),
      want: 10,
      concurrency: 4,
      fetchList: (url, cb) => {
        if (url.includes('socks')) return cb(null, '30.0.0.1:1080\n30.0.0.2:1080\n');
        cb(null, '30.0.0.3:3128\n');
      },
      testCandidate,
      getDirectIp: directIpOk,
    });

    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 3);
        // .2 (socks5, 100ms) is fastest outright.
        assert.strictEqual(list[0].host, '30.0.0.2');
        // .3 (connect, 110ms) and .1 (socks5, 200ms) are 90ms apart -- not a
        // near-tie, so pure latency ordering applies: .3 beats .1.
        assert.strictEqual(list[1].host, '30.0.0.3');
        assert.strictEqual(list[2].host, '30.0.0.1');
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'socks5 wins a genuine near-tie against connect',
  asyncTest((resolve, reject) => {
    const lines = { socks: '40.0.0.1:1080\n', http: '40.0.0.2:3128\n' };
    const testCandidate = (cand, cb) => {
      if (cand.host === '40.0.0.1') return cb(null, { latencyMs: 120, apparentIp: '9.9.9.1' }); // socks5
      return cb(null, { latencyMs: 100, apparentIp: '9.9.9.2' }); // connect, faster by 20ms (within tie window)
    };

    const pool = createPool({
      sources: [
        { url: 'http://socks.invalid/list.txt', kind: 'socks5' },
        { url: 'http://http.invalid/list.txt', kind: 'connect' },
      ],
      cachePath: tmpCachePath(),
      want: 10,
      concurrency: 4,
      fetchList: (url, cb) => cb(null, url.includes('socks') ? lines.socks : lines.http),
      testCandidate,
      getDirectIp: directIpOk,
    });

    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 2);
        // Even though connect (40.0.0.2) is 20ms faster, socks5 wins within
        // the 50ms tie window.
        assert.strictEqual(list[0].host, '40.0.0.1');
        assert.strictEqual(list[0].kind, 'socks5');
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test('a corrupt cache file is treated as empty, not thrown', () => {
  const p = tmpCachePath();
  fs.writeFileSync(p, '{ this is not valid json ][');

  let pool;
  assert.doesNotThrow(() => {
    pool = createPool({ cachePath: p, sources: [], testCandidate: alwaysPass(), getDirectIp: directIpOk });
  });

  const snap = pool.snapshot();
  assert.strictEqual(snap.count, 0);
  assert.strictEqual(snap.stale, true);
});

test(
  'demote removes an entry and marks stale below 2 verified proxies',
  asyncTest((resolve, reject) => {
    const lines = ['50.0.0.1:1080', '50.0.0.2:1080'];
    const cachePath = tmpCachePath();
    const pool = createPool({
      sources: [{ url: 'http://ok.invalid/list.txt', kind: 'socks5' }],
      cachePath,
      want: 10,
      concurrency: 4,
      fetchList: (url, cb) => cb(null, lines.join('\n')),
      testCandidate: alwaysPass(),
      getDirectIp: directIpOk,
    });

    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 2);
        const before = pool.snapshot();
        assert.strictEqual(before.stale, false);

        pool.demote(list[0].label);

        const after = pool.snapshot();
        assert.strictEqual(after.count, 1);
        assert.strictEqual(after.stale, true, 'below 2 entries should be marked stale');

        const onDisk = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
        assert.strictEqual(onDisk.proxies.length, 1);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'get() returns the cache when fresh, refreshes when stale/expired',
  asyncTest((resolve, reject) => {
    const lines = ['60.0.0.1:1080', '60.0.0.2:1080'];
    let fetchCalls = 0;
    let fakeNow = 1000;

    const pool = createPool({
      sources: [{ url: 'http://ok.invalid/list.txt', kind: 'socks5' }],
      cachePath: tmpCachePath(),
      want: 10,
      concurrency: 4,
      ttlMs: 1000,
      now: () => fakeNow,
      fetchList: (url, cb) => {
        fetchCalls++;
        cb(null, lines.join('\n'));
      },
      testCandidate: alwaysPass(),
      getDirectIp: directIpOk,
    });

    pool.get((err, list1) => {
      try {
        assert.ifError(err);
        assert.strictEqual(fetchCalls, 1);
        assert.strictEqual(list1.length, 2);
      } catch (e) {
        return reject(e);
      }

      // Still within TTL: get() should not refetch.
      pool.get((err2, list2) => {
        try {
          assert.ifError(err2);
          assert.strictEqual(fetchCalls, 1, 'fresh cache should not trigger a refetch');
          assert.strictEqual(list2.length, 2);
        } catch (e) {
          return reject(e);
        }

        // Advance past the TTL: get() should refresh.
        fakeNow += 5000;
        pool.get((err3, list3) => {
          try {
            assert.ifError(err3);
            assert.strictEqual(fetchCalls, 2, 'expired cache should trigger a refetch');
            assert.strictEqual(list3.length, 2);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
      });
    });
  })
);

test(
  'results are shaped so createEgressAgent accepts them',
  asyncTest((resolve, reject) => {
    const { createEgressAgent } = require('../egress');
    const lines = ['70.0.0.1:1080'];

    const pool = createPool({
      sources: [{ url: 'http://ok.invalid/list.txt', kind: 'socks5' }],
      cachePath: tmpCachePath(),
      want: 1,
      concurrency: 4,
      fetchList: (url, cb) => cb(null, lines.join('\n')),
      testCandidate: alwaysPass(),
      getDirectIp: directIpOk,
    });

    pool.refresh((err, egressList) => {
      try {
        assert.ifError(err);
        assert.strictEqual(egressList.length, 1);
        const agent = createEgressAgent({ egressList });
        assert.ok(agent, 'createEgressAgent should build an agent from the pool result');
        agent.destroy();
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'an unmeasurable direct IP means nothing verifies (fails closed)',
  asyncTest((resolve, reject) => {
    const lines = ['80.0.0.1:1080'];
    const pool = createPool({
      sources: [{ url: 'http://ok.invalid/list.txt', kind: 'socks5' }],
      cachePath: tmpCachePath(),
      want: 10,
      concurrency: 4,
      fetchList: (url, cb) => cb(null, lines.join('\n')),
      testCandidate: alwaysPass(),
      getDirectIp: (url, timeoutMs, cb) => cb(new Error('could not reach echo service')),
      warn: () => {},
    });

    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 0);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

// Live integration test: exercises the real network path (real sources,
// real TLS-verified tunnels, real echo service). Skipped by default so the
// rest of the suite stays network-free; run with CCR_LIVE_POOL=1 to exercise
// it on demand.
test(
  'live: a real refresh against the real sources finds working proxies',
  { skip: !process.env.CCR_LIVE_POOL },
  asyncTest((resolve, reject) => {
    const pool = createPool({ cachePath: tmpCachePath(), want: 3 });
    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.ok(Array.isArray(list));
        console.log('live pool refresh found', list.length, 'verified proxies:', list.map((e) => e.label));
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

// --- country blocklist, enforced on the OBSERVED exit country ---

// A testCandidate whose reported country depends on the candidate's port, so
// a single refresh can mix allowed and blocked exits.
function passWithCountry(byPort) {
  return (cand, cb) =>
    cb(null, { latencyMs: 10, apparentIp: '9.9.9.9', country: byPort[cand.port] || null });
}

test(
  'a proxy whose observed exit country is on the blocklist is rejected',
  asyncTest((resolve, reject) => {
    const pool = createPool({
      cachePath: tmpCachePath(),
      sources: [{ url: 'u', kind: 'socks5' }],
      fetchList: (u, cb) => cb(null, '1.1.1.1:1111\n2.2.2.2:2222\n'),
      testCandidate: passWithCountry({ 1111: 'PT', 2222: 'DE' }),
      getDirectIp: directIpOk,
      excludeCountries: ['pt'],
      want: 5,
      warn: () => {},
    });
    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 1, 'only the non-blocked exit should survive');
        assert.strictEqual(list[0].port, 2222);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'the blocklist is case insensitive',
  asyncTest((resolve, reject) => {
    const pool = createPool({
      cachePath: tmpCachePath(),
      sources: [{ url: 'u', kind: 'socks5' }],
      fetchList: (u, cb) => cb(null, '1.1.1.1:1111\n'),
      testCandidate: passWithCountry({ 1111: 'pt' }),
      getDirectIp: directIpOk,
      excludeCountries: ['PT'],
      warn: () => {},
    });
    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 0);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'an undeterminable country is rejected when a blocklist is in force',
  asyncTest((resolve, reject) => {
    // Accepting "unknown" would make the exclusion silently stop meaning
    // anything the moment the geo endpoint returned plain text.
    const pool = createPool({
      cachePath: tmpCachePath(),
      sources: [{ url: 'u', kind: 'socks5' }],
      fetchList: (u, cb) => cb(null, '1.1.1.1:1111\n'),
      testCandidate: alwaysPass(),
      getDirectIp: directIpOk,
      excludeCountries: ['PT'],
      warn: () => {},
    });
    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 0, 'unknown country must not pass a blocklist');
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);

test(
  'with no blocklist an unknown country is fine',
  asyncTest((resolve, reject) => {
    const pool = createPool({
      cachePath: tmpCachePath(),
      sources: [{ url: 'u', kind: 'socks5' }],
      fetchList: (u, cb) => cb(null, '1.1.1.1:1111\n'),
      testCandidate: alwaysPass(),
      getDirectIp: directIpOk,
      excludeCountries: [],
      warn: () => {},
    });
    pool.refresh((err, list) => {
      try {
        assert.ifError(err);
        assert.strictEqual(list.length, 1, 'country filtering is opt-in');
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  })
);
