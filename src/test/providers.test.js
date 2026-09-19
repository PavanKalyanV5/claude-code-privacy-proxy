'use strict';

// Provider-detection tests. No network: every candidate is a local fake
// server on 127.0.0.1, following the same pattern as proxy/test/egress.test.js
// -- real bytes on real sockets, not mocks, because a hand-rolled protocol
// check is exactly the kind of code where a mock agrees with a misreading of
// the wire format. Sockets and servers created here are tracked and torn
// down at the end so the file exits on its own.

const { test } = require('node:test');
const assert = require('node:assert');
const net = require('net');
const { createProviders, CATALOGUE, DEFAULT_TIMEOUT_MS } = require('../providers');

const SOCKETS = [];
const SERVERS = [];

// A real SOCKS5 server: replies to the very first bytes it receives with a
// valid method-selection reply (VER=5, METHOD=no-auth), same as a real
// SOCKS5 daemon completing its half of RFC 1928 §3. Good enough for
// detection, which never proceeds past the greeting.
function fakeSocks5() {
  const srv = net.createServer((sock) => {
    SOCKETS.push(sock);
    sock.on('error', () => {});
    sock.once('data', () => {
      sock.write(Buffer.from([0x05, 0x00]));
    });
  });
  SERVERS.push(srv);
  return srv;
}

// A plain HTTP server: this is the important "not a proxy" case. It answers
// EVERY request -- including a raw SOCKS5 binary greeting or a CONNECT line
// -- with an ordinary HTTP response, the way nginx/Apache do when CONNECT
// hits a vhost that never implements proxying (400/405), and the way any
// non-SOCKS service responds to two arbitrary bytes it cannot parse. It must
// never be mistaken for either kind of proxy.
function fakeHttpServer({ status = '400 Bad Request' } = {}) {
  const srv = net.createServer((sock) => {
    SOCKETS.push(sock);
    sock.on('error', () => {});
    sock.once('data', () => {
      sock.write(`HTTP/1.1 ${status}\r\nContent-Length: 0\r\n\r\n`);
    });
  });
  SERVERS.push(srv);
  return srv;
}

// A server that answers with bytes that are neither a SOCKS5 reply nor an
// HTTP status line -- the "sends garbage" case.
function fakeGarbageServer() {
  const srv = net.createServer((sock) => {
    SOCKETS.push(sock);
    sock.on('error', () => {});
    sock.once('data', () => {
      sock.write(Buffer.from([0x99, 0x13, 0x37, 0x00, 0x01, 0x02]));
    });
  });
  SERVERS.push(srv);
  return srv;
}

function listen(srv) {
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(srv.address().port)));
}

// A port nothing is listening on. Binding then closing guarantees an
// immediate RST/ECONNREFUSED rather than a hang -- see egress.test.js for the
// same reasoning (a low fixed port number can hang until timeout on Windows).
function closedPort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

function detect(providers) {
  return new Promise((resolve, reject) => {
    providers.detect((err, results) => {
      if (err) return reject(err);
      resolve(results);
    });
  });
}

// ------------------------------------------------------------------ detect

test('a real fake SOCKS5 server is detected', async () => {
  const srv = fakeSocks5();
  const port = await listen(srv);
  const providers = createProviders({ timeoutMs: 300, extra: { sshSocks: { port } } });
  const results = await detect(providers);
  srv.close();

  const hit = results.find((r) => r.source === 'ssh-socks');
  assert.ok(hit, 'ssh-socks candidate should have been detected: ' + JSON.stringify(results));
  assert.strictEqual(hit.egress.host, '127.0.0.1');
  assert.strictEqual(hit.egress.port, port);
  assert.strictEqual(hit.egress.kind, 'socks5');
  assert.ok(hit.label && hit.detail, 'result must be self-describing');
});

test('an HTTP server (not a proxy) on an open port is NOT detected', async () => {
  const srv = fakeHttpServer();
  const port = await listen(srv);
  // Checked as a generic-local candidate, which tries BOTH socks5 and
  // connect probes -- the strictest case, and the one most likely to false
  // positive if either probe were sloppy.
  const providers = createProviders({ timeoutMs: 300, extra: { genericLocal: { ports: [port] }, sshSocks: false, tor: false } });
  const results = await detect(providers);
  srv.close();

  assert.strictEqual(results.length, 0, 'an HTTP server must never be reported as a proxy: ' + JSON.stringify(results));
});

test('a server that sends garbage is NOT detected', async () => {
  const srv = fakeGarbageServer();
  const port = await listen(srv);
  const providers = createProviders({ timeoutMs: 300, extra: { genericLocal: { ports: [port] }, sshSocks: false, tor: false } });
  const results = await detect(providers);
  srv.close();

  assert.strictEqual(results.length, 0, 'garbage bytes must never be reported as a proxy: ' + JSON.stringify(results));
});

test('a closed port is not detected and does not throw', async () => {
  const port = await closedPort();
  const providers = createProviders({ timeoutMs: 300, extra: { sshSocks: { port }, tor: false, genericLocal: false } });
  let results;
  await assert.doesNotReject(async () => {
    results = await detect(providers);
  });
  assert.strictEqual(results.length, 0);
});

test('configured entries always come first, ahead of anything auto-detected', async () => {
  const srv = fakeSocks5();
  const detectedPort = await listen(srv);
  const providers = createProviders({
    timeoutMs: 300,
    extra: {
      configured: { urls: ['socks5://127.0.0.1:19999'] },
      sshSocks: { port: detectedPort },
      tor: false,
      genericLocal: false,
    },
  });
  const results = await detect(providers);
  srv.close();

  assert.ok(results.length >= 2, 'expected both a configured and a detected entry');
  assert.strictEqual(results[0].source, 'configured');
  assert.strictEqual(results[0].egress.port, 19999);
});

test('deduplication by host:port: the highest-priority provider wins', async () => {
  const srv = fakeSocks5();
  const port = await listen(srv);
  // Both ssh-socks and tor are pointed at the exact same endpoint. ssh-socks
  // outranks tor in CATALOGUE order, so only one result should come back,
  // attributed to ssh-socks.
  const providers = createProviders({
    timeoutMs: 300,
    extra: {
      sshSocks: { port },
      tor: { port },
      genericLocal: false,
    },
  });
  const results = await detect(providers);
  srv.close();

  const matches = results.filter((r) => r.egress.host === '127.0.0.1' && r.egress.port === port);
  assert.strictEqual(matches.length, 1, 'the same host:port must not appear twice: ' + JSON.stringify(results));
  assert.strictEqual(matches[0].source, 'ssh-socks', 'the higher-priority provider should win the dedup');
});

test('a configured entry deduplicates against an auto-detected duplicate too', async () => {
  const srv = fakeSocks5();
  const port = await listen(srv);
  const providers = createProviders({
    timeoutMs: 300,
    extra: {
      configured: { urls: [`socks5://127.0.0.1:${port}`] },
      sshSocks: { port },
      tor: false,
      genericLocal: false,
    },
  });
  const results = await detect(providers);
  srv.close();

  const matches = results.filter((r) => r.egress.port === port);
  assert.strictEqual(matches.length, 1);
  assert.strictEqual(matches[0].source, 'configured');
});

test('detection completes within the timeout when nothing is listening', async () => {
  const gone1 = await closedPort();
  const gone2 = await closedPort();
  const timeoutMs = 200;
  const providers = createProviders({
    timeoutMs,
    extra: {
      sshSocks: { port: gone1 },
      tor: { ports: [gone2] },
      // generic-local tries two probe kinds per candidate, concurrently, so
      // it must not add extra wall-clock time.
      genericLocal: { ports: [gone1, gone2] },
    },
  });

  const start = Date.now();
  const results = await detect(providers);
  const elapsed = Date.now() - start;

  assert.strictEqual(results.length, 0);
  // Generous multiple of the probe timeout to absorb CI/OS scheduling
  // jitter while still proving detection did not silently fall back to a
  // long or unbounded wait (e.g. the 15s production egress timeout).
  assert.ok(elapsed < timeoutMs * 6, `detection took ${elapsed}ms, expected well under ${timeoutMs * 6}ms`);
});

test('describeAll() lists every provider, including ones never detected', () => {
  const providers = createProviders({});
  const all = providers.describeAll();
  const ids = all.map((p) => p.id);

  assert.deepStrictEqual(ids, ['configured', 'ssh-socks', 'cloudflare-warp', 'tor', 'generic-local']);
  for (const p of all) {
    assert.ok(p.label, `${p.id} is missing a label`);
    assert.ok(p.description, `${p.id} is missing a description`);
  }
  // Matches the module's own static catalogue -- describeAll() must not be a
  // second, divergent copy of it.
  assert.deepStrictEqual(ids, CATALOGUE.map((c) => c.id));
});

test('cloudflare-warp is never guessed at: no port configured means no detection attempt', async () => {
  // Even with a real fake SOCKS5 server up, cloudflare-warp must not find it
  // unless a port was explicitly configured -- there is no default to guess.
  const srv = fakeSocks5();
  const port = await listen(srv);
  const providers = createProviders({
    timeoutMs: 300,
    extra: { sshSocks: false, tor: false, genericLocal: false /* cloudflareWarp deliberately omitted */ },
  });
  const results = await detect(providers);
  srv.close();
  assert.strictEqual(results.filter((r) => r.source === 'cloudflare-warp').length, 0);
});

test('cloudflare-warp does detect once a port is explicitly configured', async () => {
  const srv = fakeSocks5();
  const port = await listen(srv);
  const providers = createProviders({
    timeoutMs: 300,
    extra: { sshSocks: false, tor: false, genericLocal: false, cloudflareWarp: { port } },
  });
  const results = await detect(providers);
  srv.close();
  const hit = results.find((r) => r.source === 'cloudflare-warp');
  assert.ok(hit, 'cloudflare-warp should detect once explicitly pointed at a real SOCKS5 endpoint');
});

test('generic-local also picks up a real HTTP CONNECT proxy', async () => {
  const srv = net.createServer((sock) => {
    SOCKETS.push(sock);
    sock.on('error', () => {});
    sock.once('data', () => {
      sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    });
  });
  SERVERS.push(srv);
  const port = await listen(srv);
  const providers = createProviders({
    timeoutMs: 300,
    extra: { sshSocks: false, tor: false, genericLocal: { ports: [port] } },
  });
  const results = await detect(providers);
  srv.close();

  const hit = results.find((r) => r.source === 'generic-local');
  assert.ok(hit, 'a real CONNECT-accepting proxy should be detected: ' + JSON.stringify(results));
  assert.strictEqual(hit.egress.kind, 'connect');
});

test('default construction with no extra config does not throw and stays fast', async () => {
  // Uses this module's own defaults (ssh-socks 1080, tor 9050/9150, a handful
  // of generic-local ports). None of those should be listening in CI, so this
  // exercises the "nothing found, nothing throws, nothing hangs" path with
  // zero configuration -- the shape callers get if they wire this in as-is.
  const providers = createProviders({ timeoutMs: 250 });
  const start = Date.now();
  const results = await detect(providers);
  const elapsed = Date.now() - start;
  assert.ok(Array.isArray(results));
  assert.ok(elapsed < 250 * 6, `took ${elapsed}ms with defaults, expected well under ${250 * 6}ms`);
});

// -------------------------------------------------------------- teardown

test('teardown: no lingering sockets or servers keep the process alive', () => {
  for (const s of SOCKETS) s.destroy();
  for (const srv of SERVERS) {
    try {
      srv.close();
    } catch (e) {
      /* already closed */
    }
  }
  assert.ok(true);
});
