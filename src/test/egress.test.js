'use strict';

// Egress tunnel tests. The handshakes are exercised against real local fake
// proxies rather than mocks: a hand-rolled SOCKS5/CONNECT implementation is
// exactly the kind of code where a mock agrees with your misreading of the
// protocol. The fakes speak bytes.

const { test } = require('node:test');
const assert = require('node:assert');
const net = require('net');
const {
  parseEgress,
  parseEgressList,
  createEgressAgent,
  createHealth,
  socksError,
} = require('../egress');

// ------------------------------------------------------------ config parsing

test('parseEgress accepts a bare host:port and assumes socks5', () => {
  const e = parseEgress('198.51.100.7:1080');
  assert.strictEqual(e.kind, 'socks5');
  assert.strictEqual(e.host, '198.51.100.7');
  assert.strictEqual(e.port, 1080);
});

test('parseEgress reads scheme, credentials and port', () => {
  const e = parseEgress('http://bob:s3cret@proxy.example:3128');
  assert.strictEqual(e.kind, 'connect');
  assert.strictEqual(e.host, 'proxy.example');
  assert.strictEqual(e.port, 3128);
  assert.strictEqual(e.username, 'bob');
  assert.strictEqual(e.password, 's3cret');
});

test('parseEgress url-decodes credentials', () => {
  const e = parseEgress('socks5://a%40b:p%3Aw@h:1080');
  assert.strictEqual(e.username, 'a@b');
  assert.strictEqual(e.password, 'p:w');
});

test('parseEgress label never contains the password', () => {
  const e = parseEgress('http://bob:s3cret@proxy.example:3128');
  assert.ok(!e.label.includes('s3cret'), e.label);
  assert.ok(!e.label.includes('bob'), e.label);
});

test('parseEgress defaults ports per scheme', () => {
  assert.strictEqual(parseEgress('socks5://h').port, 1080);
  assert.strictEqual(parseEgress('http://h').port, 3128);
});

test('parseEgress treats socks5h as socks5 (remote DNS is already our behaviour)', () => {
  assert.strictEqual(parseEgress('socks5h://h:1080').kind, 'socks5');
});

test('parseEgress rejects unsupported schemes rather than guessing', () => {
  assert.throws(() => parseEgress('ftp://h:21'), /not supported/);
});

test('parseEgress rejects a bad port', () => {
  assert.throws(() => parseEgress('socks5://h:99999'), /invalid port|not a valid URL/);
});

test('mode off yields no proxies even when urls are present', () => {
  assert.deepStrictEqual(parseEgressList({ mode: 'off', urls: ['socks5://h:1080'] }), []);
});

test('parseEgressList preserves order across urls and url', () => {
  const l = parseEgressList({ urls: ['socks5://a:1080', 'socks5://b:1080'], url: 'http://c:3128' });
  assert.deepStrictEqual(l.map((e) => e.host), ['a', 'b', 'c']);
});

test('no egress config means no agent, not a broken agent', () => {
  assert.strictEqual(createEgressAgent({ egressList: [] }), null);
  assert.strictEqual(createEgressAgent({ egress: null }), null);
});

// ------------------------------------------------------------------- health

test('health starts unknown, not healthy', () => {
  const h = createHealth({ egressList: [parseEgress('socks5://h:1080')] });
  assert.strictEqual(h.state.ok, null, 'unexercised must not read as ok');
  assert.strictEqual(h.state.masking, null);
  assert.deepStrictEqual(h.state.configured, ['socks5://h:1080']);
});

test('masking is only true once both addresses are known and differ', () => {
  const h = createHealth({ egressList: [] });
  h.setApparentIp('203.0.113.9');
  assert.strictEqual(h.state.masking, null, 'one address alone proves nothing');
  h.setDirectIp('198.51.100.4');
  assert.strictEqual(h.state.masking, true);
});

test('a transparent proxy reports masking false', () => {
  const h = createHealth({ egressList: [] });
  h.setDirectIp('198.51.100.4');
  h.setApparentIp('198.51.100.4');
  assert.strictEqual(h.state.masking, false, 'same address means the real IP is being forwarded');
});

test('a failure clears the active proxy so nothing reads as live', () => {
  const h = createHealth({ egressList: [] });
  h.note({ ok: true, active: 'socks5://a:1080' });
  assert.strictEqual(h.state.active, 'socks5://a:1080');
  h.note({ ok: false, error: 'refused' });
  assert.strictEqual(h.state.active, null);
  assert.strictEqual(h.state.lastError, 'refused');
  assert.strictEqual(h.state.failures, 1);
});

test('socksError names known reply codes and survives unknown ones', () => {
  assert.match(socksError(0x05), /refused/);
  assert.match(socksError(0x42), /unknown reply code/);
});

// -------------------------------------------------------------- fake proxies

// Minimal SOCKS5 server. `onConnect` decides what happens after the handshake;
// by default it refuses, because these tests care about the handshake, not
// about carrying real TLS.
// Everything that can hold the event loop open. A successful tunnel leaves a
// live TLS socket and a keepAlive agent behind; without teardown the test FILE
// passes every assertion and then never exits.
const SOCKETS = [];
const AGENTS = [];

function fakeSocks5({ requireAuth = false, authOk = true, replyCode = 0x00, onRequest = null } = {}) {
  const seen = { greeting: null, auth: null, request: null };
  const srv = net.createServer((sock) => {
    SOCKETS.push(sock);
    let stage = 'greeting';
    sock.on('data', (buf) => {
      if (stage === 'greeting') {
        seen.greeting = Buffer.from(buf);
        const methods = [...buf.slice(2, 2 + buf[1])];
        if (requireAuth) {
          if (!methods.includes(0x02)) return sock.end(Buffer.from([0x05, 0xff]));
          stage = 'auth';
          return sock.write(Buffer.from([0x05, 0x02]));
        }
        stage = 'request';
        return sock.write(Buffer.from([0x05, 0x00]));
      }
      if (stage === 'auth') {
        seen.auth = Buffer.from(buf);
        stage = 'request';
        return sock.write(Buffer.from([0x01, authOk ? 0x00 : 0x01]));
      }
      if (stage === 'request') {
        seen.request = Buffer.from(buf);
        // Stop recording: on a success reply the client immediately sends a
        // TLS ClientHello, which would otherwise overwrite the handshake bytes
        // these tests exist to inspect.
        stage = 'tunnelled';
        if (onRequest) return onRequest(sock, buf);
        // VER REP RSV ATYP=1 + 4 addr + 2 port
        return sock.write(Buffer.from([0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      }
    });
    sock.on('error', () => {});
  });
  return { srv, seen };
}

function listen(srv) {
  return new Promise((res) => srv.listen(0, '127.0.0.1', () => res(srv.address().port)));
}

// A port nothing is listening on. Binding then closing guarantees an immediate
// RST; picking a low port number like 1 can instead hang until timeout on
// Windows, which turns a fast failure test into a stalled suite.
function closedPort() {
  return new Promise((res) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

// Short timeouts everywhere: these tests assert on handshake behaviour, and
// the 15s production default would make the suite unusable.
function proxy(url) {
  return parseEgress({ url, timeoutMs: 1500 });
}
function proxies(urls) {
  return urls.map(proxy);
}

// Drives just the handshake by asking the agent for a connection. We expect an
// error in most cases because the fake never speaks TLS; what we assert on is
// the bytes the fake received, and WHICH error came back.
function attempt(agent, host = 'api.anthropic.com', port = 443) {
  AGENTS.push(agent);
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(v);
      }
    };
    try {
      agent.createConnection({ host, port }, (err, sock) => {
        if (sock) sock.destroy();
        done({ err });
      });
    } catch (e) {
      done({ err: e });
    }
    const timer = setTimeout(() => done({ err: new Error('test timeout') }), 4000);
    if (timer.unref) timer.unref();
  });
}

test('SOCKS5: sends the destination as a HOSTNAME so DNS resolves at the proxy', async () => {
  const { srv, seen } = fakeSocks5();
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`socks5://127.0.0.1:${port}`)] });
  await attempt(agent, 'api.anthropic.com', 443);
  srv.close();

  assert.ok(seen.request, 'proxy received no CONNECT request');
  assert.strictEqual(seen.request[0], 0x05);
  assert.strictEqual(seen.request[1], 0x01, 'command must be CONNECT');
  assert.strictEqual(seen.request[3], 0x03, 'ATYP must be 3 (domain name), not a pre-resolved address');
  const len = seen.request[4];
  assert.strictEqual(seen.request.slice(5, 5 + len).toString(), 'api.anthropic.com');
  const p = seen.request.readUInt16BE(5 + len);
  assert.strictEqual(p, 443);
});

test('SOCKS5: offers no-auth only when no credentials are configured', async () => {
  const { srv, seen } = fakeSocks5();
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`socks5://127.0.0.1:${port}`)] });
  await attempt(agent);
  srv.close();
  const methods = [...seen.greeting.slice(2)];
  assert.deepStrictEqual(methods, [0x00], 'cleartext password auth must not be offered unsolicited');
});

test('SOCKS5: sends RFC1929 credentials when the proxy demands auth', async () => {
  const { srv, seen } = fakeSocks5({ requireAuth: true });
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`socks5://bob:s3cret@127.0.0.1:${port}`)] });
  await attempt(agent);
  srv.close();

  assert.ok(seen.auth, 'no auth message sent');
  assert.strictEqual(seen.auth[0], 0x01, 'RFC1929 version');
  const ulen = seen.auth[1];
  assert.strictEqual(seen.auth.slice(2, 2 + ulen).toString(), 'bob');
  const plen = seen.auth[2 + ulen];
  assert.strictEqual(seen.auth.slice(3 + ulen, 3 + ulen + plen).toString(), 's3cret');
});

test('SOCKS5: a proxy demanding auth with no credentials fails, it does not hang', async () => {
  const { srv } = fakeSocks5({ requireAuth: true });
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`socks5://127.0.0.1:${port}`)] });
  const { err } = await attempt(agent);
  srv.close();
  assert.ok(err, 'must surface an error');
  assert.ok(!/test timeout/.test(err.message), 'hung instead of failing: ' + err.message);
});

test('SOCKS5: rejected credentials produce a clear error', async () => {
  const { srv } = fakeSocks5({ requireAuth: true, authOk: false });
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`socks5://bob:x@127.0.0.1:${port}`)] });
  const { err } = await attempt(agent);
  srv.close();
  assert.match(err.message, /rejected the credentials/);
});

test('SOCKS5: a refusal reply is reported with its meaning', async () => {
  const { srv } = fakeSocks5({ replyCode: 0x05 });
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`socks5://127.0.0.1:${port}`)] });
  const { err } = await attempt(agent);
  srv.close();
  assert.match(err.message, /refused the connection: connection refused/);
});

test('SOCKS5: a non-SOCKS server on the port is rejected, not misparsed', async () => {
  const srv = net.createServer((s) => s.write('HTTP/1.1 200 OK\r\n\r\n'));
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`socks5://127.0.0.1:${port}`)] });
  const { err } = await attempt(agent);
  srv.close();
  assert.match(err.message, /replied with version/);
});

// -------------------------------------------------------------- HTTP CONNECT

function fakeConnect({ status = '200 Connection Established', extra = '' } = {}) {
  const seen = { head: null };
  const srv = net.createServer((sock) => {
    SOCKETS.push(sock);
    sock.on('data', (buf) => {
      // First message only: after a 200 the client sends a TLS ClientHello.
      if (seen.head !== null) return;
      seen.head = buf.toString();
      sock.write(`HTTP/1.1 ${status}\r\n\r\n${extra}`);
    });
    sock.on('error', () => {});
  });
  return { srv, seen };
}

test('CONNECT: requests the destination by hostname and sets Host', async () => {
  const { srv, seen } = fakeConnect();
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`http://127.0.0.1:${port}`)] });
  await attempt(agent, 'api.anthropic.com', 443);
  srv.close();
  assert.match(seen.head, /^CONNECT api\.anthropic\.com:443 HTTP\/1\.1\r\n/);
  assert.match(seen.head, /Host: api\.anthropic\.com:443/);
});

test('CONNECT: sends Proxy-Authorization only when credentials exist', async () => {
  const bare = fakeConnect();
  const p1 = await listen(bare.srv);
  await attempt(createEgressAgent({ egressList: [proxy(`http://127.0.0.1:${p1}`)] }));
  bare.srv.close();
  assert.ok(!/Proxy-Authorization/i.test(bare.seen.head), 'unexpected credentials header');

  const authed = fakeConnect();
  const p2 = await listen(authed.srv);
  await attempt(createEgressAgent({ egressList: [proxy(`http://bob:s3cret@127.0.0.1:${p2}`)] }));
  authed.srv.close();
  const m = /Proxy-Authorization: Basic (\S+)/.exec(authed.seen.head);
  assert.ok(m, 'missing credentials header');
  assert.strictEqual(Buffer.from(m[1], 'base64').toString(), 'bob:s3cret');
});

test('CONNECT: a non-200 status is an error, never treated as a tunnel', async () => {
  const { srv } = fakeConnect({ status: '407 Proxy Authentication Required' });
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`http://127.0.0.1:${port}`)] });
  const { err } = await attempt(agent);
  srv.close();
  assert.match(err.message, /refused CONNECT with status 407/);
});

test('CONNECT: a malformed response is rejected', async () => {
  const srv = net.createServer((s) => s.on('data', () => s.write('garbage\r\n\r\n')));
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`http://127.0.0.1:${port}`)] });
  const { err } = await attempt(agent);
  srv.close();
  assert.match(err.message, /malformed CONNECT response/);
});

// ------------------------------------------------------------------ failover

test('failover: a dead first proxy is skipped and the second is used', async () => {
  const gone = await closedPort();
  const { srv, seen } = fakeSocks5();
  const live = await listen(srv);

  const warnings = [];
  const agent = createEgressAgent({
    egressList: proxies([`socks5://127.0.0.1:${gone}`, `socks5://127.0.0.1:${live}`]),
    warn: (m) => warnings.push(m),
  });
  await attempt(agent);
  srv.close();

  assert.ok(seen.request, 'the second proxy was never tried');
  assert.ok(
    warnings.some((w) => /trying the next one/.test(w)),
    'failover should say it moved on: ' + JSON.stringify(warnings)
  );
});

test('failover: when every proxy fails the error says nothing went direct', async () => {
  const a = await closedPort();
  const b = await closedPort();
  const warnings = [];
  const agent = createEgressAgent({
    egressList: proxies([`socks5://127.0.0.1:${a}`, `http://127.0.0.1:${b}`]),
    warn: (m) => warnings.push(m),
  });
  const { err } = await attempt(agent);
  assert.match(err.message, /no egress proxy available/);
  const joined = warnings.join(' | ');
  assert.match(joined, /REFUSED/);
  assert.match(joined, /nothing sent direct/);
});

test('failover records the failure in health, leaving nothing marked active', async () => {
  const gone = await closedPort();
  const list = proxies([`socks5://127.0.0.1:${gone}`]);
  const health = createHealth({ egressList: list });
  const agent = createEgressAgent({ egressList: list, health, warn: () => {} });
  await attempt(agent);
  assert.strictEqual(health.state.ok, false);
  assert.strictEqual(health.state.active, null);
  assert.ok(health.state.failures >= 1);
});

// Runs last: destroys every socket and keepAlive agent the handshake tests
// created. Without this the file passes and then hangs, which reads as a
// suite-wide timeout rather than the resource leak it actually is.
// ------------------------------------------- the configurable escape hatch

test('default is fail closed: allowDirect must be opted into', async () => {
  const gone = await closedPort();
  const agent = createEgressAgent({ egressList: proxies([`socks5://127.0.0.1:${gone}`]), warn: () => {} });
  const { err } = await attempt(agent);
  assert.ok(err, 'must refuse by default');
  assert.match(err.message, /no egress proxy available/);
});

test('allowDirect never fails silently: it warns that the real IP was used', async () => {
  const gone = await closedPort();
  const warnings = [];
  const agent = createEgressAgent({
    egressList: proxies([`socks5://127.0.0.1:${gone}`]),
    warn: (m) => warnings.push(m),
    allowDirect: true,
  });
  // Point at a closed local port so no real connection is made; we only care
  // that the fallback was taken and announced, not that it completed.
  const dest = await closedPort();
  await attempt(agent, '127.0.0.1', dest);
  const joined = warnings.join(' | ');
  assert.match(joined, /DIRECT CONNECTION/);
  assert.match(joined, /REAL IP/);
  assert.match(joined, /onFailure/, 'the warning must name the setting that caused it');
});

test('a direct fallback is recorded stickily and forces masking false', async () => {
  const gone = await closedPort();
  const list = proxies([`socks5://127.0.0.1:${gone}`]);
  const health = createHealth({ egressList: list });
  health.setDirectIp('198.51.100.4');
  health.setApparentIp('203.0.113.9');
  assert.strictEqual(health.state.masking, true, 'starts masked');

  const agent = createEgressAgent({ egressList: list, health, warn: () => {}, allowDirect: true });
  const dest = await closedPort();
  await attempt(agent, '127.0.0.1', dest);

  assert.strictEqual(health.state.fellBackDirect, 1);
  assert.strictEqual(health.state.masking, false, 'one unmasked request must flip the verdict');
  assert.ok(health.state.lastDirectAt);

  // And a later success must NOT erase the record.
  health.note({ ok: true, active: 'socks5://x:1080' });
  assert.strictEqual(health.state.fellBackDirect, 1, 'the count is sticky for the session');
});

// --------------------------- the unshift recursion that exhausted memory

// A proxy that pipelines bytes immediately after its handshake reply crashed
// the process with ERR_MEMORY_ALLOCATION_FAILED: unshift re-delivers
// synchronously to an attached 'data' listener, so pushing the leftovers back
// while still listening fed them into the same handler, which concatenated
// and unshifted them again without bound. Found by an end-to-end run against
// real proxies, after every unit test had passed -- none of them sent trailing
// data.

test('SOCKS5: trailing data after the reply does not recurse', async () => {
  const trailing = Buffer.alloc(4096, 0x41);
  const srv = net.createServer((sock) => {
    SOCKETS.push(sock);
    let stage = 0;
    sock.on('error', () => {});
    sock.on('data', () => {
      if (stage === 0) {
        stage = 1;
        sock.write(Buffer.from([0x05, 0x00]));
      } else if (stage === 1) {
        stage = 2;
        // Reply AND payload in one write, as a busy proxy does.
        sock.write(Buffer.concat([Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), trailing]));
        sock.end(); // EOF so TLS errors promptly instead of awaiting a record
      }
    });
  });
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`socks5://127.0.0.1:${port}`)], warn: () => {} });
  const { err } = await attempt(agent);
  srv.close();
  // TLS will not complete against a fake, so an error is expected. What must
  // NOT happen is a hang or an allocation failure.
  assert.ok(err, 'expected a TLS-level error, not a crash');
  assert.ok(!/test timeout/.test(err.message), 'recursed or hung: ' + err.message);
  assert.ok(!/allocat/i.test(err.message), 'memory allocation failure: ' + err.message);
});

test('CONNECT: trailing data after the 200 does not recurse', async () => {
  const srv = net.createServer((sock) => {
    SOCKETS.push(sock);
    sock.on('error', () => {});
    sock.on('data', () => {
      // This is the exact shape that crashed: response headers plus payload.
      sock.write('HTTP/1.1 200 Connection Established\r\n\r\n' + 'B'.repeat(4096));
      sock.end(); // EOF so TLS errors promptly instead of awaiting a record
    });
  });
  const port = await listen(srv);
  const agent = createEgressAgent({ egressList: [proxy(`http://127.0.0.1:${port}`)], warn: () => {} });
  const { err } = await attempt(agent);
  srv.close();
  assert.ok(err, 'expected a TLS-level error, not a crash');
  assert.ok(!/test timeout/.test(err.message), 'recursed or hung: ' + err.message);
  assert.ok(!/allocat/i.test(err.message), 'memory allocation failure: ' + err.message);
});

test('probe purpose does not claim a request was refused', async () => {
  // A live run printed 38 lines saying "request REFUSED" while probing pool
  // candidates, none of which were requests. Those warnings feed the status
  // line, so the wording is not cosmetic.
  const gone = await closedPort();
  const warnings = [];
  const agent = createEgressAgent({
    egressList: proxies([`socks5://127.0.0.1:${gone}`]),
    warn: (m) => warnings.push(m),
    purpose: 'probe',
  });
  await attempt(agent);
  const joined = warnings.join(' | ');
  assert.match(joined, /probe failed/);
  // Matching bare /REFUSED/ would be wrong: the OS error text legitimately
  // contains ECONNREFUSED. What must not appear is the CLAIM that a request
  // was refused, or the reassurance about not sending direct -- neither of
  // which applies to a probe.
  assert.ok(!/request REFUSED/.test(joined), 'a probe must not claim a request was refused: ' + joined);
  assert.ok(!/nothing sent direct/.test(joined), 'a probe has no request to have sent: ' + joined);
});

test('request purpose still reports refusals loudly', async () => {
  const gone = await closedPort();
  const warnings = [];
  const agent = createEgressAgent({
    egressList: proxies([`socks5://127.0.0.1:${gone}`]),
    warn: (m) => warnings.push(m),
  });
  await attempt(agent);
  assert.match(warnings.join(' | '), /REFUSED/);
});

// ------------------------------- the real address is compared, not retained

// These guard a property that is invisible when it breaks: the health record
// is written to status.json, returned by /_health, and pasted into reports.
// Whenever the VPN is off, the direct address IS the user's real IP, so it
// must be comparable without being kept.
const REAL = '203.0.113.77';

test('the direct address is never retained anywhere in health state', () => {
  const h = createHealth({ egressList: [] });
  h.setDirectIp(REAL, 'PT');
  h.setApparentIp('198.51.100.9', 'DE');
  const blob = JSON.stringify(h.snapshot());
  assert.ok(!blob.includes(REAL), 'the real address leaked into health state: ' + blob);
  assert.ok(h.state.directIpDigest, 'but it must still be comparable');
  assert.strictEqual(h.state.masking, true);
  assert.strictEqual(h.state.directCountry, 'PT', 'country is fine to keep');
});

test('when masking FAILS the apparent address is not retained either', () => {
  // This is the dangerous case: a transparent proxy reports back the user's
  // own address, so "apparent" and "real" are the same value.
  const h = createHealth({ egressList: [] });
  h.setDirectIp(REAL, 'PT');
  h.setApparentIp(REAL, 'PT');
  assert.strictEqual(h.state.masking, false);
  const blob = JSON.stringify(h.snapshot());
  assert.ok(!blob.includes(REAL), 'the real address leaked when masking failed: ' + blob);
  assert.strictEqual(h.state.exitIp, null, 'there is no proxy exit to report');
});

test('a confirmed proxy exit IS reported, since it is not the user address', () => {
  const h = createHealth({ egressList: [] });
  h.setDirectIp(REAL, 'PT');
  h.setApparentIp('198.51.100.9', 'DE');
  assert.strictEqual(h.state.exitIp, '198.51.100.9');
});

test('a previously reported exit is cleared if masking later fails', () => {
  const h = createHealth({ egressList: [] });
  h.setDirectIp(REAL, 'PT');
  h.setApparentIp('198.51.100.9', 'DE');
  assert.strictEqual(h.state.exitIp, '198.51.100.9');
  // The proxy starts forwarding the real address, or the tunnel drops.
  h.setApparentIp(REAL, 'PT');
  assert.strictEqual(h.state.masking, false);
  assert.strictEqual(h.state.exitIp, null, 'a stale exit must not keep implying masking');
});

test('digests differ for different addresses and match for equal ones', () => {
  const a = createHealth({ egressList: [] });
  a.setDirectIp('1.2.3.4');
  a.setApparentIp('1.2.3.4');
  assert.strictEqual(a.state.masking, false, 'equal addresses must compare equal');

  const b = createHealth({ egressList: [] });
  b.setDirectIp('1.2.3.4');
  b.setApparentIp('1.2.3.5');
  assert.strictEqual(b.state.masking, true, 'a one-digit difference must compare unequal');
});

// --------------- masking means "the path in use", not "the tunnel"

test('not tunnelling but externally masked does not read as unmasked', () => {
  // The false alarm this prevents: auto mode correctly stands down because a
  // VPN is already masking, the agent therefore connects directly, the
  // masking probe sees apparent == direct, and a naive reading reports "the
  // proxy is forwarding your real IP". That contradicted the decision logged
  // one tick earlier and would now raise a critical desktop notification on
  // a perfectly healthy configuration.
  const h = createHealth({ egressList: [] });
  h.setTunnelDecision(false, 'already masked, no tunnel needed');
  h.setExternallyMasked(true, 'US');
  const s = h.snapshot();
  assert.strictEqual(s.tunnelling, false);
  assert.strictEqual(s.externallyMasked, true);
  assert.strictEqual(s.masking, true, 'masked by other means still counts as masked');
  assert.strictEqual(s.directCountry, 'US');
});

test('not tunnelling and NOT externally masked reads as unmasked', () => {
  // The genuinely bad case, which must stay loud: nothing is tunnelling and
  // nothing else is masking either.
  const h = createHealth({ egressList: [] });
  h.setTunnelDecision(false, 'toggled off at runtime');
  h.setExternallyMasked(false, 'IN');
  const s = h.snapshot();
  assert.strictEqual(s.masking, false);
  assert.strictEqual(s.externallyMasked, false);
});

test('teardown: no lingering sockets or agents keep the process alive', () => {
  for (const s of SOCKETS) s.destroy();
  for (const a of AGENTS) a.destroy();
  assert.ok(true);
});
