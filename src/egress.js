'use strict';

// Optional egress tunnel: route the upstream API connection through a SOCKS5
// or HTTP CONNECT proxy so the API sees the proxy's IP instead of this
// machine's.
//
// Three properties this module must never give up:
//
// 1. FAIL CLOSED. If the tunnel cannot be established, the request is refused.
//    Falling back to a direct connection would leak the very IP the tunnel
//    exists to hide, and would do it silently -- the session would keep
//    working, so nothing would ever prompt a second look.
//
// 2. TLS VERIFICATION STAYS ON. The tunnel carries a real TLS session to the
//    upstream host, negotiated end-to-end after the handshake. The proxy
//    operator sees the destination, timing and byte volume; they cannot read
//    the body. That property is exactly what certificate verification buys,
//    so nothing here sets rejectUnauthorized or passes a custom checkServerIdentity.
//
// 3. DNS RESOLVES AT THE PROXY. SOCKS5 requests are sent with ATYP=3 (domain
//    name) rather than a pre-resolved address, and CONNECT sends the hostname.
//    Resolving locally would send the destination to the local resolver --
//    usually the ISP -- which reveals who you are talking to even though the
//    connection itself is tunnelled.

const net = require('net');
const tls = require('tls');
const https = require('https');
const crypto = require('crypto');

// How long an auto-mode country observation stays trustworthy.
const DECISION_TTL_MS = 120 * 1000;

const SUPPORTED = ['socks5', 'socks5h', 'http', 'https'];

// Accepts a single `url` or a list of `urls`, tried in order. A list is the
// practical shape for free proxies: they disappear without warning, and
// because egress is fail-closed, one dead entry would otherwise take the whole
// session down. Failover keeps "always tunnelled" usable without ever
// weakening it into "tunnelled when convenient".
//
// Returns [] when egress is off.
function parseEgressList(cfg) {
  if (!cfg) return [];
  if (typeof cfg === 'string') return [parseEgress(cfg)];
  if (Array.isArray(cfg)) return cfg.map((c) => parseEgress(c)).filter(Boolean);
  if (cfg.mode === 'off') return [];

  const raws = [].concat(cfg.urls || [], cfg.url ? [cfg.url] : []);
  if (raws.length === 0) return [];
  return raws.map((u) => parseEgress(Object.assign({}, cfg, { url: u, urls: undefined })));
}

// Accepts `socks5://host:1080`, `http://user:pass@host:3128`, or a bare
// `host:port` (assumed socks5). Returns null when egress is off.
function parseEgress(cfg) {
  if (!cfg) return null;
  const raw = typeof cfg === 'string' ? cfg : cfg.url;
  const mode = typeof cfg === 'string' ? 'proxy' : cfg.mode || (raw ? 'proxy' : 'off');
  if (mode === 'off' || !raw) return null;

  const withScheme = /:\/\//.test(raw) ? raw : `socks5://${raw}`;
  let u;
  try {
    u = new URL(withScheme);
  } catch (e) {
    throw new Error(`egress.url is not a valid URL: ${raw}`);
  }

  const protocol = u.protocol.replace(':', '').toLowerCase();
  if (!SUPPORTED.includes(protocol)) {
    throw new Error(`egress protocol "${protocol}" is not supported (use ${SUPPORTED.join(', ')})`);
  }
  if (!u.hostname) throw new Error(`egress.url has no host: ${raw}`);

  const port = u.port ? Number(u.port) : protocol.startsWith('socks') ? 1080 : 3128;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`egress.url has an invalid port: ${raw}`);
  }

  return {
    kind: protocol.startsWith('socks') ? 'socks5' : 'connect',
    host: u.hostname,
    port,
    username: u.username ? decodeURIComponent(u.username) : '',
    password: u.password ? decodeURIComponent(u.password) : '',
    // Kept for logging: never log credentials.
    label: `${protocol}://${u.hostname}:${port}`,
    timeoutMs: (typeof cfg === 'object' && cfg.timeoutMs) || 15000,
  };
}

// ---------------------------------------------------------------- SOCKS5

function socks5Connect(egress, destHost, destPort, cb) {
  const sock = net.connect({ host: egress.host, port: egress.port });
  let stage = 'greeting';
  let buf = Buffer.alloc(0);
  let done = false;

  // Removes every handler this function installed. Called before handing the
  // socket on, so neither an unshift nor the socket's eventual close can
  // re-enter handshake logic that has already completed.
  const detach = () => {
    sock.removeAllListeners('data');
    sock.removeAllListeners('close');
    sock.removeAllListeners('connect');
  };

  const finish = (err, out) => {
    if (done) return;
    done = true;
    detach();
    clearTimeout(timer);
    if (err) {
      sock.destroy();
      cb(err);
    } else {
      cb(null, out);
    }
  };

  const timer = setTimeout(
    () => finish(new Error(`SOCKS5 handshake to ${egress.label} timed out after ${egress.timeoutMs}ms`)),
    egress.timeoutMs
  );

  sock.on('error', (e) => finish(new Error(`SOCKS5 proxy ${egress.label}: ${e.message}`)));
  sock.on('close', () => finish(new Error(`SOCKS5 proxy ${egress.label} closed the connection mid-handshake`)));

  sock.on('connect', () => {
    // Offer no-auth and, only if credentials exist, username/password. RFC 1929
    // sends those in cleartext to the proxy, so they are offered only when the
    // user has actually configured them.
    const methods = egress.username ? [0x00, 0x02] : [0x00];
    sock.write(Buffer.from([0x05, methods.length, ...methods]));
  });

  sock.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);

    if (stage === 'greeting') {
      if (buf.length < 2) return;
      if (buf[0] !== 0x05) return finish(new Error(`SOCKS5 proxy ${egress.label} replied with version ${buf[0]}, expected 5`));
      const method = buf[1];
      buf = buf.slice(2);

      if (method === 0x00) {
        stage = 'request';
        sendRequest();
      } else if (method === 0x02) {
        if (!egress.username) {
          return finish(new Error(`SOCKS5 proxy ${egress.label} demands a username/password but none is configured`));
        }
        stage = 'auth';
        const u = Buffer.from(egress.username, 'utf8');
        const p = Buffer.from(egress.password, 'utf8');
        if (u.length > 255 || p.length > 255) {
          return finish(new Error('SOCKS5 username/password must each be at most 255 bytes'));
        }
        sock.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
      } else if (method === 0xff) {
        return finish(new Error(`SOCKS5 proxy ${egress.label} rejected every offered authentication method`));
      } else {
        return finish(new Error(`SOCKS5 proxy ${egress.label} chose unsupported auth method 0x${method.toString(16)}`));
      }
      if (buf.length) sock.emit('data', Buffer.alloc(0));
      return;
    }

    if (stage === 'auth') {
      if (buf.length < 2) return;
      const status = buf[1];
      buf = buf.slice(2);
      if (status !== 0x00) return finish(new Error(`SOCKS5 proxy ${egress.label} rejected the credentials`));
      stage = 'request';
      sendRequest();
      if (buf.length) sock.emit('data', Buffer.alloc(0));
      return;
    }

    if (stage === 'request') {
      // VER REP RSV ATYP + addr + port
      if (buf.length < 5) return;
      if (buf[1] !== 0x00) {
        return finish(new Error(`SOCKS5 proxy ${egress.label} refused the connection: ${socksError(buf[1])}`));
      }
      const atyp = buf[3];
      let addrLen;
      if (atyp === 0x01) addrLen = 4;
      else if (atyp === 0x04) addrLen = 16;
      else if (atyp === 0x03) addrLen = buf[4] + 1;
      else return finish(new Error(`SOCKS5 proxy ${egress.label} replied with unknown address type ${atyp}`));

      const total = 4 + addrLen + 2;
      if (buf.length < total) return;
      // Anything past the reply is already-tunnelled data: push it back so the
      // TLS layer sees a complete stream.
      //
      // DETACH BEFORE UNSHIFTING. `unshift` re-delivers synchronously to any
      // attached 'data' listener, so unshifting while still listening feeds
      // the bytes straight back into this handler, which concats and unshifts
      // them again -- unbounded recursion ending in
      // ERR_MEMORY_ALLOCATION_FAILED. Only fires when the proxy sends data
      // alongside its reply, which is why it survived every earlier test.
      const extra = buf.slice(total);
      detach();
      if (extra.length) sock.unshift(extra);
      finish(null, sock);
    }
  });

  function sendRequest() {
    const hostBuf = Buffer.from(destHost, 'utf8');
    if (hostBuf.length > 255) return finish(new Error('destination hostname is too long for SOCKS5'));
    const req = Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
      hostBuf,
      Buffer.from([(destPort >> 8) & 0xff, destPort & 0xff]),
    ]);
    sock.write(req);
  }
}

function socksError(rep) {
  return (
    {
      0x01: 'general SOCKS server failure',
      0x02: 'connection not allowed by ruleset',
      0x03: 'network unreachable',
      0x04: 'host unreachable',
      0x05: 'connection refused',
      0x06: 'TTL expired',
      0x07: 'command not supported',
      0x08: 'address type not supported',
    }[rep] || `unknown reply code 0x${rep.toString(16)}`
  );
}

// ------------------------------------------------------- HTTP CONNECT

function connectTunnel(egress, destHost, destPort, cb) {
  const headers = [`CONNECT ${destHost}:${destPort} HTTP/1.1`, `Host: ${destHost}:${destPort}`];
  if (egress.username) {
    const cred = Buffer.from(`${egress.username}:${egress.password}`, 'utf8').toString('base64');
    headers.push(`Proxy-Authorization: Basic ${cred}`);
  }
  headers.push('', '');

  const sock = net.connect({ host: egress.host, port: egress.port });
  let buf = Buffer.alloc(0);
  let done = false;

  // See socks5Connect: detaching before handing the socket on is what stops
  // an unshift from re-entering this handler.
  const detach = () => {
    sock.removeAllListeners('data');
    sock.removeAllListeners('close');
    sock.removeAllListeners('connect');
  };

  const finish = (err, out) => {
    if (done) return;
    done = true;
    detach();
    clearTimeout(timer);
    if (err) {
      sock.destroy();
      cb(err);
    } else {
      cb(null, out);
    }
  };

  const timer = setTimeout(
    () => finish(new Error(`CONNECT to ${egress.label} timed out after ${egress.timeoutMs}ms`)),
    egress.timeoutMs
  );

  sock.on('error', (e) => finish(new Error(`HTTP proxy ${egress.label}: ${e.message}`)));
  sock.on('close', () => finish(new Error(`HTTP proxy ${egress.label} closed the connection mid-CONNECT`)));
  sock.on('connect', () => sock.write(headers.join('\r\n')));

  sock.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const end = buf.indexOf('\r\n\r\n');
    if (end === -1) {
      if (buf.length > 65536) finish(new Error(`HTTP proxy ${egress.label} sent an oversized CONNECT response`));
      return;
    }
    const head = buf.slice(0, end).toString('utf8');
    const status = /^HTTP\/1\.[01] (\d{3})/.exec(head);
    if (!status) return finish(new Error(`HTTP proxy ${egress.label} sent a malformed CONNECT response`));
    if (status[1] !== '200') {
      return finish(new Error(`HTTP proxy ${egress.label} refused CONNECT with status ${status[1]}`));
    }
    // Detach before unshifting -- see the note in socks5Connect. The same
    // recursion applies here, and this is the path that actually crashed:
    // an HTTP proxy that pipelines data after its CONNECT response.
    const extra = buf.slice(end + 4);
    detach();
    if (extra.length) sock.unshift(extra);
    finish(null, sock);
  });
}

// ----------------------------------------------------------------- agent

// An https.Agent whose sockets are tunnelled. Returning a TLS socket from
// createConnection is what keeps the rest of the proxy unchanged: server.js
// still calls https.request, and the transform path never learns that egress
// is in play.
// `allowDirect` relaxes property 1 above, by explicit configuration only
// (`egress.onFailure: "direct"`). It exists so a dead proxy cannot lock you out
// of your own tooling. The cost is real and unavoidable: in that mode a proxy
// outage silently becomes an unmasked connection. So the fallback is never
// quiet -- it warns on every use, and the health record keeps a permanent
// `fellBackDirect` count that the notifier surfaces, because the failure this
// guards against is not "went direct once" but "went direct for a week and
// nothing said so".
// `shouldTunnel` is consulted per connection, not once at startup, so the
// decision can change while the proxy runs: a VPN dropping mid-session must
// engage the pool without a restart, and the runtime toggle must take effect
// on the next request rather than the next launch.
function createEgressAgent({
  egress,
  egressList,
  warn = () => {},
  health = null,
  allowDirect = false,
  shouldTunnel = () => true,
  // Called with the label of a proxy that failed to carry a connection, so
  // the pool can drop it immediately. Without this a dead proxy stays in
  // the list until its cache TTL expires, and EVERY request pays its full
  // handshake timeout again -- measured at 6s each, five deep, before
  // refusing. Free proxies die within minutes of being verified, so this is
  // the difference between a self-healing pool and one that rots.
  onProxyFailure = () => {},
  // 'request' means a real API call depends on this agent, so a total failure
  // is a refusal the user needs to know about. 'probe' means the pool is
  // trying a candidate it fully expects to fail: free proxy lists have roughly
  // a 7% hit rate, so ~93% of probes fail by design. Saying "request REFUSED"
  // for those produced 38 alarming lines during a run where nothing was
  // actually refused -- and since warnings now feed the status line, it would
  // have shown a red error while everything was fine.
  purpose = 'request',
}) {
  // `egressList` may be a function, so a dynamically refreshed pool can add
  // and retire proxies without rebuilding the agent. Resolved per connection
  // attempt, not captured once.
  const dynamic = typeof egressList === 'function';
  const resolveList = dynamic
    ? () => egressList() || []
    : () => (egressList && egressList.length ? egressList : egress ? [egress] : []);
  if (!dynamic && resolveList().length === 0) return null;

  // Try each proxy in order; refuse only when every one has failed. The order
  // is stable rather than round-robin so a working proxy keeps being used and
  // the apparent IP stays put -- a rotating exit IP is itself a signal.
  function openWithFailover(destHost, destPort, cb, idx = 0, errors = [], list = resolveList()) {
    if (list.length === 0) {
      const why = 'no egress proxies available (none configured and the pool is empty)';
      warn(`${why}; request ${allowDirect ? 'going DIRECT from your real IP' : 'REFUSED'}`);
      if (health) health.note({ ok: false, error: why });
      if (allowDirect) {
        if (health) health.noteDirectFallback();
        cb(null, null, null);
      } else {
        cb(new Error(why));
      }
      return;
    }
    if (idx >= list.length) {
      const detail = errors.map((e) => e.message).join('; ');
      const many = `all ${list.length} configured prox${list.length === 1 ? 'y' : 'ies'}`;
      if (health) health.note({ ok: false, error: detail });

      if (allowDirect) {
        // Configured escape hatch: onFailure "direct".
        warn(
          `EGRESS FAILED OVER TO A DIRECT CONNECTION: ${many} unreachable, so this request went out ` +
            `from YOUR REAL IP. Personal data is still redacted; your address and location are not. ` +
            `Set egress.onFailure to "refuse" to block instead. Cause: ${detail}`
        );
        if (health) health.noteDirectFallback();
        cb(null, null, null); // null proxy => caller connects directly
        return;
      }

      if (purpose === 'probe') warn(`probe failed: ${detail}`);
      else warn(`egress tunnel unavailable through ${many}; request REFUSED, nothing sent direct: ${detail}`);
      cb(new Error(`no egress proxy available: ${detail}`));
      return;
    }
    const e = list[idx];
    const open = e.kind === 'socks5' ? socks5Connect : connectTunnel;
    open(e, destHost, destPort, (err, raw) => {
      if (err) {
        if (idx + 1 < list.length) warn(`egress proxy ${e.label} failed (${err.message}); trying the next one`);
        // Report it whether or not there is a next one: the last proxy
        // failing is exactly when the pool most needs to know.
        try { onProxyFailure(e.label, err); } catch (e2) { /* never let reporting break the attempt */ }
        // Same `list` throughout one attempt: re-resolving mid-failover could
        // shift indices under us and skip or retry a proxy.
        openWithFailover(destHost, destPort, cb, idx + 1, errors.concat(err), list);
        return;
      }
      if (health) health.note({ ok: true, active: e.label });
      cb(null, raw, e);
    });
  }

  class TunnelAgent extends https.Agent {
    createConnection(options, cb) {
      const destHost = options.host || options.hostname;
      const destPort = Number(options.port) || 443;

      // Deliberately direct: auto mode has decided we are already masked, or
      // the user toggled the tunnel off. Distinct from the allowDirect
      // fallback below, which is a failure and is reported as one.
      if (!shouldTunnel()) {
        const plain = tls.connect({ host: destHost, port: destPort, servername: destHost, ALPNProtocols: ['http/1.1'] });
        plain.once('secureConnect', () => cb(null, plain));
        plain.once('error', (e) => cb(e));
        return;
      }

      openWithFailover(destHost, destPort, (err, raw, used) => {
        if (err) {
          // Fail closed. The caller sees a connection error and returns 502;
          // no direct connection is ever attempted.
          cb(err);
          return;
        }
        if (!raw) {
          // allowDirect fallback: a normal verified TLS connection, no tunnel.
          const plain = tls.connect({ host: destHost, port: destPort, servername: destHost, ALPNProtocols: ['http/1.1'] });
          plain.once('secureConnect', () => cb(null, plain));
          plain.once('error', (e) => cb(e));
          return;
        }
        const egressLabel = used.label;
        // Verification deliberately left at its secure default. `servername`
        // must be the real upstream host, not the proxy, or SNI and hostname
        // verification would both be wrong.
        const secure = tls.connect({
          socket: raw,
          servername: destHost,
          ALPNProtocols: ['http/1.1'],
        });
        secure.once('secureConnect', () => {
          if (!secure.authorized) {
            const why = secure.authorizationError || 'certificate not authorized';
            secure.destroy();
            warn(`egress tunnel presented an untrusted certificate for ${destHost}, request refused: ${why}`);
            if (health) health.note({ ok: false, error: `TLS verification failed via ${egressLabel}` });
            cb(new Error(`TLS verification failed through ${egressLabel}: ${why}`));
            return;
          }
          cb(null, secure);
        });
        secure.once('error', (e) => cb(e));
      });
    }
  }

  // keepAliveMsecs well above the default 1s: through a free proxy the
  // handshake measured ~500ms against a ~200ms warm request, so letting an
  // idle socket die between turns means paying that repeatedly. maxFreeSockets
  // keeps more than one warm, since Claude Code can have several requests in
  // flight. A measured run showed 2 tunnels opened for 4 sequential requests
  // with the defaults -- sockets were being dropped and re-established.
  return new TunnelAgent({
    keepAlive: true,
    keepAliveMsecs: 30000,
    maxSockets: 8,
    maxFreeSockets: 4,
  });
}

// Opens a connection through the tunnel and leaves it in the agent's free
// pool, so the first real request finds a warm socket instead of paying the
// handshake. Sockets are pooled per origin, so this must target the actual
// upstream: a warm socket to the geo-check host does nothing for API calls.
//
// Any response at all means success -- an unauthenticated request is expected
// to be rejected, and a 401 proves the tunnel and TLS session are up just as
// well as a 200 would.
function prewarm({ agent, host = 'api.anthropic.com', port = 443, timeoutMs = 20000, warn = () => {} }, done = () => {}) {
  if (!agent) return done(false);
  let settled = false;
  const finish = (ok, why) => {
    if (settled) return;
    settled = true;
    if (!ok && why) warn(`egress pre-warm failed (${why}); the first request will pay the handshake instead`);
    done(ok);
  };

  const req = https.request({ hostname: host, port, path: '/', method: 'GET', agent, timeout: timeoutMs }, (res) => {
    // Drain so the socket is returned to the free pool rather than abandoned.
    res.resume();
    res.on('end', () => finish(true));
  });
  req.on('timeout', () => {
    req.destroy();
    finish(false, 'timed out');
  });
  req.on('error', (e) => finish(false, e.message));
  req.end();
}

// ----------------------------------------------------------------- health

// Tracks whether egress is actually working, and what the outside world sees
// as our address. "Configured" is not the same as "masking": a proxy can be
// reachable and still forward the real client IP, so the only honest check is
// to ask an echo service what address it sees and compare.
// Comparing addresses does not require keeping them. The masking check only
// ever asks "is the apparent address the same as the direct one", which a
// digest answers exactly as well as the value does -- and the value is the
// user's real IP in the one case that matters most, when masking has FAILED.
// Logging or persisting it there would write their location to disk at the
// precise moment they were exposed.
//
// The key is per-process and random: comparisons only ever happen within a
// single run, and a fresh key each start means the digests cannot be
// correlated across runs either.
const K_IP = crypto.randomBytes(32);
function ipDigest(ip) {
  if (!ip) return null;
  return crypto.createHmac('sha256', K_IP).update(String(ip)).digest('hex').slice(0, 12);
}

function createHealth({ egressList = [], now = () => Date.now() } = {}) {
  const state = {
    configured: egressList.map((e) => e.label),
    active: null,
    ok: null, // null = not yet exercised
    lastError: null,
    lastCheck: null,
    // Digests, not addresses -- see ipDigest above. `exitIp` holds a real
    // value only once masking is CONFIRMED, at which point it is the proxy's
    // address and not the user's.
    apparentIpDigest: null,
    apparentIpAt: null,
    apparentCountry: null,
    exitIp: null,
    directIpDigest: null,
    directCountry: null,
    masking: null, // true only once apparentIp is known AND differs from directIp
    tunnelling: null, // auto mode's current decision
    externallyMasked: null,
    decisionReason: null,
    failures: 0,
    successes: 0,
    // Sticky on purpose: a single unmasked request is worth reporting for the
    // rest of the session, so this is never reset by a later success.
    fellBackDirect: 0,
    lastDirectAt: null,
  };

  // `freshApparent` is the just-observed apparent address, passed in only so
  // it can be retained when it proves to be a proxy exit. Once the two
  // digests match, the apparent address IS the user's, so nothing is kept.
  function recompute(freshApparent) {
    if (!state.apparentIpDigest || !state.directIpDigest) return;
    state.masking = state.apparentIpDigest !== state.directIpDigest;
    if (state.masking) {
      if (freshApparent) state.exitIp = freshApparent;
    } else {
      state.exitIp = null;
    }
  }

  return {
    state,
    noteDirectFallback() {
      state.fellBackDirect++;
      state.lastDirectAt = now();
      state.masking = false;
    },
    note({ ok, active, error }) {
      state.lastCheck = now();
      state.ok = ok;
      if (ok) {
        state.active = active || state.active;
        state.successes++;
        state.lastError = null;
      } else {
        state.failures++;
        state.lastError = error || 'unknown';
        state.active = null;
      }
    },
    setApparentIp(ip, country = null) {
      state.apparentIpDigest = ipDigest(ip);
      state.apparentIpAt = now();
      if (country) state.apparentCountry = country;
      recompute(ip);
    },
    setDirectIp(ip, country = null) {
      state.directIpDigest = ipDigest(ip);
      if (country) state.directCountry = country;
      recompute(null);
    },
    setTunnelDecision(on, reason) {
      state.tunnelling = on;
      state.decisionReason = reason;
    },
    // Records masking achieved by something OTHER than our tunnel -- a VPN,
    // typically -- which is the state auto mode deliberately leaves alone.
    // Without this, a reader sees masking:false while not tunnelling and
    // concludes the user is exposed, when in fact the tunnel stood down
    // precisely because they were already covered.
    setExternallyMasked(masked, country) {
      state.externallyMasked = Boolean(masked);
      if (country) state.directCountry = country;
      // `masking` means "is the path in use masking me". While we are not
      // tunnelling, that path is the direct one.
      state.masking = Boolean(masked);
    },
    // Egress sourced from the pool has nothing to declare at startup: the
    // proxies do not exist yet. Without this, `configured` stays empty and
    // every reader -- status line included -- concludes egress is off.
    setConfigured(labels) {
      state.configured = (labels || []).slice();
    },
    snapshot() {
      return Object.assign({}, state);
    },
  };
}

// Ask an echo service what address it sees, once through the tunnel and once
// directly, and record both. Two separate calls because the question is not
// "is the proxy up" but "does traffic actually leave from somewhere else" --
// an open proxy that appends X-Forwarded-For and preserves the source address
// answers the first question yes and the second one no.
//
// `agent` null means measure the direct path. Text endpoints only; the body is
// length-capped because this is an untrusted third party.
function probeApparentIp(url, agent, timeoutMs, cb) {
  let u;
  try {
    u = new URL(url);
  } catch (e) {
    return cb(new Error(`ipCheckUrl is not a valid URL: ${url}`));
  }
  if (u.protocol !== 'https:') return cb(new Error('ipCheckUrl must be https'));

  const req = https.request(
    {
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      method: 'GET',
      agent: agent || undefined,
      headers: { host: u.hostname, accept: 'text/plain', 'user-agent': 'curl/8' },
      timeout: timeoutMs,
    },
    (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => {
        if (body.length < 256) body += c;
      });
      res.on('end', () => {
        const ip = (body.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f:]{6,}\b/i) || [])[0];
        if (!ip) return cb(new Error(`no address found in response from ${u.hostname}`));
        // Endpoints that answer with JSON (api.country.is and friends) also
        // give the country, which is what auto mode and the country blocklist
        // need. Plain-text endpoints just give the address; country stays null
        // and callers that require it say so rather than guessing.
        let country = null;
        const m = /"country"\s*:\s*"([A-Za-z]{2})"/.exec(body);
        if (m) country = m[1].toUpperCase();
        cb(null, ip, country);
      });
    }
  );
  req.on('timeout', () => req.destroy(new Error(`ip check to ${u.hostname} timed out`)));
  req.on('error', (e) => cb(e));
  req.end();
}

// Runs both probes and updates health. Never throws; a failed check is
// reported, not fatal -- it must not be able to take the session down, because
// the echo service is a third party we do not control.
function verifyMasking({ health, agent, url, timeoutMs = 10000, checkDirect = true, warn = () => {} }, done = () => {}) {
  // Fail loudly rather than dereferencing null inside an async callback, where
  // it surfaced as "cannot read properties of null" from a timer with no
  // indication of which config produced it.
  if (!health) throw new Error('verifyMasking requires a health record; egress state would otherwise be unobservable');
  let pending = checkDirect ? 2 : 1;
  const finish = () => {
    if (--pending === 0) done(health.snapshot());
  };

  probeApparentIp(url, agent, timeoutMs, (err, ip, country) => {
    if (err) {
      warn(`egress ip check failed: ${err.message}`);
      health.note({ ok: false, error: `ip check: ${err.message}` });
    } else {
      health.setApparentIp(ip, country);
    }
    finish();
  });

  if (checkDirect) {
    probeApparentIp(url, null, timeoutMs, (err, ip, country) => {
      if (!err) health.setDirectIp(ip, country);
      // A failed direct probe is not worth warning about: it only removes our
      // ability to say "masking confirmed", it does not weaken the tunnel.
      finish();
    });
  }
}

// Decides whether to tunnel, given the last observed country and how long ago
// it was observed.
//
// THE RULE: a decision older than ttlMs is not a decision. It must fail SAFE
// (tunnel), never coast on its last verdict.
//
// This was a live leak. Auto mode observed a VPN exit country, correctly
// decided "already masked, no tunnel needed", and then kept that decision for
// its full 15-minute re-check interval. The user turned the VPN off; for the
// next seven minutes every request went out from their real address while the
// status line reported them protected. Staleness is indistinguishable from a
// changed network, so the only safe reading of an expired decision is "unknown",
// and unknown means tunnel.
function decideTunnel({ mode, homeCountry, directCountry, decidedAt, now = Date.now(), ttlMs = DECISION_TTL_MS }) {
  if (mode === 'off') return { tunnel: false, reason: 'mode=off' };
  if (mode !== 'auto') return { tunnel: true, reason: `mode=${mode}` };

  // Auto mode from here on.
  if (!decidedAt || now - decidedAt > ttlMs) {
    return {
      tunnel: true,
      stale: true,
      reason: decidedAt
        ? `country last observed ${Math.round((now - decidedAt) / 1000)}s ago, older than ${Math.round(ttlMs / 1000)}s: re-verifying, tunnelling until it is known`
        : 'country not yet observed: tunnelling until it is known',
    };
  }
  if (!directCountry) {
    return { tunnel: true, reason: 'country could not be determined: tunnelling, because assuming safety is the assumption that leaks' };
  }
  if (directCountry === homeCountry) {
    return { tunnel: true, reason: `direct traffic appears to come from ${directCountry} (your home country): exposed, tunnelling` };
  }
  return { tunnel: false, reason: `direct traffic already appears to come from ${directCountry}, not ${homeCountry}: already masked, no tunnel needed` };
}

module.exports = {
  parseEgress,
  parseEgressList,
  createEgressAgent,
  createHealth,
  verifyMasking,
  prewarm,
  probeApparentIp,
  decideTunnel,
  DECISION_TTL_MS,
  socksError,
  SUPPORTED,
};
