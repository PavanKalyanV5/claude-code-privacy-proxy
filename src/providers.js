'use strict';

// Providers layer: ways to find a working SOCKS5/CONNECT endpoint that
// actually stays up, as an alternative to proxy.js's scraped public-proxy
// lists. That approach was measured in production and does not work: five
// proxies passed full verification (a certificate-verified TLS tunnel AND a
// masking check) and every one of them refused the very next connection
// seconds later (docs/redaction-proxy-runbook.md §5c). Verification does not
// predict usability.
//
// This module does DETECTION and DESCRIPTION only. It never installs
// software, never modifies anything outside this process, and never touches
// the network beyond a raw TCP handshake to 127.0.0.1 (or a host the caller
// explicitly configured). Detecting a candidate means completing a REAL
// protocol handshake -- a SOCKS5 greeting, or an HTTP CONNECT round trip --
// never just noticing that a port accepts a connection. An open port that
// does not speak the protocol must not be offered as a proxy: the whole
// point of this module is to not repeat the free-proxy-list mistake of
// trusting something that merely looks alive.
//
// Reuses egress.js rather than reimplementing it: `parseEgress`/
// `parseEgressList` produce the exact descriptor shape `createEgressAgent`
// consumes, so a detected candidate can go straight into `egressList`.

const net = require('net');
const { parseEgress, parseEgressList } = require('./egress');

const DEFAULT_TIMEOUT_MS = 1500;

// Handshake timeout attached to descriptors this module hands back, distinct
// from the (short) detection timeout above: detection must be fast, but once
// a candidate is in use it should get the same patience egress.js gives any
// other proxy.
const DEFAULT_EGRESS_TIMEOUT_MS = 15000;

// ------------------------------------------------------------- catalogue
//
// Static, in priority order (most reliable first). describeAll() returns
// this verbatim so docs/CLI can list every option, including ones that
// require the user to go set something up.

const CATALOGUE = [
  {
    id: 'configured',
    label: 'Configured egress (egress.urls)',
    reliability: 'highest -- a deliberate choice',
    description:
      'Anything already listed in egress.urls / egress.url. Always wins over ' +
      'anything auto-detected: a proxy you chose on purpose outranks a guess.',
  },
  {
    id: 'ssh-socks',
    label: 'SSH dynamic-forward SOCKS5 (ssh -D)',
    reliability: 'high -- recommended',
    description:
      'A SOCKS5 proxy created by `ssh -D 1080 user@your-host`, conventionally ' +
      'bound to 127.0.0.1:1080. This is the recommended reliable option: ' +
      'Oracle Cloud "Always Free" gives permanently free small VMs suitable ' +
      'for exactly this (register, spin up an Always Free Arm/AMD instance, ' +
      'then `ssh -D 1080 user@your-vps-ip` from this machine and leave it ' +
      'running). Reliable, fast, and the only operator is you -- it removes ' +
      'the entire class of problem the scraped-list pool had.',
  },
  {
    id: 'cloudflare-warp',
    label: 'Cloudflare WARP local proxy',
    reliability: 'medium -- depends on local setup',
    description:
      'Cloudflare WARP can run as a local SOCKS5/HTTPS proxy ("Local proxy" ' +
      'mode, desktop only): `warp-cli` (or the newer `warp-cli`/Cloudflare One ' +
      'client) is switched into proxy mode and a listen port is set, then ' +
      '`warp-cli connect` brings it up. The exact subcommands have changed ' +
      'across client versions (older: `warp-cli mode proxy`; newer: ' +
      '`warp-cli set-mode proxy` plus `warp-cli set-proxy-port <port>`), and ' +
      'Cloudflare\'s own docs do not commit to a single default port -- ' +
      'community tooling commonly assumes 40000, but that is convention, not ' +
      'a documented guarantee. Because of that, this provider detects NOTHING ' +
      'unless you tell it the port via the `cloudflareWarp` option: there is ' +
      'no built-in default port to guess at.',
  },
  {
    id: 'tor',
    label: 'Tor SOCKS5',
    reliability: 'low for availability -- last resort',
    description:
      'The Tor client\'s SOCKS5 port, conventionally 127.0.0.1:9050 for a ' +
      'system Tor daemon or 127.0.0.1:9150 for Tor Browser. WARNING: many API ' +
      'providers block Tor exit nodes outright, so a working handshake here ' +
      'does not mean the upstream API will accept the connection. Treat this ' +
      'as a last resort for availability, not a first choice.',
  },
  {
    id: 'generic-local',
    label: 'Generic local proxy scan',
    reliability: 'varies -- catches anything else',
    description:
      'A scan of a small, configurable list of common local proxy ports, so ' +
      'a user running something not covered above (Psiphon, Lantern, a ' +
      'corporate proxy) is still picked up. Every candidate still needs a ' +
      'real protocol handshake to qualify -- an open port that does not speak ' +
      'SOCKS5 or answer an HTTP CONNECT is not reported.',
  },
];

// ------------------------------------------------------------- defaults

const DEFAULT_SSH_SOCKS_PORTS = [1080];
const DEFAULT_TOR_PORTS = [9050, 9150];
// Not ssh-socks/tor's own ports (those are covered above and deduped anyway
// if they overlap); this is "everything else commonly seen locally".
const DEFAULT_GENERIC_LOCAL_PORTS = [1080, 1081, 3128, 8080, 8081, 8118, 8888, 9050, 9150];

// Expands one of the per-provider config shapes into a concrete list of
// { host, port } candidates.
//
//   undefined            -> defaultPorts on defaultHost (the provider's own
//                            conventional default, or none at all)
//   false / null         -> [] (explicitly disable this provider's probing)
//   { port }             -> [{ host: defaultHost, port }]
//   { host, port }       -> [{ host, port }]
//   { ports: [...] }     -> one candidate per port, on defaultHost or cfg.host
//   [{ host, port }, ...] -> used as-is
//   [port, port, ...]    -> one candidate per port, on defaultHost
function expandCandidates(cfg, defaultHost, defaultPorts) {
  if (cfg === false || cfg === null) return [];
  if (cfg === undefined) return defaultPorts.map((port) => ({ host: defaultHost, port }));
  if (Array.isArray(cfg)) {
    return cfg
      .map((c) => (typeof c === 'number' ? { host: defaultHost, port: c } : c && { host: c.host || defaultHost, port: c.port }))
      .filter((c) => c && Number.isInteger(c.port));
  }
  const host = cfg.host || defaultHost;
  if (Array.isArray(cfg.ports)) return cfg.ports.filter((p) => Number.isInteger(p)).map((port) => ({ host, port }));
  if (Number.isInteger(cfg.port)) return [{ host, port: cfg.port }];
  return defaultPorts.map((port) => ({ host: defaultHost, port }));
}

// ----------------------------------------------------------- protocol probes
//
// Both probes speak just enough of the real protocol to prove the endpoint
// is genuinely that protocol, then tear the socket down -- this is detection,
// not use. Neither ever sends a real destination or carries real traffic.

// Completes a SOCKS5 method-negotiation greeting (RFC 1928 §3). Offers both
// no-auth and username/password so a proxy that requires auth still answers
// with a valid, recognizable reply instead of being missed. A match requires
// the reply to be exactly VER=5 followed by a method byte SOCKS5 actually
// defines (0x00 no-auth, 0x02 user/pass, 0xFF none acceptable) -- anything
// else (an HTTP banner, garbage, a truncated reply) is not a match.
function probeSocks5(host, port, timeoutMs, cb) {
  let done = false;
  let buf = Buffer.alloc(0);
  const sock = net.connect({ host, port });

  const finish = (ok) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    sock.removeAllListeners();
    sock.destroy();
    cb(ok);
  };

  const timer = setTimeout(() => finish(false), timeoutMs);
  if (timer.unref) timer.unref();

  sock.on('error', () => finish(false));
  sock.on('close', () => finish(false));
  sock.on('connect', () => {
    sock.write(Buffer.from([0x05, 0x02, 0x00, 0x02]));
  });
  sock.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (buf.length < 2) return;
    const ok = buf[0] === 0x05 && (buf[1] === 0x00 || buf[1] === 0x02 || buf[1] === 0xff);
    finish(ok);
  });
}

// Completes an HTTP CONNECT round trip against a harmless, never-contacted
// destination name -- the probe itself never reaches that hostname; it is
// only text inside a request line the proxy parses. A match requires a real
// HTTP status line reporting a 2xx: that is what distinguishes a proxy that
// actually tunnels CONNECT from a plain web server, which typically answers
// CONNECT with 400/405/501 because it never implements the method.
function probeHttpConnect(host, port, timeoutMs, cb) {
  let done = false;
  let buf = Buffer.alloc(0);
  const sock = net.connect({ host, port });

  const finish = (ok) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    sock.removeAllListeners();
    sock.destroy();
    cb(ok);
  };

  const timer = setTimeout(() => finish(false), timeoutMs);
  if (timer.unref) timer.unref();

  sock.on('error', () => finish(false));
  sock.on('close', () => finish(false));
  sock.on('connect', () => {
    sock.write('CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n');
  });
  sock.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const end = buf.indexOf('\r\n');
    if (end === -1) {
      if (buf.length > 4096) finish(false);
      return;
    }
    const statusLine = buf.slice(0, end).toString('utf8');
    const m = /^HTTP\/1\.[01]\s+(\d{3})/.exec(statusLine);
    finish(Boolean(m) && m[1][0] === '2');
  });
}

// ----------------------------------------------------------------- detect

// Builds an egress descriptor for a detected candidate by reusing
// parseEgress -- the same parser production config goes through -- rather
// than constructing the {kind,host,port,...} shape by hand here.
function toEgress(kind, host, port, egressTimeoutMs) {
  const scheme = kind === 'socks5' ? 'socks5' : 'http';
  return parseEgress({ url: `${scheme}://${host}:${port}`, timeoutMs: egressTimeoutMs });
}

function createProviders({ testUrl, timeoutMs = DEFAULT_TIMEOUT_MS, warn = () => {}, extra = {} } = {}) {
  const egressTimeoutMs = (extra && extra.egressTimeoutMs) || DEFAULT_EGRESS_TIMEOUT_MS;

  function detect(cb) {
    // 1. `configured` -- no probing. A deliberate choice is trusted outright,
    // and it is resolved through the exact same parser production config
    // uses, so a bad URL fails the same way it would at startup.
    let configuredList = [];
    try {
      configuredList = parseEgressList(extra && extra.configured);
    } catch (e) {
      warn(`providers: egress.urls could not be parsed (${e.message}); ignoring`);
    }
    const configuredResults = configuredList.map((e) => ({
      id: `configured:${e.host}:${e.port}`,
      label: `Configured egress: ${e.label}`,
      egress: e,
      source: 'configured',
      detail: 'user-configured in egress.urls / egress.url; always preferred',
    }));

    // 2-5. Auto-detected providers, in priority order. Each carries the probe
    // kind(s) a candidate must pass to qualify.
    const jobs = [
      {
        id: 'ssh-socks',
        candidates: expandCandidates(extra && extra.sshSocks, '127.0.0.1', DEFAULT_SSH_SOCKS_PORTS),
        probes: ['socks5'],
        detailOk: 'detected via a completed SOCKS5 greeting handshake',
      },
      {
        id: 'cloudflare-warp',
        // No default port: research did not turn up a Cloudflare-documented
        // default, so nothing is guessed. Detection only runs if the caller
        // supplies a port via extra.cloudflareWarp.
        candidates: expandCandidates(extra && extra.cloudflareWarp, '127.0.0.1', []),
        probes: ['socks5'],
        detailOk: 'detected via a completed SOCKS5 greeting handshake',
      },
      {
        id: 'tor',
        candidates: expandCandidates(extra && extra.tor, '127.0.0.1', DEFAULT_TOR_PORTS),
        probes: ['socks5'],
        detailOk: 'detected via a completed SOCKS5 greeting handshake; many API providers block Tor exit nodes',
      },
      {
        id: 'generic-local',
        candidates: expandCandidates(extra && extra.genericLocal, '127.0.0.1', DEFAULT_GENERIC_LOCAL_PORTS),
        probes: ['socks5', 'connect'],
        detailOk: 'detected via a completed protocol handshake (SOCKS5 or HTTP CONNECT)',
      },
    ];

    const ops = [];
    for (const job of jobs) {
      for (const c of job.candidates) ops.push({ job, host: c.host, port: c.port });
    }

    if (ops.length === 0) return finalize([]);

    let pending = ops.length;
    const matched = [];
    for (const op of ops) {
      probeCandidate(op.job.probes, op.host, op.port, timeoutMs, (kind) => {
        if (kind) matched.push({ job: op.job, host: op.host, port: op.port, kind });
        if (--pending === 0) finalize(matched);
      });
    }

    function finalize(matches) {
      const results = configuredResults.slice();
      // Group by provider so output order follows CATALOGUE priority
      // regardless of which probe finished first.
      for (const job of jobs) {
        for (const m of matches.filter((x) => x.job.id === job.id)) {
          let egress;
          try {
            egress = toEgress(m.kind, m.host, m.port, egressTimeoutMs);
          } catch (e) {
            continue; // should not happen; never let a parse quirk crash detection
          }
          results.push({
            id: `${job.id}:${m.host}:${m.port}`,
            label: `${CATALOGUE.find((c) => c.id === job.id).label} at ${m.host}:${m.port}`,
            egress,
            source: job.id,
            detail: job.detailOk,
          });
        }
      }
      // Deduplicate by host:port, keeping the first occurrence -- results
      // are already in priority order, so the first is always the
      // highest-priority provider that found this exact endpoint.
      const seen = new Set();
      const deduped = [];
      for (const r of results) {
        const key = `${r.egress.host}:${r.egress.port}`;
        if (seen.has(key)) continue;
        seen.add(key);
        deduped.push(r);
      }
      cb(null, deduped);
    }
  }

  function describeAll() {
    return CATALOGUE.map((c) => Object.assign({}, c));
  }

  return { detect, describeAll };
}

// Runs every probe a candidate could pass CONCURRENTLY (not one after
// another), so a candidate that needs multiple probe kinds (generic-local
// tries both socks5 and connect) still resolves within one `timeoutMs`
// window rather than compounding it per kind. `probes` is given in priority
// order and that order is honoured only for which match wins when more than
// one probe happens to succeed (should not normally happen for one port).
function probeCandidate(probes, host, port, timeoutMs, cb) {
  let pending = probes.length;
  let winner = null;
  const done = () => {
    if (--pending === 0) cb(winner);
  };
  probes.forEach((kind) => {
    const probe = kind === 'socks5' ? probeSocks5 : probeHttpConnect;
    probe(host, port, timeoutMs, (ok) => {
      if (ok && !winner) winner = kind;
      done();
    });
  });
}

module.exports = {
  createProviders,
  CATALOGUE,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_EGRESS_TIMEOUT_MS,
  DEFAULT_SSH_SOCKS_PORTS,
  DEFAULT_TOR_PORTS,
  DEFAULT_GENERIC_LOCAL_PORTS,
};
