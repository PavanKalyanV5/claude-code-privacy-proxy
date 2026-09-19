'use strict';

// Automatic free-proxy pool: fetches candidate host:port lists from public
// sources, verifies which ones actually tunnel AND actually mask the source
// IP, ranks the survivors, and caches them so egress has something to try
// without a human pasting in a proxy URL.
//
// This module only SELECTS candidates. It reuses egress.js's own
// createEgressAgent/probeApparentIp to do the actual verification, so a
// candidate is tested through the exact code path production traffic would
// use -- including TLS certificate verification. Nothing here sets
// rejectUnauthorized, passes checkServerIdentity, or adds a direct-connection
// fallback to the tunnel path. The one place a direct HTTPS request happens
// is the baseline "what does this machine look like with no proxy at all"
// measurement, taken once per refresh -- the same thing egress.js's own
// verifyMasking() already does when checkDirect is true. That is a
// measurement for comparison, not a fallback: a candidate is only ever
// returned if it succeeded through the tunnelled path.

const os = require('os');
const path = require('path');
const fs = require('fs');
const https = require('https');
const { parseEgress, createEgressAgent, probeApparentIp } = require('./egress');

// ---------------------------------------------------------------- sources
//
// Empty on purpose. This used to ship six scraped public-proxy-list URLs.
// Measured in production (see docs/redaction-proxy-runbook.md §5c): five
// candidates passed full verification -- a certificate-verified TLS tunnel
// AND a masking check -- and every one of the five refused the very next
// connection seconds later. Verification does not predict usability, so
// shipping a default list of sources that are dead within minutes is worse
// than shipping nothing: it looks like a working failsafe and is not one.
//
// The pool code itself is sound (bounded concurrency, demote-on-failure,
// short TTL) and stays here for anyone who wants to point it at sources they
// have actually validated for repeat use, not just a single probe. Pass
// `sources` explicitly to opt in. See proxy/providers.js for the replacement
// approach: detecting a dependable local SOCKS5/CONNECT endpoint (your own
// SSH tunnel, Tor, WARP, etc.) instead of scraping public lists.
const DEFAULT_SOURCES = [];

const DEFAULT_CACHE_PATH = path.join(os.homedir(), '.claude', 'redaction', 'proxy-pool.json');
// Free proxies verified at time T are frequently dead by T+2min: measured
// five verifying successfully and all five refusing the very next
// connection seconds later. A 30-minute cache therefore served entries that
// had no chance of working, and every request paid their handshake timeouts
// before refusing. Short TTL plus demote-on-failure is what makes the pool
// self-healing rather than a list of corpses.
const DEFAULT_TTL_MS = 5 * 60 * 1000;
const DEFAULT_WANT = 5;
const DEFAULT_CONCURRENCY = 24;
const DEFAULT_TEST_URL = 'https://api.ipify.org';
const DEFAULT_TEST_TIMEOUT_MS = 6000;
const NEAR_TIE_MS = 50;

// Above this, the tunnel is usable but the session will feel slow. Chosen from
// a live run where real free proxies measured 2.0-5.5s round trip.
const SLOW_WARN_MS = 1500;

// A line must look like [scheme://][user@]host:port, optionally with a
// trailing slash. This is a cheap pre-filter; parseEgress() is the real
// validator and anything that slips past this regex but is not a real
// egress URL is still caught (and skipped) there.
const CANDIDATE_LINE_RE = /^(?:[a-zA-Z][\w+.-]*:\/\/)?(?:[\w.-]+@)?[\w.-]+:\d{1,5}\/?$/;

const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]{2,}$/;

// -------------------------------------------------------------- fetch/parse

function defaultFetchList(url, cb) {
  let done = false;
  const finish = (err, text) => {
    if (done) return;
    done = true;
    cb(err, text);
  };
  let req;
  try {
    req = https.get(url, { headers: { 'user-agent': 'curl/8' }, timeout: 10000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return finish(new Error(`${url} returned status ${res.statusCode}`));
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => {
        body += c;
      });
      res.on('end', () => finish(null, body));
    });
  } catch (e) {
    return finish(e);
  }
  req.on('timeout', () => req.destroy(new Error(`fetch of ${url} timed out`)));
  req.on('error', (e) => finish(e));
}

// Baseline measurement: what does this machine look like with no proxy.
// Taken once per refresh, never per candidate. This is a comparison
// baseline, not a fallback path for the tunnel agent.
function defaultGetDirectIp(testUrl, timeoutMs, cb) {
  probeApparentIp(testUrl, null, timeoutMs, cb);
}

function normalizeSource(s) {
  if (typeof s === 'string') return { url: s, kind: /socks5/i.test(s) ? 'socks5' : 'connect' };
  return s;
}

function isRealIp(ip) {
  return typeof ip === 'string' && ip.length > 0 && IP_RE.test(ip);
}

function fetchAllSources(sources, fetchList, warn, cb) {
  if (sources.length === 0) return cb([]);
  let pending = sources.length;
  const collected = [];
  sources.forEach((src) => {
    fetchList(src.url, (err, text) => {
      if (err || typeof text !== 'string') {
        warn(`proxy pool: source ${src.url} failed (${err ? err.message : 'no text'}); skipping it this refresh`);
      } else {
        collected.push({ text, kind: src.kind });
      }
      if (--pending === 0) cb(collected);
    });
  });
}

// Parses every line from every fetched source into normalized egress
// descriptors (the exact shape parseEgress produces), skipping junk and
// deduping by host:port across all sources combined.
// `timeoutMs` is passed down deliberately. Without it every candidate
// inherits the 15s production handshake timeout, and a live run showed that
// dominating the wall clock: 14 of ~40 probes each burned the full 15s, taking
// a refresh from 10s to 22s. A proxy that will work answers in well under a
// second; one that takes 15s is not a proxy worth having in a failsafe.
function buildCandidates(collected, timeoutMs) {
  const map = new Map();
  for (const { text, kind } of collected) {
    const lines = String(text).split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      if (!CANDIDATE_LINE_RE.test(line)) continue;

      const hasScheme = /^[a-zA-Z][\w+.-]*:\/\//.test(line);
      const urlStr = hasScheme ? line : `${kind === 'socks5' ? 'socks5' : 'http'}://${line}`;

      let desc;
      try {
        desc = parseEgress(timeoutMs ? { url: urlStr, timeoutMs } : urlStr);
      } catch (e) {
        continue; // not a supported/valid egress URL -- junk, skip
      }
      if (!desc) continue;

      const key = `${desc.host}:${desc.port}`;
      if (!map.has(key)) map.set(key, desc);
    }
  }
  return Array.from(map.values());
}

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
  return arr;
}

// ------------------------------------------------------------- test/verify

function defaultTestCandidate({ testUrl, testTimeoutMs, warn }) {
  return function testCandidate(cand, cb) {
    let agent;
    try {
      agent = createEgressAgent({ egressList: [cand], warn, purpose: 'probe' });
    } catch (e) {
      return cb(e);
    }
    if (!agent) return cb(new Error('failed to build an egress agent for the candidate'));

    const start = Date.now();
    probeApparentIp(testUrl, agent, testTimeoutMs, (err, ip, country) => {
      agent.destroy();
      if (err) return cb(err);
      cb(null, { latencyMs: Date.now() - start, apparentIp: ip, country: country || null });
    });
  };
}

// Bounded-concurrency worker pool with early exit. Never runs more than
// `concurrency` calls to testCandidate at once, and stops issuing new work
// (ignoring the results of anything still in flight) as soon as `want`
// candidates have verified. A candidate only verifies if its apparent IP is a
// real address AND differs from the direct IP measured once for this refresh
// -- that second half is what rejects a transparent proxy that is reachable
// but forwards the real source address.
//
// The country blocklist is enforced HERE, on the country observed after
// connecting, and never on whatever country a source list claimed. Those
// labels are frequently wrong, so pre-filtering on them would quietly route
// traffic through a country the user had excluded. A candidate whose country
// cannot be determined is rejected when a blocklist is in force: "unknown"
// cannot be checked against a list of countries to avoid, and guessing in
// favour of the proxy is how an exclusion silently stops meaning anything.
function runWorkerPool(candidates, { concurrency, want, testCandidate, directIp, excludeCountries = [], warn = () => {} }, onDone) {
  const blocked = new Set(excludeCountries.map((c) => String(c).toUpperCase()));
  if (candidates.length === 0 || want <= 0) return onDone([]);

  let idx = 0;
  let active = 0;
  let stopped = false;
  const verified = [];

  function finish() {
    if (stopped) return;
    stopped = true;
    onDone(verified);
  }

  function launchNext() {
    if (stopped) return;
    if (verified.length >= want) return finish();
    if (idx >= candidates.length) {
      if (active === 0) finish();
      return;
    }
    const cand = candidates[idx++];
    active++;
    testCandidate(cand, (err, result) => {
      active--;
      const masks = !err && result && isRealIp(result.apparentIp) && directIp && result.apparentIp !== directIp;
      if (!stopped && masks) {
        const country = result.country ? String(result.country).toUpperCase() : null;
        if (blocked.size > 0 && (!country || blocked.has(country))) {
          warn(
            `rejected proxy ${cand.label}: exit country ${country || 'unknown'} is ` +
              (country ? 'on the exclusion list' : 'undeterminable, and an exclusion list is in force')
          );
        } else {
          verified.push(Object.assign({}, cand, {
            latencyMs: result.latencyMs,
            apparentIp: result.apparentIp,
            country,
            verifiedAt: Date.now(),
          }));
        }
      }
      if (stopped) return;
      if (verified.length >= want) return finish();
      if (idx >= candidates.length && active === 0) return finish();
      launchNext();
    });
  }

  const initial = Math.min(concurrency, candidates.length);
  for (let i = 0; i < initial; i++) launchNext();
}

// Rank by latency ascending; socks5 wins a near-tie (within NEAR_TIE_MS)
// against connect, because SOCKS5 avoids the HTTP proxy's own header
// handling entirely.
function rankCandidates(list) {
  return list.slice().sort((a, b) => {
    const diff = a.latencyMs - b.latencyMs;
    if (Math.abs(diff) <= NEAR_TIE_MS && a.kind !== b.kind) {
      if (a.kind === 'socks5') return -1;
      if (b.kind === 'socks5') return 1;
    }
    return diff;
  });
}

// ------------------------------------------------------------------ cache

function loadCacheSync(cachePath) {
  const empty = { fetchedAt: 0, proxies: [] };
  try {
    const raw = fs.readFileSync(cachePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.proxies)) return empty;
    // `directIp` is deliberately not carried across: a cache written before
    // that field was dropped may still contain one, and loading it would put
    // the user's address back into the live state and the next report.
    return {
      fetchedAt: typeof parsed.fetchedAt === 'number' ? parsed.fetchedAt : 0,
      proxies: parsed.proxies,
    };
  } catch (e) {
    // Missing file or corrupt JSON: treat as empty, never throw.
    return empty;
  }
}

function persistSync(cachePath, state, warn) {
  try {
    fs.mkdirSync(path.dirname(cachePath), { recursive: true });
    fs.writeFileSync(cachePath, JSON.stringify(state, null, 2));
  } catch (e) {
    warn(`proxy pool: failed to persist cache to ${cachePath}: ${e.message}`);
  }
}

// Strips verification metadata back down to the exact descriptor shape
// parseEgressList() produces, so the result can go straight into
// createEgressAgent({ egressList: result }).
function toEgressList(proxies) {
  return proxies.map((p) => ({
    kind: p.kind,
    host: p.host,
    port: p.port,
    username: p.username || '',
    password: p.password || '',
    label: p.label,
    timeoutMs: p.timeoutMs,
  }));
}

// ----------------------------------------------------------------- public

function createPool({
  sources = DEFAULT_SOURCES,
  cachePath = DEFAULT_CACHE_PATH,
  ttlMs = DEFAULT_TTL_MS,
  want = DEFAULT_WANT,
  concurrency = DEFAULT_CONCURRENCY,
  testUrl = DEFAULT_TEST_URL,
  testTimeoutMs = DEFAULT_TEST_TIMEOUT_MS,
  // Two-letter country codes to refuse, checked against the exit country
  // observed after connecting. Empty means no country filtering.
  excludeCountries = [],
  // Optional hard ceiling on verified latency. Off by default: see the note at
  // the filter below for why a failsafe should not discard slow proxies.
  maxLatencyMs = null,
  fetchList = defaultFetchList,
  testCandidate = null,
  getDirectIp = defaultGetDirectIp,
  warn = () => {},
  now = () => Date.now(),
} = {}) {
  const normalizedSources = sources.map(normalizeSource);
  const runTestCandidate = testCandidate || defaultTestCandidate({ testUrl, testTimeoutMs, warn });

  let state = loadCacheSync(cachePath);
  let stale = false;

  function isFresh() {
    if (stale) return false;
    if (!state.fetchedAt) return false;
    if (state.proxies.length < 2) return false;
    return now() - state.fetchedAt < ttlMs;
  }

  function refresh(cb) {
    fetchAllSources(normalizedSources, fetchList, warn, (collected) => {
      const candidates = shuffle(buildCandidates(collected, testTimeoutMs));
      getDirectIp(testUrl, testTimeoutMs, (dErr, directIp) => {
        if (dErr) warn(`proxy pool: could not measure the direct IP baseline (${dErr.message}); no candidate can verify this refresh`);
        const resolvedDirectIp = dErr ? null : directIp;
        runWorkerPool(candidates, { concurrency, want, testCandidate: runTestCandidate, directIp: resolvedDirectIp, excludeCountries, warn }, (verified) => {
          let ranked = rankCandidates(verified);

          // A hard ceiling is opt-in and off by default. For a FAILSAFE,
          // slow-but-working beats blocked, so a slow proxy is reported rather
          // than discarded -- measured latencies on real free proxies ran
          // 2.0-5.5s, which is usable in an emergency and miserable as a
          // default. Discarding them by default would turn a working fallback
          // into no fallback.
          if (maxLatencyMs) {
            const before = ranked.length;
            ranked = ranked.filter((p) => p.latencyMs <= maxLatencyMs);
            if (ranked.length < before) {
              warn(`dropped ${before - ranked.length} verified prox${before - ranked.length === 1 ? 'y' : 'ies'} slower than maxLatencyMs=${maxLatencyMs}ms`);
            }
          }
          if (ranked.length && ranked[0].latencyMs > SLOW_WARN_MS) {
            warn(
              `the fastest verified proxy is ${ranked[0].latencyMs}ms; expect noticeably slower responses ` +
                'and choppier streaming while the tunnel is in use'
            );
          }

          // The direct baseline is deliberately NOT persisted. It is
          // re-measured on every refresh, so keeping it buys nothing -- and
          // when the VPN is off it is the user's real address, which has no
          // business sitting in a cache file on disk.
          state = { fetchedAt: now(), proxies: ranked };
          stale = false;
          persistSync(cachePath, state, warn);
          cb(null, toEgressList(state.proxies));
        });
      });
    });
  }

  function get(cb) {
    if (isFresh()) return cb(null, toEgressList(state.proxies));
    refresh(cb);
  }

  function snapshot() {
    return {
      count: state.proxies.length,
      fetchedAt: state.fetchedAt,
      stale: !isFresh(),
      // Country is part of the report, not internal detail: it is what the
      // exclusion list is checked against, and omitting it made a live run
      // print "unknown" for every entry while the enforcement underneath was
      // working correctly. A security control that cannot be inspected reads
      // as a broken one.
      //
      // The direct baseline is reported as a yes/no. Its VALUE is the user's
      // real address whenever the VPN is off, and a report is a thing people
      // paste into issues and chat windows.
      baselineMeasured: Boolean(state.proxies.length || state.fetchedAt),
      proxies: state.proxies.map((p) => ({
        label: p.label,
        kind: p.kind,
        latencyMs: p.latencyMs,
        apparentIp: p.apparentIp,
        country: p.country || null,
        verifiedAt: p.verifiedAt,
      })),
    };
  }

  function demote(label) {
    state = Object.assign({}, state, { proxies: state.proxies.filter((p) => p.label !== label) });
    if (state.proxies.length < 2) stale = true;
    persistSync(cachePath, state, warn);
  }

  return { get, refresh, snapshot, demote };
}

module.exports = {
  createPool,
  DEFAULT_SOURCES,
  DEFAULT_CACHE_PATH,
  DEFAULT_TTL_MS,
  DEFAULT_WANT,
  DEFAULT_CONCURRENCY,
  DEFAULT_TEST_URL,
  DEFAULT_TEST_TIMEOUT_MS,
};
