#!/usr/bin/env node
'use strict';

// `npm run status` — is the proxy healthy, and am I masked right now?
//
// Reads the running proxy's /_health and, unless --quick is passed, asks it
// for a FRESH masking probe rather than a stored field. The distinction
// matters: a cached verdict once reported "already masked" for seven minutes
// after the VPN it was describing had been switched off.
//
// Prints countries, counts and verdicts. Never prints an address of yours:
// the direct baseline is held as a digest only, and the sole address shown is
// a proxy's own exit, which is not yours.

const http = require('http');
const { load } = require('../rules');

const QUICK = process.argv.includes('--quick');
const JSON_OUT = process.argv.includes('--json');

let port = 47113;
try {
  const r = load();
  if (r.proxy && r.proxy.port) port = r.proxy.port;
} catch (e) {
  // No config readable: fall back to the default port and let the request
  // fail informatively rather than guessing at rules.
}

function get(pathname, timeoutMs, cb) {
  const req = http.get({ host: '127.0.0.1', port, path: pathname, timeout: timeoutMs }, (res) => {
    let body = '';
    res.setEncoding('utf8');
    res.on('data', (c) => (body += c));
    res.on('end', () => {
      try {
        cb(null, JSON.parse(body));
      } catch (e) {
        cb(new Error('unparseable response from ' + pathname));
      }
    });
  });
  req.on('timeout', () => {
    req.destroy();
    cb(new Error('timed out after ' + timeoutMs + 'ms'));
  });
  req.on('error', (e) => cb(e));
}

get('/_health', 5000, (err, health) => {
  if (err) {
    if (JSON_OUT) {
      console.log(JSON.stringify({ running: false, reason: err.message }, null, 2));
    } else {
      console.log('NOT RUNNING on port ' + port + ' (' + err.message + ')');
      console.log('');
      console.log('Nothing is being redacted. Start it with:  npm start');
      console.log('See docs/runbook.md section 1 if it will not start.');
    }
    process.exit(1);
  }

  const r = health.redaction || {};
  const e = health.egress || {};
  const configured = (e.configured || []).length;

  const finish = (check) => {
    if (JSON_OUT) {
      console.log(JSON.stringify({ running: true, redaction: r, egress: e, liveCheck: check || null }, null, 2));
      process.exit(0);
    }

    console.log('proxy        : running (pid ' + health.pid + ', port ' + port + ')');
    console.log(
      'redaction    : ' + r.literals + ' literals, ' + r.patterns + ' pattern-regexes, ' + r.aliases + ' aliases'
    );
    if (!r.literals) console.log('               WARNING: no literals loaded, so your own details are not listed');

    if (configured === 0) {
      console.log('ip masking   : not configured (requests leave from your own address)');
    } else if (check) {
      console.log('ip masking   : ' + (check.masked ? 'ACTIVE' : 'NOT MASKED'));
      console.log('               you appear to be in ' + (check.yourCountry || 'an unknown country'));
      if (check.masked) console.log('               traffic exits via ' + (check.exitCountry || '?') + ' (' + (check.exitAddress || 'address not reported') + ')');
      if (check.exitIsHomeCountry) {
        console.log('               WARNING: the exit is in your home country -- address hidden, location not');
      }
      console.log('               ' + configured + ' endpoint(s) available, ' + check.wentOutDirect + ' request(s) ever went out direct');
      if (check.wentOutDirect > 0) {
        console.log('               WARNING: that many requests left from your real address');
      }
    } else {
      console.log('ip masking   : ' + configured + ' endpoint(s) configured; masking ' + (e.masking === true ? 'confirmed (cached)' : e.masking === false ? 'NOT working' : 'unverified'));
      console.log('               run without --quick for a fresh live probe');
    }

    const res = health.residue;
    if (res) {
      const ago = Math.round((Date.now() - res.at) / 60000);
      console.log('last scrub   : ' + ago + ' min ago, ' + res.rewrote + ' file(s) rewritten' + (res.verifyBad ? ', ' + res.verifyBad + ' VERIFY FAILURES' : ''));
    }

    console.log('');
    console.log('full check   : npm run verify');
    process.exit(0);
  };

  if (QUICK || configured === 0) return finish(null);

  // The live probe opens real connections, so it is slower than /_health.
  get('/_egress/check', 60000, (e2, check) => finish(e2 ? null : check));
});
