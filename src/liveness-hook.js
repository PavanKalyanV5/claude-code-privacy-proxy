#!/usr/bin/env node
'use strict';

// SessionStart hook. Verifies Claude Code is actually routed through the proxy.
// Silent unprotected operation is the specific failure this guards against.
//
// Claude Code shows the user a message ONLY from a top-level `systemMessage`
// field. Any other JSON shape is ignored, which would make this hook inert --
// so the emit contract below is load-bearing, not cosmetic.

const http = require('http');
const { load } = require('./rules');

function emit(msg) {
  process.stdout.write(msg ? JSON.stringify({ systemMessage: msg }) : '{}');
  process.exit(0);
}

// A healthy proxy reports nothing UNLESS the IP masking it was asked to do is
// not happening. Silence has to mean "protected on every axis you configured",
// otherwise it trains you to ignore the hook -- so a working tunnel is quiet,
// and a configured-but-not-masking tunnel is loud.
function summarize(h) {
  const e = h.egress;
  if (!e || !e.configured || e.configured.length === 0) return null; // egress off by choice

  if (e.fellBackDirect > 0) {
    return (
      `IP EXPOSED: the egress tunnel failed ${e.fellBackDirect} time(s) and those requests went out from your ` +
      'real address, because egress.onFailure is set to "direct". Personal data was still redacted. ' +
      'Set it to "refuse" if you would rather be blocked than unmasked.'
    );
  }
  if (e.masking === false) {
    return (
      `IP NOT MASKED: the egress proxy is forwarding your real address (${e.apparentIp}). ` +
      'Personal data is still redacted, but your IP and location are exposed.'
    );
  }
  if (e.ok === false) {
    return (
      `EGRESS TUNNEL DOWN (${e.configured.length} configured, none working; last error: ${e.lastError}). ` +
      'Requests are being REFUSED rather than sent unmasked -- expect connection errors until a proxy is reachable.'
    );
  }
  if (e.masking === null && e.ok === null) {
    return `EGRESS NOT YET EXERCISED: ${e.configured.length} prox${e.configured.length === 1 ? 'y' : 'ies'} configured but masking is unverified.`;
  }
  return null; // tunnelled and verified
}

let port = 47113;
try {
  const r = load();
  if (r.proxy && r.proxy.port) port = r.proxy.port;
} catch (e) {
  /* fall back to the default */
}

// Lets a caller point the health check at a specific port without touching
// config -- currently used only by the test suite, so it can target a port
// it knows for certain is closed (or has bound itself) instead of the real
// 47113, which may have an actual dev proxy listening on it.
if (process.env.CCR_PROXY_PORT) {
  const envPort = Number(process.env.CCR_PROXY_PORT);
  if (Number.isInteger(envPort) && envPort > 0) port = envPort;
}

const expected = `http://127.0.0.1:${port}`;
const actual = process.env.ANTHROPIC_BASE_URL || '';

if (actual.replace(/\/$/, '') !== expected) {
  emit(
    `REDACTION INACTIVE: ANTHROPIC_BASE_URL is "${actual || '(unset)'}", expected "${expected}". ` +
      'Requests are going directly to the API and nothing is being redacted.'
  );
}

const req = http.get({ host: '127.0.0.1', port, path: '/_health', timeout: 2000 }, (res) => {
  const chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => {
    try {
      const h = JSON.parse(Buffer.concat(chunks).toString());
      if (h.ok === true) return emit(summarize(h));
    } catch (e) {
      /* fall through */
    }
    emit(`REDACTION PROXY UNHEALTHY on port ${port}: /_health did not report ok.`);
  });
});
req.on('timeout', () => { req.destroy(); emit(`REDACTION PROXY NOT RESPONDING on port ${port}.`); });
req.on('error', (e) => emit(`REDACTION PROXY NOT RUNNING on port ${port} (${e.code}).`));
