#!/usr/bin/env node
'use strict';

// `npm run providers` — which free egress options are available on this
// machine right now, and what are the rest?
//
// Detection completes a real protocol handshake, so an open port that merely
// accepts a connection is never reported as a proxy. That distinction is the
// whole point: a false positive here would be configured as a tunnel and then
// fail closed on every request.

const { createProviders } = require('../providers');

const JSON_OUT = process.argv.includes('--json');

// Optional: a port for anything the catalogue cannot detect without one.
// Cloudflare WARP is the case that matters -- Cloudflare's own documentation
// does not commit to a default local-proxy port, so nothing is guessed.
const portArg = (() => {
  const i = process.argv.indexOf('--warp-port');
  return i !== -1 && process.argv[i + 1] ? Number(process.argv[i + 1]) : null;
})();

const providers = createProviders({
  warn: (m) => {
    if (!JSON_OUT) console.log('  [note] ' + m);
  },
  extra: portArg ? { cloudflareWarp: { port: portArg } } : {},
});

if (!JSON_OUT) console.log('probing for local egress endpoints...');

providers.detect((err, found) => {
  const catalogue = providers.describeAll();

  if (JSON_OUT) {
    console.log(JSON.stringify({ detected: found || [], catalogue, error: err ? err.message : null }, null, 2));
    process.exit(0);
  }

  console.log('');
  if (err) {
    console.log('detection failed: ' + err.message);
  } else if (!found || found.length === 0) {
    console.log('AVAILABLE NOW: none detected on this machine.');
  } else {
    console.log('AVAILABLE NOW:');
    for (const p of found) {
      console.log('  ' + p.id.padEnd(16) + p.egress.label + (p.detail ? '   ' + p.detail : ''));
    }
    console.log('');
    console.log('To use one, put it in ~/.claude/redaction/redact-rules.json:');
    console.log('  "egress": { "mode": "auto", "homeCountry": "XX", "urls": ["' + found[0].egress.label + '"] }');
    console.log('');
    console.log('A configured url always takes priority over auto-detection, which is');
    console.log('what you want: it survives a restart and cannot be displaced.');
  }

  console.log('');
  console.log('ALL OPTIONS:');
  for (const c of catalogue) {
    const live = (found || []).some((f) => f.id === c.id);
    console.log('');
    console.log('  ' + (live ? '[available] ' : '[   -    ] ') + c.id);
    for (const line of String(c.description || '').split('\n')) {
      if (line.trim()) console.log('              ' + line.trim());
    }
  }

  console.log('');
  console.log('Full comparison, including why public proxy lists are not shipped:');
  console.log('  docs/providers.md');
  process.exit(0);
});
