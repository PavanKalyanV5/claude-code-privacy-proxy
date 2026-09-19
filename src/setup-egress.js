#!/usr/bin/env node
'use strict';

// Gets a working egress tunnel onto this machine, end to end, and only writes
// it into your config once it has been PROVEN to mask you.
//
// WHY NOT "JUST FETCH A PROXY LIST". That was built first and measured. Five
// scraped proxies passed full verification -- TLS-verified connection, echo
// service reporting a different exit address -- and all five refused the NEXT
// connection seconds later. Hit rate was ~6% per refresh, verified latency
// 2.0-6.3s, and dead entries cost a full handshake timeout each on every
// request until demoted. The lesson is not "the code was wrong", it is that
// verification does not predict usability for a resource shared with everyone
// who scraped the same list. No scheduling algorithm fixes that: you cannot
// schedule reliability into a host that disappears. src/pool.js still ships,
// with no default sources, for anyone who wants to opt in explicitly.
//
// Reliability has to come from somewhere real. The two free options that
// actually provide it are an operator who is accountable (Cloudflare) or an
// operator who is you (your own SSH tunnel). This automates the first, since
// the second needs a VM only you can create.
//
// WHY CLOUDFLARE WARP IS AUTOMATABLE NOW. The earlier provider detector
// deliberately refused to guess a WARP port, because Cloudflare's docs do not
// commit to one and community tooling merely assumes 40000. That objection
// disappears when we stop guessing and SET the port ourselves.
//
//   node src/setup-egress.js detect        what is available right now
//   node src/setup-egress.js warp          configure WARP (installs if asked)
//   node src/setup-egress.js warp --install    allow the winget install to run
//   node src/setup-egress.js warp --write      write it to egress.urls once proven
//   node src/setup-egress.js verify <url>  prove any endpoint masks you

const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const { load, RULES_PATH } = require('./rules');
const { parseEgress, createEgressAgent, createHealth, verifyMasking } = require('./egress');

const INSTALL = process.argv.includes('--install');
const WRITE = process.argv.includes('--write');
const PORT = Number(argValue('--port', '40000'));

function argValue(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

function run(cmd, args, timeoutMs = 120000) {
  const r = spawnSync(cmd, args, {
    encoding: 'utf8',
    windowsHide: true,
    timeout: timeoutMs,
  });
  return {
    ok: r.status === 0,
    status: r.status,
    out: ((r.stdout || '') + (r.stderr || '')).trim(),
  };
}

// ------------------------------------------------------------------ locate

const WARP_PATHS = [
  'warp-cli.exe',
  path.join(process.env['ProgramFiles'] || 'C:\\Program Files', 'Cloudflare', 'Cloudflare WARP', 'warp-cli.exe'),
  path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Cloudflare', 'Cloudflare WARP', 'warp-cli.exe'),
];

function findWarp() {
  for (const p of WARP_PATHS) {
    const r = run(p, ['--version'], 15000);
    if (r.ok || /warp/i.test(r.out)) return p;
  }
  return null;
}

function portOpen(port, cb) {
  const s = net.connect({ host: '127.0.0.1', port }, () => {
    s.destroy();
    cb(true);
  });
  s.on('error', () => cb(false));
  s.setTimeout(2000, () => {
    s.destroy();
    cb(false);
  });
}

// ------------------------------------------------------------------ detect

function detect() {
  console.log('checking this machine for egress options...');
  console.log('');
  const warp = findWarp();
  console.log('  Cloudflare WARP : ' + (warp ? 'installed (' + warp + ')' : 'NOT installed'));
  if (!warp) console.log('                    install: winget install --id Cloudflare.Warp --exact');

  const ssh = run('ssh', ['-V'], 10000);
  console.log('  ssh             : ' + (ssh.out ? ssh.out.split('\n')[0] : 'not available'));
  console.log('                    a tunnel needs a host: ssh -D 1080 -N user@your-vps');

  const tor = run('tor', ['--version'], 10000);
  console.log('  Tor             : ' + (tor.ok ? 'installed' : 'NOT installed'));
  console.log('                    many APIs block Tor exits; treat as last resort');

  console.log('');
  let pending = 3;
  const done = () => {
    if (--pending) return;
    console.log('');
    console.log('Recommended: node src/setup-egress.js warp --install');
  };
  for (const [label, p] of [['WARP proxy', PORT], ['ssh SOCKS', 1080], ['Tor SOCKS', 9050]]) {
    portOpen(p, (open) => {
      console.log('  listening on 127.0.0.1:' + String(p).padEnd(6) + ' (' + label + '): ' + (open ? 'YES' : 'no'));
      done();
    });
  }
}

// -------------------------------------------------------------------- warp

// The subcommand spelling changed across client versions (older: `mode proxy`,
// newer: `set-mode proxy`), and Cloudflare does not publish a stable CLI
// contract. Rather than pin a version, try each form and report which worked
// -- a setup tool that breaks on the next client release is not much better
// than no setup tool.
function warpTry(warp, variants, label) {
  for (const args of variants) {
    const r = run(warp, args, 60000);
    if (r.ok) return { ok: true, used: args.join(' ') };
  }
  return { ok: false, why: label + ': none of the known command forms were accepted' };
}

function setupWarp() {
  let warp = findWarp();

  if (!warp) {
    if (!INSTALL) {
      console.log('Cloudflare WARP is not installed.');
      console.log('');
      console.log('It is free, needs no account, and is run by a company with a published');
      console.log('privacy position -- the trade-off is that Cloudflare sees your destinations,');
      console.log('which is a real transfer of trust, just to an accountable party.');
      console.log('');
      console.log('Install it yourself:');
      console.log('  winget install --id Cloudflare.Warp --exact');
      console.log('or re-run this with --install to let it do that for you.');
      process.exit(1);
    }
    console.log('installing Cloudflare WARP via winget...');
    const r = run('winget', ['install', '--id', 'Cloudflare.Warp', '--exact', '--silent',
      '--accept-package-agreements', '--accept-source-agreements'], 600000);
    if (!r.ok) {
      console.error('install failed:\n' + r.out.slice(0, 800));
      process.exit(1);
    }
    warp = findWarp();
    if (!warp) {
      console.error('installed, but warp-cli was not found afterwards. Open a new terminal and re-run.');
      process.exit(1);
    }
    console.log('installed: ' + warp);
  }

  console.log('configuring ' + warp);

  // Wait for the service daemon to answer before configuring anything.
  // Straight after a winget install the binary exists but the daemon is
  // still coming up, and every subcommand fails -- which surfaced as
  // "none of the known command forms were accepted", sending the diagnosis
  // off towards CLI version differences when the forms were in fact correct
  // and simply too early. `status` is the cheapest command that proves the
  // daemon is listening.
  let ready = false;
  for (let i = 0; i < 30; i++) {
    if (run(warp, ['status'], 15000).ok) {
      ready = true;
      break;
    }
    spawnSync(process.execPath, ['-e', 'setTimeout(()=>{},1000)'], { timeout: 2000, windowsHide: true });
  }
  if (!ready) {
    console.error('the WARP service did not respond within ~30s.');
    console.error('It may still be starting after install. Open a new terminal and re-run:');
    console.error('  node src/setup-egress.js warp');
    process.exit(1);
  }

  // Registration is required before any mode change is accepted, and is a
  // no-op when one already exists.
  run(warp, ['--accept-tos', 'registration', 'new'], 90000);

  const mode = warpTry(warp, [
    ['--accept-tos', 'set-mode', 'proxy'],
    ['--accept-tos', 'mode', 'proxy'],
  ], 'proxy mode');
  if (!mode.ok) {
    console.error(mode.why);
    process.exit(1);
  }
  console.log('  mode  : ' + mode.used);

  const setPort = warpTry(warp, [
    ['--accept-tos', 'set-proxy-port', String(PORT)],
    ['--accept-tos', 'proxy', 'port', String(PORT)],
  ], 'proxy port');
  if (!setPort.ok) {
    console.error(setPort.why);
    process.exit(1);
  }
  console.log('  port  : ' + setPort.used);

  const conn = warpTry(warp, [['--accept-tos', 'connect']], 'connect');
  if (!conn.ok) {
    console.error(conn.why);
    process.exit(1);
  }

  // Wait for the listener rather than assuming connect() means ready --
  // reporting success on something that has not finished starting is the
  // single most repeated mistake in this project.
  let tries = 0;
  const wait = () => {
    portOpen(PORT, (open) => {
      if (open) return proveItMasks('socks5://127.0.0.1:' + PORT);
      if (++tries > 20) {
        console.error('WARP connected but nothing is listening on 127.0.0.1:' + PORT + ' after 20s.');
        console.error('Check `' + warp + ' status`, and confirm the proxy port with `' + warp + ' settings`.');
        process.exit(1);
      }
      setTimeout(wait, 1000);
    });
  };
  console.log('  waiting for 127.0.0.1:' + PORT + ' ...');
  setTimeout(wait, 1000);
}

// ------------------------------------------------------------------ verify

// The same verification the proxy itself performs, deliberately: a pass here
// means a pass there, and anything less would be a setup tool that certifies
// something the runtime then rejects.
function proveItMasks(url) {
  const rules = load();
  const ipCheck = (rules.egress && rules.egress.ipCheckUrl) || 'https://api.country.is';

  let spec;
  try {
    spec = parseEgress(url);
  } catch (e) {
    console.error('not a usable endpoint: ' + e.message);
    process.exit(1);
  }

  const health = createHealth();
  const agent = createEgressAgent({ egress: spec, health, warn: () => {} });

  console.log('');
  console.log('verifying ' + url + ' ...');
  verifyMasking(
    { health, agent, url: ipCheck, timeoutMs: 15000, checkDirect: true, warn: (m) => console.log('  ' + m) },
    // ONE argument: the health snapshot. Not (err, result). Getting this
    // wrong made a working tunnel report "FAILED: undefined", because the
    // successful snapshot was being read as an error object.
    (res) => {
      if (!res) {
        console.error('  FAILED: verification produced no result');
        console.error('');
        console.error('Not written to your config. An endpoint that cannot be proven to mask');
        console.error('you is worse than none: it would make the config claim a fallback that');
        console.error('does not exist.');
        process.exit(1);
      }
      const masked = res.masking === true;
      console.log('  tunnel up     : ' + (res.ok === true ? 'yes' : 'no'));
      console.log('  masked        : ' + (masked ? 'YES' : 'NO'));
      if (res.exitIp) console.log('  exit address  : ' + res.exitIp);
      if (res.apparentCountry) console.log('  exit country  : ' + res.apparentCountry);
      if (res.directCountry) console.log('  your country  : ' + res.directCountry);
      if (res.lastError) console.log('  last error    : ' + res.lastError);

      if (!masked) {
        console.error('');
        console.error('The echo service sees the same address as a direct connection, so this');
        console.error('endpoint is forwarding your real IP. Not written.');
        process.exit(1);
      }

      console.log('');
      console.log('PROVEN: traffic through this endpoint leaves from a different address.');
      console.log('');
      if (WRITE) return writeIntoRules(url);
      console.log('Add it with:  node src/setup-egress.js verify ' + url + ' --write');
      console.log('or by hand, in ~/.claude/redaction/redact-rules.json:');
      console.log('');
      console.log('  "egress": { "urls": ["' + url + '"] }');
      process.exit(0);
    }
  );
}

// -------------------------------------------------------------------- write

// Edits the live rules file in place. This process reads and writes it; the
// values never pass through anything else, and the file is backed up first
// because it holds config the user cannot reconstruct from memory.
function writeIntoRules(url) {
  const p = process.env.CCR_RULES_PATH || RULES_PATH;
  let raw;
  try {
    raw = fs.readFileSync(p, 'utf8');
  } catch (e) {
    console.error('could not read ' + p + ': ' + e.message);
    process.exit(1);
  }

  let cfg;
  try {
    cfg = JSON.parse(raw);
  } catch (e) {
    console.error('rules file is not valid JSON; refusing to touch it: ' + e.message);
    process.exit(1);
  }

  cfg.egress = cfg.egress || {};
  const urls = Array.isArray(cfg.egress.urls) ? cfg.egress.urls.slice() : [];
  if (urls.includes(url)) {
    console.log('already present in egress.urls; nothing to do');
    process.exit(0);
  }
  urls.push(url);
  cfg.egress.urls = urls;

  const backup = p + '.backup-egress-' + Date.now() + '.json';
  fs.writeFileSync(backup, raw);
  fs.writeFileSync(p, JSON.stringify(cfg, null, 2) + '\n');

  // Re-read and re-parse, so a corrupted write is caught here rather than at
  // the next proxy start.
  try {
    JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    fs.writeFileSync(p, raw);
    console.error('write produced invalid JSON; restored the original. ' + e.message);
    process.exit(1);
  }

  console.log('added to egress.urls  (backup: ' + path.basename(backup) + ')');
  console.log('egress.urls now has ' + urls.length + ' endpoint(s)');
  console.log('');
  console.log('Restart the proxy for it to take effect:');
  console.log('  npm run stop && npm start      (or wait for the watchdog)');
  process.exit(0);
}

// ---------------------------------------------------------------------- main

const MODE = (process.argv[2] || 'detect').toLowerCase();
if (require.main === module) {
  if (MODE === 'detect') detect();
  else if (MODE === 'warp') setupWarp();
  else if (MODE === 'verify') {
    const url = process.argv[3];
    if (!url || url.startsWith('--')) {
      console.error('usage: node src/setup-egress.js verify socks5://host:port [--write]');
      process.exit(2);
    }
    proveItMasks(url);
  } else {
    console.error('usage: node src/setup-egress.js detect|warp|verify [--install] [--write] [--port N]');
    process.exit(2);
  }
}

module.exports = { findWarp };
