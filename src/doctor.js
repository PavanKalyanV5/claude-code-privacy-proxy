#!/usr/bin/env node
'use strict';

// One command that checks the WHOLE chain, in the order a request travels it,
// and says plainly what is not protected.
//
// WHY. Every piece of this system reports on itself -- /_health, the
// dashboard, `npm run verify`, `npm run supervise`, `npm run egress`. None of
// them answers "is the whole thing actually set up correctly", and the two
// worst incidents in this project both happened in the gaps BETWEEN
// components: ANTHROPIC_BASE_URL pointing at a port nothing was listening on,
// and a logon launcher whose working directory had been renamed away. Both
// showed green everywhere you would think to look.
//
// Rules this follows:
//   - unverifiable is reported as NOT verified, never assumed fine
//   - every failure names the command that fixes it
//   - counts and verdicts only, never a personal value, so the output is
//     safe to paste into an issue
//
//   node src/doctor.js            human-readable
//   node src/doctor.js --json     machine-readable

const fs = require('fs');
const os = require('os');
const http = require('http');
const path = require('path');
const { execFileSync } = require('child_process');

const JSON_OUT = process.argv.includes('--json');
const ROOT = path.join(__dirname, '..');
const HOME = process.env.HOME || os.homedir();
const STATE = path.join(HOME, '.claude', 'redaction');

const checks = [];
function add(name, status, detail, fix) {
  checks.push({ name, status, detail: detail || null, fix: fix || null });
}

function sh(cmd, args, timeout = 20000) {
  try {
    return { ok: true, out: execFileSync(cmd, args, { encoding: 'utf8', windowsHide: true, timeout }) };
  } catch (e) {
    return { ok: false, out: ((e.stdout || '') + (e.stderr || '')).toString() };
  }
}

// ------------------------------------------------------------ 1. config

let rules = null;
try {
  rules = require('./rules').load();
  const lits = (rules.literals || []).length;
  const pats = (rules.patterns || []).length;
  const aliases = (rules.aliases || []).length;
  if (!lits && !pats) {
    add('rules load', 'FAIL', 'no literals and no patterns: nothing would be redacted', 'edit ~/.claude/redaction/redact-rules.json');
  } else {
    add('rules load', 'ok', lits + ' literals, ' + pats + ' patterns, ' + aliases + ' aliases');
  }
} catch (e) {
  // This is the single worst state: the proxy cannot start at all, so a
  // restart leaves you with no redaction and a dead port.
  add('rules load', 'FAIL', 'rules file is unreadable or invalid JSON: ' + e.message, 'fix the JSON; the proxy cannot start until you do');
}

try {
  require('./keys').loadMaster();
  add('master key', 'ok', 'present and readable');
} catch (e) {
  add('master key', 'FAIL', e.message, 'see the Install section of the README');
}

// Patterns that would be silently disabled protect nothing.
if (rules) {
  const { isPatternSafe } = require('./rules');
  const bad = [];
  for (const p of rules.patterns || []) {
    if (!p || typeof p.regex !== 'string') continue;
    if (!isPatternSafe(p.regex, p.flags || 'g').ok) bad.push(p.name || '?');
  }
  if (bad.length) add('pattern safety', 'FAIL', bad.length + ' pattern(s) disabled at load: ' + bad.join(', '), 'rewrite or remove them; they currently protect nothing');
  else add('pattern safety', 'ok', 'every configured pattern loads');
}

// ------------------------------------------------------------ 2. routing

const PORT = (rules && rules.proxy && rules.proxy.port) || 47113;
const EXPECTED = 'http://127.0.0.1:' + PORT;

// Read from settings.json rather than this process's env: a doctor run from
// a plain shell has no ANTHROPIC_BASE_URL and would wrongly report it unset.
let settingsBase = null;
try {
  const s = JSON.parse(fs.readFileSync(path.join(HOME, '.claude', 'settings.json'), 'utf8'));
  settingsBase = (s.env && s.env.ANTHROPIC_BASE_URL) || null;
  const hooks = (s.hooks && s.hooks.SessionStart) || [];
  const hasHook = JSON.stringify(hooks).includes('lifecycle.js');
  add(
    'SessionStart hook',
    hasHook ? 'ok' : 'WARN',
    hasHook ? 'lifecycle.js wired' : 'not wired: protection will not start by itself when you open Claude Code',
    hasHook ? null : 'see README "Wire it into Claude Code"'
  );
} catch (e) {
  add('settings.json', 'WARN', 'could not read it: ' + e.message, null);
}

if (settingsBase !== null) {
  const match = settingsBase.replace(/\/$/, '') === EXPECTED;
  add(
    'ANTHROPIC_BASE_URL',
    match ? 'ok' : 'FAIL',
    match ? 'points at the proxy' : 'is "' + settingsBase + '", expected "' + EXPECTED + '" — traffic bypasses redaction entirely',
    match ? null : 'fix it in ~/.claude/settings.json and restart Claude Code'
  );
} else {
  add('ANTHROPIC_BASE_URL', 'FAIL', 'not set in settings.json: nothing is being redacted', 'add it to the env block');
}

// ------------------------------------------------------------ 3. runtime

function health(cb) {
  const req = http.get({ host: '127.0.0.1', port: PORT, path: '/_health', timeout: 4000 }, (res) => {
    let b = '';
    res.on('data', (c) => (b += c));
    res.on('end', () => {
      try {
        cb(null, JSON.parse(b));
      } catch (e) {
        cb(new Error('unparseable /_health'));
      }
    });
  });
  req.on('timeout', () => { req.destroy(); cb(new Error('timed out')); });
  req.on('error', (e) => cb(e));
}

// Can we actually open a TCP connection to a configured egress endpoint
// right now? This is the question "do I have a working fallback" reduces to,
// and it is cheap enough to answer directly rather than infer.
function probeEndpoints(list, cb) {
  const net = require('net');
  if (!list.length) return cb(null, '');
  let pending = list.length;
  let anyOpen = false;
  const notes = [];
  for (const url of list) {
    let host = '127.0.0.1';
    let port = 0;
    try {
      const u = new URL(url);
      host = u.hostname || host;
      port = Number(u.port);
    } catch (e) {
      /* unparseable: counted as closed below */
    }
    if (!port) {
      notes.push('unparseable');
      if (--pending === 0) cb(anyOpen, notes.join(', '));
      continue;
    }
    const s = net.connect({ host, port }, () => {
      s.destroy();
      anyOpen = true;
      notes.push(host + ':' + port + ' open');
      if (--pending === 0) cb(anyOpen, notes.join(', '));
    });
    const fail = () => {
      s.destroy();
      notes.push(host + ':' + port + ' refused');
      if (--pending === 0) cb(anyOpen, notes.join(', '));
    };
    s.on('error', fail);
    s.setTimeout(3000, fail);
  }
}

health((err, h) => {
  if (err) {
    add('proxy listening', 'FAIL', 'nothing healthy on port ' + PORT + ' (' + err.message + ')', 'node src/lifecycle.js ensure');
  } else {
    add('proxy listening', 'ok', 'pid ' + h.pid + ' on ' + PORT);
    const eg = h.egress || {};
    const configured = (eg.configured || []).length;
    return probeEndpoints(eg.configured || [], function (reachable, endpointNote) {
      finishEgress(h, eg, configured, reachable, endpointNote);
    });
  }
  finishEgress(h, {}, 0, null, '');
});

function finishEgress(h, eg, configured, reachable, endpointNote) {
  {
    if (configured === 0) {
      add('egress fallback', 'WARN', 'no tunnel configured: if your VPN drops, requests are REFUSED rather than sent unmasked', 'npm run egress:warp -- --install');
    } else if (reachable === true) {
      // Measured just now by connecting, not read from eg.ok. That field is
      // the result of the last time the proxy USED the tunnel, and in auto
      // mode it may not have tried for hours -- so a recovered tunnel keeps
      // reporting the failure that took it down, and a tunnel that died
      // after a successful probe keeps reporting ok. Neither is the answer
      // to "can I fall back right now".
      add('egress fallback', 'ok', configured + ' endpoint(s), ' + endpointNote);
    } else if (reachable === false) {
      add(
        'egress fallback',
        'FAIL',
        configured + ' endpoint(s) configured but NOT accepting connections (' + endpointNote + ')',
        'start the tunnel, e.g. `warp-cli connect`, then re-run'
      );
    } else if (eg.ok === false) {
      // A configured-but-dead tunnel is worse than none, because you believe
      // you have a fallback. Caught here for real: WARP had silently
      // disconnected, the endpoint was still listed in the config, and an
      // earlier version of this check reported "ok" while the health record
      // it was reading said ok=false.
      add(
        'egress fallback',
        'FAIL',
        configured + ' endpoint(s) configured but NOT reachable' + (eg.lastError ? ' — ' + String(eg.lastError).slice(0, 90) : ''),
        'check the tunnel is up, then: node src/setup-egress.js verify ' + (eg.configured[0] || '')
      );
    } else if (eg.ok !== true) {
      add('egress fallback', 'WARN', configured + ' endpoint(s), not yet verified this session', 'curl http://127.0.0.1:' + PORT + '/_egress/check');
    } else {
      add('egress fallback', 'ok', configured + ' endpoint(s) reachable');
    }

    // Masking is reported separately from the tunnel, because they fail
    // independently: a dead tunnel while a VPN is up is a lost fallback, not
    // an exposure, and conflating them produces either false alarm or false
    // comfort depending on which way you round.
    if (eg.masking === true) {
      add('currently masked', 'ok', eg.externallyMasked ? 'by a VPN or equivalent (tunnel idle by design)' : 'via the tunnel');
    } else if (eg.masking === false) {
      add('currently masked', 'FAIL', 'your real address is reaching the API', 'npm run egress and configure a tunnel');
    } else {
      add('currently masked', 'WARN', 'not verified', 'curl http://127.0.0.1:' + PORT + '/_egress/check');
    }
    if (eg.fellBackDirect > 0) {
      add('unmasked requests', 'FAIL', eg.fellBackDirect + ' request(s) went out from your real IP', 'set egress.onFailure to "refuse"');
    } else {
      add('unmasked requests', 'ok', 'none');
    }
  }

  // --------------------------------------------------------- 4. supervision

  if (process.platform === 'win32') {
    const task = sh('schtasks.exe', ['/query', '/tn', 'ClaudeRedactionProxy-Watchdog', '/xml']);
    if (!task.ok) {
      add('crash recovery', 'WARN', 'no watchdog registered: a crash between sessions goes unrepaired', 'npm run supervise:install');
    } else if (/<DisallowStartIfOnBatteries>true</i.test(task.out)) {
      // Found the hard way: the task sat Enabled and Ready for half an hour
      // without ever running, because the machine was unplugged.
      add('crash recovery', 'FAIL', 'watchdog will NOT run on battery', 'npm run supervise:repair');
    } else {
      add('crash recovery', 'ok', 'watchdog registered and battery-safe');
    }

    const startup = path.join(process.env.APPDATA || '', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'claude-redaction-proxy.vbs');
    add(
      'start at logon',
      fs.existsSync(startup) ? 'ok' : 'WARN',
      fs.existsSync(startup) ? 'Startup entry present' : 'nothing starts the proxy after a reboot',
      fs.existsSync(startup) ? null : 'npm run supervise:install'
    );
  }

  // ----------------------------------------------------------- 5. residue

  try {
    const residueLog = require('./residue-log');
    const sum = residueLog.summary();
    if (!rules || !(rules.residue && rules.residue.scrub)) {
      add('transcript scrub', 'WARN', 'disabled: real values already on disk are never cleaned up', 'set "residue": { "scrub": true }');
    } else if (sum.neverRun) {
      add('transcript scrub', 'WARN', 'enabled but has never run', 'npm run scrub:apply');
    } else if (sum.lastFailed) {
      add('transcript scrub', 'FAIL', 'the most recent pass FAILED; values remain on disk', 'check the job history in the dashboard');
    } else {
      add('transcript scrub', 'ok', sum.runs + ' run(s) recorded, last ' + new Date(sum.lastRun).toLocaleString());
    }
  } catch (e) {
    add('transcript scrub', 'WARN', 'could not read job history: ' + e.message, null);
  }

  // --------------------------------------------------------- 6. retention

  try {
    const retention = require('./retention');
    const pol = retention.policy(rules || {});
    const hist = retention.history(1);
    if (pol.enabled === false) {
      add('log retention', 'WARN', 'disabled: logs and pre-redaction backups grow forever', 'set "retention": { "enabled": true }');
    } else if (!hist.length) {
      add('log retention', 'WARN', 'enabled but no pass recorded yet', 'it runs a minute after the proxy starts');
    } else {
      add('log retention', 'ok', 'last pass ' + new Date(hist[0].ts).toLocaleString());
    }
  } catch (e) {
    add('log retention', 'WARN', 'could not read retention history: ' + e.message, null);
  }

  // --------------------------------------------------------- 7. deployment

  try {
    const deployed = path.join(HOME, '.claude', 'privacy-proxy', 'DEPLOYED.json');
    if (fs.existsSync(deployed)) {
      const d = JSON.parse(fs.readFileSync(deployed, 'utf8'));
      add('deployed copy', 'ok', (d.fileCount || '?') + ' files, commit ' + ((d.git && d.git.commit) || '?') + ((d.git && d.git.dirty) ? ' (dirty)' : ''));
    } else {
      add('deployed copy', 'WARN', 'running from the development tree: editing it changes what protects you', 'node src/deploy.js install');
    }
  } catch (e) {
    add('deployed copy', 'WARN', e.message, null);
  }

  report();
}

function report() {
  if (JSON_OUT) {
    const fails = checks.filter((c) => c.status === 'FAIL').length;
    console.log(JSON.stringify({ checks, fails, warnings: checks.filter((c) => c.status === 'WARN').length }, null, 2));
    process.exit(fails ? 1 : 0);
  }

  const pad = Math.max.apply(null, checks.map((c) => c.name.length));
  console.log('');
  console.log('  REDACTION PROXY — END TO END CHECK');
  console.log('  ' + '-'.repeat(60));
  for (const c of checks) {
    const mark = c.status === 'ok' ? '  ok  ' : c.status === 'WARN' ? ' WARN ' : ' FAIL ';
    console.log('  ' + mark + c.name.padEnd(pad) + '  ' + (c.detail || ''));
    if (c.fix) console.log('  ' + ' '.repeat(6 + pad) + '  -> ' + c.fix);
  }
  const fails = checks.filter((c) => c.status === 'FAIL');
  const warns = checks.filter((c) => c.status === 'WARN');
  console.log('  ' + '-'.repeat(60));
  if (fails.length) {
    console.log('  NOT FULLY PROTECTED: ' + fails.length + ' failure(s), ' + warns.length + ' warning(s)');
  } else if (warns.length) {
    console.log('  PROTECTED, with ' + warns.length + ' thing(s) worth fixing');
  } else {
    console.log('  ALL CHECKS PASSED — every stage of the chain is verified');
  }
  console.log('');
  process.exit(fails.length ? 1 : 0);
}
