'use strict';

// Tests for OS-level supervision and the supervised lifecycle mode.
//
// Nothing here registers a scheduled task. Installing persistence is the
// user's decision and requires their consent, so these tests cover the two
// things that can be verified without it: the launcher script the installer
// would write, and how lifecycle.js behaves when a watchdog runs it instead
// of a Claude Code session.
//
// The launcher tests matter because the PREVIOUS launcher was broken for
// several commits in a way nothing detected: it set WScript's CurrentDirectory
// to a directory that had been renamed away, WScript throws on a missing path,
// and the logon autostart silently became a no-op. A generated script whose
// paths are never checked is a generated script that will eventually point at
// nothing.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFileSync, spawn } = require('child_process');

const SRC = path.join(__dirname, '..');

function tmpHome() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ccr-sup-'));
  return d;
}

// supervise.js reads homedir at require time, so each launcher test runs it in
// a child process with USERPROFILE redirected rather than fighting the module
// cache.
function generateLauncherIn(home) {
  const script = path.join(home, 'gen.js');
  fs.writeFileSync(
    script,
    'const s = require(' + JSON.stringify(path.join(SRC, 'supervise.js')) + ');\n' +
      'process.stdout.write(s.writeLauncher());\n'
  );
  const out = execFileSync(process.execPath, [script], {
    encoding: 'utf8',
    windowsHide: true,
    env: Object.assign({}, process.env, { USERPROFILE: home, HOME: home }),
  });
  return { path: out.trim(), text: fs.readFileSync(out.trim(), 'utf8') };
}

test('launcher does not set a working directory', () => {
  const home = tmpHome();
  try {
    const { text } = generateLauncherIn(home);
    // The exact defect that silently disabled the old logon autostart.
    assert.ok(!/CurrentDirectory/i.test(text), 'launcher must not assign CurrentDirectory');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('launcher creates no console window and does not block', () => {
  const home = tmpHome();
  try {
    const { text } = generateLauncherIn(home);
    // Window style 0 is what makes this invisible; bWaitOnReturn False is what
    // keeps a 5-minute watchdog from holding a wscript host open.
    assert.match(text, /,\s*0\s*,\s*False/, 'must use window style 0 and not wait');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('launcher uses CRLF, which VBS requires', () => {
  const home = tmpHome();
  try {
    const { text } = generateLauncherIn(home);
    assert.ok(text.includes('\r\n'), 'VBS needs CRLF line endings');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('every path inside the launcher actually exists', () => {
  const home = tmpHome();
  try {
    const { text } = generateLauncherIn(home);
    const m = /sh\.Run "(.*)", 0, False/.exec(text);
    assert.ok(m, 'launcher must contain a Run call');
    const inner = m[1].replace(/""/g, '"');
    const quoted = inner.match(/"([^"]+)"/g) || [];
    assert.ok(quoted.length >= 2, 'both the node binary and the script must be quoted');
    for (const q of quoted) {
      const p = q.slice(1, -1);
      assert.ok(fs.existsSync(p), 'launcher path must resolve: ' + p);
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('the Startup entry and the scheduled task run identical content', () => {
  // The logon path and the crash-recovery path are separate mechanisms --
  // the Startup folder (no elevation needed) and Task Scheduler (ONLOGON is
  // refused unelevated, measured: "Access is denied"). Generating both from
  // one function is what stops them drifting; the original failure was a
  // launcher nobody regenerated after a directory rename, which then threw a
  // Windows Script Host dialog at every logon.
  const home = tmpHome();
  try {
    const a = generateLauncherIn(home).text;
    const b = generateLauncherIn(home).text;
    assert.strictEqual(a, b, 'both entry points must be byte-identical');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('launcher invokes lifecycle.js in supervised mode', () => {
  const home = tmpHome();
  try {
    const { text } = generateLauncherIn(home);
    assert.match(text, /lifecycle\.js/);
    // Without this flag the watchdog would apply session-only checks and cry
    // wolf about ANTHROPIC_BASE_URL every five minutes.
    assert.match(text, /--supervised/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ------------------------------------------------- supervised lifecycle mode

// A minimal stand-in for the proxy's /_health, so these tests never depend on
// a real proxy being up.
function fakeProxy(payload) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      if (req.url === '/_health') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(payload));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

function readAudit(home) {
  return fs.readFileSync(path.join(home, '.claude', 'redaction', 'supervisor.log'), 'utf8');
}

// Deliberately async. execFileSync would block this process's event loop, and
// the fake /_health server above lives in THIS process -- so a synchronous
// child could never be served and every test would see ECONNREFUSED. The
// first version of this file made exactly that mistake and blamed the code
// under test for it.
function runLifecycle(args, home, port) {
  const rulesPath = path.join(home, 'rules.json');
  fs.writeFileSync(
    rulesPath,
    JSON.stringify({
      proxy: { port },
      literals: [{ value: 'Testy McTest', category: 'name' }],
      patterns: [],
      residue: { scrub: false },
    })
  );
  const env = Object.assign({}, process.env, {
    USERPROFILE: home,
    HOME: home,
    CCR_RULES_PATH: rulesPath,
  });
  delete env.ANTHROPIC_BASE_URL;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(SRC, 'lifecycle.js')].concat(args), {
      windowsHide: true,
      env,
    });
    let out = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (c) => (out += c));
    child.on('error', reject);
    child.on('close', () => resolve(out));
  });
}

const HEALTHY = {
  ok: true,
  redaction: { literals: 1, patterns: 0, aliases: 0 },
  egress: { configured: ['socks5://x'], tunnelling: true, masking: true, fellBackDirect: 0 },
};

test('supervised mode stays silent on stdout', async () => {
  const home = tmpHome();
  const { srv, port } = await fakeProxy(HEALTHY);
  try {
    const out = await runLifecycle(['start', '--supervised'], home, port);
    // A detached watchdog's stdout goes nowhere. Writing hook JSON into it
    // would be noise, and an empty write is the honest representation.
    assert.strictEqual(out, '', 'supervised runs must not write hook JSON');
  } finally {
    srv.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('supervised mode does not cry wolf about ANTHROPIC_BASE_URL', async () => {
  const home = tmpHome();
  const { srv, port } = await fakeProxy(HEALTHY);
  try {
    await runLifecycle(['start', '--supervised'], home, port);
    const log = readAudit(home);
    // The watchdog is not a session and has no reason to have the variable
    // set. A false alarm every five minutes trains the user to ignore the
    // real one.
    assert.ok(!/REDACTION INACTIVE/.test(log), 'watchdog must not report an inactive session');
    assert.match(log, /"by":"watchdog"/);
  } finally {
    srv.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('session mode still reports a wrong ANTHROPIC_BASE_URL', async () => {
  const home = tmpHome();
  const { srv, port } = await fakeProxy(HEALTHY);
  try {
    const out = await runLifecycle(['start'], home, port);
    // The check must remain live for real sessions: this is the condition
    // under which traffic bypasses the proxy entirely.
    assert.match(out, /REDACTION INACTIVE/);
  } finally {
    srv.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('every run is recorded in the audit log', async () => {
  const home = tmpHome();
  const { srv, port } = await fakeProxy(HEALTHY);
  try {
    await runLifecycle(['start', '--supervised'], home, port);
    await runLifecycle(['start', '--supervised'], home, port);
    const lines = readAudit(home).trim().split(/\r?\n/);
    assert.strictEqual(lines.length, 2, 'one line per run');
    for (const l of lines) {
      const rec = JSON.parse(l);
      assert.ok(rec.t && rec.mode && rec.by && rec.event, 'each record must be complete: ' + l);
    }
  } finally {
    srv.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('audit log records the caveat when protection is incomplete', async () => {
  const home = tmpHome();
  const degraded = {
    ok: true,
    redaction: { literals: 1, patterns: 0, aliases: 0 },
    // No egress endpoint: with fail-closed egress this means a dropped VPN
    // turns into refused requests, which the user must be told about.
    egress: { configured: [], tunnelling: true, masking: null, fellBackDirect: 0 },
  };
  const { srv, port } = await fakeProxy(degraded);
  try {
    await runLifecycle(['start', '--supervised'], home, port);
    assert.match(readAudit(home), /no egress endpoint is available/);
  } finally {
    srv.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('shutdown on a dead port says so instead of killing something', async () => {
  const home = tmpHome();
  // Bind briefly only to obtain a port nothing is listening on, so the test
  // can never depend on 47113 being free -- or, worse, stop a real proxy.
  const { srv, port } = await fakeProxy(HEALTHY);
  await new Promise((r) => srv.close(r));
  try {
    const out = await runLifecycle(['shutdown'], home, port);
    assert.match(out, /[Nn]othing healthy is listening/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('shutdown refuses to act when /_health reports no PID', async () => {
  const home = tmpHome();
  // A proxy that answers but names no process is not something to guess at:
  // killing a PID from a stale source risks killing whatever the OS has since
  // assigned that number to.
  const { srv, port } = await fakeProxy({
    ok: true,
    redaction: { literals: 1, patterns: 0, aliases: 0 },
    egress: { configured: ['socks5://x'], tunnelling: true, masking: true, fellBackDirect: 0 },
  });
  try {
    const out = await runLifecycle(['shutdown'], home, port);
    // The PID-less branch writes to stderr and exits non-zero, so stdout
    // carries no success message.
    assert.ok(!/Stopped the redaction proxy/.test(out), 'must not claim it stopped anything');
  } finally {
    srv.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('a load() failure is reported rather than passing silently', () => {
  const home = tmpHome();
  const rulesPath = path.join(home, 'broken.json');
  fs.writeFileSync(rulesPath, '{ this is not json');
  const env = Object.assign({}, process.env, { USERPROFILE: home, HOME: home, CCR_RULES_PATH: rulesPath });
  delete env.ANTHROPIC_BASE_URL;
  // Synchronous is fine here: this path never reaches the network, because
  // load() fails before any health check is attempted.
  const out = execFileSync(process.execPath, [path.join(SRC, 'lifecycle.js'), 'start'], {
    encoding: 'utf8',
    windowsHide: true,
    env,
  });
  // Failing open here would leave the user believing they were protected.
  assert.match(out, /REDACTION CANNOT START/);
  fs.rmSync(home, { recursive: true, force: true });
});
