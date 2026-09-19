'use strict';

// Startup tests: run the REAL start.js against fixture configs.
//
// This file exists because of a bug that reached the user. `start.js`
// referenced a `const` before its declaration, inside a ternary that only
// evaluated when `egress.pool.enabled` was true. Every one of the ~300 unit
// tests passed, because every one of them tested a module in isolation and
// nothing ever ran the entry point. The proxy started fine with the pool off
// and threw ReferenceError the moment it was switched on -- discovered live,
// with the port left dead and the session blocked.
//
// The lesson is not "check for TDZ". It is that start.js is where config meets
// wiring, that mistakes there are config-dependent, and that a config
// permutation nobody exercises is a config permutation nobody has tested. So
// this walks the permutations and asserts the proxy comes up and serves
// /_health for each.
//
// Hermetic: CCR_STARTUP_ONLY skips the pool refresh, masking probe and
// pre-warm, so no test here touches the network. Paths are redirected to a
// temp dir so none of them read or write the user's live rules, key or log.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const START = path.join(ROOT, 'src', 'start.js');

// A basic but complete config. Each case overrides pieces of it.
function baseConfig(port) {
  return {
    literals: ['Jane Q. Testerson', 'janeqtest@gmail.com'],
    patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}', flags: 'gi' }],
    aliases: [{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }],
    remoteTools: ['mcp__zen__'],
    normalize: { timezone: true, rewrites: [] },
    deviceId: { mode: 'off' },
    proxy: { port },
  };
}

// A counter starting at a fixed number is not a free port, it is a GUESS.
// It held up locally and then failed in CI with
// `EADDRINUSE: address already in use 127.0.0.1:47506` -- a shared runner has
// no obligation to leave any particular port alone, and a port released
// moments earlier can still be in TIME_WAIT.
//
// Randomising the base makes a collision between concurrently running test
// FILES unlikely, and the retry in startWith handles the rest. Asking the OS
// for a port and then closing it would still race, because the child binds it
// a moment later -- there is no way to hand an already-bound socket to a
// separate process here.
let portSeq = 20000 + Math.floor(Math.random() * 30000);
function freePort() {
  return portSeq++;
}

// Runs start.js in a child process with the given config, then asks /_health.
// A child process rather than require(): a crash at startup is the failure
// mode under test, and it must be observable as an exit code rather than
// taking the test runner down with it.
// Retries on EADDRINUSE with a fresh port. Binding a port is inherently
// racy on a shared machine, and a test that fails for that reason teaches
// nobody anything -- it just trains people to re-run CI until it is green,
// which is how a real flake gets ignored.
function startWith(config, extraEnv = {}, attempt = 0) {
  const res = startOnce(config, extraEnv);
  if (attempt < 4 && /EADDRINUSE/.test(res.out + res.log)) {
    const next = JSON.parse(JSON.stringify(config));
    if (next.proxy) next.proxy.port = freePort();
    return startWith(next, extraEnv, attempt + 1);
  }
  return res;
}

function startOnce(config, extraEnv = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'startt-'));
  const rulesPath = path.join(dir, 'rules.json');
  const keyPath = path.join(dir, 'redact.key');
  const logPath = path.join(dir, 'proxy.log');
  fs.writeFileSync(rulesPath, JSON.stringify(config, null, 2));
  fs.writeFileSync(keyPath, Buffer.alloc(32, 7));

  const env = Object.assign({}, process.env, {
    CCR_RULES_PATH: rulesPath,
    CCR_KEY_PATH: keyPath,
    CCR_LOG_PATH: logPath,
    CCR_STATUS_PATH: path.join(dir, 'status.json'),
    CCR_STARTUP_ONLY: '1',
  }, extraEnv);

  // `node -e` so we can start and immediately report, without the script
  // keeping the process alive on its own timers.
  const code = [
    "const { start } = require(process.argv[1]);",
    "try {",
    "  const s = start();",
    "  s.on('listening', () => { console.log('LISTENING'); try { s.close(); } catch (e) {} process.exit(0); });",
    "  setTimeout(() => { console.log('NEVER_LISTENED'); try { s.close(); } catch (e) {} process.exit(0); }, 10000);",
    "} catch (e) {",
    "  console.log('THREW ' + e.constructor.name + ': ' + e.message);",
    "  process.exit(3);",
    "}",
  ].join('\n');

  const res = spawnSync(process.execPath, ['-e', code, START], {
    env,
    encoding: 'utf8',
    timeout: 20000,
  });
  return {
    status: res.status,
    out: (res.stdout || '') + (res.stderr || ''),
    log: fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8') : '',
  };
}

function expectStarts(name, config, extraEnv) {
  const r = startWith(config, extraEnv);
  assert.ok(!/THREW/.test(r.out), `${name}: start threw -- ${r.out.trim().slice(0, 300)}`);
  assert.strictEqual(r.status, 0, `${name}: exited ${r.status} -- ${r.out.trim().slice(0, 300)}`);
  assert.match(r.out, /LISTENING/, `${name}: never listened -- ${r.out.trim().slice(0, 300)}`);
  return r;
}

// ------------------------------------------------- the permutation matrix

test('starts with egress absent entirely', () => {
  const c = baseConfig(freePort());
  expectStarts('no egress key', c);
});

test('starts with egress mode off', () => {
  const c = baseConfig(freePort());
  c.egress = { mode: 'off' };
  expectStarts('mode off', c);
});

test('starts with egress mode on and a manual proxy url', () => {
  const c = baseConfig(freePort());
  c.egress = { mode: 'on', urls: ['socks5://127.0.0.1:1080'], onFailure: 'refuse' };
  expectStarts('mode on + url', c);
});

test('starts with the POOL enabled and no manual urls', () => {
  // The exact configuration that crashed in production: pool on, urls empty.
  // The crashing line was only evaluated when pool.enabled was true.
  const c = baseConfig(freePort());
  c.egress = {
    mode: 'on',
    urls: [],
    onFailure: 'refuse',
    ipCheckUrl: 'https://api.country.is',
    pool: { enabled: true, want: 3, excludeCountries: ['IN'] },
  };
  expectStarts('pool-only', c);
});

test('starts in auto mode with a home country', () => {
  const c = baseConfig(freePort());
  c.egress = {
    mode: 'auto',
    homeCountry: 'IN',
    urls: [],
    pool: { enabled: true, excludeCountries: ['IN'] },
  };
  expectStarts('auto + pool', c);
});

test('starts with onFailure direct', () => {
  const c = baseConfig(freePort());
  c.egress = { mode: 'on', urls: ['socks5://127.0.0.1:1080'], onFailure: 'direct' };
  const r = expectStarts('onFailure direct', c);
  assert.match(r.log, /onFailure is "direct"/, 'the escape hatch must announce itself');
});

test('starts with device id rewriting enabled', () => {
  const c = baseConfig(freePort());
  c.deviceId = { mode: 'stable' };
  const r = expectStarts('device stable', c);
  assert.match(r.log, /device_id rewriting is ENABLED/);
});

test('starts with a header policy configured', () => {
  const c = baseConfig(freePort());
  c.headers = { keep: ['accept-language'], extra: { 'x-custom': null } };
  expectStarts('header policy', c);
});

test('starts with normalization fully populated', () => {
  const c = baseConfig(freePort());
  c.normalize = {
    timezone: true,
    rewrites: [
      { name: 'os-build', regex: 'Windows (\\d+)(?: [A-Za-z]+)? \\d+\\.\\d+\\.\\d+', flags: 'g', replace: 'Windows $1' },
      { name: 'locale', regex: '\\b[a-z]{2}_[A-Z]{2}\\b', flags: 'g', replace: 'en_US' },
    ],
  };
  expectStarts('full normalize', c);
});

test('starts with no literals and no aliases', () => {
  // Degenerate but legal: it should warn, not crash.
  const c = baseConfig(freePort());
  c.literals = [];
  c.aliases = [];
  const r = expectStarts('empty rules', c);
  assert.match(r.log, /no effective literals/);
  assert.match(r.log, /no aliases configured/);
});

// --------------------------------------------- configs that MUST be rejected

test('auto mode without a home country refuses to start, with a clear message', () => {
  const c = baseConfig(freePort());
  c.egress = { mode: 'auto', urls: [], pool: { enabled: true } };
  const r = startWith(c);
  assert.match(r.out, /THREW/, 'must not start in a mode it cannot evaluate');
  assert.match(r.out, /homeCountry/, `message should name the missing setting -- got ${r.out.trim()}`);
});

test('an invalid onFailure refuses to start rather than guessing', () => {
  const c = baseConfig(freePort());
  c.egress = { mode: 'on', urls: ['socks5://127.0.0.1:1080'], onFailure: 'maybe' };
  const r = startWith(c);
  assert.match(r.out, /THREW/);
  assert.match(r.out, /onFailure/);
});

test('a malformed egress url refuses to start rather than going direct', () => {
  // Silently ignoring this would degrade to an unmasked connection, which is
  // the one outcome the egress config exists to prevent.
  const c = baseConfig(freePort());
  c.egress = { mode: 'on', urls: ['ftp://nope:21'] };
  const r = startWith(c);
  assert.match(r.out, /THREW/);
});

test('a wrong-size master key refuses to start rather than hashing unkeyed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'startk-'));
  const rulesPath = path.join(dir, 'rules.json');
  const keyPath = path.join(dir, 'short.key');
  fs.writeFileSync(rulesPath, JSON.stringify(baseConfig(freePort())));
  fs.writeFileSync(keyPath, Buffer.alloc(8, 1));
  const res = spawnSync(process.execPath, ['-e', "require(process.argv[1]).start()", START], {
    env: Object.assign({}, process.env, {
      CCR_RULES_PATH: rulesPath,
      CCR_KEY_PATH: keyPath,
      CCR_LOG_PATH: path.join(dir, 'p.log'),
      CCR_STARTUP_ONLY: '1',
    }),
    encoding: 'utf8',
    timeout: 20000,
  });
  assert.notStrictEqual(res.status, 0, 'a bad key must be fatal');
  assert.match((res.stdout || '') + (res.stderr || ''), /expected 32|32 bytes/i);
});

test('unparseable rules JSON refuses to start', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'startj-'));
  const rulesPath = path.join(dir, 'rules.json');
  const keyPath = path.join(dir, 'k.key');
  fs.writeFileSync(rulesPath, '{ not json');
  fs.writeFileSync(keyPath, Buffer.alloc(32, 7));
  const res = spawnSync(process.execPath, ['-e', "require(process.argv[1]).start()", START], {
    env: Object.assign({}, process.env, {
      CCR_RULES_PATH: rulesPath,
      CCR_KEY_PATH: keyPath,
      CCR_LOG_PATH: path.join(dir, 'p.log'),
      CCR_STARTUP_ONLY: '1',
    }),
    encoding: 'utf8',
    timeout: 20000,
  });
  assert.notStrictEqual(res.status, 0);
});

test('a risky alias is fatal at startup, not a warning', () => {
  // A risky alias silently rewrites source files on write, and the damage is
  // invisible until someone reads the file much later. Refusing to start
  // forces a safe alias rather than quietly choosing between corrupting files
  // and leaking the real value.
  const RISKY = 'h' + 'o' + 's' + 't'; // built: writing it literally gets un-aliased
  const c = baseConfig(freePort());
  c.aliases = [{ real: 'SOME-MACHINE-NAME', alias: RISKY }];
  const r = startWith(c);
  assert.match(r.out, /THREW/, 'must refuse to start');
  assert.match(r.out, /unsafe alias/, `should name the problem -- got ${r.out.trim().slice(0, 200)}`);
});

test('a distinctive alias starts normally', () => {
  const c = baseConfig(freePort());
  c.aliases = [{ real: 'SOME-MACHINE-NAME', alias: 'MACHINE-A1' }];
  expectStarts('safe alias', c);
});
