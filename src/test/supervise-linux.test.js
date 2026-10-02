'use strict';

// The systemd user units that supervise the proxy on Linux.
//
// Like supervise.test.js, nothing here registers anything: installing
// persistence is the user's decision. These test the two generated unit files,
// which is where the failures live.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const sup = require('../supervise');

const ROOT = path.join(__dirname, '..', '..');

test('the service is a oneshot that runs lifecycle.js in supervised mode', () => {
  const t = sup.serviceUnitText();
  assert.match(t, /^Type=oneshot$/m);
  assert.match(t, /lifecycle\.js" start --supervised$/m);
});

test('the service uses KillMode=process, or the proxy it starts dies with the unit', () => {
  // lifecycle.js revives a dead proxy by spawning it DETACHED and exiting.
  // Under systemd's default KillMode=control-group, every process left in a
  // oneshot's cgroup is killed when the unit ends -- so the watchdog would
  // start the proxy and kill it in the same breath. Measured: a detached child
  // spawned from a oneshot was gone two seconds after the unit finished under
  // the default, and survived under KillMode=process.
  assert.match(sup.serviceUnitText(), /^KillMode=process$/m);
});

test('the service has no WorkingDirectory', () => {
  // The Windows launcher's CurrentDirectory pointed at a renamed directory and
  // silently turned the logon autostart into a no-op. lifecycle.js resolves
  // everything from __dirname, so there is nothing for a directory to do.
  assert.ok(!/WorkingDirectory/.test(sup.serviceUnitText()));
});

test('the service is not itself installed anywhere: only the timer is enabled', () => {
  assert.ok(!/\[Install\]/.test(sup.serviceUnitText()));
});

test('every path the service runs exists', () => {
  const t = sup.serviceUnitText();
  const quoted = [...t.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  assert.ok(quoted.length >= 2, 'node and the script must both be quoted');
  for (const p of quoted) assert.ok(fs.existsSync(p), p + ' must exist');
});

test('paths with spaces, quotes, backslashes and percent signs survive systemd parsing', () => {
  // systemd splits ExecStart on whitespace and expands %-specifiers, so each of
  // these would otherwise silently run a different command.
  assert.strictEqual(sup.unitQuote('/opt/my node/node'), '"/opt/my node/node"');
  assert.strictEqual(sup.unitQuote('/a/50%/b'), '"/a/50%%/b"');
  assert.strictEqual(sup.unitQuote('/a/"q"/b'), '"/a/\\"q\\"/b"');
  assert.strictEqual(sup.unitQuote('/a\\b'), '"/a\\\\b"');
  const t = sup.serviceUnitText('/opt/my node/node', '/srv/a b/50%');
  assert.match(t, /^ExecStart="\/opt\/my node\/node" "\/srv\/a b\/50%%\/src\/lifecycle\.js" start --supervised$/m);
});

test('the timer fires at activation and then every five minutes on the clock', () => {
  const t = sup.timerUnitText();
  assert.match(t, /^OnActiveSec=\d+s$/m);
  assert.match(t, new RegExp('^OnCalendar=\\*:0/' + sup.WATCHDOG_MINUTES + '$', 'm'));
});

test('the timer is not monotonic-after-inactive, which does not count suspended time', () => {
  // A laptop that slept would wait out the whole interval after waking and
  // run unprotected in the meantime. A calendar timer fires on the clock.
  assert.ok(!/OnUnitInactiveSec|OnUnitActiveSec/.test(sup.timerUnitText()));
});

test('the timer is wanted by timers.target, so it comes back at every login', () => {
  assert.match(sup.timerUnitText(), /^\[Install\]\nWantedBy=timers\.target$/m);
});

test('the units are named consistently', () => {
  assert.strictEqual(path.basename(sup.SERVICE_FILE), sup.UNIT_NAME + '.service');
  assert.strictEqual(path.basename(sup.TIMER_FILE), sup.UNIT_NAME + '.timer');
});

test('systemd itself accepts both units', { skip: process.platform !== 'linux' }, (t) => {
  try {
    execFileSync('systemd-analyze', ['--version'], { stdio: 'ignore' });
  } catch (e) {
    return t.skip('systemd-analyze not available');
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ccr-units-'));
  try {
    const svc = path.join(dir, sup.UNIT_NAME + '.service');
    const tmr = path.join(dir, sup.UNIT_NAME + '.timer');
    fs.writeFileSync(svc, sup.serviceUnitText());
    fs.writeFileSync(tmr, sup.timerUnitText());
    // Throws, with systemd's own message, on a malformed unit.
    execFileSync('systemd-analyze', ['--user', 'verify', svc, tmr], { stdio: ['ignore', 'pipe', 'pipe'] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('on Linux, status and install no longer say Windows only', { skip: process.platform !== 'linux' }, () => {
  const src = fs.readFileSync(path.join(ROOT, 'src', 'supervise.js'), 'utf8');
  assert.ok(!/Windows only\./.test(src), 'the old unsupported-platform message must be gone');
});
