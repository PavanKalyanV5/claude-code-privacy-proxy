#!/usr/bin/env node
'use strict';

// Makes protection survive failure, without a console window ever appearing.
//
// WHAT WAS WRONG BEFORE THIS FILE
//
// There was no cron and no supervisor. The hourly scrub was a setInterval
// INSIDE the proxy process (start.js), so every schedule died with the
// process that owned it. The only recovery path was a .vbs in the Startup
// folder, which runs at logon and nowhere else -- and which had been silently
// broken since the proxy/ -> src/ rename, because it set CurrentDirectory to a
// directory that no longer existed. WScript throws on that, so the autostart
// had been doing nothing at all.
//
// The failure mode that produces: the proxy dies at 10am, every timer dies
// with it, nothing scrubs, and ANTHROPIC_BASE_URL still points at the dead
// port. Requests are refused -- which is the correct fail-closed behaviour and
// also an outage that nothing recovers from until the user notices.
//
// WHAT THIS DOES INSTEAD
//
// Hands supervision to the operating system, which is already good at it:
//
//   Startup folder -> protection is up before the first session
//   MINUTE/5 task  -> a crash is repaired within five minutes, and this
//                     survives reboot, logoff, and the proxy dying in any way
//
// Both triggers run the same idempotent `lifecycle.js` check, which stays
// silent when the proxy is already healthy, so the 5-minute task is nearly
// free and never restarts a working proxy.
//
// WHY THE STARTUP FOLDER FOR LOGON, AND NOT A SCHEDULED TASK
//
// `schtasks /create /sc ONLOGON` fails with "Access is denied" for a normal
// user, because a logon trigger registers against the machine rather than the
// session and needs elevation. Measured on this machine: the ONLOGON task was
// refused while the MINUTE/5 task registered fine, unelevated, in the same
// run.
//
// The Startup folder needs no elevation at all and is the mechanism Windows
// provides for exactly this. So logon comes from there, crash recovery comes
// from Task Scheduler, and neither one asks the user for admin rights. Both
// files are produced by the same generator below so they cannot drift apart.
//
// WHY A VBS WRAPPER AND NOT node.exe DIRECTLY
//
// A scheduled task that runs a console executable in an interactive desktop
// session flashes a console window, and no amount of windowsHide inside our
// own code can prevent that -- the window is created by the shell that starts
// us, before our code runs. WScript.Shell.Run(cmd, 0, False) with window style
// 0 is the one launcher on Windows that creates no console at all. So the task
// starts the VBS, and the VBS starts node invisibly.
//
//   node src/supervise.js install     register both tasks (no admin needed)
//   node src/supervise.js uninstall   remove them
//   node src/supervise.js status      what is registered, when it last ran

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const STATE_DIR = path.join(os.homedir(), '.claude', 'redaction');
const LAUNCHER = path.join(STATE_DIR, 'ccr-launch.vbs');
const AUDIT = path.join(STATE_DIR, 'supervisor.log');

// Kept only so uninstall can clean up installs made before the logon trigger
// moved to the Startup folder. Never created any more.
const TASK_LOGON = 'ClaudeRedactionProxy-Logon';
const TASK_WATCHDOG = 'ClaudeRedactionProxy-Watchdog';
const WATCHDOG_MINUTES = 5;

const STARTUP_DIR = process.env.APPDATA
  ? path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
  : null;
const STARTUP_VBS = STARTUP_DIR ? path.join(STARTUP_DIR, 'claude-redaction-proxy.vbs') : null;

// Wreckage from earlier attempts. The .bak and .superseded copies are inert
// (Windows only runs .vbs from this folder) but they contain the broken
// CurrentDirectory line, so leaving them invites someone to restore one.
const STALE_STARTUP = STARTUP_DIR
  ? [
      path.join(STARTUP_DIR, 'claude-redaction-proxy.vbs.bak'),
      path.join(STARTUP_DIR, 'claude-redaction-proxy.vbs.superseded'),
    ]
  : [];

function sh(args) {
  // windowsHide matters even here: schtasks is a console program, and without
  // it an install run from a GUI context flashes a window per invocation.
  return execFileSync('schtasks.exe', args, {
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

// schtasks creates every task with DisallowStartIfOnBatteries=true and
// StopIfGoingOnBatteries=true, and offers no command-line flag to change
// either. On a laptop that is not a tuning detail -- it is the difference
// between a watchdog and a decoration. Measured here: the task sat Enabled
// and Ready with a correct action and a "Last Run Time" of 30-11-1999, i.e.
// never, because the machine was on battery the whole time. Windows reports
// no error for this; the run simply does not happen.
//
// A privacy watchdog that only works while plugged in is worse than none,
// because the status output says Enabled either way.
//
// StartWhenAvailable is set too, so a run missed while asleep fires on wake
// rather than waiting for the next interval.
function relaxPowerConstraints(name) {
  if (process.platform !== 'win32') return { ok: true };
  const ps =
    '$ErrorActionPreference="Stop";' +
    'Set-ScheduledTask -TaskName "' + name + '" -Settings ' +
    '(New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable) | Out-Null';
  try {
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      timeout: 30000,
    });
  } catch (e) {
    const msg = (e.stderr || e.stdout || e.message || '').toString().trim().split(/\r?\n/)[0];
    return { ok: false, why: msg };
  }
  // Verify against the registered definition rather than trusting the call.
  try {
    const xml = execFileSync('schtasks.exe', ['/query', '/tn', name, '/xml'], {
      encoding: 'utf8',
      windowsHide: true,
    });
    if (/<DisallowStartIfOnBatteries>true<\/DisallowStartIfOnBatteries>/i.test(xml)) {
      return { ok: false, why: 'the setting did not take effect' };
    }
  } catch (e) {
    return { ok: false, why: 'could not read back the task definition' };
  }
  return { ok: true };
}

function taskExists(name) {
  try {
    sh(['/query', '/tn', name]);
    return true;
  } catch (e) {
    return false;
  }
}

// ------------------------------------------------------------------ launcher

function launcherText() {
  const node = process.execPath;
  const script = path.join(ROOT, 'src', 'lifecycle.js');

  // VBS string literals escape a quote by doubling it. The command therefore
  // needs each embedded path wrapped in a doubled pair, because both the node
  // path and the script path can contain spaces ("Program Files", "Desktop").
  const cmd = '""' + node + '"" ""' + script + '"" start --supervised';

  const vbs = [
    "' Launches the Claude Code redaction lifecycle check with NO console window.",
    "' Generated by src/supervise.js -- delete to disable, or run:",
    "'   node src/supervise.js uninstall",
    "'",
    "' Window style 0 with bWaitOnReturn False is the only way on Windows to",
    "' start a console program with no window at all. A scheduled task running",
    "' node.exe directly would flash one before our own code could hide it.",
    'Set sh = CreateObject("WScript.Shell")',
    // No CurrentDirectory assignment. The previous launcher set it to a
    // directory that had been renamed away, and WScript throws on a missing
    // path -- which is precisely how the logon autostart came to be a no-op.
    // lifecycle.js resolves everything from __dirname, so a working directory
    // is not needed and setting one only creates a way to fail.
    'sh.Run "' + cmd + '", 0, False',
  ].join('\r\n');

  return vbs;
}

// Both the Startup-folder copy and the scheduled task's target come from
// launcherText(), so the two entry points cannot drift apart -- the previous
// design's failure was a launcher nobody regenerated after a rename.
function writeLauncher() {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(LAUNCHER, launcherText(), 'utf8');
  return LAUNCHER;
}

function writeStartupEntry() {
  if (!STARTUP_VBS) return null;
  fs.writeFileSync(STARTUP_VBS, launcherText(), 'utf8');
  return STARTUP_VBS;
}

// ------------------------------------------------------------------- install

function install() {
  if (process.platform !== 'win32') {
    console.error('supervise: Windows only. On Linux/macOS use a systemd user timer or launchd agent');
    console.error('           running: ' + process.execPath + ' ' + path.join(ROOT, 'src', 'lifecycle.js') + ' start');
    process.exit(2);
  }

  const launcher = writeLauncher();
  const out = [];
  let logonOk = false;
  let watchdogOk = false;

  // Logon coverage via the Startup folder. Not a scheduled ONLOGON task:
  // that registers against the machine, needs elevation, and was refused
  // outright ("Access is denied") on this machine while the interval task
  // registered fine in the same run.
  try {
    const p = writeStartupEntry();
    if (p) {
      out.push('  logon    : ' + p);
      logonOk = true;
    } else {
      out.push('  logon    : SKIPPED (no APPDATA in the environment)');
    }
  } catch (e) {
    out.push('  logon    : FAILED to write the Startup entry: ' + e.message);
  }

  // Remove wreckage from earlier installs, including the launcher whose
  // CurrentDirectory pointed at the renamed proxy/ directory and which threw
  // a Windows Script Host error dialog at every logon.
  for (const stale of STALE_STARTUP) {
    try {
      if (fs.existsSync(stale)) {
        fs.unlinkSync(stale);
        out.push('  cleaned  : removed ' + path.basename(stale));
      }
    } catch (e) {
      out.push('  cleaned  : could not remove ' + stale + ': ' + e.message);
    }
  }

  // Crash recovery via Task Scheduler. /rl LIMITED keeps this a normal user
  // task: no elevation to install, and none granted to what it runs. The
  // proxy binds a loopback port and reads files in the user's own profile; it
  // has no business running with more authority than the user who started it.
  try {
    sh([
      '/create', '/tn', TASK_WATCHDOG,
      '/tr', 'wscript.exe "' + launcher + '"',
      '/sc', 'MINUTE', '/mo', String(WATCHDOG_MINUTES),
      '/f', '/rl', 'LIMITED',
    ]);
    out.push('  watchdog : registered ' + TASK_WATCHDOG + ' (every ' + WATCHDOG_MINUTES + ' min)');
    const power = relaxPowerConstraints(TASK_WATCHDOG);
    if (power.ok) {
      out.push('  power    : will run on battery');
      watchdogOk = true;
    } else {
      // Not treated as success. A task that only runs on mains power is a
      // watchdog that is absent exactly when a laptop is most likely to be
      // in use away from a desk.
      out.push('  power    : WARNING -- could not allow battery operation (' + power.why + ')');
      out.push('             the watchdog will NOT run while unplugged');
    }
  } catch (e) {
    const msg = (e.stderr || e.stdout || e.message || '').toString().trim().split(/\r?\n/)[0];
    out.push('  watchdog : FAILED: ' + msg);
  }

  // A stale ONLOGON task from a previous version would now double-start at
  // logon alongside the Startup entry.
  if (taskExists(TASK_LOGON)) {
    try {
      sh(['/delete', '/tn', TASK_LOGON, '/f']);
      out.push('  cleaned  : removed the old ' + TASK_LOGON + ' task');
    } catch (e) {
      /* it may have been created by an admin; leaving it is not harmful */
    }
  }

  console.log('supervisor installed:');
  console.log(out.join('\n'));
  console.log('');
  console.log(
    (logonOk ? '  at logon          -> protection is up before your first session'
             : '  AT LOGON: NOT COVERED -- protection will not start by itself after a reboot')
  );
  console.log(
    (watchdogOk ? '  every ' + WATCHDOG_MINUTES + ' minutes  -> a crashed proxy is restarted within ' + WATCHDOG_MINUTES + ' min'
                : '  CRASH RECOVERY: NOT COVERED -- a dead proxy stays dead until a new session')
  );
  console.log('  no console window is created by either path');
  console.log('');
  console.log('Verify with:  node src/supervise.js status');
  // Exit non-zero when either half is missing, so a partial install cannot be
  // mistaken for a complete one by anything reading the exit code.
  if (!logonOk || !watchdogOk) process.exitCode = 1;
}

function uninstall() {
  const out = [];
  for (const name of [TASK_LOGON, TASK_WATCHDOG]) {
    if (!taskExists(name)) {
      out.push('  ' + name + ' was not registered');
      continue;
    }
    try {
      sh(['/delete', '/tn', name, '/f']);
      out.push('  removed ' + name);
    } catch (e) {
      out.push('  FAILED to remove ' + name + ': ' + e.message);
    }
  }
  for (const p of [LAUNCHER, STARTUP_VBS].concat(STALE_STARTUP)) {
    try {
      if (p && fs.existsSync(p)) {
        fs.unlinkSync(p);
        out.push('  removed ' + p);
      }
    } catch (e) {
      out.push('  could not remove ' + p + ': ' + e.message);
    }
  }
  console.log('supervisor uninstalled:');
  console.log(out.join('\n'));
  console.log('\nProtection now depends on the SessionStart hook alone: a crash');
  console.log('between sessions will go unrepaired until you start a new one.');
}

// -------------------------------------------------------------------- status

function field(text, label) {
  const m = new RegExp('^\\s*' + label + ':\\s*(.*)$', 'im').exec(text);
  return m ? m[1].trim() : null;
}

// Task Scheduler reports "never ran" as a 1999 date plus an HRESULT, neither
// of which reads as ordinary English. Translating the common ones keeps the
// status output from looking like a fault when nothing is wrong.
function explainResult(code) {
  const map = {
    '0': 'ok',
    '267011': 'has not run yet',
    '267009': 'currently running',
    '267014': 'last run was terminated',
    '1': 'the launcher returned an error',
  };
  return map[String(code).trim()] || null;
}

function status() {
  const rows = [];
  for (const name of [TASK_WATCHDOG]) {
    if (!taskExists(name)) {
      rows.push({ name, registered: false });
      continue;
    }
    let v = '';
    try {
      v = sh(['/query', '/tn', name, '/fo', 'LIST', '/v']);
    } catch (e) {
      /* registered but unreadable; report what we know */
    }
    let onBattery = null;
    try {
      const xml = sh(['/query', '/tn', name, '/xml']);
      onBattery = !/<DisallowStartIfOnBatteries>true<\/DisallowStartIfOnBatteries>/i.test(xml);
    } catch (e) {
      /* reported as unknown below rather than guessed at */
    }
    rows.push({
      name,
      registered: true,
      state: field(v, 'Scheduled Task State') || field(v, 'Status'),
      lastRun: field(v, 'Last Run Time'),
      lastResult: field(v, 'Last Result'),
      nextRun: field(v, 'Next Run Time'),
      onBattery,
    });
  }

  const logonCovered = Boolean(STARTUP_VBS && fs.existsSync(STARTUP_VBS));
  const watchdogCovered = rows.some((r) => r.registered);

  if (process.argv.includes('--json')) {
    console.log(
      JSON.stringify(
        {
          logon: { covered: logonCovered, path: logonCovered ? STARTUP_VBS : null },
          tasks: rows,
          launcher: fs.existsSync(LAUNCHER) ? LAUNCHER : null,
        },
        null,
        2
      )
    );
    return;
  }

  console.log('supervisor status');
  console.log('  launcher : ' + (fs.existsSync(LAUNCHER) ? LAUNCHER : 'MISSING -- run `npm run supervise:install`'));
  console.log(
    '  at logon : ' + (logonCovered ? 'covered (' + STARTUP_VBS + ')' : 'NOT COVERED -- nothing starts the proxy after a reboot')
  );
  for (const r of rows) {
    if (!r.registered) {
      console.log('  watchdog : NOT REGISTERED -- a crashed proxy will not be repaired');
      continue;
    }
    const meaning = explainResult(r.lastResult);
    console.log('  watchdog : ' + (r.state || 'unknown') + ' (every ' + WATCHDOG_MINUTES + ' min)');
    console.log(
      '      last run: ' + (r.lastRun || '?') + '   result: ' + (r.lastResult || '?') + (meaning ? ' (' + meaning + ')' : '')
    );
    if (r.nextRun) console.log('      next run: ' + r.nextRun);
    if (r.onBattery === false) {
      // The failure this exists to catch: Enabled, Ready, correct action,
      // and it never runs because the machine is unplugged.
      console.log('      ON BATTERY: WILL NOT RUN -- fix with `npm run supervise:repair`');
    } else if (r.onBattery === true) {
      console.log('      runs on battery: yes');
    }
  }

  // Say plainly what is not covered. A status display that only lists what
  // exists lets a half-installed supervisor read as a working one.
  if (!logonCovered || !watchdogCovered) {
    console.log('');
    if (!logonCovered && !watchdogCovered) {
      console.log('  Nothing supervises the proxy. Run: npm run supervise:install');
    } else if (!logonCovered) {
      console.log('  A reboot will leave you unprotected until you start a session.');
    } else {
      console.log('  A crash between sessions will go unrepaired.');
    }
  }
}

// ---------------------------------------------------------------------- main

// Fixes an ALREADY-registered task in place: rewrites the launcher so it
// points at this copy, and lifts the battery constraint. Separate from
// install because it needs no persistence permission -- the task already
// exists and its action path does not change, only the settings and the
// contents of the .vbs it invokes.
function repair() {
  const launcher = writeLauncher();
  console.log('launcher : ' + launcher);
  try {
    const p = writeStartupEntry();
    if (p) console.log('logon    : ' + p);
  } catch (e) {
    console.log('logon    : FAILED: ' + e.message);
  }
  if (!taskExists(TASK_WATCHDOG)) {
    console.log('watchdog : NOT REGISTERED -- run `npm run supervise:install` first');
    process.exitCode = 1;
    return;
  }
  const power = relaxPowerConstraints(TASK_WATCHDOG);
  if (power.ok) {
    console.log('watchdog : repaired, will now run on battery');
  } else {
    console.log('watchdog : COULD NOT lift the battery restriction (' + power.why + ')');
    console.log('           it will not run while unplugged');
    process.exitCode = 1;
  }
  console.log('');
  console.log('Verify with: npm run supervise');
}

const MODE = (process.argv[2] || 'status').toLowerCase();
if (require.main === module) {
  if (MODE === 'install') install();
  else if (MODE === 'uninstall') uninstall();
  else if (MODE === 'repair') repair();
  else if (MODE === 'status') status();
  else {
    console.error('usage: node src/supervise.js install|uninstall|repair|status [--json]');
    process.exit(2);
  }
}

module.exports = { writeLauncher, taskExists, TASK_LOGON, TASK_WATCHDOG, WATCHDOG_MINUTES, LAUNCHER, AUDIT };
