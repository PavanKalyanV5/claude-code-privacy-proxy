'use strict';

// Desktop notifications: the one channel left that can speak to the user
// mid-session.
//
// statusLine is confirmed unsupported in the Claude Code VS Code extension
// (terminal-CLI only). SessionStart fires once and cannot speak again. The
// routing of `systemMessage` for mid-session hooks is undocumented, so
// nothing here depends on it. The 502 error body only fires when a request
// actually fails. None of those can say "you just lost IP masking" while the
// session keeps running -- which is exactly the gap that once left this
// session unmasked for seven minutes while status.js still reported
// protected. This module is the fix: an OS-native toast/notification fired
// directly by the proxy process, independent of anything Claude Code reads.
//
// Two properties matter more than anything else here, because a notifier is
// an addition to a security tool and must not become a liability itself:
//
//   1. It can NEVER throw into the caller or crash the proxy. A failed
//      notification is a missed toast; a thrown exception is an outage.
//      Every path below is wrapped so the worst case is "nothing appeared".
//
//   2. The message text is HOSTILE DATA from the moment it leaves this
//      module's control, because it is about to reach either a PowerShell
//      command line or an AppleScript source string. Both are interpreters
//      that a naive "just embed the string" approach would let a crafted
//      message escape. See buildWindows/buildMac for how each avoids ever
//      splicing the message into a parsed string at all.

const { spawn: realSpawn } = require('child_process');

const DEFAULT_MIN_INTERVAL_MS = 5 * 60 * 1000;

// ------------------------------------------------------------- data hygiene
//
// Belt-and-suspenders, not the primary redaction engine: notifications can
// sit on a locked screen and in OS notification history, so nothing that
// looks like an address should ever reach one, even if a future call site
// gets that wrong. Country codes and counts are fine and pass through
// untouched.
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_RE = /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi;

function scrubAddresses(text) {
  const s = text == null ? '' : String(text);
  return s.replace(IPV4_RE, '[address redacted]').replace(IPV6_RE, '[address redacted]');
}

// -------------------------------------------------------------- platform builders
//
// Every builder returns { command, args, options } for child_process.spawn.
// Shared design across all three: spawn is called WITHOUT `shell: true`, so
// there is no shell in the picture to hand argv to for parsing. That alone
// defeats `;`, `&&`, backticks and `$(...)` as far as OS-level command
// injection goes. What remains is the risk that the TARGET interpreter
// (PowerShell, osascript) itself parses part of its own argv/script as code
// and message text ends up inside a parsed string literal. Both Windows and
// macOS builders below route the message through an environment variable
// instead of ever writing it into command-line or script text, so the
// message is never parsed as anything -- it is read as an opaque string
// value at runtime. Linux's notify-send takes the summary/body as plain
// argv with no script/interpreter step at all, so passing it directly is
// already safe under the no-shell rule.

// Windows: BurntToast is not installed and cannot be assumed present, so this
// uses the classic System.Windows.Forms.NotifyIcon balloon-tip API, which
// ships with every stock Windows install as part of .NET Framework (present
// since XP, still present and working on Windows 11) and needs no modules,
// no packaged AppUserModelID and no WinRT activation quirks -- the WinRT
// `Windows.UI.Notifications.ToastNotificationManager` route was considered
// and rejected because it is known to fail from bare Windows PowerShell
// without a registered AppUserModelID, which a script-launched process does
// not have.
//
// The PowerShell SOURCE is a fixed, constant string -- it does not contain
// the title or message anywhere, in any form, for any input. Title, message
// and level travel only through the child's environment block
// (CCR_NOTIFY_*), which PowerShell reads with `$env:NAME` as plain string
// data and assigns straight into .NET properties (`$ni.BalloonTipText = ...`).
// There is no `Invoke-Expression`, no string concatenation into a command,
// no `&` call operator applied to anything derived from the message. A
// message of `"; Remove-Item C:\ -Recurse -Force #` never touches the parser
// at all: it is a value, not source.
//
// -EncodedCommand (base64 of UTF-16LE) is used instead of -Command so the
// script never needs quoting for the outer shell/argv boundary either.
const WINDOWS_SCRIPT = [
  'Add-Type -AssemblyName System.Windows.Forms',
  'Add-Type -AssemblyName System.Drawing',
  '$title = $env:CCR_NOTIFY_TITLE',
  '$text = $env:CCR_NOTIFY_MESSAGE',
  '$lvl = $env:CCR_NOTIFY_LEVEL',
  '$icon = [System.Windows.Forms.ToolTipIcon]::Warning',
  "if ($lvl -eq 'critical') { $icon = [System.Windows.Forms.ToolTipIcon]::Error }",
  '$ni = New-Object System.Windows.Forms.NotifyIcon',
  '$ni.Icon = [System.Drawing.SystemIcons]::Information',
  '$ni.Visible = $true',
  '$ni.BalloonTipTitle = $title',
  '$ni.BalloonTipText = $text',
  '$ni.BalloonTipIcon = $icon',
  '$ni.ShowBalloonTip(10000)',
  'Start-Sleep -Seconds 10',
  '$ni.Dispose()',
].join('\r\n');

function buildWindows(level, title, message, env) {
  const encoded = Buffer.from(WINDOWS_SCRIPT, 'utf16le').toString('base64');
  return {
    command: 'powershell.exe',
    args: ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', encoded],
    options: {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
      env: Object.assign({}, env, {
        CCR_NOTIFY_TITLE: title,
        CCR_NOTIFY_MESSAGE: message,
        CCR_NOTIFY_LEVEL: level,
      }),
    },
  };
}

// macOS: osascript -e with a FIXED script, same reasoning as Windows. AppleScript
// reads the title/message via `system attribute`, which is its documented way
// to read an environment variable as a string -- again, data, never source.
const MAC_SCRIPT =
  'on run\n' +
  '  set msgTitle to system attribute "CCR_NOTIFY_TITLE"\n' +
  '  set msgText to system attribute "CCR_NOTIFY_MESSAGE"\n' +
  '  display notification msgText with title msgTitle\n' +
  'end run';

function buildMac(level, title, message, env) {
  return {
    command: 'osascript',
    args: ['-e', MAC_SCRIPT],
    options: {
      detached: true,
      stdio: 'ignore',
      env: Object.assign({}, env, {
        CCR_NOTIFY_TITLE: title,
        CCR_NOTIFY_MESSAGE: message,
        CCR_NOTIFY_LEVEL: level,
      }),
    },
  };
}

// Linux: notify-send takes summary/body as plain positional argv, no
// interpreter and no script step in between. With no shell involved (spawn,
// not exec/shell:true), the OS hands notify-send the message as one opaque
// argv element via execve; there is nothing downstream to parse `;` or
// backticks as syntax. Passing it directly is therefore already safe.
function buildLinux(level, title, message, env) {
  return {
    command: 'notify-send',
    args: ['--urgency=' + (level === 'critical' ? 'critical' : 'normal'), title, message],
    options: { detached: true, stdio: 'ignore', env: Object.assign({}, env) },
  };
}

function buildCommand(platform, level, title, message, env) {
  if (platform === 'win32') return buildWindows(level, title, message, env);
  if (platform === 'darwin') return buildMac(level, title, message, env);
  if (platform === 'linux') return buildLinux(level, title, message, env);
  throw new Error(`no notification mechanism for platform ${platform}`);
}

// ------------------------------------------------------------------ notifier

function safeWarn(warn, msg) {
  try {
    warn(msg);
  } catch (e) {
    // A broken warn callback must not be allowed to matter either.
  }
}

// createNotifier({ enabled, minIntervalMs, warn, spawn, now }) -> { alert, lastSent }
//
// `spawn` and `now` are injectable purely for tests: production wiring never
// passes them and gets child_process.spawn / Date.now.
function createNotifier({
  enabled = true,
  minIntervalMs = DEFAULT_MIN_INTERVAL_MS,
  warn = () => {},
  spawn = realSpawn,
  now = () => Date.now(),
} = {}) {
  // Keyed on message identity (level+title+message), not just a clock: two
  // DIFFERENT problems must not suppress each other just because one of them
  // fired recently. Exposed directly (not hidden behind a closure) so tests
  // and status reporting can both see what was actually sent and when.
  const lastSent = {};

  function alert(level, title, message) {
    try {
      if (!enabled) return;
      const lvl = level === 'critical' ? 'critical' : 'warn';
      const safeTitle = scrubAddresses(title);
      const safeMessage = scrubAddresses(message);
      const key = lvl + '\u0000' + safeTitle + '\u0000' + safeMessage;
      const t = now();
      const last = lastSent[key];
      if (typeof last === 'number' && t - last < minIntervalMs) return; // rate-limited
      lastSent[key] = t;
      dispatch(lvl, safeTitle, safeMessage);
    } catch (e) {
      safeWarn(warn, `notify: alert failed: ${e && e.message}`);
    }
  }

  function dispatch(level, title, message) {
    let plan;
    try {
      plan = buildCommand(process.platform, level, title, message, process.env);
    } catch (e) {
      safeWarn(warn, `notify: ${e && e.message}`);
      return;
    }
    let child;
    try {
      child = spawn(plan.command, plan.args, plan.options);
    } catch (e) {
      safeWarn(warn, `notify: spawn threw: ${e && e.message}`);
      return;
    }
    try {
      if (child && typeof child.on === 'function') {
        child.on('error', (e) => safeWarn(warn, `notify: spawn error: ${e && e.message}`));
        child.on('exit', (code) => {
          if (code !== 0) safeWarn(warn, `notify: notifier process exited ${code}`);
        });
      }
      if (child && typeof child.unref === 'function') child.unref();
    } catch (e) {
      safeWarn(warn, `notify: post-spawn handling failed: ${e && e.message}`);
    }
  }

  return { alert, lastSent };
}

module.exports = { createNotifier, buildCommand, scrubAddresses };
