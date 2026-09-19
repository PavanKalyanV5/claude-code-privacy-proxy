'use strict';

// Propagates proxy state to the session.
//
// There is no push channel from a local process into a running Claude Code
// session, and the routing of `systemMessage` for mid-session hook events is
// undocumented -- so nothing here depends on it. What IS documented and
// reliable is `statusLine`: a command Claude Code runs on session start and on
// each new assistant message, whose stdout becomes the status line.
//
// So the proxy writes state to a small file and the status line reads it.
// Deliberately a file rather than an HTTP call from the status command:
//   - no network, no timeout, nothing that can hang the status line
//   - the proxy being dead is detected by the file being stale, which is
//     exactly the condition we most need to report
//
// THE LOAD-BEARING RULE: a missing, unreadable or stale file renders as NOT
// PROTECTED. Claiming protection we cannot verify is the one failure mode that
// matters here, because it is silent and the user would have no reason to look.

const fs = require('fs');
const path = require('path');

// How old the file may be before we stop believing it. The proxy heartbeats
// well inside this, so exceeding it means the proxy stopped writing -- which
// in practice means it died.
const STALE_MS = 90 * 1000;
const MAX_NOTICES = 3;

function defaultStatusPath() {
  return path.join(require('os').homedir(), '.claude', 'redaction', 'status.json');
}

// Writes atomically: the status line may read at any moment, and a torn file
// would render as unparseable, i.e. as NOT PROTECTED -- a false alarm.
function writeStatus(statusPath, state) {
  try {
    fs.mkdirSync(path.dirname(statusPath), { recursive: true });
    const tmp = statusPath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state));
    fs.renameSync(tmp, statusPath);
    return true;
  } catch (e) {
    return false;
  }
}

function readStatus(statusPath, now = Date.now()) {
  let raw;
  try {
    raw = fs.readFileSync(statusPath, 'utf8');
  } catch (e) {
    return { ok: false, reason: 'proxy not running' };
  }
  let s;
  try {
    s = JSON.parse(raw);
  } catch (e) {
    return { ok: false, reason: 'status unreadable' };
  }
  if (typeof s.ts !== 'number' || now - s.ts > STALE_MS) {
    return { ok: false, reason: 'proxy not responding' };
  }
  return { ok: true, state: s };
}

// Collects state plus a short ring of recent notices. Notices exist so a
// transient problem -- one failed-over proxy, one unresolved label -- is still
// visible a moment later, rather than only being observable by watching the
// log in real time.
function createStatusWriter({ statusPath = defaultStatusPath(), now = () => Date.now() } = {}) {
  const notices = [];
  let last = null;

  function note(level, text) {
    notices.unshift({ level, text, ts: now() });
    notices.length = Math.min(notices.length, MAX_NOTICES);
  }

  function publish(snapshot) {
    last = Object.assign({ ts: now(), notices: notices.slice() }, snapshot);
    writeStatus(statusPath, last);
    return last;
  }

  return { note, publish, notices, statusPath, get last() { return last; } };
}

// ------------------------------------------------------------------ render

const C = {
  reset: '\u001b[0m',
  green: '\u001b[32m',
  yellow: '\u001b[33m',
  red: '\u001b[31m',
  dim: '\u001b[2m',
};

// Truncate on a word boundary. A hard slice cut mid-word ("...this machine's
// ow"), which reads like the status line itself is broken -- the opposite of
// what a protection indicator should convey.
function clip(text, max) {
  const t = String(text).replace(/\s+/g, ' ').trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const sp = cut.lastIndexOf(' ');
  return (sp > max * 0.6 ? cut.slice(0, sp) : cut).replace(/[,;:]$/, '') + '…';
}

// One line, short enough to sit alongside whatever else is in the status line.
// Colour carries the summary so it is readable at a glance; the text carries
// the detail. Worst state wins: if anything is unprotected, that is the
// headline regardless of what else is fine.
function render(status, { color = true } = {}) {
  const c = (code, s) => (color ? code + s + C.reset : s);

  if (!status.ok) return c(C.red, `⚠ REDACTION OFF (${status.reason})`);

  const s = status.state;
  const parts = [];

  // Redaction: the primary function. Zero rules loaded means it is running but
  // doing nothing, which deserves to look different from healthy.
  const r = s.redaction || {};
  const ruleCount = (r.literals || 0) + (r.patterns || 0);
  parts.push(ruleCount > 0 ? c(C.green, '\u{1f512} redacted') : c(C.red, '⚠ NO RULES'));

  // Egress, when configured at all.
  const e = s.egress || {};
  if (e.configured && e.configured.length) {
    if (e.fellBackDirect > 0) parts.push(c(C.red, `⚠ IP EXPOSED x${e.fellBackDirect}`));
    // The tunnel decision outranks any masking result, and must be checked
    // FIRST. In auto mode the startup probe tunnels before the decision is
    // made, so a stale masking:true sat alongside tunnelling:false -- the line
    // claimed the proxy's exit country while traffic was actually going out
    // directly. Report what is happening now, not what a probe once managed.
    else if (e.tunnelling === false) {
      parts.push(c(C.dim, `direct ${e.directCountry || ''}`.trim() + ' (no tunnel needed)'));
    }
    else if (e.masking === true) parts.push(c(C.green, `ip ${e.apparentCountry || 'masked'}`));
    else if (e.masking === false) parts.push(c(C.red, '⚠ IP NOT MASKED'));
    else parts.push(c(C.yellow, 'ip unverified'));
  }

  const worst = (s.notices || []).find((n) => n.level === 'error') || (s.notices || [])[0];
  if (worst && worst.level !== 'info') {
    parts.push(c(worst.level === 'error' ? C.red : C.yellow, clip(worst.text, 56)));
  }

  return parts.join(c(C.dim, ' · '));
}

module.exports = { createStatusWriter, writeStatus, readStatus, render, defaultStatusPath, STALE_MS, MAX_NOTICES };
