#!/usr/bin/env node
'use strict';

// One entry point for "make sure protection is running", used as Claude Code's
// SessionStart hook.
//
// WHY THIS EXISTS. Starting the proxy has been a manual, ordered ritual: start
// it, confirm /_health, only then start Claude Code. Getting that order wrong
// produced the two worst incidents in this project's history -- both times the
// port was dead while ANTHROPIC_BASE_URL pointed at it, and from inside Claude
// Code a dead port is indistinguishable from a firewall problem. A ritual that
// must be performed correctly every time is a ritual that will be performed
// incorrectly.
//
// So this does the whole thing, idempotently:
//
//   1. is a healthy proxy already listening?          -> done, say nothing
//   2. is something listening but unhealthy/stale?    -> report it, do not fight it
//   3. nothing listening?                             -> start it, WAIT for health
//   4. did it fail to become healthy?                 -> say so LOUDLY
//
// Claude Code shows the user a message only from a top-level `systemMessage`
// field. Any other shape is silently ignored, which would make this hook inert
// -- so the emit contract below is load-bearing, not cosmetic.
//
//   node src/lifecycle.js start     (SessionStart hook)
//   node src/lifecycle.js stop      (SessionEnd hook: final scrub, leave proxy up)
//   node src/lifecycle.js ensure    (same as start, but always prints a verdict)
//   node src/lifecycle.js shutdown  (actually stop the proxy -- see below)

const fs = require('fs');
const os = require('os');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');
const { load } = require('./rules');
const residueLog = require('./residue-log');

const MODE = (process.argv[2] || 'start').toLowerCase();
const ALWAYS_REPORT = MODE === 'ensure';
const ROOT = path.join(__dirname, '..');

// Set when the OS watchdog invokes us (see supervise.js) rather than Claude
// Code. There is no session to show a message to, so the verdict has to go
// somewhere durable instead -- otherwise supervision is invisible, and
// "something restarted the proxy at 3am" is exactly the kind of event that
// needs a record rather than a discarded stdout write.
const SUPERVISED = process.argv.includes('--supervised');
const AUDIT_PATH = path.join(os.homedir(), '.claude', 'redaction', 'supervisor.log');
const AUDIT_MAX_BYTES = 512 * 1024;

function audit(event, detail) {
  try {
    // Trim from the front when it grows, so an every-5-minutes writer cannot
    // fill the disk over months. Keeping the tail keeps recent history, which
    // is the half anyone actually reads.
    try {
      if (fs.statSync(AUDIT_PATH).size > AUDIT_MAX_BYTES) {
        const keep = fs.readFileSync(AUDIT_PATH, 'utf8').split(/\r?\n/).slice(-1000).join('\n');
        fs.writeFileSync(AUDIT_PATH, keep);
      }
    } catch (e) {
      /* no log yet, or unreadable: the append below will create it */
    }
    fs.mkdirSync(path.dirname(AUDIT_PATH), { recursive: true });
    fs.appendFileSync(
      AUDIT_PATH,
      JSON.stringify({ t: new Date().toISOString(), mode: MODE, by: SUPERVISED ? 'watchdog' : 'session', event, detail: detail || null }) + '\n'
    );
  } catch (e) {
    // Never let logging break the thing it is logging about.
  }
}

function emit(msg, event) {
  audit(event || (msg ? 'reported' : 'ok'), msg || null);
  // Only a session start has a reader. Writing hook JSON into a detached
  // watchdog's discarded stdout would be pure noise.
  if (!SUPERVISED) process.stdout.write(msg ? JSON.stringify({ systemMessage: msg }) : '{}');
  process.exit(0);
}

let rules = {};
try {
  rules = load();
} catch (e) {
  emit(
    'REDACTION CANNOT START: ' + (e && e.message ? e.message : 'the rules file could not be read') +
      '. Nothing is being redacted. Fix ~/.claude/redaction/redact-rules.json, then restart this session.'
  );
}

const PORT = (rules.proxy && rules.proxy.port) || 47113;
const EXPECTED_BASE = 'http://127.0.0.1:' + PORT;

function health(timeoutMs, cb) {
  const req = http.get({ host: '127.0.0.1', port: PORT, path: '/_health', timeout: timeoutMs }, (res) => {
    let body = '';
    res.setEncoding('utf8');
    res.on('data', (c) => (body += c));
    res.on('end', () => {
      try {
        const h = JSON.parse(body);
        cb(h && h.ok === true ? null : new Error('/_health did not report ok'), h);
      } catch (e) {
        cb(new Error('unparseable /_health response'));
      }
    });
  });
  req.on('timeout', () => {
    req.destroy();
    cb(new Error('timed out'));
  });
  req.on('error', (e) => cb(e));
}

// Describes what is and is not protected, so a report is never vaguer than the
// data behind it.
function verdict(h) {
  const r = (h && h.redaction) || {};
  const e = (h && h.egress) || {};
  const notes = [];

  if (!r.literals) {
    notes.push('no literals are loaded, so your own details are NOT being redacted');
  }

  const configured = (e.configured || []).length;
  if (configured === 0 && e.tunnelling !== false) {
    // Egress is meant to be active but has nothing to work with. With
    // onFailure "refuse" this means requests will be blocked the moment
    // something else stops masking you.
    notes.push(
      'no egress endpoint is available, so if your VPN drops requests will be REFUSED rather than sent unmasked ' +
        '(run `npm run providers` for free options that are actually dependable)'
    );
  }
  if (e.fellBackDirect > 0) {
    notes.push(e.fellBackDirect + ' request(s) have gone out from your real IP via the "direct" fallback');
  }
  if (e.masking === false && e.tunnelling === true) {
    notes.push('the egress proxy is forwarding your real IP -- treat yourself as unmasked');
  }
  return notes;
}

// Whether an OS-level watchdog is registered. Read directly rather than
// imported from supervise.js so that a missing or broken supervisor module
// can never stop the shutdown path from working.
function taskRegistered() {
  if (process.platform !== 'win32') return false;
  try {
    require('child_process').execFileSync('schtasks.exe', ['/query', '/tn', 'ClaudeRedactionProxy-Watchdog'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    return true;
  } catch (e) {
    return false;
  }
}

function baseUrlWarning() {
  // The watchdog is not a Claude Code session and has no reason to have
  // ANTHROPIC_BASE_URL set. Checking it there would report "REDACTION
  // INACTIVE" every five minutes, for a session that does not exist -- a
  // false alarm frequent enough to train the user to ignore real ones.
  if (SUPERVISED) return null;
  const actual = (process.env.ANTHROPIC_BASE_URL || '').replace(/\/$/, '');
  if (actual === EXPECTED_BASE) return null;
  return (
    'REDACTION INACTIVE: ANTHROPIC_BASE_URL is "' + (actual || '(unset)') + '", expected "' + EXPECTED_BASE +
    '". Requests are going straight to the API and nothing is being redacted.'
  );
}

function report(h) {
  const wrongBase = baseUrlWarning();
  const notes = verdict(h);
  // The base-URL problem outranks everything: if traffic is not coming through
  // the proxy, nothing else about the proxy matters.
  if (wrongBase) emit(wrongBase + (notes.length ? ' Also: ' + notes.join('; ') + '.' : ''));
  if (notes.length) emit('Redaction proxy is running, but: ' + notes.join('; ') + '.');
  if (ALWAYS_REPORT) {
    const r = h.redaction || {};
    emit(
      'Protected: ' + r.literals + ' literals, ' + r.patterns + ' patterns, ' + r.aliases + ' aliases active on port ' + PORT + '.'
    );
  }
  emit(null); // healthy and unremarkable: stay quiet
}

// -------------------------------------------------------------- shutdown

// Deliberately NOT an HTTP route. A /_shutdown endpoint would be reachable by
// any local page that can issue a cross-origin POST to loopback, and because
// egress is fail-closed, killing the proxy turns every subsequent request
// into a refusal -- a denial of service any website could trigger. Doing it
// from the command line keeps that capability where it belongs.
//
// The PID comes from /_health rather than a pidfile, so we can only ever kill
// a process that is currently answering as this proxy on this port. A stale
// pidfile could name a PID the OS has since reused.
if (MODE === 'shutdown') {
  health(2000, (err, h) => {
    if (err) {
      console.log('Nothing healthy is listening on port ' + PORT + ' (' + err.message + '); nothing to stop.');
      process.exit(0);
    }
    if (!h || !h.pid) {
      console.error('The proxy answered but did not report a PID, so it cannot be stopped safely.');
      console.error('Find it with:  netstat -ano | findstr :' + PORT);
      process.exit(1);
    }
    try {
      process.kill(h.pid, 'SIGTERM');
    } catch (e) {
      console.error('Could not stop PID ' + h.pid + ': ' + e.message);
      process.exit(1);
    }
    audit('shutdown', 'stopped proxy pid ' + h.pid + ' on port ' + PORT);
    console.log('Stopped the redaction proxy (pid ' + h.pid + ').');
    // Say this unprompted. The supervisor exists precisely to undo this, and
    // a user who stops the proxy and finds it running again five minutes
    // later should have been told why, not left to discover it.
    if (taskRegistered()) {
      console.log('');
      console.log('NOTE: the watchdog will restart it within 5 minutes.');
      console.log('To keep it stopped:  npm run supervise:uninstall');
    }
    console.log('');
    console.log('Claude Code will now get connection errors until you either restart it');
    console.log('(`npm start`) or remove ANTHROPIC_BASE_URL from your settings.json.');
    process.exit(0);
  });
}

// ------------------------------------------------------------------ stop

if (MODE === 'stop') {
  // Deliberately does NOT stop the proxy. Other sessions may be using it, and
  // a proxy that dies with one window is a proxy that leaves the next session
  // pointing at a dead port -- the exact failure this file exists to prevent.
  // What a session END is good for is scrubbing the transcript it just wrote.
  const residue = rules.residue || {};
  if (!residue.scrub) emit(null);
  try {
    const started = Date.now();
    const child = spawn(
      process.execPath,
      [path.join(ROOT, 'src', 'scrub-residue.js'), '--write', '--quiet', '--no-backup', '--skip-newer-than-min', '0'],
      // stdio piped rather than ignored, so this pass is recorded in the job
      // history like the scheduled one. A session-end scrub that leaves no
      // trace is the one most likely to be blamed later for a change nobody
      // can account for.
      { detached: true, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }
    );
    let out = '';
    child.stdout.on('data', (c) => (out += c));
    child.stderr.on('data', (c) => (out += c));
    child.on('close', (code) => {
      const m = /files rewritten\s*:\s*(\d+)/.exec(out);
      const v = /verify failures\s*:\s*(\d+)/.exec(out);
      residueLog.record({
        trigger: 'session-end',
        ok: code === 0 && !(v && v[1] !== '0'),
        filesRewritten: m ? Number(m[1]) : 0,
        verifyFailures: v ? Number(v[1]) : 0,
        exitCode: code,
        durationMs: Date.now() - started,
        output: out,
      });
    });
    child.unref();
  } catch (e) {
    // A failed scrub must not block session shutdown.
  }
  emit(null);
}

// ----------------------------------------------------------------- start

health(2000, (err, h) => {
  if (!err) return report(h);

  // Nothing healthy is listening. Start it and wait for it to become healthy
  // rather than assuming it will -- reporting success on a process that has
  // not finished starting is how a dead port gets mistaken for a live one.
  let child;
  try {
    child = spawn(process.execPath, [path.join(ROOT, 'src', 'start.js')], {
      detached: true,
      windowsHide: true,
      stdio: 'ignore',
      cwd: ROOT,
    });
    child.unref();
  } catch (e) {
    emit('REDACTION PROXY FAILED TO START: ' + e.message + '. Nothing is being redacted.');
  }

  const deadline = Date.now() + 15000;
  const poll = () => {
    health(1500, (e2, h2) => {
      // Distinguished from a plain healthy check in the audit log: "the
      // watchdog found the proxy dead and revived it" is the single most
      // important line this log can contain, and it must not read the same as
      // "nothing was wrong".
      if (!e2) {
        audit('restarted', 'proxy was not listening on ' + PORT + '; started it and it became healthy');
        return report(h2);
      }
      if (Date.now() > deadline) {
        emit(
          'REDACTION PROXY DID NOT COME UP within 15s on port ' + PORT + ' (' + e2.message + '). ' +
            'Nothing is being redacted. Run `node src/start.js` in a terminal to see why it is refusing to start.',
          'start-failed'
        );
      }
      setTimeout(poll, 500);
    });
  };
  setTimeout(poll, 400);
});
