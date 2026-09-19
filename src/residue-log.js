'use strict';

// A durable record of every residue pass -- the job that rewrites real values
// out of transcripts, tool results and edit snapshots already on disk.
//
// WHY THIS EXISTS. That job was previously observable only as `lastScrub`, a
// single record held in the proxy's memory. It was lost on every restart, and
// the proxy restarts at logon, on a crash, and whenever the watchdog revives
// it. So the one background job that MODIFIES the user's files had no history
// at all: you could not answer "did it run overnight", "has it ever failed",
// or "when did that file stop containing my phone number".
//
// For a job that rewrites files unattended, that is the wrong thing to have
// no record of. A privacy cleanup you cannot audit is a privacy cleanup you
// are trusting on faith.
//
// One JSON object per line, appended, self-trimming. Deliberately the same
// shape as supervisor.log so both can be read the same way.

const fs = require('fs');
const os = require('os');
const path = require('path');

const MAX_BYTES = 512 * 1024;
const KEEP_LINES = 500;
const KEEP_RUNS = 200; // detail logs retained on disk
const MAX_DETAIL_BYTES = 256 * 1024; // per run, tail-trimmed

function defaultPath() {
  // process.env.HOME first: os.homedir() ignores it on Windows, which has
  // repeatedly caused tests to operate on the real profile.
  return path.join(process.env.HOME || os.homedir(), '.claude', 'redaction', 'residue-jobs.jsonl');
}

// Per-run output lives in its own file rather than inline in the index.
// Inlining would make the index both huge and slow to read for the common
// case -- rendering a list of runs -- when the full output is only wanted
// for the one run someone clicks on.
function runsDir(logPath = defaultPath()) {
  return path.join(path.dirname(logPath), 'residue-runs');
}

function detailPath(id, logPath = defaultPath()) {
  // id is generated here, never taken from a request, but constrain it
  // anyway: this path is reachable from an HTTP route, and a component that
  // can contain ".." is a directory traversal waiting to be introduced by
  // the next person who wires it up.
  const safe = String(id).replace(/[^0-9a-zA-Z_-]/g, '');
  return path.join(runsDir(logPath), safe + '.log');
}

function pruneRuns(logPath = defaultPath()) {
  try {
    const dir = runsDir(logPath);
    const files = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith('.log'))
      .sort();
    for (const f of files.slice(0, Math.max(0, files.length - KEEP_RUNS))) {
      try {
        fs.unlinkSync(path.join(dir, f));
      } catch (e) {
        /* best effort */
      }
    }
  } catch (e) {
    /* no runs dir yet */
  }
}

// The captured output of one run, for auditing what a pass actually did.
function readDetail(id, logPath = defaultPath()) {
  try {
    return fs.readFileSync(detailPath(id, logPath), 'utf8');
  } catch (e) {
    return null;
  }
}

// Never throws. A failure to record must not fail the job being recorded --
// the scrub itself is the thing that matters, and losing one log line is a
// far smaller problem than aborting a pass that was rewriting files.
function record(entry, logPath = defaultPath()) {
  try {
    const p = logPath;
    try {
      if (fs.statSync(p).size > MAX_BYTES) {
        const kept = fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).slice(-KEEP_LINES);
        fs.writeFileSync(p, kept.join('\n') + '\n');
      }
    } catch (e) {
      /* no log yet; the append below creates it */
    }
    fs.mkdirSync(path.dirname(p), { recursive: true });

    const now = new Date();
    // Sortable and unique enough for one machine's job history. Sorting by
    // filename then equals sorting by time, which is what pruneRuns relies on.
    const id = now.toISOString().replace(/[:.]/g, '-') + '-' + Math.random().toString(36).slice(2, 6);

    const { output, ...rest } = entry || {};
    const rec = Object.assign({ ts: now.toISOString(), id }, rest);

    if (typeof output === 'string' && output.length) {
      // Keep the TAIL: a scrub's summary lines are at the end, and a run that
      // produced pages of per-file output is exactly the one whose verdict
      // you need. Truncation is marked so a clipped log is never mistaken
      // for a short one.
      let body = output;
      if (body.length > MAX_DETAIL_BYTES) {
        body = '[... truncated, showing the last ' + MAX_DETAIL_BYTES + ' bytes ...]\n' + body.slice(-MAX_DETAIL_BYTES);
      }
      try {
        fs.mkdirSync(runsDir(p), { recursive: true });
        fs.writeFileSync(detailPath(id, p), body);
        rec.hasLog = true;
        rec.logBytes = body.length;
        pruneRuns(p);
      } catch (e) {
        rec.hasLog = false;
      }
    } else {
      rec.hasLog = false;
    }

    fs.appendFileSync(p, JSON.stringify(rec) + '\n');
    return rec;
  } catch (e) {
    return null;
  }
}

// Newest first, because that is the order anyone reads a job history in.
// Unparseable lines are skipped rather than throwing: a log truncated
// mid-write by a power cut should still be readable.
function read(limit = 50, logPath = defaultPath()) {
  let raw;
  try {
    raw = fs.readFileSync(logPath, 'utf8');
  } catch (e) {
    return [];
  }
  const out = [];
  const lines = raw.split(/\r?\n/).filter(Boolean);
  for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
    try {
      out.push(JSON.parse(lines[i]));
    } catch (e) {
      /* skip */
    }
  }
  return out;
}

// Rolled-up view for the dashboard: enough to answer "is this job healthy"
// without reading every row.
function summary(logPath = defaultPath()) {
  const all = read(500, logPath);
  if (!all.length) return { runs: 0, lastRun: null, lastOk: null, failures: 0, filesRewritten: 0, neverRun: true };
  let failures = 0;
  let filesRewritten = 0;
  let lastOk = null;
  for (const r of all) {
    if (r.ok === false) failures++;
    filesRewritten += Number(r.filesRewritten || 0);
    if (lastOk === null && r.ok === true) lastOk = r.ts;
  }
  return {
    runs: all.length,
    lastRun: all[0].ts,
    lastOk,
    // A job that has not succeeded recently matters more than one that has
    // never run: the second is obviously unconfigured, the first looks fine
    // from the outside while quietly leaving real values on disk.
    lastFailed: all[0].ok === false,
    failures,
    filesRewritten,
    neverRun: false,
  };
}

module.exports = { record, read, summary, readDetail, defaultPath, runsDir };
