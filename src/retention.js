'use strict';

// One retention policy for every file this tool writes.
//
// WHY CENTRAL. Retention had been improvised per-writer: the audit log grew
// unbounded, supervisor.log self-trimmed at 512KB, the residue index grew
// with the filesystem, and backups accumulated forever. Four different
// answers to the same question, none of them visible to the user and none of
// them configurable. For a privacy tool that is the wrong default twice over
// -- old records are both a disk problem and a data-exposure problem, since
// every one of these files describes what was on this machine and when.
//
// So: one config block, one enforcement pass, one place to look.
//
//   "retention": {
//     "auditLogMB": 5,          proxy request log, trimmed by size
//     "supervisorDays": 14,     lifecycle/watchdog events
//     "residueJobsDays": 90,    scrub job history (the audit trail)
//     "residueRunsKeep": 200,   per-run captured output
//     "backupsDays": 30,        rules backups and residue backups
//     "enabled": true
//   }
//
// Everything is optional; the defaults below apply when absent. A value of 0
// or null means "keep forever" and is reported as such rather than silently
// treated as "delete everything", which is the failure mode that turns a
// housekeeping feature into data loss.

const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULTS = {
  enabled: true,
  auditLogMB: 5,
  supervisorDays: 14,
  residueJobsDays: 90,
  residueRunsKeep: 200,
  backupsDays: 30,
  // The retention log governs itself. A housekeeping feature that exempts
  // its own output is how you end up with one file that grows forever.
  retentionLogDays: 30,
  // Raw change logs hold the actual values a scrub removed, so they get the
  // SHORTEST window of anything here by default. They exist to answer "what
  // exactly did that pass rewrite" in the days after it ran; keeping them
  // beyond that turns an audit aid into a standing copy of the data the
  // scrub was run to delete.
  rawLogDays: 7,
};

const RETENTION_LOG = 'retention-log.jsonl';

function stateDir() {
  return path.join(process.env.HOME || os.homedir(), '.claude', 'redaction');
}

function policy(rules) {
  const cfg = (rules && rules.retention) || {};
  const out = Object.assign({}, DEFAULTS);
  for (const k of Object.keys(DEFAULTS)) {
    if (cfg[k] !== undefined) out[k] = cfg[k];
  }
  return out;
}

function safeStat(p) {
  try {
    return fs.statSync(p);
  } catch (e) {
    return null;
  }
}

function olderThanDays(stat, days) {
  if (!days || days <= 0) return false; // 0/null = keep forever
  return Date.now() - stat.mtimeMs > days * 86400000;
}

// ------------------------------------------------------------------ trims

// Size-trim a line-oriented log, keeping the TAIL. Recent entries are the
// ones anyone reads, and truncating from the front preserves the ability to
// answer "what happened just now" at the cost of ancient history.
function trimBySize(p, maxBytes, keepFraction = 0.6) {
  const st = safeStat(p);
  if (!st || !maxBytes || st.size <= maxBytes) return 0;
  try {
    const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean);
    // Keep roughly keepFraction of the budget so this does not re-trim on
    // every single append once the file sits at the limit.
    let kept = [];
    let bytes = 0;
    for (let i = lines.length - 1; i >= 0; i--) {
      bytes += lines[i].length + 1;
      if (bytes > maxBytes * keepFraction) break;
      kept.push(lines[i]);
    }
    kept = kept.reverse();
    fs.writeFileSync(p, kept.length ? kept.join('\n') + '\n' : '');
    return st.size - (safeStat(p) || { size: 0 }).size;
  } catch (e) {
    return 0;
  }
}

// Age-trim a JSONL log by each record's own timestamp, not the file's mtime:
// an append-only file is always "recently modified", so mtime would never
// expire anything.
function trimByAge(p, days, tsField = 'ts') {
  if (!days || days <= 0) return 0;
  const st = safeStat(p);
  if (!st) return 0;
  const cutoff = Date.now() - days * 86400000;
  try {
    const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean);
    const kept = lines.filter((l) => {
      try {
        const rec = JSON.parse(l);
        const t = Date.parse(rec[tsField] || rec.t || '');
        return isNaN(t) ? true : t >= cutoff; // undated lines are kept, not guessed at
      } catch (e) {
        return true; // unparseable lines are kept: deleting what you cannot read is not housekeeping
      }
    });
    if (kept.length === lines.length) return 0;
    fs.writeFileSync(p, kept.length ? kept.join('\n') + '\n' : '');
    return lines.length - kept.length;
  } catch (e) {
    return 0;
  }
}

function pruneDirByCount(dir, keep, suffix) {
  if (!keep || keep <= 0) return 0;
  try {
    const files = fs
      .readdirSync(dir)
      .filter((f) => !suffix || f.endsWith(suffix))
      .sort();
    let removed = 0;
    for (const f of files.slice(0, Math.max(0, files.length - keep))) {
      try {
        fs.unlinkSync(path.join(dir, f));
        removed++;
      } catch (e) {
        /* best effort */
      }
    }
    return removed;
  } catch (e) {
    return 0;
  }
}

function pruneByAge(dir, days, match) {
  if (!days || days <= 0) return 0;
  let removed = 0;
  try {
    for (const name of fs.readdirSync(dir)) {
      if (match && !match.test(name)) continue;
      const p = path.join(dir, name);
      const st = safeStat(p);
      if (!st || !olderThanDays(st, days)) continue;
      try {
        if (st.isDirectory()) fs.rmSync(p, { recursive: true, force: true });
        else fs.unlinkSync(p);
        removed++;
      } catch (e) {
        /* best effort */
      }
    }
  } catch (e) {
    /* no dir */
  }
  return removed;
}

// ----------------------------------------------------------------- enforce

// Records what a pass DID, including passes that did nothing.
//
// A "nothing to remove" entry is not noise -- it is the evidence that the
// sweep ran at all. Without it, a retention system that silently stopped
// working looks identical to one with nothing to do, and the user has no way
// to tell which they have. That is the same failure as the watchdog that sat
// Enabled for half an hour without ever firing.
//
// Contents are counts, file names and byte totals. No file CONTENTS are read
// or recorded, so this log can never itself become a place personal data
// accumulates -- which would be a self-defeating way to implement a data
// retention policy.
function recordRun(result, dir = stateDir()) {
  try {
    const p = path.join(dir, RETENTION_LOG);
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(
      p,
      JSON.stringify({
        ts: new Date().toISOString(),
        trigger: result.trigger || 'scheduled',
        enabled: result.enabled !== false,
        actionCount: (result.actions || []).length,
        actions: result.actions || [],
        freedBytes: (result.actions || []).reduce((n, a) => n + (a.freedBytes || 0), 0),
        removedRecords: (result.actions || []).reduce((n, a) => n + (a.removedRecords || 0), 0),
        removedFiles: (result.actions || []).reduce((n, a) => n + (a.removedFiles || 0), 0),
      }) + '\n'
    );
  } catch (e) {
    /* logging a cleanup must never break the cleanup */
  }
}

function history(limit = 100, dir = stateDir()) {
  let raw;
  try {
    raw = fs.readFileSync(path.join(dir, RETENTION_LOG), 'utf8');
  } catch (e) {
    return [];
  }
  const lines = raw.split(/\r?\n/).filter(Boolean);
  const out = [];
  for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
    try {
      out.push(JSON.parse(lines[i]));
    } catch (e) {
      /* skip unreadable */
    }
  }
  return out;
}

function enforce(rules, dir = stateDir(), opts = {}) {
  const p = policy(rules);
  const actions = [];
  if (p.enabled === false) {
    const off = { enabled: false, actions, trigger: opts.trigger };
    // Recorded even when disabled, so "why has nothing been cleaned up?" has
    // an answer in the same place as everything else.
    recordRun(off, dir);
    return off;
  }

  const audit = path.join(dir, 'redact-proxy.log');
  const bytes = trimBySize(audit, (p.auditLogMB || 0) * 1024 * 1024);
  if (bytes > 0) actions.push({ target: 'redact-proxy.log', freedBytes: bytes });

  const sup = trimByAge(path.join(dir, 'supervisor.log'), p.supervisorDays, 't');
  if (sup > 0) actions.push({ target: 'supervisor.log', removedRecords: sup });

  const jobs = trimByAge(path.join(dir, 'residue-jobs.jsonl'), p.residueJobsDays, 'ts');
  if (jobs > 0) actions.push({ target: 'residue-jobs.jsonl', removedRecords: jobs });

  const runs = pruneDirByCount(path.join(dir, 'residue-runs'), p.residueRunsKeep, '.log');
  if (runs > 0) actions.push({ target: 'residue-runs/', removedFiles: runs });

  // Raw change logs, by AGE rather than by count. Count-based retention on
  // this one would be wrong: a quiet month leaves the oldest raw values
  // sitting there indefinitely simply because nothing newer displaced them,
  // and "how many files ago" is not how anyone reasons about how long a copy
  // of their personal data has existed.
  const rawByAge = pruneByAge(path.join(dir, 'residue-runs'), p.rawLogDays, /\.raw\.jsonl$/i);
  if (rawByAge > 0) actions.push({ target: 'residue-runs/*.raw.jsonl', removedFiles: rawByAge });

  // Manifests carry no values, so they follow the run-log policy.
  const manifests = pruneDirByCount(path.join(dir, 'residue-runs'), p.residueRunsKeep, '.manifest.json');
  if (manifests > 0) actions.push({ target: 'residue-runs/*.manifest.json', removedFiles: manifests });

  // Backups: rules snapshots and residue backup trees. These are the highest
  // value to keep briefly and the highest risk to keep forever -- a residue
  // backup is a verbatim copy of transcripts BEFORE redaction, so it holds
  // exactly the values the scrub was run to remove.
  const backups =
    pruneByAge(dir, p.backupsDays, /^redact-rules\..*backup.*\.json$/i) +
    pruneByAge(dir, p.backupsDays, /^residue-backup-/i);
  if (backups > 0) actions.push({ target: 'backups', removedFiles: backups });

  const rlog = trimByAge(path.join(dir, RETENTION_LOG), p.retentionLogDays, 'ts');
  if (rlog > 0) actions.push({ target: RETENTION_LOG, removedRecords: rlog });

  const result = { enabled: true, policy: p, actions, trigger: opts.trigger };
  recordRun(result, dir);
  return result;
}

// -------------------------------------------------------------- describe

// What exists right now and what governs it, for the dashboard. Reports
// sizes and counts only -- never contents.
function describe(rules, dir = stateDir()) {
  const p = policy(rules);
  const item = (label, file, rule) => {
    const full = path.join(dir, file);
    const st = safeStat(full);
    let records = null;
    if (st && st.isFile() && /\.(jsonl|log)$/.test(file)) {
      try {
        records = fs.readFileSync(full, 'utf8').split(/\r?\n/).filter(Boolean).length;
      } catch (e) {
        /* unreadable */
      }
    }
    return {
      label,
      file,
      exists: Boolean(st),
      bytes: st ? (st.isDirectory() ? null : st.size) : 0,
      records,
      modified: st ? new Date(st.mtimeMs).toISOString() : null,
      rule,
    };
  };

  let runFiles = 0;
  let rawFiles = 0;
  try {
    const names = fs.readdirSync(path.join(dir, 'residue-runs'));
    runFiles = names.filter((f) => f.endsWith('.log')).length;
    rawFiles = names.filter((f) => f.endsWith('.raw.jsonl')).length;
  } catch (e) {
    /* none yet */
  }

  const never = (v) => (!v || v <= 0 ? 'kept forever' : null);

  return {
    enabled: p.enabled !== false,
    policy: p,
    items: [
      item('Proxy request log', 'redact-proxy.log', never(p.auditLogMB) || 'trimmed above ' + p.auditLogMB + ' MB'),
      item('Lifecycle / watchdog', 'supervisor.log', never(p.supervisorDays) || 'records older than ' + p.supervisorDays + ' days removed'),
      item('Residue job history', 'residue-jobs.jsonl', never(p.residueJobsDays) || 'records older than ' + p.residueJobsDays + ' days removed'),
      Object.assign(item('Per-run scrub logs', 'residue-runs', never(p.residueRunsKeep) || 'newest ' + p.residueRunsKeep + ' kept'), { records: runFiles }),
      Object.assign(
        item('Raw change logs', 'residue-runs', never(p.rawLogDays) || 'deleted after ' + p.rawLogDays + ' days — CONTAINS REAL VALUES'),
        { records: rawFiles, sensitive: true }
      ),
      item('Residue index', 'residue-index.json', 'rebuilt automatically when rules change'),
    ],
    backups: {
      rule: never(p.backupsDays) || 'removed after ' + p.backupsDays + ' days',
      warning:
        'Residue backups contain transcripts as they were BEFORE redaction, so they hold exactly the values the scrub removed.',
    },
  };
}

module.exports = { enforce, describe, policy, history, recordRun, DEFAULTS, stateDir, RETENTION_LOG };
