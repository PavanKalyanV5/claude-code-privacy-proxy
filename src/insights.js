'use strict';

// Turns the audit trails into things worth acting on.
//
// WHY. A job history is a list of rows. Rows do not tell you that your
// transcripts started leaking three times as much as usual last Tuesday, or
// that the scrub silently stopped running nine days ago, or that verification
// has failed on every pass this week. Those are the facts that change what
// someone DOES -- and a log that contains them but does not surface them has
// only technically reported them.
//
// Each signal answers: what happened, why it matters, and what to do. A
// finding with no action is an anxiety generator, not an audit tool.
//
// Deliberately conservative. A monitor that cries wolf gets ignored, and an
// ignored monitor is worse than none because it occupies the slot a working
// one would have. Every threshold here needs a real anomaly, not a wobble.

const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 };

function median(xs) {
  if (!xs.length) return 0;
  const s = xs.slice().sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function hoursSince(ts) {
  const t = Date.parse(ts);
  return isNaN(t) ? null : (Date.now() - t) / 3600000;
}

// jobs: newest-first residue job records
// retention: newest-first retention run records
// opts.intervalMinutes: configured scrub interval, for the staleness test
function analyse({ jobs = [], retention = [], intervalMinutes = 60, retentionEnabled = true } = {}) {
  const out = [];
  const add = (severity, title, detail, action) => out.push({ severity, title, detail, action });

  // ---------------------------------------------------------- scrub health

  if (!jobs.length) {
    add(
      'warning',
      'The transcript scrub has never run',
      'Nothing has rewritten the real values already sitting in your transcripts, tool results and edit snapshots. Redaction only protects what is sent from now on; what is on disk stays as it is.',
      'Set "residue": { "scrub": true } in your rules, or run `npm run scrub:apply` once.'
    );
  } else {
    const latest = jobs[0];
    const age = hoursSince(latest.ts);
    // Two missed intervals, floored at 3h, so an hourly job is not reported
    // stale because a laptop was shut for lunch.
    const staleAfter = Math.max(3, (intervalMinutes * 2) / 60);
    if (age !== null && age > staleAfter) {
      add(
        'warning',
        'The scrub has not run in ' + Math.round(age) + ' hours',
        'Expected roughly every ' + intervalMinutes + ' minutes. Each session writes new transcripts containing real values, so the gap is accumulating.',
        'Check the proxy is running (`npm run supervise`) and that residue.scrub is still enabled.'
      );
    }

    // A failure means the pass did NOT finish rewriting. Values remain.
    const recentFailures = jobs.slice(0, 10).filter((j) => j.ok === false).length;
    if (latest.ok === false) {
      add(
        'critical',
        'The most recent scrub FAILED',
        'The last pass did not complete, so real values it was meant to remove are still on disk. Exit code ' + (latest.exitCode == null ? '?' : latest.exitCode) + '.',
        'Open its log in the job history below, then run `npm run scrub` to see the failure in full.'
      );
    } else if (recentFailures >= 3) {
      add(
        'warning',
        recentFailures + ' of the last 10 scrubs failed',
        'The job recovers but is not reliable, so removal of real values is intermittent rather than guaranteed.',
        'Read the logs of the failed runs below; repeated failures usually mean one unreadable or locked file.'
      );
    }

    // Verification failing is more serious than the pass failing: it means
    // the rewrite happened and then did not survive re-reading.
    const verifyBad = jobs.slice(0, 20).reduce((n, j) => n + (Number(j.verifyFailures) || 0), 0);
    if (verifyBad > 0) {
      add(
        'critical',
        'Verification failed on ' + verifyBad + ' file(s)',
        'Files were rewritten and then did not re-parse or still contained values afterwards. This is the one failure mode that can damage data rather than merely leave it exposed.',
        'Do not run further scrubs until this is understood. Backups are in ~/.claude/redaction/residue-backup-*.'
      );
    }

    // ------------------------------------------------------------- spikes

    // A sudden jump in rewritten files means substantially more personal
    // data reached disk than usual -- a habit worth noticing, not just a
    // number. Needs 5 prior runs and a non-trivial baseline before it will
    // fire, so early history and idle machines stay quiet.
    const rewritten = jobs.map((j) => Number(j.filesRewritten) || 0);
    if (rewritten.length >= 6) {
      const current = rewritten[0];
      const base = median(rewritten.slice(1, 11));
      if (base >= 2 && current >= base * 3 && current >= 10) {
        add(
          'warning',
          'Spike: ' + current + ' files rewritten, against a typical ' + base,
          'The most recent pass found roughly ' + Math.round(current / base) + '× the usual amount of personal data on disk. Something in the last session put far more of it into transcripts than normal.',
          'Worth knowing WHAT: run `npm run pii:report` and read the categories. A spike is usually one new kind of value, not more of the old ones.'
        );
      }
    }

    // Steady growth is a different signal from a spike, and a more useful
    // one: it means a habit, not an incident.
    if (rewritten.length >= 10) {
      const recent = median(rewritten.slice(0, 5));
      const older = median(rewritten.slice(5, 15));
      if (older >= 2 && recent >= older * 2) {
        add(
          'info',
          'Upward trend in personal data reaching disk',
          'Recent passes are rewriting about ' + Math.round(recent / older) + '× as many files as earlier ones. This looks like a change in habit rather than a one-off.',
          'If this is new work touching customer or employee data, consider adding those names to your literals so they are redacted in transit, not just cleaned up afterwards.'
        );
      }
    }
  }

  // ------------------------------------------------------- retention health

  if (!retentionEnabled) {
    add(
      'warning',
      'Retention is disabled',
      'Logs, job history and backups will grow without limit. Residue backups are the concern: they are copies of transcripts from BEFORE redaction, so they hold exactly the values the scrub removed.',
      'Set "retention": { "enabled": true } in your rules.'
    );
  } else if (!retention.length) {
    add(
      'info',
      'No retention pass recorded yet',
      'Housekeeping runs a minute after the proxy starts and hourly after that, so this resolves on its own shortly.',
      'Use "Apply retention now" below if you would rather not wait.'
    );
  } else {
    const age = hoursSince(retention[0].ts);
    if (age !== null && age > 6) {
      add(
        'warning',
        'Retention has not run in ' + Math.round(age) + ' hours',
        'It is enforced by the proxy, so this usually means the proxy has not been running rather than that retention itself is broken.',
        'Check `npm run supervise` — the watchdog should be restarting it within 5 minutes.'
      );
    }
    // Large sweeps are worth surfacing: they say a policy is doing real work,
    // and if that is a surprise, the policy may be tighter than intended.
    const freed = retention.slice(0, 5).reduce((n, r) => n + (r.freedBytes || 0), 0);
    const files = retention.slice(0, 5).reduce((n, r) => n + (r.removedFiles || 0), 0);
    if (freed > 20 * 1024 * 1024 || files > 100) {
      add(
        'info',
        'Retention removed a lot recently',
        'The last five passes freed ' + (freed / 1024 / 1024).toFixed(1) + ' MB and removed ' + files + ' file(s).',
        'Expected after a long gap. If it keeps happening, your retention windows may be shorter than you intended.'
      );
    }
  }

  out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return out;
}

module.exports = { analyse };
