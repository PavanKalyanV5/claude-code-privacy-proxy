#!/usr/bin/env node
'use strict';

// PHASE 4: rewrite local residue as the model saw it.
//
// Transcripts, file-history snapshots and shell snapshots are written before
// the proxy ever sees them, so they hold real values. Scrubbing them is
// exactly the same operation the proxy performs outbound -- redact, alias,
// normalize -- so this reuses renderForModel with the REAL key. Two
// consequences worth stating:
//
//   * the labels written here are byte-identical to the ones the proxy would
//     have sent for the same value, because labels are keyed HMACs and the key
//     is the same one
//   * `--resume` keeps working and stays coherent, because a label is what the
//     model would have been shown anyway
//
// SAFETY, in order of how much it matters:
//   1. Dry run unless --write. The dry run reports exactly what would change.
//   2. Backs up every file it modifies before touching it (--no-backup opts
//      out, and prints what you are giving up).
//   3. Skips anything modified recently, so it can never rewrite the
//      transcript of the session you are sitting in. That file is open and
//      being appended to; rewriting it would corrupt the conversation.
//   4. JSONL is parsed per line and re-serialized. A line that does not parse
//      is left untouched rather than guessed at. Text replacement across a
//      JSONL file would be faster and would eventually produce a file Claude
//      Code cannot read.
//   5. Verifies after writing that every line still parses.
//
//   node src/scrub-residue.js                  dry run
//   node src/scrub-residue.js --write          apply
//   node src/scrub-residue.js --write --quiet  apply, summary only
//   --skip-newer-than-min N   default 60
//   --no-backup
//   --no-index                force a full pass, ignoring any on-disk index
//   --rebuild-index            discard the on-disk index and rebuild it

const fs = require('fs');
const os = require('os');
const path = require('path');
const { load, compile } = require('./rules');
const { compileAliases } = require('./aliases');
const { compileNormalizers } = require('./normalize');
const { loadMaster, subkey, restrictAcl } = require('./keys');
const { renderForModel } = require('./pipeline');
const { redactWithSpans } = require('./spans');
const { createIndex, computeRulesFingerprint } = require('./residue-index');

const argv = process.argv.slice(2);
const WRITE = argv.includes('--write');
const QUIET = argv.includes('--quiet');
// Writes a complete per-file record of what this pass changed. Needed
// because the summary answers "how many" and an audit needs "which" -- and
// because the scheduled pass runs with --no-backup, so there is no
// before-copy to diff against afterwards. The manifest is the only durable
// evidence of what a pass actually touched.
const MANIFEST = (() => {
  const i = argv.indexOf('--manifest');
  return i !== -1 && argv[i + 1] ? argv[i + 1] : null;
})();
// The raw change log: every individual value replaced, with the label it
// became. This is the only record that answers "what exactly did it rewrite"
// -- and it is therefore a concentrated copy of the data the scrub removed.
//
// So it is treated like the master key, not like a log: written 0600 with
// inheritance stripped, never echoed to the console, governed by its own
// (short) retention window, and off by default. The manifest above is the
// safe default; this is the opt-in for when counts are not enough.
const RAW_LOG = (() => {
  const i = argv.indexOf('--raw-log');
  return i !== -1 && argv[i + 1] ? argv[i + 1] : null;
})();
const NO_BACKUP = argv.includes('--no-backup');
const NO_INDEX = argv.includes('--no-index');
const REBUILD_INDEX = argv.includes('--rebuild-index');
const argNum = (name, dflt) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? Number(argv[i + 1]) : dflt;
};
const SKIP_NEWER_MIN = argNum('--skip-newer-than-min', 60);

const rules = load();
const RULES = compile(rules, () => {});
const ALIASES = compileAliases(rules.aliases, () => {});
const NORM = compileNormalizers(rules.normalize, () => {});
// The real label key, so labels match what the proxy emits for the same value.
const K_LABEL = subkey(loadMaster(process.env.CCR_KEY_PATH || undefined), 'label');
const PIPE = { rules: RULES, kLabel: K_LABEL, aliases: ALIASES, normalizers: NORM };

// The index of files already known clean under the CURRENT rules. See
// residue-index.js for why a rules-fingerprint mismatch discards the whole
// index rather than trusting stale entries.
const INDEX = NO_INDEX
  ? null
  : createIndex({
      indexPath: process.env.CCR_RESIDUE_INDEX_PATH,
      rulesFingerprint: computeRulesFingerprint(rules),
    });
if (INDEX && !REBUILD_INDEX) INDEX.load();

// os.homedir() ignores process.env.HOME on Windows, so a test that sets
// HOME to a fixture was silently still walking the real ~/.claude -- which
// is why every attempt to test this script timed out on 590MB of the
// user's transcripts. Honouring HOME first is what makes isolation possible.
const HOME = process.env.HOME || os.homedir();
// Positional arguments override the default targets, matching
// scan-residue.js. This exists so the script can be pointed at a fixture:
// without it nothing could test a script that rewrites hundreds of the
// user's files, which is precisely the gap that let a crash reach production
// in start.js.
const explicitTargets = argv.filter((a) => !a.startsWith('--') && !/^\d+$/.test(a));
const TARGETS = explicitTargets.length
  ? explicitTargets.map((p) => path.resolve(p))
  : [
      path.join(HOME, '.claude', 'projects'),
      path.join(HOME, '.claude', 'history.jsonl'),
      path.join(HOME, '.claude', 'file-history'),
      path.join(HOME, '.claude', 'todos'),
      path.join(HOME, '.claude', 'shell-snapshots'),
    ];
const BACKUP_ROOT = path.join(HOME, '.claude', 'redaction', 'residue-backup-' + new Date().toISOString().replace(/[:.]/g, '-'));

// Never touch our own state: the rules file holds the values we are scrubbing
// FOR, and the backup directory would be scrubbed on a second run.
const EXCLUDE_DIRS = [path.join(HOME, '.claude', 'redaction')];
const SKIP_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf', '.zip', '.gz', '.exe', '.dll', '.node']);

function walk(p, out = []) {
  if (EXCLUDE_DIRS.some((d) => p.startsWith(d))) return out;
  let st;
  try {
    st = fs.statSync(p);
  } catch (e) {
    return out;
  }
  if (st.isFile()) {
    if (!SKIP_EXT.has(path.extname(p).toLowerCase())) out.push({ p, mtime: st.mtimeMs, size: st.size });
    return out;
  }
  if (!st.isDirectory()) return out;
  let names;
  try {
    names = fs.readdirSync(p);
  } catch (e) {
    return out;
  }
  for (const n of names) walk(path.join(p, n), out);
  return out;
}

// Scrub every string in a parsed JSON value, leaving structure alone.
function scrubDeep(node) {
  if (typeof node === 'string') return renderForModel(node, PIPE).text;
  if (Array.isArray(node)) return node.map(scrubDeep);
  if (node && typeof node === 'object') {
    const out = {};
    for (const k of Object.keys(node)) out[k] = scrubDeep(node[k]);
    return out;
  }
  return node;
}

// Returns { text, changed, unparsed } for a JSONL file. Structure is preserved
// by parsing and re-serializing rather than replacing across the raw bytes.
function scrubJsonl(raw) {
  const lines = raw.split('\n');
  let changed = 0;
  let unparsed = 0;
  const out = lines.map((line) => {
    if (line.trim() === '') return line;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (e) {
      unparsed++;
      return line; // leave it exactly as found rather than guess
    }
    const scrubbed = scrubDeep(parsed);
    const next = JSON.stringify(scrubbed);
    if (next !== line) changed++;
    return next;
  });
  return { text: out.join('\n'), changed, unparsed };
}

// A .json file is ONE document, usually pretty-printed across many lines.
// Treating it as JSONL means every line fails to parse, the file is counted
// as unparseable, and it is left completely untouched. That is exactly what
// happened: the tool-results/*.json files -- which hold the CONTENTS OF FILES
// that were read, and so carry the densest concentration of real values
// anywhere on disk -- were silently skipped by the first two passes. They also
// accounted for the "24 unparseable lines" that looked harmless.
function scrubJsonDoc(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    // Genuinely not JSON despite the extension: fall back to text, which is
    // still better than skipping it.
    return scrubText(raw);
  }
  // Preserve the original layout. Re-serializing a compact one-line document
  // as pretty-printed changes 1 line into 7 and makes every diff and every
  // line-based check scream, for no benefit -- JSON.parse does not care.
  const compact = raw.trimEnd().indexOf(String.fromCharCode(10)) === -1;
  const next = compact ? JSON.stringify(scrubDeep(parsed)) : JSON.stringify(scrubDeep(parsed), null, 2);
  return { text: next, changed: next === raw ? 0 : 1, unparsed: 0 };
}

function scrubText(raw) {
  const next = renderForModel(raw, PIPE).text;
  return { text: next, changed: next === raw ? 0 : 1, unparsed: 0 };
}

const now = Date.now();
const skipMs = SKIP_NEWER_MIN * 60 * 1000;

let scanned = 0;
let wouldChange = 0;
let skippedRecent = 0;
let skippedIndex = 0;
let unparsedTotal = 0;
let bytesToBackup = 0;
let written = 0;
let verifyFailures = 0;
const changedFiles = [];
const rawRecords = [];

// 1-based line number for a character offset. Counting newlines up to the
// offset is O(n) per call, which is fine: it runs only for files that
// actually changed, and only when a raw log was asked for.
function lineOf(text, off) {
  let n = 1;
  for (let i = 0; i < off && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}
// Every path the walk produced, recent-skipped ones included (they still
// exist on disk and must not be pruned from the index just because this
// pass didn't touch them).
const seenForIndex = new Set();

for (const t of TARGETS) {
  for (const f of walk(t)) {
    scanned++;
    seenForIndex.add(f.p);
    if (now - f.mtime < skipMs) {
      // Skipped for a DIFFERENT reason than "known clean": it may be a live
      // session being appended to right now. Never mark it clean here --
      // that would let a future pass skip examining it even after it goes
      // stale and stops being "recent".
      skippedRecent++;
      continue;
    }

    // Skip files the index already verified clean under the CURRENT rules.
    // isClean() cannot say yes across a rules change (the index loads empty
    // in that case), so this is safe by construction.
    if (INDEX && INDEX.isClean(f.p, { mtimeMs: f.mtime, size: f.size })) {
      skippedIndex++;
      continue;
    }

    let raw;
    try {
      raw = fs.readFileSync(f.p, 'utf8');
    } catch (e) {
      continue;
    }

    const isJsonl = f.p.endsWith('.jsonl');
    const isJsonDoc = f.p.endsWith('.json');
    const res = isJsonl ? scrubJsonl(raw) : isJsonDoc ? scrubJsonDoc(raw) : scrubText(raw);
    unparsedTotal += res.unparsed;
    if (res.text === raw) {
      // Examined under the current rules and found clean: safe to remember.
      if (INDEX) INDEX.markClean(f.p, { mtimeMs: f.mtime, size: f.size });
      continue;
    }

    wouldChange++;
    bytesToBackup += f.size;

    // Category breakdown for the audit manifest: WHAT was removed from this
    // file, not just that something was. Computed only for files that
    // actually changed, so the cost is bounded by the small set that did.
    //
    // Counts only, never the values. A manifest listing what it removed
    // would recreate, in a file that persists, exactly the data the scrub
    // exists to delete.
    let categories = null;
    if (MANIFEST || RAW_LOG) {
      try {
        const red = redactWithSpans(raw, PIPE.rules, PIPE.kLabel);
        const spans = red.spans || [];
        categories = {};
        for (const s of spans) categories[s.category] = (categories[s.category] || 0) + 1;

        if (RAW_LOG) {
          // One record per replaced value: where it was, what it was, and
          // what it became. The label is read out of the redacted text at
          // the span's own offsets rather than recomputed, so it is exactly
          // the string that replaced the value -- which is what lets an
          // auditor match a line in a scrubbed transcript back to the
          // original.
          const rel = path.relative(HOME, f.p).split(path.sep).join('/');
          for (const s of spans) {
            rawRecords.push({
              file: rel,
              line: lineOf(raw, s.realStart),
              category: s.category,
              before: s.value,
              after: red.text.slice(s.redStart, s.redEnd),
            });
          }
        }
      } catch (e) {
        categories = null; // an audit aid, never a reason to fail a pass
      }
    }
    changedFiles.push({ p: f.p, lines: res.changed, size: f.size, categories });

    if (!WRITE) {
      // Dry run: known dirty, but nothing on disk changed, so there is
      // nothing safe to mark clean. Drop any stale entry rather than leave
      // one that (by coincidence of stat) could look valid later.
      if (INDEX) INDEX.markDirty(f.p);
      continue;
    }

    // Back up before touching anything.
    if (!NO_BACKUP) {
      const rel = path.relative(HOME, f.p);
      const dest = path.join(BACKUP_ROOT, rel);
      try {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.copyFileSync(f.p, dest);
      } catch (e) {
        console.log(`  SKIPPED (backup failed): ${f.p} -- ${e.message}`);
        if (INDEX) INDEX.markDirty(f.p);
        continue;
      }
    }

    try {
      fs.writeFileSync(f.p, res.text);
      written++;
    } catch (e) {
      console.log(`  FAILED to write ${f.p}: ${e.message}`);
      if (INDEX) INDEX.markDirty(f.p);
      continue;
    }

    // Verify: every line must still parse, or the file is now unreadable to
    // Claude Code and resume would break.
    let verifyOk = true;
    if (isJsonDoc) {
      try {
        JSON.parse(fs.readFileSync(f.p, "utf8"));
      } catch (e) {
        verifyFailures++;
        verifyOk = false;
        console.log("  VERIFY FAILED (document no longer parses): " + f.p);
      }
    } else
    if (isJsonl) {
      const check = fs.readFileSync(f.p, 'utf8').split('\n');
      for (const line of check) {
        if (line.trim() === '') continue;
        try {
          JSON.parse(line);
        } catch (e) {
          verifyFailures++;
          verifyOk = false;
          console.log(`  VERIFY FAILED (a line no longer parses): ${f.p}`);
          break;
        }
      }
    }

    // Rewritten AND verified: it is clean now, under its NEW stat. Marking
    // it lets the next pass skip it instead of re-reading the file it was
    // just proven to hold no residue.
    if (INDEX) {
      if (verifyOk) {
        let newStat;
        try {
          newStat = fs.statSync(f.p);
          INDEX.markClean(f.p, { mtimeMs: newStat.mtimeMs, size: newStat.size });
        } catch (e) {
          INDEX.markDirty(f.p);
        }
      } else {
        INDEX.markDirty(f.p);
      }
    }
  }
}

if (INDEX) {
  INDEX.prune(seenForIndex);
  INDEX.save();
}

console.log(WRITE ? 'PHASE 4 SCRUB - APPLYING' : 'PHASE 4 SCRUB - DRY RUN (nothing written)');
console.log('');
console.log(`files examined           : ${scanned}`);
console.log(`skipped as too recent    : ${skippedRecent}  (modified within ${SKIP_NEWER_MIN} min, includes your live session)`);
if (INDEX) console.log(`skipped via index        : ${skippedIndex}  (already known clean, unchanged since last verified)`);
else console.log('index                    : disabled (--no-index)');
console.log(`files containing residue : ${wouldChange}`);
if (unparsedTotal) console.log(`unparseable JSONL lines  : ${unparsedTotal}  (left exactly as found)`);

// The manifest: every file this pass touched, with what was removed from it.
// Written even when --quiet, because quiet governs the CONSOLE and this is
// the audit record. Paths are relative to home so the file is portable and
// does not repeat the home directory hundreds of times.
if (MANIFEST) {
  try {
    const rows = changedFiles
      .slice()
      .sort((a, b) => b.lines - a.lines)
      .map((c) => ({
        file: path.relative(HOME, c.p).split(path.sep).join('/'),
        linesChanged: c.lines,
        bytes: c.size,
        categories: c.categories || null,
      }));
    const totals = {};
    for (const r of rows) {
      for (const [k, v] of Object.entries(r.categories || {})) totals[k] = (totals[k] || 0) + v;
    }
    fs.mkdirSync(path.dirname(path.resolve(MANIFEST)), { recursive: true });
    fs.writeFileSync(
      path.resolve(MANIFEST),
      JSON.stringify(
        {
          ts: new Date().toISOString(),
          applied: WRITE,
          filesExamined: scanned,
          filesChanged: rows.length,
          // Stated explicitly: without a backup there is nothing to diff
          // against, so this manifest is the whole audit trail.
          backupsKept: !NO_BACKUP,
          backupRoot: NO_BACKUP ? null : BACKUP_ROOT,
          totalsByCategory: totals,
          files: rows,
        },
        null,
        2
      ) + '\n'
    );
  } catch (e) {
    console.log('  (could not write manifest: ' + e.message + ')');
  }
}

// The raw change log. Locked down exactly like the master key, because that
// is what it is worth: a single file containing every personal value this
// pass removed. Written last so a failure here cannot affect the pass.
if (RAW_LOG) {
  const target = path.resolve(RAW_LOG);
  try {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    // JSONL: appendable, streamable, and a truncated write still leaves
    // every complete earlier record readable.
    const body = rawRecords.map((r) => JSON.stringify(r)).join('\n') + (rawRecords.length ? '\n' : '');
    fs.writeFileSync(target, body, { mode: 0o600 });
    const locked = restrictAcl(target);
    // Say so when the file could NOT be protected. A raw PII dump that the
    // user believes is owner-only, and is not, is worse than one they know
    // is exposed.
    console.log(
      'raw change log           : ' + rawRecords.length + ' record(s) -> ' + target +
        (locked ? '  (owner-only)' : '  *** PERMISSIONS NOT RESTRICTED ***')
    );
    console.log('                           CONTAINS REAL VALUES. Review, then delete.');
  } catch (e) {
    console.log('  (could not write raw change log: ' + e.message + ')');
  }
}

if (!QUIET && changedFiles.length) {
  console.log('');
  const top = changedFiles.slice().sort((a, b) => b.lines - a.lines).slice(0, 10);
  console.log('most affected files (path shown, contents never printed):');
  for (const c of top) {
    console.log(`  ${String(c.lines).padStart(5)} line(s)  ${path.relative(HOME, c.p)}`);
  }
}

console.log('');
if (WRITE) {
  console.log(`files rewritten          : ${written}`);
  if (!NO_BACKUP) console.log(`backup                   : ${BACKUP_ROOT}`);
  else console.log('backup                   : SKIPPED (--no-backup); the originals are gone');
  console.log(`verify failures          : ${verifyFailures}`);
  console.log('');
  console.log(verifyFailures === 0
    ? 'Every rewritten JSONL line still parses. Re-run scan-residue.js to confirm the counts dropped.'
    : 'SOME FILES NO LONGER PARSE -- restore them from the backup above.');
  process.exit(verifyFailures ? 1 : 0);
} else {
  console.log(`would back up            : ${(bytesToBackup / 1024 / 1024).toFixed(1)} MB`);
  console.log('');
  console.log('Re-run with --write to apply. Labels written will be identical to the');
  console.log('ones the proxy sends for the same values, so resumed sessions stay');
  console.log('coherent.');
}
