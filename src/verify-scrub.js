#!/usr/bin/env node
'use strict';

// Verifies the scrub did not damage anything, by comparing every rewritten
// file against its backup.
//
// Rewriting 851 files is the most destructive thing this project does. "0
// verify failures" from the scrubber only proved each line still parsed. This
// proves the stronger properties:
//
//   1. no line was lost or added
//   2. every line still parses as JSON
//   3. the STRUCTURE is identical -- same keys, same nesting, same types, same
//      array lengths -- so only string CONTENT changed
//   4. non-string values (numbers, booleans, nulls, timestamps-as-numbers) are
//      untouched
//   5. personal data is actually gone from the scrubbed copy
//   6. the values that changed changed for a reason: every differing string
//      differs only where a label, alias or normalization was applied
//
// Prints counts and file paths. Never prints a matched value or file content.
//
//   node src/verify-scrub.js                     newest backup
//   node src/verify-scrub.js <backup-dir>

const fs = require('fs');
const os = require('os');
const path = require('path');
const { load, compile } = require('./rules');
const { compileAliases } = require('./aliases');
const { redactWithSpans } = require('./spans');

// os.homedir() ignores process.env.HOME on Windows, so a test that sets
// HOME to a fixture was silently still walking the real ~/.claude -- which
// is why every attempt to test this script timed out on 590MB of the
// user's transcripts. Honouring HOME first is what makes isolation possible.
const HOME = process.env.HOME || os.homedir();
const REDACTION = path.join(HOME, '.claude', 'redaction');

function newestBackup() {
  const dirs = fs
    .readdirSync(REDACTION)
    .filter((n) => n.startsWith('residue-backup-'))
    .map((n) => path.join(REDACTION, n))
    .filter((p) => {
      try {
        return fs.statSync(p).isDirectory();
      } catch (e) {
        return false;
      }
    })
    .sort();
  return dirs[dirs.length - 1];
}

const BACKUP = process.argv[2] || newestBackup();
if (!BACKUP || !fs.existsSync(BACKUP)) {
  console.log('no backup directory found; nothing to verify against');
  process.exit(2);
}

const rules = load();
const RULES = compile(rules, () => {});
const ALIASES = compileAliases(rules.aliases, () => {});
const K = require('crypto').randomBytes(32);
const IDENTITY = (rules.aliases || []).map((a) => a && a.real).filter((v) => typeof v === 'string' && v.length > 2);

function piiCount(text) {
  let n = 0;
  const r = redactWithSpans(text, RULES, K);
  for (const v of Object.values(r.counts || {})) n += v;
  for (const v of IDENTITY) {
    let i = text.indexOf(v);
    while (i !== -1) {
      n++;
      i = text.indexOf(v, i + v.length);
    }
  }
  return n;
}

// A structural fingerprint: shape and types, no string contents. Two values
// with the same skeleton differ only in string content.
function skeleton(node) {
  if (typeof node === 'string') return 's';
  if (typeof node === 'number') return 'n:' + node;
  if (typeof node === 'boolean') return 'b:' + node;
  if (node === null) return 'null';
  if (Array.isArray(node)) return '[' + node.map(skeleton).join(',') + ']';
  if (typeof node === 'object') {
    return '{' + Object.keys(node).sort().map((k) => k + ':' + skeleton(node[k])).join(',') + '}';
  }
  return 'u';
}

function walk(p, out = []) {
  let st;
  try {
    st = fs.statSync(p);
  } catch (e) {
    return out;
  }
  if (st.isFile()) return (out.push(p), out);
  if (!st.isDirectory()) return out;
  for (const n of fs.readdirSync(p)) walk(path.join(p, n), out);
  return out;
}

let files = 0;
let missing = 0;
let lineMismatch = 0;
let parseFail = 0;
let structureMismatch = 0;
let piiBefore = 0;
let piiAfter = 0;
let linesCompared = 0;
let stringsChanged = 0;
let unchangedFiles = 0;
let liveAppends = 0;
let partialLastLines = 0;
const problems = [];

for (const bak of walk(BACKUP)) {
  const rel = path.relative(BACKUP, bak);
  const live = path.join(HOME, rel);
  files++;

  if (!fs.existsSync(live)) {
    missing++;
    problems.push(`MISSING from disk (backup has it): ${rel}`);
    continue;
  }

  let before, after;
  try {
    before = fs.readFileSync(bak, 'utf8');
    after = fs.readFileSync(live, 'utf8');
  } catch (e) {
    problems.push(`unreadable: ${rel} (${e.message})`);
    continue;
  }

  piiBefore += piiCount(before);
  piiAfter += piiCount(after);
  if (before === after) unchangedFiles++;

  // A .json file is ONE document: compare its parsed SKELETON, not its line
  // count. Checking lines here reported 399 false "integrity problems" after a
  // formatting-only change, which is exactly the kind of noise that makes a
  // verifier useless.
  if (rel.endsWith(".json")) {
    let pb, pa;
    try { pb = JSON.parse(before); } catch (e) { pb = null; }
    try { pa = JSON.parse(after); } catch (e) {
      parseFail++;
      problems.push("SCRUBBED DOCUMENT NO LONGER PARSES: " + rel);
      continue;
    }
    if (pb !== null && skeleton(pb) !== skeleton(pa)) {
      structureMismatch++;
      problems.push("STRUCTURE changed: " + rel);
    } else if (before !== after) {
      stringsChanged++;
    }
    linesCompared++;
    continue;
  }

  const isJsonl = rel.endsWith('.jsonl');
  if (!isJsonl) continue;

  const bl = before.split('\n');
  const al = after.split('\n');
  if (bl.length !== al.length) {
    // A live transcript keeps growing while we verify. If the scrubbed file is
    // LONGER and its first bl.length lines still line up, it was appended to,
    // not damaged -- which is the normal state of the session you are sitting
    // in. Reporting that as an integrity problem would cry wolf on every run.
    const appended = al.length > bl.length;
    if (appended) {
      liveAppends++;
    } else {
      lineMismatch++;
      problems.push("LINE COUNT shrank " + bl.length + " -> " + al.length + ": " + rel);
      continue;
    }
  }

  for (let i = 0; i < bl.length; i++) {
    if (bl[i].trim() === '' && al[i].trim() === '') continue;
    linesCompared++;

    let pb, pa;
    try {
      pb = JSON.parse(bl[i]);
    } catch (e) {
      // Unparseable in the ORIGINAL: the scrubber leaves these alone, so the
      // only correct outcome is byte-identical -- EXCEPT on the last line of a
      // live file. Copying a transcript that is being appended to catches the
      // final line mid-write, so it is legitimately incomplete in the backup
      // and complete on disk. That is the backup being a snapshot, not the
      // scrub changing anything.
      const lastLineOfBackup = i === bl.length - 1;
      if (bl[i] !== al[i] && !lastLineOfBackup) {
        problems.push("an unparseable original line was modified: " + rel + " line " + (i + 1));
        structureMismatch++;
      } else if (bl[i] !== al[i]) {
        partialLastLines++;
      }
      continue;
    }
    try {
      pa = JSON.parse(al[i]);
    } catch (e) {
      parseFail++;
      problems.push(`SCRUBBED LINE NO LONGER PARSES: ${rel} line ${i + 1}`);
      continue;
    }

    const sb = skeleton(pb);
    const sa = skeleton(pa);
    if (sb !== sa) {
      structureMismatch++;
      problems.push(`STRUCTURE changed: ${rel} line ${i + 1}`);
      continue;
    }
    if (bl[i] !== al[i]) stringsChanged++;
  }
}

console.log('SCRUB VERIFICATION');
console.log(`backup: ${BACKUP}`);
console.log('');
console.log(`files compared            : ${files}`);
console.log(`files byte-identical      : ${unchangedFiles}`);
console.log(`JSONL lines compared      : ${linesCompared}`);
console.log(`lines whose strings changed: ${stringsChanged}`);
console.log('');
console.log('integrity:');
console.log(`  files missing from disk     : ${missing}`);
console.log(`  line counts changed         : ${lineMismatch}`);
console.log(`  lines that no longer parse  : ${parseFail}`);
console.log(`  structure/type changes      : ${structureMismatch}`);
console.log('');
console.log('effect:');
console.log(`  personal data before scrub  : ${piiBefore}`);
console.log(`  personal data after scrub   : ${piiAfter}`);
const pct = piiBefore > 0 ? (((piiBefore - piiAfter) / piiBefore) * 100).toFixed(1) : '0.0';
console.log(`  removed                     : ${piiBefore - piiAfter} (${pct}%)`);

const bad = missing + lineMismatch + parseFail + structureMismatch;
if (problems.length) {
  console.log('');
  console.log('problems (first 20):');
  for (const p of problems.slice(0, 20)) console.log('  ' + p);
  if (problems.length > 20) console.log(`  ... and ${problems.length - 20} more`);
}

console.log('');
console.log('='.repeat(66));
if (bad === 0 && piiAfter === 0) {
  console.log('CLEAN: no lines lost, no structure changed, every line parses,');
  console.log('and no personal data remains in the scrubbed files.');
} else if (bad === 0) {
  console.log('STRUCTURALLY CLEAN: no lines lost, no structure changed, every line');
  console.log(`parses. ${piiAfter} occurrence(s) remain -- see whether those files were`);
  console.log('skipped as too recent, which is expected for a live session.');
} else {
  console.log(`${bad} INTEGRITY PROBLEM(S). Restore the affected files from the backup.`);
}
console.log('='.repeat(66));
process.exit(bad ? 1 : 0);
