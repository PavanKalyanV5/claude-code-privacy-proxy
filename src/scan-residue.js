#!/usr/bin/env node
'use strict';

// PHASE 4: what personal data is sitting on this machine's disk?
//
// The proxy protects the API boundary. It does nothing about what Claude Code
// writes locally: conversation transcripts, prompt history, and file-history
// snapshots all contain the real values, because they are written before the
// proxy ever sees them and are never sent anywhere.
//
// This reports COUNTS BY CATEGORY per file. It never prints a matched value,
// never prints surrounding text, and never writes anything. Run it yourself;
// paste the output freely.
//
//   node src/scan-residue.js              scan the default locations
//   node src/scan-residue.js --json       machine-readable summary
//   node src/scan-residue.js <dir>...     scan specific directories
//   --no-index         force a full pass, ignoring any on-disk index
//   --rebuild-index    discard the on-disk index and rebuild it from scratch

const fs = require('fs');
const os = require('os');
const path = require('path');
const { load, compile } = require('./rules');
const { compileAliases } = require('./aliases');
const { redactWithSpans } = require('./spans');
const { createIndex, computeRulesFingerprint } = require('./residue-index');

const JSON_OUT = process.argv.includes('--json');
const NO_INDEX = process.argv.includes('--no-index');
const REBUILD_INDEX = process.argv.includes('--rebuild-index');
const explicitDirs = process.argv.slice(2).filter((a) => !a.startsWith('--'));

const rules = load();
const RULES = compile(rules, () => {});
const ALIASES = compileAliases(rules.aliases, () => {});
const K = require('crypto').randomBytes(32); // counting only

// The index of files already known clean under the CURRENT rules. Consulted
// before reading a file; see residue-index.js for why the rules fingerprint
// is what makes this safe to trust.
const INDEX = NO_INDEX
  ? null
  : createIndex({
      indexPath: process.env.CCR_RESIDUE_INDEX_PATH,
      rulesFingerprint: computeRulesFingerprint(rules),
    });
if (INDEX && !REBUILD_INDEX) INDEX.load();

// Identity values that aliasing would normally hide. On disk they are raw.
const IDENTITY = [];
for (const a of rules.aliases || []) {
  if (a && typeof a.real === 'string' && a.real.length > 2) IDENTITY.push(a.real);
}

// The local-time offset this machine writes into logs and timestamps. It pins
// your region as precisely as a city name; the proxy normalizes it outbound,
// but transcripts on disk keep it.
function localOffset() {
  const mins = -new Date().getTimezoneOffset();
  const sign = mins >= 0 ? '+' : '-';
  const a = Math.abs(mins);
  return sign + String(Math.floor(a / 60)).padStart(2, '0') + String(a % 60).padStart(2, '0');
}
const OFFSET = localOffset();

// os.homedir() ignores process.env.HOME on Windows, so a test that sets
// HOME to a fixture was silently still walking the real ~/.claude -- which
// is why every attempt to test this script timed out on 590MB of the
// user's transcripts. Honouring HOME first is what makes isolation possible.
const HOME = process.env.HOME || os.homedir();
const DEFAULT_TARGETS = [
  { label: 'conversation transcripts', p: path.join(HOME, '.claude', 'projects') },
  { label: 'prompt history', p: path.join(HOME, '.claude', 'history.jsonl') },
  { label: 'file-history snapshots', p: path.join(HOME, '.claude', 'file-history') },
  { label: 'todo state', p: path.join(HOME, '.claude', 'todos') },
  { label: 'shell snapshots', p: path.join(HOME, '.claude', 'shell-snapshots') },
  { label: 'statsig cache', p: path.join(HOME, '.claude', 'statsig') },
  { label: 'assistant memory', p: path.join(HOME, '.claude', 'projects') },
];

const SKIP_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf', '.zip', '.gz', '.exe', '.dll', '.node']);

function walk(p, out = []) {
  let st;
  try {
    st = fs.statSync(p);
  } catch (e) {
    return out;
  }
  if (st.isFile()) {
    if (!SKIP_EXT.has(path.extname(p).toLowerCase())) out.push({ p, size: st.size, mtimeMs: st.mtimeMs });
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

function countIn(text) {
  const counts = {};
  // Literals and patterns, via the real redaction engine so the categories
  // match exactly what the proxy would label.
  const r = redactWithSpans(text, RULES, K);
  for (const [k, v] of Object.entries(r.counts || {})) counts[k] = (counts[k] || 0) + v;

  // Identity values (username, hostname) are aliased outbound, so they are
  // not in r.counts -- but on disk they are the real thing.
  for (const v of IDENTITY) {
    let n = 0;
    let i = text.indexOf(v);
    while (i !== -1) {
      n++;
      i = text.indexOf(v, i + v.length);
    }
    if (n) counts.identity = (counts.identity || 0) + n;
  }

  // Local timezone offset.
  let n = 0;
  let i = text.indexOf(OFFSET);
  while (i !== -1) {
    n++;
    i = text.indexOf(OFFSET, i + OFFSET.length);
  }
  if (n) counts.timezone = (counts.timezone || 0) + n;

  return counts;
}

const report = [];
const totals = {};
let filesWith = 0;
let filesScanned = 0;
let filesSkippedIndex = 0;
let bytesScanned = 0;

const targets = explicitDirs.length
  ? explicitDirs.map((p) => ({ label: p, p: path.resolve(p) }))
  : DEFAULT_TARGETS;

const seen = new Set();
for (const t of targets) {
  const files = walk(t.p);
  const group = { label: t.label, path: t.p, files: 0, withPii: 0, counts: {} };
  let groupSkipped = 0;
  for (const f of files) {
    if (seen.has(f.p)) continue;
    seen.add(f.p);

    // Skip files the index already verified clean under the CURRENT rules.
    // isClean() itself refuses to say yes across a rules change (the index
    // is loaded empty in that case), so this is safe by construction.
    if (INDEX && INDEX.isClean(f.p, { mtimeMs: f.mtimeMs, size: f.size })) {
      filesSkippedIndex++;
      groupSkipped++;
      continue;
    }

    let text;
    try {
      text = fs.readFileSync(f.p, 'utf8');
    } catch (e) {
      continue;
    }
    filesScanned++;
    bytesScanned += f.size;
    group.files++;
    const c = countIn(text);
    const hits = Object.values(c).reduce((a, b) => a + b, 0);
    if (hits > 0) {
      filesWith++;
      group.withPii++;
      for (const [k, v] of Object.entries(c)) {
        group.counts[k] = (group.counts[k] || 0) + v;
        totals[k] = (totals[k] || 0) + v;
      }
      if (INDEX) INDEX.markDirty(f.p);
    } else if (INDEX) {
      INDEX.markClean(f.p, { mtimeMs: f.mtimeMs, size: f.size });
    }
  }
  if (group.files > 0 || groupSkipped > 0) report.push(group);
}

if (INDEX) {
  INDEX.prune(seen);
  INDEX.save();
}
const indexStats = INDEX ? INDEX.stats() : null;

if (JSON_OUT) {
  console.log(JSON.stringify({
    filesScanned,
    filesWith,
    totals,
    groups: report,
    index: INDEX ? { enabled: true, skipped: filesSkippedIndex, examined: filesScanned, ...indexStats } : { enabled: false },
  }, null, 2));
  process.exit(0);
}

console.log('PHASE 4 RESIDUE SCAN - counts only, no values printed');
console.log('');
console.log(`scanned ${filesScanned} file(s), ${(bytesScanned / 1024 / 1024).toFixed(1)} MB`);
if (INDEX) {
  console.log(`index    : ${filesScanned} examined, ${filesSkippedIndex} skipped (already known clean, unchanged), ${indexStats.entries} entries tracked`);
} else {
  console.log('index    : disabled (--no-index)');
}
console.log(`local timezone offset being looked for: ${OFFSET}`);
console.log('');

for (const g of report) {
  const total = Object.values(g.counts).reduce((a, b) => a + b, 0);
  console.log(`${g.label}`);
  console.log(`  ${g.path}`);
  console.log(`  files ${g.files}, containing personal data ${g.withPii}, occurrences ${total}`);
  if (total > 0) {
    const parts = Object.entries(g.counts)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => `${k}=${v}`);
    console.log(`  by category: ${parts.join(' ')}`);
  }
  console.log('');
}

const grand = Object.values(totals).reduce((a, b) => a + b, 0);
console.log('='.repeat(66));
console.log(`TOTAL: ${grand} occurrence(s) across ${filesWith} file(s)`);
if (grand > 0) {
  console.log('');
  const parts = Object.entries(totals).sort((a, b) => b[1] - a[1]);
  for (const [k, v] of parts) console.log(`  ${k.padEnd(12)} ${v}`);
  console.log('');
  console.log('None of this has been sent anywhere -- it is local only. It matters if');
  console.log('anything else on this machine reads it, if the disk is backed up or');
  console.log('synced, or if a file is ever shared.');
}
console.log('='.repeat(66));
