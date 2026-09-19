#!/usr/bin/env node
'use strict';

// Writes a REVIEWABLE list of every PII occurrence found in a directory:
// file, line, category, the actual matched value, and the surrounding line.
//
// WHY THIS IS SEPARATE FROM `npm run scan`. The scanner deliberately reports
// counts only, so its output is safe to paste into an issue, a chat, or a
// model context. This tool does the opposite on purpose: it exists for the
// one case where counts are not enough -- deciding whether a repository is
// safe to publish. You cannot make that judgement from "identity: 6". You
// have to see which six.
//
// The output therefore CONTAINS YOUR PERSONAL DATA IN CLEAR TEXT. It is
// written straight to a local file by this process and never printed to
// stdout, so it cannot end up in a terminal transcript, a tool result, or a
// model's context window. Only counts go to the console.
//
// Delete the report when you are done with it. It is added to .gitignore,
// but a file that exists is a file that can be copied somewhere that is not.
//
//   node src/pii-report.js . --out PII-AUDIT.txt
//   node src/pii-report.js src docs README.md --out report.txt

const fs = require('fs');
const os = require('os');
const path = require('path');
const { load, compile } = require('./rules');
const { loadMaster, subkey } = require('./keys');
const { redactWithSpans } = require('./spans');

const SKIP_DIRS = new Set(['.git', 'node_modules', '.playwright-mcp']);
const SKIP_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf', '.zip', '.gz', '.exe', '.dll', '.node', '.ico']);

function argValue(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const OUT = path.resolve(argValue('--out', 'PII-AUDIT.txt'));

// Flags that consume the following argument. Without this list, the VALUE of
// a flag is treated as a path to scan: `--fail-on identity,personal` made
// "identity,personal" the only target, which matched no files, so the gate
// reported PASSED having examined nothing. A gate that passes because it
// scanned zero files is worse than no gate -- it produces the green tick
// someone is relying on.
const VALUE_FLAGS = new Set(['--out', '--fail-on']);

const targets = [];
{
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      if (VALUE_FLAGS.has(a)) i++; // skip its value
      continue;
    }
    targets.push(a);
  }
}

if (!targets.length) targets.push('.');

const rules = load();
const K = subkey(loadMaster(), 'label');
const compiled = compile(rules, () => {});

// Identity values are ALIASED outbound rather than labelled, so they never
// appear in redactWithSpans' counts -- but on disk they are the real string,
// and for a publishing decision they are the most important category there
// is. A username in a committed path is not anonymised by the proxy.
const IDENTITY = [];
for (const a of rules.aliases || []) {
  if (a && typeof a.real === 'string' && a.real.length >= 3) IDENTITY.push({ value: a.real, category: 'identity' });
}

// The local UTC offset, normalized outbound rather than labelled, so it is
// also absent from redactWithSpans' counts. Included so this report's totals
// reconcile with `npm run scan` -- a validation report whose numbers disagree
// with the scanner's is a report nobody can act on with confidence.
function localOffset() {
  const mins = -new Date().getTimezoneOffset();
  const sign = mins >= 0 ? '+' : '-';
  const a = Math.abs(mins);
  return sign + String(Math.floor(a / 60)).padStart(2, '0') + String(a % 60).padStart(2, '0');
}
const OFFSET = localOffset();

function walk(p, out = []) {
  let st;
  try {
    st = fs.statSync(p);
  } catch (e) {
    return out;
  }
  if (st.isFile()) {
    // Never scan the report itself. It contains every value found, so a
    // second run would count each one again and report inflated totals --
    // observed: 571 occurrences became 1957 on the very next run, which
    // would have made the numbers untrustworthy exactly when someone is
    // relying on them to decide what is safe to publish.
    if (path.resolve(p) === OUT) return out;
    if (!SKIP_EXT.has(path.extname(p).toLowerCase()) && st.size < 8 * 1024 * 1024) out.push(p);
    return out;
  }
  if (!st.isDirectory()) return out;
  if (SKIP_DIRS.has(path.basename(p))) return out;
  let names;
  try {
    names = fs.readdirSync(p);
  } catch (e) {
    return out;
  }
  for (const n of names) {
    if (SKIP_DIRS.has(n)) continue;
    walk(path.join(p, n), out);
  }
  return out;
}

// Offset -> 1-based line number, computed once per file.
function lineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (off) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= off) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, start: starts[lo], end: starts[lo + 1] !== undefined ? starts[lo + 1] - 1 : text.length };
  };
}

// Git-tracked files are the ones that PUBLISH. Everything else is local-only:
// still worth knowing about, but a completely different decision.
//
// Conflating the two makes the report unusable for the question it exists to
// answer. A scan of "." reports agent scratch directories and archived
// configs alongside the README, so a repo that is perfectly safe to publish
// shows hundreds of hits and the one that matters is buried.
let trackedSet = null;
try {
  const { execFileSync } = require('child_process');
  trackedSet = new Set(
    execFileSync('git', ['ls-files'], { encoding: 'utf8', windowsHide: true })
      .split(/\r?\n/)
      .filter(Boolean)
      .map((f) => path.resolve(f))
  );
} catch (e) {
  trackedSet = null; // not a git repo: everything is treated as untracked
}

const TRACKED_ONLY = process.argv.includes('--tracked');

let files = targets.reduce((acc, t) => walk(t, acc), []);
if (TRACKED_ONLY) {
  if (!trackedSet) {
    console.error('--tracked needs a git repository');
    process.exit(2);
  }
  files = files.filter((f) => trackedSet.has(path.resolve(f)));
}

const isTracked = (f) => Boolean(trackedSet && trackedSet.has(path.resolve(f)));
const byFile = new Map();
const totals = {};
let occurrences = 0;

for (const file of files) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    continue;
  }
  const hits = [];

  const r = redactWithSpans(text, compiled, K);
  for (const s of r.spans || []) {
    hits.push({ off: s.realStart, value: s.value, category: s.category });
  }

  // Aliased identity values, found by plain substring search for the same
  // reason the scanner does it: they are not part of the label pipeline.
  for (const id of IDENTITY) {
    let i = text.indexOf(id.value);
    while (i !== -1) {
      hits.push({ off: i, value: id.value, category: 'identity' });
      i = text.indexOf(id.value, i + id.value.length);
    }
  }

  let t = text.indexOf(OFFSET);
  while (t !== -1) {
    hits.push({ off: t, value: OFFSET, category: 'timezone' });
    t = text.indexOf(OFFSET, t + OFFSET.length);
  }

  if (!hits.length) continue;
  hits.sort((a, b) => a.off - b.off);
  const at = lineIndex(text);
  byFile.set(
    file,
    hits.map((h) => {
      const L = at(h.off);
      totals[h.category] = (totals[h.category] || 0) + 1;
      occurrences++;
      return {
        line: L.line,
        category: h.category,
        value: h.value,
        context: text.slice(L.start, L.end).trim().slice(0, 200),
      };
    })
  );
}

// ------------------------------------------------------------------ report

const lines = [];
lines.push('PII AUDIT REPORT');
lines.push('generated ' + new Date().toISOString());
lines.push('scanned   ' + files.length + ' files under: ' + targets.join(', '));
lines.push('');
lines.push('*** THIS FILE CONTAINS YOUR PERSONAL DATA IN CLEAR TEXT. ***');
lines.push('*** Review it, act on it, then delete it.                ***');
lines.push('');
lines.push('WHAT TO DO WITH THIS');
lines.push('  Every line below is something that would be visible to anyone who');
lines.push('  reads this repository after you publish it. For each one, decide:');
lines.push('');
lines.push('    - a real value of yours        -> must be removed before publishing');
lines.push('    - a deliberate test fixture    -> fine, but check it is obviously fake');
lines.push('    - a false positive             -> fine, and worth narrowing the rule');
lines.push('');
lines.push('  Categories: "identity" and "personal" are the ones to look at first.');
lines.push('  "timezone" and "ip" are frequently 127.0.0.1 and +05:30 in tests.');
lines.push('');
lines.push('SUMMARY BY CATEGORY');
for (const [k, v] of Object.entries(totals).sort((a, b) => b[1] - a[1])) {
  lines.push('  ' + String(v).padStart(6) + '  ' + k);
}
lines.push('  ' + String(occurrences).padStart(6) + '  TOTAL across ' + byFile.size + ' files');
lines.push('');
lines.push('='.repeat(78));
lines.push('');

// Files with identity/personal hits first: those decide whether this is
// publishable at all, and a reviewer should not have to scroll past 500
// instances of 127.0.0.1 to find them.
const severity = (hits) => hits.some((h) => h.category === 'identity' || h.category === 'personal');
const sorted = [...byFile.entries()].sort((a, b) => {
  const sa = severity(a[1]) ? 0 : 1;
  const sb = severity(b[1]) ? 0 : 1;
  if (sa !== sb) return sa - sb;
  return b[1].length - a[1].length;
});

for (const [file, hits] of sorted) {
  const rel = path.relative(process.cwd(), file) || file;
  const flag = (severity(hits) ? '  <<< IDENTITY/PERSONAL' : '') + (trackedSet && !isTracked(file) ? '  [untracked: local only]' : '');
  lines.push(rel + '   (' + hits.length + ' occurrence' + (hits.length === 1 ? '' : 's') + ')' + flag);
  for (const h of hits) {
    lines.push('  line ' + String(h.line).padStart(6) + '  [' + h.category + ']  ' + h.value);
    if (h.context && h.context !== h.value) lines.push('              | ' + h.context);
  }
  lines.push('');
}

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, lines.join('\n') + '\n', 'utf8');

// Console output is counts only, deliberately: this is the part that may be
// read by a tool result or a model, and it must stay values-free.
console.log('wrote ' + OUT);
console.log('  files scanned    : ' + files.length + (TRACKED_ONLY ? ' (git-tracked only)' : ''));
console.log('  files with hits  : ' + byFile.size);
console.log('  total occurrences: ' + occurrences);
for (const [k, v] of Object.entries(totals).sort((a, b) => b[1] - a[1])) {
  console.log('    ' + String(v).padStart(5) + '  ' + k);
}

// The split that actually drives a decision. Tracked hits are a publishing
// problem and must be fixed; untracked hits are a local-disk fact, handled by
// `npm run scrub:apply` rather than by editing anything.
if (!TRACKED_ONLY && trackedSet) {
  let tHits = 0;
  let uHits = 0;
  let tFiles = 0;
  let uFiles = 0;
  for (const [file, hits] of byFile) {
    if (isTracked(file)) {
      tHits += hits.length;
      tFiles++;
    } else {
      uHits += hits.length;
      uFiles++;
    }
  }
  console.log('');
  console.log('  WILL PUBLISH (git-tracked) : ' + tHits + ' in ' + tFiles + ' file(s)');
  console.log('  local only  (untracked)    : ' + uHits + ' in ' + uFiles + ' file(s)');
  if (uHits) {
    console.log('');
    console.log('  Untracked hits do not reach the repository. They are on your disk,');
    console.log('  which is what `npm run scrub:apply` is for. Use --tracked to see');
    console.log('  only what publishing would expose.');
  }
}
console.log('');
console.log('The report contains real values. Review it, then delete it.');

// A publish gate. `--fail-on identity,personal` exits non-zero if any of the
// named categories appear, so this can sit in front of a push instead of
// relying on someone remembering to read the report.
//
// The categories that matter are the ones no reader can dismiss as a
// fixture: 127.0.0.1 and jane@example.com are obviously synthetic, a real
// username is not. This repo needed the gate twice -- once for a README
// whose before/after table showed a real username as the ANONYMISED side,
// and once for a source comment where writing the alias caused the resolver
// to substitute the real value on the way to disk. The second is the
// nastier: the text was correct when written and wrong when saved.
const failOn = (argValue('--fail-on', '') || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

if (failOn.length) {
  // The gate judges what would PUBLISH. Failing on untracked scratch files
  // would make it permanently red on any real working machine, and a gate
  // that is always red is a gate everyone learns to pass with --no-verify.
  const gateTotals = {};
  for (const [file, hits] of byFile) {
    if (trackedSet && !isTracked(file)) continue;
    for (const h of hits) gateTotals[h.category] = (gateTotals[h.category] || 0) + 1;
  }
  const tripped = failOn.filter((c) => (gateTotals[c] || 0) > 0);
  if (trackedSet) console.log('  (gate considers git-tracked files only)');
  console.log('');
  if (tripped.length) {
    console.log('GATE FAILED: ' + tripped.map((c) => c + '=' + gateTotals[c]).join(', '));
    console.log('These categories must be zero before publishing. See ' + path.basename(OUT) + '.');
    process.exit(1);
  }
  console.log('GATE PASSED: none of [' + failOn.join(', ') + '] present.');
}
