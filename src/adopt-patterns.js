#!/usr/bin/env node
'use strict';

// Merges a pattern set into your live redact-rules.json.
//
// WHY A SCRIPT. The rules file holds real personal data, so it is not
// something to hand-edit through an assistant that would then have it in
// context. This process reads and writes it; nothing else sees the contents.
// The console output is counts and pattern names only.
//
// Refuses to do anything unsafe:
//   - backs up first, and restores that backup if the result will not parse
//   - screens every incoming pattern for catastrophic backtracking, because
//     a quadratic regex hung this proxy for 42 seconds once already
//   - skips names that already exist rather than duplicating or overwriting
//     a pattern you may have tuned
//
//   node src/adopt-patterns.js                      dry run
//   node src/adopt-patterns.js --write              apply
//   node src/adopt-patterns.js --from other.json    a different source

const fs = require('fs');
const path = require('path');
const { isPatternSafe, RULES_PATH } = require('./rules');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const WRITE = process.argv.includes('--write');
const FROM = path.resolve(arg('--from', path.join(__dirname, '..', 'config', 'patterns.example.json')));
const TARGET = process.env.CCR_RULES_PATH || RULES_PATH;

let incoming;
try {
  incoming = JSON.parse(fs.readFileSync(FROM, 'utf8')).patterns || [];
} catch (e) {
  console.error('could not read pattern source ' + FROM + ': ' + e.message);
  process.exit(1);
}

let raw;
let cfg;
try {
  raw = fs.readFileSync(TARGET, 'utf8');
  cfg = JSON.parse(raw);
} catch (e) {
  // A malformed rules file is the one state where writing would make things
  // materially worse, so this stops rather than trying to repair it.
  console.error('rules file is unreadable or not valid JSON; refusing to touch it.');
  console.error('  ' + e.message);
  process.exit(1);
}

const existing = Array.isArray(cfg.patterns) ? cfg.patterns : [];
const haveNames = new Set(existing.map((p) => p && p.name).filter(Boolean));
const haveRegex = new Set(existing.map((p) => p && p.regex).filter(Boolean));

const toAdd = [];
const skipped = [];
const rejected = [];

for (const p of incoming) {
  if (!p || typeof p.regex !== 'string') continue;
  if (haveNames.has(p.name)) {
    skipped.push(p.name + ' (name already present)');
    continue;
  }
  if (haveRegex.has(p.regex)) {
    skipped.push(p.name + ' (identical regex already present)');
    continue;
  }
  const verdict = isPatternSafe(p.regex, p.flags || 'g');
  if (!verdict.ok) {
    rejected.push(p.name + ': ' + verdict.why);
    continue;
  }
  // _why is documentation for the example file; it does not belong in a
  // live config where every key is read by the loader.
  const { _why, ...clean } = p;
  toAdd.push(clean);
}

console.log('source   : ' + FROM);
console.log('target   : ' + TARGET);
console.log('existing : ' + existing.length + ' pattern(s)');
console.log('to add   : ' + toAdd.length);
for (const p of toAdd) console.log('    + ' + p.name + '  (' + (p.category || 'uncategorised') + ')');
if (skipped.length) {
  console.log('skipped  : ' + skipped.length);
  for (const s of skipped) console.log('    - ' + s);
}
if (rejected.length) {
  console.log('REJECTED : ' + rejected.length + '  (these would be disabled at load anyway)');
  for (const s of rejected) console.log('    ! ' + s);
}

if (!WRITE) {
  console.log('');
  console.log(toAdd.length ? 'dry run — re-run with --write to apply' : 'nothing to do');
  process.exit(0);
}

if (!toAdd.length) {
  console.log('');
  console.log('nothing to add; file untouched');
  process.exit(0);
}

const backup = TARGET + '.backup-patterns-' + Date.now() + '.json';
fs.writeFileSync(backup, raw);

cfg.patterns = existing.concat(toAdd);
fs.writeFileSync(TARGET, JSON.stringify(cfg, null, 2) + '\n');

// Re-read and re-parse. A write that produces invalid JSON would stop the
// proxy from starting at all, which is a far worse outcome than not having
// the new patterns.
try {
  const after = JSON.parse(fs.readFileSync(TARGET, 'utf8'));
  if (!Array.isArray(after.patterns) || after.patterns.length !== existing.length + toAdd.length) {
    throw new Error('pattern count after write does not match what was intended');
  }
} catch (e) {
  fs.writeFileSync(TARGET, raw);
  console.error('');
  console.error('write failed verification (' + e.message + '); ORIGINAL RESTORED.');
  process.exit(1);
}

console.log('');
console.log('added ' + toAdd.length + ' pattern(s); now ' + cfg.patterns.length + ' total');
console.log('backup: ' + path.basename(backup));
console.log('');
console.log('Rules are read at startup, so restart for these to take effect:');
console.log('  npm run stop && npm start      (or wait up to 5 min for the watchdog)');
