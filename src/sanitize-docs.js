#!/usr/bin/env node
'use strict';

// Replaces real identity values (the `real` side of every alias) with an
// obviously-synthetic placeholder, in the files that are actually tracked by
// git and would therefore be published.
//
// WHY A SCRIPT AND NOT A HAND EDIT. Everything the model reads has already
// been through redaction, so an assistant editing these files sees
// "example-user" where the disk holds "C:\Users\<your real name>". An
// exact-match edit is impossible against text you cannot see, and a
// find-and-replace typed from memory would either miss or corrupt. This
// script reads the real values from the rules at RUNTIME, so they are
// resolved by the process doing the work and never surface anywhere.
//
// Documentation written while a project is live tends to acquire real values
// in exactly the place that claims to show anonymised output -- this repo's
// README showed a real username as the supposedly-safe right-hand side of a
// before/after table. That is the specific defect this exists to remove.
//
//   node src/sanitize-docs.js            report what would change
//   node src/sanitize-docs.js --write    apply

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { load } = require('./rules');

const WRITE = process.argv.includes('--write');
const PLACEHOLDER = 'example-user';

const rules = load();

// Longest first, so a value that contains another is replaced whole rather
// than being partly consumed by the shorter one.
const REAL = (rules.aliases || [])
  .map((a) => (a && typeof a.real === 'string' ? a.real : null))
  .filter((v) => v && v.length >= 3)
  .sort((a, b) => b.length - a.length);

if (!REAL.length) {
  console.log('no aliases configured; nothing to sanitise');
  process.exit(0);
}

let tracked;
try {
  tracked = execFileSync('git', ['ls-files'], { encoding: 'utf8', windowsHide: true })
    .split(/\r?\n/)
    .filter(Boolean);
} catch (e) {
  console.error('not a git repository, or git is unavailable: ' + e.message);
  process.exit(1);
}

const TEXT_EXT = new Set(['.md', '.txt', '.json', '.js', '.yml', '.yaml', '.html', '.css', '.example']);

let filesChanged = 0;
let totalReplaced = 0;
const perFile = [];

for (const rel of tracked) {
  if (!TEXT_EXT.has(path.extname(rel).toLowerCase())) continue;
  let text;
  try {
    text = fs.readFileSync(rel, 'utf8');
  } catch (e) {
    continue;
  }

  let out = text;
  let n = 0;
  for (const real of REAL) {
    // Case-insensitive, because a username appears lowercase in paths and
    // capitalised in prose, and a case-sensitive pass has already missed
    // occurrences in this project once before.
    const parts = [];
    let i = 0;
    const hay = out.toLowerCase();
    const needle = real.toLowerCase();
    for (;;) {
      const at = hay.indexOf(needle, i);
      if (at === -1) break;
      parts.push(out.slice(i, at), PLACEHOLDER);
      i = at + real.length;
      n++;
    }
    if (parts.length) {
      parts.push(out.slice(i));
      out = parts.join('');
    }
  }

  if (!n) continue;
  filesChanged++;
  totalReplaced += n;
  perFile.push({ rel, n });
  if (WRITE) fs.writeFileSync(rel, out);
}

// Counts and paths only. The values being removed are precisely what must
// not be echoed to a terminal.
for (const f of perFile) console.log('  ' + f.rel + ': ' + f.n + ' occurrence(s)');
console.log('');
console.log((WRITE ? 'replaced ' : 'would replace ') + totalReplaced + ' occurrence(s) across ' + filesChanged + ' tracked file(s)');
if (!WRITE && totalReplaced) console.log('re-run with --write to apply');
