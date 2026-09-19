#!/usr/bin/env node
'use strict';

// Renders the script descriptions from package.json.
//
// WHY THIS EXISTS. There are 23 npm scripts, several of which modify files
// or register OS-level persistence, and JSON cannot carry comments. A README
// table would answer it, but a table in a different file drifts: this reads
// package.json itself, so the documentation cannot describe a script that is
// no longer there.
//
// It also reports the drift in BOTH directions -- a script with no
// description, and a description for a script that no longer exists --
// because a help text that silently omits a command is worse than none.
//
//   npm run help              grouped summaries
//   npm run help <name>       the full detail for one command
//   npm run help --all        every summary AND detail

const fs = require('fs');
const path = require('path');

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8'));
const scripts = pkg.scripts || {};
const info = pkg.scriptsInfo || {};

const args = process.argv.slice(2).filter((a) => a !== '--');
const ALL = args.includes('--all');
const only = args.find((a) => !a.startsWith('--'));

function wrap(text, width, indent) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if (line && (line + ' ' + w).length > width) {
      lines.push(line);
      line = w;
    } else {
      line = line ? line + ' ' + w : w;
    }
  }
  if (line) lines.push(line);
  return lines.map((l, i) => (i === 0 ? l : indent + l)).join('\n');
}

// ---------------------------------------------------------------- one command

if (only) {
  const i = info[only];
  if (!scripts[only]) {
    console.error('no such script: ' + only);
    console.error('run `npm run help` for the list');
    process.exit(1);
  }
  console.log('');
  console.log('  npm run ' + only);
  console.log('  ' + '-'.repeat(Math.max(10, only.length + 8)));
  console.log('  runs: ' + scripts[only]);
  console.log('');
  if (i) {
    console.log('  ' + wrap(i.summary, 72, '  '));
    if (i.detail) {
      console.log('');
      console.log('  ' + wrap(i.detail, 72, '  '));
    }
  } else {
    console.log('  (no description recorded for this script)');
  }
  console.log('');
  process.exit(0);
}

// ------------------------------------------------------------------ the list

const GROUP_ORDER = [
  'Start here',
  'Running it',
  'Proving it works',
  'Keeping it running',
  'IP masking',
  'On-disk residue',
  'Rules and patterns',
  'Publishing safely',
];

const groups = new Map();
for (const name of Object.keys(scripts)) {
  const i = info[name];
  const g = (i && i.group) || 'Other';
  if (!groups.has(g)) groups.set(g, []);
  groups.get(g).push(name);
}

const ordered = GROUP_ORDER.filter((g) => groups.has(g)).concat(
  [...groups.keys()].filter((g) => GROUP_ORDER.indexOf(g) === -1).sort()
);

const width = Math.max.apply(null, Object.keys(scripts).map((s) => s.length));

console.log('');
console.log('  ' + pkg.name + ' — ' + Object.keys(scripts).length + ' commands');
console.log('');

for (const g of ordered) {
  console.log('  ' + g.toUpperCase());
  for (const name of groups.get(g)) {
    const i = info[name];
    const summary = i ? i.summary : '(undocumented)';
    console.log('    ' + name.padEnd(width) + '  ' + wrap(summary, 70 - width, '    ' + ' '.repeat(width + 2)));
    if (ALL && i && i.detail) {
      console.log('    ' + ' '.repeat(width + 2) + wrap(i.detail, 70 - width, '    ' + ' '.repeat(width + 2)));
      console.log('');
    }
  }
  console.log('');
}

console.log('  npm run help <name>   full detail for one command');
console.log('  npm run help --all    every detail at once');

// Drift, reported in both directions. A description that outlives its script
// is how a help text starts lying.
const undocumented = Object.keys(scripts).filter((s) => !info[s]);
const orphaned = Object.keys(info).filter((s) => !scripts[s]);
if (undocumented.length || orphaned.length) {
  console.log('');
  if (undocumented.length) console.log('  WARNING: no description for: ' + undocumented.join(', '));
  if (orphaned.length) console.log('  WARNING: description for missing script(s): ' + orphaned.join(', '));
  process.exitCode = 1;
}
console.log('');
