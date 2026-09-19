#!/usr/bin/env node
'use strict';

// Works out the next version from the commits since the last release tag,
// using Conventional Commits. Zero dependencies, like everything else here.
//
// WHY NOT semantic-release OR release-please. Both are good. Both would mean
// this repository's release process depends on code nobody here has read, in
// a project whose entire argument is that a privacy tool should be
// inspectable rather than trusted. The rules below fit in one file:
//
//   BREAKING CHANGE: in the body, or a `!` before the colon  -> major
//   feat:                                                    -> minor
//   fix: / perf: / revert:                                   -> patch
//   anything else (chore, docs, test, ci, refactor, style)   -> no release
//
// THE LAST LINE IS THE IMPORTANT ONE. Releasing on every push to main would
// cut a version for a typo fix in the README, and a changelog where most
// entries say "chore: tidy" is a changelog nobody reads. A release should
// mean something changed for the person installing it.
//
//   node src/cli/version.js              human-readable
//   node src/cli/version.js --json       for CI
//   node src/cli/version.js --changelog  the notes for this release

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const JSON_OUT = process.argv.includes('--json');
const CHANGELOG = process.argv.includes('--changelog');

function git(args, fallback = '') {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', windowsHide: true }).trim();
  } catch (e) {
    return fallback;
  }
}

const pkgPath = path.join(ROOT, 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const current = pkg.version;

// The last tag that looks like a release. Not `git describe --tags`, which
// also picks up annotated tags people add for other reasons.
const lastTag = git(['tag', '--list', 'v*', '--sort=-v:refname'], '').split('\n').filter(Boolean)[0] || null;

const range = lastTag ? lastTag + '..HEAD' : 'HEAD';
// %B is the full message including the body, because BREAKING CHANGE lives
// there. \x00 as the separator: a commit body can contain anything, and a
// newline-delimited format would split messages in half.
const raw = git(['log', range, '--format=%H%x1f%B%x00'], '');
const commits = raw
  .split('\x00')
  .map((c) => c.trim())
  .filter(Boolean)
  .map((c) => {
    const [sha, ...rest] = c.split('\x1f');
    const message = rest.join('\x1f');
    const subject = message.split('\n')[0];
    const m = /^(\w+)(\([^)]*\))?(!)?:\s*(.+)$/.exec(subject);
    return {
      sha: sha.slice(0, 7),
      subject,
      message,
      type: m ? m[1].toLowerCase() : null,
      scope: m && m[2] ? m[2].slice(1, -1) : null,
      bang: Boolean(m && m[3]),
      description: m ? m[4] : subject,
    };
  });

const MINOR = new Set(['feat']);
const PATCH = new Set(['fix', 'perf', 'revert']);

let bump = null;
for (const c of commits) {
  // A `!` or a BREAKING CHANGE footer outranks the type entirely.
  if (c.bang || /^BREAKING[ -]CHANGE:/m.test(c.message)) {
    bump = 'major';
    break;
  }
  if (MINOR.has(c.type)) bump = 'minor';
  else if (PATCH.has(c.type) && bump !== 'minor') bump = 'patch';
}

function next(version, kind) {
  const [maj, min, pat] = version.split('.').map(Number);
  if (kind === 'major') return maj + 1 + '.0.0';
  if (kind === 'minor') return maj + '.' + (min + 1) + '.0';
  return maj + '.' + min + '.' + (pat + 1);
}

const nextVersion = bump ? next(current, bump) : current;

// ------------------------------------------------------------- changelog

function notes() {
  const groups = {
    major: { title: 'Breaking changes', items: [] },
    feat: { title: 'Features', items: [] },
    fix: { title: 'Fixes', items: [] },
    perf: { title: 'Performance', items: [] },
  };
  for (const c of commits) {
    const breaking = c.bang || /^BREAKING[ -]CHANGE:/m.test(c.message);
    const line = '- ' + (c.scope ? '**' + c.scope + '**: ' : '') + c.description + ' (' + c.sha + ')';
    if (breaking) groups.major.items.push(line);
    else if (c.type === 'feat') groups.feat.items.push(line);
    else if (c.type === 'fix') groups.fix.items.push(line);
    else if (c.type === 'perf') groups.perf.items.push(line);
  }
  const out = [];
  for (const g of Object.values(groups)) {
    if (!g.items.length) continue;
    out.push('### ' + g.title, '', ...g.items, '');
  }
  // Everything else is summarised rather than listed. A reader wants to know
  // housekeeping happened, not to read 20 lines of it.
  const other = commits.filter(
    (c) => !['feat', 'fix', 'perf'].includes(c.type) && !c.bang && !/^BREAKING[ -]CHANGE:/m.test(c.message)
  ).length;
  if (other) out.push('_Plus ' + other + ' maintenance commit' + (other === 1 ? '' : 's') + '._', '');
  return out.join('\n').trim();
}

// ---------------------------------------------------------------- output

if (CHANGELOG) {
  console.log(notes() || '_No user-facing changes._');
  process.exit(0);
}

if (JSON_OUT) {
  console.log(
    JSON.stringify(
      {
        current,
        next: nextVersion,
        bump,
        releasable: Boolean(bump),
        lastTag,
        commits: commits.length,
        notes: notes(),
      },
      null,
      2
    )
  );
  process.exit(0);
}

console.log('  current version : ' + current);
console.log('  last tag        : ' + (lastTag || '(none)'));
console.log('  commits since   : ' + commits.length);
console.log('  bump            : ' + (bump || 'none'));
console.log('  next version    : ' + (bump ? nextVersion : current + '  (nothing releasable)'));
if (bump) {
  console.log('');
  console.log(notes());
}
