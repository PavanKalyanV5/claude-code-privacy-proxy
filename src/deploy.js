#!/usr/bin/env node
'use strict';

// Installs a self-contained copy of the proxy into ~/.claude, so the thing
// protecting you is not the same tree you are editing.
//
// WHY THIS EXISTS. Development has been happening in the directory that the
// live proxy, the logon launcher and the 5-minute watchdog all point at. That
// means an edit mid-session changes the running system, a rename breaks the
// launcher silently (it already did once, throwing a Windows Script Host
// dialog at every logon), and a half-finished refactor is indistinguishable
// from a working install. Protection should not move when the source does.
//
// After deploying, everything points at ~/.claude/privacy-proxy and the
// development tree is free to be edited, renamed, or published.
//
// WHAT IS COPIED. src/, config/, package.json, README, LICENSE. Not .git, not
// docs, not archive, not the agent scratch directories. Tests come along
// deliberately: being able to run the suite against the DEPLOYED copy is what
// makes "is the thing actually protecting me intact?" an answerable question.
//
// SAFE TO RE-RUN, INCLUDING OVER A RUNNING PROXY. Each file is written to a
// temporary name and renamed into place, so no file is ever half-written.
//
// It does NOT stage a whole directory and swap it in, which is what the first
// version did: Windows refuses to rename a directory that is any process's
// current working directory, so the moment the watchdog started the proxy
// from the deployed copy, every redeploy failed with EBUSY. Per-file renames
// have no such restriction. Overwriting a .js file that a running Node
// process already loaded is safe -- it keeps its loaded copy until restarted.
//
// The manifest is written LAST. An interrupted deploy therefore leaves the
// OLD manifest in place, and `status` reports drift rather than claiming a
// successful deploy that did not finish.
//
//   node src/deploy.js install     copy this tree to ~/.claude/privacy-proxy
//   node src/deploy.js status      compare deployed against this tree
//   node src/deploy.js --target X  deploy somewhere else

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const SRC_ROOT = path.join(__dirname, '..');
const HOME = process.env.HOME || os.homedir();

function argValue(name) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : null;
}

const TARGET = argValue('--target') || path.join(HOME, '.claude', 'privacy-proxy');
const MANIFEST = 'DEPLOYED.json';

// Copied wholesale. Anything not listed here does not reach the deployed
// copy, which is the point: an allowlist cannot accidentally ship .git or a
// scratch directory the way an ignore-list eventually does.
const INCLUDE = ['src', 'config', 'package.json', 'README.md', 'LICENSE'];

// Excluded even inside the included paths.
const EXCLUDE_DIRS = new Set(['node_modules', '.git', '.playwright-mcp', '.superpowers', 'dash-data']);

function listFiles(rel, out = []) {
  const abs = path.join(SRC_ROOT, rel);
  let st;
  try {
    st = fs.statSync(abs);
  } catch (e) {
    return out;
  }
  if (st.isFile()) {
    out.push(rel);
    return out;
  }
  if (!st.isDirectory()) return out;
  if (EXCLUDE_DIRS.has(path.basename(abs))) return out;
  for (const name of fs.readdirSync(abs)) {
    if (EXCLUDE_DIRS.has(name)) continue;
    listFiles(path.join(rel, name), out);
  }
  return out;
}

function hashFile(p) {
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex').slice(0, 16);
}

function gitInfo() {
  const run = (args) => {
    try {
      return execFileSync('git', args, { cwd: SRC_ROOT, encoding: 'utf8', windowsHide: true }).trim();
    } catch (e) {
      return null;
    }
  };
  return {
    commit: run(['rev-parse', '--short', 'HEAD']),
    branch: run(['rev-parse', '--abbrev-ref', 'HEAD']),
    // A dirty tree is not refused -- sometimes you deploy work in progress on
    // purpose -- but it IS recorded, so "which code is actually running" has
    // an answer later.
    dirty: Boolean(run(['status', '--porcelain'])),
  };
}

// ------------------------------------------------------------------ install

function install() {
  const files = INCLUDE.reduce((acc, rel) => listFiles(rel, acc), []);
  if (!files.length) {
    console.error('deploy: nothing to copy from ' + SRC_ROOT);
    process.exit(1);
  }

  if (path.resolve(TARGET) === path.resolve(SRC_ROOT)) {
    console.error('deploy: target is the source tree; that would defeat the purpose');
    process.exit(1);
  }

  // Read the outgoing manifest first so files that have since been deleted
  // from the source can be pruned from the install. Without this, a module
  // removed here lingers there forever and may still be require()d.
  let priorFiles = {};
  try {
    priorFiles = JSON.parse(fs.readFileSync(path.join(TARGET, MANIFEST), 'utf8')).files || {};
  } catch (e) {
    /* first deploy, or an interrupted one; nothing to prune against */
  }

  const manifest = { files: {} };
  let written = 0;
  for (const rel of files) {
    const from = path.join(SRC_ROOT, rel);
    const to = path.join(TARGET, rel);
    const key = rel.split(path.sep).join('/');
    const hash = hashFile(from);
    manifest.files[key] = hash;

    // Skip files that are already byte-identical. On a re-deploy this makes
    // the operation touch only what actually changed.
    try {
      if (hashFile(to) === hash) continue;
    } catch (e) {
      /* not there yet */
    }
    fs.mkdirSync(path.dirname(to), { recursive: true });
    const tmp = to + '.tmp';
    fs.copyFileSync(from, tmp);
    fs.renameSync(tmp, to); // atomic per file, and legal while the dir is in use
    written++;
  }

  const pruned = [];
  for (const key of Object.keys(priorFiles)) {
    if (manifest.files[key]) continue;
    try {
      fs.unlinkSync(path.join(TARGET, key.split('/').join(path.sep)));
      pruned.push(key);
    } catch (e) {
      /* already gone */
    }
  }

  const git = gitInfo();
  // Last, deliberately: see the header note on interrupted deploys.
  fs.writeFileSync(
    path.join(TARGET, MANIFEST),
    JSON.stringify(
      {
        deployedAt: new Date().toISOString(),
        from: SRC_ROOT,
        git,
        fileCount: files.length,
        files: manifest.files,
      },
      null,
      2
    )
  );

  console.log('deployed to ' + TARGET);
  console.log('  files   : ' + files.length + ' (' + written + ' written, ' + (files.length - written) + ' already current)');
  if (pruned.length) console.log('  pruned  : ' + pruned.length + ' file(s) no longer in the source');
  console.log('  commit  : ' + (git.commit || 'unknown') + (git.dirty ? ' (WORKING TREE WAS DIRTY)' : '') + ' on ' + (git.branch || '?'));
  console.log('');
  console.log('Next, from the DEPLOYED copy so everything points at it:');
  console.log('');
  console.log('  cd "' + TARGET + '"');
  console.log('  npm test                    # prove the copy is intact');
  console.log('  npm run supervise:install   # repoint logon + watchdog here');
  console.log('');
  console.log('Then update the hook paths in ~/.claude/settings.json to:');
  console.log('  node "' + path.join(TARGET, 'src', 'lifecycle.js') + '" start');
  console.log('  node "' + path.join(TARGET, 'src', 'lifecycle.js') + '" stop');
}

// ------------------------------------------------------------------- status

function status() {
  const manifestPath = path.join(TARGET, MANIFEST);
  let deployed;
  try {
    deployed = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (e) {
    console.log('Nothing deployed at ' + TARGET);
    console.log('Run: node src/deploy.js install');
    process.exitCode = 1;
    return;
  }

  console.log('deployed at ' + TARGET);
  console.log('  when   : ' + deployed.deployedAt);
  console.log('  commit : ' + ((deployed.git && deployed.git.commit) || 'unknown') + ((deployed.git && deployed.git.dirty) ? ' (dirty)' : ''));
  console.log('  files  : ' + deployed.fileCount);

  // Drift in both directions matters. A file that changed here but not there
  // means the deployed copy is stale; a file that changed THERE means someone
  // edited the live install directly, and the next deploy will silently
  // discard it.
  const current = INCLUDE.reduce((acc, rel) => listFiles(rel, acc), []).map((r) => r.split(path.sep).join('/'));
  const changed = [];
  const missing = [];
  const edited = [];
  for (const rel of current) {
    const here = hashFile(path.join(SRC_ROOT, rel));
    const recorded = deployed.files[rel];
    if (!recorded) {
      missing.push(rel);
      continue;
    }
    if (recorded !== here) changed.push(rel);
    const livePath = path.join(TARGET, rel);
    try {
      if (hashFile(livePath) !== recorded) edited.push(rel);
    } catch (e) {
      edited.push(rel + ' (missing from the deployed copy)');
    }
  }
  const removed = Object.keys(deployed.files).filter((r) => !current.includes(r));

  console.log('');
  if (!changed.length && !missing.length && !removed.length && !edited.length) {
    console.log('  in sync with this tree');
    return;
  }
  const show = (label, list) => {
    if (!list.length) return;
    console.log('  ' + label + ' (' + list.length + '):');
    for (const r of list.slice(0, 15)) console.log('      ' + r);
    if (list.length > 15) console.log('      ... and ' + (list.length - 15) + ' more');
  };
  show('changed here since deploy', changed);
  show('new here, not deployed', missing);
  show('deleted here, still deployed', removed);
  show('EDITED IN THE DEPLOYED COPY (a redeploy will discard these)', edited);
  console.log('');
  console.log('  Redeploy with: node src/deploy.js install');
  process.exitCode = 1;
}

const MODE = (process.argv[2] || 'status').toLowerCase();
if (require.main === module) {
  if (MODE === 'install') install();
  else if (MODE === 'status') status();
  else {
    console.error('usage: node src/deploy.js install|status [--target DIR]');
    process.exit(2);
  }
}

module.exports = { listFiles, INCLUDE, TARGET };
