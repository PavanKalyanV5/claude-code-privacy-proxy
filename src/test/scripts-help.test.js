'use strict';

// Keeps package.json's script descriptions honest.
//
// Documentation in a different file from the thing it documents drifts, and
// the drift is silent: a command gets added, the table does not, and the
// help output quietly omits it. Since several of these scripts modify files
// or register OS-level persistence, an undocumented one is a command someone
// runs without knowing what it does.
//
// So the descriptions live in package.json beside the scripts, and this
// asserts the two stay in step.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

test('every script has a description', () => {
  const missing = Object.keys(pkg.scripts || {}).filter((s) => !(pkg.scriptsInfo || {})[s]);
  assert.deepStrictEqual(missing, [], 'undocumented script(s): ' + missing.join(', '));
});

test('no description outlives its script', () => {
  // The direction people forget. A description for a deleted command is how
  // help text starts describing behaviour that no longer exists.
  const orphaned = Object.keys(pkg.scriptsInfo || {}).filter((s) => !(pkg.scripts || {})[s]);
  assert.deepStrictEqual(orphaned, [], 'description(s) for missing script(s): ' + orphaned.join(', '));
});

test('each description has a group and a summary', () => {
  for (const [name, i] of Object.entries(pkg.scriptsInfo || {})) {
    assert.ok(i.group, name + ' has no group');
    assert.ok(i.summary && i.summary.length > 10, name + ' has no usable summary');
    // A summary that runs past a terminal width stops being scannable,
    // which is the only thing a summary is for.
    assert.ok(i.summary.length <= 90, name + ' summary is too long to scan: ' + i.summary.length + ' chars');
  }
});

test('destructive commands say so in their detail', () => {
  // These either modify the user's files or register persistence. Someone
  // reading the help must not have to infer that from the name.
  const mustWarn = {
    'scrub:apply': /backup|rewrit/i,
    'stop': /connection errors|restart/i,
    'supervise:install': /logon|administrator|task/i,
    'patterns:adopt': /back|dry run/i,
    'pii:report': /local|values|delet/i,
  };
  for (const [name, re] of Object.entries(mustWarn)) {
    const i = (pkg.scriptsInfo || {})[name];
    assert.ok(i, name + ' is missing entirely');
    assert.match(i.detail || '', re, name + ' detail does not explain its effect');
  }
});

test('help runs and lists every script', () => {
  const out = execFileSync(process.execPath, [path.join(ROOT, 'src', 'cli', 'help.js')], {
    encoding: 'utf8',
    windowsHide: true,
    cwd: ROOT,
  });
  for (const name of Object.keys(pkg.scripts || {})) {
    assert.ok(out.includes(name), 'help output omits ' + name);
  }
  assert.ok(!/WARNING/.test(out), 'help reported drift: ' + out.slice(-300));
});

test('help for one command prints what it actually runs', () => {
  const out = execFileSync(process.execPath, [path.join(ROOT, 'src', 'cli', 'help.js'), 'doctor'], {
    encoding: 'utf8',
    windowsHide: true,
    cwd: ROOT,
  });
  assert.match(out, /runs: node src\/doctor\.js/);
  assert.match(out, /end to end/i);
});

test('the VS Code config is regenerated from the same descriptions', () => {
  // Three surfaces describe these commands: `npm run help`, the Run Task
  // picker, and the Run and Debug list. All three are generated from
  // scriptsInfo so they cannot say three different things -- but only if
  // someone remembers to regenerate. This fails the build instead.
  const r = require('child_process').spawnSync(
    process.execPath,
    [path.join(ROOT, 'src', 'cli', 'vscode-config.js'), '--check'],
    { encoding: 'utf8', windowsHide: true, cwd: ROOT }
  );
  assert.strictEqual(r.status, 0, 'run `npm run vscode` to regenerate:\n' + r.stdout);
});

test('every command appears in the VS Code task picker, with its description', () => {
  const tasks = JSON.parse(fs.readFileSync(path.join(ROOT, '.vscode', 'tasks.json'), 'utf8')).tasks;
  const byScript = new Map(tasks.map((t) => [t.script, t]));
  for (const name of Object.keys(pkg.scripts || {})) {
    const t = byScript.get(name);
    assert.ok(t, 'no task for ' + name);
    // The detail is the whole point: without it the picker shows a bare
    // name and the user is back to guessing.
    assert.ok(t.detail && t.detail.length > 20, name + ' has no usable detail');
  }
});

test('commands that change things are flagged in the picker', () => {
  const tasks = JSON.parse(fs.readFileSync(path.join(ROOT, '.vscode', 'tasks.json'), 'utf8')).tasks;
  const byScript = new Map(tasks.map((t) => [t.script, t]));
  // The difference between `scrub` and `scrub:apply` is one rewrites your
  // files. That must be visible BEFORE pressing enter, not after.
  for (const name of ['scrub:apply', 'supervise:install', 'patterns:adopt', 'stop']) {
    assert.match(byScript.get(name).detail, /CHANGES THINGS/, name + ' is not flagged as mutating');
  }
  assert.ok(!/CHANGES THINGS/.test(byScript.get('scrub').detail), 'the dry run must NOT be flagged');
  assert.ok(!/CHANGES THINGS/.test(byScript.get('doctor').detail), 'a read-only check must NOT be flagged');
});

test('no task is registered as the default build task', () => {
  // Ctrl+Shift+B must never run something that modifies files.
  const tasks = JSON.parse(fs.readFileSync(path.join(ROOT, '.vscode', 'tasks.json'), 'utf8')).tasks;
  for (const t of tasks) {
    if (t.group && t.group.kind === 'build' && t.group.isDefault) {
      assert.fail(t.label + ' is the default build task');
    }
  }
});

test('an unknown command name fails rather than printing nothing', () => {
  let failed = false;
  try {
    execFileSync(process.execPath, [path.join(ROOT, 'src', 'cli', 'help.js'), 'no-such-script'], {
      encoding: 'utf8',
      windowsHide: true,
      stdio: 'pipe',
      cwd: ROOT,
    });
  } catch (e) {
    failed = true;
  }
  assert.ok(failed, 'help must exit non-zero for an unknown script');
});
