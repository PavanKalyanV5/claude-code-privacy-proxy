'use strict';

// Tests for the publish gate.
//
// The gate exists to stop personal data reaching a public repository, so its
// failure modes are asymmetric: a false RED wastes a few minutes, a false
// GREEN publishes someone's name forever. Both defects below produced a
// false green.
//
//   1. `--fail-on identity,personal` was parsed as a PATH, because the arg
//      filter only skipped tokens starting with "--" and not the values that
//      follow them. The gate scanned zero files and reported PASSED.
//
//   2. The gate counted hits from untracked files too, which on any real
//      machine means agent scratch directories and archived configs. That is
//      the opposite failure -- permanently red, and a gate that is always red
//      is one everybody learns to bypass.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', 'pii-report.js');

function makeRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ccr-gate-'));
  const run = (args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', windowsHide: true });
  run(['init', '-q']);
  run(['config', 'user.email', 'test@example.com']);
  run(['config', 'user.name', 'Test']);
  return { dir, run };
}

// Written OUTSIDE the repo under test. A rules file inside it is itself an
// untracked file containing the literal, so it would be counted as a hit and
// skew the tracked/untracked split this suite asserts on.
function rulesFile(dir, literals) {
  const p = path.join(path.dirname(dir), path.basename(dir) + '-rules.json');
  fs.writeFileSync(p, JSON.stringify({ literals: literals.map((v) => ({ value: v, category: 'personal' })), patterns: [] }));
  return p;
}

function runReport(dir, rulesPath, args) {
  return spawnSync(process.execPath, [SCRIPT].concat(args), {
    cwd: dir,
    encoding: 'utf8',
    windowsHide: true,
    env: Object.assign({}, process.env, { CCR_RULES_PATH: rulesPath, HOME: dir, USERPROFILE: dir }),
  });
}

test('the gate scans real files, not the value of --fail-on', () => {
  const { dir, run } = makeRepo();
  try {
    const rules = rulesFile(dir, ['Wilhelmina Fitzgerald']);
    fs.writeFileSync(path.join(dir, 'tracked.md'), 'contact Wilhelmina Fitzgerald today\n');
    run(['add', 'tracked.md']);

    const r = runReport(dir, rules, ['--tracked', '--out', 'out.txt', '--fail-on', 'personal']);
    // The original bug: "personal" became the scan target, nothing matched
    // it, and the gate passed having examined no files at all.
    assert.match(r.stdout, /files scanned\s*:\s*[1-9]/, 'must actually scan something: ' + r.stdout);
    assert.match(r.stdout, /GATE FAILED/, 'a tracked personal value must fail the gate');
    assert.notStrictEqual(r.status, 0, 'a failing gate must exit non-zero');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the gate ignores untracked files', () => {
  const { dir, run } = makeRepo();
  try {
    const rules = rulesFile(dir, ['Wilhelmina Fitzgerald']);
    fs.writeFileSync(path.join(dir, 'tracked.md'), 'nothing sensitive here\n');
    run(['add', 'tracked.md']);
    // Scratch content that will never be published. Counting this would keep
    // the gate permanently red on any working machine.
    fs.writeFileSync(path.join(dir, 'scratch.md'), 'Wilhelmina Fitzgerald\n');

    const r = runReport(dir, rules, ['--tracked', '--out', 'out.txt', '--fail-on', 'personal']);
    assert.match(r.stdout, /GATE PASSED/, 'untracked hits must not fail the gate: ' + r.stdout);
    assert.strictEqual(r.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a default scan separates what publishes from what is local', () => {
  const { dir, run } = makeRepo();
  try {
    const rules = rulesFile(dir, ['Wilhelmina Fitzgerald']);
    fs.writeFileSync(path.join(dir, 'tracked.md'), 'Wilhelmina Fitzgerald\n');
    run(['add', 'tracked.md']);
    fs.writeFileSync(path.join(dir, 'scratch.md'), 'Wilhelmina Fitzgerald\nWilhelmina Fitzgerald\n');

    const r = runReport(dir, rules, ['.', '--out', 'out.txt']);
    // The split is what makes the report actionable: the two numbers call
    // for completely different responses.
    assert.match(r.stdout, /WILL PUBLISH \(git-tracked\)\s*:\s*1\b/, r.stdout);
    assert.match(r.stdout, /local only\s+\(untracked\)\s*:\s*2\b/, r.stdout);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the report never writes values to stdout', () => {
  const { dir, run } = makeRepo();
  try {
    const rules = rulesFile(dir, ['Wilhelmina Fitzgerald']);
    fs.writeFileSync(path.join(dir, 'tracked.md'), 'Wilhelmina Fitzgerald\n');
    run(['add', 'tracked.md']);

    const r = runReport(dir, rules, ['.', '--out', 'out.txt']);
    // Console output is read by terminals, CI logs and models. The values go
    // to the file and nowhere else.
    assert.ok(!r.stdout.includes('Wilhelmina'), 'stdout leaked a value');
    const written = fs.readFileSync(path.join(dir, 'out.txt'), 'utf8');
    assert.ok(written.includes('Wilhelmina'), 'the file is supposed to carry the values');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the report never scans its own output', () => {
  const { dir, run } = makeRepo();
  try {
    const rules = rulesFile(dir, ['Wilhelmina Fitzgerald']);
    fs.writeFileSync(path.join(dir, 'tracked.md'), 'Wilhelmina Fitzgerald\n');
    run(['add', 'tracked.md']);

    const first = runReport(dir, rules, ['.', '--out', 'out.txt']);
    const second = runReport(dir, rules, ['.', '--out', 'out.txt']);
    const n = (s) => Number(/total occurrences:\s*(\d+)/.exec(s)[1]);
    // Observed before the fix: 571 became 1957 on the second run.
    assert.strictEqual(n(first.stdout), n(second.stdout), 'counts must be stable across runs');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
