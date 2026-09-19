'use strict';

// Tests for src/residue-index.js and its wiring into scan-residue.js /
// scrub-residue.js.
//
// Fixture directories only. Nothing here reads, writes, or points at
// ~/.claude/redaction/redact-rules.json, and every CLI invocation is given an
// explicit HOME and CCR_RESIDUE_INDEX_PATH pointing inside a temp dir, so no
// test can accidentally create or touch a real index under the user's
// ~/.claude.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const { createIndex, computeRulesFingerprint } = require('../residue-index');

// ============================================================ Test Utilities

function mkfix() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'residue-idx-'));
  const work = path.join(dir, 'work');
  fs.mkdirSync(work, { recursive: true });
  return {
    dir,
    work,
    rules: path.join(dir, 'rules.json'),
    key: path.join(dir, 'key.bin'),
    log: path.join(dir, 'proxy.log'),
    index: path.join(dir, 'residue-index.json'),
    clean() { try { fs.rmSync(this.dir, { recursive: true, force: true }); } catch (e) { } },
  };
}

function baseRules(literals) {
  return {
    literals: literals || ['SecretTest'],
    patterns: [],
    aliases: [],
    normalize: { timezone: false, rewrites: [] },
    proxy: { port: 47113 },
  };
}

function writeRules(f, rules) {
  fs.writeFileSync(f.rules, JSON.stringify(rules));
}

function writeKey(f) {
  fs.writeFileSync(f.key, Buffer.alloc(32, 7));
}

function run(script, args, env) {
  const res = spawnSync(process.execPath, [script, ...args], {
    cwd: env.cwd || os.tmpdir(),
    env: Object.assign({}, process.env, env),
    encoding: 'utf8',
    timeout: 20000,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  return { code: res.status, out: res.stdout || '', err: res.stderr || '' };
}

function scanJson(f, args) {
  const r = run(path.join(ROOT, 'src', 'scan-residue.js'), ['--json', ...(args || []), f.work], {
    CCR_RULES_PATH: f.rules,
    CCR_RESIDUE_INDEX_PATH: f.index,
    HOME: f.dir,
    cwd: f.dir,
  });
  let json = null;
  try { json = JSON.parse(r.out); } catch (e) { /* leave null, caller asserts */ }
  return { code: r.code, out: r.out, err: r.err, json };
}

function scrubRun(f, args) {
  return run(path.join(ROOT, 'src', 'scrub-residue.js'), [...(args || []), f.work], {
    CCR_RULES_PATH: f.rules,
    CCR_KEY_PATH: f.key,
    CCR_LOG_PATH: f.log,
    CCR_RESIDUE_INDEX_PATH: f.index,
    HOME: f.dir,
    cwd: f.dir,
  });
}

function num(re, out) {
  const m = re.exec(out);
  return m ? Number(m[1]) : null;
}

// ================================================================ unit: index

test('residue-index: a clean file is marked and then reported clean', () => {
  const f = mkfix();
  try {
    const idx = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-1' });
    idx.load();
    const stat = { mtimeMs: 1000, size: 10 };
    assert.strictEqual(idx.isClean('/some/path.txt', stat), false, 'unknown file is not clean');
    idx.markClean('/some/path.txt', stat);
    assert.strictEqual(idx.isClean('/some/path.txt', stat), true, 'marked-clean file matches its stat');
  } finally {
    f.clean();
  }
});

test('residue-index: persists across save/load with matching fingerprint', () => {
  const f = mkfix();
  try {
    const stat = { mtimeMs: 2000, size: 20 };
    const w = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-A' });
    w.load();
    w.markClean('/x/file.txt', stat);
    w.save();

    const r = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-A' });
    r.load();
    assert.strictEqual(r.isClean('/x/file.txt', stat), true, 'reloaded index remembers the entry');
  } finally {
    f.clean();
  }
});

test('residue-index: size changed but mtime did not is re-examined', () => {
  const f = mkfix();
  try {
    const idx = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-1' });
    idx.load();
    idx.markClean('/x/file.txt', { mtimeMs: 5000, size: 10 });
    // Same mtime, different size -- an edit that happened to land in the
    // same filesystem timestamp tick.
    assert.strictEqual(idx.isClean('/x/file.txt', { mtimeMs: 5000, size: 11 }), false);
  } finally {
    f.clean();
  }
});

test('residue-index: mtime changed but size did not is re-examined', () => {
  const f = mkfix();
  try {
    const idx = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-1' });
    idx.load();
    idx.markClean('/x/file.txt', { mtimeMs: 5000, size: 10 });
    // Same size, different mtime -- an equal-length edit (e.g. one value
    // swapped for another of the same length).
    assert.strictEqual(idx.isClean('/x/file.txt', { mtimeMs: 6000, size: 10 }), false);
  } finally {
    f.clean();
  }
});

test('residue-index: markDirty forgets a previously clean entry', () => {
  const f = mkfix();
  try {
    const idx = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-1' });
    idx.load();
    const stat = { mtimeMs: 1, size: 1 };
    idx.markClean('/x/file.txt', stat);
    assert.strictEqual(idx.isClean('/x/file.txt', stat), true);
    idx.markDirty('/x/file.txt');
    assert.strictEqual(idx.isClean('/x/file.txt', stat), false, 'forgotten entry must be re-examined');
  } finally {
    f.clean();
  }
});

test('residue-index: a corrupt index file is treated as empty and does not throw', () => {
  const f = mkfix();
  try {
    fs.writeFileSync(f.index, '{ this is not valid JSON ][');
    const idx = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-1' });
    assert.doesNotThrow(() => idx.load());
    assert.strictEqual(idx.stats().entries, 0);
    assert.strictEqual(idx.isClean('/x/file.txt', { mtimeMs: 1, size: 1 }), false);
  } finally {
    f.clean();
  }
});

test('residue-index: a missing index file is treated as empty and does not throw', () => {
  const f = mkfix();
  try {
    const idx = createIndex({ indexPath: path.join(f.dir, 'does-not-exist.json'), rulesFingerprint: 'fp-1' });
    assert.doesNotThrow(() => idx.load());
    assert.strictEqual(idx.stats().entries, 0);
  } finally {
    f.clean();
  }
});

test('residue-index: a malformed index (entries not an object) is treated as empty', () => {
  const f = mkfix();
  try {
    fs.writeFileSync(f.index, JSON.stringify({ rulesFingerprint: 'fp-1', entries: 'nope' }));
    const idx = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-1' });
    idx.load();
    assert.strictEqual(idx.stats().entries, 0);
  } finally {
    f.clean();
  }
});

test('residue-index: THE CRITICAL CASE -- a changed rules fingerprint discards the whole index', () => {
  const f = mkfix();
  try {
    const stat = { mtimeMs: 1, size: 1 };
    const w = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-old' });
    w.load();
    w.markClean('/x/a.txt', stat);
    w.markClean('/x/b.txt', stat);
    w.save();
    assert.strictEqual(w.stats().entries, 2);

    // Same file, DIFFERENT fingerprint (as if a literal was just added to the
    // rules). Every previously-clean entry must vanish, not just the ones
    // that would newly match -- there is no cheap way to know which those
    // are, so partial invalidation would be exactly the silent lie the brief
    // warns about.
    const r = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-new' });
    r.load();
    assert.strictEqual(r.stats().entries, 0, 'index must load empty when the fingerprint changed');
    assert.strictEqual(r.isClean('/x/a.txt', stat), false);
    assert.strictEqual(r.isClean('/x/b.txt', stat), false);
  } finally {
    f.clean();
  }
});

test('residue-index: computeRulesFingerprint changes when a literal is added, stable otherwise', () => {
  const a = computeRulesFingerprint(baseRules(['Jane']));
  const b = computeRulesFingerprint(baseRules(['Jane']));
  const c = computeRulesFingerprint(baseRules(['Jane', 'NewLiteral']));
  assert.strictEqual(a, b, 'identical rule content must fingerprint identically');
  assert.notStrictEqual(a, c, 'adding a literal must change the fingerprint');
});

test('residue-index: prune drops entries for files that no longer exist', () => {
  const f = mkfix();
  try {
    const idx = createIndex({ indexPath: f.index, rulesFingerprint: 'fp-1' });
    idx.load();
    const stat = { mtimeMs: 1, size: 1 };
    idx.markClean('/x/keep.txt', stat);
    idx.markClean('/x/gone.txt', stat);
    assert.strictEqual(idx.stats().entries, 2);

    idx.prune(new Set(['/x/keep.txt']));
    assert.strictEqual(idx.stats().entries, 1);
    assert.strictEqual(idx.isClean('/x/keep.txt', stat), true);
    assert.strictEqual(idx.isClean('/x/gone.txt', stat), false);
  } finally {
    f.clean();
  }
});

// ============================================================ CLI: scan-residue

test('scan-residue + index: a clean file is skipped on the second pass', () => {
  const f = mkfix();
  try {
    fs.writeFileSync(path.join(f.work, 'clean.txt'), 'nothing sensitive in here at all');
    writeRules(f, baseRules(['NotPresentLiteral']));

    const first = scanJson(f);
    assert.strictEqual(first.code, 0, first.out + first.err);
    assert.ok(first.json, 'first pass must produce valid JSON');
    assert.strictEqual(first.json.filesScanned, 1, 'first pass examines the file');
    assert.strictEqual(first.json.index.skipped, 0, 'nothing to skip yet');

    const second = scanJson(f);
    assert.strictEqual(second.code, 0, second.out + second.err);
    assert.strictEqual(second.json.filesScanned, 0, 'second pass must not re-read the unchanged file');
    assert.strictEqual(second.json.index.skipped, 1, 'second pass must report the skip via the index');
  } finally {
    f.clean();
  }
});

test('scan-residue + index: a file whose content changed is re-examined', () => {
  const f = mkfix();
  try {
    const file = path.join(f.work, 'a.txt');
    fs.writeFileSync(file, 'short');
    writeRules(f, baseRules(['NotPresentLiteral']));

    const first = scanJson(f);
    assert.strictEqual(first.json.filesScanned, 1);

    // New content, different size, and force the mtime forward so this can
    // never land in the same filesystem timestamp tick as the first write.
    fs.writeFileSync(file, 'a much longer replacement body than before');
    const future = (Date.now() + 5000) / 1000;
    fs.utimesSync(file, future, future);

    const second = scanJson(f);
    assert.strictEqual(second.json.filesScanned, 1, 'changed file must be re-examined, not skipped');
    assert.strictEqual(second.json.index.skipped, 0);
  } finally {
    f.clean();
  }
});

test('scan-residue + index: --no-index examines everything every time', () => {
  const f = mkfix();
  try {
    fs.writeFileSync(path.join(f.work, 'clean.txt'), 'nothing sensitive in here at all');
    writeRules(f, baseRules(['NotPresentLiteral']));

    scanJson(f); // build up an index entry
    const second = scanJson(f, ['--no-index']);
    assert.strictEqual(second.json.index.enabled, false);
    assert.strictEqual(second.json.filesScanned, 1, '--no-index must ignore any existing index entry');
  } finally {
    f.clean();
  }
});

test('scan-residue + index: --rebuild-index discards prior entries and re-examines', () => {
  const f = mkfix();
  try {
    fs.writeFileSync(path.join(f.work, 'clean.txt'), 'nothing sensitive in here at all');
    writeRules(f, baseRules(['NotPresentLiteral']));

    scanJson(f); // clean entry now on disk
    const rebuilt = scanJson(f, ['--rebuild-index']);
    assert.strictEqual(rebuilt.json.filesScanned, 1, '--rebuild-index must not trust the old entry');

    // And the new index it just wrote is honoured normally afterwards.
    const after = scanJson(f);
    assert.strictEqual(after.json.filesScanned, 0);
  } finally {
    f.clean();
  }
});

test('scan-residue + index: a corrupt on-disk index does not crash the scan', () => {
  const f = mkfix();
  try {
    fs.writeFileSync(path.join(f.work, 'clean.txt'), 'nothing sensitive in here at all');
    writeRules(f, baseRules(['NotPresentLiteral']));
    fs.writeFileSync(f.index, 'not { valid json');

    const r = scanJson(f);
    assert.strictEqual(r.code, 0, 'a corrupt index must not crash the scan');
    assert.strictEqual(r.json.filesScanned, 1, 'a corrupt index is treated as empty, so the file is examined');
  } finally {
    f.clean();
  }
});

test('scan-residue + index: THE CRITICAL CASE -- adding a literal forces re-examination and finds it', () => {
  const f = mkfix();
  try {
    const file = path.join(f.work, 'transcript.txt');
    fs.writeFileSync(file, 'the secret codeword is PurpleFalcon77 in this message');
    // Rules do NOT yet know about PurpleFalcon77.
    writeRules(f, baseRules(['SomeOtherLiteral']));

    const first = scanJson(f);
    assert.strictEqual(first.json.filesScanned, 1);
    assert.strictEqual(first.json.filesWith, 0, 'the new literal is not yet a rule, so nothing is flagged');

    // The user adds the literal to their rules -- the fingerprint changes.
    writeRules(f, baseRules(['SomeOtherLiteral', 'PurpleFalcon77']));

    const second = scanJson(f);
    assert.strictEqual(second.json.index.entries, 0, 'the rules change must have discarded the whole index');
    assert.strictEqual(second.json.filesScanned, 1, 'the file must be re-examined, not trusted as clean');
    assert.strictEqual(second.json.filesWith, 1, 'the newly-added literal must actually be found');
    assert.ok((second.json.totals.personal || 0) >= 1, 'the literal occurrence must be counted');
  } finally {
    f.clean();
  }
});

// =============================================================== CLI: scrub-residue

test('scrub-residue + index: a rewritten file is marked clean with its new stat', () => {
  const f = mkfix();
  try {
    const file = path.join(f.work, 'dirty.txt');
    fs.writeFileSync(file, 'this transcript contains SecretTest right here');
    const old = (Date.now() - 2 * 60 * 60 * 1000) / 1000;
    fs.utimesSync(file, old, old);
    writeRules(f, baseRules(['SecretTest']));
    writeKey(f);

    // --skip-newer-than-min 0 disables the (unrelated) recency guard: a file
    // just rewritten by this same test would otherwise look "too recent" on
    // the second pass and never reach the index check at all, which would
    // test that guard instead of the one this test targets.
    const first = scrubRun(f, ['--write', '--no-backup', '--skip-newer-than-min', '0']);
    assert.strictEqual(first.code, 0, first.out + first.err);
    assert.strictEqual(num(/files rewritten\s*:\s*(\d+)/, first.out), 1, 'the dirty file must be rewritten');
    assert.ok(!fs.readFileSync(file, 'utf8').includes('SecretTest'), 'the literal must be gone after rewrite');

    // Second pass: the rewritten file was marked clean with ITS NEW stat, so
    // this pass must skip it via the index rather than re-reading it.
    const second = scrubRun(f, ['--write', '--no-backup', '--skip-newer-than-min', '0']);
    assert.strictEqual(second.code, 0, second.out + second.err);
    assert.strictEqual(num(/skipped via index\s*:\s*(\d+)/, second.out), 1, 'the rewritten file must be skipped next pass');
    assert.strictEqual(num(/files rewritten\s*:\s*(\d+)/, second.out), 0);
  } finally {
    f.clean();
  }
});

test('scrub-residue + index: a file skipped as too recent is NOT marked clean', () => {
  const f = mkfix();
  try {
    const file = path.join(f.work, 'live.jsonl');
    fs.writeFileSync(file, JSON.stringify({ msg: 'SecretTest' }));
    // Freshly modified -- falls inside the default 60-minute recency window.
    writeRules(f, baseRules(['SecretTest']));
    writeKey(f);

    const r = scrubRun(f, ['--write', '--no-backup']);
    assert.strictEqual(r.code, 0, r.out + r.err);
    assert.ok(num(/skipped as too recent\s*:\s*(\d+)/, r.out) >= 1, 'the live file must be skipped as recent');
    // Content must be untouched -- it was never examined.
    assert.ok(fs.readFileSync(file, 'utf8').includes('SecretTest'));

    // The index itself must have no opinion about this file: reload it
    // in-process and confirm nothing was recorded for it.
    const rules = JSON.parse(fs.readFileSync(f.rules, 'utf8'));
    const idx = createIndex({ indexPath: f.index, rulesFingerprint: computeRulesFingerprint(rules) });
    idx.load();
    const st = fs.statSync(file);
    assert.strictEqual(idx.isClean(file, { mtimeMs: st.mtimeMs, size: st.size }), false, 'a too-recent file must never be marked clean');
  } finally {
    f.clean();
  }
});

// ===================================================================== timing

test('perf: a second scan pass over ~200 files is not slower than the first, and skips them all', () => {
  const f = mkfix();
  try {
    const N = 200;
    for (let i = 0; i < N; i++) {
      fs.writeFileSync(path.join(f.work, `file-${i}.txt`), `file number ${i} contains nothing of interest here at all, just padding text to give the scanner something real to read through on every pass. `.repeat(20));
    }
    writeRules(f, baseRules(['NotPresentLiteral']));

    const t0 = Date.now();
    const first = scanJson(f);
    const firstMs = Date.now() - t0;
    assert.strictEqual(first.code, 0, first.out + first.err);
    assert.strictEqual(first.json.filesScanned, N);

    const t1 = Date.now();
    const second = scanJson(f);
    const secondMs = Date.now() - t1;
    assert.strictEqual(second.code, 0, second.out + second.err);
    assert.strictEqual(second.json.filesScanned, 0, 'every file must be served from the index');
    assert.strictEqual(second.json.index.skipped, N);

    console.log(`    [residue-index perf] first pass (cold, ${N} files): ${firstMs}ms; second pass (all skipped via index): ${secondMs}ms`);
    // Not a tight bound -- process spawn overhead dominates at this file
    // count -- but the index pass must not be slower than a full read.
    assert.ok(secondMs <= firstMs + 50, `second pass (${secondMs}ms) should not be slower than the first (${firstMs}ms)`);
  } finally {
    f.clean();
  }
});
