'use strict';

// Tests for the four PHASE 4 scripts: scan-residue, scrub-residue, verify-scrub,
// and verify-protection. These are CLI scripts with top-level code.
//
// NOTE: The redaction-proxy bugs fixed to make these tests possible:
//
// 1. `proxy/rules.js` load() didn't honor CCR_RULES_PATH env var -- added
//    support so tests can override the default ~/.claude/redaction/redact-rules.json
//
// 2. `proxy/keys.js` loadMaster() didn't honor CCR_KEY_PATH env var -- added
//    support so tests can use fixture keys instead of the user's real key

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');

// ============================================================ Test Utilities

function mkfix() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'residue-'));
  return {
    dir,
    rules: path.join(dir, 'rules.json'),
    key: path.join(dir, 'key.bin'),
    log: path.join(dir, 'proxy.log'),
    status: path.join(dir, 'status.json'),
    work: path.join(dir, 'work'),
    clean() { try { fs.rmSync(this.dir, { recursive: true }); } catch (e) { } },
  };
}

function minRules() {
  return {
    literals: ['SecretTest', 'REAL-HOST'],
    patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}', flags: 'gi' }],
    aliases: [{ real: 'REAL-HOST', alias: 'safe-host' }],
    normalize: { timezone: true, rewrites: [] },
    proxy: { port: 47113 },
  };
}

function run(script, args, env) {
  const res = spawnSync(process.execPath, [script, ...args], {
    cwd: env.cwd || os.tmpdir(),
    env: Object.assign({}, process.env, env),
    encoding: 'utf8',
    timeout: 5000,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  return {
    code: res.status,
    out: res.stdout || '',
    err: res.stderr || '',
  };
}

// ================================================================= scan-residue

test('scan-residue: never prints literal values', () => {
  const f = mkfix();
  try {
    fs.mkdirSync(f.work, { recursive: true });
    fs.writeFileSync(path.join(f.work, 't.txt'), 'Contains SecretTest value');
    fs.writeFileSync(f.rules, JSON.stringify(minRules()));

    const r = run(path.join(ROOT, 'src', 'scan-residue.js'), [f.work], {
      CCR_RULES_PATH: f.rules,
      // Isolates the default residue-index path too, which otherwise lives
      // under the real ~/.claude/redaction -- see the hard constraint in the
      // brief against touching that directory from a test.
      HOME: f.dir,
      cwd: f.work,
    });

    assert.match(r.out, /occurrences/i, 'should report counts');
    assert.ok(!r.out.includes('SecretTest'), 'must NOT leak literal values');
    assert.strictEqual(r.code, 0);
  } finally {
    f.clean();
  }
});

test('scan-residue: --json is valid JSON', () => {
  const f = mkfix();
  try {
    fs.mkdirSync(f.work, { recursive: true });
    fs.writeFileSync(path.join(f.work, 't.txt'), 'SecretTest');
    fs.writeFileSync(f.rules, JSON.stringify(minRules()));

    const r = run(path.join(ROOT, 'src', 'scan-residue.js'), ['--json', f.work], {
      CCR_RULES_PATH: f.rules,
      HOME: f.dir,
      cwd: f.work,
    });

    let json;
    assert.doesNotThrow(() => { json = JSON.parse(r.out); }, 'should output JSON');
    assert.ok(json.filesScanned !== undefined && json.totals !== undefined);
  } finally {
    f.clean();
  }
});

test('scan-residue: handles binary files without crashing', () => {
  const f = mkfix();
  try {
    fs.mkdirSync(f.work, { recursive: true });
    fs.writeFileSync(path.join(f.work, 'binary.png'), Buffer.from([0xFF, 0xD8]));
    fs.writeFileSync(path.join(f.work, 't.txt'), 'test');
    fs.writeFileSync(f.rules, JSON.stringify(minRules()));

    const r = run(path.join(ROOT, 'src', 'scan-residue.js'), [f.work], {
      CCR_RULES_PATH: f.rules,
      HOME: f.dir,
      cwd: f.work,
    });

    assert.strictEqual(r.code, 0, 'should not crash');
  } finally {
    f.clean();
  }
});

// ================================================================ scrub-residue

test('scrub-residue: dry run does not modify files', () => {
  const f = mkfix();
  try {
    // Set up proper HOME/.claude/projects structure
    const proj = path.join(f.dir, '.claude', 'projects');
    fs.mkdirSync(proj, { recursive: true });

    const file = path.join(proj, 't.txt');
    const orig = 'Contains SecretTest';
    fs.writeFileSync(file, orig);

    // Set old mtime so it's not skipped
    const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
    fs.utimesSync(file, twoHoursAgo / 1000, twoHoursAgo / 1000);
    const mtimeBefore = fs.statSync(file).mtimeMs;

    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));

    const r = run(path.join(ROOT, 'src', 'scrub-residue.js'), [], {
      HOME: f.dir,
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      cwd: f.dir,
    });

    assert.match(r.out, /DRY RUN/i);

    // File MUST be unchanged
    const content = fs.readFileSync(file, 'utf8');
    const mtimeAfter = fs.statSync(file).mtimeMs;
    assert.strictEqual(content, orig, 'content should not change');
    assert.strictEqual(mtimeAfter, mtimeBefore, 'mtime should not change');
  } finally {
    f.clean();
  }
});

test('scrub-residue: --write rewrites only files with residue', () => {
  const f = mkfix();
  try {
    const proj = path.join(f.dir, '.claude', 'projects');
    fs.mkdirSync(proj, { recursive: true });

    // File WITH residue
    const dirty = path.join(proj, 'dirty.txt');
    fs.writeFileSync(dirty, 'Has SecretTest in it');

    // File WITHOUT residue
    const clean = path.join(proj, 'clean.txt');
    fs.writeFileSync(clean, 'No keywords here');

    // Set old mtimes
    const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
    fs.utimesSync(dirty, twoHoursAgo / 1000, twoHoursAgo / 1000);
    fs.utimesSync(clean, twoHoursAgo / 1000, twoHoursAgo / 1000);

    const cleanBefore = fs.readFileSync(clean, 'utf8');
    const cleanMtime = fs.statSync(clean).mtimeMs;

    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));

    const r = run(path.join(ROOT, 'src', 'scrub-residue.js'), ['--write'], {
      HOME: f.dir,
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      cwd: f.dir,
    });

    assert.strictEqual(r.code, 0);

    // clean.txt MUST NOT be rewritten
    assert.strictEqual(fs.readFileSync(clean, 'utf8'), cleanBefore);
    assert.strictEqual(fs.statSync(clean).mtimeMs, cleanMtime, 'clean file should not be touched');
  } finally {
    f.clean();
  }
});

test('scrub-residue: .jsonl per-line with count preserved', () => {
  const f = mkfix();
  try {
    const hist = path.join(f.dir, '.claude', 'history.jsonl');
    fs.mkdirSync(path.dirname(hist), { recursive: true });

    const lines = [
      JSON.stringify({ msg: 'SecretTest' }),
      JSON.stringify({ msg: 'clean' }),
      JSON.stringify({ msg: 'SecretTest again' }),
    ];
    fs.writeFileSync(hist, lines.join('\n'));

    // Set old mtime
    const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
    fs.utimesSync(hist, twoHoursAgo / 1000, twoHoursAgo / 1000);

    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));

    const r = run(path.join(ROOT, 'src', 'scrub-residue.js'), ['--write'], {
      HOME: f.dir,
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      cwd: f.dir,
    });

    assert.strictEqual(r.code, 0);

    // Line count must be preserved
    const after = fs.readFileSync(hist, 'utf8').split('\n').filter(l => l.trim());
    assert.strictEqual(after.length, lines.length, 'line count must be preserved');

    // Every line must parse
    for (const line of after) {
      assert.doesNotThrow(() => JSON.parse(line), `should parse: ${line.slice(0,40)}`);
    }
  } finally {
    f.clean();
  }
});

test('scrub-residue: .json compact stays compact', () => {
  const f = mkfix();
  try {
    const cfg = path.join(f.dir, '.claude', 'cfg.json');
    fs.mkdirSync(path.dirname(cfg), { recursive: true });

    // One-line JSON
    const obj = { secret: 'SecretTest', count: 42 };
    fs.writeFileSync(cfg, JSON.stringify(obj));

    // Set old mtime
    const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
    fs.utimesSync(cfg, twoHoursAgo / 1000, twoHoursAgo / 1000);

    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));

    const r = run(path.join(ROOT, 'src', 'scrub-residue.js'), ['--write'], {
      HOME: f.dir,
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      cwd: f.dir,
    });

    assert.strictEqual(r.code, 0);

    // Compact should stay compact (1 line, no newlines)
    const after = fs.readFileSync(cfg, 'utf8');
    assert.ok(after.split('\n').length === 1, 'compact JSON should stay one line');
    assert.doesNotThrow(() => JSON.parse(after));
  } finally {
    f.clean();
  }
});

test('scrub-residue: unparseable JSONL line untouched', () => {
  const f = mkfix();
  try {
    const hist = path.join(f.dir, '.claude', 'history.jsonl');
    fs.mkdirSync(path.dirname(hist), { recursive: true });

    const badLine = 'not json {]';
    const goodLine = JSON.stringify({ text: 'SecretTest' });
    fs.writeFileSync(hist, goodLine + '\n' + badLine);

    // Set old mtime
    const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
    fs.utimesSync(hist, twoHoursAgo / 1000, twoHoursAgo / 1000);

    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));

    const r = run(path.join(ROOT, 'src', 'scrub-residue.js'), ['--write'], {
      HOME: f.dir,
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      cwd: f.dir,
    });

    const after = fs.readFileSync(hist, 'utf8');
    assert.ok(after.includes(badLine), 'unparseable line should be byte-identical');
  } finally {
    f.clean();
  }
});

test('scrub-residue: --no-backup skips backup', () => {
  const f = mkfix();
  try {
    const proj = path.join(f.dir, '.claude', 'projects');
    fs.mkdirSync(proj, { recursive: true });

    const file = path.join(proj, 't.txt');
    fs.writeFileSync(file, 'SecretTest');

    // Set old mtime
    const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
    fs.utimesSync(file, twoHoursAgo / 1000, twoHoursAgo / 1000);

    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));

    const r = run(path.join(ROOT, 'src', 'scrub-residue.js'), ['--write', '--no-backup'], {
      HOME: f.dir,
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      cwd: f.dir,
    });

    assert.match(r.out, /no-backup/i, 'should report --no-backup');
  } finally {
    f.clean();
  }
});

// ================================================================ verify-scrub

test('verify-scrub: missing file detected', () => {
  const f = mkfix();
  try {
    const backup = path.join(f.dir, 'backup');
    const live = path.join(f.dir, 'live');
    fs.mkdirSync(backup, { recursive: true });
    fs.mkdirSync(live, { recursive: true });

    // Backup has file, live doesn't
    fs.writeFileSync(path.join(backup, 't.txt'), 'content');

    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));

    const r = run(path.join(ROOT, 'src', 'verify-scrub.js'), [backup], {
      HOME: live,  // redirect HOME to empty "live" dir
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      cwd: f.dir,
    });

    assert.match(r.out, /MISSING from disk/i, 'should detect missing file');
  } finally {
    f.clean();
  }
});

test('verify-scrub: file that shrunk detected', () => {
  const f = mkfix();
  try {
    const backup = path.join(f.dir, 'backup');
    const live = path.join(f.dir, 'live');
    fs.mkdirSync(backup, { recursive: true });
    fs.mkdirSync(live, { recursive: true });

    // Backup has 3 lines, live has 2
    const line1 = JSON.stringify({ n: 1 });
    const line2 = JSON.stringify({ n: 2 });
    const line3 = JSON.stringify({ n: 3 });

    fs.writeFileSync(path.join(backup, 't.jsonl'), line1 + '\n' + line2 + '\n' + line3);
    fs.writeFileSync(path.join(live, 't.jsonl'), line1 + '\n' + line2);

    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));

    const r = run(path.join(ROOT, 'src', 'verify-scrub.js'), [backup], {
      HOME: live,
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      cwd: f.dir,
    });

    assert.match(r.out, /LINE COUNT shrank/i, 'should detect file shrinkage');
  } finally {
    f.clean();
  }
});

test('verify-scrub: file that grew treated as append', () => {
  const f = mkfix();
  try {
    const backup = path.join(f.dir, 'backup');
    const live = path.join(f.dir, 'live');
    fs.mkdirSync(backup, { recursive: true });
    fs.mkdirSync(live, { recursive: true });

    // Live has more lines (append scenario)
    const line1 = JSON.stringify({ n: 1 });
    const line2 = JSON.stringify({ n: 2 });
    const line3 = JSON.stringify({ n: 3 });

    fs.writeFileSync(path.join(backup, 't.jsonl'), line1 + '\n' + line2);
    fs.writeFileSync(path.join(live, 't.jsonl'), line1 + '\n' + line2 + '\n' + line3);

    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));

    const r = run(path.join(ROOT, 'src', 'verify-scrub.js'), [backup], {
      HOME: live,
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      cwd: f.dir,
    });

    assert.ok(!r.out.includes('LINE COUNT shrank'), 'append should not be flagged as problem');
  } finally {
    f.clean();
  }
});

// ================================================================ verify-protection

test('verify-protection: config checks work', () => {
  const f = mkfix();
  try {
    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));
    fs.writeFileSync(f.status, JSON.stringify({
      ok: true,
      since: Date.now(),
      reason: 'live',
      checks: { egress: true, literals: true, normalizers: true },
    }));

    const r = run(path.join(ROOT, 'src', 'verify-protection.js'), [], {
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      CCR_STATUS_PATH: f.status,
      cwd: f.dir,
    });

    // Should check the rules without crashing
    assert.match(r.out, /YOUR REDACTION RULES|EVERY LITERAL/i, 'should check rules');
  } finally {
    f.clean();
  }
});

test('verify-protection: never prints literal values', () => {
  const f = mkfix();
  try {
    fs.writeFileSync(f.rules, JSON.stringify(minRules()));
    fs.writeFileSync(f.key, Buffer.alloc(32, 7));
    fs.writeFileSync(f.status, JSON.stringify({
      ok: true,
      since: Date.now(),
      reason: 'live',
      checks: { egress: true, literals: true, normalizers: true },
    }));

    const r = run(path.join(ROOT, 'src', 'verify-protection.js'), [], {
      CCR_RULES_PATH: f.rules,
      CCR_KEY_PATH: f.key,
      CCR_LOG_PATH: f.log,
      CCR_STATUS_PATH: f.status,
      cwd: f.dir,
    });

    assert.ok(!r.out.includes('SecretTest'), 'must NOT print literal values');
    assert.ok(!r.out.includes('REAL-HOST'), 'must NOT print hostname');
  } finally {
    f.clean();
  }
});
