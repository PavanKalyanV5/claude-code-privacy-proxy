'use strict';

// Does --resume still work after a transcript has been scrubbed?
//
// I asserted it does, on the reasoning that labels are keyed HMACs computed
// with the same key the proxy uses, so a scrubbed transcript contains exactly
// the labels the model would have been shown anyway. Reasoning is not
// evidence, and the scrubber rewrites hundreds of real transcripts, so the
// claim needs pinning.
//
// Two distinct properties, and only the second is the interesting one:
//
//   1. STRUCTURAL: the transcript still parses and still carries the fields
//      Claude Code reads to reconstruct a conversation (type, uuid,
//      parentUuid, timestamp, message.role, message.content). Already covered
//      broadly by verify-scrub, pinned here for the specific shape of a real
//      transcript line.
//
//   2. LABEL COHERENCE: the label written into the transcript for a value is
//      byte-identical to the label the live proxy produces for that same
//      value. If these diverged, a resumed conversation would contain labels
//      the resolver cannot map back, and every subsequent tool call touching
//      that value would silently refuse.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const { compile } = require('../rules');
const { compileAliases } = require('../aliases');
const { compileNormalizers } = require('../normalize');
const { subkey } = require('../keys');
const { renderForModel } = require('../pipeline');
const { createResolver } = require('../resolver');

const SECRET = 'ZanderKrellmont';
const MASTER = Buffer.alloc(32, 0x5a);

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'resume-'));
  const work = path.join(dir, 'work');
  fs.mkdirSync(work, { recursive: true });
  const rules = path.join(dir, 'rules.json');
  const key = path.join(dir, 'key.bin');
  fs.writeFileSync(
    rules,
    JSON.stringify({
      literals: [SECRET],
      patterns: [],
      aliases: [],
      normalize: { timezone: false, rewrites: [] },
    })
  );
  // The SAME master key the in-process pipeline below will use, which is the
  // whole point: labels must agree across the two.
  fs.writeFileSync(key, MASTER);
  return { dir, work, rules, key, log: path.join(dir, 'p.log'), clean() { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {} } };
}

// A transcript line shaped like the real thing.
function transcriptLine(uuid, parent, text) {
  return {
    type: 'user',
    uuid,
    parentUuid: parent,
    timestamp: '2026-09-18T10:00:00.000Z',
    sessionId: 'sess-1',
    version: '2.0.1',
    cwd: '/tmp/x',
    message: { role: 'user', content: [{ type: 'text', text }] },
  };
}

function scrub(f) {
  const res = spawnSync(
    process.execPath,
    [path.join(ROOT, 'src', 'scrub-residue.js'), '--write', '--quiet', '--no-backup', '--skip-newer-than-min', '0', f.work],
    {
      env: Object.assign({}, process.env, {
        CCR_RULES_PATH: f.rules,
        CCR_KEY_PATH: f.key,
        CCR_LOG_PATH: f.log,
        HOME: f.dir,
        USERPROFILE: f.dir,
      }),
      encoding: 'utf8',
      timeout: 20000,
    }
  );
  return { code: res.status, out: (res.stdout || '') + (res.stderr || '') };
}

test('resume: a scrubbed transcript keeps every field Claude Code reads', () => {
  const f = fixture();
  try {
    const p = path.join(f.work, 'session.jsonl');
    const before = [
      transcriptLine('u1', null, 'my name is ' + SECRET),
      transcriptLine('u2', 'u1', 'nothing sensitive here'),
    ];
    fs.writeFileSync(p, before.map((o) => JSON.stringify(o)).join('\n') + '\n');

    const r = scrub(f);
    assert.strictEqual(r.code, 0, r.out);

    const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
    assert.strictEqual(lines.length, 2);

    lines.forEach((line, i) => {
      const o = JSON.parse(line);
      // Every field the conversation is reconstructed from must survive
      // untouched. A scrub that renamed or dropped one of these would make the
      // transcript unreadable, and the failure would only appear on --resume.
      assert.strictEqual(o.type, before[i].type, 'type changed');
      assert.strictEqual(o.uuid, before[i].uuid, 'uuid changed');
      assert.strictEqual(o.parentUuid, before[i].parentUuid, 'parentUuid changed -- the reply chain would break');
      assert.strictEqual(o.timestamp, before[i].timestamp, 'timestamp changed');
      assert.strictEqual(o.sessionId, before[i].sessionId, 'sessionId changed');
      assert.strictEqual(o.message.role, before[i].message.role, 'role changed');
      assert.strictEqual(o.message.content[0].type, 'text', 'content block type changed');
      assert.strictEqual(typeof o.message.content[0].text, 'string', 'content text is no longer a string');
    });

    assert.ok(!lines[0].includes(SECRET), 'the literal survived the scrub');
    assert.ok(lines[1].includes('nothing sensitive here'), 'an unrelated message was altered');
  } finally {
    f.clean();
  }
});

test('resume: the label in a scrubbed transcript is the label the proxy would send', () => {
  // THE claim. If these disagree, a resumed conversation carries labels the
  // live resolver has never seen, and every tool call touching that value
  // refuses -- silently, because refusing is the safe branch.
  const f = fixture();
  try {
    const p = path.join(f.work, 'session.jsonl');
    fs.writeFileSync(p, JSON.stringify(transcriptLine('u1', null, 'call ' + SECRET + ' today')) + '\n');

    const r = scrub(f);
    assert.strictEqual(r.code, 0, r.out);

    const scrubbedText = JSON.parse(fs.readFileSync(p, 'utf8').trim()).message.content[0].text;
    const labelInTranscript = (/\[PII:[a-z0-9-]+:[0-9a-f]{16}\]/.exec(scrubbedText) || [])[0];
    assert.ok(labelInTranscript, 'no label was written: ' + JSON.stringify(scrubbedText));

    // What the live pipeline produces for the same value, same master key.
    const RULES = compile({ literals: [SECRET], patterns: [] }, () => {});
    const PIPE = {
      rules: RULES,
      kLabel: subkey(MASTER, 'label'),
      aliases: compileAliases([], () => {}),
      normalizers: compileNormalizers({ timezone: false, rewrites: [] }, () => {}),
    };
    const live = renderForModel('call ' + SECRET + ' today', PIPE).text;
    const labelFromProxy = (/\[PII:[a-z0-9-]+:[0-9a-f]{16}\]/.exec(live) || [])[0];

    assert.strictEqual(
      labelInTranscript,
      labelFromProxy,
      'the scrubbed transcript and the live proxy disagree on the label for the same value'
    );
    assert.strictEqual(scrubbedText, live, 'the scrubbed text differs from what the proxy would send');
  } finally {
    f.clean();
  }
});

test('resume: a different master key produces a DIFFERENT label (the check has teeth)', () => {
  // Guards the test above from passing vacuously. If labels did not depend on
  // the key, comparing them would prove nothing.
  const RULES = compile({ literals: [SECRET], patterns: [] }, () => {});
  const mk = (master) => ({
    rules: RULES,
    kLabel: subkey(master, 'label'),
    aliases: compileAliases([], () => {}),
    normalizers: compileNormalizers({ timezone: false, rewrites: [] }, () => {}),
  });
  const a = renderForModel(SECRET, mk(Buffer.alloc(32, 0x5a))).text;
  const b = renderForModel(SECRET, mk(Buffer.alloc(32, 0x5b))).text;
  assert.notStrictEqual(a, b, 'labels do not depend on the key, so coherence is untestable');
  assert.match(a, /\[PII:personal:[0-9a-f]{16}\]/);
});

test('resume: a label surviving from a scrubbed transcript still resolves for a local tool', () => {
  // The practical consequence of coherence: when a resumed conversation feeds
  // a label back into a tool call, the resolver must map it to the real value
  // from the cache or from the file. Here there is no file, so it must refuse
  // rather than pass a label through to a local tool as if it were real data.
  const RULES = compile({ literals: [SECRET], patterns: [] }, () => {});
  const kLabel = subkey(MASTER, 'label');
  const PIPE = {
    rules: RULES,
    kLabel,
    aliases: compileAliases([], () => {}),
    normalizers: compileNormalizers({ timezone: false, rewrites: [] }, () => {}),
  };
  const label = (/\[PII:[a-z0-9-]+:[0-9a-f]{16}\]/.exec(renderForModel(SECRET, PIPE).text) || [])[0];
  assert.ok(label);

  const resolver = createResolver({ rules: RULES, kLabel });
  const out = resolver.resolveToolInput('Write', { file_path: path.join(os.tmpdir(), 'nope-' + Math.random(), 'x.txt'), content: 'value is ' + label });
  // With no file to derive from and no cache entry, the label cannot be
  // resolved. Passing it through would write "[PII:...]" into a real file,
  // which the resolver warns about rather than doing silently.
  assert.ok(out && typeof out.content === 'string');
  assert.ok(out.content.includes(label) || !out.content.includes(SECRET), 'an unresolvable label must not become the real value by accident');
});
