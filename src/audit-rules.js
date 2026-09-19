#!/usr/bin/env node
'use strict';

// Audits your REAL redact-rules.json: does every literal actually get
// redacted, is any of them likely to over-match, and would a proposed pattern
// misfire on your own machine?
//
// WHY THE OUTPUT IS SHAPED THIS WAY. The console output is values-free --
// indexes, categories, lengths and verdicts, never the value itself. That is
// what makes it safe to paste into an issue, read out in a review, or hand to
// an assistant that must not see your personal data. The optional --detail
// file is the opposite and carries real values, for your eyes only.
//
// This matters more than it sounds. "Are my rules working?" is the one
// question you cannot answer by inspection, because the failure modes are
// adjacency-shaped: a literal that works bare and fails inside a JSON string
// looks identical in the config file.
//
//   node src/audit-rules.js                 values-free verdict
//   node src/audit-rules.js --detail f.txt  plus a local file naming names
//   node src/audit-rules.js --patterns config/patterns.example.json --corpus .
//                                           measure a pattern set against
//                                           real local content first

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { load, compile, isPatternSafe } = require('./rules');
const { redactWithSpans } = require('./spans');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const DETAIL = arg('--detail', null);
const PATTERNS_FILE = arg('--patterns', null);
const CORPUS = arg('--corpus', null);

const rules = load();
const K = crypto.randomBytes(32); // ephemeral: this is a test, not a session
const compiled = compile(rules, () => {});

const literals = (rules.literals || []).map((l) => (typeof l === 'string' ? { value: l, category: 'personal' } : l));

// The adjacency shapes that have actually caused leaks in this project.
function shapes(v) {
  return [
    [v, 'bare'],
    ['Hello ' + v + ', hi', 'in prose'],
    ['(' + v + ')', 'parenthesised'],
    ['"' + v + '"', 'quoted'],
    ['{"k":"' + v + '"}', 'inside JSON'],
    [v + ',', 'trailing comma'],
    ['<' + v + '>', 'angle brackets'],
    [v + v, 'doubled'],
    ['[' + v + ']', 'square brackets'],
    [v.toUpperCase(), 'uppercased'],
    [v.toLowerCase(), 'lowercased'],
    ['  ' + v + '  ', 'padded'],
    ['/' + v + '/path', 'in a path'],
    ['=' + v + ';', 'as a value'],
  ];
}

const detail = [];
let leakTotal = 0;
const rows = [];

literals.forEach((lit, idx) => {
  const v = String(lit.value || '');
  if (!v) return;
  let leaks = 0;
  const failed = [];
  for (const [text, shape] of shapes(v)) {
    const out = redactWithSpans(text, compiled, K).text;
    if (out.toLowerCase().includes(v.toLowerCase())) {
      leaks++;
      failed.push(shape);
    }
  }
  leakTotal += leaks;

  // Over-matching risk, judged on shape rather than on the value's meaning.
  const notes = [];
  if (v.length <= 3) notes.push('very short: will match inside unrelated words');
  else if (v.length <= 5) notes.push('short: check it is not a common word');
  if (/^[0-9]+$/.test(v) && v.length <= 9) notes.push('bare digits: may match IDs and timestamps');
  if (/^[a-z]+$/i.test(v) && v.length <= 6) notes.push('single common-looking word');

  rows.push({
    idx,
    category: lit.category || 'personal',
    length: v.length,
    boundary: lit.boundary === false ? 'off' : 'on',
    leaks,
    failed,
    notes,
  });

  if (leaks || notes.length) {
    detail.push(
      '#' + idx + '  ' + JSON.stringify(v) +
      (leaks ? '\n   LEAKS in: ' + failed.join(', ') : '') +
      (notes.length ? '\n   note: ' + notes.join('; ') : '')
    );
  }
});

console.log('LITERAL COVERAGE');
console.log('  literals audited : ' + rows.length);
console.log('  shapes per literal: ' + shapes('x').length);
console.log('  total leaks      : ' + leakTotal);
const leaky = rows.filter((r) => r.leaks > 0);
if (leaky.length) {
  console.log('  LEAKING LITERALS (by index, value withheld):');
  for (const r of leaky) console.log('    #' + r.idx + '  ' + r.category + '  len=' + r.length + '  fails: ' + r.failed.join(', '));
} else {
  console.log('  every literal is redacted in every shape tested');
}

const risky = rows.filter((r) => r.notes.length);
if (risky.length) {
  console.log('');
  console.log('  OVER-MATCH RISK (by index, value withheld):');
  for (const r of risky) console.log('    #' + r.idx + '  len=' + r.length + '  boundary=' + r.boundary + '  ' + r.notes.join('; '));
}

// ------------------------------------------------------------- patterns

console.log('');
console.log('PATTERNS IN YOUR RULES');
let unsafe = 0;
for (const p of rules.patterns || []) {
  if (!p || typeof p.regex !== 'string') continue;
  const v = isPatternSafe(p.regex, p.flags || 'g');
  if (!v.ok) {
    unsafe++;
    console.log('  DISABLED AT LOAD: "' + (p.name || '?') + '" — ' + v.why);
  }
}
console.log('  configured : ' + (rules.patterns || []).length);
console.log('  unsafe     : ' + unsafe + (unsafe ? '  <-- these never load, so they protect nothing' : ''));

// ------------------------------------------- proposed pattern dry-run

// Measures a candidate pattern set against REAL local content before you
// adopt it. A pattern with a high hit rate on your own machine is not
// necessarily wrong, but it is certainly worth looking at: over-redaction
// destroys the code the model needs to reason about.
if (PATTERNS_FILE && CORPUS) {
  const SKIP = new Set(['.git', 'node_modules', '.playwright-mcp']);
  const SKIP_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf', '.zip', '.gz', '.exe', '.dll', '.node', '.ico']);
  const files = [];
  (function walk(p) {
    let st;
    try {
      st = fs.statSync(p);
    } catch (e) {
      return;
    }
    if (st.isFile()) {
      if (!SKIP_EXT.has(path.extname(p).toLowerCase()) && st.size < 4 * 1024 * 1024) files.push(p);
      return;
    }
    if (!st.isDirectory() || SKIP.has(path.basename(p))) return;
    for (const n of fs.readdirSync(p)) {
      if (!SKIP.has(n)) walk(path.join(p, n));
    }
  })(CORPUS);

  const { patterns } = JSON.parse(fs.readFileSync(PATTERNS_FILE, 'utf8'));
  console.log('');
  console.log('PROPOSED PATTERNS vs ' + files.length + ' local files');
  const hits = patterns.map((p) => ({ name: p.name, category: p.category, n: 0, files: new Set() }));

  for (const f of files) {
    let text;
    try {
      text = fs.readFileSync(f, 'utf8');
    } catch (e) {
      continue;
    }
    patterns.forEach((p, i) => {
      let re;
      try {
        re = new RegExp(p.regex, p.flags || 'g');
      } catch (e) {
        return;
      }
      const m = text.match(re);
      if (m && m.length) {
        hits[i].n += m.length;
        hits[i].files.add(f);
      }
    });
  }

  for (const h of hits.sort((a, b) => b.n - a.n)) {
    const verdict = h.n === 0 ? 'no hits here (safe to add)' : h.n + ' hit(s) in ' + h.files.size + ' file(s) — REVIEW before adopting';
    console.log('  ' + h.name.padEnd(30) + ' ' + verdict);
  }
  console.log('');
  console.log('  A pattern with hits is not necessarily wrong -- it may be finding real');
  console.log('  secrets. Use `node src/pii-report.js` to see WHICH values, locally.');
}

if (DETAIL) {
  fs.writeFileSync(
    path.resolve(DETAIL),
    ['LITERAL AUDIT DETAIL', 'generated ' + new Date().toISOString(), '',
     '*** CONTAINS YOUR REAL VALUES. Review, act, delete. ***', '',
     detail.length ? detail.join('\n\n') : 'No leaks and no over-match risks found.', ''].join('\n')
  );
  console.log('');
  console.log('detail written to ' + path.resolve(DETAIL) + ' (contains real values -- delete when done)');
}

process.exitCode = leakTotal > 0 || unsafe > 0 ? 1 : 0;
