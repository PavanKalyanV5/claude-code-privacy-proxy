'use strict';

// Loads and compiles redact-rules.json.
//
// Two behaviors matter and are easy to get wrong:
//
//   * Each literal compiles to its OWN regex entry, never merged with other
//     literals (or patterns) into a shared alternation. A single regex's
//     exec() loop advances lastIndex past whatever it just matched, so it can
//     never report two overlapping matches against itself -- if two literals
//     crossed (one's tail overlapping another's head), the second would
//     simply never be found, leaking cleartext. Compiling one regex per
//     literal means every candidate reaches spans.js as an independent match,
//     whose sort-by-start/length-desc + crossing-clip logic then resolves
//     precedence and overlap correctly -- including a broad category pattern
//     beating a short literal that starts at the same offset. Patterns stay
//     combined per flag-bucket (they are the expensive ones to run, and few);
//     literals are typically under 20, so the extra exec() passes are cheap.
//   * Literals are word-boundary matched. A bare-substring literal "Jane"
//     would rewrite "JaneAdapter" throughout a codebase. Literals whose edges
//     are not word characters get no boundary on that side, so "+1-555-..."
//     still matches.

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

// Redaction state lives outside the repo so it can never be committed and no task
// working in the repo can stumble on it.
const RULES_PATH = path.join(os.homedir(), '.claude', 'redaction', 'redact-rules.json');
const PROBE_TIMEOUT_MS = 500;

// The values shipped in the template. Matching these would redact the literal
// word "Your" out of every file, so they are ignored until replaced.
const PLACEHOLDERS = new Set([
  'your full name',
  'your.email@example.com',
  '+1-555-000-0000',
  'your street address',
]);

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Unicode-aware "word" class used for boundary anchoring. Plain `\w` is
// ASCII-only ([A-Za-z0-9_]), so a literal ending in e.g. an accented letter
// got no trailing anchor and matched inside a longer word (the exact
// over-matching bug boundaries exist to prevent -- see CRITICAL 4). These
// property escapes require the regex they end up in to carry the `u` flag;
// see compile() below and aliases.js, which both add it where needed.
const WORD_CLASS = '[\\p{L}\\p{N}_]';
const WORD_START_RE = /^[\p{L}\p{N}_]/u;
const WORD_END_RE = /[\p{L}\p{N}_]$/u;

// Shared with aliases.js (compileAliases), so both the redaction-literal
// boundary and the alias boundary use the identical rule instead of two
// copies that could drift apart.
// A boundary is satisfied by a non-word character OR by another occurrence
// of the value itself.
//
// The second clause is the fix for a real bypass: with only the first,
// "<value><value>" matched nothing at all, because the leading copy failed
// its trailing check and the trailing copy failed its leading one, so a
// literal repeated with no separator went out verbatim. Widening the guard
// keeps the false-positive protection it was added for ("MYBOX" must not
// match inside "MYBOXES") while making repetition matchable.
//
// `self` defaults to the escaped value; callers with a pattern of their own
// (aliases match separators flexibly) pass that instead, so a doubled path
// is recognised whichever separator form it uses.
function edgeBoundary(value, self) {
  const me = self || escapeRegex(value);
  return {
    pre: WORD_START_RE.test(value) ? `(?:(?<!${WORD_CLASS})|(?<=${me}))` : '',
    post: WORD_END_RE.test(value) ? `(?:(?!${WORD_CLASS})|(?=${me}))` : '',
  };
}

// Guard only a value made ENTIRELY of word characters. Those are the only
// ones that can hide inside a longer word, which is the single thing the
// guards were added for ("MYBOX" must not match inside "MYBOXES").
//
// A value containing a space, a dot, a dash or a path separator cannot hide
// that way, and guarding it actively breaks redaction: a full name wrapped
// in word characters ("xxxJane Q. Testersonyyy") failed both guards and went
// out verbatim. No length threshold works here -- a 5-character hostname
// needs guarding and a 17-character name must not have it -- so the
// discriminator is shape, not size.
function defaultBoundary(value) {
  return /^[\p{L}\p{N}_]+$/u.test(value);
}
function boundedLiteral(literal) {
  const { pre, post } = edgeBoundary(literal);
  return pre + escapeRegex(literal) + post;
}

// A catastrophic regex never returns, so it cannot be timed in-process -- the
// proxy would hang at startup. Run it in a child with a hard timeout instead.
// One-off cost at load: ~50ms per pattern.
function isPatternSafe(source, flags) {
  try {
    new RegExp(source, flags);
  } catch (e) {
    return { ok: false, why: `invalid regex: ${e.message}` };
  }

  // Probe LENGTH matters more than probe variety. These were 60 characters,
  // which is far too short: quadratic backtracking on 60 characters costs
  // microseconds and sails through the 500ms budget. The shipped email
  // pattern passed this screen and then hung the proxy for 42 seconds on a
  // 100KB message. 20k characters makes O(n^2) unmistakable while staying
  // instant for a linear pattern.
  //
  // The runs are the shapes that actually cause trouble: a long stretch of
  // word characters that never satisfies the delimiter the pattern waits
  // for (letters with no @, digits with no separator, hex with no colon).
  // Source and flags travel in the ENVIRONMENT, not argv. Passed as
  // arguments, any pattern beginning with "-" is parsed by node as an option:
  // a legitimate `-----BEGIN PRIVATE KEY-----` pattern made the child exit
  // non-zero, and this function reported it as catastrophic backtracking.
  // A screen that rejects valid patterns with a misleading reason is worse
  // than one that is merely strict -- it sends the user to rewrite a regex
  // that was never the problem.
  const probe = [
    'const re = new RegExp(process.env.CCR_PROBE_SRC, process.env.CCR_PROBE_FLAGS);',
    'const probes = [',
    "  'a'.repeat(20000) + '!',",
    "  '1'.repeat(20000) + 'x',",
    "  'ab'.repeat(10000) + '!',",
    "  'a1'.repeat(10000) + '@',",
    "  'abcdef0123'.repeat(2000) + '!',",
    "  'a.b_c-d+e%'.repeat(2000) + '!',",
    "  '('.repeat(2000), ' '.repeat(20000),",
    '];',
    'for (const p of probes) { re.lastIndex = 0; re.test(p); }',
  ].join('\n');

  try {
    execFileSync(process.execPath, ['-e', probe], {
      timeout: PROBE_TIMEOUT_MS,
      stdio: 'ignore',
      env: Object.assign({}, process.env, { CCR_PROBE_SRC: source, CCR_PROBE_FLAGS: flags }),
      // One child PER PATTERN, and load() runs in the proxy, the lifecycle
      // hook, both residue tools and every CLI. Without windowsHide that is a
      // console window per pattern per process -- the flashing windows the
      // user reported. stdio:'ignore' silences the output but does not stop
      // Windows from creating the console itself.
      windowsHide: true,
    });
    return { ok: true };
  } catch (e) {
    if (e.killed || e.code === 'ETIMEDOUT' || e.signal) {
      return {
        ok: false,
        why: `pattern exceeded ${PROBE_TIMEOUT_MS}ms on adversarial input: catastrophic backtracking`,
      };
    }
    return { ok: false, why: e.message };
  }
}

function compile(rules, warn = () => {}) {
  const patternBuckets = new Map();
  let n = 0;
  // Counted as patterns are accepted, so it reflects what actually LOADED --
  // a pattern rejected by the safety screen must not be counted as active.
  let patternCount = 0;

  // Category patterns sharing the same case-sensitivity are combined into one
  // alternation per flag-bucket, same as before. Literals are NOT added here
  // -- see the header note above for why they each get their own entry.
  const addPattern = (insensitive, source, label) => {
    const flags = insensitive ? 'gi' : 'g';
    let b = patternBuckets.get(flags);
    if (!b) {
      b = { parts: [], labels: {}, flags };
      patternBuckets.set(flags, b);
    }
    const name = `r${n++}`;
    b.parts.push(`(?<${name}>${source})`);
    b.labels[name] = label;
  };

  for (const p of rules.patterns || []) {
    if (!p || typeof p.regex !== 'string') continue;
    const verdict = isPatternSafe(p.regex, p.flags || 'g');
    if (!verdict.ok) {
      warn(`pattern "${p.name || '?'}" disabled: ${verdict.why}`);
      continue;
    }
    addPattern(/i/.test(p.flags || ''), p.regex, p.name || 'pattern');
    patternCount++;
  }

  const literals = [];
  for (const entry of rules.literals || []) {
    const value = typeof entry === 'string' ? entry : entry && entry.value;
    if (typeof value !== 'string') continue;
    const v = value.trim();
    if (v.length < 3 || PLACEHOLDERS.has(v.toLowerCase())) continue;
    // An explicit boolean in the config wins; otherwise decide by shape.
    const explicit = typeof entry === 'object' && entry !== null && typeof entry.boundary === 'boolean'
      ? entry.boundary
      : null;
    const boundary = explicit === null ? defaultBoundary(v) : explicit;
    literals.push({ v, boundary });
  }
  // Longest first is no longer load-bearing for precedence (spans.js's sort
  // now owns that), but it's kept anyway since it's a harmless, sensible
  // default order for the regexes array.
  literals.sort((a, b) => b.v.length - a.v.length);

  const regexes = [];
  for (const [, b] of patternBuckets) {
    try {
      regexes.push({ re: new RegExp(b.parts.join('|'), b.flags), labels: b.labels });
    } catch (e) {
      warn(`combined regex for flags "${b.flags}" failed to compile: ${e.message}`);
    }
  }

  // One independent regex per literal -- see the header note on why these
  // must not be merged. Always case-insensitive with the 'u' flag: literal
  // sources are always plain escapes plus (optionally) the Unicode boundary
  // lookarounds, both valid under 'u'.
  for (const l of literals) {
    const source = l.boundary ? boundedLiteral(l.v) : escapeRegex(l.v);
    const name = `r${n++}`;
    try {
      regexes.push({ re: new RegExp(`(?<${name}>${source})`, 'giu'), labels: { [name]: 'personal' } });
    } catch (e) {
      warn(`literal regex failed to compile: ${e.message}`);
    }
  }

  // patternCount is the number of PATTERNS THAT LOADED, reported separately
  // because it cannot be derived from `regexes`. Patterns are bucketed by
  // flags and combined, so 27 patterns become a couple of alternation
  // regexes -- and every caller was computing
  // `regexes.length - literalCount`, which after adopting 20 new patterns
  // printed "patterns=2".
  //
  // A count that shrinks when you add rules is worse than no count: it says
  // the adoption failed when in fact every one of them was live and firing.
  return { regexes, literalCount: literals.length, patternCount };
}

function load(rulesPath = process.env.CCR_RULES_PATH || RULES_PATH) {
  return JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
}

module.exports = { load, compile, isPatternSafe, boundedLiteral, edgeBoundary, defaultBoundary, RULES_PATH };
