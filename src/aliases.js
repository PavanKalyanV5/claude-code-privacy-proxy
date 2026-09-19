'use strict';

// Static bidirectional identity aliases: OS username, hostname, project roots.
//
// Deliberately narrow. This is the only reverse transform in the system, and
// every entry added here is something that can be turned back into real data,
// so it covers only identifiers that MUST round-trip for tools to work.
//
// Matching is case-insensitive and separator-agnostic, because Windows paths
// arrive as both C:\Users\SOMEONE and c:/users/someone. The matched separator run is
// preserved verbatim in the output -- only the segment text changes -- so an
// escaped path in source code (C:\\Users\\SOMEONE, two literal backslashes) keeps
// its exact escaping instead of being collapsed to whatever separator style
// happens to be typed in config. Collapsing was a real bug: it silently turned
// a double backslash into a single one, corrupting source files.

const { edgeBoundary } = require('./rules');

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Treat any run of slashes or backslashes as interchangeable.
function separatorAgnostic(s) {
  return s
    .split(/[\\/]+/)
    .map(escapeRegex)
    .join('[\\\\/]+');
}

function splitSegments(value) {
  return value.split(/[\\/]+/);
}

// Build a regex source that matches `segs` joined by ANY separator run, with a
// capturing group around each separator so the run that actually matched can
// be re-emitted verbatim instead of a fixed configured separator.
function segmentedPatternSource(segs) {
  const parts = [escapeRegex(segs[0])];
  for (let i = 1; i < segs.length; i++) {
    parts.push('([\\\\/]+)');
    parts.push(escapeRegex(segs[i]));
  }
  return parts.join('');
}

// Rebuild the replacement text for a segmented match: target segment text,
// joined by the separator runs actually captured from the input (match[1..]).
function rebuildFromSegments(targetSegs, match) {
  let out = targetSegs[0];
  for (let i = 1; i < targetSegs.length; i++) {
    out += match[i] + targetSegs[i];
  }
  return out;
}

// Anchored the same way rules.js anchors literals (see edgeBoundary there):
// without this, a short value like the alias "host" matches as a bare
// substring inside "localhost", "ghost", "hostNAME", etc. Boundary is
// computed per-value from its own edges, not assumed -- a path like
// "C:\Users\x" ends in a word character but a backslash separator right
// after it (as in "...\Desktop") still satisfies `(?!\w)`, so path aliases
// keep matching mid-path.
// Guards are applied only to values that actually need them.
//
// A doubled value defeats a boundary guard: the first copy fails its
// trailing check and the second fails its leading one, so neither matches
// and the real value passes through verbatim. That was a live bypass, found
// by the self-test on the very first run against a real config.
//
// Alias values are paths and machine names, which contain separators,
// digits or dashes. Those are distinctive enough to match bare, and bare
// matching is what makes "the real value never appears outbound" true.
// Short all-word-character values keep their guards -- and aliasRisk()
// already refuses those on the alias side.
function boundedSource(value, patternSource) {
  // The self-adjacency lookaround uses the ESCAPED LITERAL value, not
  // patternSource. patternSource carries capture groups (aliases match
  // separator runs and rebuild around them), and duplicating those inside a
  // lookaround renumbers the groups, which broke 21 tests: the replacement
  // then referenced the wrong ones. A doubled path in the configured
  // separator form is matched; a doubled path that also switches separator
  // mid-way is not, which is an acceptable gap for a far simpler guard.
  // Same rule as rules.js defaultBoundary: guard only an all-word-character
  // value. Paths and dashed machine names cannot hide inside another word,
  // and guarding them broke redaction when one abutted word characters.
  //
  // The lookaround uses the ESCAPED LITERAL, not patternSource: that source
  // carries capture groups for separator-run preservation, and duplicating
  // them inside a lookaround renumbers the groups, which broke 21 tests.
  const guard = /^[\p{L}\p{N}_]+$/u.test(value);
  const { pre, post } = guard ? edgeBoundary(value) : { pre: '', post: '' };
  return pre + patternSource + post;
}

// Aliases whose ALIAS side is a common word or identifier corrupt source
// files. Inbound un-aliasing replaces the alias with the real value, so an
// alias of "host" turns every `host:` in an options object, every
// mention in prose, and every such token in code into the machine name --
// silently, on write, in files the model never re-reads.
//
// This happened. The shipped example config used exactly that alias, and it
// rewrote source comments and test fixtures across the repo before anyone
// noticed, including into git history. The word-boundary guard was working
// correctly the whole time: "localhost" and "hostname" were
// properly left alone. The problem is not the matching, it is that the alias
// VALUE was a word that legitimately appears in code on its own.
//
// So the alias side must be a token nothing would type by accident.
const RISKY_ALIASES = new Set([
  'host', 'hostname', 'server', 'machine', 'box', 'pc', 'home', 'user', 'name',
  'local', 'dev', 'test', 'prod', 'app', 'src', 'tmp', 'data', 'path', 'dir',
  'admin', 'root', 'me', 'my', 'work', 'desktop', 'laptop', 'node', 'main',
]);

// Returns a reason string when the alias is unsafe, or null when it is fine.
function aliasRisk(alias) {
  if (typeof alias !== "string" || alias.length === 0) return "empty";
  const a = alias.trim();
  if (RISKY_ALIASES.has(a.toLowerCase())) {
    return `"${a}" is a common word or identifier, so un-aliasing would rewrite it wherever it legitimately appears in code or prose`;
  }
  // A short, purely alphabetic token is almost certainly a real word.
  if (a.length < 8 && /^[A-Za-z]+$/.test(a)) {
    return `"${a}" is a short plain word (${a.length} chars); use something no one would type by accident, e.g. "MACHINE-A1"`;
  }
  return null;
}
function compileAliases(list, warn = () => {}) {
  return (list || [])
    .filter(
      (a) =>
        a &&
        typeof a.real === 'string' &&
        typeof a.alias === 'string' &&
        a.real.trim().length >= 3 &&
        a.alias.trim().length >= 1
    )
    // Longest real value first, so a nested root is aliased before its parent.
    .sort((a, b) => b.real.length - a.real.length)
    .map((a) => {
      const realSegs = splitSegments(a.real);
      const aliasSegs = splitSegments(a.alias);
      const segmented = realSegs.length === aliasSegs.length;

      if (!segmented) {
        warn(
          `alias pair real="${a.real}" alias="${a.alias}" has a different number of ` +
            'path segments; separators for this pair will be collapsed to the configured form'
        );
      }

      const realPatternSource = segmented ? segmentedPatternSource(realSegs) : separatorAgnostic(a.real);
      const aliasPatternSource = segmented ? segmentedPatternSource(aliasSegs) : separatorAgnostic(a.alias);

      return {
        real: a.real,
        alias: a.alias,
        segmented,
        realSegs,
        aliasSegs,
        // `u` flag is required by edgeBoundary's `\p{...}` lookarounds.
        toAlias: new RegExp(boundedSource(a.real, realPatternSource), 'giu'),
        toReal: new RegExp(boundedSource(a.alias, aliasPatternSource), 'giu'),
      };
    });
}

// Find every match of `dirKey` across all compiled entries against the
// ORIGINAL text, resolve overlaps (earliest start wins; on a tie the longer
// match wins), and build the output plus an ascending, non-overlapping span
// list in one pass -- same shape/guarantees as spans.js's redactWithSpans.
function applyDirection(text, compiled, dirKey) {
  const isAlias = dirKey === 'toAlias';
  const found = [];

  for (const a of compiled) {
    const re = a[dirKey];
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      found.push({ start: m.index, end: m.index + m[0].length, entry: a, match: m });
    }
  }

  if (found.length === 0) return { text, count: 0, spans: [] };

  found.sort((x, y) => x.start - y.start || y.end - x.end);

  let out = '';
  let cursor = 0;
  let count = 0;
  const spans = [];

  for (const f of found) {
    if (f.start < cursor) continue; // overlaps an already-accepted match: drop

    out += text.slice(cursor, f.start);
    const outStart = out.length;

    const targetSegs = isAlias ? f.entry.aliasSegs : f.entry.realSegs;
    const repl = f.entry.segmented
      ? rebuildFromSegments(targetSegs, f.match)
      : isAlias
        ? f.entry.alias
        : f.entry.real;

    out += repl;
    spans.push({ srcStart: f.start, srcEnd: f.end, outStart, outEnd: out.length });
    count++;
    cursor = f.end;
  }
  out += text.slice(cursor);

  return { text: out, count, spans };
}

function toAliasWithSpans(text, compiled) {
  return applyDirection(text, compiled, 'toAlias');
}

function toRealWithSpans(text, compiled) {
  return applyDirection(text, compiled, 'toReal');
}

function toAlias(text, compiled) {
  const r = toAliasWithSpans(text, compiled);
  return { text: r.text, count: r.count };
}

function toReal(text, compiled) {
  const r = toRealWithSpans(text, compiled);
  return { text: r.text, count: r.count };
}

module.exports = { compileAliases, aliasRisk, toAlias, toReal, toAliasWithSpans, toRealWithSpans };
