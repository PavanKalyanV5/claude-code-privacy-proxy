'use strict';

// Redaction that also reports WHERE it redacted.
//
// Matches from every compiled regex are gathered against the ORIGINAL text and
// overlaps resolved, rather than applying regexes one after another to each
// other's output. Two reasons: no double-redaction, and the span offsets stay
// meaningful relative to the real text -- which is what Phase 2's derived
// resolution needs in order to translate an edit back onto the real file.

const crypto = require('crypto');

function makeLabel(kLabel, category, value) {
  const mac = crypto
    .createHmac('sha256', kLabel)
    .update(value, 'utf8')
    .digest('hex')
    .slice(0, 16);
  return `[PII:${category}:${mac}]`;
}

function labelOf(match, labels) {
  const groups = match.groups;
  if (groups) {
    for (const name of Object.keys(groups)) {
      if (groups[name] !== undefined) return labels[name];
    }
  }
  return 'personal';
}

// Regions that are already labels. Nothing inside one may be redacted again.
//
// WHY. A label is `[PII:category:16hex]`, and some perfectly reasonable
// patterns match that shape: `api[_-]?key\s*[=:]\s*[A-Za-z0-9_-]{16,}` finds
// "api-key:f9cff609da63178e" INSIDE `AIzafffffffffffffffffffffffffffffffffff`.
// The result was a nested label, `[PII:google-[PII:generic-...:...]]`, which
// no longer resolves -- and resolution is what lets tools edit real files.
//
// It also made redaction non-idempotent, which the residue scrubber depends
// on: it re-runs this pipeline over files that ALREADY contain labels from
// earlier passes, so each pass would corrupt the previous pass's output.
//
// Guarding at the engine level rather than tightening the one pattern that
// exposed it: any future pattern could collide with the label format, and a
// rule the user writes themselves should not be able to break resolution.
const LABEL_RE = /\[PII:[A-Za-z0-9_-]+:[0-9a-f]{8,}\]/g;

function labelRegions(text) {
  const regions = [];
  LABEL_RE.lastIndex = 0;
  let m;
  while ((m = LABEL_RE.exec(text)) !== null) {
    regions.push([m.index, m.index + m[0].length]);
  }
  return regions;
}

function redactWithSpans(text, compiled, kLabel) {
  const found = [];
  const protectedRegions = labelRegions(text);
  const insideLabel = (start, end) => {
    for (const [a, b] of protectedRegions) {
      if (start < b && end > a) return true; // any overlap at all
    }
    return false;
  };

  for (const { re, labels } of compiled.regexes || []) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++; // guard against zero-width loops
        continue;
      }
      if (insideLabel(m.index, m.index + m[0].length)) continue;
      found.push({
        start: m.index,
        end: m.index + m[0].length,
        value: m[0],
        category: labelOf(m, labels),
      });
    }
  }

  if (found.length === 0) return { text, spans: [], counts: {} };

  // Earliest first; on a tie the longest wins, which is what makes a broad
  // category pattern beat a short literal starting at the same offset.
  found.sort((a, b) => a.start - b.start || b.end - a.end);

  const spans = [];
  const counts = {};
  let out = '';
  let cursor = 0;

  for (const f of found) {
    if (f.end <= cursor) continue; // fully nested in an already-accepted span -- drop it
    // A candidate that STARTS inside an already-accepted span but EXTENDS
    // beyond it is a crossing match, not a nested one. Dropping it wholesale
    // (as this used to do) throws away its non-overlapping tail, which then
    // survives untouched in cleartext. Clip it to the uncovered remainder
    // instead of re-running the compiled regexes against residual text --
    // the tail is not necessarily a match on its own (a crossing candidate's
    // suffix need not itself satisfy any registered pattern/literal), so
    // clipping the candidate we already found is the only way to guarantee
    // the tail still gets redacted.
    const start = Math.max(f.start, cursor);
    const value = start === f.start ? f.value : text.slice(start, f.end);
    const label = makeLabel(kLabel, f.category, value);
    out += text.slice(cursor, start);
    const redStart = out.length;
    out += label;
    spans.push({
      realStart: start,
      realEnd: f.end,
      redStart,
      redEnd: out.length,
      value,
      category: f.category,
    });
    counts[f.category] = (counts[f.category] || 0) + 1;
    cursor = f.end;
  }
  out += text.slice(cursor);

  return { text: out, spans, counts };
}

module.exports = { redactWithSpans, makeLabel };
