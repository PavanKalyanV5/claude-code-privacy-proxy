'use strict';

// One-way environment normalization.
//
// Distinct from redaction on purpose. Redaction turns a value into a label and
// is reversible for local tools, which suits anything the model might need to
// use in a command. Normalization rewrites a value to a coarser one with no
// label and no reverse, which suits a timezone offset or an OS build string --
// nothing round-trips them, and a label there would just be noise the model has
// to reason around.
//
// The hazard here is over-matching. A rule that fires on a version number, an
// ID or an IP address is worse than the leak it closes, so every pattern is
// anchored tightly and the test suite carries negative cases.

// A full datetime with a trailing offset. Requires a real date AND time, so a
// bare "2026-2030" or "+5" cannot match.
const DATETIME_OFFSET =
  /(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?\s?([+-])(\d{2}):?(\d{2})\b/g;

// A bare offset not attached to a datetime. Must be preceded by whitespace or
// '=' and be exactly 4 digits, so "+5 items" and "-0700.50" do not match.
const BARE_OFFSET = /(^|[\s=])([+-])(\d{2})(\d{2})(?![\d.])/g;

function toUtc(text) {
  let count = 0;

  let out = text.replace(
    DATETIME_OFFSET,
    (m, y, mo, d, h, mi, s, frac, sign, oh, om) => {
      const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}${frac || ''}${sign}${oh}:${om}`;
      const ms = Date.parse(iso);
      if (!Number.isFinite(ms)) {
        // Nonsense date: no instant can be computed, but the zone must still
        // not survive. Blank the offset and leave the rest as written.
        count++;
        return `${y}-${mo}-${d}T${h}:${mi}:${s}${frac || ''}+0000`;
      }
      count++;
      const u = new Date(ms).toISOString(); // e.g. 2026-09-17T15:38:56.250Z
      return frac ? u : u.replace(/\.\d{3}Z$/, 'Z');
    }
  );

  out = out.replace(BARE_OFFSET, (m, pre) => {
    count++;
    return `${pre}+0000`;
  });

  return { text: out, count };
}

function compileNormalizers(cfg = {}, warn = () => {}) {
  const rewrites = [];
  for (const r of cfg.rewrites || []) {
    if (!r || typeof r.regex !== 'string') continue;
    try {
      const flags = r.flags && r.flags.includes('g') ? r.flags : `${r.flags || ''}g`;
      rewrites.push({
        name: r.name || 'rewrite',
        re: new RegExp(r.regex, flags),
        replace: typeof r.replace === 'string' ? r.replace : '',
      });
    } catch (e) {
      warn(`normalize rewrite "${r.name || '?'}" disabled: ${e.message}`);
    }
  }
  return { timezone: cfg.timezone === true, rewrites };
}

// Same transform as normalize(), but reports an offset map in the same shape
// spans.js's redactWithSpans uses, so the outbound pipeline can compose all
// three stages uniformly (see pipeline.js). Implemented independently of
// normalize()/toUtc() rather than by instrumenting their String.replace
// callbacks: matches are gathered by running every rewrite regex plus the two
// timezone regexes as exec() scans against the ORIGINAL text, then resolved
// and rebuilt in one pass exactly like redactWithSpans -- earliest start
// wins, ties broken by the longer match, so a datetime match always wins over
// a bare-offset candidate nested inside it (the offset suffix of that same
// datetime).
function normalizeWithSpans(text, compiled) {
  if (typeof text !== 'string' || !compiled) return { text, count: 0, spans: [] };

  const found = [];

  for (const r of compiled.rewrites) {
    r.re.lastIndex = 0;
    let m;
    while ((m = r.re.exec(text)) !== null) {
      if (m[0].length === 0) {
        r.re.lastIndex++;
        continue;
      }
      const value = r.replace.replace(/\$(\d)/g, (_, n) => m[Number(n)] ?? '');
      found.push({ start: m.index, end: m.index + m[0].length, value });
    }
  }

  if (compiled.timezone) {
    DATETIME_OFFSET.lastIndex = 0;
    let m;
    while ((m = DATETIME_OFFSET.exec(text)) !== null) {
      if (m[0].length === 0) {
        DATETIME_OFFSET.lastIndex++;
        continue;
      }
      const [, y, mo, d, h, mi, s, frac, sign, oh, om] = m;
      const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}${frac || ''}${sign}${oh}:${om}`;
      const ms = Date.parse(iso);
      let value;
      if (!Number.isFinite(ms)) {
        value = `${y}-${mo}-${d}T${h}:${mi}:${s}${frac || ''}+0000`;
      } else {
        const u = new Date(ms).toISOString();
        value = frac ? u : u.replace(/\.\d{3}Z$/, 'Z');
      }
      found.push({ start: m.index, end: m.index + m[0].length, value });
    }

    BARE_OFFSET.lastIndex = 0;
    while ((m = BARE_OFFSET.exec(text)) !== null) {
      if (m[0].length === 0) {
        BARE_OFFSET.lastIndex++;
        continue;
      }
      found.push({ start: m.index, end: m.index + m[0].length, value: `${m[1]}+0000` });
    }
  }

  if (found.length === 0) return { text, count: 0, spans: [] };

  // Earliest first; on a tie the longer match wins -- same rule spans.js
  // uses, and what makes a full datetime win over a bare-offset candidate
  // nested inside its own trailing offset.
  found.sort((a, b) => a.start - b.start || b.end - a.end);

  let out = '';
  let cursor = 0;
  let count = 0;
  const spans = [];

  for (const f of found) {
    if (f.start < cursor) continue; // overlaps an already-accepted match: drop
    out += text.slice(cursor, f.start);
    const outStart = out.length;
    out += f.value;
    spans.push({ srcStart: f.start, srcEnd: f.end, outStart, outEnd: out.length });
    count++;
    cursor = f.end;
  }
  out += text.slice(cursor);

  return { text: out, count, spans };
}

function normalize(text, compiled) {
  if (typeof text !== 'string' || !compiled) return { text, count: 0 };
  let out = text;
  let count = 0;

  for (const r of compiled.rewrites) {
    r.re.lastIndex = 0;
    out = out.replace(r.re, (...args) => {
      count++;
      // Build the replacement with $1..$9 support, without re-running the regex.
      return r.replace.replace(/\$(\d)/g, (_, n) => args[Number(n)] ?? '');
    });
  }

  if (compiled.timezone) {
    const t = toUtc(out);
    out = t.text;
    count += t.count;
  }

  return { text: out, count };
}

module.exports = { compileNormalizers, normalize, normalizeWithSpans, toUtc };
