'use strict';

// Derived resolution: turn an edit expressed against REDACTED text into one
// expressed against the REAL file, without ever storing the mapping.
//
// Redaction is deterministic, so re-redacting the file on disk reproduces
// byte-for-byte what the model saw, plus a span map of real<->redacted offsets.
// The mapping therefore exists for the duration of one function call and is
// derived entirely from a file the caller already has.
//
// Every ambiguity refuses. A wrong offset corrupts a user's file, so "pass it
// through and let the Edit fail visibly" is always the better outcome.

const { makeLabel } = require('./spans');

const LABEL_RE = /\[PII:[a-z0-9_-]+:[0-9a-f]{16}\]/gi;

// Translate an offset in the REDACTED text to the corresponding offset in the
// REAL text. Returns null when the offset falls strictly inside a replaced
// span, where no single real offset corresponds.
function mapOffset(redOffset, spans) {
  let delta = 0;
  for (const s of spans) {
    if (redOffset <= s.redStart) break; // at or before this span: done
    if (redOffset < s.redEnd) return null; // strictly inside: ambiguous
    delta += (s.realEnd - s.realStart) - (s.redEnd - s.redStart);
  }
  return redOffset + delta;
}

// Replace every label in `text` with its real value, using only values present
// in THIS file's spans. Returns null if any label remains unresolved -- writing
// a literal [PII:...] marker into a file would be worse than failing.
function rehydrate(text, spans, kLabel) {
  if (typeof text !== 'string') return text;
  const byLabel = new Map();
  for (const s of spans) byLabel.set(makeLabel(kLabel, s.category, s.value), s.value);

  let out = text;
  for (const [label, value] of byLabel) {
    if (out.includes(label)) out = out.split(label).join(value);
  }

  LABEL_RE.lastIndex = 0;
  if (LABEL_RE.test(out)) return null; // an unknown label survived
  return out;
}

/**
 * @param realText  the file's true contents
 * @param redacted  the result of redactWithSpans(realText, ...)
 * @param oldString the model's old_string, expressed against redacted text
 * @param newString the model's new_string, may contain labels
 * @param kLabel    HMAC key, to recompute labels from span values
 * @param resolveNewString optional custom resolver for newString; if provided, replaces rehydrate
 * @returns { oldString, newString } against the REAL text, or null to refuse
 */
function translateEdit({ realText, redacted, oldString, newString, kLabel, resolveNewString }) {
  if (typeof oldString !== 'string' || oldString.length === 0) return null;

  const hay = redacted.text;
  const idx = hay.indexOf(oldString);
  if (idx === -1) return null; // not found
  if (hay.indexOf(oldString, idx + 1) !== -1) return null; // ambiguous

  const realStart = mapOffset(idx, redacted.spans);
  const realEnd = mapOffset(idx + oldString.length, redacted.spans);
  if (realStart === null || realEnd === null) return null; // boundary inside a span

  const realOld = realText.slice(realStart, realEnd);
  const realNew = resolveNewString
    ? resolveNewString(newString)
    : rehydrate(newString, redacted.spans, kLabel);
  if (realNew === null) return null; // unknown label in new_string

  return { oldString: realOld, newString: realNew };
}

module.exports = { mapOffset, rehydrate, translateEdit, LABEL_RE };
