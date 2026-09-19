'use strict';

// Per-request audit line. Counts only -- never values, never credentials.
// Under-redaction and over-redaction are both invisible without this.

const fs = require('fs');

const kb = (n) => `${(n / 1024).toFixed(1)}KB`;

function formatLine({ method, url, bytes, stats, resolvedAliases = 0 }) {
  const s = stats || {};
  const counts = s.counts || {};
  const cats = Object.keys(counts).sort();
  const redacted = cats.length ? cats.map((c) => `${c}=${counts[c]}`).join(' ') : 'redacted=none';
  const total = (s.memoHit || 0) + (s.memoMiss || 0);
  const t = new Date().toISOString().slice(11, 19);
  return (
    `[${t}] ${method} ${url} body=${kb(bytes)} walked=${kb(s.walkedChars || 0)} ` +
    `memo=${s.memoHit || 0}/${total} | ${redacted} ` +
    `aliased=${s.aliased || 0} unaliased=${resolvedAliases}`
  );
}

function createLogger(logPath) {
  const write = (text) => {
    try {
      fs.appendFileSync(logPath, text + '\n');
    } catch (e) {
      /* logging must never break a request */
    }
    process.stdout.write(text + '\n');
  };
  return {
    line: (entry) => write(formatLine(entry)),
    warn: (msg) => write(`[warn] ${msg}`),
  };
}

module.exports = { formatLine, createLogger };
