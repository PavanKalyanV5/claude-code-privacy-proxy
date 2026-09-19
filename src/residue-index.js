'use strict';

// Incremental scan/scrub support: a small on-disk index of files already
// known to be clean, so a scan or scrub pass does not have to re-read 599MB
// of transcripts to find the handful of files that changed since the last
// pass.
//
// Keyed by absolute path. The value captures BOTH mtimeMs and size, because
// either alone is defeated by a realistic edit: mtime alone is fooled by a
// same-second rewrite (Windows and fast disks make this easy to hit), and
// size alone is fooled by an edit that happens to produce an equal-length
// file (e.g. one redacted value swapped for a same-length label).
//
// THE PART THAT MATTERS MOST: the index also carries a fingerprint of the
// rules it was verified against. If the user adds a literal, every
// previously-"clean" file must be re-examined -- a stale index would report
// a clean machine while the new literal sat in a thousand transcripts
// untouched. So the fingerprint is checked on load, and any mismatch
// discards the whole index (not just the affected entries -- there is no
// cheap way to know which entries a rules change affects, so treating the
// index as entirely unverified is the only safe move). Getting this wrong
// means the tool silently lies about what is on disk.
//
// Corrupt or missing index files are treated as an empty index rather than
// thrown errors: a scan/scrub tool that crashes because of its own cache is
// worse than one that occasionally does a full pass.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// os.homedir() ignores process.env.HOME on Windows -- honour HOME first, same
// as scan-residue.js and scrub-residue.js, so a fixture HOME actually
// isolates the index too.
function homeDir() {
  return process.env.HOME || os.homedir();
}

function defaultIndexPath() {
  return path.join(homeDir(), '.claude', 'redaction', 'residue-index.json');
}

// A fingerprint over exactly the fields that decide what "clean" means:
// literals, patterns, aliases and normalize config. Anything else in the
// rules file (proxy port, egress config, ...) does not affect what residue
// scanning finds, so changing it must not force a full re-scan.
function computeRulesFingerprint(rules) {
  const material = JSON.stringify({
    literals: (rules && rules.literals) || [],
    patterns: (rules && rules.patterns) || [],
    aliases: (rules && rules.aliases) || [],
    normalize: (rules && rules.normalize) || {},
  });
  return crypto.createHash('sha256').update(material).digest('hex');
}

function createIndex({ indexPath, rulesFingerprint, now = Date.now } = {}) {
  const resolvedPath = indexPath || defaultIndexPath();
  let entries = new Map();
  let loadedFingerprint = null;
  const counters = { hits: 0, misses: 0 };

  // Loads from disk, verifying the rules fingerprint. A missing file, an
  // unparseable file, a malformed shape, or a fingerprint mismatch all result
  // in an empty index -- never a thrown error and never stale entries.
  function load() {
    entries = new Map();
    loadedFingerprint = null;

    let raw;
    try {
      raw = fs.readFileSync(resolvedPath, 'utf8');
    } catch (e) {
      return; // no index yet
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      return; // corrupt file -- treat as empty
    }

    if (!parsed || typeof parsed !== 'object' || typeof parsed.entries !== 'object' || parsed.entries === null) {
      return; // malformed -- treat as empty
    }

    // A rules change invalidates the ENTIRE index, not just some entries:
    // there is no cheap way to know which files a new literal or pattern
    // would newly match, so anything less than a full discard risks a false
    // "clean".
    if (typeof parsed.rulesFingerprint !== 'string' || parsed.rulesFingerprint !== rulesFingerprint) {
      return;
    }

    loadedFingerprint = parsed.rulesFingerprint;
    for (const [p, v] of Object.entries(parsed.entries)) {
      if (v && typeof v.mtimeMs === 'number' && typeof v.size === 'number') {
        entries.set(p, { mtimeMs: v.mtimeMs, size: v.size });
      }
    }
  }

  function save() {
    const obj = {
      version: 1,
      rulesFingerprint,
      savedAt: typeof now === 'function' ? now() : now,
      entries: Object.fromEntries(entries),
    };
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
    fs.writeFileSync(resolvedPath, JSON.stringify(obj));
  }

  // True only if this exact path was previously marked clean, at this exact
  // (mtimeMs, size), under the CURRENT rules fingerprint. Any mismatch --
  // including one this process's own load() already refused because the
  // fingerprint changed, since that leaves `entries` empty -- means "examine
  // it", never "assume clean".
  function isClean(filePath, stat) {
    const e = entries.get(filePath);
    const clean = !!e && e.mtimeMs === stat.mtimeMs && e.size === stat.size;
    if (clean) counters.hits++;
    else counters.misses++;
    return clean;
  }

  function markClean(filePath, stat) {
    entries.set(filePath, { mtimeMs: stat.mtimeMs, size: stat.size });
  }

  function markDirty(filePath) {
    entries.delete(filePath);
  }

  // Drops entries for files that no longer exist, so the index does not grow
  // without bound as transcripts are rotated away.
  function prune(existingPaths) {
    const keep = existingPaths instanceof Set ? existingPaths : new Set(existingPaths);
    for (const p of Array.from(entries.keys())) {
      if (!keep.has(p)) entries.delete(p);
    }
  }

  function stats() {
    return { entries: entries.size, hits: counters.hits, misses: counters.misses };
  }

  return { isClean, markClean, markDirty, load, save, stats, prune };
}

module.exports = { createIndex, computeRulesFingerprint, defaultIndexPath };
