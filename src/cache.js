'use strict';

// Encrypted, TTL-bounded label -> value cache.
//
// Derivation from the file on disk is authoritative for file edits; this exists
// only for the case derivation cannot serve -- a label inside a Bash command,
// where there is no target file.
//
// On encryption: the proxy, the key and this file are all readable by the same
// user, so this does not defeat a local attacker. What it prevents is
// ACCIDENTAL exposure -- the file being swept into a cloud sync, a backup or a
// support bundle. That is the realistic threat for a file of this shape.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const CACHE_PATH = path.join(os.homedir(), '.claude', 'redaction', 'redact-cache.enc');
const DEFAULT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_MAX_ENTRIES = 5000;
const IV_BYTES = 12;

function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${tag.toString('base64')}.${enc.toString('base64')}`;
}

function decrypt(key, blob) {
  const [ivB64, tagB64, dataB64] = String(blob).split('.');
  if (!ivB64 || !tagB64 || !dataB64) throw new Error('malformed cache blob');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(dataB64, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

function createCache({
  key,
  path: cachePath = CACHE_PATH,
  ttlMs = DEFAULT_TTL_MS,
  maxEntries = DEFAULT_MAX_ENTRIES,
  now = () => Date.now(),
} = {}) {
  // label -> { v: value, t: epoch ms }
  let entries = new Map();

  try {
    const raw = fs.readFileSync(cachePath, 'utf8');
    const obj = JSON.parse(decrypt(key, raw));
    const cutoff = now() - ttlMs;
    for (const [label, rec] of Object.entries(obj)) {
      if (rec && typeof rec.v === 'string' && typeof rec.t === 'number' && rec.t > cutoff) {
        entries.set(label, rec);
      }
    }
  } catch (e) {
    // Missing, corrupt, tampered, or written under a different key. Rebuild
    // empty -- a cache must never fail a request.
    entries = new Map();
  }

  return {
    get(label) {
      const rec = entries.get(label);
      if (!rec) return undefined;
      if (rec.t <= now() - ttlMs) {
        entries.delete(label);
        return undefined;
      }
      // Refresh the timestamp and move to end for LRU eviction.
      rec.t = now();
      entries.delete(label);
      entries.set(label, rec);
      return rec.v;
    },
    set(label, value) {
      if (typeof label !== 'string' || typeof value !== 'string') return;
      entries.delete(label); // refresh insertion order
      entries.set(label, { v: value, t: now() });
      while (entries.size > maxEntries) entries.delete(entries.keys().next().value);
    },
    save() {
      try {
        fs.mkdirSync(path.dirname(cachePath), { recursive: true });
        const obj = {};
        for (const [label, rec] of entries) obj[label] = rec;
        const tmp = `${cachePath}.${process.pid}.tmp`;
        fs.writeFileSync(tmp, encrypt(key, JSON.stringify(obj)), { mode: 0o600 });
        fs.renameSync(tmp, cachePath);
      } catch (e) {
        // Persistence is best-effort; an in-memory cache still works.
      }
    },
    size() {
      return entries.size;
    },
  };
}

module.exports = { createCache, CACHE_PATH, DEFAULT_TTL_MS };
