'use strict';

// Master key plus purpose-separated subkeys.
//
// The master key is a 32-byte file with ACLs restricted to the current user.
// It is generated locally and never transmitted. Losing it invalidates every
// label (and, from Phase 2, every cache entry), so rotation is a deliberate
// manual act rather than something scheduled.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

// Redaction state lives outside the repo so it can never be committed and no task
// working in the repo can stumble on it.
const KEY_PATH = path.join(os.homedir(), '.claude', 'redaction', 'redact.key');
const KEY_BYTES = 32;

// Node's `mode` option is largely inert on Windows, so tighten the real ACL.
// Returns true if the restriction was actually applied, false otherwise, so
// callers can decide whether that failure is worth surfacing.
function restrictAcl(target) {
  if (process.platform !== 'win32') {
    try {
      fs.chmodSync(target, 0o600);
      return true;
    } catch (e) {
      return false;
    }
  }
  const who = process.env.USERNAME || process.env.USER;
  if (!who) return false;
  try {
    execFileSync('icacls', [target, '/inheritance:r', '/grant:r', `${who}:F`], {
      stdio: 'ignore',
      windowsHide: true,
    });
    return true;
  } catch (e) {
    return false;
  }
}

function loadMaster(keyPath = process.env.CCR_KEY_PATH || KEY_PATH) {
  try {
    const buf = fs.readFileSync(keyPath);
    if (buf.length !== KEY_BYTES) {
      throw new Error(
        `master key at ${keyPath} is ${buf.length} bytes, expected ${KEY_BYTES}. ` +
          'Refusing to start rather than fall back to unkeyed hashing.'
      );
    }
    return buf;
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }

  const key = crypto.randomBytes(KEY_BYTES);
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  fs.writeFileSync(keyPath, key, { mode: 0o600 });
  const restricted = restrictAcl(keyPath);
  if (!restricted && process.platform === 'win32') {
    process.stderr.write(
      `redaction proxy: warning: could not restrict ACLs on master key at ${keyPath}; ` +
        'the file may retain inherited ACLs, making it readable by more than the current user.\n'
    );
  }
  return key;
}

function subkey(master, purpose) {
  return Buffer.from(
    crypto.hkdfSync('sha256', master, Buffer.alloc(0), Buffer.from(purpose, 'utf8'), 32)
  );
}

module.exports = { loadMaster, subkey, restrictAcl, KEY_PATH, KEY_BYTES };
