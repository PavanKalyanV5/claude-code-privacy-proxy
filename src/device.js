'use strict';

// Optional rewriting of metadata.user_id's device_id.
//
// device_id is a stable SHA-256 machine fingerprint sent on every request. The
// account is already identified by the API key, so this adds a persistent
// MACHINE identity on top -- which is what makes cross-session correlation to
// one computer possible.
//
// Off by default, and deliberately so: unlike everything else in this proxy, a
// change here has ACCOUNT-level consequences rather than local ones. A device
// fingerprint that changes every session plausibly looks like abuse.
//
//   "stable"  -- HMAC(k_device, real_id): a different value, but consistent
//                forever. Hides the real fingerprint without looking like a new
//                machine each time. The sensible middle.
//   "session" -- random per proxy start. Maximum unlinkability, highest chance
//                of tripping something.

const crypto = require('crypto');

function makeDeviceRewriter({ mode = 'off', kDevice, sessionId } = {}) {
  if (mode !== 'stable' && mode !== 'session') return null;

  const sessionValue =
    mode === 'session' ? (sessionId || crypto.randomBytes(32).toString('hex')) : null;

  return function rewrite(metadata) {
    if (!metadata || typeof metadata !== 'object') return metadata;
    if (typeof metadata.user_id !== 'string') return metadata;

    let inner;
    try {
      inner = JSON.parse(metadata.user_id);
    } catch (e) {
      return metadata; // shape we do not recognise: leave it alone
    }
    if (!inner || typeof inner.device_id !== 'string') return metadata;

    const replacement =
      mode === 'session'
        ? sessionValue
        : crypto.createHmac('sha256', kDevice).update(inner.device_id, 'utf8').digest('hex');

    return Object.assign({}, metadata, {
      user_id: JSON.stringify(Object.assign({}, inner, { device_id: replacement })),
    });
  };
}

module.exports = { makeDeviceRewriter };
