'use strict';

// Request header hygiene.
//
// `transformBody` walks the JSON body. Headers are a completely separate
// channel and were being forwarded verbatim -- measured: 9 of 9 fingerprinting
// headers reached upstream unchanged. Several of them carry exactly what the
// rest of this system exists to hide:
//
//   accept-language              regional locale (a "pt-PT" pins the country)
//   x-stainless-os / -arch       OS and CPU architecture
//   x-stainless-runtime-version  exact Node build, a narrow fingerprint
//   x-forwarded-for / x-real-ip  a literal IP, if any intermediary set one
//
// Redaction is deliberately NOT applied to header values: header names and
// shapes are a protocol contract, and a [PII:...] label in a header would
// break the request rather than protect it. These are normalized to plausible
// generic values or dropped, never labelled.
//
// Anything not listed is passed through: an allowlist would break the API the
// first time a new header appeared, and this proxy must never be the reason a
// request fails.

// Header -> replacement value. `null` means remove the header entirely.
const DEFAULT_RULES = {
  // Regional locale. A generic value is sent rather than dropping it, because
  // absent locale is itself slightly unusual.
  'accept-language': 'en-US,en;q=0.9',

  // Client telemetry. Kept present and plausible so the request still looks
  // like a normal SDK call, with the machine specifics generalized away.
  'x-stainless-os': 'Unknown',
  'x-stainless-arch': 'unknown',
  'x-stainless-runtime-version': null,

  // Address-bearing headers. Claude Code does not set these; an intermediary
  // or a misconfigured egress proxy can, and then the tunnel's whole purpose
  // is defeated by a header. Dropped unconditionally.
  'x-forwarded-for': null,
  'x-real-ip': null,
  'x-client-ip': null,
  forwarded: null,
  via: null,
};

// Compile a policy from config. `mode` off disables everything; `keep` lists
// header names to leave alone; `extra` adds or overrides rules.
function compileHeaderPolicy(cfg = {}) {
  if (cfg === false || cfg.mode === 'off') return null;
  const rules = Object.assign({}, DEFAULT_RULES, cfg.extra || {});
  for (const k of cfg.keep || []) delete rules[k.toLowerCase()];
  return { rules, count: Object.keys(rules).length };
}

// Returns a new headers object; never mutates the input. Node lowercases
// incoming header names, so matching on lowercase keys is sufficient.
function applyHeaderPolicy(headers, policy, stats = null) {
  if (!policy) return headers;
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const rule = policy.rules[k.toLowerCase()];
    if (rule === undefined) {
      out[k] = v;
      continue;
    }
    if (stats) stats[k.toLowerCase()] = (stats[k.toLowerCase()] || 0) + 1;
    if (rule === null) continue; // dropped
    out[k] = rule;
  }
  return out;
}

module.exports = { compileHeaderPolicy, applyHeaderPolicy, DEFAULT_RULES };
