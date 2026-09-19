'use strict';

// Tests for the auto-mode tunnel decision.
//
// These exist because of a live leak. Auto mode observed a VPN exit country,
// correctly decided "already masked, no tunnel needed", and then held that
// decision for its full 15-minute re-check interval. The user turned the VPN
// off; for the next seven minutes every request went out from their real
// address while the status line reported them protected.
//
// The rule being pinned: an expired observation is NOT a decision. Staleness
// is indistinguishable from a changed network, so an expired decision reads as
// "unknown", and unknown means tunnel.

const { test } = require('node:test');
const assert = require('node:assert');
const { decideTunnel, DECISION_TTL_MS } = require('../egress');

const NOW = 1_000_000_000;
const fresh = NOW - 1000;

test('off never tunnels', () => {
  assert.strictEqual(decideTunnel({ mode: 'off', now: NOW }).tunnel, false);
});

test('on always tunnels, regardless of country', () => {
  const d = decideTunnel({ mode: 'on', homeCountry: 'IN', directCountry: 'IN', decidedAt: fresh, now: NOW });
  assert.strictEqual(d.tunnel, true);
});

test('auto tunnels when the observed country IS home (exposed)', () => {
  const d = decideTunnel({ mode: 'auto', homeCountry: 'IN', directCountry: 'IN', decidedAt: fresh, now: NOW });
  assert.strictEqual(d.tunnel, true);
  assert.match(d.reason, /home country/);
});

test('auto does not tunnel when the observed country is elsewhere (VPN up)', () => {
  const d = decideTunnel({ mode: 'auto', homeCountry: 'IN', directCountry: 'NL', decidedAt: fresh, now: NOW });
  assert.strictEqual(d.tunnel, false);
  assert.match(d.reason, /already masked/);
});

// ------------------------------------------------ the staleness fail-safe

test('an EXPIRED "already masked" decision fails safe and tunnels', () => {
  // The exact leak: observation said NL, then the VPN went away.
  const d = decideTunnel({
    mode: 'auto',
    homeCountry: 'IN',
    directCountry: 'NL',
    decidedAt: NOW - DECISION_TTL_MS - 1,
    now: NOW,
  });
  assert.strictEqual(d.tunnel, true, 'a stale decision must never keep sending traffic direct');
  assert.strictEqual(d.stale, true);
  assert.match(d.reason, /re-verifying/);
});

test('a decision exactly at the TTL boundary is still trusted', () => {
  const d = decideTunnel({
    mode: 'auto',
    homeCountry: 'IN',
    directCountry: 'NL',
    decidedAt: NOW - DECISION_TTL_MS,
    now: NOW,
  });
  assert.strictEqual(d.tunnel, false);
  assert.ok(!d.stale);
});

test('one millisecond past the TTL flips to tunnelling', () => {
  const d = decideTunnel({
    mode: 'auto',
    homeCountry: 'IN',
    directCountry: 'NL',
    decidedAt: NOW - DECISION_TTL_MS - 1,
    now: NOW,
  });
  assert.strictEqual(d.tunnel, true);
});

test('never having observed a country means tunnel', () => {
  const d = decideTunnel({ mode: 'auto', homeCountry: 'IN', directCountry: null, decidedAt: null, now: NOW });
  assert.strictEqual(d.tunnel, true);
  assert.match(d.reason, /not yet observed/);
});

test('a fresh observation with an UNKNOWN country still tunnels', () => {
  // Reachable when the geo endpoint answers without a country field.
  const d = decideTunnel({ mode: 'auto', homeCountry: 'IN', directCountry: null, decidedAt: fresh, now: NOW });
  assert.strictEqual(d.tunnel, true);
  assert.match(d.reason, /could not be determined/);
});

test('an expired EXPOSED decision also tunnels (no accidental flip to direct)', () => {
  const d = decideTunnel({
    mode: 'auto',
    homeCountry: 'IN',
    directCountry: 'IN',
    decidedAt: NOW - DECISION_TTL_MS * 10,
    now: NOW,
  });
  assert.strictEqual(d.tunnel, true);
});

test('the only path to NOT tunnelling in auto mode is a fresh non-home country', () => {
  // Exhaustive over the inputs that matter: exactly one combination may
  // return false. If a future change widens that, this fails.
  const cases = [];
  for (const country of ['IN', 'NL', null]) {
    for (const age of [0, DECISION_TTL_MS - 1, DECISION_TTL_MS + 1]) {
      for (const decided of [true, false]) {
        cases.push({ country, age, decided });
      }
    }
  }
  const direct = cases.filter((c) => {
    const d = decideTunnel({
      mode: 'auto',
      homeCountry: 'IN',
      directCountry: c.country,
      decidedAt: c.decided ? NOW - c.age : null,
      now: NOW,
    });
    return d.tunnel === false;
  });
  for (const c of direct) {
    assert.strictEqual(c.country, 'NL', `unexpected direct verdict for ${JSON.stringify(c)}`);
    assert.strictEqual(c.decided, true, `unexpected direct verdict for ${JSON.stringify(c)}`);
    assert.ok(c.age <= DECISION_TTL_MS, `unexpected direct verdict for ${JSON.stringify(c)}`);
  }
  assert.ok(direct.length > 0, 'sanity: at least one case should go direct');
});
