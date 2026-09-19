'use strict';

// The pool-only configuration: `egress.urls` empty, `egress.pool.enabled`
// true. This is the shape for "rely on fetched proxies, keep the VPN as a
// manual fallback", and it was broken -- health was created only when manual
// urls existed, while the agent was created whenever either source existed.
// So the masking check ran with a null health record and crashed, and the
// status line had nothing to report about IP masking.
//
// These tests pin the invariant: whenever egress can carry traffic, its state
// is observable. An unobservable protection is the failure mode this whole
// notification layer exists to prevent.

const { test } = require('node:test');
const assert = require('node:assert');
const { createHealth, createEgressAgent, verifyMasking } = require('../egress');
const { render } = require('../status');

test('an agent built from a dynamic list alone is still a real agent', () => {
  // Pool-only: nothing configured up front, proxies arrive later.
  let poolList = [];
  const agent = createEgressAgent({ egressList: () => poolList, warn: () => {} });
  assert.ok(agent, 'a dynamic list must produce an agent even while empty');
  assert.strictEqual(typeof agent.createConnection, 'function');
  agent.destroy();
});

test('verifyMasking refuses a missing health record loudly, not with a TypeError', () => {
  // Defence in depth: start.js should always pass one, but if it ever fails
  // to again, the failure must name the problem rather than surface as
  // "cannot read properties of null".
  assert.throws(
    () => verifyMasking({ health: null, agent: null, url: 'https://example.com' }, () => {}),
    /health/i
  );
});

test('health can be told what is configured after the fact', () => {
  // The pool does not exist yet at startup, so `configured` has to be
  // updatable or the status line can never mention egress in this mode.
  const h = createHealth({ egressList: [] });
  assert.deepStrictEqual(h.state.configured, []);
  h.setConfigured(['socks5://a:1080', 'socks5://b:1080']);
  assert.deepStrictEqual(h.state.configured, ['socks5://a:1080', 'socks5://b:1080']);
});

test('pool-only egress is visible on the status line once the pool fills', () => {
  const h = createHealth({ egressList: [] });
  h.setConfigured(['socks5://a:1080']);
  h.setDirectIp('203.0.113.1', 'IN');
  h.setApparentIp('198.51.100.1', 'US');
  const line = render({ ok: true, state: { redaction: { literals: 3 }, egress: h.snapshot() } }, { color: false });
  assert.match(line, /ip US/, 'masking state must reach the status line: ' + line);
});

test('pool-only egress with an empty pool reports unprotected, not silence', () => {
  // The dangerous case: egress is meant to be active, the pool came back
  // empty, so nothing can be tunnelled. Rendering nothing here would look
  // identical to "no egress configured, all fine".
  const h = createHealth({ egressList: [] });
  h.setConfigured(['(pool)']);
  h.note({ ok: false, error: 'no proxies verified' });
  const line = render({ ok: true, state: { redaction: { literals: 3 }, egress: h.snapshot() } }, { color: false });
  assert.ok(/unverified|NOT MASKED|EXPOSED/.test(line), 'an active-but-broken egress must be visible: ' + line);
});
