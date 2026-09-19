'use strict';

// The dashboard token guards the only route in this project that WRITES the
// user's PII rules. These tests pin down where it is allowed to come to rest.
//
// The original design reasoned explicitly that the token must not reach
// status.json, "readable by any other local process", and then logged it in
// full to the audit log. Measured on this machine:
//
//   redact.key         MACHINE\USER:(F)                      inheritance stripped
//   redact-proxy.log   USER:(I)(F) SYSTEM:(I)(F) Admins:(I)(F)  inherited
//
// So the log was a strictly WEAKER location than the one deliberately
// avoided, and unlike a status snapshot it persists indefinitely. These tests
// exist so that cannot silently come back.

const { test } = require('node:test');
const assert = require('node:assert');
const { parseLogLine } = require('../dash');

test('a token in a log line is masked before it is served', () => {
  const line = '[warn] dashboard: http://127.0.0.1:47113/_dash?t=5d597114bf546c518d8941f429d087c4';
  const parsed = parseLogLine(line);
  assert.ok(!parsed.text.includes('5d597114bf546c518d8941f429d087c4'), 'the token must not survive parsing');
  assert.match(parsed.text, /t=\[redacted\]/);
});

test('masking applies to every log line shape, not just warnings', () => {
  // The three shapes parseLogLine handles: warn-prefixed, timestamped, bare.
  const shapes = [
    '[warn] see http://127.0.0.1:47113/_dash?t=' + 'a'.repeat(32),
    '[12:34:56] GET /_dash?t=' + 'b'.repeat(32) + ' body=0KB',
    'unprefixed line with ?t=' + 'c'.repeat(32),
  ];
  for (const s of shapes) {
    const parsed = parseLogLine(s);
    assert.ok(!/[a-f]{32}/.test(parsed.text), 'token leaked from shape: ' + s);
  }
});

test('masking also catches a token passed as a second query parameter', () => {
  const parsed = parseLogLine('[warn] http://127.0.0.1:47113/_dash?x=1&t=' + 'd'.repeat(32));
  assert.ok(!parsed.text.includes('d'.repeat(32)));
});

test('ordinary log content is left alone', () => {
  // Over-eager masking would corrupt the log viewer, which is the one place
  // the user can see what the proxy actually did.
  const line = '[12:34:56] POST /v1/messages body=543.8KB walked=0.6KB memo=248/252';
  assert.strictEqual(parseLogLine(line).text, 'POST /v1/messages body=543.8KB walked=0.6KB memo=248/252');
});

test('a short t= value is not mistaken for a token', () => {
  // Real query parameters named t exist (timestamps, tab indexes). The
  // pattern requires at least 16 hex characters so those survive intact.
  const line = '[12:34:56] GET /something?t=3 body=0KB';
  assert.ok(parseLogLine(line).text.includes('t=3'), 'must not mangle a short t= value');
});
