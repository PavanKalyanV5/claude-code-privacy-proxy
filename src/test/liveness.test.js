'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('child_process');
const path = require('path');
const net = require('net');

const HOOK = path.join(__dirname, '..', 'liveness-hook.js');

function runHook(env) {
  const out = execFileSync(process.execPath, [HOOK], {
    encoding: 'utf8',
    env: Object.assign({}, process.env, env),
  });
  return JSON.parse(out);
}

// Binds an ephemeral port and immediately releases it, so the caller gets a
// port number that is guaranteed to be closed at the moment of the call --
// unlike a hardcoded port such as 47113, which may have a real dev proxy
// listening on it (this test must not depend on that external state).
function getClosedPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

test('warns via systemMessage when ANTHROPIC_BASE_URL is unset', () => {
  const r = runHook({ ANTHROPIC_BASE_URL: '' });
  assert.ok('systemMessage' in r, `must use systemMessage, got: ${JSON.stringify(r)}`);
  assert.match(r.systemMessage, /REDACTION INACTIVE/);
  assert.match(r.systemMessage, /nothing is being redacted/);
});

test('warns via systemMessage when the proxy is not running', async () => {
  // Must not depend on whether a real proxy happens to be running on the
  // default 47113 (it routinely is, during development) -- use a port that
  // is guaranteed closed, and point the hook at it via CCR_PROXY_PORT so
  // ANTHROPIC_BASE_URL and the health check target agree.
  const port = await getClosedPort();
  const r = runHook({
    ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}`,
    CCR_PROXY_PORT: String(port),
  });
  assert.ok('systemMessage' in r, `must use systemMessage, got: ${JSON.stringify(r)}`);
  assert.match(r.systemMessage, /NOT RUNNING|NOT RESPONDING|UNHEALTHY/);
});

test('output is always a single valid JSON object', () => {
  for (const env of [{ ANTHROPIC_BASE_URL: '' }, { ANTHROPIC_BASE_URL: 'http://127.0.0.1:47113' }]) {
    const r = runHook(env);
    assert.strictEqual(typeof r, 'object');
    assert.ok(r !== null);
  }
});
