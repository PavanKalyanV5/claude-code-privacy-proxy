'use strict';

// Tests for the audit dashboard (src/dash.js). Built directly against
// createDashboard() rather than the full proxy: dash.js is deliberately
// decoupled from start.js (which we must never start from a test -- see
// start.test.js), so a bare http server wrapping dash.handle() is enough to
// exercise every route, and is exactly what server.js does in production.
//
// Every fixture lives in a temp dir; nothing here reads or writes the user's
// real ~/.claude/redaction files.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

const { createDashboard } = require('../dash');

function tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dasht-'));
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  return p;
}

function baseRules() {
  return {
    literals: ['Jane Q. Testerson'],
    patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}', flags: 'gi' }],
    aliases: [{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\DELL' }],
    remoteTools: [],
    normalize: { timezone: true, rewrites: [] },
    deviceId: { mode: 'off' },
    egress: { mode: 'off' },
    proxy: { port: 0 },
  };
}

function defaultSnapshot() {
  return {
    proxy: { pid: 111, port: 47113, uptimeMs: 1000 },
    redaction: { literals: 1, patterns: 1, aliases: 1, rewrites: 0, timezone: true },
    egress: { configured: [] },
    residue: null,
  };
}

// Builds a dashboard against fixture files and serves it on an ephemeral
// port, the same way server.js dispatches to it: try dash.handle() first,
// fall through to a plain 404 for anything it declines.
function startDash(opts = {}) {
  const rules = opts.rules || baseRules();
  const rulesPath = opts.rulesPath || tmpFile('rules.json', JSON.stringify(rules, null, 2));
  const logPath = opts.logPath || tmpFile('proxy.log', opts.log != null ? opts.log : '');
  const dashboard = createDashboard({
    rulesPath,
    logPath,
    getSnapshot: opts.getSnapshot || defaultSnapshot,
    egressActions: opts.egressActions || {},
    residueScan: opts.residueScan,
    verify: opts.verify,
    intervalMs: opts.intervalMs,
  });
  const server = http.createServer((req, res) => {
    if (!dashboard.handle(req, res)) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found\n');
    }
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, dashboard, port: server.address().port, rulesPath, logPath });
    });
  });
}

function request(port, method, urlPath, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : typeof body === 'string' ? body : JSON.stringify(body);
    const reqHeaders = Object.assign({}, headers);
    if (data) {
      reqHeaders['content-type'] = 'application/json';
      reqHeaders['content-length'] = Buffer.byteLength(data);
    }
    const req = http.request({ host: '127.0.0.1', port, method, path: urlPath, headers: reqHeaders }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// -------------------------------------------------------------------- auth

test('an unauthenticated request to a /_dash route is refused with no detail', async () => {
  const { server, port } = await startDash({});
  const r = await request(port, 'GET', '/_dash/api/status');
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.trim(), 'forbidden');
  server.close();
});

test('a wrong-length token is refused', async () => {
  const { server, port } = await startDash({});
  const r = await request(port, 'GET', '/_dash/api/status', { headers: { 'x-dash-token': 'tooshort' } });
  assert.strictEqual(r.status, 403);
  server.close();
});

test('a wrong-value token of the correct length is refused', async () => {
  const { server, dashboard, port } = await startDash({});
  const wrong = crypto.randomBytes(16).toString('hex');
  assert.strictEqual(wrong.length, dashboard.token.length, 'test token must match the real one in length to test the value check');
  assert.notStrictEqual(wrong, dashboard.token);
  const r = await request(port, 'GET', '/_dash/api/status', { headers: { 'x-dash-token': wrong } });
  assert.strictEqual(r.status, 403);
  server.close();
});

test('the correct token is accepted', async () => {
  const { server, dashboard, port } = await startDash({});
  const r = await request(port, 'GET', '/_dash/api/status', { headers: { 'x-dash-token': dashboard.token } });
  assert.strictEqual(r.status, 200);
  server.close();
});

test('the token also works as a ?t= query parameter, for assets EventSource cannot set headers on', async () => {
  const { server, dashboard, port } = await startDash({});
  const r = await request(port, 'GET', '/_dash/api/status?t=' + dashboard.token);
  assert.strictEqual(r.status, 200);
  server.close();
});

test('no JSON API response body contains the token, authenticated or not', async () => {
  const { server, dashboard, port } = await startDash({});
  const authed = ['/_dash/api/status', '/_dash/api/config', '/_dash/api/config/raw', '/_dash/api/logs'];
  for (const p of authed) {
    const r = await request(port, 'GET', p, { headers: { 'x-dash-token': dashboard.token } });
    assert.strictEqual(r.body.indexOf(dashboard.token), -1, `${p} leaked the token in its body`);
  }
  const denied = await request(port, 'GET', '/_dash/api/status');
  assert.strictEqual(denied.body.indexOf(dashboard.token), -1);
  server.close();
});

test('a path outside /_dash is declined (handle returns false) so the host server can fall through', async () => {
  // startDash listens, so the server must be closed even though this test
  // calls handle() directly and never makes a request. Leaving it open holds
  // the event loop forever: the test itself passes, the reporter prints a
  // clean summary, and then `node --test` simply never exits -- which is what
  // made the whole suite look like it hung.
  const { server, dashboard } = await startDash({});
  const req = { url: '/_health', headers: {} };
  const res = { writeHead() {}, end() {} };
  assert.strictEqual(dashboard.handle(req, res), false);
  server.close();
});

// ------------------------------------------------------------------ config

test('GET /api/config masks literal values; /api/config/raw does not', async () => {
  const rules = baseRules();
  const { server, dashboard, port } = await startDash({ rules });
  const masked = await request(port, 'GET', '/_dash/api/config', { headers: { 'x-dash-token': dashboard.token } });
  const raw = await request(port, 'GET', '/_dash/api/config/raw', { headers: { 'x-dash-token': dashboard.token } });
  const m = JSON.parse(masked.body);
  const r = JSON.parse(raw.body);

  assert.strictEqual(m.literals[0].value, '***');
  assert.strictEqual(m.literals[0].length, 'Jane Q. Testerson'.length);
  assert.strictEqual(r.literals[0], 'Jane Q. Testerson');

  assert.strictEqual(m.aliases[0].real, '***');
  assert.strictEqual(m.aliases[0].realLength, 'C:\\Users\\SOMEONE'.length);
  assert.strictEqual(r.aliases[0].real, 'C:\\Users\\SOMEONE');
  // The alias's safe side is not PII and stays visible in both views.
  assert.strictEqual(m.aliases[0].alias, 'C:\\Users\\DELL');
  server.close();
});

test('POST /api/config rejects a catastrophic-backtracking pattern; the rules file is left byte-for-byte unchanged', async () => {
  const rules = baseRules();
  const { server, dashboard, port, rulesPath } = await startDash({ rules });
  const before = fs.readFileSync(rulesPath);
  const bad = Object.assign({}, rules, { patterns: [{ name: 'evil', regex: '^(a+)+$', flags: 'g' }] });

  const r = await request(port, 'POST', '/_dash/api/config', { headers: { 'x-dash-token': dashboard.token }, body: bad });
  assert.strictEqual(r.status, 400);
  const parsed = JSON.parse(r.body);
  assert.ok(Array.isArray(parsed.errors) && parsed.errors.length > 0);

  const after = fs.readFileSync(rulesPath);
  assert.deepStrictEqual(before, after, 'a rejected save must not touch the rules file');
  server.close();
});

test('POST /api/config rejects a risky alias; nothing is written', async () => {
  const rules = baseRules();
  const { server, dashboard, port, rulesPath } = await startDash({ rules });
  const before = fs.readFileSync(rulesPath);
  const bad = Object.assign({}, rules, { aliases: [{ real: 'SOME-MACHINE-NAME', alias: 'host' }] });

  const r = await request(port, 'POST', '/_dash/api/config', { headers: { 'x-dash-token': dashboard.token }, body: bad });
  assert.strictEqual(r.status, 400);
  const parsed = JSON.parse(r.body);
  assert.match(JSON.stringify(parsed.errors), /host/);
  assert.deepStrictEqual(fs.readFileSync(rulesPath), before);
  server.close();
});

test('POST /api/config rejects real === alias; nothing is written', async () => {
  const rules = baseRules();
  const { server, dashboard, port, rulesPath } = await startDash({ rules });
  const before = fs.readFileSync(rulesPath);
  const bad = Object.assign({}, rules, { aliases: [{ real: 'SAME-VALUE-XYZ', alias: 'SAME-VALUE-XYZ' }] });

  const r = await request(port, 'POST', '/_dash/api/config', { headers: { 'x-dash-token': dashboard.token }, body: bad });
  assert.strictEqual(r.status, 400);
  assert.deepStrictEqual(fs.readFileSync(rulesPath), before);
  server.close();
});

test('POST /api/config rejects egress.mode "auto" without a homeCountry', async () => {
  const rules = baseRules();
  const { server, dashboard, port, rulesPath } = await startDash({ rules });
  const before = fs.readFileSync(rulesPath);
  const bad = Object.assign({}, rules, { egress: { mode: 'auto' } });

  const r = await request(port, 'POST', '/_dash/api/config', { headers: { 'x-dash-token': dashboard.token }, body: bad });
  assert.strictEqual(r.status, 400);
  assert.deepStrictEqual(fs.readFileSync(rulesPath), before);
  server.close();
});

test('a valid POST writes the config, backs up first, and the backup holds the ORIGINAL content', async () => {
  const rules = baseRules();
  const { server, dashboard, port, rulesPath } = await startDash({ rules });
  const before = fs.readFileSync(rulesPath, 'utf8');
  const good = Object.assign({}, rules, { literals: ['A Whole New Name'] });

  const r = await request(port, 'POST', '/_dash/api/config', { headers: { 'x-dash-token': dashboard.token }, body: good });
  assert.strictEqual(r.status, 200);
  const parsed = JSON.parse(r.body);
  assert.strictEqual(parsed.ok, true);
  assert.ok(parsed.backup && fs.existsSync(parsed.backup), 'response must point at a real backup file');
  assert.strictEqual(fs.readFileSync(parsed.backup, 'utf8'), before, 'backup must hold the ORIGINAL content, not the new one');

  const onDisk = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
  assert.deepStrictEqual(onDisk.literals, ['A Whole New Name']);
  server.close();
});

// -------------------------------------------------------------------- logs

test('GET /api/logs respects limit and never exceeds the max of 2000', async () => {
  const lines = [];
  for (let i = 0; i < 50; i++) {
    lines.push(`[00:00:${String(i % 60).padStart(2, '0')}] GET /v1/messages body=1KB walked=1KB memo=0/0`);
  }
  const { server, dashboard, port } = await startDash({ log: lines.join('\n') + '\n' });

  const small = await request(port, 'GET', '/_dash/api/logs?limit=10', { headers: { 'x-dash-token': dashboard.token } });
  const smallBody = JSON.parse(small.body);
  assert.strictEqual(smallBody.lines.length, 10);

  const huge = await request(port, 'GET', '/_dash/api/logs?limit=999999', { headers: { 'x-dash-token': dashboard.token } });
  const hugeBody = JSON.parse(huge.body);
  assert.ok(hugeBody.lines.length <= 2000, 'must clamp to the documented max even when asked for more');
  assert.ok(hugeBody.lines.length <= 50, 'must not fabricate lines beyond what is in the log');
  server.close();
});

test('GET /api/logs newest-first, and warn/error lines are classified separately from request lines', async () => {
  const log = [
    '[00:00:01] GET /v1/messages body=1KB walked=1KB memo=0/0',
    '[warn] pool: refreshing (startup)',
    '[warn] EGRESS NOT MASKING: tunnelling is ON but not masking',
    '[00:00:02] GET /v1/messages body=2KB walked=2KB memo=0/0',
  ].join('\n') + '\n';
  const { server, dashboard, port } = await startDash({ log });
  const r = await request(port, 'GET', '/_dash/api/logs?level=all', { headers: { 'x-dash-token': dashboard.token } });
  const body = JSON.parse(r.body);
  // Ordering asserted on identity, not on a substring's offset. The previous
  // form (indexOf(...) === 0) assumed parseLogLine strips the whole prefix
  // down to the payload; it strips only the timestamp, so the offset was 17
  // and the test failed while newest-first was working correctly.
  assert.strictEqual(body.lines.length, 4);
  assert.ok(body.lines[0].text.includes('body=2KB'), 'newest line must come first');
  assert.ok(body.lines[3].text.includes('body=1KB'), 'oldest line must come last');
  const levels = body.lines.map((l) => l.level);
  assert.ok(levels.includes('info'));
  assert.ok(levels.includes('warn'));
  assert.ok(levels.includes('error'), 'the NOT MASKING line must be promoted to error');
  server.close();
});

// ------------------------------------------------------------------- events

test('SSE endpoint sets the right headers and stops polling the snapshot after the client disconnects', async () => {
  let calls = 0;
  const { server, dashboard, port } = await startDash({
    intervalMs: 30,
    getSnapshot: () => {
      calls++;
      return defaultSnapshot();
    },
  });

  await new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: '/_dash/api/events', headers: { 'x-dash-token': dashboard.token } },
      (res) => {
        assert.strictEqual(res.statusCode, 200);
        assert.match(res.headers['content-type'], /text\/event-stream/);
        res.on('data', () => {});
        setTimeout(() => {
          req.destroy();
          resolve();
        }, 100);
      }
    );
    req.on('error', () => {}); // destroying the socket raises one; not the assertion under test
    req.end();
  });

  // Give the server a moment to notice the disconnect and clear its timer.
  await new Promise((r) => setTimeout(r, 150));
  const callsAtDisconnect = calls;
  await new Promise((r) => setTimeout(r, 300));
  assert.strictEqual(calls, callsAtDisconnect, 'the snapshot kept being polled after the client disconnected');
  server.close();
});

// ---------------------------------------------------------------- delegated

test('POST /api/egress/:action delegates to the injected handlers', async () => {
  let toggled = null;
  let checked = false;
  const { server, dashboard, port } = await startDash({
    egressActions: {
      toggle: (on) => { toggled = on; },
      check: (cb) => { checked = true; cb({ masked: true }); },
    },
  });
  const on = await request(port, 'POST', '/_dash/api/egress/on', { headers: { 'x-dash-token': dashboard.token } });
  assert.strictEqual(on.status, 200);
  assert.strictEqual(toggled, true);

  const check = await request(port, 'POST', '/_dash/api/egress/check', { headers: { 'x-dash-token': dashboard.token } });
  assert.strictEqual(check.status, 200);
  assert.strictEqual(checked, true);
  assert.deepStrictEqual(JSON.parse(check.body), { masked: true });
  server.close();
});

test('egress actions return 409 when egress is not configured', async () => {
  const { server, dashboard, port } = await startDash({});
  const r = await request(port, 'POST', '/_dash/api/egress/on', { headers: { 'x-dash-token': dashboard.token } });
  assert.strictEqual(r.status, 409);
  server.close();
});

test('POST /api/residue/scan and /api/verify delegate to injected implementations', async () => {
  const { server, dashboard, port } = await startDash({
    residueScan: (cb) => cb(null, { filesScanned: 3, filesWith: 1, totals: { email: 1 } }),
    verify: (cb) => cb(null, { checks: [{ name: 'x', ok: true, note: 'x' }], passed: 1, failed: 0 }),
  });
  const scan = await request(port, 'POST', '/_dash/api/residue/scan', { headers: { 'x-dash-token': dashboard.token } });
  assert.strictEqual(scan.status, 200);
  assert.deepStrictEqual(JSON.parse(scan.body), { filesScanned: 3, filesWith: 1, totals: { email: 1 } });

  const verify = await request(port, 'POST', '/_dash/api/verify', { headers: { 'x-dash-token': dashboard.token } });
  assert.strictEqual(verify.status, 200);
  const vBody = JSON.parse(verify.body);
  assert.strictEqual(vBody.passed, 1);
  assert.strictEqual(vBody.failed, 0);
  server.close();
});
