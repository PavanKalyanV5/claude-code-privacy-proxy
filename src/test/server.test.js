'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { compile } = require('../rules');
const { compileAliases } = require('../aliases');
const { makeContext } = require('../walk');
const { createServer } = require('../server');

function fakeUpstream(onReq) {
  const s = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => onReq(req, Buffer.concat(chunks), res));
  });
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r(s)));
}

function startProxy(upstreamPort) {
  const ctx = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: ['Jane Q. Testerson'], patterns: [] }),
    aliases: compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]),
  });
  const logger = { line: () => {}, warn: () => {} };
  const srv = createServer({
    ctx,
    aliases: ctx.aliases,
    logger,
    upstream: '127.0.0.1',
    upstreamPort,
    insecure: true,
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv)));
}

function post(port, path, body) {
  return new Promise((resolve) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json' } },
      (res) => {
        const c = [];
        res.on('data', (d) => c.push(d));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString() }));
      }
    );
    req.end(body);
  });
}

test('binds loopback only', async () => {
  const up = await fakeUpstream((r, b, res) => res.end('ok'));
  const proxy = await startProxy(up.address().port);
  assert.strictEqual(proxy.address().address, '127.0.0.1');
  proxy.close();
  up.close();
});

test('redacts the body before it reaches upstream', async () => {
  let seen = null;
  const up = await fakeUpstream((r, b, res) => {
    seen = b.toString();
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n');
  });
  const proxy = await startProxy(up.address().port);
  await post(
    proxy.address().port,
    '/v1/messages?beta=true',
    JSON.stringify({ messages: [{ role: 'user', content: 'hi Jane Q. Testerson at C:\\Users\\SOMEONE' }] })
  );
  assert.ok(!seen.includes('Jane Q. Testerson'), seen);
  assert.ok(!seen.includes('SOMEONE'), seen);
  assert.match(seen, /\[PII:personal:/);
  assert.ok(seen.includes('anon'));
  proxy.close();
  up.close();
});

test('non-/v1/messages paths pass through unmodified', async () => {
  let seen = null;
  const up = await fakeUpstream((r, b, res) => {
    seen = b.toString();
    res.end('ok');
  });
  const proxy = await startProxy(up.address().port);
  const raw = JSON.stringify({ note: 'Jane Q. Testerson' });
  await post(proxy.address().port, '/v1/other', raw);
  assert.strictEqual(seen, raw);
  proxy.close();
  up.close();
});

test('un-aliases tool_use input on the way back', async () => {
  const up = await fakeUpstream((r, b, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    const start = { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'Read', input: {} } };
    const delta = { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"file_path":"C:\\\\Users\\\\anon\\\\a.js"}' } };
    const stop = { type: 'content_block_stop', index: 0 };
    res.end(
      `event: content_block_start\ndata: ${JSON.stringify(start)}\n\n` +
        `event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n` +
        `event: content_block_stop\ndata: ${JSON.stringify(stop)}\n\n`
    );
  });
  const proxy = await startProxy(up.address().port);
  const r = await post(proxy.address().port, '/v1/messages', JSON.stringify({ messages: [] }));
  assert.ok(r.body.includes('SOMEONE'), r.body);
  proxy.close();
  up.close();
});

test('a malformed body is forwarded unmodified', async () => {
  let seen = null;
  const up = await fakeUpstream((r, b, res) => {
    seen = b.toString();
    res.end('ok');
  });
  const proxy = await startProxy(up.address().port);
  await post(proxy.address().port, '/v1/messages', '{not json');
  assert.strictEqual(seen, '{not json');
  proxy.close();
  up.close();
});

test('CRITICAL 5: a crash inside the redaction transform fails closed (502, nothing forwarded)', async () => {
  let upstreamCalled = false;
  const up = await fakeUpstream((r, b, res) => {
    upstreamCalled = true;
    res.end('ok');
  });
  const ctx = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    // Poisoned rules: exercising this throws from inside redactWithSpans,
    // simulating a redaction-engine crash without touching source.
    rules: { regexes: [{ re: null, labels: {} }] },
    aliases: [],
  });
  const warnings = [];
  const logger = { line: () => {}, warn: (m) => warnings.push(m) };
  const srv = createServer({
    ctx,
    aliases: ctx.aliases,
    logger,
    upstream: '127.0.0.1',
    upstreamPort: up.address().port,
    insecure: true,
  });
  const proxy = await new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv)));

  try {
    const r = await post(
      proxy.address().port,
      '/v1/messages',
      JSON.stringify({ messages: [{ role: 'user', content: 'hello there' }] })
    );

    assert.strictEqual(r.status, 502, r.body);
    assert.strictEqual(upstreamCalled, false, 'upstream must never see a request when the transform fails closed');
    assert.ok(warnings.length > 0, 'expected a warning to be logged');
  } finally {
    proxy.close();
    up.close();
  }
});

test('/_health answers without contacting upstream', async () => {
  const up = await fakeUpstream(() => assert.fail('should not be called'));
  const proxy = await startProxy(up.address().port);
  const r = await new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port: proxy.address().port, path: '/_health' }, (res) => {
      const c = [];
      res.on('data', (d) => c.push(d));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString() }));
    });
  });
  assert.strictEqual(r.status, 200);
  assert.match(r.body, /"ok":true/);
  proxy.close();
  up.close();
});

test('Bug 1: overlapping requests snapshot stats before shared ctx is reset', async () => {
  // Capture logger.line calls to verify stats are snapshot correctly
  const logLines = [];
  const up = await fakeUpstream((r, b, res) => {
    // Delay response to ensure the two client requests genuinely overlap
    setTimeout(() => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.end('event: message_stop\ndata: {"type":"message_stop"}\n\n');
    }, 50);
  });
  const ctx = makeContext({
    kLabel: Buffer.alloc(32, 3),
    kMemo: Buffer.alloc(32, 4),
    rules: compile({ literals: ['Jane Q. Testerson'], patterns: [] }),
    aliases: compileAliases([{ real: 'C:\\Users\\SOMEONE', alias: 'C:\\Users\\anon' }]),
  });
  const logger = {
    line: (entry) => logLines.push(entry),
    warn: () => {}
  };
  const srv = createServer({
    ctx,
    aliases: ctx.aliases,
    logger,
    upstream: '127.0.0.1',
    upstreamPort: up.address().port,
    insecure: true,
  });
  const proxy = await new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv)));

  // Fire two overlapping POST requests
  const req1 = post(proxy.address().port, '/v1/messages', JSON.stringify({ messages: [{ role: 'user', content: 'Jane Q. Testerson' }] }));
  const req2 = post(proxy.address().port, '/v1/messages', JSON.stringify({ messages: [{ role: 'user', content: 'no pii here' }] }));

  await Promise.all([req1, req2]);

  // Wait a bit for logger calls to be processed
  await new Promise(r => setTimeout(r, 100));

  assert.strictEqual(logLines.length, 2, `Expected 2 log lines, got ${logLines.length}`);

  // Find which log line corresponds to which request
  // The first request had PII so should have non-zero counts
  // The second request had no PII so should have zero counts
  const linesWithCounts = logLines.filter(l => l.stats && l.stats.counts && Object.keys(l.stats.counts).length > 0);
  const linesWithoutCounts = logLines.filter(l => l.stats && l.stats.counts && Object.keys(l.stats.counts).length === 0);

  // At least one line should have non-empty counts (from the PII request)
  assert.ok(linesWithCounts.length > 0, `No log line with non-empty counts found. Lines: ${JSON.stringify(logLines.map(l => l.stats))}`);
  // At least one line should have zero counts (from the no-PII request)
  assert.ok(linesWithoutCounts.length > 0, `No log line with zero counts found. Lines: ${JSON.stringify(logLines.map(l => l.stats))}`);

  proxy.close();
  up.close();
});

test('Bug 2: accept-encoding header is removed before upstream request', async () => {
  // Capture the headers received by upstream
  let upstreamHeaders = null;
  const up = await fakeUpstream((r, b, res) => {
    upstreamHeaders = r.headers;
    res.end('ok');
  });
  const proxy = await startProxy(up.address().port);

  // Send request with accept-encoding header
  await new Promise((resolve) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: proxy.address().port,
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'accept-encoding': 'gzip, br'
        }
      },
      (res) => {
        const c = [];
        res.on('data', (d) => c.push(d));
        res.on('end', () => resolve());
      }
    );
    req.end(JSON.stringify({ messages: [] }));
  });

  // Verify accept-encoding was not sent to upstream
  assert.ok(upstreamHeaders, 'No headers captured from upstream');
  assert.strictEqual(upstreamHeaders['accept-encoding'], undefined,
    `accept-encoding should not be sent to upstream, but got: ${upstreamHeaders['accept-encoding']}`);

  proxy.close();
  up.close();
});
