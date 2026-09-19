'use strict';

// The proxy. Binds loopback, forwards everything, transforms only
// POST /v1/messages*.
//
// Loopback binding is a hard requirement, not a default: this accepts
// unauthenticated plaintext HTTP and forwards it with the user's credentials
// attached, so exposing it on another interface would hand anyone on the
// network an authenticated channel to the API.

const http = require('http');
const https = require('https');
const { transformBody, resetStats } = require('./walk');
const { createSseTransformer } = require('./sse');
const { applyHeaderPolicy } = require('./headers');

const MESSAGES_PATH = /^\/v1\/messages/;

function createServer({
  ctx,
  aliases,
  logger,
  resolver = null,
  remoteTools = [],
  upstream = 'api.anthropic.com',
  upstreamPort = 443,
  insecure = false,
  egressAgent = null,
  egressHealth = null,
  headerPolicy = null,
  egressToggle = null,
  egressCheck = null,
  // The audit dashboard (src/dash.js). Optional: when absent, /_dash simply
  // falls through to the 404 this server already gives any unknown path.
  // Checked FIRST and dispatched by prefix, same as the /_health and
  // /_egress/* routes below it, but factored into its own module because it
  // is a whole second surface (auth, static files, a config editor) rather
  // than a couple of one-line handlers.
  dash = null,
  // Only used to print a copy-pasteable toggle command in the 502 body.
  port = 47113,
}) {
  const agent = insecure ? http : https;

  return http.createServer((req, res) => {
    if (dash && dash.handle(req, res)) return;

    // Browser noise, answered locally.
    //
    // The dashboard is served by THIS port, so a browser pointed at it also
    // asks for /favicon.ico and /.well-known/appspecific/*. Those matched no
    // local route and were forwarded upstream -- measured at 362ms against
    // 1.5ms for /_health, i.e. a full round trip to api.anthropic.com, with
    // the user's API credentials attached, for a file the browser invented.
    //
    // A denylist rather than an API allowlist on purpose: an allowlist would
    // silently break the first new endpoint Anthropic ships, and breaking
    // real API calls is far worse than forwarding a favicon.
    if (/^\/(favicon\.ico|robots\.txt|apple-touch-icon[\w-]*\.png|sitemap\.xml)$/.test(req.url) ||
        req.url.indexOf('/.well-known/') === 0) {
      res.writeHead(404, { 'content-type': 'text/plain', 'cache-control': 'max-age=86400' });
      res.end('not found\n');
      return;
    }

    if (req.url === '/_health') {
      const payload = JSON.stringify({
        ok: true,
        pid: process.pid,
        memo: ctx.memo.size,
        // What the notifier reads. Reported even when egress is off, so the
        // difference between "not configured" and "configured but broken" is
        // visible rather than inferred from silence.
        // patternCount, not regexes.length: patterns are bucketed by flags
        // and combined, so regexes.length is 16 for 27 patterns plus 14
        // literals. This endpoint feeds the dashboard, the lifecycle hook and
        // `doctor`, so the wrong number here was the wrong number everywhere.
        redaction: { literals: ctx.rules.literalCount, patterns: ctx.rules.patternCount, aliases: ctx.aliases.length },
        egress: egressHealth
          ? egressHealth.snapshot()
          : { configured: [], active: null, ok: null, masking: null, note: 'egress not configured' },
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(payload);
      return;
    }

    // Runtime egress toggle. The SessionStart hook cannot fire mid-session, so
    // when the tunnel dies at 3pm what you actually see is a connection error.
    // This is how you act on it without editing config and restarting.
    // Loopback-only, like everything else here. Turning the tunnel OFF is a
    // weakening of protection, so it is logged loudly rather than quietly
    // accepted.
    // On-demand live verification. Runs a FRESH probe rather than reporting a
    // cached field, because the whole point is to answer "is it masked right
    // now" without trusting anything already stored -- a stale cached verdict
    // is exactly how a VPN drop went unnoticed for seven minutes once.
    if (req.url === "/_egress/check") {
      if (!egressCheck) {
        res.writeHead(409, { "content-type": "application/json" });
        res.end(JSON.stringify({ masked: null, reason: "egress is not configured" }, null, 2));
        return;
      }
      egressCheck((result) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(result, null, 2));
      });
      return;
    }

    if (req.url === '/_egress/on' || req.url === '/_egress/off') {
      const on = req.url.endsWith('/on');
      if (!egressToggle) {
        res.writeHead(409, { 'content-type': 'text/plain' });
        res.end('no egress configured; nothing to toggle\n');
        return;
      }
      egressToggle(on);
      logger.warn(
        on
          ? 'egress tunnel switched ON at runtime'
          : 'egress tunnel switched OFF at runtime: requests now go out from your real IP until switched back on'
      );
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`egress tunnel ${on ? 'ON' : 'OFF'}\n`);
      return;
    }

    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = Buffer.concat(chunks);
      const isMessages = req.method === 'POST' && MESSAGES_PATH.test(req.url);
      resetStats(ctx);

      if (isMessages && body.length) {
        let parsed;
        let parseOk = true;
        try {
          parsed = JSON.parse(body.toString('utf8'));
        } catch (e) {
          // Fail open: a parse failure must never break the session -- there
          // is nothing to redact if it isn't JSON, so the original body (which
          // was never valid Messages input to begin with) goes through as-is.
          parseOk = false;
          logger.warn(`body not transformed (${e.message}); forwarded unmodified`);
        }

        if (parseOk) {
          // Fail CLOSED: unlike a parse failure, a transform failure means we
          // found redactable content and then crashed before redacting it.
          // Forwarding the original body here would silently leak whatever
          // the transform choked on. Never forward it -- refuse the request
          // instead and let the caller retry.
          try {
            body = Buffer.from(JSON.stringify(transformBody(parsed, ctx)), 'utf8');
          } catch (e) {
            logger.warn(`transform failed (${e.message}); request refused, nothing forwarded`);
            res.writeHead(502, { 'content-type': 'text/plain' });
            res.end('redaction proxy: transform failed, request refused');
            return;
          }
        }
      }

      // Snapshot now: ctx.stats is shared, and the audit line is written
      // asynchronously when the response ends -- by which time an overlapping
      // request will have called resetStats() and wiped these counts.
      const stats = { ...ctx.stats, counts: { ...ctx.stats.counts }, headers: {} };

      // Headers are a separate channel from the body: locale, OS, arch and
      // any address-bearing header would otherwise reach upstream verbatim.
      const headers = Object.assign(
        {},
        applyHeaderPolicy(req.headers, headerPolicy, stats.headers),
        { host: upstream }
      );
      delete headers['content-length'];
      // The SSE transformer rewrites the body as utf8 text, so a compressed
      // response would be corrupted. Ask upstream for identity encoding.
      delete headers['accept-encoding'];
      if (body.length) headers['content-length'] = String(body.length);

      const sseStats = { resolvedAliases: 0 };
      const upstreamReq = agent.request(
        { hostname: upstream, port: upstreamPort, path: req.url, method: req.method, headers },
        (ur) => {
          const streaming = (ur.headers['content-type'] || '').includes('text/event-stream');
          res.writeHead(ur.statusCode, ur.headers);

          if (!streaming || !isMessages) {
            ur.pipe(res);
            ur.on('end', () =>
              logger.line({ method: req.method, url: req.url, bytes: body.length, stats, resolvedAliases: 0 })
            );
            return;
          }

          const t = createSseTransformer({ aliases, stats: sseStats, resolver, remoteTools });
          ur.setEncoding('utf8');
          ur.on('data', (chunk) => {
            const outChunk = t.push(chunk);
            if (outChunk) res.write(outChunk);
          });
          ur.on('end', () => {
            const tail = t.flush();
            if (tail) res.write(tail);
            res.end();
            logger.line({
              method: req.method,
              url: req.url,
              bytes: body.length,
              stats,
              resolvedAliases: sseStats.resolvedAliases,
            });
          });
        }
      );

      upstreamReq.on('error', (e) => {
        logger.warn(`upstream error: ${e.message}`);
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
        // An egress failure surfaces here as a connection error. This body is
        // the only mid-session channel that reaches the user, so it says what
        // happened and how to act on it rather than just "upstream error".
        const egressFailure = /egress proxy|no egress/i.test(e.message);
        res.end(
          egressFailure
            ? 'redaction proxy: the egress tunnel could not be established, so this request was REFUSED ' +
                'rather than sent from your real IP.\n\n' +
                `To continue unmasked for now:  curl -X POST http://127.0.0.1:${port}/_egress/off\n` +
                `To retry with the tunnel:      curl -X POST http://127.0.0.1:${port}/_egress/on\n\n` +
                `Cause: ${e.message}\n`
            : 'redaction proxy: upstream error'
        );
      });

      if (body.length) upstreamReq.write(body);
      upstreamReq.end();
    });
  });
}

module.exports = { createServer, MESSAGES_PATH };
