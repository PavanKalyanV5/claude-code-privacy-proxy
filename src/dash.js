'use strict';

// Local audit dashboard, served by the EXISTING proxy process under /_dash.
// No new port, no new process: server.js hands matching requests to
// `handle()` below and falls through to its own routes for everything else.
//
// WHY THIS EXISTS: the proxy has no other real window into itself. statusLine
// does not exist in the Claude Code VS Code extension, so the continuous
// indicator is inert there, and the audit log is a text file nobody reads
// live. This is the only place the user can actually see whether their rules
// are sane, whether masking is working, and what the proxy has done.
//
// AUTH: loopback + a random per-process token (crypto.randomBytes(16)).
// Every /_dash* request must present it, as `?t=` or `X-Dash-Token`, compared
// with crypto.timingSafeEqual on equal-length buffers. Anything else is a
// bare 403 with no detail -- this dashboard does not just report state like
// /_health, it EDITS the user's real PII rules, so any other local process
// running as the user must not be able to read or touch it for free.
//
// The token is generated here and handed back to the caller (start.js) so it
// can be logged once. It must never reach status.json (any other local
// process can read that) or any JSON response body this module produces --
// see the tests for both.

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { compile, isPatternSafe, RULES_PATH: DEFAULT_RULES_PATH } = require('./rules');
const { aliasRisk } = require('./aliases');
const residueLog = require('./residue-log');
const retention = require('./retention');
const insights = require('./insights');

const DASH_DIR = path.join(__dirname, 'dash');
const DEFAULT_LOG_PATH = path.join(os.homedir(), '.claude', 'redaction', 'redact-proxy.log');

// Messages promoted from "warn" to "error" for log-viewer colouring. Same
// substrings start.js already treats as critical when it feeds the status
// line, kept in sync deliberately rather than invented separately.
const ERROR_RE = /REFUSED|NOT MASK|EXPOSED|DIRECT CONNECTION|UNHEALTHY/;

const PREFIX = '/_dash';
const EGRESS_PREFIX = '/_dash/api/egress/';

// ------------------------------------------------------------- log tailing

// Reads only the tail of the log file: seeks backward from the end in
// bounded chunks until at least `maxLines` newlines have been seen (or the
// start of the file is reached), rather than loading the whole file. A log
// that has been running for months must not become a multi-hundred-MB read
// on every dashboard refresh.
function tailLines(logPath, maxLines) {
  let fd;
  try {
    fd = fs.openSync(logPath, 'r');
  } catch (e) {
    return [];
  }
  try {
    const stat = fs.fstatSync(fd);
    const CHUNK = 65536;
    let position = stat.size;
    let data = '';
    while (position > 0) {
      const size = Math.min(CHUNK, position);
      position -= size;
      const buf = Buffer.alloc(size);
      fs.readSync(fd, buf, 0, size, position);
      data = buf.toString('utf8') + data;
      let newlineCount = 0;
      for (let i = 0; i < data.length; i++) {
        if (data.charCodeAt(i) === 10) newlineCount++;
      }
      if (newlineCount > maxLines) break;
    }
    const lines = data.split('\n');
    if (lines.length && lines[lines.length - 1] === '') lines.pop();
    return lines.slice(-maxLines);
  } finally {
    fs.closeSync(fd);
  }
}

// Parses one audit-log line into { ts, level, text }. String-sliced rather
// than a regex with escape sequences: formatLine's shape ("[HH:MM:SS] rest")
// and the warn shape ("[warn] rest") are both fixed and cheap to check
// positionally, and this file has a documented history of regex escapes
// silently misbehaving on this machine.
// Any dashboard token appearing in a log line is masked before the line is
// served. Defence in depth, for two reasons: logs written by older versions
// still contain a full `?t=<32 hex>` URL, and the log viewer is the one place
// in this project that renders arbitrary historical file content back to a
// browser. A secret that guards PII-rule writes should not be recoverable by
// scrolling the log tab, or by anything that captures the page.
function redactTokens(text) {
  return text.replace(/([?&]t=)[0-9a-f]{16,}/gi, '$1[redacted]');
}

function parseLogLine(raw) {
  if (raw.indexOf('[warn] ') === 0) {
    const text = raw.slice(7);
    return { ts: null, level: ERROR_RE.test(text) ? 'error' : 'warn', text: redactTokens(text) };
  }
  if (raw.length > 10 && raw[0] === '[' && raw[9] === ']' && raw[10] === ' ' && raw[3] === ':' && raw[6] === ':') {
    return { ts: raw.slice(1, 9), level: 'info', text: redactTokens(raw.slice(11)) };
  }
  return { ts: null, level: 'info', text: redactTokens(raw) };
}

// ------------------------------------------------------------ config masks

// The parsed rules file, with every literal PII value replaced by a fixed
// placeholder plus its length. This is the DEFAULT config route precisely
// because it is safe for anything that can reach loopback with the token to
// call without also handing over the user's real name, email, phone and
// paths -- /_dash/api/config/raw exists separately, and only it carries the
// real values, so an accidental default never leaks them.
function maskLiteral(entry) {
  if (typeof entry === 'string') return { value: '***', length: entry.length };
  if (entry && typeof entry === 'object') {
    const out = Object.assign({}, entry);
    if (typeof out.value === 'string') {
      out.length = out.value.length;
      out.value = '***';
    }
    return out;
  }
  return entry;
}

function maskAlias(entry) {
  if (!entry || typeof entry !== 'object') return entry;
  const out = Object.assign({}, entry);
  if (typeof out.real === 'string') {
    out.realLength = out.real.length;
    out.real = '***';
  }
  return out;
}

function maskConfig(rules) {
  const clone = JSON.parse(JSON.stringify(rules || {}));
  if (Array.isArray(clone.literals)) clone.literals = clone.literals.map(maskLiteral);
  if (Array.isArray(clone.aliases)) clone.aliases = clone.aliases.map(maskAlias);
  return clone;
}

// -------------------------------------------------------------- validation

// Everything a save must pass before a single byte is written. Every one of
// these checks exists because skipping it once already cost something real:
// a quadratic pattern hung the proxy for 42 seconds (isPatternSafe), and a
// common-word alias silently rewrote source files across the repo
// (aliasRisk). A dashboard that lets a user save past either of those
// reintroduces exactly the incidents rules.js and aliases.js exist to
// prevent, just from a browser instead of a hand-edited file.
function validateConfig(rules) {
  const errors = [];
  const warnings = [];

  if (!rules || typeof rules !== 'object' || Array.isArray(rules)) {
    return { errors: ['config must be a JSON object'], warnings };
  }

  try {
    compile(rules, (m) => warnings.push(m));
  } catch (e) {
    errors.push(`rules failed to compile: ${e.message}`);
  }

  for (const p of rules.patterns || []) {
    if (!p || typeof p.regex !== 'string') continue;
    const verdict = isPatternSafe(p.regex, p.flags || 'g');
    if (!verdict.ok) errors.push(`pattern "${p.name || '?'}": ${verdict.why}`);
  }

  for (const a of rules.aliases || []) {
    if (!a || typeof a !== 'object') continue;
    const risk = aliasRisk(a.alias);
    if (risk) errors.push(`alias "${String(a.alias)}": ${risk}`);
    if (typeof a.real === 'string' && typeof a.alias === 'string' && a.real === a.alias) {
      errors.push(`alias real and alias must not be identical (got "${a.real}")`);
    }
  }

  const egress = rules.egress || {};
  if (egress.mode === 'auto' && !egress.homeCountry) {
    errors.push('egress.mode is "auto" but egress.homeCountry is not set');
  }
  if (egress.onFailure !== undefined && !['refuse', 'direct'].includes(egress.onFailure)) {
    errors.push(`egress.onFailure must be "refuse" or "direct", got ${JSON.stringify(egress.onFailure)}`);
  }

  return { errors, warnings };
}

// ----------------------------------------------------------- self-checks

// Default residue-scan and verify implementations shell out to the existing,
// already-tested CLI scripts rather than re-implementing their logic, so the
// dashboard can never drift from what `npm run scan` / `npm run verify`
// actually do. Run with execFile (async), never execFileSync: a full residue
// scan walks thousands of files, and blocking the proxy's event loop while it
// runs would turn a visibility feature into an outage -- the exact reasoning
// start.js already applies to the scheduled scrub.
function defaultResidueScan(rulesPath) {
  return function residueScan(cb) {
    const script = path.join(__dirname, 'scan-residue.js');
    execFile(
      process.execPath,
      [script, '--json'],
      { env: Object.assign({}, process.env, { CCR_RULES_PATH: rulesPath }), timeout: 60000, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout) => {
        if (err && !stdout) return cb(err);
        try {
          const parsed = JSON.parse(stdout);
          cb(null, { filesScanned: parsed.filesScanned, filesWith: parsed.filesWith, totals: parsed.totals || {} });
        } catch (e) {
          cb(e);
        }
      }
    );
  };
}

function defaultVerify(rulesPath) {
  return function verify(cb) {
    const script = path.join(__dirname, 'verify-protection.js');
    execFile(
      process.execPath,
      [script],
      { env: Object.assign({}, process.env, { CCR_RULES_PATH: rulesPath }), timeout: 30000, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const out = (stdout || '') + (stderr || '');
        const checks = [];
        const lines = out.split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          let ok = null;
          let note = null;
          if (trimmed.indexOf('ok ') === 0) {
            ok = true;
            note = trimmed.slice(3).trim();
          } else if (trimmed.indexOf('FAIL ') === 0) {
            ok = false;
            note = trimmed.slice(5).trim();
          }
          if (note) checks.push({ name: note, ok, note });
        }
        const passed = checks.filter((c) => c.ok).length;
        const failed = checks.length - passed;
        cb(null, { checks, passed, failed });
      }
    );
  };
}

// ------------------------------------------------------------------- core

function createDashboard(opts = {}) {
  const rulesPath = opts.rulesPath || process.env.CCR_RULES_PATH || DEFAULT_RULES_PATH;
  const logPath = opts.logPath || process.env.CCR_LOG_PATH || DEFAULT_LOG_PATH;
  const dashDir = opts.dashDir || DASH_DIR;
  const getSnapshot = opts.getSnapshot || (() => ({ proxy: {}, redaction: {}, egress: {}, residue: null }));
  const egressActions = opts.egressActions || {};
  const residueScan = opts.residueScan || defaultResidueScan(rulesPath);
  const verify = opts.verify || defaultVerify(rulesPath);
  const intervalMs = opts.intervalMs || 3000;

  const token = crypto.randomBytes(16).toString('hex');
  const tokenBuf = Buffer.from(token, 'utf8');

  function authOk(req, urlObj) {
    let supplied = req.headers['x-dash-token'];
    if (typeof supplied !== 'string') supplied = urlObj.searchParams.get('t');
    if (typeof supplied !== 'string' || supplied.length === 0) return false;
    const suppliedBuf = Buffer.from(supplied, 'utf8');
    // Equal-length check FIRST: timingSafeEqual throws on a length mismatch
    // rather than returning false, and constructing equal-length buffers
    // before comparing is what keeps this constant-time for the case that
    // actually matters (a near-miss guess), not just the trivial one.
    if (suppliedBuf.length !== tokenBuf.length) return false;
    return crypto.timingSafeEqual(suppliedBuf, tokenBuf);
  }

  function deny(res) {
    // No detail on why: this is the one response that must never help an
    // unauthenticated caller narrow down what went wrong.
    res.writeHead(403, { 'content-type': 'text/plain' });
    res.end('forbidden\n');
  }

  function sendJson(res, code, obj) {
    res.writeHead(code, { 'content-type': 'application/json' });
    res.end(JSON.stringify(obj));
  }

  function readBody(req, res, onOk) {
    const chunks = [];
    let size = 0;
    let tooBig = false;
    req.on('data', (c) => {
      if (tooBig) return;
      size += c.length;
      if (size > 5 * 1024 * 1024) {
        tooBig = true;
        sendJson(res, 413, { errors: ['request body too large'] });
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) return;
      onOk(Buffer.concat(chunks));
    });
  }

  function serveFile(res, name, contentType) {
    let data;
    try {
      data = fs.readFileSync(path.join(dashDir, name));
    } catch (e) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found\n');
      return;
    }
    res.writeHead(200, { 'content-type': contentType, 'cache-control': 'no-store' });
    res.end(data);
  }

  function serveIndex(res) {
    let html;
    try {
      html = fs.readFileSync(path.join(dashDir, 'index.html'), 'utf8');
    } catch (e) {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end('dashboard assets missing\n');
      return;
    }
    // The one deliberate templating step: the page needs the token to build
    // authenticated links to its own CSS/JS/API/SSE, none of which the
    // browser will otherwise attach it to on its own. split/join, not a
    // regex replace -- the token is opaque hex and this is a plain literal
    // substitution, not a pattern match.
    html = html.split('__DASH_TOKEN__').join(token);
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    res.end(html);
  }

  function loadRulesFile() {
    return JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
  }

  function handleConfigGet(res, masked) {
    let rules;
    try {
      rules = loadRulesFile();
    } catch (e) {
      sendJson(res, 500, { error: 'failed to read the rules file' });
      return;
    }
    sendJson(res, 200, masked ? maskConfig(rules) : rules);
  }

  function handleConfigPost(req, res) {
    readBody(req, res, (buf) => {
      let parsed;
      try {
        parsed = JSON.parse(buf.toString('utf8'));
      } catch (e) {
        sendJson(res, 400, { errors: [`request body is not valid JSON: ${e.message}`] });
        return;
      }

      const { errors, warnings } = validateConfig(parsed);
      if (errors.length) {
        // Nothing is read or written past this point: a rejected save must
        // leave the live rules file byte-for-byte untouched.
        sendJson(res, 400, { errors });
        return;
      }

      let original = null;
      try {
        original = fs.readFileSync(rulesPath);
      } catch (e) {
        // No existing file to back up; proceed to write the first one.
      }

      const backupPath = path.join(path.dirname(rulesPath), `redact-rules.backup-dash-${Date.now()}.json`);
      if (original !== null) {
        try {
          fs.writeFileSync(backupPath, original);
        } catch (e) {
          sendJson(res, 500, { errors: [`could not create backup, nothing written: ${e.message}`] });
          return;
        }
      }

      const serialized = JSON.stringify(parsed, null, 2);
      try {
        fs.writeFileSync(rulesPath, serialized);
      } catch (e) {
        sendJson(res, 500, { errors: [`write failed: ${e.message}`] });
        return;
      }

      // Re-read and re-parse what actually landed on disk. A write can be
      // silently truncated by the filesystem; trusting the buffer we just
      // wrote rather than what is actually there is how a corrupt config
      // would go unnoticed until the next restart.
      try {
        JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      } catch (e) {
        if (original !== null) {
          try {
            fs.writeFileSync(rulesPath, original);
          } catch (e2) {
            // Nothing more can be done from here; the 500 below still fires.
          }
        }
        sendJson(res, 500, { errors: ['the written file did not parse back; restored the previous version'] });
        return;
      }

      sendJson(res, 200, { ok: true, warnings, backup: backupPath });
    });
  }

  function handleLogs(res, urlObj) {
    const limitParam = Number(urlObj.searchParams.get('limit'));
    let limit = Number.isFinite(limitParam) && limitParam > 0 ? Math.floor(limitParam) : 200;
    if (limit > 2000) limit = 2000;
    const level = urlObj.searchParams.get('level') === 'warn' ? 'warn' : 'all';
    const q = (urlObj.searchParams.get('q') || '').toLowerCase();

    const windowSize = Math.min(Math.max(limit * 5, 2000), 20000);
    const raw = tailLines(logPath, windowSize);

    const parsed = [];
    for (const line of raw) {
      if (line === '') continue;
      parsed.push(parseLogLine(line));
    }
    parsed.reverse(); // newest first

    const filtered = parsed.filter((l) => {
      if (level === 'warn' && l.level === 'info') return false;
      if (q && l.text.toLowerCase().indexOf(q) === -1) return false;
      return true;
    });

    sendJson(res, 200, { lines: filtered.slice(0, limit), total: filtered.length });
  }

  function handleEvents(req, res) {
    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-store',
      connection: 'keep-alive',
    });
    let closed = false;
    const send = () => {
      if (closed) return;
      try {
        res.write(`data: ${JSON.stringify(getSnapshot())}\n\n`);
      } catch (e) {
        // A write to an already-closing socket must not crash the proxy.
      }
    };
    send();
    const timer = setInterval(send, intervalMs);
    // unref so a live SSE stream can never be the only thing keeping the
    // process alive. The proxy's own listening socket holds it open, and this
    // timer holding it open independently is how a dashboard tab turns into a
    // process that refuses to exit. Matches the treatment of every other
    // interval in start.js.
    if (timer.unref) timer.unref();
    const stop = () => {
      if (closed) return;
      closed = true;
      clearInterval(timer);
    };
    req.on('close', stop);
    res.on('close', stop);
  }

  function handleEgressAction(res, action) {
    if (action === 'on' || action === 'off') {
      if (typeof egressActions.toggle !== 'function') {
        sendJson(res, 409, { error: 'egress is not configured' });
        return;
      }
      egressActions.toggle(action === 'on');
      sendJson(res, 200, { ok: true, tunnel: action === 'on' });
      return;
    }
    if (action === 'check') {
      if (typeof egressActions.check !== 'function') {
        sendJson(res, 409, { error: 'egress is not configured' });
        return;
      }
      egressActions.check((result) => sendJson(res, 200, result));
      return;
    }
    sendJson(res, 404, { error: 'unknown egress action' });
  }

  function handleResidueScan(res) {
    residueScan((err, result) => {
      if (err) {
        sendJson(res, 500, { error: 'residue scan failed' });
        return;
      }
      sendJson(res, 200, result);
    });
  }

  function handleVerify(res) {
    verify((err, result) => {
      if (err) {
        sendJson(res, 500, { error: 'verification failed to run' });
        return;
      }
      sendJson(res, 200, result);
    });
  }

  // Returns true if this request belonged to the dashboard (handled or
  // refused), false if the caller should fall through to its own routing.
  function handle(req, res) {
    const urlObj = new URL(req.url, 'http://127.0.0.1');
    const pathname = urlObj.pathname;
    if (pathname !== PREFIX && pathname.indexOf(PREFIX + '/') !== 0) return false;

    if (!authOk(req, urlObj)) {
      deny(res);
      return true;
    }

    if (pathname === PREFIX && req.method === 'GET') {
      serveIndex(res);
      return true;
    }
    if (pathname === PREFIX + '/app.css' && req.method === 'GET') {
      serveFile(res, 'app.css', 'text/css; charset=utf-8');
      return true;
    }
    if (pathname === PREFIX + '/app.js' && req.method === 'GET') {
      serveFile(res, 'app.js', 'application/javascript; charset=utf-8');
      return true;
    }
    if (pathname === PREFIX + '/api/status' && req.method === 'GET') {
      sendJson(res, 200, getSnapshot());
      return true;
    }
    if (pathname === PREFIX + '/api/events' && req.method === 'GET') {
      handleEvents(req, res);
      return true;
    }
    if (pathname === PREFIX + '/api/logs' && req.method === 'GET') {
      handleLogs(res, urlObj);
      return true;
    }
    if (pathname === PREFIX + '/api/config' && req.method === 'GET') {
      handleConfigGet(res, true);
      return true;
    }
    if (pathname === PREFIX + '/api/config/raw' && req.method === 'GET') {
      handleConfigGet(res, false);
      return true;
    }
    if (pathname === PREFIX + '/api/config' && req.method === 'POST') {
      handleConfigPost(req, res);
      return true;
    }
    if (pathname.indexOf(EGRESS_PREFIX) === 0 && req.method === 'POST') {
      handleEgressAction(res, pathname.slice(EGRESS_PREFIX.length));
      return true;
    }
    if (pathname === PREFIX + '/api/residue/scan' && req.method === 'POST') {
      handleResidueScan(res);
      return true;
    }
    // The scrub job's own audit trail: which passes ran, what each one did,
    // and the captured output of any single pass. Without this the one
    // background job that MODIFIES the user's files was unauditable.
    if (pathname === PREFIX + '/api/residue/jobs' && req.method === 'GET') {
      const limit = Math.min(Number(urlObj.searchParams.get('limit')) || 50, 200);
      sendJson(res, 200, { jobs: residueLog.read(limit), summary: residueLog.summary() });
      return true;
    }
    // The per-run manifest: which files a pass rewrote and what category of
    // value came out of each. Counts only -- the values themselves live in
    // the optional raw log, which is owner-only on disk and deliberately not
    // served over HTTP.
    if (pathname === PREFIX + '/api/residue/manifest' && req.method === 'GET') {
      const id = String(urlObj.searchParams.get('id') || '').replace(/[^0-9a-zA-Z_.-]/g, '');
      const p = path.join(os.homedir(), '.claude', 'redaction', 'residue-runs', id + '.manifest.json');
      try {
        sendJson(res, 200, JSON.parse(fs.readFileSync(p, 'utf8')));
      } catch (e) {
        sendJson(res, 404, { error: 'no manifest for that run' });
      }
      return true;
    }
    if (pathname === PREFIX + '/api/residue/job' && req.method === 'GET') {
      const id = urlObj.searchParams.get('id') || '';
      const body = residueLog.readDetail(id);
      if (body === null) {
        sendJson(res, 404, { error: 'no captured log for that run' });
        return true;
      }
      sendJson(res, 200, { id, log: body });
      return true;
    }
    // Signals: the audit trails turned into things worth acting on. A job
    // history is a list of rows; this is what those rows mean.
    if (pathname === PREFIX + '/api/insights' && req.method === 'GET') {
      let rules = {};
      try {
        rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      } catch (e) {
        /* defaults */
      }
      const pol = retention.policy(rules);
      sendJson(res, 200, {
        signals: insights.analyse({
          jobs: residueLog.read(50),
          retention: retention.history(50),
          intervalMinutes: (rules.residue && rules.residue.intervalMinutes) || 60,
          retentionEnabled: pol.enabled !== false,
        }),
      });
      return true;
    }
    if (pathname === PREFIX + '/api/retention/history' && req.method === 'GET') {
      const limit = Math.min(Number(urlObj.searchParams.get('limit')) || 50, 200);
      sendJson(res, 200, { runs: retention.history(limit) });
      return true;
    }
    if (pathname === PREFIX + '/api/retention' && req.method === 'GET') {
      let rules = {};
      try {
        rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      } catch (e) {
        /* describe() falls back to defaults */
      }
      sendJson(res, 200, retention.describe(rules));
      return true;
    }
    if (pathname === PREFIX + '/api/retention/run' && req.method === 'POST') {
      let rules = {};
      try {
        rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      } catch (e) {
        /* defaults */
      }
      try {
        sendJson(res, 200, retention.enforce(rules, undefined, { trigger: 'manual' }));
      } catch (e) {
        sendJson(res, 500, { error: 'retention pass failed: ' + e.message });
      }
      return true;
    }
    if (pathname === PREFIX + '/api/verify' && req.method === 'POST') {
      handleVerify(res);
      return true;
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found\n');
    return true;
  }

  return { handle, token, rulesPath, logPath };
}

module.exports = { createDashboard, maskConfig, validateConfig, tailLines, parseLogLine };
