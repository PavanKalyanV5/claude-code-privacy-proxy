#!/usr/bin/env node
'use strict';

// Prints the dashboard URL, token included, for pasting into a browser.
//
// This exists so the token does not have to live anywhere convenient. It used
// to be written into the audit log, which turned out to be a strictly weaker
// location than the status file that was deliberately avoided: the log
// carries inherited ACLs (owner + SYSTEM + Administrators), while the token
// file this reads has inheritance stripped and is owner-only, exactly like
// the master key. The log also persists forever, and the dashboard's own log
// viewer renders it back to a browser.
//
// The token is per-process: it is regenerated every time the proxy starts, so
// a stale value here means the proxy has restarted, not that anything is
// wrong.
//
//   npm run dash

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { load } = require('../rules');

const STATE_DIR = path.join(process.env.HOME || os.homedir(), '.claude', 'redaction');
const TOKEN_PATH = path.join(STATE_DIR, 'dash-token');

let port = 47113;
try {
  const rules = load();
  port = (rules.proxy && rules.proxy.port) || port;
} catch (e) {
  // A broken rules file is the proxy's problem to report, not this one's.
}

let token = null;
try {
  token = fs.readFileSync(TOKEN_PATH, 'utf8').trim();
} catch (e) {
  token = null;
}

if (!token) {
  console.error('No dashboard token found at ' + TOKEN_PATH);
  console.error('');
  console.error('The token is created when the proxy starts. Either it is not running,');
  console.error('or it is an older build that logged the token instead of storing it.');
  console.error('Start it with:  node src/lifecycle.js ensure');
  process.exit(1);
}

const url = 'http://127.0.0.1:' + port + '/_dash?t=' + token;

// Confirm the proxy is actually up before handing over a URL, so a dead port
// is reported as a dead port rather than as a browser error the user has to
// interpret.
const req = http.get({ host: '127.0.0.1', port, path: '/_health', timeout: 2000 }, (res) => {
  res.resume();
  const ok = res.statusCode === 200;
  console.log(url);
  if (!ok) console.error('\n(warning: /_health returned ' + res.statusCode + '; the dashboard may not respond)');
});
req.on('timeout', () => {
  req.destroy();
  console.log(url);
  console.error('\n(warning: the proxy did not answer on port ' + port + '; start it with `node src/lifecycle.js ensure`)');
});
req.on('error', (e) => {
  console.log(url);
  console.error('\n(warning: nothing is listening on port ' + port + ' -- ' + e.code + '. Start it with `node src/lifecycle.js ensure`)');
});
