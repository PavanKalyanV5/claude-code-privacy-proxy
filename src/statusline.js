#!/usr/bin/env node
'use strict';

// statusLine command. Claude Code runs this on session start and on each new
// assistant message, passing session JSON on stdin, and puts stdout in the
// status line.
//
// Runs on every assistant message, so it does exactly one small file read and
// nothing else -- no network, no waiting on the proxy, nothing that can hang
// the UI. Process startup is the floor cost and the read is negligible beside
// it.
//
// Never exits non-zero and never throws: a crashing status line would be a
// worse outcome than a wrong one, and the fallback text is the pessimistic
// reading anyway.
//
// No ANSI escapes live in this file. All colour comes from status.js, where
// the codes are written as \u escapes -- a literal ESC byte in source does not
// survive routine editing, and a silently colourless status line is a defect
// no test would catch.

function main() {
  // stdin is drained but unused: Claude Code passes session JSON, and reading
  // it is what lets the process exit promptly on some platforms rather than
  // waiting on an unconsumed pipe.
  try {
    require('fs').readFileSync(0, 'utf8');
  } catch (e) {
    /* no stdin is fine */
  }

  const { readStatus, render, defaultStatusPath } = require('./status');
  const p = process.env.CCR_STATUS_PATH || defaultStatusPath();
  process.stdout.write(render(readStatus(p), { color: !process.env.NO_COLOR }));
}

try {
  main();
} catch (e) {
  // Pessimistic and uncoloured: if we cannot tell, say so rather than say
  // nothing. Reaching here means status.js itself failed to load, so it
  // cannot be asked for colour codes.
  process.stdout.write('REDACTION STATUS UNKNOWN');
}
