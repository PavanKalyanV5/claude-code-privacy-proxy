#!/usr/bin/env node
'use strict';

// Runs the test suite portably.
//
// WHY THIS EXISTS. `node --test src/test/*.test.js` relies on the SHELL
// expanding the glob. bash does; PowerShell does not, and neither does
// Node's argument handling before v22. So CI failed on windows-latest with
//
//   Could not find 'D:\a\...\src\test\*.test.js'
//
// while passing on Linux and macOS, and passing on Windows + Node 22 where
// the runner had grown its own glob support. A test command that works on
// three of four platforms is a test command that will let a Windows-only
// bug through -- and this project has had several, because it spawns
// processes, sets ACLs and registers scheduled tasks.
//
// `node --test <directory>` is not a fix either: its discovery rules have
// changed across versions and it found exactly one file here on v24.
//
// Expanding the list ourselves is boring and works everywhere.

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const dir = path.join(__dirname, '..', 'test');
let files;
try {
  files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.test.js'))
    .sort()
    .map((f) => path.join(dir, f));
} catch (e) {
  console.error('cannot read ' + dir + ': ' + e.message);
  process.exit(1);
}

if (!files.length) {
  // An empty suite passing is how a broken test command looks like a green
  // build. Refuse instead.
  console.error('no *.test.js files found in ' + dir);
  process.exit(1);
}

const args = ['--test'].concat(process.argv.slice(2)).concat(files);
const child = spawn(process.execPath, args, { stdio: 'inherit', windowsHide: true });
child.on('error', (e) => {
  console.error('could not start the test runner: ' + e.message);
  process.exit(1);
});
child.on('close', (code) => process.exit(code === null ? 1 : code));
