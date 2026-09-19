#!/usr/bin/env node
'use strict';

// Generates .vscode/tasks.json and .vscode/launch.json from the
// `scriptsInfo` block in package.json.
//
// WHY. VS Code's NPM Scripts explorer shows a script's NAME and the command
// it runs, and nothing else -- so with 23 commands, several of which modify
// files or register OS-level persistence, the UI gives you no way to tell
// `scrub` from `scrub:apply` except by remembering. VS Code does have a
// field for exactly this: a task's `detail`, which the "Run Task" picker
// renders underneath the label. It just has to be populated.
//
// Generated rather than hand-written, from the same block `npm run help`
// reads, so three surfaces (terminal help, task picker, debug list) cannot
// describe the same command three different ways.
//
//   node src/cli/vscode-config.js          write .vscode/
//   node src/cli/vscode-config.js --check   fail if regeneration would change it

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const CHECK = process.argv.includes('--check');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const scripts = pkg.scripts || {};
const info = pkg.scriptsInfo || {};

// Commands that change something outside this process: files on disk, the
// user's config, or OS-level persistence. Flagged in the picker so the
// difference between a dry run and the real thing is visible BEFORE you
// press enter, not afterwards.
const MUTATES = new Set([
  'scrub:apply',
  'patterns:adopt',
  'supervise:install',
  'supervise:uninstall',
  'supervise:repair',
  'egress:warp',
  'stop',
  'pii:report',
]);

const tasks = [];
const configs = [];

for (const name of Object.keys(scripts)) {
  const i = info[name] || {};
  const group = i.group || 'Other';
  const summary = i.summary || '(undocumented)';

  // The picker shows `label` then `detail` on a second, dimmer line. Putting
  // the group in the label keeps related commands together alphabetically,
  // which is how the picker sorts.
  const detail = (MUTATES.has(name) ? 'CHANGES THINGS — ' : '') + summary + (i.detail ? '  ·  ' + i.detail : '');

  tasks.push({
    type: 'npm',
    script: name,
    label: group + ': ' + name,
    detail: detail,
    problemMatcher: [],
    presentation: {
      reveal: 'always',
      panel: 'dedicated',
      clear: true,
    },
    // `test` is the only one VS Code should treat as the test task; nothing
    // here should be the default build task, because a stray Ctrl+Shift+B
    // must never run something that modifies files.
    group: name === 'test' ? { kind: 'test', isDefault: true } : undefined,
  });

  // A debug entry per script, so breakpoints work without anyone having to
  // hand-write an args array for a command they are trying to understand.
  const cmd = scripts[name];
  const m = /^node\s+(\S+)(.*)$/.exec(cmd);
  if (m) {
    const args = m[2].trim();
    configs.push({
      type: 'node',
      request: 'launch',
      name: group + ': ' + name + (MUTATES.has(name) ? '  [CHANGES THINGS]' : ''),
      program: '${workspaceFolder}/' + m[1].replace(/\\/g, '/'),
      args: args ? args.split(/\s+/) : [],
      cwd: '${workspaceFolder}',
      console: 'integratedTerminal',
      skipFiles: ['<node_internals>/**'],
    });
  }
}

const tasksJson = {
  version: '2.0.0',
  // Regenerated: see the note below. Edits here are lost on the next run.
  _generated: 'by `node src/cli/vscode-config.js` from package.json scriptsInfo. Edit the descriptions there, not here.',
  tasks: tasks,
};

const launchJson = {
  version: '0.2.0',
  _generated: 'by `node src/cli/vscode-config.js` from package.json scriptsInfo. Edit the descriptions there, not here.',
  configurations: configs,
};

const dir = path.join(ROOT, '.vscode');
const files = [
  ['tasks.json', JSON.stringify(tasksJson, null, 2) + '\n'],
  ['launch.json', JSON.stringify(launchJson, null, 2) + '\n'],
];

let drift = 0;
for (const [name, body] of files) {
  const p = path.join(dir, name);
  let current = null;
  try {
    current = fs.readFileSync(p, 'utf8');
  } catch (e) {
    /* not there yet */
  }
  if (current === body) {
    console.log('  up to date : .vscode/' + name);
    continue;
  }
  if (CHECK) {
    drift++;
    console.log('  STALE      : .vscode/' + name + ' (run `npm run vscode` to regenerate)');
    continue;
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(p, body);
  console.log('  wrote      : .vscode/' + name + '  (' + (name === 'tasks.json' ? tasks.length + ' tasks' : configs.length + ' debug configs') + ')');
}

if (!CHECK) {
  console.log('');
  console.log('  In VS Code:');
  console.log('    Ctrl+Shift+P -> "Tasks: Run Task"   — descriptions show under each name');
  console.log('    Run and Debug panel                 — breakpoints in any command');
  console.log('');
  console.log('  Commands that modify files or register persistence are marked CHANGES THINGS.');
}

process.exitCode = drift ? 1 : 0;
