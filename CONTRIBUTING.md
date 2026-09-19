# Contributing

Thanks for looking. A few things about this project that will save you time.

## Before anything else: never paste your real data

Issues, PRs, test fixtures, commit messages — all of it is public and
permanent. Use synthetic values; `config/redact-rules.example.json` exists
for this.

If you need to show output, most of the tooling here is already values-free
on purpose:

```bash
npm run doctor     # verdicts and counts, no values
npm run verify     # same
npm run scan       # counts by category, never prints a value
```

`npm run pii:report` and `audit-rules --detail` are the exceptions. They
write real values to a **local file**, gitignored, for your eyes only. Never
attach one.

## Getting set up

```bash
git clone <your fork>
cd claude-code-privacy-proxy
npm test          # no network needed, runs against fixtures only
npm run help      # what every command does
```

Node 18+. There are no dependencies to install, and there never will be —
see below.

## The bar for a change

**Tests are not optional, and they must be able to fail.** The convention
here is to write the test first, watch it go red, then fix the thing. Several
bugs in this codebase were found because a test was sabotaged deliberately to
confirm it could detect the problem it claimed to cover. If your test passes
against the unfixed code, it is not testing what you think.

**Anything unverifiable reports as NOT protected.** Never "probably fine".
If a check cannot confirm something, it says so. A tool that wrongly claims
protection is worse than no tool, because it stops people looking.

**Fail closed on transform, fail open on parse.** If we cannot redact
something, the request does not go. If we cannot parse something, it passes
only when it could never have contained PII — and that is logged.

**Explain WHY in comments, not what.** The code says what it does. The
comments exist for the reasoning that is not recoverable from reading it —
especially when the obvious approach was tried and failed.

## Things that will get a PR sent back

- **A new runtime dependency.** This process sits in front of every API
  request and handles personal data in plaintext. Every dependency is code
  with that same access, trusted on someone else's word. Node's stdlib is
  enough; it has been so far.
- **A pattern that is not false-positive tested.** Over-redaction destroys
  the code the model needs to reason about, and a user whose tool mangles
  their source turns the tool off. Every pattern in
  `config/patterns.example.json` has both a `should` and a `shouldNot` list.
- **A regex that has not been through the safety screen.** `isPatternSafe`
  runs candidates in a killable child against 20,000-char adversarial input.
  An unbounded email pattern once took **42,698 ms** on 100 KB.
- **Weakening a check to make a test pass.** If a check is wrong, fix the
  check and say why. Do not lower it.

## Gotchas that have cost real time here

Worth reading before you debug something strange.
[docs/orchestration.md](docs/orchestration.md) has the full list.

- **Redaction must be idempotent.** The scrubber re-runs the pipeline over
  files that already contain labels. `spans.js` refuses to match inside an
  existing label region — without it, an `api_key` pattern matches inside the
  proxy's own label and produces a nested one that no longer resolves.
- **`os.homedir()` ignores `process.env.HOME` on Windows.** Every path helper
  reads `process.env.HOME || os.homedir()`. Without it, a test that sets
  `HOME` to a fixture silently operates on the real profile.
- **`windowsHide: true` on every spawn.** `stdio: 'ignore'` silences output
  but Windows still creates the console.
- **Do not `execFileSync` in a test that also serves the child.** It blocks
  the event loop, so the fake server can never respond. Use async `spawn`.
- **Close every server a test opens.** One missing `server.close()` held the
  event loop open and made the suite appear to hang for 60s while every test
  had already passed in 2.6s.

## Before you open a PR

```bash
npm test              # all of it
npm run vscode        # regenerate VS Code entries if you touched scripts
npm run publish:check # no personal data in tracked files
```

If you changed anything in the redaction path, confirm idempotence too —
applying the pipeline twice must not change the output.
`src/test/label-integrity.test.js` covers the shipped pattern set.

## Scope

This is deliberately a small, single-purpose tool. Things that are a good fit:
new pattern categories, another platform's supervisor, better provider
detection, bug fixes with tests.

Things that are probably not: a plugin system, a GUI beyond the existing
dashboard, support for proxying other vendors' APIs. Not because they are bad
ideas, but because each one multiplies the surface that has to stay correct
while handling plaintext personal data.

Open an issue before a large change. It is a friendlier outcome than a
rejected PR you spent a weekend on.
