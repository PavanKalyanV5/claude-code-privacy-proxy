# Orchestration and error reference

*For developers working on or debugging this proxy. If you only want to run
it, the README is enough.*

Everything here is automatic once installed. This document explains **what
runs when**, **what happens when each part fails**, and **what every error
message means**. It exists because the two worst failures this project has
had were not bugs in a component — they were gaps between components, and
both showed green everywhere anyone thought to look.

---

## 1. The orchestration cycle

Five independent mechanisms. None depends on another being healthy, which is
deliberate: a single supervisor is a single point of failure.

```
  EVENT                    RUNS                        IF IT FAILS
  ─────                    ────                        ───────────
  You log in           →   Startup/*.vbs               watchdog catches it ≤5 min
  Claude Code starts   →   lifecycle.js start          message in the session
  Every 5 minutes      →   lifecycle.js --supervised   logged; next tick retries
  Claude Code ends     →   lifecycle.js stop           silent; scheduled scrub covers it
  Proxy running        →   hourly scrub + retention    logged; next hour retries
```

### Startup order, and why it is that order

`lifecycle.js start` is the only entry point, and it is **idempotent** — safe
to call from four places concurrently.

```
1. load rules            FAIL → emit "REDACTION CANNOT START", stop.
2. GET /_health (2s)     ok   → report and exit. Nothing else to do.
3. spawn start.js        detached, windowsHide, stdio ignored
4. poll /_health (15s)   ok   → report. timeout → emit LOUDLY.
```

Step 4 is load-bearing. Reporting success on a process that has not finished
starting is how a dead port gets mistaken for a live one — and from inside
Claude Code, a dead port is indistinguishable from a firewall problem.

### What the proxy owns once up

| Interval | Job | Guard |
|---|---|---|
| 30s | publish `status.json` | `unref`'d |
| 60s | flush the label cache | `unref`'d |
| 1 min after start, then hourly | retention sweep | try/catch, never fatal |
| `residue.intervalMinutes` (60) | transcript scrub | re-entrancy flag |
| `DECISION_TTL_MS` (120s) | re-decide tunnel vs direct | recomputed per connection |

Every timer is `unref`'d so none of them can keep the process alive on its
own. The scrub runs in a **detached child** — it walks ~4,000 files and
several hundred MB, and doing that inline would stall the event loop and turn
a privacy cleanup into an outage.

---

## 2. Error-handling philosophy

Three rules, applied consistently. When they conflict, the earlier one wins.

### Fail closed on transform, fail open on parse

If we cannot *redact* something, the request does not go. If we cannot
*parse* something, it passes through unredacted **only** when it was never
going to contain PII in the first place — and that decision is logged.

A redaction proxy that silently degrades to a pass-through is worse than no
proxy, because it stops you looking.

### Unverifiable is reported as not protected

Never "probably fine". The dashboard computes its verdict client-side from
the raw snapshot and renders `DEGRADED` or `NOT PROTECTED` for anything it
cannot confirm — it will not accept a pre-judged field from the server.

### Maintenance failures are never fatal

Retention, logging and job history are wrapped so they cannot take down
redaction. A full disk is a problem; a proxy that refuses to start because it
could not delete an old backup is a worse one.

---

## 3. Failure modes, by stage

### Config

| Condition | Behaviour |
|---|---|
| Rules file is invalid JSON | **Proxy will not start.** `lifecycle.js` emits `REDACTION CANNOT START`. The running proxy is unaffected — it read rules at startup — so this often only surfaces on the next restart. |
| Zero literals *and* zero patterns | Starts, logs a warning, raises a **critical desktop notification**. Nothing is being redacted. |
| Zero literals, patterns present | Starts with a warning. Categories still apply. |
| A pattern is catastrophic | That pattern is **disabled**, others load, warning logged. Screened in a killable child process against 20,000-char adversarial input. |
| An alias is a common word | **Fatal — refuses to start.** Inbound un-aliasing substitutes the real value everywhere the alias appears, so a common word would rewrite code and comments. Losing the proxy is recoverable; silently corrupting source is not. |
| Master key missing | Fatal. Never falls back to unkeyed hashing. |

### Routing

| Condition | Behaviour |
|---|---|
| `ANTHROPIC_BASE_URL` unset or wrong | `REDACTION INACTIVE` at session start. Traffic bypasses the proxy entirely — this outranks every other warning, because nothing else matters if requests are not passing through. |
| Port dead while the variable points at it | Connection errors inside Claude Code. The SessionStart hook and the 5-minute watchdog both exist to prevent this state. |

### Egress

| Condition | Behaviour |
|---|---|
| No endpoint available, `onFailure: "refuse"` | Requests are **REFUSED**. Correct and deliberate: a dead tunnel must not become a silent unmasked connection. |
| No endpoint available, `onFailure: "direct"` | Request proceeds unmasked, `EGRESS FAILED OVER TO A DIRECT CONNECTION` logged, and a **sticky counter** increments. That counter never resets, because "we were exposed once" is not something a later success should erase. |
| Tunnel up but not masking | `EGRESS NOT MASKING` — the echo service sees the same address as a direct connection, so the proxy is forwarding your real IP. |
| Auto mode declines to tunnel | Not an error. `masking` means *"is the path I am actually using masking me"* — when a VPN already does the job, the tunnel stays idle by design. Conflating these produced a false alarm three separate times. |

### Residue scrub

| Condition | Behaviour |
|---|---|
| A pass is already running | Skipped. A slow pass must not stack up behind itself. |
| Child cannot start | Logged, recorded in job history, next interval retries. |
| Non-zero exit | Recorded as a failure with its captured output. Values remain on disk. |
| **Verification failure** | The most serious case: files were rewritten and then did not re-parse. Backups are in `~/.claude/redaction/residue-backup-*`. Stop and investigate before running further passes. |
| A file was modified recently | Skipped by `skipNewerThanMin` — it may be the live session's own transcript. |

---

## 4. Error reference

Search for the message you saw.

### Session-start messages

**`REDACTION CANNOT START: <reason>`**
The rules file could not be read or parsed. Nothing is redacted and the proxy
cannot start. Fix the JSON. `npm run doctor` reports the parse position.

**`REDACTION INACTIVE: ANTHROPIC_BASE_URL is "..."`**
Claude Code is talking straight to the API. Check the `env` block in
`~/.claude/settings.json`, then restart Claude Code — it reads that at
startup only.

**`REDACTION PROXY DID NOT COME UP within 15s`**
The spawn succeeded but `/_health` never answered. Run `node src/start.js` in
a terminal to see why it is refusing to start — the detached child's output
goes nowhere by design.

**`Redaction proxy is running, but: no egress endpoint is available`**
Redaction works; IP masking has no fallback. With `onFailure: "refuse"` a
dropped VPN means refused requests. Fix with `npm run egress:warp -- --install`.

### Runtime warnings

**`EGRESS IDLE AND UNMASKED`**
Not tunnelling, and the direct path appears to come from your home country.
Your own address is in use.

**`EGRESS NOT MASKING: tunnelling is ON, but ...`**
The proxy is forwarding your real IP. Treat yourself as unmasked.

**`EGRESS FAILED OVER TO A DIRECT CONNECTION`**
Only possible with `onFailure: "direct"`. A request went out from your real
address. The counter is sticky and surfaces in the dashboard and `doctor`.

**`request REFUSED, nothing sent direct`**
Fail-closed working as designed. An outage, not an exposure.

**`pattern "<name>" disabled: ... catastrophic backtracking`**
Screened out before it could hang the proxy. An unbounded email pattern once
took **42,698 ms** on 100 KB of input. Bound your quantifiers.
*If the pattern begins with `-`, and you are on a build before the env-var
fix, this message was a misdiagnosis — the probe child parsed it as a CLI
option.*

**`unsafe alias in redact-rules.json`**
Refuses to start. Pick an alias that cannot appear in ordinary source text.

**`residue scrub FAILED (exit N, verify failures M)`**
Real values remain on disk. Open the run's log in the dashboard's Residue
tab.

**`retention pass failed (...)`**
Housekeeping only. Logs will grow until it is fixed; nothing is unprotected.

### Supervisor

**`watchdog will NOT run on battery`**
`schtasks` sets `DisallowStartIfOnBatteries=true` by default and offers no
flag to change it. On a laptop the task sits `Enabled` and `Ready` and never
fires — measured here as a `Last Run Time` of `30-11-1999`. Fix with
`npm run supervise:repair`.

**`ONLOGON: Access is denied`**
Expected. A logon trigger registers against the machine and needs elevation.
Logon coverage comes from the Startup folder instead, which does not.

**`Windows Script Host: The system cannot find the file specified` at logon**
A stale launcher pointing at a renamed directory. `npm run supervise:install`
rewrites it and removes the old copies.

---

## 5. Developer notes

Things that cost real time to learn here.

**Redaction must be idempotent.** The scrubber re-runs the pipeline over
files that already contain labels. `spans.js` refuses to match inside an
existing `[PII:category:hex]` region — without that guard, an `api[_-]?key`
pattern matches inside the proxy's *own* label and produces a nested one that
no longer resolves. Guarded in the engine, not per-pattern, because any
user-written rule could collide.

**Writing an alias in source code substitutes the real value.** Aliases are
bidirectional. A comment containing the alias string is un-aliased on its way
to disk, so the file ends up holding the real username. This happened *in the
file whose job is removing exactly that*. Never hand-edit files that contain
identity values — use a script that resolves them at runtime.

**`os.homedir()` ignores `process.env.HOME` on Windows.** Every path helper
here reads `process.env.HOME || os.homedir()`. Without it, tests that set
`HOME` to a fixture silently operate on the real profile — which is why every
early attempt to test the scanner timed out on 599 MB of real transcripts.

**`windowsHide: true` on every spawn.** `stdio: 'ignore'` silences output but
Windows still creates the console. `rules.js` spawns one child *per pattern*,
so without it a 12-pattern config flashes 12 windows on every start.

**Patterns reach the safety probe through the environment**, not argv. A
pattern starting with `-` is otherwise parsed by node as an option.

**Never rename a directory a process has as its cwd.** Windows returns
`EBUSY`. The deploy tool writes per-file with atomic renames for this reason;
a directory swap worked exactly once and then never again.

**Tests must not block the event loop while serving themselves.**
`execFileSync` in a test that also runs the fake server deadlocks — the child
can never be served. Use async `spawn`.

**Close every server a test opens.** One missing `server.close()` held the
event loop open and made the whole suite appear to hang for 60s+ while every
test had actually passed in 2.6s.

---

## 6. Verifying a change

```bash
npm test              # 479 tests, no network required
npm run verify        # 17 checks against your real config
npm run doctor        # the whole chain, end to end
npm run publish:check # no identity or personal data in tracked files
```

If you touched redaction, also confirm idempotence — applying the pipeline
twice must not change the output. `src/test/label-integrity.test.js` covers
it for the shipped pattern set.
