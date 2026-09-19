# claude-code-privacy-proxy

A local proxy that strips your personal data, machine metadata and location
fingerprints out of Claude Code's API requests — and optionally masks your
source IP — **without breaking any tool.**

Zero dependencies. Node stdlib only. Everything runs on your machine. Nothing
is uploaded anywhere, including by this project.

```
490 tests   ·   0 runtime dependencies   ·   no TLS interception, no CA to install
```

**Who this is for.** Anyone whose prompts carry things their employer's DPA,
an NDA, or plain self-interest says should not leave the building — client
names in a refactor, a customer record in a stack trace, an internal hostname
in every path. AI coding assistants moved that exposure from "files you chose
to upload" to "everything the tool reads on your behalf", and you are not the
one assembling the requests.

This does not make you anonymous to Anthropic — billing already identifies
you, and pretending otherwise would be the first lie. It keeps *personal and
organisational data out of the payload*, and your location and machine out of
the metadata.

```
  what you type                          what the API receives
  ─────────────                          ─────────────────────
  I'm Jane Q. Testerson,                 I'm [PII:personal:a1b2c3d4e5f60718],
  jane@example.com,                      [PII:email:9f8e7d6c5b4a3928],
  +1-555-0142                            [PII:phone:1a2b3c4d5e6f7a8b]
  C:\Users\jqtesterson\proj              C:\Users\example-user\proj
  built 2026-09-18T14:22:05+0530         built 2026-09-18T08:52:05Z
  LANG=en_IN.UTF-8                       LANG=en_US.UTF-8
  x-stainless-os: Windows                x-stainless-os: Unknown
  …from 203.0.113.42 (IN)                …from 198.51.100.7 (DE)
```

And when Claude Code then asks to edit that file, the tool receives
`C:\Users\jqtesterson\proj` and `Jane Q. Testerson` — the real values, resolved
back. **The model works with labels; your tools work with reality.**

---

## Why this matters now

AI coding assistants changed what "sharing data" means. You used to choose
what to upload. Now the tool reads whatever it needs — your files, your
stack traces, your shell output, your paths — and assembles the request
itself. **You are no longer the one deciding what leaves.**

That is a problem three ways at once:

| | |
|---|---|
| **Personal** | Your name, address, phone and email are in the files you work on, and your username, hostname, timezone and OS build are in every request whether you type them or not |
| **Organisational** | Client names in a refactor, a customer record in a stack trace, an internal hostname in a config, a credential in a `.env` you asked about |
| **Regulatory** | Most DPAs and NDAs do not distinguish between data you meant to send and data your tooling sent for you |

The usual answers are all bad. *Be careful* does not scale, and you are not
assembling the requests anyway. *Ban the tool* costs you the productivity and
pushes people to unmanaged personal accounts — the worst of both. *Wait for
an enterprise tier* leaves you exposed today, and still trusts a policy
rather than a mechanism.

**This is the mechanism.** A local proxy between Claude Code and the API that
removes the data before it leaves your machine, and puts the real values back
before your tools see them — so nothing breaks.

### What makes it different

Most redaction tools are a regex pass. The hard parts are everywhere else:

- **Reversible where it has to be.** Usernames and paths are *aliased* out
  and restored on the way back in, so `Edit`, `Bash` and `Read` still operate
  on real paths. Redaction that breaks your tools gets switched off.
- **Deterministic labels.** The same value always produces the same label,
  keyed with HMAC-SHA256 — so **prompt caching keeps working**. A naive
  random-token approach would silently multiply your bill.
- **No stored PII map.** Resolution is *derived* by re-reading the file and
  re-redacting, then translating offsets. There is no database of your
  personal data to protect, because there is no database.
- **Fail closed.** If a transform fails, the request does not go. If the
  tunnel is down and masking was requested, the request is refused rather
  than sent unmasked. You get an outage, never a silent exposure.
- **Cleans up what already leaked.** Transcripts written before you installed
  this still hold real values. The scrubber rewrites them using the *same*
  pipeline and key, so `--resume` keeps working.
- **Self-auditing.** Every scrub pass, every retention sweep and every
  restart is recorded durably, with per-run logs, a per-file manifest, and
  anomaly signals — because a privacy control you cannot inspect is one you
  are trusting on faith.

### On compliance

Stated plainly, because overclaiming here would be its own kind of harm:
**this does not make you or your company compliant with anything.** No tool
does. Compliance is a programme, not a dependency.

What it gives you is a **technical control with evidence** — the thing
auditors and DPAs actually ask for:

- **Data minimisation** (GDPR Art. 5(1)(c)) enforced at the boundary rather
  than by policy, with counts showing what was removed
- **A record of processing** — durable job history, per-file manifests, and
  category totals for every pass
- **Retention limits** you configure and the tool enforces hourly, including
  on its own logs
- **Demonstrability** (GDPR Art. 5(2)) — `npm run doctor`, `npm run verify`
  and the dashboard produce dated, values-free output you can attach to a
  review
- **Residual-risk honesty** — [docs/threat-model.md](docs/threat-model.md)
  states what is *not* covered, which is the section a serious reviewer reads
  first

If you are answering a vendor questionnaire about AI tooling, the useful
sentence is: *personal and organisational data is removed client-side before
transmission, with configurable retention and an auditable record of every
redaction pass.* That is a claim this tool lets you actually support.

---

## Why this exists

Claude Code sends your conversation, your file contents, your paths and your
shell output to an API. Most of that is the point. Some of it isn't:

- your name, email, phone, address
- your OS username and hostname, in every path
- your timezone offset and locale, which pin your region as precisely as an IP
- your OS build and CPU architecture, in request headers
- your IP address, which pins your city

You cannot selectively withhold these by being careful, because you are not the
one assembling the requests.

---

## What it does and does not do

**Protects:**

| | |
|---|---|
| Listed literals | your name, emails, phone numbers, employer, handles |
| Pattern categories | email, phone, public IPv4/IPv6, MAC, git org and repo |
| Secrets and keys | AWS, GitHub, Slack, OpenAI, Anthropic, Stripe, Google, SendGrid, npm, HuggingFace, JWTs, bearer headers, private keys, DB URLs with passwords — 20 shipped patterns, each false-positive tested |
| Financial and national ID | card numbers, IBAN, Aadhaar, India PAN, US SSN |
| Identity, reversibly | OS username, hostname, project roots — aliased outbound, restored inbound so tools still work |
| Location fingerprints | timezone offsets, IANA zone names, locale strings, OS build |
| Request headers | `accept-language`, `x-stainless-os`/`-arch`, and any address-bearing header |
| Source IP | optional SOCKS5 / HTTP CONNECT tunnel, fail-closed |
| On-disk residue | transcripts, tool results, edit snapshots — scrubbed on a schedule |

**Does NOT protect — know these before you rely on it:**

- **Anything you type yourself.** It redacts patterns and listed literals, not
  intent. If you paste a secret, it goes.
- **Other programs' traffic.** It covers Claude Code's API calls only. An MCP
  server making its own request, or anything `Bash` runs (`curl`, `npm
  install`, `git push`), leaves from your real IP. **Only an OS-level VPN
  covers everything** — this is why the recommended setup keeps a VPN as
  primary.
- **Your account identity.** Anthropic knows who you are from billing. The goal
  here is location and machine metadata, and keeping personal data out of
  prompts — not anonymity from your provider.
- **A single-token literal wrapped in word characters.** `xxJanexx` is
  deliberately not redacted, because that guard is the only thing stopping
  `Jane` matching inside `Janet`. Override per-value with
  `{ "value": "...", "boundary": false }`.

---

## Measured, not claimed

Every number here came from running the thing, and several of them are the
result of it failing first.

| | |
|---|---|
| **On-disk residue** | 41,906 → 220 occurrences across 851 files. 173,653 lines rewritten, **0 lines lost, 0 structure changes** |
| **Fingerprinting headers** | 9 of 9 → 3 of 9 reaching the API |
| **Redaction correctness** | every literal checked in 20 adjacency shapes — prefixed, suffixed, doubled, punctuation-wrapped, inside JSON strings |
| **Catastrophic regex** | an unbounded email pattern took **42,698 ms** on 100 KB. Bounded, it takes 10 ms. Every pattern is now screened against 20,000-char adversarial input before it loads |
| **Residue scanning** | 124 s → **3.3 s** (4,204 files read → 20) via an index keyed on a fingerprint of your rules, so adding a literal invalidates everything |
| **Test suite** | 490 tests, no network required |

**And the measurement that removed a feature.** A scraped free-proxy pool was
built, and it worked: five proxies passed full verification — TLS-verified
connection, echo service confirming a different exit address. All five
refused the *next* connection, seconds later. ~6% hit rate, 2.0–6.3 s
latency. It ships with no default sources, and the README says to use
Cloudflare WARP or your own SSH tunnel instead. **Verification does not
predict usability**, and a privacy tool that overstates its coverage is worse
than no tool, because it stops you looking.

---

## Install

Requires Node 18+. Nothing else.

```bash
git clone <this repo>
cd claude-code-privacy-proxy
npm test                       # 490 tests, no network needed
```

**1. Create your config and key**

```bash
mkdir -p ~/.claude/redaction
cp config/redact-rules.example.json ~/.claude/redaction/redact-rules.json
node -e "require('fs').writeFileSync(require('os').homedir()+'/.claude/redaction/redact.key', require('crypto').randomBytes(32))"
```

Edit `~/.claude/redaction/redact-rules.json` and put **your** details in
`literals` and **your** paths in `aliases`. That file is gitignored and never
leaves your machine.

**2. Check the config before trusting it**

```bash
npm run verify
```

Reads your real rules and checks every literal in 20 adjacency shapes, every
pattern, alias safety, and live masking. Prints **verdicts and counts only —
never a value, never an address**, so the output is safe to paste anywhere.

**3. Wire it into Claude Code**

Add all of this to `~/.claude/settings.json`:

```json
{
  "env": { "ANTHROPIC_BASE_URL": "http://127.0.0.1:47113" },
  "hooks": {
    "SessionStart": [{ "hooks": [{ "type": "command",
      "command": "node /ABSOLUTE/PATH/TO/claude-code-privacy-proxy/src/lifecycle.js start" }] }],
    "SessionEnd": [{ "hooks": [{ "type": "command",
      "command": "node /ABSOLUTE/PATH/TO/claude-code-privacy-proxy/src/lifecycle.js stop" }] }]
  }
}
```

Use a full absolute path — hooks do not run from the repo directory.

`lifecycle.js` replaces the start-up ritual this project used to require.
Every session start it checks whether a healthy proxy is listening, starts one
if not, **waits for it to become healthy**, and tells you if it could not.
When everything is fine it says nothing.

> **Why this is a hook and not something you run.** Starting the proxy used to
> be a manual ordered sequence — start it, confirm `/_health`, only then start
> Claude Code — and getting the order wrong caused the two worst incidents in
> this project's history. Both times the port was dead while
> `ANTHROPIC_BASE_URL` pointed at it, and from inside Claude Code a dead port
> is indistinguishable from a firewall problem. A ritual that must be performed
> correctly every time will eventually be performed incorrectly.

`SessionEnd` deliberately does **not** stop the proxy — other sessions may be
using it, and a proxy that dies with one window leaves the next session
pointing at a dead port. It scrubs the transcript that session just wrote.

**4. Survive reboots and crashes**

```bash
npm run supervise:install
npm run supervise               # confirm both halves say covered
```

Two mechanisms, neither needing admin rights:

| | Covers | Mechanism |
|---|---|---|
| Startup folder | protection is up before your first session | logon |
| Scheduled task | a crashed proxy is restarted within 5 min | every 5 minutes |

Both run the same idempotent check, so the 5-minute task costs almost nothing
and never restarts a working proxy. Neither creates a console window.

> A scheduled `ONLOGON` task is **not** used: a logon trigger registers against
> the machine rather than your session and is refused without elevation. The
> Startup folder needs none, which is why logon lives there.

Without this, a proxy that dies at 10am stays dead until your next session —
and because egress is fail-closed, that shows up as refused requests.

**5. Open the dashboard**

```bash
npm run dash                    # prints the URL, token included
```

Five tabs — Overview, Logs, PII rules, Egress, Residue — served by the proxy
itself on the same port, live over server-sent events. It is the only place
that shows whether your rules are sane, whether masking is working, and what
the proxy has actually done.

The token is stored in `~/.claude/redaction/dash-token`, locked to your
account with the same ACL as the master key. It is regenerated every time the
proxy starts, so run `npm run dash` again after a restart.

---

## Daily use

Nothing. That is the design goal.

Open Claude Code and the hook ensures protection is running. Reboot and the
Startup entry brings it back. Kill the proxy and the watchdog restores it
within five minutes. Close Claude Code and the transcript gets scrubbed.

The two things worth doing occasionally:

```bash
npm run dash                    # look at the dashboard
npm run verify                  # full check against your real config
```

If a session start ever prints a warning, read it — the messages are written
to be specific about what is *not* protected, and none of them appear when
everything is working.

---

## Stopping it

**Pause for one session** — comment out `ANTHROPIC_BASE_URL` in
`settings.json` and restart Claude Code. Traffic goes straight to the API
unredacted; the proxy keeps running but sees nothing.

**Stop the proxy now:**

```bash
npm run stop
```

It tells you if the watchdog is registered, because the watchdog will restart
it within five minutes — stopping it for good means turning that off too.

> There is deliberately **no** `/_shutdown` HTTP route. Any local web page can
> POST to loopback, and because egress is fail-closed, killing the proxy turns
> every later request into a refusal — a denial of service any website you
> visit could trigger. The PID comes from `/_health`, so this can only ever
> stop a process currently answering as the proxy on that port.

**Careful:** Claude Code reads `ANTHROPIC_BASE_URL` at startup and keeps using
it. Stop the proxy while a session is open and that session gets connection
errors until the proxy is back — a dead port and a blocked firewall look
identical from inside Claude Code.

**Turn off supervision:**

```bash
npm run supervise:uninstall
```

Removes the Startup entry, the scheduled task and the launcher. Protection
then depends on the SessionStart hook alone — a crash between sessions will go
unrepaired until you start a new one.

**Remove it completely:**

```bash
npm run supervise:uninstall
```

Then delete the `hooks` and `ANTHROPIC_BASE_URL` entries from
`settings.json`, and remove `~/.claude/redaction/` if you also want the key,
rules, cache and logs gone.

> Deleting the key makes every label already written to disk permanently
> unresolvable. If you have scrubbed transcripts you still care about, keep
> `redact.key` — resolution re-derives labels from it, and nothing else can.

---

## IP masking (optional)

Content redaction works on its own. This layer is separate and hides *where*
requests come from.

```json
"egress": {
  "mode": "auto",
  "homeCountry": "IN",
  "onFailure": "refuse",
  "urls": ["socks5://127.0.0.1:1080"],
  "ipCheckUrl": "https://api.country.is"
}
```

`mode: "auto"` tunnels **only when you look exposed** — decided by comparing
the country a direct connection appears to come from against `homeCountry`. So
when your VPN is up the tunnel stays out of the way; when it drops, it engages.

`onFailure: "refuse"` means that if no proxy is reachable, requests are
**blocked rather than sent unmasked**. You get connection errors, not silent
exposure. Set it to `"direct"` if you would rather stay working — it warns on
every fallback and keeps a sticky counter.

### Getting a reliable free proxy

See **[docs/providers.md](docs/providers.md)** for the full comparison. Short
version, most dependable first:

1. **Your own SSH tunnel** — `ssh -D 1080 user@your-vps`. Oracle Cloud's
   "Always Free" tier gives permanently free VMs that do this well. You are the
   only operator, so nothing is shared and nothing disappears.
2. **Cloudflare WARP** — free, run by a company with a reputation, no account
   required.
3. **Tor** — free and always available, but many API providers block exit
   nodes. A last resort for availability rather than a first choice.

`npm run providers` detects which of these are already running locally.

> **Public "free proxy list" scraping is deliberately not shipped.** It was
> built, measured, and removed: five proxies passed verification and **all five
> refused the very next connection seconds later.** Verification does not
> predict usability. The code remains in `src/pool.js` for anyone who wants to
> opt in with explicit sources, and ships with none.

---

## One command to check everything

```bash
npm run doctor
```

```
  ok  rules load          14 literals, 27 patterns, 2 aliases
  ok  pattern safety      every configured pattern loads
  ok  ANTHROPIC_BASE_URL  points at the proxy
  ok  proxy listening     pid 13780 on 47113
  ok  egress fallback     1 endpoint(s), 127.0.0.1:40000 open
  ok  currently masked    by a VPN or equivalent (tunnel idle by design)
  ok  crash recovery      watchdog registered and battery-safe
  ok  start at logon      Startup entry present
  ok  transcript scrub    3 run(s) recorded, last 19/9/2026, 7:58 pm
  ALL CHECKS PASSED — every stage of the chain is verified
```

Every other tool here reports on **one** component. This walks the whole
chain in the order a request travels it, because the two worst failures this
project has had both lived in the gaps *between* components — a
`ANTHROPIC_BASE_URL` pointing at a port nothing was listening on, and a logon
launcher whose directory had been renamed away. Both showed green everywhere
you would think to look.

Each failure names the command that fixes it. Output is verdicts and counts
only, never a value, so it is safe to paste into an issue.

---

## Secret and PII patterns

`config/patterns.example.json` ships 20 optional patterns. Adopt them with:

```bash
npm run patterns:adopt            # dry run: shows what would be added
npm run patterns:adopt -- --write # apply, with a backup
```

| Group | Covers |
|---|---|
| **Keys and tokens** | AWS, GitHub, Slack, OpenAI, Anthropic, Stripe, Google, SendGrid, npm, HuggingFace, JWT, `Bearer` headers, private-key blocks, DB URLs with inline passwords, generic `api_key =` assignments |
| **Financial** | card numbers (by prefix and length), IBAN |
| **National ID** | Aadhaar, India PAN, US SSN |

Every one is screened for catastrophic backtracking **and** tested against
near-misses before shipping — `api_key = ""`, `npm install express` and
`http://127.0.0.1:8080` all survive untouched. The provider-prefixed ones
matter most: they catch a key pasted **on its own**, which is how a key
actually gets leaked, with no assignment for a rule to anchor to.

Check a set against your own machine before adopting it:

```bash
node src/audit-rules.js --patterns config/patterns.example.json --corpus .
```

A pattern with hits on your files is not necessarily wrong — but
over-redaction destroys the code the model needs to reason about, so it is
worth looking first.

---

## Auditing your own rules

```bash
npm run audit:rules                        # values-free verdict
node src/audit-rules.js --detail out.txt   # plus a local file naming names
```

Tests every literal across 14 adjacency shapes — bare, quoted, inside JSON,
doubled, in a path, upper and lower case — and reports leaks by **index**,
category and length, never by value. That makes the verdict safe to share
while still being specific enough to act on. Values go to the optional
`--detail` file, for your eyes only.

It also flags the opposite risk: a literal short enough to match inside
unrelated words.

---

## Knowing it works

The design rule throughout: **anything unverifiable reports as NOT protected.**
A tool that wrongly claims protection is worse than no tool, because it stops
you looking.

```bash
npm run verify                              # full check against your real config
curl http://127.0.0.1:47113/_egress/check    # fresh live probe: am I masked right now?
```

`/_egress/check` runs a **new** measurement when you ask — direct and tunnelled,
compared at that moment — rather than reporting a stored field:

```json
{
  "masked": true,
  "yourCountry": "IN",
  "exitCountry": "DE",
  "exitIsHomeCountry": false,
  "wentOutDirect": 0,
  "onFailure": "refuse"
}
```

`exitIsHomeCountry` is broken out because a proxy inside your own country hides
your address while leaving your location intact — and that reads as success on
every other field.

### If something breaks

```bash
curl -X POST http://127.0.0.1:47113/_egress/off    # stop tunnelling, keep working
curl -X POST http://127.0.0.1:47113/_egress/on     # resume
```

No restart needed. Turning the tunnel off exposes your IP; **redaction keeps
working regardless.** [docs/runbook.md](docs/runbook.md) is written to be
usable when the proxy itself is the broken thing.

---

## Local residue

Transcripts, tool results and edit snapshots are written **before** the proxy
sees anything, so they hold real values. On one real machine: **41,906
occurrences across 608 files.**

```bash
npm run scan            # counts by category, never prints a value
npm run scrub           # dry run — shows exactly what would change
npm run scrub:apply     # apply, with backups
npm run verify:scrub    # prove nothing was damaged
```

Scrubbing is the *same operation* as rendering for the model, reusing the same
pipeline and key — so `--resume` keeps working, because the labels written are
exactly what the model would have been shown.

It backs up every file first, **skips anything modified recently so it can
never rewrite your live session**, parses `.jsonl` per line and `.json` as one
document, leaves an unparseable line byte-identical, and re-parses everything
afterwards. Verified on a real run: **851 files, 173,653 lines, 0 lines lost, 0
structure changes, personal data 39,482 → 0.**

Set `"residue": { "scrub": true }` to have the proxy do this hourly.

### Auditing the scrub

Every pass is recorded durably — when it ran, what triggered it, how many
files it rewrote, whether verification passed, and **the log that pass
produced**. The Residue tab lists them, with two buttons per run:

| Button | Shows |
|---|---|
| **view log** | The console output that pass produced |
| **which files** | The manifest: every file rewritten, lines changed, and which categories of value came out of each |

"327 files rewritten" is not auditable on its own. The manifest answers
*which*, and because the scheduled pass runs with `--no-backup`, **it is the
only record** — the originals are gone by design, so that they are not left
lying around holding the values the scrub removed.

If counts are not enough, `residue.rawLog` records **every individual value
replaced and the exact label it became**:

```json
"residue": { "scrub": true, "rawLog": true }
```

That file is treated like the master key, not like a log: written `0600` with
inheritance stripped so only your account can read it, never echoed to a
console, and deleted after `retention.rawLogDays` (**7 by default** — the
shortest window of anything here). It is off by default, because it is a
concentrated copy of exactly what the scrub was run to remove.

This exists because the scrub is the only background job here that *modifies*
your files, and it was previously observable only as a field in the proxy's
memory — lost at logon, on a crash, and every time the watchdog revived it.
"Did it run overnight?" had no answer.

### Retention

Every log this tool writes has a configurable lifetime:

```json
"retention": {
  "enabled": true,
  "auditLogMB": 5,
  "supervisorDays": 14,
  "residueJobsDays": 90,
  "residueRunsKeep": 200,
  "backupsDays": 30,
  "retentionLogDays": 30,
  "rawLogDays": 7
}
```

Enforced hourly by the proxy, with its own log subject to its own policy. `0`
means keep forever, and is reported as such rather than silently deleting
everything.

Backups get the shortest window on purpose: a residue backup is a copy of
your transcripts *before* redaction, so it holds exactly the values the scrub
was run to remove.

Passes that remove nothing are still recorded. That entry is the evidence the
sweep ran — without it, a retention system that has silently stopped looks
identical to one with nothing to do.

### Signals

The dashboard turns that history into things worth acting on rather than rows
to read: a scrub that has not run in too long, repeated failures, verification
failures, a **spike** in files rewritten against the rolling median, or a
steady upward trend. Each says what happened, why it matters, and what to do.

A spike is the useful one. Three times the usual personal data hitting disk
generally means one *new kind* of value entered your work, not more of the
old ones — so the suggested action is to look at which category, and consider
adding it to your literals so it is redacted in transit rather than cleaned
up afterwards.

---

## Every command

| Command | What it does |
|---|---|
| `npm run help` | Every command, grouped, with what it does and when to use it |
| `npm run vscode` | Regenerate VS Code task + debug entries so descriptions show in the UI |
| `npm run doctor` | **Start here.** Checks the whole chain end to end |
| `npm start` / `npm run stop` | Start or stop the proxy |
| `npm run dash` | Print the dashboard URL, token included |
| `npm run verify` | 17 checks against your real config |
| `npm run status` | Current protection state, one line |
| **Setup** | |
| `npm run supervise:install` | Start at logon + 5-minute crash recovery |
| `npm run supervise` | Is anything watching the proxy? |
| `npm run supervise:repair` | Re-point the launcher, lift the battery restriction |
| `npm run supervise:uninstall` | Remove both |
| **Egress** | |
| `npm run egress` | What tunnels are available on this machine |
| `npm run egress:warp -- --install` | Install and configure Cloudflare WARP, verified before use |
| `npm run providers` | Compare free egress options |
| **Rules and patterns** | |
| `npm run audit:rules` | Test every literal across 14 adjacency shapes |
| `npm run patterns:adopt -- --write` | Add the shipped secret/PII patterns to your config |
| **On-disk residue** | |
| `npm run scan` | Count real values still on disk (never prints one) |
| `npm run scrub` / `:apply` | Dry run / rewrite them, with backups |
| `npm run verify:scrub` | Prove nothing was damaged |
| **Publishing** | |
| `npm run pii:report` | List every value found, to a local file, split by tracked vs untracked |
| `npm run publish:check` | Fail if any **tracked** file holds identity or personal data |
| **Deployment** | |
| `node src/deploy.js install` | Copy to `~/.claude/privacy-proxy` so edits here stop affecting you |
| `node src/deploy.js status` | Compare deployed against this tree, both directions |

---

## Documentation

| | |
|---|---|
| **[docs/architecture.md](docs/architecture.md)** | How it works and why each piece is shaped that way |
| **[docs/orchestration.md](docs/orchestration.md)** | What runs when, every failure mode, and an error-message reference |
| **[docs/runbook.md](docs/runbook.md)** | Recovery first: what to do when it breaks |
| **[docs/providers.md](docs/providers.md)** | Free egress options, honestly compared |
| **[docs/threat-model.md](docs/threat-model.md)** | What this defends against, and what it does not |
| **[docs/design-history/](docs/design-history/)** | The original specs and phase plans |

---

## Design notes worth knowing

A few decisions that are load-bearing:

- **No TLS interception.** The proxy speaks plain HTTP on loopback and makes
  its own *verified* HTTPS connection outward. No private CA, no trust-store
  change. Your API key stays inside TLS and is never visible to a tunnel
  operator.
- **No stored label map.** Real values are re-derived from the file on disk on
  demand, so there is nothing to leak and offsets always match the file as it
  is now. When derivation is ambiguous it **refuses** — a loud failure instead
  of a silent corruption.
- **Labels are keyed HMACs, not hashes.** Personal data is low-entropy; a bare
  hash of a name or phone number is brute-forced in seconds. Keying also makes
  labels deterministic, which is what keeps prompt caching working.
- **Memoized per block.** Measured on a 2.1 MB body: 858 of 861 blocks reused,
  1168 KB reduced to 1.8 KB actually scanned.

And the honest part: most of the guards in this codebase exist because
something failed first. A pipeline divergence that corrupted edits. A stale
decision that left a user unmasked for seven minutes *while reporting
protection*. A regex that hung the proxy for 42 seconds on a pasted minified
file — and a safety screen that missed it because its probes were 60 characters
long. `.json` files silently skipped by the scrubber. Each is described in
[docs/architecture.md](docs/architecture.md) next to the design it produced,
because if you are deciding whether to trust this, the failures tell you more
than the feature list.

---

## License

MIT — see [LICENSE](LICENSE).
