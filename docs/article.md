# I measured what Claude Code actually sends. Then I built a proxy to stop it.

*A local redacting proxy for AI coding assistants. Zero dependencies, 489
tests, and a list of the things it does **not** protect.*

---

## The thing nobody tells you about AI coding assistants

You used to decide what to upload. You picked the file, you pasted the
snippet, you knew what left the building.

That is over. An AI coding assistant reads whatever it needs — your files,
your stack traces, your shell output, your paths — and assembles the request
itself. **You are no longer the one deciding what leaves.**

I wanted to know how much that actually mattered, so I measured it. Here is
what was in my own requests, before I typed a single word:

- my **OS username**, in every absolute path
- my **hostname**, in shell output
- my **timezone offset**, which pins my region about as precisely as an IP
- my **OS build and CPU architecture**, in request headers
- my **locale**, in `accept-language`
- my **IP address**, which pins my city

And then in the content itself: client names in a refactor, a customer email
in a test fixture, an internal hostname in a config file I asked about.

None of that was a mistake. It is the tool working correctly.

Then I scanned what had already accumulated on disk — transcripts, tool
results, edit snapshots, all written *before* anything gets sent:

```
41,906 occurrences of personal data across 608 files
```

That is not a leak. That is a normal few weeks of using the thing.

---

## Why the obvious answers are all bad

**"Be careful."** You are not assembling the requests. Care is not the
mechanism.

**"Ban the tool."** You lose the productivity, and people move to unmanaged
personal accounts. Now you have the same exposure with none of the
visibility.

**"Wait for an enterprise tier."** You are exposed today. And when it
arrives, you are trusting a policy rather than a mechanism.

I wanted a mechanism. Something that removes the data before it leaves my
machine, and does it *without breaking anything* — because a privacy tool
that makes your editor worse gets switched off in a week.

---

## What I built

A local proxy that sits between Claude Code and the API. You point
`ANTHROPIC_BASE_URL` at `127.0.0.1`, and it rewrites requests on the way out.

```
  what you type                      what the API receives
  ─────────────                      ─────────────────────
  I’m Jane Q. Testerson,             I’m [PII:personal:a1b2c3d4],
  jane@example.com                   [PII:email:9f8e7d6c],
  +1-555-0142                        [PII:phone:1a2b3c4d]
  C:\Users\jtesterson\proj           C:\Users\example-user\proj
  …from 203.0.113.42 (IN)          …from 198.51.100.7 (DE)
  x-stainless-os: Windows            x-stainless-os: Unknown
```

Plain HTTP to loopback. **No TLS interception, no certificate to install** —
the thing most corporate proxies get wrong and the reason people disable
them.

### The part that makes it usable

Here is the problem that took the longest to solve. If you redact
`C:\Users\jane\project` out of a request, the model answers about a path that
does not exist. Then it asks to edit that file, and the edit fails.

So redaction has to be **reversible in one direction only**:

- **Model-bound:** real values → labels
- **Tool-bound:** labels → real values

The model reasons about `C:\Users\example-user\proj`. When it asks to edit
that file, the tool receives the real path. **The model works with labels;
your tools work with reality.**

### Three decisions that turned out to matter

**Labels are deterministic.** `HMAC-SHA256(key, value)`, so the same value
always produces the same label. This sounds like a detail. It is not: a
random token per occurrence would change the prompt prefix on every request
and **silently destroy prompt caching**. Your bill would quietly multiply and
you would never connect it to your privacy tool.

**There is no stored mapping.** I nearly built one — a TTL'd encrypted map
from label to value. Then I realised what I was building: a single file
containing every piece of personal data I had ever sent, which now needs
protecting. Instead, resolution is *derived*: re-read the file, re-run the
same redaction, translate offsets through a span map. **There is no database
of your PII, because there is no database.**

**It fails closed.** If a transform fails, the request does not go. If IP
masking was requested and the tunnel is down, the request is refused rather
than sent unmasked. You get an outage, never a silent exposure. That is the
right trade for a privacy tool, and it needs to be a deliberate choice
because the alternative is always more convenient.

---

## The bugs are the interesting part

Anyone can write a regex that matches an email. What took the time was
everything that went wrong afterwards. A few, because I think the failure
modes are more useful than the feature list.

### The pattern that took 42 seconds

The shipped email pattern passed a catastrophic-backtracking screen. Then it
hung the proxy for **42,698 ms** on a 100 KB message.

The screen was not wrong, it was too gentle: it tested 60-character probes.
Quadratic backtracking on 60 characters costs microseconds. Now every pattern
is run in a killable child process against 20,000-character adversarial
input. Same pattern, bounded: **10 ms**.

### The alias that rewrote my source code

Aliases are bidirectional — that is what makes tools keep working. Which
means anything matching the alias on the way *in* gets replaced with the real
value.

I used an alias that was also an ordinary English word. It was substituted
into 30 places across my repository, including committed history, before I
noticed. The tool now **refuses to start** on a risky alias. Not a warning —
refuses. Losing the proxy is recoverable; silently corrupting source is not.

### The watchdog that never ran

I added a 5-minute scheduled task to restart the proxy if it died. Registered
fine. Status: `Enabled`, `Ready`. Correct action.

`Last Run Time: 30-11-1999`. It had never fired, once.

`schtasks` creates every task with `DisallowStartIfOnBatteries=true` and
offers no flag to change it. On a laptop, unplugged, Windows silently
declines to start the task and reports nothing anywhere. **A privacy watchdog
that only works while plugged in is worse than none, because the thing you
would check to find out says it is fine.**

### The pattern that redacted the tool's own output

I added a rule for `api_key = <something long>`. Reasonable rule. It also
matches `api-key:f9cff609...` **inside the proxy's own label**
`[PII:google-api-key:f9cff609...]`, producing a nested label that no longer
resolves.

Two things break: tools start receiving labels instead of real values, and
the transcript scrubber — which re-runs the pipeline over files that already
contain labels — degrades its own output on every pass.

The fix is in the engine, not the pattern: nothing may be redacted inside an
existing label region. Any pattern can collide with the label format,
including one a user writes, and a user-written rule must not be able to
break resolution.

### The check that passed because it checked nothing

A pre-push gate to stop personal data reaching the public repository. It
printed:

```
GATE PASSED: none of [identity, personal] present.
```

It had scanned **zero files**. The value of `--fail-on` was being parsed as a
path, so it scanned a directory named `identity,personal`, found nothing, and
reported success.

A gate that passes because it scanned nothing is worse than no gate. It
produces exactly the green tick someone is relying on.

---

## The pattern behind all of them

Every one of those bugs is the same shape: **something reported success it
had not earned.**

That is the failure mode that matters for a privacy tool, and it is not the
one people design for. A crash is loud. A tool that says `PROTECTED` while
data leaks is quiet, and it stops you looking — which is strictly worse than
having no tool at all.

So the design rule became: **anything unverifiable reports as NOT protected.**

The dashboard computes its verdict client-side from the raw data and refuses
a pre-judged field from the server. The end-to-end check opens a real TCP
connection to the tunnel rather than reading a cached health flag — because
that flag turned out to be hours stale and still saying `ok` after the tunnel
had dropped. Retention records passes that removed nothing, because
"nothing to do" and "silently stopped running" look identical otherwise.

---

## What it does not do

The most important section, and the one a serious reviewer reads first.

- **Anything you type yourself.** It redacts listed literals and pattern
  categories, not intent. Paste a secret and it goes.
- **Other programs' traffic.** It covers Claude Code's API calls. An MCP
  server making its own requests, or anything `Bash` runs, leaves from your
  real IP. Only an OS-level VPN covers everything.
- **Your account identity.** Anthropic knows who you are from billing. The
  goal is keeping personal data out of payloads and location out of metadata
   — not anonymity from your provider. Claiming otherwise would be the first
  lie.
- **Compliance.** It does not make you or your company compliant with
  anything. No tool does. What it gives you is a technical control with
  evidence: data minimisation enforced at the boundary, a record of every
  redaction pass, retention limits the tool enforces, and dated values-free
  output you can attach to a review.

---

## The feature I deleted

I built a free-proxy pool: fetch the public lists, test each candidate
through a real tunnel, verify it actually masks, rank by latency, cache the
winners. It worked.

It worked exactly once per proxy.

```
pool: 5 verified proxies available    (fastest 2572ms)
...seconds later...
all 5 handshakes timed out -> request REFUSED
```

Every one passed full verification — TLS-verified connection, echo service
confirming a different exit address — then refused the *next* connection.
Roughly a 6% hit rate, 2–6 second latencies on a streaming API.

**Verification does not predict usability** for a resource shared with
everyone who scraped the same list. No scheduling algorithm fixes that; you
cannot schedule reliability into a host that disappears.

The code still ships, with no default sources, and the documentation tells
you to use Cloudflare WARP or your own SSH tunnel instead. I think shipping
the measurement that killed a feature is more useful than shipping the
feature.

---

## By the numbers

```
489 tests          0 runtime dependencies      0 dev dependencies
41 source files    ~10,400 lines               Node stdlib only
```

| | |
|---|---|
| On-disk residue | 41,906 → 220 occurrences across 851 files. 173,653 lines rewritten, **0 lines lost** |
| Fingerprinting headers | 9 of 9 → 3 of 9 reaching the API |
| Residue scanning | 124 s → **3.3 s**, via an index keyed on a fingerprint of your rules |
| Catastrophic regex | 42,698 ms → 10 ms, and now screened before loading |
| Shipped patterns | 20 secret/PII patterns, each false-positive tested |

The dependency count is deliberate. This process sits in front of every API
request and handles personal data in plaintext. Every dependency would be
code with that same access, trusted on someone else's word.

---

## Try it

```bash
git clone https://github.com/<owner>/claude-code-privacy-proxy
cd claude-code-privacy-proxy
npm test            # 489 tests, no network required
npm run help        # what all 24 commands do
npm run doctor      # checks the whole chain end to end
```

MIT licensed. Windows, macOS and Linux, though the supervisor integration is
Windows-first because that is what I use.

If you find a way to make it claim protection it is not providing, that is
the bug I most want to hear about — privately, via GitHub's security
reporting. And please use fake data when you report it. It would be a poor
showing for this particular project to collect real PII in its own issue
tracker.
