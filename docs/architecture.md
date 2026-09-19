# Architecture

How the proxy is put together, and why each piece is shaped the way it is.
Most of these shapes are the result of something going wrong; where that is
the case, the failure is described rather than hidden, because the failure is
the argument for the design.

---

## 1. Where it sits

Claude Code talks to the API over HTTPS. You cannot inspect or rewrite that
traffic from outside without terminating TLS, which means a private CA, a
trust-store change, and a machine-in-the-middle on your own credentials.

You do not need any of that, because Claude Code honours `ANTHROPIC_BASE_URL`.
Point it at loopback and it hands you the request before TLS begins.

```
┌─────────────┐   plain HTTP    ┌──────────────────┐   HTTPS (TLS verified)   ┌────────────┐
│ Claude Code │ ──────────────► │  redaction proxy │ ───────────────────────► │ Anthropic  │
│             │   127.0.0.1     │   (this repo)    │   optionally tunnelled   │    API     │
└─────────────┘                 └──────────────────┘                          └────────────┘
       ▲                                 │
       │      resolved tool inputs       │
       └─────────────────────────────────┘
```

Two consequences worth being explicit about:

- **No TLS interception.** The proxy speaks plain HTTP on loopback and makes
  its own verified HTTPS connection outward. No CA is installed, nothing in
  your trust store changes.
- **Loopback binding is a hard requirement, not a default.** This process
  accepts unauthenticated plaintext and forwards it with your API credentials
  attached. Exposed on any other interface it would hand anyone on the network
  an authenticated channel to your account.

---

## 2. The outbound pipeline

Every string leaving for the API passes through three stages, in this order:

```
   real text
       │
       ▼
┌──────────────┐   "Jane Q. Testerson" ──► "[PII:personal:a1b2c3d4e5f60718]"
│  1. REDACT   │   keyed HMAC label, deterministic, one-way
└──────┬───────┘
       ▼
┌──────────────┐   "C:\Users\realname" ──► "example-user"
│  2. ALIAS    │   bidirectional: reversed on the way back in
└──────┬───────┘
       ▼
┌──────────────┐   "+0530" ──► "+0000",  "Asia/Kolkata" ──► "UTC"
│ 3. NORMALIZE │   one-way, no label, nothing to reverse
└──────┬───────┘
       ▼
  what the model sees
```

The order matters. Redaction runs on the original text so its offsets stay
meaningful for stage 4 below. Normalization runs last so a timestamp rewritten
to UTC is not then re-scanned as a phone number.

### Three kinds of transform, deliberately different

| | Example | Reversible? | Why |
|---|---|---|---|
| **Redact** | your name, email, phone, IP, MAC | via derivation | The model must not see it, but a local tool may still need the real value |
| **Alias** | OS username, hostname, project root | yes, both ways | Paths must round-trip or every file tool breaks |
| **Normalize** | timezone offset, locale, OS build | no | Nothing needs the original back, so keeping a way back is pure risk |

### Labels are keyed, not hashed

A label is `HMAC-SHA256(k_label, value)` truncated to 16 hex characters, where
`k_label` is derived from a 32-byte master key via HKDF.

A plain hash would be useless here. Personal data is low-entropy — a name, a
phone number, a city — and a bare `SHA-256` of any of them is brute-forced in
seconds with a wordlist. Keying it means a label discloses nothing without the
key, which never leaves the machine.

The same property makes labels **deterministic**, which is what lets prompt
caching keep working: the same value always produces the same label, so an
unchanged conversation prefix stays byte-identical across requests.

---

## 3. Inbound: getting real values back to tools

The model sees `[PII:personal:a1b2…]`. When it then asks to edit a file, the
tool needs the real text or the edit fails.

**No map of labels to values is ever stored.** Instead the real value is
re-derived on demand:

```
model sends:  Edit(file, old_string = "const N = \"[PII:personal:a1b2…]\";")
                                │
                                ▼
                  1. read the file from disk, NOW
                  2. run the SAME pipeline over it  ──►  span map
                  3. translate the model's offsets back through the map
                  4. slice the real text at the real offsets
                                │
                                ▼
tool receives: Edit(file, old_string = "const N = \"Jane Q. Testerson\";")
```

Deriving rather than storing has three consequences, all of them good:

- there is no map to leak, and nothing to keep in sync
- offsets always reflect the file as it is *now*, so a stale entry can never
  write a removed value back into a file
- when derivation is ambiguous it **refuses**, and a refused edit is a loud
  failure rather than a silent corruption

> **Both directions must use the same pipeline definition.** They did not, once.
> `walk.js` and `resolver.js` each had their own idea of "what the model sees"
> and drifted twice — aliasing and normalization were applied outbound but not
> reversed inbound, so any line they touched could not be edited at all. Both
> now route through `pipeline.js`, and `makeContext` builds one **frozen**
> config object that the resolver takes **by reference**, so they cannot even be
> given different rules.

---

## 4. Local vs remote tools

```
                        ┌─────────────────────────────┐
     tool_use ────────► │  is the tool name listed in │
                        │      remoteTools[] ?        │
                        └──────────┬──────────────────┘
                          no       │        yes
                  ┌────────────────┘        └────────────────┐
                  ▼                                          ▼
    ┌──────────────────────────┐              ┌────────────────────────────┐
    │ LOCAL: resolve labels,   │              │ REMOTE: pass through       │
    │ reverse aliases, give    │              │ COMPLETELY UNMODIFIED.     │
    │ the tool real values     │              │ Labels and aliases stay.   │
    └──────────────────────────┘              └────────────────────────────┘
```

A local MCP server runs as you and could read your files directly, so
withholding data from it buys nothing. A remote one is a third party and gets
labels only.

> **This list fails open by design.** Anything *not* listed is treated as local
> and receives real values. That is what makes local servers work without
> configuration — and it means adding a new remote MCP server without listing
> its prefix will hand it your real data. Prefix matching is anchored, so
> `mcp__zen__` covers every tool on that server.

---

## 5. Egress: masking where the request comes from

Everything above hides *what* is in a request. Nothing above hides *where it
came from*. That is a separate layer, and it is optional.

```
         ┌───────────────────────── egress.mode ─────────────────────────┐
         │                                                               │
      "off"                      "auto"                              "on"
         │                          │                                  │
         ▼                          ▼                                  ▼
   never tunnel      ┌─────────────────────────────┐             always tunnel
                     │ what country does a DIRECT  │
                     │ connection appear to be in? │
                     └──────────┬──────────────────┘
                     == home    │    != home
                  ┌─────────────┘    └──────────────┐
                  ▼                                 ▼
          exposed → TUNNEL            already masked → go direct
                                      (a VPN is doing the job)
```

`auto` exists so that a VPN and this proxy do not stack pointlessly. When your
VPN is up, the tunnel stays out of the way; when it drops, the tunnel engages.

### Fail closed

If no proxy can be reached, the request is **refused**. A silent direct
connection would leak the exact address the tunnel exists to hide, and it would
keep working — so nothing would ever prompt you to look.

`onFailure: "direct"` opts out for people who would rather be unmasked than
blocked. It warns on every fallback and keeps a sticky counter that the
notifier and status reporting surface until you change the setting back.

### A stale decision is not a decision

> Auto mode once observed a VPN exit, correctly decided "already masked", and
> then held that decision for its full 15-minute re-check interval. The VPN was
> switched off. For seven minutes every request went out from the real address
> **while the system reported protection**.
>
> Staleness is indistinguishable from a changed network, so an expired
> observation now reads as *unknown*, and unknown means tunnel. Observations
> expire after 120 s, polling runs at 90 s to stay inside that window, and the
> decision is recomputed **per connection** rather than read from storage.

### What the tunnel operator can and cannot see

```
  you ──► proxy operator ──► api.anthropic.com
              │
              │  CAN see: destination host, timing, byte volume
              │  CANNOT see: request body, your API key, model output
              └─ because TLS is negotiated end-to-end THROUGH the tunnel,
                 with certificate verification ON. A proxy attempting
                 interception is refused, not trusted.
```

DNS is resolved **at the proxy** (SOCKS5 `ATYP=3`, or CONNECT by hostname).
Resolving locally would hand the destination to your ISP's resolver, revealing
who you are talking to even though the connection itself is tunnelled.

---

## 6. Headers are a separate channel

`transformBody` walks JSON. Headers do not go through it, and they carry
plenty:

| Header | Carries | Action |
|---|---|---|
| `accept-language` | your region (`en-IN`, `pt-PT`) | normalized to a generic value |
| `x-stainless-os` / `-arch` | OS and CPU | generalized |
| `x-stainless-runtime-version` | exact Node build, a narrow fingerprint | dropped |
| `x-forwarded-for`, `x-real-ip`, `forwarded`, `via` | a literal IP | dropped outright |

Measured before: **9 of 9** fingerprinting headers reached upstream verbatim.
After: **3 of 9**, and those three are identical for every user of the same
Claude Code version, so they do not individuate you.

Header values are never *labelled*. A `[PII:…]` in a header would break the
request rather than protect it.

---

## 7. Performance

The transform runs on every request, and conversation history is resent in
full each turn, so a naive implementation would re-scan the entire transcript
every time.

**Per-block memoization**, keyed by an HMAC of the block content:

```
  request 1:  861 blocks,  861 transformed
  request 2:  864 blocks,    3 transformed,  861 served from memo
```

Measured on a live 2.1 MB body: **858 of 861 blocks reused**, 1168 KB of text
reduced to 1.8 KB actually walked.

The memo is bounded and evicts, because an unbounded cache in a long-lived
process is a leak. Signed `thinking` blocks are passed through by identical
object reference — rewriting one would invalidate its signature.

> **Regex cost is the other half.** The shipped email pattern was quadratic on
> any long run of word characters containing no `@`: at every start position the
> leading class consumed greedily to the end of the run, failed, and backtracked
> one character at a time. Measured 1k→3 ms, 4k→45 ms, 16k→741 ms, and a single
> 100 KB message hung the proxy for **42 seconds** — a denial of service on your
> own session, from a minified bundle pasted into a chat.
>
> Bounded quantifiers fixed it (100 KB in 115 ms) and are RFC-correct anyway.
> The load-time backtracking screen that exists to catch exactly this had been
> passing it, because its probes were 60 characters long. Probe **length**, not
> variety, is what detects quadratic behaviour; they are now 20 000.

---

## 8. Local residue

The proxy protects the API boundary. It does nothing about what Claude Code
writes to disk, because those files are written before the proxy sees anything
and are never sent anywhere.

```
  ~/.claude/projects/**/*.jsonl        conversation transcripts
  ~/.claude/projects/**/tool-results/  the CONTENTS of files you read
  ~/.claude/file-history/              edit snapshots
  ~/.claude/shell-snapshots/           shell state
```

Measured on a real machine: **41 906 occurrences of personal data across 608
files**.

Scrubbing them is *the same operation* as rendering for the model, so it reuses
the same pipeline with the same key. Two consequences: the labels written are
byte-identical to what the proxy would have sent, and `--resume` keeps working,
because a label is what the model would have been shown anyway.

Safety properties, in order of how much they matter:

1. dry run by default
2. backs up every file before touching it
3. skips anything modified recently, so it can never rewrite the transcript of
   the session you are sitting in
4. `.jsonl` parsed **per line**, `.json` as **one document** — an unparseable
   line is left byte-identical rather than guessed at
5. verifies afterwards that every line still parses

> `.json` files were originally routed to the line-based scrubber. Every line of
> a pretty-printed document fails to parse, so the file was counted
> "unparseable" and silently skipped — and those were the `tool-results` files,
> the densest concentration of real data on disk.

---

## 9. Module map

| File | Responsibility |
|---|---|
| `start.js` | entry point: load config, wire everything, listen |
| `server.js` | HTTP server, request/response plumbing, health + control endpoints |
| `rules.js` | load and compile `redact-rules.json`; backtracking screen |
| `spans.js` | redact text, emit a span map |
| `aliases.js` | bidirectional identity aliasing, separator-agnostic |
| `normalize.js` | one-way fingerprint rewrites |
| `pipeline.js` | **the single definition** of what the model sees, and how to map back |
| `walk.js` | traverse a request body, memoize, skip what must not change |
| `resolver.js` | re-derive real values for tool inputs |
| `sse.js` | transform streaming responses |
| `headers.js` | request header hygiene |
| `egress.js` | SOCKS5 / CONNECT tunnelling, health, tunnel decision |
| `providers.js` | discover dependable free egress options |
| `pool.js` | optional: fetch and verify proxies from lists (off by default) |
| `cache.js` | encrypted, TTL'd label cache for values with no file to derive from |
| `keys.js` | master key loading, HKDF subkey derivation |
| `status.js` | publish state for external readers |
| `notify.js` | OS-native alerts when protection is lost |
| `audit.js` | append-only log of counts, never values |

---

## 10. Design rules, learned the hard way

Each of these is here because violating it caused a real failure.

1. **Fail closed on transform, fail open on parse.** A parse failure means
   there was nothing to redact. A transform failure means we found something
   and then crashed — forwarding that body would leak exactly what we choked
   on.
2. **Anything unverifiable reports as NOT protected.** A status line that
   wrongly claims protection is worse than none: it actively discourages
   looking.
3. **One definition of the pipeline, shared by reference.** Two copies drift,
   and the drift corrupts files.
4. **A screen must be able to detect what it screens for.** Probe length,
   threshold choice, search case-sensitivity — a check that cannot see the
   thing it looks for converts a real leak into a clean bill of health.
5. **Silence must mean safe.** "Ran and found nothing" has to be
   distinguishable from "never ran".
6. **Never log the value you are protecting.** Not even in the branch where
   protection failed — *especially* not there.
