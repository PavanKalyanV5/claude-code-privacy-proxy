# API Redaction Proxy — Design

**Date:** 2026-09-17
**Status:** Approved design, not yet implemented
**Supersedes:** the hook-based redaction suite (archived in `temp/`)

## Goal

Strip identifying information out of everything Claude Code sends to the
Anthropic API, at a single chokepoint, without blocking any tool call.

The hook-based approach this replaces could only reach tools it had a hook for.
It covered Read/Grep/Glob and Bash, and structurally could not cover MCP tool
results, WebFetch, or `@file` mentions — no hook can rewrite a tool's output. It
also imposed six classes of blocked tool call as the price of that partial
coverage.

### Threat model

Two audiences, with different achievable outcomes. Conflating them leads to
either false comfort or wasted effort.

| | To Anthropic | To third parties (MCP servers, other model providers, logs, shared transcripts) |
|---|---|---|
| Account identity | **known and accepted** — billing and rate limiting require it | hidden |
| Personal data in content | removed | removed |
| OS username, hostname | removed | removed |
| Machine fingerprint (`device_id`) | see mechanism D | hidden |
| Timezone / location | removed from content | removed |
| IP address | optional, via egress tunnel | optional, via egress tunnel |

Against third parties, genuine anonymity is achievable. Against Anthropic this
is **content minimization**: the account is authenticated, so the goal is that a
request carries an account identifier and nothing else identifying the person,
the machine, the location, or the client being worked for.

## Non-goals

- **Transcripts on disk** (`~/.claude/history.jsonl`, session files). Handled
  separately.
- **The user's own typed prompts.** Accepted risk — shared deliberately.
  (Covered anyway as a side effect; not a requirement.)
- **The `x-api-key` header.** Removing it causes rejection.

## Feasibility (established by spike, 2026-09-17)

A zero-modification pass-through proxy was built, pointed at via
`ANTHROPIC_BASE_URL`, and verified against a real session:

- `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>` is honored. **Plain HTTP to
  loopback works — no TLS interception, no CA installation, no MITM.**
- Auth travels as `x-api-key` and passes through untouched.
- The full request body (94.7 KB for a trivial turn) is available in the clear
  inside the proxy.
- Responses are `text/event-stream`.
- A `HEAD /api/hello` preflight occurs and must pass through transparently.
- `anthropic-beta` includes `prompt-caching-scope-2026-01-05` and
  `context-1m-2025-08-07`.

## Mechanisms

### A. PII redaction — keyed labels

Personal data in request content is replaced with a deterministic label:

```
label = "[PII:" + category + ":" + HMAC-SHA256(k_label, value).hex[0..16] + "]"

alice@corp.io   ->  [PII:email:7f3a2b1c9d04e618]
+1 555 867 5309 ->  [PII:phone:b204e7719a31c05d]
```

**Why HMAC and not a bare hash.** A plain `sha256(value)` is reversible for
personal data, because personal data has almost no entropy. Anyone holding a
label can compute candidates themselves:

| Value type | Search space | Time, one modern GPU |
|---|---|---|
| 10-digit phone | 10¹⁰ | under a second |
| Common full name | ~10⁶ name list | instant |
| Email | ~10¹⁰ breach corpora | seconds |

Keying the hash with a 32-byte secret that never leaves the device removes the
attacker's ability to compute candidates at all. Brute force is not slowed; it
is eliminated.

Properties retained: **deterministic** (same key + value → same label), which
prompt caching requires — a non-deterministic label would change the cached
prefix every turn and make each request a full re-read. Fixed 16-hex width
leaks nothing about value length.

The **category is retained** (`email`, `phone`, `personal`) because it measurably
helps the model reason about code. It reveals the type, never the value, and the
type is usually obvious from surrounding context anyway.

Key rotation invalidates every label and every cache entry, so it is a
deliberate manual act, never scheduled.

### A2. Reverse resolution — derivation first, cache second

When Claude returns an `Edit` whose `old_string` contains labels, the real
values must come back. Two sources, in this order:

**1. Derivation from the file on disk (authoritative).**

1. Read the real file.
2. Re-redact it. Redaction is deterministic, so this reproduces byte-identical
   text to what Claude saw — and while doing it, record a **span map**:
   `{ realStart, realEnd, redStart, redEnd, value }` per replacement.
3. Locate `old_string` in the redacted text.
4. Translate its offsets through the span map to real offsets.
5. Resolve labels in `new_string` from the same span map.
6. Rewrite the tool_use input to real values, so the Edit lands correctly.

Derivation is preferred for `Edit`/`Write`/`MultiEdit`/`NotebookEdit` because
offsets must reflect the file **as it is now**. A stale mapping could write PII
back into a file it had been removed from.

**2. Encrypted TTL cache (fallback, and the only source where no file exists).**

A label → value store, needed for cases derivation cannot serve:

- **Labels in Bash commands** — no target file to derive from.
- Labels whose source file has since changed or been deleted.

| Property | Value |
|---|---|
| Encryption | AES-256-GCM under `k_cache` |
| TTL | 30 days, with idle eviction |
| Location | `~/.claude/redact-cache.enc` |
| Used for | Bash and non-file tools; fallback only, never for Edit offsets |

**What the encryption does and does not buy.** On this machine the proxy, the
key, and the cache are all readable by the same user account, so this does not
defeat a local attacker. What it does prevent is **accidental** exposure — the
file being swept into a cloud sync, a backup, a shared folder, or a support
bundle. That is the realistic threat for a file of this shape, and encryption
handles it well.

### B. Identity aliasing — static, bidirectional

Structural identifiers that must survive a round trip or nothing works. A
`[PII:...]` label inside a path would break every Read, Edit, Write, Bash and
Glob, because the path would not exist on disk; an alias still *looks* like a
path, so the model reasons about it correctly.

```
outbound:  C:\Users\SOMEONE\   ->  C:\Users\anon\
           <hostname>       ->  host
           work\AcmeCorp\   ->  work\clientA\
inbound:   reverse of the above
```

Static pairs in config — no hash, no map, nothing persisted. Covers the **OS
username** (present in `cwd` and essentially every tool call), the **hostname**,
and **project roots** (a path like `work\AcmeCorp\billing-migration` names the
client, the project, and the nature of the work in every request). Deliberately
nothing else; every addition here is a reversibility risk.

### C. Environment normalization — one-way

Fingerprints needing no round trip:

- **Timezone.** Observed live: `git blame` emitted
  `2026-09-17 21:08:56 +0530`, pinning the region precisely. Every `git log`,
  `ls -la`, `date`, and file mtime reaching the model carries it. Outbound
  offsets and local timestamps are normalized to UTC.
- **OS build string.** The system prompt carries `Windows 11 Pro 10.0.26200`, a
  precise machine fingerprint. Generalized to `Windows 11`. `win32` is retained,
  since tools legitimately branch on it.
- **Git remote / org URLs.** `github.com/<org>/<repo>` frequently names an
  employer or client. A generic rule redacts the org and repo components rather
  than relying on every name being listed in `literals`.

### D. `metadata.user_id`

Captured from a live request:

```json
{ "device_id": "<64 hex>", "account_uuid": "", "session_id": "<uuid>" }
```

`device_id` is a **stable SHA-256 machine fingerprint persisting across every
session on this computer**; `account_uuid` is empty; `session_id` is ephemeral.

This is a persistent *machine* identity layered on the account identity the
`x-api-key` already provides, so it is a legitimate target. Against that: it is
plausibly used for abuse detection, and altering it may trigger account security
checks.

**Default: unmodified, presence logged, with an opt-in `randomizeDeviceId`
flag.** Not changed silently, because the failure mode is account-level rather
than local.

### E. Network egress — optional tunnel

The proxy connects from the real IP; TCP sits below anything it rewrites. Since
the proxy is already the single egress point, an optional **upstream SOCKS5/VPN**
option routes it through a tunnel, removing the IP and its geolocation.

Caveat to document: against Anthropic this buys less than it appears, since the
account's billing country is already known, and unusual IPs can trip security
checks. Against third parties it is effective. If configured and the tunnel is
down, **fail closed** — never silently fall back to direct egress.

### F. MCP tool policy — two independent, configurable dimensions

**This reverses an earlier decision in this spec, on measured evidence.**

The original design kept the alias for every `mcp__*` tool so a third-party
server could never learn the real username. Audited against the built system,
that meant **every MCP tool received a path that does not exist on disk** — 8 of
11 tools usable, 3 broken — and the promised opt-in was never implemented, so
there was no way to recover a working tool.

What changed the call is how little the alias protects. It covers only the OS
username, hostname and project roots. A **local** MCP server already runs as the
user and can read `%USERNAME%` from its own environment, so withholding it costs
a working tool and buys nothing. A **remote** server is different.

Two dimensions, each independently configurable, because they carry different
risk:

| Dimension | What it exposes | Default | Config key |
|---|---|---|---|
| Alias reversal | OS username, hostname, project root — in paths | **on** for all tools | `aliasReverseExclude` (prefixes that keep the alias) |
| PII label resolution | the user's actual name, email, phone | **off** for `mcp__*` | `resolveLabelsFor` (prefixes opted in) |

The asymmetry is deliberate. Reversing an alias hands over a username; resolving
a label hands over personal data. So aliases default open (tools work) with an
exclude list for remote servers, while labels default closed with an explicit
allowlist for a local server the user trusts and that genuinely needs real
values — a local database or search server being the plausible case.

```json
  "aliasReverseExclude": ["mcp__zen__"],
  "resolveLabelsFor": []
```

A server named in neither list gets real paths and labelled personal data, which
is the right posture for the common case: a local tool that needs to find files
but has no business knowing who the user is.

## Cryptography

One master key, subkeys derived by purpose. Reusing a key across two primitives
is poor hygiene, so they are separated.

```
master  = 32 random bytes            (~/.claude/redact.key, restricted ACL)
k_label = HKDF-SHA256(master, "label")    -> HMAC key for PII labels
k_cache = HKDF-SHA256(master, "cache")    -> AES-256-GCM key for the TTL cache
k_memo  = HKDF-SHA256(master, "memo")     -> HMAC key for in-memory memo keys
```

**Key storage: a 32-byte file with ACLs restricted to the user account**, in
`~/.claude/`. Chosen for simplicity and zero dependencies over DPAPI.

The residual risk this accepts: the key is **plaintext on disk**, so anything
that captures `~/.claude/` captures both the key and the encrypted cache
together, which collapses the cache's protection. Mitigation to document at
install time: **exclude `~/.claude/` from cloud sync and backup.** That is the
one operational requirement this choice creates.

All key material is generated locally and **never transmitted**. The proxy
stores and logs no credentials; auth headers are forwarded verbatim and never
written to the log.

**Bind `127.0.0.1` only, never `0.0.0.0`.** The proxy accepts unauthenticated
plaintext HTTP and forwards it with the user's credentials attached, so exposing
it on any other interface would hand anyone on the network an authenticated
channel to the API. Loopback binding is a hard requirement, not a default.

## Architecture

```
Claude Code ──http──> redaction proxy ──https──> [tunnel] ──> api.anthropic.com
                       │
                       ├── outbound: PII -> keyed label        (A)
                       │             identity -> alias         (B)
                       │             timezone/OS/git-remote    (C)
                       └── inbound:  alias -> identity         (B)
                                     label -> value            (A2)
                                     tool_use inputs only
```

| File | Role |
|---|---|
| `proxy/server.js` | HTTP listener, upstream forwarding (optional tunnel), transparent pass-through for non-`/v1/messages` paths |
| `proxy/redact-request.js` | Walks the request body; applies A, B, C; memoizes per block |
| `proxy/resolve-response.js` | SSE parser, per-block buffering, alias reversal, label resolution |
| `proxy/spans.js` | Span-tracking redactor: redacted text plus offset map |
| `proxy/keys.js` | Master key generation, ACLs, HKDF subkeys |
| `proxy/cache.js` | AES-256-GCM TTL cache |
| `proxy/rules.js` | Loads and compiles `redact-rules.json`; pattern validation and watchdog |
| `proxy/health.js` | `GET /_health`, audit log, SessionStart liveness assertion |
| `redact-rules.json` | **Retained** — live PII list, plus `aliases`, `normalize`, `egress` blocks |

## Outbound transform

The spike established which fields carry user data. Walking only those cuts the
work from 94.7 KB to ~30 KB for a small turn.

**Transform:** `system[].text`; and `messages[].content` when a bare string,
plus `.content[].text`, `.content[].content` (tool results) and
`.content[].input` (tool_use inputs) when a block array. **Both content forms
occur in practice.** Re-redacting tool_use inputs keeps history consistent after
the inbound transform injected real values.

**Leave untouched:**

- `tools[]` — static product documentation, 45% of the body, no user data.
  Skipping it is the largest single performance decision here.
- `thinking` / `redacted_thinking` — **cryptographically signed; altering one
  byte invalidates the signature and the API rejects the request.** Safe to skip:
  the model only ever saw labels, so its thinking contains labels, not personal
  data.
- Base64 image and document payloads — see limitations.

## Performance

**The dominant cost is re-redacting unchanged history, and it is avoidable.**
The entire conversation is re-uploaded every turn, so at large context the body
is megabytes, not kilobytes:

| Context | Body content | Naive JS at ~10 MB/s |
|---|---|---|
| 30 KB (measured) | 30 KB | 3 ms |
| ~250 K tokens | ~1 MB | ~100 ms |
| ~1 M tokens | ~4 MB | **~400 ms every turn** |

**Per-block memoization** removes this. Conversation history is append-only and
redaction is deterministic, so a block redacted last turn redacts identically
this turn:

- Key each message/system block by `HMAC-SHA256(k_memo, rawBlockBytes)`.
- In-memory LRU (bounded, ~2000 entries), holding the **transformed** block
  against those keys. Keys are keyed hashes rather than plain ones, so they
  reveal nothing about the content they index.
- Per-turn work becomes proportional to **new** content only.

**What the memo does and does not contain.** Values the rules match are stored
in label form, so no redactable personal data is held. It is *not* true that the
memo contains no personal data at all: a `thinking` block passes through
untransformed by design (it is signed and cannot be rewritten), so an assistant
block carrying one is cached with that text intact. This adds no exposure — the
same text is already in the request body in process memory, the memo is never
persisted, and it dies with the process — but the distinction matters, because
"the cache holds nothing sensitive" is the kind of claim that later gets relied
on. Suppressing memoization for thinking-bearing blocks was considered and
rejected: thinking is present in most assistant turns, so it would remove
nearly all of the benefit to buy nothing real.

Result: **~1 ms per turn at any context size.** This is algorithmic; no language
choice substitutes for it. For comparison, a native implementation without
memoization would still spend ~40 ms on a 4 MB body.

| Metric | Hooks (measured) | Proxy (target) |
|---|---|---|
| Per tool call | ~50 ms × 1–2 node spawns | 0 |
| Per turn, 30 KB context | — | 3 ms cold / ~1 ms memoized |
| Per turn, 1 M context | — | ~1 ms memoized (~400 ms without) |
| Per Edit | — | one file read + re-redact |
| Grep/Glob warm | 96 ms | 0 — no mirror |
| Disk footprint | mirror of every project | one key + one encrypted cache |
| File size limit | 2 MB | none |
| Blocked tool calls | 6 classes | 0 |

## Language: JavaScript

Decided deliberately, not by default.

- **Throughput is not the differentiator.** With memoization the hot path is
  ~1 ms at any context size; a faster language optimizes work that has already
  been eliminated.
- **Switching would cost correctness.** Rust's `regex` and Go's `RE2` have no
  lookbehind, and the phone pattern depends on `(?<![\d.])` to avoid matching
  IDs, version strings, hex and IP addresses. Rewriting patterns without
  lookaround is where a real bug would be introduced; reaching for
  `fancy-regex`/PCRE restores lookbehind *and* restores backtracking, defeating
  the reason for switching.
- **Auditability matters for a privacy system.** The owner should be able to read
  and change it without a build toolchain.
- Node's crypto (HMAC, AES-GCM, HKDF) and SSE handling are mature and free.

**The one legitimate gap is closed explicitly, not waved off.** JavaScript regex
backtracks, and the proxy is a single point of failure for all API traffic, so a
pathological pattern would stall Claude Code entirely rather than slow one call.
Mitigation: validate every pattern at load time against adversarial inputs, and
run matching under a watchdog that disables an offending rule with a loud warning
instead of hanging.

Revisit only if the workload ever requires sustained multi-MB/s throughput.

## Rules

`redact-rules.json` keeps `literals` and `patterns`, and gains `aliases`,
`normalize`, and `egress` blocks. Compiler notes:

- **Carried over — category patterns before literals** in the combined
  alternation. Alternation is leftmost-first, so a literal `Jane` would otherwise
  match inside `jane.test@example.org` and leave the rest exposed. Implemented
  and tested.
- **New — literals become word-boundary matched.** The archived implementation
  matched bare substrings with a 3-character minimum, so a literal `Jane` would
  rewrite `JaneAdapter` throughout a codebase. Redaction now applies to all
  content including source, so this matters more. The user's current rules hold
  three single-token literals of 5–6 characters, precisely the case this
  protects. Escape hatch: `{ "value": "...", "boundary": false }`.
- **New — span tracking.** The redactor returns offset pairs, not just text.
  Load-bearing for A2; an off-by-one here corrupts files.
- **New — pattern validation and watchdog.** See Language.

Editing rules changes the redacted prefix and costs exactly one cache miss,
which is correct. It also invalidates the memo LRU.

## Observability

A per-request audit line, so under- and over-redaction are both visible:

```
[16:04:07] POST /v1/messages  body=94.7KB walked=30.1KB memo_hit=41/43
           redacted: email=3 phone=1 personal=2  aliased=7  normalized=2
           resolved: Edit old_string=1 label  cache_hit=0
```

**Counts only, never values, never credentials.** This is how a literal that
fires too aggressively gets caught.

## Failure modes

| Condition | Behavior |
|---|---|
| Proxy not running | Claude Code cannot reach the API. **Fails closed** — visible error, no leak. |
| `ANTHROPIC_BASE_URL` unset or wrong | **The one dangerous case.** Requests go direct, everything appears to work, nothing is redacted, no warning. Mitigated below. |
| Master key missing | Generate on first run. If present but unreadable, refuse to start — never fall back to unkeyed hashing. |
| Malformed request body | Forward unmodified, log a warning. Never break a session over a parse failure. |
| Pathological regex | Watchdog disables that rule, warns loudly, continues. |
| `old_string` unresolvable | Pass through unchanged; Edit fails normally. Never guess at an offset. |
| Cache corrupt / undecryptable | Discard and rebuild empty. Never fail a request over it. |
| Tunnel down (if configured) | Fail closed; no direct-egress fallback. |
| Upstream error | Pass status and body through untouched. |

**Liveness assertion.** All enforcement sits in one process, so its absence must
be loud. A `SessionStart` hook verifies `ANTHROPIC_BASE_URL` points at the
expected loopback address and that `GET /_health` answers, emitting a prominent
`systemMessage` if either fails. Silent unprotected operation is the specific
failure this guards against.

**Lifecycle: autostart at logon.** The base URL is read at startup and the first
request follows within seconds, so the proxy cannot start on demand. Registered
as a logon task; the liveness assertion is the safety net, not the mechanism.

## Retirement

The hook suite is **archived, not deleted** — all ten files are preserved in
`temp/`. Both steps happen only *after* the proxy is verified; there must be no
window with neither mechanism active.

1. Remove working-tree copies of `redact-mirror.js`, `redact-hook.js`,
   `bash-hook.js`, `redact-stream.js`, `warm-mirror.js`, and the four test files.
   The `temp/` archive stays.
2. Replace the `hooks` block in `~/.claude/settings.json` with the single
   SessionStart liveness assertion.

`redact-rules.json` stays — it is the live config.

Note: `temp/` invites accidental deletion and is ignored by many tool defaults;
`legacy-hooks/` or `archive/` would protect it better.

This removes as dead weight: the `%TEMP%` mirror and its second plaintext copy
of every project, the manifest and fingerprint invalidation, hardlink
management, the proposed watcher daemon, the 2 MB file cap, the ZIP/XML document
rewriter, length-preserving binary redaction, and lazy skip-dir expansion — each
of which solved a problem the proxy does not have. It also removes all six
classes of blocked tool call.

## Known limitations

1. **Authentication identifies the account.** Content minimization, not
   anonymity, against Anthropic.
2. **The master key is plaintext on disk.** Requires excluding `~/.claude/` from
   cloud sync and backup; otherwise key and encrypted cache travel together.
3. **Images.** Base64 screenshots cannot be pattern-redacted; a Playwright
   snapshot or Figma export containing personal data passes through intact.
4. **MCP servers doing their own file I/O** never pass through Claude Code's
   tools or the API inbound, so the proxy cannot see the data.
5. **MCP servers with independent outbound egress**, on their own schedule.
6. **Pattern matching is best-effort.** Nicknames, initials, misspellings, a name
   split across two fields, or encoded data pass through.
7. **Labels in Bash commands resolve only from cache.** Within the 30-day TTL
   they resolve; outside it, the command carries an unresolved label and will not
   match. Rare and visible.
8. **Path shapes still travel.** Aliasing hides the username and project root;
   intermediate directory names remain visible.

## Testing strategy

- **Crypto** — HKDF subkey separation; label determinism across process
  restarts with the same key; label *non*-determinism across different keys; key
  file created with restricted ACLs; refusal to start on an unreadable key.
- **Cache** — AES-GCM round trip; tamper detection rejects a modified blob; TTL
  eviction; corrupt cache rebuilds empty without failing a request.
- **Span tracking** — offsets correct with multi-byte UTF-8, adjacent matches,
  matches at position 0 and EOF, overlapping candidates. Property test: for
  random content, every span's real slice equals its recorded value.
- **Derived resolution round trip** — redact a file, construct an Edit against
  the redacted text, resolve, apply, assert the real file matches byte-for-byte.
  Include the boundary-inside-a-span case and assert pass-through rather than a
  guess.
- **Memoization** — a repeated block is redacted once; memo output is identical
  to non-memoized output for the same input; rules change invalidates the LRU;
  memo store holds no plaintext PII.
- **Body walker** — both `content` forms; `tools[]` and signed `thinking` left
  byte-identical; idempotence.
- **Alias round trip** — `cwd` aliased outbound and reversed inbound; alias split
  across SSE deltas; multiple concurrent tool_use blocks; `content_block_stop`
  ordering; malformed events forwarded unchanged; `mcp__*` inputs NOT reversed.
- **Normalization** — `+0530` becomes UTC; OS build generalized; git remote
  org/repo redacted.
- **Regex watchdog** — a catastrophic-backtracking pattern is disabled at load,
  and one that slips through is killed by the watchdog without stalling traffic.
- **Cache stability** — two identical bodies redact to byte-identical output.
- **Integration** — real `claude -p` through the proxy performing Read, Glob,
  Bash and an Edit *on a line containing PII* in an aliased path; assert from the
  audit log that the model saw only labels and aliases, and that the file on disk
  received the real value.
- **Failure** — proxy down, env var unset, malformed body, bad regex,
  unresolvable `old_string`, tunnel down, missing key.

## Endpoint coverage (established by discovery pass, 2026-09-17)

A log-only pass-through proxy was run across a plain prompt and a
subagent-spawning prompt (17 requests total). Findings:

- **Exactly two endpoints are used:** `POST /v1/messages?beta=true` and
  `HEAD /api/hello`. **`/v1/messages/count_tokens` was never called**, so no
  non-streaming inbound branch is required — all 15 message requests were
  `stream=true` with `text/event-stream` responses.
- **Subagents route through `ANTHROPIC_BASE_URL`.** The `Explore` agent's turns
  appeared in the proxy log on the same endpoint, so spawned agents inherit the
  base URL and are covered. This was the main open risk; there is no bypass.
- **Memoization is empirically justified.** Content (`messages` + `system`) grew
  monotonically 19,057 → 34,302 chars across 15 turns — roughly 1 KB of new
  content per turn against a 34 KB total, i.e. ~34× less work per turn even at
  this trivial context size. The ratio improves as context grows.

## Open items before implementation

1. **Phasing.** Eight modules is more than one clean pass. Order:

   - **Phase 1 — working end to end.** Core proxy, keyed-label redaction,
     aliases, memoization, SSE parsing, **and inbound alias reversal**. The
     reversal cannot be deferred: aliasing paths outbound without reversing them
     inbound would hand every tool a path that does not exist on disk, so the
     two must ship together or not at all. Delivers the bulk of the privacy
     benefit and is independently verifiable.
   - **Phase 2 — edits on PII lines.** Span tracking, derived resolution, and
     the encrypted TTL cache. Until this lands, an Edit touching a redacted line
     fails with "string not found", which is the documented Phase 1 behavior.
   - **Phase 3 — hardening.** Normalization (timezone, OS, git remotes), egress
     tunnel, `randomizeDeviceId`, and worker-thread regex watchdog.
   - **Phase 4 — local residue.** The last phase, scoped in below.

   Each phase gets its own implementation plan; Phase 1's is written first.

### Phase 4 — local residue (design deferred, scope fixed now)

Everything above governs what leaves the machine. Phase 4 addresses what stays
on it.

**The problem.** Real values necessarily pass through Claude Code's local
process — that is how a file gets written. The proxy resolves a label back to
the real value on the inbound path, so from that moment the value exists in
Claude Code's memory and in anything it persists. Redaction at the API boundary
does nothing about this by construction; it is the correct boundary for the
stated threat model, and the wrong one for this.

**Known surfaces, to be inventoried properly at design time:**

| Surface | Holds | Notes |
|---|---|---|
| `~/.claude/history.jsonl` | prompts | retained `cleanupPeriodDays`, default 30 |
| per-project session transcripts | full conversation | includes resolved tool inputs |
| `~/.claude/file-history/` | pre-edit file snapshots | exists to power `/rewind` |
| `~/.claude/redaction/redact-cache.enc` | label → value | encrypted, but the key sits beside it |
| `~/.claude/redaction/redact-rules.json` | the literals themselves | unavoidable; it is the config |
| `~/.claude/redaction/redact-proxy.log` | counts only | audited: no values |

**What makes this genuinely hard, and why it is last.** The values are *supposed*
to be there — a transcript without them could not support `/rewind`, and a cache
without them could not restore an edit. So this is not a leak to plug but a
retention question: how long should local plaintext live, and who can read it.
Likely levers rather than a solution: a short `cleanupPeriodDays`, excluding
`~/.claude` from cloud sync and backup (already verified not synced on this
machine), OS-level encryption of that directory, and possibly scrubbing
resolved tool inputs out of transcripts at session end — which trades away
`/rewind` fidelity.

**Explicitly accepted and not part of Phase 4:** the model cannot reason about a
value it cannot see. Asking "is this email valid?" yields a label. This is
inherent to one-way redaction, the user has accepted it, and no phase attempts
to solve it.

## Resolved decisions

| Decision | Outcome |
|---|---|
| Transport | `ANTHROPIC_BASE_URL` to loopback; MITM/CA unnecessary |
| Language | **JavaScript** — memoization removes the throughput argument; switching would cost lookbehind and auditability |
| Regex hang risk | Load-time validation + matching watchdog |
| Large-context cost | Per-block memoization, ~1 ms at any context size |
| Label construction | **HMAC-SHA256 with a local 32-byte key**, not a bare hash |
| Label category | Retained — reveals type, never value |
| Stored reverse map | **Adopted**, as an encrypted 30-day TTL cache, not a plaintext harvest |
| Resolution order | Derivation authoritative for file edits; cache for Bash and as fallback |
| Edits on PII lines | **Work** |
| `text_delta` resolution | No — yields PII-free transcripts for free |
| Key storage | File with restricted ACLs; requires excluding `~/.claude/` from sync |
| Identity round-tripping | Static bidirectional alias: username, hostname, project roots |
| MCP alias reversal | **Reversed by default**, with `aliasReverseExclude` for remote servers (reverses an earlier decision — see Mechanism F) |
| MCP label resolution | Never by default; `resolveLabelsFor` opts a trusted local server in |
| Timezone / OS / git-remote | Normalized one-way |
| `device_id` | Unmodified by default; opt-in `randomizeDeviceId` |
| IP address | Optional upstream SOCKS5/VPN; fail closed if configured and down |
| Proxy lifecycle | Autostart at logon |
| Hook suite | Archived in `temp/`, unwired only after the proxy is verified |
