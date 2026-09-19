# Threat model

What this defends against, what it does not, and which gaps are accepted
rather than unsolved. Read the second list before relying on the first.

---

## The goal, stated precisely

**Keep personal data, machine metadata and location out of API requests, and
out of files on disk — without breaking the tools that need real values.**

Not a goal: anonymity from your provider. Your account is identified by
billing. The aim is that the *contents* of requests, and the *network origin*
they arrive from, reveal as little about you as possible.

---

## Adversaries, in order of how much the design worries about them

### 1. Accidental disclosure to the model and its logs

The primary case. Your name, address, client names and paths end up in prompts
because you didn't assemble the request — Claude Code did, from your files and
your shell.

**Defence:** the outbound pipeline. Listed literals and pattern categories are
replaced with keyed labels; identity values are aliased; location fingerprints
are normalized away; fingerprinting headers are genericized.

**Residual risk:** what you type yourself is not filtered by intent. Paste a
secret and it goes.

### 2. Someone reading your disk

Transcripts, tool results and edit snapshots contain real values, written
before the proxy sees anything. Backup software, sync clients, another account
on the machine, or a shared screenshot all reach them.

**Defence:** `scan-residue` measures it, `scrub-residue` rewrites it through
the same pipeline, on a schedule. Measured on one real machine: 41,906
occurrences across 608 files, reduced to effectively zero.

**Residual risk:** the *live* session's transcript is deliberately skipped
while it is being appended to — rewriting an open file would corrupt the
conversation. There is always a window of one session's worth of data.

### 3. Network observers and the API's view of your origin

Your IP pins your city. Your ISP sees which hosts you contact.

**Defence:** optional SOCKS5 / HTTP CONNECT tunnel, fail-closed, with DNS
resolved at the proxy so your ISP's resolver never learns the destination.

**Residual risk:** substantial, and worth being blunt about. The proxy covers
**Claude Code's API calls only**. An MCP server making its own outbound
request, and anything `Bash` runs — `curl`, `npm install`, `git push`, `pip` —
goes out from your real address. Only an OS-level VPN or firewall covers
everything.

### 4. The tunnel operator

A proxy you route through is a third party in the path.

**What they can see:** destination host, connection timing, byte volume.

**What they cannot see:** the request body, the model's output, or your API
key. TLS is negotiated end-to-end *through* the tunnel with certificate
verification **on**; a proxy attempting interception is refused, not trusted.

**Residual risk:** traffic analysis, and the operator's jurisdiction.
`excludeCountries` is the lever. A proxy inside your own country hides your
address but not your location — which is why `exitIsHomeCountry` is reported
separately from `masked`.

### 5. A remote MCP server

A third-party tool server receiving resolved real values would defeat the
entire point.

**Defence:** `remoteTools` prefixes receive tool inputs **completely
unmodified** — labels and aliases stay. Local servers get real values, because
a local server runs as you and could read the files directly anyway.

**Residual risk:** the list **fails open**. Anything unlisted is treated as
local. Add a remote server without listing its prefix and it gets your real
data. This is a deliberate trade for local servers working without
configuration, and it is the single easiest way to misconfigure this system.

### 6. Yourself, six months from now

The failure mode that actually bit repeatedly during development: a component
reporting success while not working.

**Defence, as a design rule:** anything unverifiable reports as **NOT
protected**. A missing status file, an unparseable one, a stale timestamp, zero
loaded rules, an unconfirmed tunnel — all render as unprotected. Verification
prints counts and verdicts but never values, so checking is always safe.

**Residual risk:** `statusLine` — the continuous indicator — **is not
supported in the Claude Code VS Code extension**, only the terminal CLI. In the
extension the channels that work are the SessionStart message, OS-native
notifications, refused requests, and running `npm run verify` yourself.

---

## Accepted risks

Decided deliberately. Listed so nobody re-opens them as though they were
oversights.

| Risk | Why accepted |
|---|---|
| Your own typed input is unfiltered | Filtering intent is not possible; patterns and literals are |
| Local MCP servers see real values | They run as you and could read the files directly |
| The model cannot reason about values it cannot see | The cost of redaction; labels are stable so it can still refer to them |
| Anthropic knows the account | Billing identity is out of scope |
| One session's transcript is always unscrubbed | Rewriting an open file would corrupt the conversation |
| Bash and MCP egress is unmasked | Out of scope for a proxy in front of one client; use a VPN |
| A four-part version string may match the IP pattern | A false positive costs a label; a false negative costs an address |
| Single-token literals inside words are not redacted | The guard that allows this is what stops `Jane` matching `Janet` |

---

## Failure modes and what happens

| Failure | Behaviour | Why |
|---|---|---|
| Transform throws mid-request | **Refuse** (502) | We found redactable content and then crashed; forwarding would leak exactly what we choked on |
| Body is not JSON | **Forward unmodified** | Nothing to redact; refusing would break the session for no gain |
| No egress proxy reachable | **Refuse** (or `direct` if configured) | A silent direct connection leaks the address the tunnel exists to hide |
| Tunnel presents a bad certificate | **Refuse** | An intercepting proxy is the thing verification exists to catch |
| Master key missing or wrong size | **Refuse to start** | Falling back to unkeyed hashing would make labels brute-forceable |
| Rules file malformed | **Refuse to start** | Starting with no rules means running while protecting nothing |
| A risky alias is configured | **Refuse to start** | A common-word alias rewrites source files on write |
| A regex fails the backtracking screen | **Disabled with a warning** | One bad pattern should not take the proxy down |
| Edit derivation is ambiguous | **Refuse the edit** | A wrong `old_string` corrupts a file silently |
| Label cannot be resolved for a write | **Warn loudly, pass through** | Writing `[PII:…]` into a file is visible and fixable; guessing is not |
| Status file stale or missing | **Report NOT protected** | Cannot verify means cannot claim |

---

## What would genuinely improve this

Honest list of what is missing, not a roadmap.

- **System-wide egress.** An `HTTP_PROXY`-style listener would cover `curl`,
  `npm` and `git`, closing most of gap 3. Tool-dependent, and Node's `fetch`
  ignores those variables.
- **A working mid-session indicator in the VS Code extension.** Currently
  impossible from outside; OS notifications are the substitute.
- **Encrypted transcripts at rest**, rather than scrubbing after the fact.
  Needs Claude Code's cooperation.
- **A shipped reliable free egress path.** Everything dependable needs either
  your own VPS or a third party's client. The honest answer today is "bring
  your own tunnel".
