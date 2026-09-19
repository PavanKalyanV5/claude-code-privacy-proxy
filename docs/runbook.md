# Redaction proxy — operator runbook

Everything you need to start it, check it, and un-break it. Written to be
usable when the proxy is the thing that's broken and Claude Code won't talk to
you.

**The one-line summary:** the proxy redacts personal data out of API requests.
Redaction is reliable. The IP-masking layer on top of it depends on free public
proxies and is **not** reliable — keep your VPN as the primary and treat the
proxy pool as an emergency fallback only.

---

## 1. Emergency: Claude Code shows an API / connection / firewall error

Almost always one of three things. Work down the list.

### 1a. The proxy isn't running

`ANTHROPIC_BASE_URL` points at `http://127.0.0.1:47113`. If nothing is
listening there, every request fails and the error mentions a proxy, firewall,
or connection problem.

```powershell
# is anything listening?
netstat -ano | Select-String ":47113" | Select-String "LISTENING"

# start it
cd C:\Users\SOMEONE\Desktop\games\files
node src/start.js
```

Leave that window open, or start it detached:

```powershell
Start-Process -WindowStyle Hidden node -ArgumentList "src/start.js" -WorkingDirectory C:\Users\SOMEONE\Desktop\games\files
```

Confirm:

```powershell
curl http://127.0.0.1:47113/_health
```

### 1b. The proxy is running but refusing every request

This is **fail-closed working as designed**: no egress proxy could be reached,
so rather than sending your traffic out unmasked it refuses. You are not
exposed — you are blocked.

The fastest unblock, no restart needed:

```powershell
# stop tunnelling; requests go out from your real IP from now on
curl -X POST http://127.0.0.1:47113/_egress/off

# ...and to turn it back on later
curl -X POST http://127.0.0.1:47113/_egress/on
```

Turning it off means your IP is no longer masked. Personal data is still
redacted — that part is independent. **Turn your VPN on** and you get the
masking back by a different route.

The permanent version of the same decision, in
`~/.claude/redaction/redact-rules.json`:

```json
"egress": { "onFailure": "direct" }
```

That keeps you working when proxies die, at the cost of going out from your
real IP when they do. Every fallback is logged and the status line reports it
until you change the setting back.

### 1c. The proxy won't start at all

Run it in the foreground and read the error — it is designed to tell you which
setting is wrong:

```powershell
node src/start.js
```

| Error | Cause | Fix |
|---|---|---|
| `Unexpected token ... in JSON` | `redact-rules.json` is malformed | Fix the JSON, or restore a `redact-rules.backup-*.json` |
| `master key ... expected 32 bytes` | `redact.key` is wrong size/corrupt | Restore the key. **Without the original key the label cache is unreadable** — not fatal, it rebuilds |
| `egress.mode "auto" needs egress.homeCountry` | auto mode with no home country | Set `"homeCountry": "IN"` |
| `egress.onFailure must be "refuse" or "direct"` | typo in that value | Fix the spelling |
| `egress protocol "..." is not supported` | bad proxy URL scheme | Use `socks5://` or `http://` |
| `EADDRINUSE` | another instance already running | Kill it (§4) or leave it |

---

## 2. The correct start-up order

Getting this wrong is what caused the outage. **Config is read only at
startup.** Editing the JSON changes nothing until the proxy restarts.

1. **Edit** `~/.claude/redaction/redact-rules.json`.
2. **Validate it** before trusting it:
   ```powershell
   node .superpowers/sdd/2026-09-18-redaction-proxy-phase3/inspect-config.js
   ```
   Prints structure and counts only — never your personal data. It flags
   missing patterns, missing normalization, and bad egress settings.
3. **Restart the proxy** (§4).
4. **Wait for it to be ready** — see §3. In `mode: "on"` there is a window of
   10–30s after startup where the pool is still filling and *every request is
   refused*. Do not restart Claude Code during that window.
5. **Only then restart Claude Code.**

Reverse that order and Claude Code starts before the proxy is serving, which
looks exactly like a firewall problem.

---

## 3. How to tell whether it's healthy

**The one command that answers "am I actually protected?":**

```powershell
node src/verify-protection.js
```

It reads your real rules and checks every configured literal in 20 adjacency
shapes, every pattern category, alias safety, live masking, and status
freshness. It prints verdicts and counts only — never a literal, never an
address — so it is safe to run and safe to paste. Exit code 0 means every
check passed.

Expect one informational note: a single-token literal wrapped in word
characters on both sides (`xxNAMExx`) is deliberately not redacted, because
that guard is the only thing stopping a short name matching inside an
unrelated word. To override it for a specific value, list it as
`{ "value": "...", "boundary": false }`.

For the network side specifically:

```powershell
node .superpowers/sdd/2026-09-18-redaction-proxy-phase3/live-status.js
```

```
pid              : 2964
redaction        : literals 10, pattern-regexes 12, aliases 2
proxies ready    : 5
tunnel up        : true
masking          : CONFIRMED
exit country     : ID
your country     : NL   (address not stored, digest only)
went out direct  : 0
```

What to look for:

| Field | Good | Bad — and what it means |
|---|---|---|
| `redaction` | literals > 0 | `literals 0` — running but redacting nothing |
| `tunnel up` | `true`, or n/a if not tunnelling | `false` with mode on/auto-engaged = requests refused |
| `masking` | `CONFIRMED` | `NO` = a proxy is forwarding your real IP. `not yet verified` = unknown, treat as unmasked |
| `went out direct` | `0` | `> 0` = that many requests left from your real IP |

The status line in Claude Code shows the same thing continuously:

| Status line | Meaning |
|---|---|
| `🔒 redacted · ip HK` | Working, tunnelled, exiting via Hong Kong |
| `🔒 redacted · direct NL (no tunnel needed)` | Working; auto mode sees your VPN and stays out of the way |
| `🔒 redacted · ip unverified` | Tunnel state unknown — treat as unmasked |
| `🔒 redacted · ⚠ IP NOT MASKED` | A proxy is forwarding your real address |
| `🔒 redacted · ⚠ IP EXPOSED x2` | 2 requests went out unmasked via the `direct` fallback |
| `⚠ NO RULES` | Proxy up, zero rules loaded |
| `⚠ REDACTION OFF (proxy not running)` | Nothing is being redacted |
| `⚠ REDACTION OFF (proxy not responding)` | Status file went stale — the proxy died |

**Silence means protected.** Anything unverifiable renders as NOT protected by
design: a status line that wrongly claims protection is worse than none.

---

## 4. Restarting cleanly

```powershell
# find and stop the running instance
$pid = (netstat -ano | Select-String ":47113.*LISTENING" | ForEach-Object { ($_ -split '\s+')[-1] } | Select-Object -First 1)
if ($pid) { taskkill /PID $pid /F }

# start fresh
cd C:\Users\SOMEONE\Desktop\games\files
node src/start.js
```

There is also a logon launcher (`.vbs` in the Startup folder) that starts it
automatically. It runs `start.js`, so it always picks up current code and
whatever is in `redact-rules.json` at that moment.

---

## 5. What actually went wrong, and why

Three failures, worth understanding because they explain the design.

### 5a. Dead port — the outage you hit

I stopped the proxy to restart it on new config and the turn was interrupted
before I started the new one. Port 47113 sat empty. With
`ANTHROPIC_BASE_URL` pointed there, every request failed with what looks like
a firewall error.

**Prevention:** §2's order, and `curl /_health` before restarting Claude Code.
Never assume a restart succeeded.

### 5b. `ReferenceError: Cannot access 'ipCheck' before initialization`

`start.js` used a `const` above its declaration, inside a ternary that only
evaluated when `egress.pool.enabled` was true. So the proxy started fine with
the pool off and crashed the moment it was switched on.

~300 tests passed throughout, because every one tested a module in isolation
and **nothing ever ran `start.js`** — the file where config meets wiring.

**Prevention:** `proxy/test/start.test.js` now boots the real `start.js`
against 15 config permutations (egress absent/off/on/pool-only/auto, device
rewriting, header policy, empty rules) plus the configs that must be *rejected*.
Verified it catches the original bug: restoring the old ordering fails exactly
the two pool-enabled permutations.

### 5c. Free proxies verify, then die seconds later — the important one

The log that told the real story:

```
pool: 5 verified proxies available   (fastest 2572ms)
...seconds later...
all 5 handshakes timed out → request REFUSED
```

Each proxy completed the verification probe and then refused the very next
connection. Rate-limiting, or hosts that vanish. **Verification does not
predict usability.**

My earlier validation runs passed because they did one probe plus one masking
check in quick succession — the one thing these proxies *can* do. Repeated
connections over time, which is what real traffic is, was never tested. Those
PASS results were real but measured the wrong thing.

**Consequence: do not rely on the free pool.** With `onFailure: "refuse"` it
will block you often; with `"direct"` it will silently stop masking. Neither is
a working primary.

Mitigations since: dead proxies are **demoted immediately** on a live failure
rather than retried for their full timeout on every request, an exhausted pool
triggers a refresh, and the cache TTL is 5 minutes instead of 30. That makes
the pool self-healing rather than a list of corpses. It does not make free
proxies dependable.

### 5d. A stale tunnel decision kept reporting "protected"

Auto mode observed a VPN exit country, correctly decided *"already masked, no
tunnel needed"*, and then held that decision for its full 15-minute re-check
interval. The VPN was switched off. For the next seven minutes every request
went out from the real address **while the status line said protected**.

Confirmed at the time: the proxy believed `NL`, an out-of-band probe said `IN`,
and `tunnelling` was `false`.

**The rule now:** staleness is indistinguishable from a changed network, so an
expired observation reads as *unknown*, and unknown means tunnel. Observations
expire after **120 seconds**, auto polls every 90s to stay inside that window,
and the decision is recomputed **per connection** rather than trusted from
storage. An exhaustive test asserts the only route to not tunnelling in auto
mode is a fresh, non-home country.

### 5e. An alias rewrote source files on write

The shipped example config aliased the hostname to a short common word.
Inbound un-aliasing replaces the alias with the real value *everywhere it
appears*, so every standalone occurrence of that word — in an options object,
in prose, in a comment — was rewritten to the real machine name on write. It
corrupted comments in `aliases.js` and `aliases.test.js`, including the very
comment explaining why boundaries matter, and reached git history.

The boundary logic was **correct throughout**: compound forms were properly
left alone. The defect was that the alias *value* was a word that appears in
code on its own, which no amount of boundary correctness can fix.

**Now:** a risky alias is **fatal at startup** (denylist plus a short
plain-word rule), and both configs use a distinctive token. If you ever change
an alias, pick something nothing would type by accident.

One curiosity worth knowing: repairing this required building the replacement
token from fragments at runtime, because writing it literally meant it was
itself un-aliased on the way to disk. The first repair script was a silent
no-op for exactly that reason.

### 5f. A redaction bypass when a value abutted a word character

Found by the stress suite. Literals were word-boundary matched, so a literal
abutting a word character — **including another copy of itself** — matched
nothing at all. `<name><name>` with no separator went out completely
unredacted. Aliases had the identical bug, found by `verify-protection.js` on
its first run.

**Now:** a boundary is satisfied by a non-word character *or* by another
occurrence of the value, and guards apply only to values made entirely of word
characters (the only ones that can hide inside a longer word). Both properties
are needed; either alone regresses the other.

---

## 6. So what should you actually run?

**Recommended, and what is configured now:**

```json
"egress": {
  "mode": "auto",
  "homeCountry": "IN",
  "onFailure": "refuse",
  "ipCheckUrl": "https://api.country.is",
  "pool": { "enabled": true, "want": 5, "excludeCountries": ["IN"] }
}
```

- **VPN on** → auto sees a non-IN exit country, decides you're already masked,
  and leaves the tunnel alone. Full speed, no free proxies involved.
- **VPN off** → auto sees IN, engages the pool. It may work; it may refuse. It
  is a failsafe, not a plan.

**If you want reliable masking without your VPN**, the free-list approach is
the wrong tool. Either of these is solid:

- **Your own SOCKS5 on a cheap VPS** — `ssh -D 1080 user@your-vps` gives you a
  SOCKS5 proxy on `localhost:1080`. Put `"socks5://127.0.0.1:1080"` in
  `egress.urls` and it will be preferred over anything scraped from the
  internet. Reliable, fast, and the only operator is you.
- **A paid proxy provider** with authentication — same config shape,
  `socks5://user:pass@host:port`.

Both remove the entire class of problem in §5c.

---

## 7. What is and isn't protected

**Protected:** name, email, phone and any other literal you list; email/phone/
IP/IPv6/MAC by pattern; git org and repo names; your OS username and hostname
(aliased, and reversed on the way back so tools still work); timezone offsets
and IANA zone names; locale strings; Windows build strings; and the
fingerprinting request headers (`accept-language`, `x-stainless-os/-arch`,
`x-forwarded-for`).

**Not protected — know these:**

- **Anything you type yourself.** Accepted risk; the proxy redacts patterns and
  literals, not intent.
- **Other programs' traffic.** The proxy only covers Claude Code's API calls.
  MCP servers making their own requests, and anything Bash runs (`curl`,
  `npm install`, `git push`), go out from your real IP regardless. This is why
  VPN-primary is the architecture and not a fallback.
- **Local disk.** Transcripts, `~/.claude/history.jsonl` and `file-history/`
  still contain real values. That is Phase 4, not yet done.
- **Your account identity.** Anthropic knows who you are from billing. The
  goal here is location and machine metadata, not anonymity from them.

---

## 8. File map

| Path | What it is |
|---|---|
| `~/.claude/redaction/redact-rules.json` | Your config and personal data. Never committed |
| `~/.claude/redaction/redact-rules.backup-*.json` | Timestamped backups taken before any edit |
| `~/.claude/redaction/redact.key` | 32-byte master key. Losing it only costs the label cache |
| `~/.claude/redaction/redact-proxy.log` | Audit log — counts and warnings, never addresses |
| `~/.claude/redaction/status.json` | What the status line reads. Stale = "proxy dead" |
| `~/.claude/redaction/proxy-pool.json` | Cached verified proxies. Safe to delete any time |
| `src/start.js` | Entry point. Reads config once, at startup |

Useful scripts, all under
`.superpowers/sdd/2026-09-18-redaction-proxy-phase3/`:

| Script | Use |
|---|---|
| `src/verify-protection.js` | **Am I protected?** The one to run. Values-free output |
| `live-status.js` | Is it healthy right now? |
| `inspect-config.js` | Is my config sane? (structure only, prints no personal data) |
| `validate-egress.js --home IN --exclude IN` | Does the failsafe work? Runs out-of-band so a failure can't break your session |
| `e2e.js --exclude IN` | Full chain check against a fake upstream |
| `leak-scan.js <ip>` | What still gets through? |
