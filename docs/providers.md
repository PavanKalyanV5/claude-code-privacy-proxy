# Free egress options, honestly compared

The proxy can route the upstream API connection through a SOCKS5 or HTTP
CONNECT tunnel so the API sees that exit address instead of yours. This
document is about where to get one that actually works.

Run this first — it detects what is already available on your machine:

```bash
npm run providers
```

---

## The short answer

**Run your own tunnel.** `ssh -D 1080 user@your-vps` on a permanently-free VM
is the only option here that is both free and genuinely dependable, because
you are the only operator. Everything else is a compromise, and the public
free-proxy lists are not a compromise so much as a trap — see the measurements
at the bottom.

---

## Comparison

| Option | Free? | Reliability | Who sees your destination | Setup |
|---|---|---|---|---|
| **Your own SSH tunnel** | Yes, on a free-tier VM | **High** | Only you | 10 min, one-time |
| **Cloudflare WARP** | Yes, no account | **High** | Cloudflare | Install a client |
| **Tailscale exit node** | Yes, up to 3 users | High | Only you | Needs a second device |
| **Authenticated free tier** | Limited quota | Medium | The provider | Sign up |
| **Tor** | Yes | High *availability*, often blocked | Entry guard + exit node | Install Tor |
| **Psiphon / Lantern** | Yes | Medium | The operator | Install a client |
| **Scraped public lists** | Yes | **Effectively zero** | Anyone | None — and don't |

---

## 1. Your own SSH tunnel — recommended

```bash
ssh -D 1080 -N -C user@your-vps
```

That opens a SOCKS5 proxy on `127.0.0.1:1080` for as long as the SSH session
lives. Then:

```json
"egress": { "urls": ["socks5://127.0.0.1:1080"] }
```

Manual entries always take priority over anything auto-detected.

**Where to get a permanently free VM:**

- **Oracle Cloud "Always Free"** — the strongest option. Free *indefinitely*,
  not a trial, and the Arm instances are generous. Requires a card for identity
  verification.
- **Google Cloud free tier** — one small `e2-micro` per month, ongoing.
- **AWS free tier** — 12 months only, then it bills. Set a budget alarm.
- **Fly.io / Render / Oracle alternatives** — usable, quotas change often;
  check current terms rather than trusting any guide including this one.

**Why this is the best option:** the operator is you. Nothing is shared, no one
else's quota runs out, and the exit address is stable — which matters, because a
constantly-rotating exit IP is itself a fingerprint.

**Keeping it up:** a bare `ssh -D` dies with your terminal. Use `autossh`, or a
systemd/Task Scheduler entry, or accept that a dropped tunnel means fail-closed
refusals until you reconnect. `onFailure: "refuse"` makes that loud rather than
silent, which is the point.

---

## 2. Cloudflare WARP

Free, no account required, run by a company with a reputation to protect and a
published privacy position. It is a genuinely reasonable default if you do not
want to run a VM.

Install the WARP client, then check whether it exposes a local proxy — the
mechanism and port differ by version and platform, and `npm run providers` will
detect it if present. Verify against Cloudflare's current documentation rather
than a hardcoded port from any tutorial.

**Trade-off:** Cloudflare sees your destinations. That is a real trust
transfer, just to a more accountable party than an anonymous proxy operator.

---

## 3. Tailscale exit node

If you already have a second machine somewhere else — a home server, a
relative's spare box, a cheap VPS — Tailscale's free tier lets you route
through it as an exit node. Excellent reliability, and the operator is still
you.

Needs that second device, which is why it is not the headline recommendation.

---

## 4. Authenticated free tiers

Providers with a free allowance and real credentials:

- **Webshare** — a small number of proxies on a monthly bandwidth allowance.
- **Oxylabs / others** — limited free static IPs, quota-capped.

```json
"egress": { "urls": ["socks5://user:pass@host:port"] }
```

**Why these beat public lists:** authentication. A public open proxy is shared
with everyone who scraped the same list, which is why they die in seconds. An
authenticated endpoint is yours for the quota you were given.

**Watch:** the quota. Streaming responses through a metered proxy consumes it
faster than you would expect.

---

## 5. Tor

```json
"egress": { "urls": ["socks5://127.0.0.1:9050"] }
```

Tor Browser's bundled daemon listens on `9150`; a standalone `tor` service uses
`9050`.

**High availability, frequently unusable.** Tor itself is one of the most
reliable things on this list — but many API providers block known exit nodes,
so requests may be refused at the destination rather than in the tunnel. Treat
it as a last-resort fallback.

**Also:** it is slow, and slow shows up directly as choppy token streaming.

---

## 6. Psiphon, Lantern and similar

Free circumvention clients that expose a local proxy. They work, they are
reasonably reliable, and the operator is a third party whose funding model you
should understand before routing your work through it. `npm run providers`
scans a few common local ports, so if one of these is running it will be
detected.

---

## 7. Scraped public proxy lists — why they are not shipped

This was built first, and it was the obvious approach: fetch the well-known
GitHub proxy lists, test each candidate through a real tunnel, verify it
actually masks, rank by latency, cache the winners.

It works exactly once per proxy.

**Measured on real lists:**

```
pool: 5 verified proxies available    (fastest 2572ms)
...seconds later...
all 5 handshakes timed out -> request REFUSED
```

Every one of the five completed the full verification — TLS-verified
connection, echo service reporting a different exit address — and then refused
the *next* connection seconds afterwards. Rate limits, or hosts that simply
vanish.

**The lesson generalises: verification does not predict usability.** A check
that passes at time T tells you nothing about T+5s for a resource shared with
everyone who scraped the same list. Our own validation runs "passed" because
they did one probe plus one masking check in quick succession — precisely the
one thing these proxies can do.

Other measurements from the same work:

- roughly **6% hit rate** across ~40 probes per refresh
- verified latencies of **2.0–6.3 s**, i.e. visibly slow
- exits landed in RU, VE, HK, DO and others — a jurisdiction lottery unless you
  maintain an exclusion list
- dead entries cost a full handshake timeout *each* on every request until
  demoted

The implementation survives in `src/pool.js` with **no default sources**,
demote-on-failure, refresh-on-exhaustion and a short cache TTL. If you want it,
supply sources explicitly and read the runbook section on what to expect.

---

## Choosing an exit country

```json
"egress": {
  "homeCountry": "IN",
  "pool": { "excludeCountries": ["IN"] }
}
```

`homeCountry` is used **only** to tell exposed from masked in `auto` mode.
`excludeCountries` decides which exits are acceptable. They are deliberately
separate settings, because they answer different questions.

Put your own country in the exclusion list: a proxy inside it hides your
address but not your location. The proxy reports `exitIsHomeCountry`
separately from `masked` for exactly this reason.

Country is verified **after connecting**, never taken from a list's own label —
those labels are frequently wrong, and trusting them would route you through a
country you had excluded.

---

## What "reliable" has to mean here

Because egress is fail-closed, an unreliable proxy does not degrade your
privacy — it degrades your *availability*. A dead tunnel means refused
requests, which is the correct behaviour and also an outage.

So the bar is not "does it work now". It is:

1. **Does it survive repeated connections** over an hour, not one probe?
2. **Is the exit address stable**, or does it rotate and fingerprint you?
3. **Is the operator accountable** for what they log?
4. **Does it recover** without you noticing, or does it need intervention?

Your own SSH tunnel is the only free option that answers all four well. That
is the honest recommendation, even though "bring your own VPS" is a less
satisfying answer than a list of hostnames.
