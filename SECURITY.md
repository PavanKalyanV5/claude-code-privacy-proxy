# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private reporting: **Security → Report a vulnerability** on this
repository. That opens a channel visible only to the maintainers.

Include what you can. A rough report today is worth more than a perfect one
next month.

**Do not include your real personal data in a report.** This project's whole
purpose is keeping that data out of places it does not belong, and an issue
tracker is one of those places. Use synthetic values — the ones in
`config/redact-rules.example.json` are there for exactly this.

You should get an acknowledgement within a week. If you do not, assume it was
missed rather than ignored, and follow up.

## What counts as a vulnerability here

The severity of a bug in this project is not about crashing. It is about
whether personal data reaches somewhere it should not, or whether the tool
**claims protection it is not providing**.

Roughly, worst first:

| | |
|---|---|
| **Critical** | A value that should be redacted reaches the API. A label that resolves to the wrong value. Anything that makes the tool report PROTECTED while data is leaking. |
| **High** | The dashboard token or the master key becoming readable by another local account. A pattern that corrupts files. A path that bypasses the proxy without warning. |
| **Medium** | A crash that leaves the proxy dead while `ANTHROPIC_BASE_URL` still points at it, with no warning to the user. Retention failing silently. |
| **Low** | Over-redaction, log noise, cosmetic dashboard issues. |

**Reporting a false sense of security is always worth a report**, even if no
data actually leaked. A tool that wrongly claims protection is worse than no
tool, because it stops people looking.

## What is deliberately out of scope

These are documented, accepted limitations rather than bugs. See
[docs/threat-model.md](docs/threat-model.md) for the reasoning.

- **Anything you type yourself.** The proxy redacts listed literals and
  pattern categories, not intent. Paste a secret and it goes.
- **Other programs' traffic.** It covers Claude Code's API calls. An MCP
  server making its own requests, or anything `Bash` runs, leaves from your
  real IP. Only an OS-level VPN covers everything.
- **Your account identity.** Anthropic knows who you are from billing. The
  goal is keeping personal data out of payloads and location out of metadata,
  not anonymity from your provider.
- **Local attackers already running as you.** Anything running under your
  account can read your rules and key. This defends the network boundary, not
  your own machine against itself.
- **A single-token literal wrapped in word characters.** `xxJanexx` is
  deliberately not redacted, because that guard is what stops `Jane` matching
  inside `Janet`. Override per value with `"boundary": false`.

## Supported versions

The latest release on `main`. This is a single-maintainer project; there are
no backported security branches. If that is not enough assurance for your
use, vendor it and maintain your own fork — the MIT licence exists for that.

## Handling

There is no bounty. What you will get is a fix, a test that keeps it fixed,
and credit in the changelog unless you would rather not be named.
