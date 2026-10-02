# Changelog

## v1.2.0 — 2026-10-02

### Features

- **supervise**: crash recovery and start-at-login on Linux via systemd user units (08e7ab2)
- **resolver**: derive labels for configured literals without the cache (e58d30a)

### Fixes

- **resolver**: resolve labels in tool paths and search patterns (e1f7bf6)

_Plus 3 maintenance commits._

## v1.1.2 — 2026-09-19

### Fixes

- **rules**: stop compiling untrusted patterns in the parent process (30e13a7)

## v1.1.1 — 2026-09-19

### Fixes

- **rules**: a slow machine could silently disable a working pattern (20b5207)

## v1.1.0 — 2026-09-19

### Features

- **release**: automatic versioning and publishing from main (7bfe09d)

### Fixes

- three security-scan findings, one of them a real bug (28b7bb5)
- **ci**: three failures, each hiding a real portability problem (aebbd82)

_Plus 3 maintenance commits._
