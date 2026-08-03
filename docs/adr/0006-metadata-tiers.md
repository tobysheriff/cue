# ADR-0006 — Mandatory metadata floor plus opt-in Quiet Mode

**Status:** Accepted · **Adversaries addressed:** A1 (passive network observer),
A2 (operator), A7 (global passive adversary, partially)

## Context

The project goal is full metadata resistance: padding, cover traffic, timing decorrelation,
private discovery. Some of those are cheap and some are extremely expensive. Constant-rate
cover traffic at a useful rate costs roughly 50–200 MB/day and meaningfully drains a
battery; a privacy tool that flattens the battery gets uninstalled, which protects nobody.

There is also a counterintuitive risk: a protection used by a small minority becomes a
fingerprint identifying that minority as the interesting users.

## Decision

**Mandatory floor — always on, no setting, no way to weaken it:**
fixed-size padded envelopes (1/4/16/64 KB, including all control messages); sealed sender;
rotating mailbox identifiers; anonymous auth credentials with batch issuance decorrelated
from use; IP-blind ingress with access logging disabled and in-memory-only bucket
reputation; no contact upload; encrypted group state; attachment decorrelation.

**Quiet Mode — opt-in, per account:** constant-rate cover traffic in both directions,
batched delivery with jitter, onion transport via bundled `arti`, and presence/typing/read
receipts disabled.

Presented as a situation ("when it matters that nobody can tell you're messaging at all"),
not as a paranoia dial.

## Consequences

**Good:** every user gets protections strong enough to be meaningful without being asked.
Users who need more can have it, on the same protocol, with no separate build.

**Bad:** default mode does not defeat a global passive adversary, and the docs say so.
Quiet Mode costs latency (up to ~60 s) and data. Quiet Mode's rarity may itself be a signal
— an unresolved tension tracked as `docs/12` Q1, with a plan to make it default on
desktop-when-plugged-in once it's proven, where the cost is near zero and the anonymity set
grows for free.

**Enforcement:** metadata properties are exactly what a routine refactor silently breaks.
A traffic-analysis test harness lands in Phase 3 and runs in CI forever, asserting envelope
size uniformity and statistical indistinguishability of send/receive/idle in Quiet Mode.

## Alternatives rejected

- **Maximum protection for everyone by default:** unusable on mobile, and mobile is where a
  Signal alternative lives or dies.
- **Sealed sender only, everything else the user's problem:** leaves message sizes and
  timing wide open, which is most of the social graph.
- **A mixnet in v1:** the only real defence against A7, and a different project. The
  transport layer is abstracted so a mixnet backend can be added as a third tier later
  without protocol changes; no mixnet-grade claims are made in the meantime.
