# ADR-0005 — Deliver-and-delete, with mutual save as the only exception

**Status:** Accepted · **Adversaries addressed:** A3 (legal process), A4 (seizure),
A6 (device seizure)

## Context

Server-held message history — even ciphertext the operator can't read — is a long-lived,
seizable object, and the delivery metadata around it is worse than the ciphertext itself.
Signal's model is to hold a message only until it is delivered. The cost is that history
doesn't sync to new devices.

## Decision

**Server:** an envelope exists only until every recipient device acknowledges it, then it
is deleted. Undelivered envelopes expire at 30 days. No archive, no backup of the queue.

**Client:** conversations have a retention window, default 7 days for DMs and groups, with
options from "on read + 1 minute" to "keep until I delete". Changes apply to future
messages and are shown in-thread to both sides.

**Mutual save:** any participant can request that a message be saved; it persists only once
**every** participant confirms (majority-save is an off-by-default group option). Any
participant can unsave at any time, which returns the message to normal expiry — consent to
retention is continuously revocable. Save state is an E2EE control message; the Node never
learns that anything was saved.

## Consequences

**Good:** a seized Node yields only in-flight ciphertext for offline users. A seized
*device* usually yields very little. Retention is a shared decision rather than one party
unilaterally archiving the other.

**Bad:** no history sync to new devices (mitigated by encrypted device-to-device transfer
over the local network). Users lose things they wanted. Unanimity is friction in a
20-person group. Cue will never feel like Slack, and users who want a searchable archive
of their life are not the audience.

**Honest limit:** ephemerality protects against later device seizure, not against the person
you're messaging. Screenshot detection is deliberately not implemented — it is unreliable
and it teaches users to feel protected when they aren't. The app states this in onboarding.

## Alternatives rejected

- **Encrypted server-side archive:** much better UX, but creates the persistent seizable
  object the design exists to avoid.
- **Deliver-and-delete with no save at all:** loses information users legitimately need to
  keep, and pushes them to screenshot everything — which is worse, because a screenshot is
  invisible to the other party while a save is not.
- **Unilateral save:** lets one party archive the other's words without their knowledge.
  The mutual requirement is the entire point.
