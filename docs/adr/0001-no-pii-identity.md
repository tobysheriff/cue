# ADR-0001 — Auto-assigned handles, no phone number or email

**Status:** Accepted · **Adversaries addressed:** A2 (operator), A3 (legal process),
A4 (seizure)

## Context

Signal requires a phone number. That is a state-issued identifier tied to a billing
relationship, often to an address, and increasingly to identity documents. It makes the
contact graph discoverable, and it means the operator holds — and can be compelled to
produce — something that maps an account to a person. Every other privacy property Signal
has is built on top of that liability.

Cue's premise is that the operator should be architecturally incapable of betraying users.
Holding any PII contradicts that premise directly.

## Decision

Accounts are identified by an **auto-generated handle** of the form `adjective-nounNNN`
(e.g. `brisk-otter472`) bound to a long-term identity keypair. No phone number, no email,
no password, no chosen username. Handles are assigned rather than chosen, from a ~4.2
billion keyspace, with limited rerolls.

## Consequences

**Good:** the honest answer to legal process is a very short list. Seizure yields nothing
that identifies a person. No contact-discovery problem exists at all, which deletes an
entire subsystem (Signal's private contact discovery enclaves) before it's built. Users
can shed a burned identifier by rerolling.

**Bad:** no Sybil resistance from identity — anti-abuse must come from proof of work,
ingress reputation, trust levels, and message-request gating (`docs/02`), and it will still
be weaker than phone verification. Ban evasion is possible and cannot be fully prevented.
Account recovery is a recovery phrase or nothing, and real users will lose accounts.
Discovery is manual (handle, QR, invite link), which is friction on the growth path.

## Alternatives rejected

- **Phone numbers:** the problem being solved. Rejected outright.
- **Chosen usernames:** leak identity through reuse across services, invite squatting, and
  create a namespace that needs policing.
- **Optional email for recovery:** any stored email is a subpoena target, and "optional"
  privacy defaults are chosen by nobody who needs them.
- **Invite-only registration as the global default:** excellent abuse resistance, but the
  invite graph is itself sensitive metadata, and it throttles adoption hard. Kept as a
  per-Node option (`docs/10`) rather than a protocol requirement.
