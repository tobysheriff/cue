# ADR-0003 — MLS for groups, 20-member default cap

**Status:** Accepted · **Adversaries addressed:** A2 (operator), A6 (endpoint compromise
of a former member)

## Context

Cue uses the Signal protocol for 1:1. For groups there are two credible options: Signal's
own sender-key scheme layered over pairwise Double Ratchet sessions, or MLS (RFC 9420).

Sender keys are simple and battle-tested, but membership changes cost O(n) pairwise
messages, and removal is weak: every remaining member must rotate and redistribute, and one
lazy or offline client leaves the removed member able to read on. MLS gives O(log n)
membership updates via a TreeKEM ratchet tree, and a removal commit genuinely excludes the
removed member from everything afterwards.

## Decision

- **1:1:** PQXDH + Double Ratchet (libsignal), unchanged.
- **Groups of 3 or more:** MLS via `openmls`, ciphersuite
  `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`.
- **The Node is the MLS Delivery Service** and cannot read messages or see membership;
  membership is protected by zkgroup-style anonymous credentials.
- **Default cap: 20 members** on the default Node. Node operators may configure
  `groups.max_members` up to a protocol ceiling of **1,000**. The cap is advertised in the
  Node capability descriptor and shown to users.
- Only one group mechanism. No sender-key path for small groups.

## Consequences

**Good:** correct removal semantics, cheap membership changes, post-compromise security
across the group, and a standardised protocol with a maintained Rust implementation. One
group code path instead of two.

**Bad:** MLS is younger than the Double Ratchet and `openmls` is less battle-tested than
`libsignal`. Group state is heavier on the client. Epoch/commit ordering must be handled
carefully when clients are offline for long periods — the main implementation risk.

The 20-member default is a product stance: a group that small is people who know each
other, which is the threat model E2EE actually serves. Anything larger is a broadcast
channel wearing a group's clothes, and belongs in a Hall where the encryption claim isn't
quietly false. Users who want bigger encrypted groups can use a Node that allows them —
which is decentralisation doing its job.

## Alternatives rejected

- **Sender keys everywhere:** weak removal, O(n) membership churn.
- **Sender keys for small, MLS for large:** two protocols, two sets of bugs, a migration
  edge at the boundary. Not worth it.
- **A single global cap:** takes a legitimate choice away from Node operators for no
  security benefit — the ceiling of 1,000 exists for client performance, not for policy.
