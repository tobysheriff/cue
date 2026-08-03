# Architecture Decision Records

One file per decision that would be expensive to reverse. Format: context, decision,
consequences, alternatives rejected. Superseded ADRs are kept, marked, and linked — the
record of why we changed our mind is worth as much as the decision.

Rule from `docs/01`: **every protocol change requires an ADR naming the adversary it
addresses.**

| # | Decision | Status |
|---|---|---|
| [0001](0001-no-pii-identity.md) | Auto-assigned handles, no phone number or email | Accepted |
| [0002](0002-two-tier-encryption.md) | Two explicit encryption tiers, never blurred | Accepted |
| [0003](0003-mls-for-groups.md) | MLS for groups; 20-member default cap | Accepted |
| [0004](0004-no-federation-v1.md) | Independent Nodes, no federation in v1 | Accepted |
| [0005](0005-deliver-and-delete.md) | Deliver-and-delete with mutual save | Accepted |
| [0006](0006-metadata-tiers.md) | Mandatory metadata floor + opt-in Quiet Mode | Accepted |
| [0007](0007-rust-core-clients.md) | Shared Rust core, Electron + web shells | Accepted |
| [0008](0008-licensing.md) | AGPL-3.0 server, GPL-3.0 clients | Accepted |
| [0009](0009-sybil-and-ban-evasion.md) | Layered Sybil resistance; multiple optional paths to trust | Accepted |
