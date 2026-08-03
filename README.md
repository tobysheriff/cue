# Cue

An open-source, metadata-resistant messenger. End-to-end encrypted private messaging
with the Signal protocol, plus optional public communities — on backends anyone can run.

**Status: Phase 0 (foundations) — see `docs/11-roadmap.md`.** Cargo workspace and CI are
in place; no protocol implementation yet.

Cue is designed around one uncomfortable premise: *the operator of the default Node should
not be able to betray its users, even under legal compulsion, even if the machine is
seized, even if the operator wants to.* Everything in this design follows from that.

## Vocabulary

Three words do a lot of work in these docs. They are deliberately distinct:

| Term | What it is | Analogy |
|---|---|---|
| **Node** | A backend deployment. Hosts accounts, relays ciphertext, has its own operators, moderators, rules, and branding. `cue.example` is a Node; you can run your own. | A homeserver / an email provider |
| **Hall** | A public community living on a Node. Has members, roles, moderators, and persistent history. | A Discord server / Telegram group |
| **Room** | A channel inside a Hall. | `#general` |

An account belongs to exactly one Node. A Node hosts many Halls. A Hall contains many Rooms.

## What Cue is

- **Private by identity.** Accounts are auto-generated handles (`brisk-otter472`). No
  phone number. No email. The Node never holds an identifier that maps to a person.
- **End-to-end encrypted.** Signal protocol (PQXDH + Double Ratchet) for direct messages,
  MLS (RFC 9420) for encrypted groups.
- **Metadata-resistant.** Padded fixed-size envelopes, sealed sender, IP-blind ingress,
  anonymous authentication credentials, and an opt-in high-security transport with cover
  traffic and timing decorrelation.
- **Ephemeral by default.** Messages are delivered and deleted. Keeping one is a mutual,
  visible act — either side can ask to save a message, and it persists only if both agree.
- **Two honest tiers.** Encrypted DMs and groups the Node cannot read, and public Halls it
  *can* read — labelled unmistakably, never blurred.
- **Yours to run.** Anyone can operate a Node, with real control over it: invite-only or
  open registration, its own automod policy, its own branding, its own rules and
  moderators. The client ships pointing at the default Node and lets you change it in one
  screen.

## What Cue is not

- Not a federated network (v1). An account lives on one Node. See `docs/10`.
- Not anonymous against a global passive adversary in default mode. See `docs/01`.
- Not a place where the operator can read your private messages *and also* not a place
  where the operator can stop you from being harassed in one. See `docs/08`.

## Documentation

| Doc | What it covers |
|---|---|
| [00 — Vision & Scope](docs/00-vision-and-scope.md) | Product definition, non-goals, success criteria |
| [01 — Threat Model](docs/01-threat-model.md) | Adversaries, assets, explicit non-protections |
| [02 — Identity & Accounts](docs/02-identity-and-accounts.md) | Handles, keys, devices, recovery, anti-abuse |
| [03 — Cryptographic Design](docs/03-cryptographic-design.md) | PQXDH, Double Ratchet, MLS, zkgroup, key transparency |
| [04 — Metadata Resistance](docs/04-metadata-resistance.md) | Padding, sealed sender, IP-blind ingress, cover traffic |
| [05 — Node Architecture](docs/05-node-architecture.md) | Rust crates, storage, data retention, operations |
| [06 — Client Architecture](docs/06-client-architecture.md) | Rust core, Electron shell, web shell, local storage |
| [07 — Halls](docs/07-halls.md) | Discord/Telegram-style public communities |
| [08 — Moderation & Trust and Safety](docs/08-moderation-and-trust-safety.md) | Franking, reports, moderator tooling, legal posture |
| [09 — Message Lifecycle](docs/09-message-lifecycle.md) | Ephemerality, mutual save, attachments, calls |
| [10 — Running a Node](docs/10-running-a-node.md) | Node policy, branding, invite-only, directory, federation |
| [11 — Roadmap](docs/11-roadmap.md) | Phases, milestones, sequencing, effort |
| [12 — Open Questions](docs/12-open-questions.md) | Unresolved decisions, with recommendations |
| [ADRs](docs/adr/) | Architecture decision records |

## Licence

Node server: AGPL-3.0. Clients and shared cores: GPL-3.0. Protocol specification:
CC-BY-4.0. See [ADR-0008](docs/adr/0008-licensing.md) for the reasoning.
