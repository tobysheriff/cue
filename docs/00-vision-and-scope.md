# 00 — Vision & Scope

## The one-sentence version

Cue is a messenger where the server operator's honesty is irrelevant, because the server
is architecturally incapable of learning who you are, who you talk to, or what you say.

## Why build it

Signal is excellent cryptography attached to a phone number. That phone number is the
whole problem: it is a state-issued identifier, it is required to register, it links an
account to a billing relationship and often to a physical address, and it makes the
contact graph discoverable. For a large class of users — journalists, activists,
researchers, abuse survivors, people in jurisdictions where a SIM card requires a passport
— that single design choice defeats everything built on top of it.

Cue's bet is that you can have Signal-grade message security *without* an identity anchor,
and that the remaining hard problems (spam, moderation, discovery, recovery) are solvable
with cryptography and product design rather than with PII.

## Product definition

Cue has exactly two kinds of space, and the difference is stated bluntly in the UI:

**Private (encrypted).** Direct messages and fully end-to-end encrypted groups — 20
members by default, a limit each Node sets for itself up to a protocol ceiling of 1,000.
The Node routes ciphertext and knows nothing else: not the content, not the member list,
not who sent what. Ephemeral by default. No server-side search. No server-side moderation
— only cryptographically verifiable user reports.

**Halls (public).** Discord/Telegram-style communities: channels, roles, threads,
persistent history, search, invites, bots. Transport-encrypted, **not** end-to-end
encrypted; the server and the Hall's moderators can read them. This is stated on join,
shown persistently in the channel header, and rendered in a visually distinct treatment
so it can never be mistaken for a private conversation.

Blurring these two is the single worst thing this project could do. Telegram's core sin
is that "chat" and "secret chat" look alike; Cue must make the boundary impossible to
misread. See [ADR-0002](adr/0002-two-tier-encryption.md).

## Design principles

1. **The server is a dumb, forgetful pipe.** Every feature request gets asked: does this
   require the server to remember something? If yes, can we push it to the client?
2. **No PII, ever, anywhere.** Not "hashed", not "encrypted at rest", not "deleted after
   30 days". Not collected.
3. **Anonymity is default, not a mode.** A privacy feature that users must find and
   enable protects almost nobody. The exception is cost: features with a real battery or
   bandwidth price are opt-in with clear framing (see `docs/04`).
4. **Honest about limits.** Every documented protection has a documented failure case.
   Overclaiming gets people hurt.
5. **Boring cryptography.** Use libsignal, OpenMLS, and RustCrypto. Novel primitives only
   where the literature is settled and no implementation exists, and never without review.
6. **Auditable end to end.** Reproducible builds, signed releases, public audits, and an
   architecture a reviewer can hold in their head.

## Success criteria

Cue v1.0 is successful if all of the following are true:

- An external cryptographic audit finds no critical or high findings in the protocol
  or its implementation.
- Seizing the default server's disks yields: a set of opaque account records with no
  usernames-to-IP linkage, a queue of undelivered ciphertext, and public Hall content.
  Nothing else. This is demonstrated publicly with a documented seizure-simulation exercise.
- A new user can install, register, and message a friend in under 90 seconds without
  entering any personal information.
- A Hall of 5,000 members is moderated by its own team, with a Node-level moderator
  escalation path, without the operator having any ability to read private messages.
- Someone unaffiliated with the project has successfully run their own Cue server from
  the documentation alone, without asking for help.

## Explicit non-goals for v1

- **Federation.** Independent Nodes only. Design keeps the door open; see `docs/10`.
- **Mobile clients.** The Rust core is built so mobile can bind to it without rewriting
  crypto, but shipping iOS/Android is post-1.0. This is the largest known gap in the
  "Signal alternative" claim and is stated as such.
- **Interoperability** with Signal, Matrix, XMPP, or anything else.
- **Server-side message search** in private tiers. Not possible; not attempted.
- **Cloud backup of private history.** Ephemerality is a feature, not a limitation to
  work around.
- **Monetisation.** No ads, no telemetry, no analytics, no paid tiers in v1. Funding
  model is an open question (`docs/12`).

## Scale assumptions for v1

Sizing the design honestly, so we don't over-engineer or under-engineer:

| Dimension | v1 target | Design headroom |
|---|---|---|
| Registered accounts (default Node) | 50,000 | 1M |
| Concurrent connections | 10,000 | 250,000 |
| Messages/sec sustained | 500 | 20,000 |
| Encrypted group size | 20 (default Node policy) | 1,000 (protocol ceiling) |
| Hall size | 10,000 | 100,000 |
| Attachment size | 100 MB | 2 GB |

## The uncomfortable trade-offs, stated up front

- **No recovery.** Lose every device and your recovery key, and the account is gone —
  no reset, no support ticket, no exception. This *is* the security property; anything
  the operator can do to restore your account, an attacker can coerce them into doing.
- **Ephemerality costs history.** Deliver-and-delete plus mutual-save means Cue will never
  feel like Slack. Users who want a searchable archive of their life are not the audience.
- **Anonymity costs spam resistance.** No phone number means the anti-abuse system has to
  be genuinely good (`docs/02`), and it will still be worse than Signal's at stopping
  determined mass registration.
- **Metadata resistance costs speed and battery.** The high-security transport tier trades
  latency and bandwidth for unlinkability, which is why it is a tier and not the floor.
- **The operator carries legal risk.** Running a public default Node with anonymous
  registration and encrypted messaging attracts hostile attention. `docs/08` covers the
  legal posture; this needs real legal advice, not just engineering.
