# 11 — Roadmap

## Read this first

This is a multi-year project. An honest estimate for everything in these docs, built to a
standard where an external audit passes, is **roughly 30–45 person-months** — about
2.5–3.5 years for one experienced full-time engineer, or 12–18 months for a team of three
with the right mix (Rust backend, cryptography, client/UX).

That is not a reason not to build it. It *is* a reason to sequence ruthlessly, ship
something real early, and make sure that if the project stops at Phase 4, what exists is
still a working, honest, useful messenger rather than half a protocol.

The order below is chosen so that every phase ends with something that works.

---

## Phase 0 — Foundations (4–6 weeks)

Decide and write down, before any product code:

- [ ] Finalise `docs/12` open questions; write ADRs for each resolution
- [ ] Cargo workspace, CI (fmt, clippy `-D warnings`, deny.toml for licences/advisories)
- [ ] `cue-proto`: protobuf schema for every wire object, version byte, size buckets
- [ ] `cue-crypto`: libsignal + openmls wrappers with the policy layer and doc comments
- [ ] Threat model review with someone outside the project
- [ ] Legal: jurisdiction decision, entity structure, terms, privacy policy — this gates
      the default Node's existence and has a long lead time, so start it now
- [ ] Reproducible-build infrastructure from the first commit, not retrofitted

**Exit:** protocol spec reviewable by a cryptographer; empty but building workspace.

## Phase 1 — Private messaging, end to end (10–14 weeks)

The vertical slice that proves the whole thing.

- [ ] `cue-node`: registration (PoW, handle assignment), prekeys, devices
- [ ] Ingress with IP stripping and in-memory bucket reputation
- [ ] Delivery: mailboxes, deliver-and-delete, WebSocket connection
- [ ] `cue-core`: PQXDH + Double Ratchet 1:1 sessions, encrypted local store
- [ ] Minimal Electron shell: register, add contact by handle, send/receive text
- [ ] Recovery phrase generation and restore
- [ ] Two-clients-plus-Node integration test in CI

**Exit:** two people message each other securely. Ugly, but real.

## Phase 2 — Ephemerality, groups, and the things that make it usable (10–14 weeks)

- [ ] Retention windows, expiry enforcement in core, secure deletion
- [ ] Mutual save: request/confirm/unsave, Saved view, group unanimity rules
- [ ] MLS groups via `openmls`, 20-member default cap, Node-configurable
- [ ] zkgroup-style anonymous group credentials — the Node stops seeing membership
- [ ] Attachments: encryption, metadata stripping, blob store, decorrelated fetch
- [ ] Message requests, blocking, safety numbers, QR verification
- [ ] Multi-device linking and device-to-device history transfer
- [ ] Real UI: the two-tier visual language, accessibility pass, i18n scaffolding

**Exit:** a messenger you could actually use daily with a small group of people.

## Phase 3 — Key transparency and metadata floor (8–12 weeks)

The phase that turns "trust the operator" into "verify the operator".

- [ ] `cue-kt`: Merkle prefix tree, signed tree heads, inclusion/consistency proofs
- [ ] Client-side KT verification; auditor API; at least one independent auditor recruited
- [ ] Sealed sender + anonymous delivery credentials (VOPRF), batch issuance schedule
- [ ] Padding buckets enforced end to end; padded control messages
- [ ] Rotating mailbox identifiers
- [ ] Traffic-analysis test harness in CI (`docs/04`)

**Exit:** a hostile Node can't substitute keys undetected and can't see who sends what.

## Phase 4 — Halls, moderation, and self-hosting (12–16 weeks)

- [ ] Halls: Rooms, roles, permissions, threads, invites, history, search
- [ ] Automod engine, profiles, Node baseline + per-Hall rules
- [ ] Asymmetric message franking — **external cryptographic review before merge**
- [ ] Franked reporting flow, report bundles with per-message consent
- [ ] Moderation console, queue, sanctions, appeals, audit log
- [ ] Node policy engine, `cue-node init/validate/doctor`, branding
- [ ] Self-hosting docs, Docker/systemd/Nix packaging, Node directory
- [ ] Web client (WASM) with its honest limitations notice

**Exit:** communities work, moderators have tools, other people can run Nodes.

## Phase 5 — Hardening, audit, and 1.0 (10–14 weeks)

- [ ] External cryptographic + application security audit; fix; publish in full
- [ ] Quiet Mode: cover traffic, batched delivery, `arti` onion transport
- [ ] OHTTP relay with an independent operator
- [ ] Seizure simulation and published data-at-rest inventory
- [ ] Reproducible builds verified by a third party; signed releases; update channel
- [ ] Load testing to the `docs/00` targets; failure-mode runbooks
- [ ] Transparency report, warrant canary, law-enforcement guide, disclosure policy
- [ ] Documentation completeness pass; protocol spec published

**Exit: 1.0.**

## Phase 6 and beyond (post-1.0)

Roughly in order of value:

1. **Mobile clients** (iOS + Android via UniFFI over `cue-core`). The biggest gap in the
   "Signal alternative" claim; also where push-notification metadata gets hard (`docs/12`).
2. **Voice and video** — E2EE 1:1 and small-group calls with unconditional TURN relay;
   SFU for Halls.
3. **Bots and webhooks** for Halls.
4. **Account portability** between Nodes.
5. **Secure recovery backup** (SVR-style), only if the hardware story is credible.
6. **Federation** for DMs and groups, if the metadata cost can be justified.
7. **Mixnet transport** as a third tier.

---

## Sequencing rules

- **Nothing ships to real users before Phase 3.** Key transparency and sealed sender aren't
  polish; without them the security claims aren't true, and users who arrive early make
  decisions based on claims that don't yet hold.
- **Franking gets external review before it merges.** It is the one novel construction in
  the project (`docs/03`).
- **The traffic-analysis suite lands in Phase 3 and runs forever.** Metadata properties are
  the ones a routine refactor silently breaks, and nobody notices without a test.
- **Every phase ends with the threat model reviewed** against what actually got built.
- **Don't build Halls before private messaging is finished.** Halls are the fun part and
  the trap: they're a normal chat app with no cryptographic constraints, so they'll expand
  to fill all available time.

## Team shape

The minimum viable team is three people: one Rust backend engineer, one engineer
comfortable with applied cryptography (the KT, credential, and franking work is not
generalist work), and one client/UX engineer who takes the two-tier visual language
seriously. Plus, before launch: a lawyer, an external auditor, and — from the moment the
default Node opens — at least two moderators who are not you.

The most common way projects like this fail is not technical. It is a solo founder
building excellent cryptography, launching a public default Node, and discovering that
moderation and legal exposure are a full-time job that arrived overnight.
