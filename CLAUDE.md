#
 CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Cue is an open-source, metadata-resistant messenger: E2EE private messaging (Signal
protocol) plus optional public communities ("Halls"), on backends ("Nodes") anyone can
run. The core premise driving every design decision: the operator of the default Node
must not be able to betray its users, even under legal compulsion or device seizure.

**Status: Phase 0 scaffolding is done; Phase 1 (private messaging) is underway.** See
`## Implementation status` below for exactly what's real versus still a stub. Most modules
are still doc-comment stubs describing what they must do and must never do, with
`todo!()` or `NotImplemented` bodies. When implementing a stub, read its module doc
comment first — those comments encode security constraints, not just descriptions, and
are treated as load-bearing.

Read `docs/11-roadmap.md` before starting non-trivial work to know what phase we're in and
what's explicitly out of scope for now (e.g. don't build Halls before private messaging;
franking requires external cryptographic review before merge).

## Implementation status

Kept current at the end of each coding session — see "Keeping this file current" at the
bottom. Anything not listed here is still a stub; check its module doc comment for what it
must never do before touching it.

- **`cue-crypto::sessions`** — real: PQXDH + Double Ratchet via `libsignal-protocol`.
  `Identity`, `generate_prekeys`, `establish_session`, `encrypt_message`, `decrypt_message`,
  `save_generated_prekeys` (saves a device's own generated prekeys locally before the
  public bundle is published — added so `cue-core` doesn't need its own direct
  `libsignal-protocol` dependency just to call the same three store-trait methods),
  `deserialize_ciphertext` (reconstructs a `CiphertextMessage` from wire bytes + declared
  `CiphertextMessageType` — Whisper/PreKey only, the two variants a 1:1 session ever
  produces), and `bundle_from_parts` (reconstructs a `PreKeyBundle` from a peer's raw
  published key bytes — the receiving side of `generate_prekeys`, used once those bytes
  have crossed the wire) all work end-to-end (round-trip test in `sessions.rs` — Alice and
  Bob complete a handshake and exchange messages; also exercised for real by
  `cue-testkit`'s two-clients-plus-Node test). Storage is generic over a new
  `ProtocolStoreParts` trait (exposes a store's disjoint sub-stores via one
  `parts_mut` call, since libsignal's own free functions need several simultaneous
  `&mut` sub-store borrows that only type-check against a concrete struct's named
  fields, not a trait object) rather than hard-coding `InMemSignalProtocolStore` —
  implemented for `InMemSignalProtocolStore` (this crate's own fast unit test, still
  in-memory) and for `cue-core`'s `EncryptedStore` (real persistence, see below).
  This crate itself still never depends on a storage engine.
- **`cue-crypto::recovery`** — real: `RecoveryPhrase` (docs/02 "Recovery"), the sole account
  recovery mechanism. `generate` produces a standard 24-word/256-bit English BIP39 phrase —
  docs/02 says "40-word... ~256 bits", but standard BIP39 ties word count to entropy
  precisely (24 words at 11 bits/word for 256 bits), so this uses the audited off-the-shelf
  wordlist rather than a bespoke 40-word encoding invented to match the doc literally
  (deliberate reconciliation, not a bug). `parse` restores from user-entered text and
  rejects a bad BIP39 checksum (almost always a mistyped word) instead of silently
  deriving the wrong identity. `to_identity` deterministically re-derives a `sessions::
  Identity`: the phrase's BIP39 seed is run through HKDF-SHA256 (domain-separated from
  BIP39's own HD-wallet derivation purpose) to seed a `ChaCha20Rng`, which
  `Identity::generate` then consumes exactly as it would any other `Rng + CryptoRng` —
  same phrase always yields the same identity (and registration id). `bip39`'s `zeroize`
  feature wipes the phrase/entropy on drop. Tested: word count, parse round-trip,
  determinism, distinct phrases yield distinct identities, and a tampered phrase is
  rejected at parse time. Not yet wired into a real registration/restore flow —
  `EncryptedStore::create`/`open` (see `cue-core` below) already accept any `Identity`
  regardless of how it was produced, but there is no account-creation flow to call them
  from yet (`Identity::generate` itself is still test-only in `cue-core`); that lands with
  the Electron shell.
- **`cue-crypto::groups`, `::credentials`, `::franking`** — stubs (`NotImplemented`).
- **`cue-proto`** — real: `Envelope`/`SizeBucket` wire types (`Envelope` now carries an
  `envelope_id`, assigned by `delivery` on enqueue for dedup/ack — never set by the sender),
  a `registration.proto` (`RegistrationChallenge`, `RegisterRequest`/`Response` — both now
  carrying `registration_id`, required to reconstruct a usable `PreKeyBundle` and
  previously missing from the wire format entirely,
  `PrekeyBundleResponse` — also carrying the recipient's `mailbox_id` so a peer
  establishing a session learns where to address envelopes, `RerollHandleRequest`/
  `Response`) for `cue-node`'s registration API, a `delivery.proto`
  (`MailboxEnvelopes`, `AckRequest`) for the mailbox API, and a `transport.proto`
  (`SealedSenderStub`, `CiphertextMessageType`) — `cue-core`'s Phase 1 interim inner-envelope
  format, carried inside `Envelope.ciphertext`; see the `cue-core` entry below for the
  metadata-resistance trade-off it makes. Round-trip tested.
- **`cue-node`** — real (Phase 1 registration + delivery slice): split into a library
  (`lib.rs`, with `api` and `delivery` — and `accounts` for the integration test below —
  `pub`) and a thin `main.rs` binary, so `cue-testkit`'s integration test can drive a real
  `api::router` over a real socket from outside the crate; `accounts::pow::solve` (the
  client-side PoW search) is likewise `pub`, not test-only, since no client has its own
  registration module yet. An axum server exposing `POST /v1/register/challenge`,
  `POST /v1/register`, `POST /v1/register/reroll`,
  `GET /v1/accounts/{handle}/prekey-bundle`, `POST /v1/deliver`, `GET /v1/mailbox/{id}`,
  `POST /v1/mailbox/{id}/ack`, and `GET /v1/mailbox/{id}/ws`. `accounts::pow` (Argon2id
  proof of work, single-use challenges), `accounts::handle` (adjective-nounNNN assignment
  from an embedded 128-word placeholder wordlist pair — docs/02 specs a curated
  2,048-entry pair, swappable later as a data change), `accounts::trust` (L0–L3 enum,
  always L0 today — the ramp logic isn't implemented), and `accounts::store`
  (`AccountStore` trait + in-memory impl) all work end-to-end, covered by an
  axum-`Router`-level integration test (`api::tests`, driven via
  `tower::ServiceExt::oneshot`) that registers an account, fetches and exhausts its
  one-time prekey, and reroll-authenticates with a real libsignal identity-key signature.
  `delivery::mailbox` (`MailboxStore` trait + in-memory impl) is a deliver-and-delete queue
  keyed by opaque `mailbox_id` alone — no dependency on `accounts`, by design (docs/04 #2,
  #3) — with a hard 30-day TTL swept hourly from `main`, `POST /v1/deliver` validating
  ciphertext length against its claimed `SizeBucket`, and `GET /v1/mailbox/{id}/ws` flushing
  the queue on connect then fanning out live enqueues, tested end-to-end with a real bound
  socket and `tokio-tungstenite` as the client. Known Phase 1 gap against docs/04: mailbox
  IDs are minted once at registration and never epoch-rotate (Phase 3's job), and there's no
  sealed-sender/anonymous-credential auth on the delivery endpoints yet (also Phase 3) — the
  Node currently trusts whatever `mailbox_id` a caller supplies, same trust level as
  registration's PoW-gated-but-otherwise-open endpoints. `ingress::reputation` provides
  IP-bucketing (daily-rotating HMAC, never stores or forwards the IP itself) and
  strike-based CAPTCHA/review escalation; CAPTCHA verification itself is a `CaptchaVerifier`
  trait with only a test stub (`NullCaptchaVerifier`) — no real provider wired in. Storage
  is in-memory only throughout; a Postgres-backed `AccountStore` and `envelopes` table are
  the natural next step. `admin`, `auth`, `blobs`, `halls`, `mls_ds`, `moderation`, `policy`
  are still stubs.
- **`cue-core`** — real (Phase 1 session slice): `Command`/`Event` are no longer empty —
  `Command::{EstablishSession, SendMessage, ReceiveMessage}` in, `Event::{SessionEstablished,
  MessageSent, MessageReceived, CommandFailed}` out, both with hand-written (not derived)
  `Debug` impls that print shapes/lengths only, never plaintext or key material. `session::
  SessionManager` wraps `cue_crypto::sessions` (one `InMemSignalProtocolStore` per device,
  in-memory only — same caveat as `cue-crypto::sessions` itself, persistence still
  unwired). `Core::spawn` runs the actor on its own dedicated OS thread with a
  single-threaded Tokio runtime + `LocalSet`, not `tokio::spawn` on a shared runtime —
  `libsignal-protocol`'s store traits return `!Send` futures, so a plain `tokio::spawn`
  doesn't compile; this is still "its own Tokio runtime" per docs/06, just not the shell's.
  Tested at both layers: `session::tests` exercises `SessionManager` directly (mirroring
  `cue-crypto`'s own round-trip test), and `tests` in `lib.rs` drives two full `Core` actors
  purely through their `Command`/`Event` channels to complete a handshake and exchange
  messages both directions.

  `transport` (new) resolves `Event::MessageSent`'s former "still undesigned" gap:
  `seal_for_delivery`/`open_received` turn a raw `CiphertextMessage` into a wire-ready
  `cue_proto::v1::Envelope` and back, and `NodeClient` (`reqwest`, rustls) speaks
  `cue-node`'s full delivery surface — `/v1/deliver`, `/v1/mailbox/{id}`,
  `/v1/mailbox/{id}/ack`, `/v1/accounts/{handle}/prekey-bundle` over HTTP, plus
  `watch_mailbox` opening a live `GET /v1/mailbox/{id}/ws` connection
  (`tokio-tungstenite`) that returns a `MailboxStream` with `recv`/`ack`, so a shell isn't
  limited to polling `fetch_mailbox`. It is a separate layer composed with `Core` over its
  public channels, not a new `Command`/`Event` variant. **Deliberate,
  tracked trade-off:** sender identity travels in the clear inside
  `Envelope.ciphertext` (a `cue_proto::v1::SealedSenderStub`, not a new `Envelope` field),
  because real sealed sender — asymmetric encryption of sender identity to the recipient's
  identity key (docs/03) — is Phase 3 crypto work, not wiring; libsignal's decrypt is
  keyed by sender address, so the recipient needs to learn it somehow before Phase 3 lands.
  This is a real metadata-resistance regression against docs/04 #2, accepted for Phase 1
  only and documented on `SealedSenderStub` itself. Padding reaches bucket granularity only
  (the four docs/04 sizes), not a stronger traffic-analysis bar — that's the Phase 3
  harness's job. Also assumes one (primary) device per account, matching `cue-node`'s
  current account model.

  Exercised end-to-end (not just unit-tested) by `cue-testkit`'s
  `two_clients_and_a_node.rs`, two tests: the polling path (two real
  `Core`+`SessionManager` clients, real HTTP registration including solving a real PoW
  challenge, and a real bound `cue-node` socket — the closest thing to Phase 1's "two
  people message each other" exit criterion that exists yet, and the
  "two-clients-plus-Node integration test in CI" docs/11 asks for), and the live
  `watch_mailbox` path (connects before delivery, so a passing `recv()` proves the
  server's live fan-out branch, not its connect-time queue flush; acks over the socket
  itself rather than the HTTP endpoint).

  Not yet built: KT verification and group sessions/MLS.

  `store` (new) is the encrypted local store (docs/06 "Local storage and ephemerality",
  docs/03 "Local storage encryption"): `EncryptedStore`, a SQLCipher-backed (`rusqlite`,
  `bundled-sqlcipher-vendored-openssl` — vendors SQLCipher *and* OpenSSL from source, no
  new system dependency, matching this workspace's existing reproducible-build rationale)
  replacement for `InMemSignalProtocolStore` that persists identity, sessions, and prekeys
  across restarts, implementing `cue_crypto::sessions::ProtocolStoreParts` so it plugs
  straight into the same functions `SessionManager` already called. Keyed by a random
  256-bit key held in the OS keychain (`keyring` crate; macOS Keychain / Windows Credential
  Manager / Linux Secret Service via `zbus`) via `StoreKeySource`/`OsKeychainKeySource` —
  `EncryptedStore::create`/`open` take the key directly, so tests never touch a real
  keychain (`cargo test` uses a fixed test key, exercising the exact same SQL/trait-impl
  code as production including SQLite's special `":memory:"` connection string for
  zero-disk-I/O speed). `SessionManager::new` now takes an already-opened `EncryptedStore`
  instead of building an in-memory one itself — the caller (still just tests; no shell
  exists yet) is responsible for `create` on first run vs. `open` on restart. `Core`,
  `Command`, and `Event` needed no changes. Tested with a real temp-dir-backed store closed
  and reopened mid-test (session and prekey state survive), a wrong-key-must-fail-not-
  corrupt test, and a manual check that the on-disk file has no plaintext SQLite header.
  **Deliberate, tracked Phase 1 scope**, matching `SealedSenderStub`'s precedent: no
  optional Argon2id app-lock passphrase (docs/03's other keying mode), no "panic wipe," no
  ephemerality timers or secure-deletion vacuum, no local search index — each is Phase 2
  polish (docs/11: "Retention windows, expiry enforcement in core, secure deletion"), not
  this slice's job.
- **`cue-kt`** — stub / scaffolding only.
- **`cue-testkit`** — `size_bucket_for` is real (the docs/04 1/4/16/64 KB mapping — an
  independent reference implementation, not one `cue-core`'s `transport` calls into, so it
  can actually catch drift). `tests/two_clients_and_a_node.rs` (two tests, polling and live
  WebSocket push) is the docs/11 Phase 1 exit test described above; it's why this crate
  carries dev-dependencies on `cue-core`, `cue-crypto`, and `cue-node` even though its own
  runtime `lib.rs` still depends on `cue-proto` only, matching the architecture diagram
  below. The traffic-analysis harness itself is still Phase 3 scope.

## Commands

```sh
cargo build --workspace --all-targets   # build everything, including tests/examples
cargo test --workspace                  # run all tests
cargo test -p cue-proto envelope_round_trips_through_the_wire_format  # single test
cargo fmt --all -- --check              # CI formatting gate
cargo fmt --all                         # apply formatting
cargo clippy --workspace --all-targets -- -D warnings  # CI lint gate (warnings are errors)
cargo deny check                        # licence + advisory gate (needs cargo-deny installed)
```

CI (`.github/workflows/ci.yml`) runs `fmt`, `clippy -D warnings`, `build` + `test`, and
`cargo-deny` as independent jobs on every push/PR to `main`. Match these locally before
considering work done — `unsafe_code` is `#![forbid]`'d in every crate, and clippy warnings
fail CI.

`cue-proto`'s build script (`crates/cue-proto/build.rs`) compiles `.proto` files with
`protox` (pure-Rust) into generated Rust — no system `protoc` install required.

`cue-crypto` depends on `libsignal-protocol` (git dependency, pinned by tag — not published
to crates.io by design; see `crates/cue-crypto/Cargo.toml`). Unlike `cue-proto`, this *does*
require a system `protoc` (its `spqr` sub-dependency shells out to it): install
`protobuf-compiler` locally, and note CI installs it in the `clippy`/`test` jobs. Bumping
the pinned tag is a deliberate, reviewed change, not a routine update — re-check
`deny.toml`'s licence allow-list, `sources.allow-git`, and the advisory `ignore` entry
against the new tag's dependency tree (`cargo deny check`) before merging a bump.

`cue-core`'s `rusqlite` dependency (the encrypted local store) uses the
`bundled-sqlcipher-vendored-openssl` feature: it compiles SQLCipher and OpenSSL from
vendored C source rather than linking a system library, so a clean build of `cue-core`
takes noticeably longer than the rest of the workspace — no new system dependency to
install, just build time. Pinned to `rusqlite` 0.33, not latest: 0.40's `libsqlite3-sys`
build script uses the still-unstable `cfg_select!` std macro and fails to compile on
stable rustc.

## Workspace architecture

Six crates, one binary (`cue-node`). Dependency direction is strict and one-way:

```
cue-proto  (wire types, Apache-2.0)  <- depended on by everything, depends on nothing internal
    ^                ^
cue-crypto        cue-testkit
    ^
cue-kt  <- (independent of crypto/proto today; verification logic)
    ^
cue-core  (client core, GPL-3.0)          cue-node  (server, AGPL-3.0)
```

- **`cue-proto`** — protobuf schema (`proto/envelope.proto`) and generated types. Shared
  verbatim by server and every client so they can never disagree about the wire format.
  Must never depend on any other Cue crate. Licensed Apache-2.0 (distinct from the rest of
  the workspace) specifically so third parties can build interoperable clients.
- **`cue-crypto`** — a *policy* wrapper over cryptographic primitives (PQXDH + Double
  Ratchet via `libsignal-protocol` — implemented, see Implementation status above; MLS via
  `openmls`, zkgroup-style anonymous credentials, and asymmetric message franking — still
  stubs). Owns policy decisions (key rotation cadence, prekey buffer size, credential epoch
  length) and must never reimplement or touch primitive internals directly. `franking` is
  the one novel cryptographic construction in the project and is gated on external review
  before it merges (Phase 4).
- **`cue-kt`** — key transparency: Merkle prefix tree, signed tree heads, inclusion/
  consistency proofs. Modelled on Signal KT/Parakeet, no novel crypto. This is what makes
  an equivocating Node provably detectable by a third-party auditor. Lands Phase 3.
- **`cue-core`** — the client core (GPL-3.0). All security-relevant client logic lives
  here: sessions, KT verification, local encrypted store, transport (padding, cover
  traffic, Tor via `arti`), credential lifecycle, franking. Exposes a narrow `Command` in /
  `Event` out API (not RPC) so shells stay "dumb" — they render and dispatch, and cannot
  make a cryptographic decision because they never get FFI access below this boundary.
  Bound by Electron (NAPI-RS), web (wasm-bindgen), and eventually mobile (UniFFI) — see
  ADR-0007. `#[non_exhaustive]`, versioned types throughout: an old shell must fail closed
  against a newer core, not guess.
- **`cue-node`** — the server (AGPL-3.0), one binary / one Postgres DB / one object store
  (Postgres isn't wired yet — see Implementation status above; the registration slice runs
  entirely in-memory). Submodules under `crates/cue-node/src/` (`accounts`, `admin`, `auth`,
  `blobs`, `delivery`, `halls`, `ingress`, `mls_ds`, `moderation`, `policy`) each carry a doc
  comment stating what that module must never do — e.g. `ingress` must never forward a
  client IP past itself or write a request-level access log (its `reputation` submodule is
  the one deliberate exception: it takes an `IpAddr` in and returns only an opaque,
  daily-rotating bucket key out); `delivery` must never grow a durable archive (envelopes
  are deleted on ack, hard 30-day TTL otherwise); `auth` must never let issuance and spend
  of a token be correlated. Preserve these invariants when touching these modules — they
  are the mechanism, not aspirational. `accounts`'s own invariant (never map a handle to a
  person) is likewise load-bearing, not aspirational.
- **`cue-testkit`** — protocol conformance suite (any future client must pass it) plus the
  traffic-analysis harness that asserts envelope sizes are uniform within a bucket and
  Quiet Mode timing is indistinguishable from idle (Phase 3+, then runs in CI forever). Its
  runtime `lib.rs` depends on `cue-proto` only, matching the diagram above — but it carries
  `cue-core`/`cue-crypto`/`cue-node` as **dev-dependencies** for its cross-crate integration
  tests (e.g. `tests/two_clients_and_a_node.rs`), which is this crate's actual job: it's
  the one place allowed to depend on a real client and a real server at once to verify they
  agree on the wire.

Clients (`clients/desktop`, `clients/web`) are not started yet — see their READMEs and
`docs/06-client-architecture.md`.

## Two-tier model — the thing not to break

Everything in this codebase distinguishes two honest tiers, and that distinction must
never blur:
1. **Encrypted DMs/groups** the Node genuinely cannot read.
2. **Public Halls** the Node *can* read, and which must be labelled unmistakably as such.

`policy::mod` (cue-node) exists specifically so Node branding can never reach the
encryption-tier indicators or the Hall/private visual distinction — a styled-to-look-secure
Hall is treated as a real attack, not a UX nitpick. Keep this in mind for anything touching
branding, UI labels, or the boundary between `halls` and everything else.

## Licensing shape

Per ADR-0008: `cue-node` is AGPL-3.0, `cue-core`/clients are GPL-3.0, `cue-proto`'s
generated types are Apache-2.0, the protocol spec (`docs/`) is CC-BY-4.0. `deny.toml`
enforces the allowed licence set for dependencies — check it before adding a new
dependency. Contributions use DCO (`Signed-off-by`), not a CLA.

## Docs map

`docs/00` through `docs/12` are numbered design docs (vision, threat model, identity,
crypto design, metadata resistance, node/client architecture, halls, moderation, message
lifecycle, running a node, roadmap, open questions); `docs/adr/` holds architecture
decision records. Module and crate doc comments throughout the code point back to specific
docs (e.g. `docs/04 #5`) — follow those references when a change touches security-relevant
behavior, rather than re-deriving the reasoning from scratch.

## Keeping this file current

Along with committing all changes and writing descriptive commit messages for each file, update this file before ending any coding session that changed what's implemented, not
just what's documented — a stale status here is worse than none, since the next session
(or the next instance of Claude) will trust it over re-deriving state from scratch:

- Update `## Implementation status` the moment a stub becomes real (or a real thing
  regresses to a stub) — that section is the first thing to check when picking up work,
  so it must reflect the code, not the plan.
- Update `## Commands` when a session adds a new system dependency, build step, or CI job
  (e.g. the `protoc` requirement `cue-crypto` introduced when it started wrapping
  `libsignal-protocol`).
- Update the `## Workspace architecture` bullet for a crate when its actual dependencies
  or role change materially from what's described there.
- Bump the `**Status: ...**` line at the top when a phase genuinely starts or finishes —
  don't leave it claiming Phase 0 once Phase 1 work has landed.
- Record a non-obvious architecture or trade-off decision inline, next to the thing it
  affects, in a sentence or two (e.g. "pinned to tag X, not latest, because Y") — not as a
  changelog entry. This file describes current state; `git log` is the history.

Don't let this section (or `## Implementation status`) turn into a changelog: when new
detail supersedes old, replace it, don't append to it.
