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
  `Identity`, `generate_prekeys`, `establish_session`, `encrypt_message`, `decrypt_message`
  all work end-to-end (round-trip test in `sessions.rs` — Alice and Bob complete a
  handshake and exchange messages). Storage is in-memory only
  (`libsignal_protocol::InMemSignalProtocolStore`); persistence is `cue-core`'s job
  (docs/06) and isn't wired yet.
- **`cue-crypto::groups`, `::credentials`, `::franking`** — stubs (`NotImplemented`).
- **`cue-proto`** — real: `Envelope`/`SizeBucket` wire types, plus a `registration.proto`
  (`RegistrationChallenge`, `RegisterRequest`/`Response`, `PrekeyBundleResponse`,
  `RerollHandleRequest`/`Response`) for `cue-node`'s registration API. Round-trip tested.
- **`cue-node`** — real (Phase 1 registration slice): an axum server (`main.rs`) exposing
  `POST /v1/register/challenge`, `POST /v1/register`, `POST /v1/register/reroll`, and
  `GET /v1/accounts/{handle}/prekey-bundle`. `accounts::pow` (Argon2id proof of work,
  single-use challenges), `accounts::handle` (adjective-nounNNN assignment from an embedded
  128-word placeholder wordlist pair — docs/02 specs a curated 2,048-entry pair, swappable
  later as a data change), `accounts::trust` (L0–L3 enum, always L0 today — the ramp logic
  isn't implemented), and `accounts::store` (`AccountStore` trait + in-memory impl) all work
  end-to-end, covered by an axum-`Router`-level integration test (`api::tests`, driven via
  `tower::ServiceExt::oneshot`) that registers an account, fetches and exhausts its
  one-time prekey, and reroll-authenticates with a real libsignal identity-key signature.
  `ingress::reputation` provides IP-bucketing (daily-rotating HMAC, never stores or forwards
  the IP itself) and strike-based CAPTCHA/review escalation; CAPTCHA verification itself is
  a `CaptchaVerifier` trait with only a test stub (`NullCaptchaVerifier`) — no real provider
  wired in. Storage is in-memory only; a Postgres-backed `AccountStore` is the natural next
  step. `admin`, `auth`, `blobs`, `delivery`, `halls`, `mls_ds`, `moderation`, `policy` are
  still stubs.
- **`cue-kt`, `cue-core`, `cue-testkit`** — stubs / scaffolding only. `cue-core`'s
  `Command`/`Event` enums are intentionally empty.

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
  Quiet Mode timing is indistinguishable from idle (Phase 3+, then runs in CI forever).

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

Update this file before ending any coding session that changed what's implemented, not
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
