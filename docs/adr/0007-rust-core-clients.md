# ADR-0007 — Shared Rust core with Electron and web shells

**Status:** Accepted · **Adversaries addressed:** A6 (endpoint compromise), and the
perennial adversary of two diverging implementations

## Context

Cue needs a desktop app and benefits enormously from a web client. It will eventually need
mobile. Reimplementing the Signal protocol, MLS, key transparency, and the metadata
transport per platform would guarantee divergence, and divergence in crypto code means
vulnerabilities in exactly one platform that nobody notices.

## Decision

All security-relevant logic lives in **`cue-core`**, a Rust crate: sessions, ratchets, MLS,
key transparency verification, local encrypted storage, transport, padding, cover traffic,
anonymous credentials, franking. It is shared with the server via `cue-proto` and
`cue-crypto`, so client and server can never disagree about the wire format.

Shells bind to it:
- **Electron desktop** via NAPI-RS (native module in the main process)
- **Web PWA** via wasm-bindgen
- **Mobile, post-1.0** via UniFFI — no crypto rewrite required

The shells are deliberately dumb: they render and dispatch commands, and cannot make a
cryptographic decision. The core exposes a narrow, versioned command/event API rather than
a broad RPC surface.

## Consequences

**Good:** one audited implementation. Headless testing of the real protocol in CI. A clear
mobile path that doesn't restart the security work. The renderer can be given **zero**
network, filesystem, and key access, because all I/O happens in the core — which downgrades
a renderer XSS from catastrophic to cosmetic.

**Bad:** Electron is a large attack surface and a Chromium CVE treadmill; hardening is
non-negotiable and CI-enforced (`docs/06`). FFI boundaries add build complexity across three
platforms. WASM constrains the core (no threads by default, weaker key storage), so the
core must be written to work in both environments from the start rather than retrofitted.

The web client is **materially less secure** — IndexedDB key storage, no verifiable code
delivery — and says so in a persistent, non-dismissible notice rather than hiding it.

## Alternatives rejected

- **Native clients per platform:** best security and UX, several times the work, guarantees
  divergence for a small team.
- **Electron with TypeScript crypto:** a second implementation, in a language with weaker
  guarantees, that will drift from the server's.
- **Web-only PWA:** one codebase, but no reliable background delivery and permanently
  weaker key storage — an unacceptable ceiling for the users this project is for.
