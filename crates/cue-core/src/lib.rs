//! Client core (docs/06, ADR-0007). Everything security-relevant lives
//! here: session management, KT verification, the local encrypted store,
//! transport (padding, cover traffic, Tor via `arti`), anonymous credential
//! lifecycle, franking. Shells (Electron via NAPI-RS, web via
//! `wasm-bindgen`, mobile later via UniFFI) are deliberately dumb — they
//! render and dispatch `Command`s, and cannot make a cryptographic
//! decision, because they never get FFI access to anything below this
//! module boundary.
//!
//! Interface shape: a `Command` in, `Event` stream out — not a
//! request/response RPC surface — to keep the boundary narrow and
//! auditable. All types here are `#[non_exhaustive]` and versioned, since a
//! shell built against an older core must fail closed, not guess.
//!
//! Core owns its own Tokio runtime; shells communicate over channels. No
//! blocking calls are allowed across the FFI boundary.

#![forbid(unsafe_code)]

/// Commands a shell can issue to the core. Intentionally empty until
/// session establishment (`cue-crypto`) lands in Phase 1 (docs/11) — a
/// command surface designed before there's a session to command against
/// would be guesswork.
#[non_exhaustive]
#[derive(Debug)]
pub enum Command {}

/// Events the core emits back to a shell.
#[non_exhaustive]
#[derive(Debug)]
pub enum Event {}
