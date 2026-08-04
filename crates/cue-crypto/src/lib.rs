//! Policy wrapper over Cue's cryptographic primitives (docs/03).
//!
//! This crate owns *policy* — key rotation cadence, one-time-prekey buffer
//! size, credential epoch length — and never reimplements a primitive.
//! Sessions wrap `libsignal-protocol`, groups wrap `openmls`; both land in
//! Phase 1 (docs/11) alongside the wire types they operate on. Nothing here
//! may touch primitive internals directly, and nothing here may roll its
//! own ratchet, add key escrow, or add server-assisted plaintext search —
//! all explicitly rejected in docs/03.

#![forbid(unsafe_code)]

/// PQXDH session establishment and Double Ratchet messaging for 1:1 chats
/// (docs/03 "Direct messages"). Wraps `libsignal-protocol`.
pub mod sessions;

/// Recovery phrase generation and restore (docs/02 "Recovery"): the sole
/// account recovery mechanism, deterministically re-deriving a device's
/// long-term identity key.
pub mod recovery;

/// MLS group sessions via `openmls` (docs/03 "Encrypted groups", ADR-0003).
/// TreeKEM ratchet tree, 20-member default cap enforced by the client.
pub mod groups;

/// zkgroup-style anonymous group membership credentials and Privacy
/// Pass/VOPRF blind delivery tokens (docs/03 "Anonymous group membership",
/// docs/04 #4). The Node must never be able to link an issued credential to
/// its later use.
pub mod credentials;

/// Asymmetric message franking (Tyagi et al., docs/03 "Message franking").
/// The one novel construction in this project — gated on external
/// cryptographic review before it merges (docs/11 Phase 4).
pub mod franking;

/// Errors shared across the policy layer. Deliberately does not implement
/// `Clone` — error values may transiently hold key material and must not be
/// casually duplicated.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("operation not yet implemented: {0}")]
    NotImplemented(&'static str),

    #[error("invalid recovery phrase: {0}")]
    InvalidRecoveryPhrase(String),

    #[error(transparent)]
    Signal(#[from] libsignal_protocol::SignalProtocolError),
}
