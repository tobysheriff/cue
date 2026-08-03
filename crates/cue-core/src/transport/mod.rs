//! Turns `cue-core`'s raw Double Ratchet output into a wire-ready
//! `cue_proto::v1::Envelope` and back, and speaks to a `cue-node`'s
//! delivery HTTP surface (docs/06 "Transport"). This resolves the gap
//! `Event::MessageSent`'s doc comment flags — "still undesigned" — for
//! Phase 1, with one deliberate, tracked trade-off:
//!
//! **Sender identity is plaintext for now.** libsignal's `message_decrypt`
//! is keyed by sender address, so the recipient must learn who sent an
//! envelope before it can be decrypted. Real sealed sender (docs/03)
//! encrypts that identity to the recipient's identity key independent of
//! session state — a genuine cryptographic construction, not just wiring,
//! and out of scope until Phase 3 (docs/11). Until then, [`frame`] wraps
//! the ciphertext in a [`cue_proto::v1::SealedSenderStub`] that names the
//! sender in the clear. The Node's operator can read `sender_handle` and
//! `sender_device_id` off `Envelope.ciphertext` today — a real
//! metadata-resistance regression against docs/04 #2, accepted
//! deliberately for this phase and documented here and on the stub message
//! itself so it isn't mistaken for the final design.
//!
//! Padding only reaches bucket granularity (docs/04 "fixed-size padded
//! envelopes"): the inner frame is padded to the smallest of the four
//! bucket sizes it fits in, not to a value chosen to defeat a more
//! sophisticated traffic analyst. The Phase 3 traffic-analysis harness
//! (`cue-testkit`, docs/11) is what will hold this to a stricter bar.

mod bundle;
mod client;
mod frame;

pub use bundle::bundle_from_response;
pub use client::{MailboxStream, NodeClient};
pub use frame::{open_received, seal_for_delivery};

/// Errors from turning ciphertext into an `Envelope` (or back), and from
/// talking to a Node over HTTP. Deliberately does not implement `Clone`,
/// matching [`cue_crypto::CryptoError`] — some variants wrap ciphertext or
/// key-derived bytes in transit.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error(
        "no size bucket fits a {0}-byte framed message (docs/04: this should become an attachment)"
    )]
    MessageTooLarge(usize),

    #[error("malformed envelope frame: {0}")]
    MalformedFrame(&'static str),

    #[error("failed to decode the inner SealedSenderStub: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error(transparent)]
    Crypto(#[from] cue_crypto::CryptoError),

    #[error("request to the Node failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("the Node responded with {0}")]
    UnexpectedStatus(reqwest::StatusCode),

    #[error("mailbox websocket error: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
}
