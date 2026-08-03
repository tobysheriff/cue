//! Asymmetric message franking (Tyagi et al.), docs/03. The one novel
//! cryptographic construction in this project: no production Rust
//! implementation exists to wrap, and this module is gated on external
//! cryptographic review before it merges (docs/11 Phase 4).

use crate::CryptoError;

pub fn commit_to_plaintext() -> Result<(), CryptoError> {
    Err(CryptoError::NotImplemented("franking::commit_to_plaintext"))
}
