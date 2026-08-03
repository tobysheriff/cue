//! Key transparency (docs/03 "Key transparency"): an append-only Merkle
//! prefix tree of handle→key bindings, signed tree heads, and inclusion /
//! consistency proofs. Modelled on Signal KT / Parakeet — no novel
//! cryptography, just an append-only log with proofs.
//!
//! This is the mechanism that catches an equivocating Node after the fact:
//! it must never be possible for the Node to serve two clients different,
//! inconsistent views of the tree without the split being provably
//! detectable by a third-party auditor. Lands in Phase 3 (docs/11).

#![forbid(unsafe_code)]

#[derive(Debug, thiserror::Error)]
pub enum KtError {
    #[error("operation not yet implemented: {0}")]
    NotImplemented(&'static str),
}

/// A signed tree head: the root of the Merkle prefix tree at some log size,
/// signed by the Node, gossiped between auditors so no two auditors can be
/// shown different roots for the same size undetected.
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub signature: Vec<u8>,
}

pub fn verify_inclusion() -> Result<(), KtError> {
    Err(KtError::NotImplemented("verify_inclusion"))
}

pub fn verify_consistency() -> Result<(), KtError> {
    Err(KtError::NotImplemented("verify_consistency"))
}
