//! Trust-level ramp L0–L3 (docs/02 "Trust levels", ADR-0009: "the
//! load-bearing one"). Gates harm vectors — message-request fan-out, group
//! creation, invite minting — not general usage; a brand-new L0 account can
//! already read and reply.

// L1-L3 aren't constructed yet: docs/02's "Multiple paths to L2" ramp
// (time+behaviour, invite, attestation, payment) is reputation logic this
// registration-only slice doesn't implement. Every new account starts, and
// today stays, at L0.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TrustLevel {
    #[default]
    L0,
    L1,
    L2,
    L3,
}
