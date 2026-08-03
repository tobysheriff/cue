//! Protocol conformance suite and traffic-analysis harness.
//!
//! Two responsibilities that must both live here rather than being
//! scattered per-crate: (1) a conformance suite any future client
//! implementation must pass, so a second client can't quietly drift from
//! the protocol `cue-node` and `cue-core` agree on; (2) the traffic-analysis
//! harness from docs/04 "Verification" that asserts envelope sizes are
//! uniform within a bucket and that Quiet Mode timing is indistinguishable
//! from idle. That harness runs in CI forever once it exists (docs/11
//! Phase 3), because metadata properties are exactly what a routine
//! refactor breaks silently.

#![forbid(unsafe_code)]

pub fn size_bucket_for(_ciphertext_len: usize) -> cue_proto::v1::SizeBucket {
    // TODO(Phase 0/1): implement the actual 1/4/16/64 KB bucket mapping
    // from docs/04 once cue-core has real envelopes to pad.
    cue_proto::v1::SizeBucket::Unspecified
}
