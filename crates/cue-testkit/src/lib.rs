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

/// The 1/4/16/64 KB bucket mapping from docs/04 "fixed-size padded
/// envelopes": the smallest bucket `ciphertext_len` fits inside, or
/// `Unspecified` if it exceeds even the largest bucket — that case must
/// become an attachment on a separate, decorrelated fetch path (docs/04),
/// not a bigger envelope.
///
/// This is an independent reference implementation, not one `cue-core`
/// calls into: the point of a conformance suite is to catch a real
/// implementation's bucket selection drifting from the spec, which a
/// shared helper both sides call could never do.
pub fn size_bucket_for(ciphertext_len: usize) -> cue_proto::v1::SizeBucket {
    use cue_proto::v1::SizeBucket;
    match ciphertext_len {
        0..=1024 => SizeBucket::B1kb,
        1025..=4096 => SizeBucket::B4kb,
        4097..=16384 => SizeBucket::B16kb,
        16385..=65536 => SizeBucket::B64kb,
        _ => SizeBucket::Unspecified,
    }
}
