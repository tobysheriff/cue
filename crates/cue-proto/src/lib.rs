//! Wire format for Cue: protobuf schema and generated types.
//!
//! Shared verbatim by `cue-node` and `cue-core` so server and client can
//! never disagree about the wire format (ADR-0007). This crate must never
//! depend on `cue-crypto`, `cue-node`, or `cue-core` — it is the one thing
//! every other crate depends on, not the other way around.
//!
//! Generated types are licensed Apache-2.0 (ADR-0008), distinct from the
//! rest of the workspace, so anyone can build an interoperable client.

#![forbid(unsafe_code)]

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/cue.v1.rs"));
}

#[cfg(test)]
mod tests {
    use super::v1::{Envelope, SizeBucket};
    use prost::Message;

    #[test]
    fn envelope_round_trips_through_the_wire_format() {
        let envelope = Envelope {
            version: 1,
            mailbox_id: vec![0xAB; 16],
            size_bucket: SizeBucket::B1kb as i32, // proto: SIZE_BUCKET_B1KB
            ciphertext: vec![0; 1024],
        };

        let bytes = envelope.encode_to_vec();
        let decoded = Envelope::decode(bytes.as_slice()).expect("decode envelope");

        assert_eq!(decoded, envelope);
    }
}
