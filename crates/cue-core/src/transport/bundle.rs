//! Turns a Node's `prekey-bundle` HTTP response into the `PreKeyBundle`
//! `SessionManager::establish_session` needs.

use cue_crypto::sessions::{
    bundle_from_parts, DeviceId, PreKeyBundle, RawOneTimePrekey, RawSignedPrekey,
};
use cue_proto::v1::PrekeyBundleResponse;

use super::TransportError;

/// Phase 1 assumes exactly one (primary) device per account — multi-device
/// linking is Phase 2 (docs/11) — so every bundle a Node serves today is
/// implicitly for device 1; `accounts::store::DeviceRecord` on the server
/// side makes the same assumption (`record.devices.first()`).
const PRIMARY_DEVICE_ID: u8 = 1;

/// Reconstruct the `PreKeyBundle` a session can be established from, plus
/// the recipient's current mailbox id to address envelopes to (docs/03
/// "Session establishment: PQXDH").
pub fn bundle_from_response(
    response: PrekeyBundleResponse,
) -> Result<(PreKeyBundle, [u8; 16]), TransportError> {
    let signed_prekey = response
        .signed_prekey
        .ok_or(TransportError::MalformedFrame("missing signed_prekey"))?;
    let kyber_prekey = response
        .kyber_prekey
        .ok_or(TransportError::MalformedFrame("missing kyber_prekey"))?;

    let bundle = bundle_from_parts(
        response.registration_id,
        DeviceId::new(PRIMARY_DEVICE_ID).expect("1 is always a valid device id"),
        &response.identity_key,
        RawSignedPrekey {
            id: signed_prekey.id,
            public_key: signed_prekey.public_key,
            signature: signed_prekey.signature,
        },
        RawSignedPrekey {
            id: kyber_prekey.id,
            public_key: kyber_prekey.public_key,
            signature: kyber_prekey.signature,
        },
        response.one_time_prekey.map(|p| RawOneTimePrekey {
            id: p.id,
            public_key: p.public_key,
        }),
    )?;

    let mailbox_id: [u8; 16] = response
        .mailbox_id
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::MalformedFrame("mailbox_id must be 16 bytes"))?;

    Ok((bundle, mailbox_id))
}
