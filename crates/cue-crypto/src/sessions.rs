//! PQXDH + Double Ratchet 1:1 sessions (docs/03 "Direct messages"). Wraps
//! `libsignal-protocol` rather than reimplementing X3DH, Kyber, or the
//! ratchet ourselves (docs/03 "Things explicitly rejected": "Rolling our
//! own ratchet. No.").
//!
//! This module owns *policy*: how many one-time prekeys to keep buffered
//! and how often the signed prekey rotates ([`PrekeyPolicy`]). It never
//! reaches into ratchet, KEM, or AEAD internals — every cryptographic
//! operation below is a direct call into `libsignal_protocol`.
//!
//! Storage is generic over [`ProtocolStoreParts`]: functions here take
//! `&mut S` for any store implementing it rather than a concrete type,
//! because libsignal's own API requires disjoint `&mut store.session_store`
//! / `&mut store.identity_store` field borrows passed as separate arguments
//! — which only work against a concrete struct's named fields, not a
//! `&mut dyn ProtocolStore` trait object (two simultaneous mutable borrows
//! of one trait object don't type-check even though the underlying fields
//! are disjoint). `ProtocolStoreParts::parts_mut` is how a concrete store
//! exposes that disjointness generically: implemented here for
//! [`InMemSignalProtocolStore`] (this crate's own round-trip test, below),
//! and by `cue-core`'s encrypted local store (docs/06 "Local storage") for
//! everything else — this module stays ignorant of which, and in
//! particular never depends on `cue-core` or a storage engine.

use std::time::SystemTime;

pub use libsignal_protocol::kem;
use libsignal_protocol::KeyPair;
pub use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, Direction, GenericSignedPreKey,
    IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, PublicKey, SessionRecord, SessionStore,
    SignalMessage, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
    Timestamp,
};
use rand::{CryptoRng, Rng};

use crate::CryptoError;

/// A store type usable by this module's functions — see the module doc for
/// why this exists instead of a plain `&mut dyn ProtocolStore`. `parts_mut`
/// is called once per function here and must hand back five genuinely
/// disjoint borrows (sound to implement directly against a struct's named
/// fields, as [`InMemSignalProtocolStore`]'s impl below does; not soundly
/// implementable against anything that needs to synthesize the borrows,
/// e.g. through a lock).
pub trait ProtocolStoreParts {
    type Session: SessionStore;
    type Identity: IdentityKeyStore;
    type PreKey: PreKeyStore;
    type SignedPreKey: SignedPreKeyStore;
    type KyberPreKey: KyberPreKeyStore;

    #[allow(clippy::type_complexity)]
    fn parts_mut(
        &mut self,
    ) -> (
        &mut Self::Session,
        &mut Self::Identity,
        &mut Self::PreKey,
        &mut Self::SignedPreKey,
        &mut Self::KyberPreKey,
    );
}

impl ProtocolStoreParts for InMemSignalProtocolStore {
    type Session = libsignal_protocol::InMemSessionStore;
    type Identity = libsignal_protocol::InMemIdentityKeyStore;
    type PreKey = libsignal_protocol::InMemPreKeyStore;
    type SignedPreKey = libsignal_protocol::InMemSignedPreKeyStore;
    type KyberPreKey = libsignal_protocol::InMemKyberPreKeyStore;

    fn parts_mut(
        &mut self,
    ) -> (
        &mut Self::Session,
        &mut Self::Identity,
        &mut Self::PreKey,
        &mut Self::SignedPreKey,
        &mut Self::KyberPreKey,
    ) {
        (
            &mut self.session_store,
            &mut self.identity_store,
            &mut self.pre_key_store,
            &mut self.signed_pre_key_store,
            &mut self.kyber_pre_key_store,
        )
    }
}

/// Prekey buffer size and rotation cadence (docs/02 "Prekeys", docs/03
/// "Implementation"). Cue's own decision, not libsignal's — a Node may tune
/// these without touching the ratchet or the PQXDH handshake.
#[derive(Debug, Clone, Copy)]
pub struct PrekeyPolicy {
    /// One-time EC prekeys a device should keep buffered on its Node.
    pub one_time_prekey_buffer: u32,
    /// How long a signed prekey (EC + Kyber) stays current before rotating.
    pub signed_prekey_rotation: std::time::Duration,
}

impl Default for PrekeyPolicy {
    fn default() -> Self {
        Self {
            one_time_prekey_buffer: 100,
            signed_prekey_rotation: std::time::Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

/// A device's long-term Signal identity: the X25519 key pair backing
/// `IdentityKey`, plus the registration id libsignal uses to notice a
/// reinstalled client. Generated once at registration (docs/02) and never
/// escrowed (docs/03 "Key escrow of any kind... No.").
pub struct Identity {
    pub key_pair: IdentityKeyPair,
    pub registration_id: u32,
}

impl Identity {
    /// Generate a new device identity from `csprng`.
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        Self {
            key_pair: IdentityKeyPair::generate(csprng),
            // Valid registration ids are 14 bits (docs/03; matches Signal's
            // own convention so libsignal's session-version negotiation
            // sees a value in the range it expects).
            registration_id: csprng.random_range(1..0x4000),
        }
    }

    /// A fresh in-memory session store for this identity — this crate's own
    /// tests only; `cue-core` uses its encrypted local store instead
    /// (docs/06 "Local storage").
    pub fn new_store(&self) -> Result<InMemSignalProtocolStore, CryptoError> {
        Ok(InMemSignalProtocolStore::new(
            self.key_pair,
            self.registration_id,
        )?)
    }
}

/// One PQXDH prekey bundle's worth of key material: the public `bundle` to
/// publish to the Node, and the private records the owning device must save
/// into its own session store *before* publishing, so it can answer an
/// incoming handshake that uses them (docs/03 "Session establishment: PQXDH").
pub struct GeneratedPrekeys {
    pub bundle: PreKeyBundle,
    pub one_time_prekey: (PreKeyId, PreKeyRecord),
    pub signed_prekey: (SignedPreKeyId, SignedPreKeyRecord),
    pub kyber_prekey: (KyberPreKeyId, KyberPreKeyRecord),
}

/// Generate one one-time EC prekey, one signed EC prekey, and one signed
/// ML-KEM-1024 prekey, all signed by `identity`, and assemble them into a
/// bundle publishable to the Node. Called at registration and whenever the
/// Node's one-time prekey buffer needs topping up
/// (`PrekeyPolicy::one_time_prekey_buffer`).
pub fn generate_prekeys<R: Rng + CryptoRng>(
    identity: &Identity,
    device_id: DeviceId,
    pre_key_id: PreKeyId,
    signed_pre_key_id: SignedPreKeyId,
    kyber_pre_key_id: KyberPreKeyId,
    csprng: &mut R,
) -> Result<GeneratedPrekeys, CryptoError> {
    let now = Timestamp::from_epoch_millis(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    );

    let one_time_key_pair = KeyPair::generate(csprng);
    let one_time_record = PreKeyRecord::new(pre_key_id, &one_time_key_pair);

    let signed_key_pair = KeyPair::generate(csprng);
    let signed_pre_key_public = signed_key_pair.public_key.serialize();
    let signed_signature = identity
        .key_pair
        .private_key()
        .calculate_signature(&signed_pre_key_public, csprng)
        .map_err(libsignal_protocol::SignalProtocolError::from)?;
    let signed_record =
        SignedPreKeyRecord::new(signed_pre_key_id, now, &signed_key_pair, &signed_signature);

    let kyber_key_pair = kem::KeyPair::generate(kem::KeyType::MLKEM1024, csprng);
    let kyber_pre_key_public = kyber_key_pair.public_key.serialize();
    let kyber_signature = identity
        .key_pair
        .private_key()
        .calculate_signature(&kyber_pre_key_public, csprng)
        .map_err(libsignal_protocol::SignalProtocolError::from)?;
    let kyber_record =
        KyberPreKeyRecord::new(kyber_pre_key_id, now, &kyber_key_pair, &kyber_signature);

    let bundle = PreKeyBundle::new(
        identity.registration_id,
        device_id,
        Some((pre_key_id, one_time_key_pair.public_key)),
        signed_pre_key_id,
        signed_key_pair.public_key,
        signed_signature.to_vec(),
        kyber_pre_key_id,
        kyber_key_pair.public_key.clone(),
        kyber_signature.to_vec(),
        *identity.key_pair.identity_key(),
    )?;

    Ok(GeneratedPrekeys {
        bundle,
        one_time_prekey: (pre_key_id, one_time_record),
        signed_prekey: (signed_pre_key_id, signed_record),
        kyber_prekey: (kyber_pre_key_id, kyber_record),
    })
}

/// Save `prekeys` into `store` so this device can complete an inbound
/// PQXDH handshake that references them (docs/02 "Registration flow": the
/// private halves must be saved locally *before* the public `bundle` is
/// published — publishing first would let a peer's handshake reference
/// prekeys this device can't yet answer with).
pub async fn save_generated_prekeys<S: ProtocolStoreParts>(
    store: &mut S,
    prekeys: &GeneratedPrekeys,
) -> Result<(), CryptoError> {
    let (_, _, pre_key_store, signed_pre_key_store, kyber_pre_key_store) = store.parts_mut();
    pre_key_store
        .save_pre_key(prekeys.one_time_prekey.0, &prekeys.one_time_prekey.1)
        .await?;
    signed_pre_key_store
        .save_signed_pre_key(prekeys.signed_prekey.0, &prekeys.signed_prekey.1)
        .await?;
    kyber_pre_key_store
        .save_kyber_pre_key(prekeys.kyber_prekey.0, &prekeys.kyber_prekey.1)
        .await?;
    Ok(())
}

/// Establish an outbound session from a recipient's published prekey bundle
/// (docs/03 "Session establishment: PQXDH"): an X25519 DH combination *and*
/// an ML-KEM-1024 encapsulation, both mixed into the root key for
/// harvest-now-decrypt-later resistance. After this returns,
/// [`encrypt_message`] can be called for `remote_address`.
pub async fn establish_session<S: ProtocolStoreParts, R: Rng + CryptoRng>(
    store: &mut S,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    bundle: &PreKeyBundle,
    now: SystemTime,
    csprng: &mut R,
) -> Result<(), CryptoError> {
    let (session_store, identity_store, _, _, _) = store.parts_mut();
    libsignal_protocol::process_prekey_bundle(
        remote_address,
        local_address,
        session_store,
        identity_store,
        bundle,
        now,
        csprng,
    )
    .await?;
    Ok(())
}

/// Encrypt `plaintext` for `remote_address` under the Double Ratchet,
/// wrapping it in a fresh PQXDH handshake message if the session hasn't yet
/// received a response (docs/03 "Ongoing messages: Double Ratchet").
pub async fn encrypt_message<S: ProtocolStoreParts, R: Rng + CryptoRng>(
    store: &mut S,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    plaintext: &[u8],
    now: SystemTime,
    csprng: &mut R,
) -> Result<CiphertextMessage, CryptoError> {
    let (session_store, identity_store, _, _, _) = store.parts_mut();
    let message = libsignal_protocol::message_encrypt(
        plaintext,
        remote_address,
        local_address,
        session_store,
        identity_store,
        now,
        csprng,
    )
    .await?;
    Ok(message)
}

/// Decrypt a message from `remote_address`, transparently completing an
/// inbound PQXDH handshake (docs/03) if `ciphertext` is the first message of
/// a new session.
pub async fn decrypt_message<S: ProtocolStoreParts, R: Rng + CryptoRng>(
    store: &mut S,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    ciphertext: &CiphertextMessage,
    csprng: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    let (session_store, identity_store, pre_key_store, signed_pre_key_store, kyber_pre_key_store) =
        store.parts_mut();
    let plaintext = libsignal_protocol::message_decrypt(
        ciphertext,
        remote_address,
        local_address,
        session_store,
        identity_store,
        pre_key_store,
        &*signed_pre_key_store,
        kyber_pre_key_store,
        csprng,
    )
    .await?;
    Ok(plaintext)
}

/// One raw signed prekey (EC or Kyber) as served by a Node's
/// `prekey-bundle` endpoint, before its bytes have been validated into a
/// [`PublicKey`]/[`kem::PublicKey`] (docs/03).
pub struct RawSignedPrekey {
    pub id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct RawOneTimePrekey {
    pub id: u32,
    pub public_key: Vec<u8>,
}

/// Reconstruct a [`PreKeyBundle`] from a peer's published wire-format key
/// material (docs/03 "Session establishment: PQXDH") — the receiving side
/// of what [`generate_prekeys`]'s `bundle` field produces for a Node to
/// serve back out. `one_time_prekey` is `None` exactly when the Node's
/// buffer was already empty (docs/02).
///
/// Takes raw parts rather than a `cue_proto` wire type: this crate never
/// depends on `cue-proto` (docs/03's charter — a policy wrapper over
/// primitives, nothing more), so unpacking the wire response is
/// `cue-core`'s `transport` module's job; this is the validation step once
/// the bytes are in hand.
#[allow(clippy::too_many_arguments)]
pub fn bundle_from_parts(
    registration_id: u32,
    device_id: DeviceId,
    identity_key: &[u8],
    signed_prekey: RawSignedPrekey,
    kyber_prekey: RawSignedPrekey,
    one_time_prekey: Option<RawOneTimePrekey>,
) -> Result<PreKeyBundle, CryptoError> {
    let identity_key = IdentityKey::decode(identity_key)?;
    let signed_pre_key_public = PublicKey::deserialize(&signed_prekey.public_key)
        .map_err(libsignal_protocol::SignalProtocolError::from)?;
    let kyber_pre_key_public = kem::PublicKey::deserialize(&kyber_prekey.public_key)?;
    let one_time = one_time_prekey
        .map(|p| -> Result<_, CryptoError> {
            let public_key = PublicKey::deserialize(&p.public_key)
                .map_err(libsignal_protocol::SignalProtocolError::from)?;
            Ok((PreKeyId::from(p.id), public_key))
        })
        .transpose()?;

    Ok(PreKeyBundle::new(
        registration_id,
        device_id,
        one_time,
        SignedPreKeyId::from(signed_prekey.id),
        signed_pre_key_public,
        signed_prekey.signature,
        KyberPreKeyId::from(kyber_prekey.id),
        kyber_pre_key_public,
        kyber_prekey.signature,
        identity_key,
    )?)
}

/// Reconstruct a [`CiphertextMessage`] from its wire bytes and declared
/// [`CiphertextMessageType`] (docs/03) — the receiving side of what
/// [`CiphertextMessage::serialize`] and [`CiphertextMessage::message_type`]
/// produce, needed once a message has crossed the wire and lost its enum
/// shape. Only `Whisper` and `PreKey` are handled: those are the two
/// variants [`encrypt_message`] can ever produce for a 1:1 session —
/// `SenderKey`/`Plaintext` are MLS/group concerns this module doesn't
/// touch (docs/03 "Encrypted groups" lands in `groups`, separately).
pub fn deserialize_ciphertext(
    message_type: CiphertextMessageType,
    bytes: &[u8],
) -> Result<CiphertextMessage, CryptoError> {
    match message_type {
        CiphertextMessageType::Whisper => Ok(CiphertextMessage::SignalMessage(
            SignalMessage::try_from(bytes)?,
        )),
        CiphertextMessageType::PreKey => Ok(CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(bytes)?,
        )),
        CiphertextMessageType::SenderKey | CiphertextMessageType::Plaintext => {
            Err(CryptoError::NotImplemented(
                "deserialize_ciphertext only handles 1:1 session message types (Whisper, PreKey)",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    #[tokio::test]
    async fn alice_and_bob_exchange_messages_through_a_pqxdh_handshake() {
        let mut csprng = OsRng.unwrap_err();

        let alice_address = ProtocolAddress::new("alice".to_owned(), DeviceId::new(1).unwrap());
        let bob_address = ProtocolAddress::new("bob".to_owned(), DeviceId::new(1).unwrap());

        let alice_identity = Identity::generate(&mut csprng);
        let bob_identity = Identity::generate(&mut csprng);

        let mut alice_store = alice_identity.new_store().unwrap();
        let mut bob_store = bob_identity.new_store().unwrap();

        let bob_prekeys = generate_prekeys(
            &bob_identity,
            DeviceId::new(1).unwrap(),
            1.into(),
            1.into(),
            1.into(),
            &mut csprng,
        )
        .unwrap();
        save_generated_prekeys(&mut bob_store, &bob_prekeys)
            .await
            .expect("Bob can save his own generated prekeys before publishing them");

        establish_session(
            &mut alice_store,
            &alice_address,
            &bob_address,
            &bob_prekeys.bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("Alice can establish a session from Bob's published bundle");

        let first_message = encrypt_message(
            &mut alice_store,
            &alice_address,
            &bob_address,
            b"En handling, camarade.",
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("Alice can encrypt to a freshly established session");

        let decrypted = decrypt_message(
            &mut bob_store,
            &bob_address,
            &alice_address,
            &first_message,
            &mut csprng,
        )
        .await
        .expect("Bob can complete the handshake and decrypt Alice's first message");
        assert_eq!(decrypted, b"En handling, camarade.");

        let reply = encrypt_message(
            &mut bob_store,
            &bob_address,
            &alice_address,
            b"Toujours.",
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("Bob can reply on the now-acknowledged session");

        let decrypted_reply = decrypt_message(
            &mut alice_store,
            &alice_address,
            &bob_address,
            &reply,
            &mut csprng,
        )
        .await
        .expect("Alice can decrypt Bob's reply with the ratchet advanced");
        assert_eq!(decrypted_reply, b"Toujours.");
    }
}
