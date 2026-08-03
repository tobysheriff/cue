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
//! Storage is in-memory only, via `libsignal_protocol::InMemSignalProtocolStore`,
//! until `cue-core`'s encrypted local store lands (docs/06 "Local storage").
//! Functions here take that concrete type rather than a generic store trait
//! because libsignal's own API requires disjoint `&mut store.session_store` /
//! `&mut store.identity_store` field borrows — which only work against a
//! concrete struct, not a `&mut dyn ProtocolStore` trait object (two
//! simultaneous mutable borrows of one trait object don't type-check even
//! though the underlying fields are disjoint). When `cue-core` needs
//! persistence, it will re-implement `InMemSignalProtocolStore`'s fields as
//! its own encrypted-store equivalents; this module's signatures will
//! change to match at that point rather than being generalised early.

use std::time::SystemTime;

use libsignal_protocol::kem;
pub use libsignal_protocol::{
    CiphertextMessage, DeviceId, IdentityKeyPair, InMemSignalProtocolStore, KyberPreKeyId,
    KyberPreKeyRecord, PreKeyBundle, PreKeyId, PreKeyRecord, ProtocolAddress, PublicKey,
    SignedPreKeyId, SignedPreKeyRecord, Timestamp,
};
use libsignal_protocol::{GenericSignedPreKey as _, KeyPair};
use rand::{CryptoRng, Rng};

use crate::CryptoError;

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

    /// A fresh in-memory session store for this identity. Temporary until
    /// `cue-core`'s encrypted local store lands (docs/06).
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

/// Establish an outbound session from a recipient's published prekey bundle
/// (docs/03 "Session establishment: PQXDH"): an X25519 DH combination *and*
/// an ML-KEM-1024 encapsulation, both mixed into the root key for
/// harvest-now-decrypt-later resistance. After this returns,
/// [`encrypt_message`] can be called for `remote_address`.
pub async fn establish_session<R: Rng + CryptoRng>(
    store: &mut InMemSignalProtocolStore,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    bundle: &PreKeyBundle,
    now: SystemTime,
    csprng: &mut R,
) -> Result<(), CryptoError> {
    libsignal_protocol::process_prekey_bundle(
        remote_address,
        local_address,
        &mut store.session_store,
        &mut store.identity_store,
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
pub async fn encrypt_message<R: Rng + CryptoRng>(
    store: &mut InMemSignalProtocolStore,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    plaintext: &[u8],
    now: SystemTime,
    csprng: &mut R,
) -> Result<CiphertextMessage, CryptoError> {
    let message = libsignal_protocol::message_encrypt(
        plaintext,
        remote_address,
        local_address,
        &mut store.session_store,
        &mut store.identity_store,
        now,
        csprng,
    )
    .await?;
    Ok(message)
}

/// Decrypt a message from `remote_address`, transparently completing an
/// inbound PQXDH handshake (docs/03) if `ciphertext` is the first message of
/// a new session.
pub async fn decrypt_message<R: Rng + CryptoRng>(
    store: &mut InMemSignalProtocolStore,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    ciphertext: &CiphertextMessage,
    csprng: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = libsignal_protocol::message_decrypt(
        ciphertext,
        remote_address,
        local_address,
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        csprng,
    )
    .await?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::{KyberPreKeyStore as _, PreKeyStore as _, SignedPreKeyStore as _};
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
        bob_store
            .pre_key_store
            .save_pre_key(
                bob_prekeys.one_time_prekey.0,
                &bob_prekeys.one_time_prekey.1,
            )
            .await
            .unwrap();
        bob_store
            .signed_pre_key_store
            .save_signed_pre_key(bob_prekeys.signed_prekey.0, &bob_prekeys.signed_prekey.1)
            .await
            .unwrap();
        bob_store
            .kyber_pre_key_store
            .save_kyber_pre_key(bob_prekeys.kyber_prekey.0, &bob_prekeys.kyber_prekey.1)
            .await
            .unwrap();

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
