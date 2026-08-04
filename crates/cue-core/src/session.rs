//! Client-side session management: the `cue-core` half of docs/03's PQXDH +
//! Double Ratchet handshake, wrapping `cue_crypto::sessions` with the
//! shapes the `Command`/`Event` actor (`crate::Core`) drives it with.
//!
//! Storage is `crate::store::EncryptedStore`, the encrypted local store
//! (docs/06 "Local storage and ephemerality") — a session established here
//! survives the process exiting. The caller is responsible for opening or
//! creating that store first (`EncryptedStore::create` on first run,
//! `EncryptedStore::open` on restart) and passing it in already built,
//! since only the caller knows which of those two cases applies.

use std::time::SystemTime;

use cue_crypto::sessions::{
    self, CiphertextMessage, GeneratedPrekeys, PreKeyBundle, ProtocolAddress,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

use crate::store::EncryptedStore;
use crate::CoreError;

/// One device's live session state: the encrypted store holding every peer
/// session it has established, and the address peers use to reach it
/// (docs/03 "Direct messages").
pub struct SessionManager {
    local_address: ProtocolAddress,
    store: EncryptedStore,
}

impl SessionManager {
    /// Wrap an already-opened `store` (see module doc), addressed as
    /// `local_address` (docs/02: `(handle, device_id)` pair).
    pub fn new(store: EncryptedStore, local_address: ProtocolAddress) -> Self {
        Self {
            local_address,
            store,
        }
    }

    /// Save this device's own generated prekeys locally, before the public
    /// bundle is published to the Node (docs/02 "Registration flow") — an
    /// inbound handshake that references them would otherwise fail.
    pub async fn register_own_prekeys(
        &mut self,
        prekeys: &GeneratedPrekeys,
    ) -> Result<(), CoreError> {
        sessions::save_generated_prekeys(&mut self.store, prekeys).await?;
        Ok(())
    }

    /// Establish an outbound session to `remote_address` from their
    /// published prekey bundle (docs/03 "Session establishment: PQXDH").
    pub async fn establish_session(
        &mut self,
        remote_address: &ProtocolAddress,
        bundle: &PreKeyBundle,
    ) -> Result<(), CoreError> {
        let mut csprng = OsRng.unwrap_err();
        sessions::establish_session(
            &mut self.store,
            &self.local_address,
            remote_address,
            bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;
        Ok(())
    }

    /// Encrypt `plaintext` for `remote_address` under the Double Ratchet,
    /// wrapping it in a fresh PQXDH handshake message if the session
    /// hasn't yet received a response.
    pub async fn send(
        &mut self,
        remote_address: &ProtocolAddress,
        plaintext: &[u8],
    ) -> Result<CiphertextMessage, CoreError> {
        let mut csprng = OsRng.unwrap_err();
        let message = sessions::encrypt_message(
            &mut self.store,
            &self.local_address,
            remote_address,
            plaintext,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;
        Ok(message)
    }

    /// Decrypt a message from `remote_address`, transparently completing
    /// an inbound PQXDH handshake if `ciphertext` is the first message of
    /// a new session.
    pub async fn receive(
        &mut self,
        remote_address: &ProtocolAddress,
        ciphertext: &CiphertextMessage,
    ) -> Result<Vec<u8>, CoreError> {
        let mut csprng = OsRng.unwrap_err();
        let plaintext = sessions::decrypt_message(
            &mut self.store,
            &self.local_address,
            remote_address,
            ciphertext,
            &mut csprng,
        )
        .await?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoreKey;
    use cue_crypto::sessions::{generate_prekeys, DeviceId, Identity};

    fn address(name: &str) -> ProtocolAddress {
        ProtocolAddress::new(name.to_owned(), DeviceId::new(1).unwrap())
    }

    fn test_store(identity: &Identity) -> EncryptedStore {
        EncryptedStore::create(":memory:", &StoreKey::from_bytes([0x24; 32]), identity)
            .expect("an in-memory store always opens")
    }

    #[tokio::test]
    async fn establishing_a_session_lets_both_sides_exchange_messages() {
        let mut csprng = OsRng.unwrap_err();

        let alice_identity = Identity::generate(&mut csprng);
        let bob_identity = Identity::generate(&mut csprng);

        let mut alice = SessionManager::new(test_store(&alice_identity), address("alice"));
        let mut bob = SessionManager::new(test_store(&bob_identity), address("bob"));

        let bob_prekeys = generate_prekeys(
            &bob_identity,
            DeviceId::new(1).unwrap(),
            1.into(),
            1.into(),
            1.into(),
            &mut csprng,
        )
        .unwrap();
        bob.register_own_prekeys(&bob_prekeys).await.unwrap();

        alice
            .establish_session(&address("bob"), &bob_prekeys.bundle)
            .await
            .expect("Alice can establish a session from Bob's published bundle");

        let first_message = alice
            .send(&address("bob"), b"En handling, camarade.")
            .await
            .expect("Alice can encrypt to a freshly established session");

        let decrypted = bob
            .receive(&address("alice"), &first_message)
            .await
            .expect("Bob can complete the handshake and decrypt Alice's first message");
        assert_eq!(decrypted, b"En handling, camarade.");

        let reply = bob
            .send(&address("alice"), b"Toujours.")
            .await
            .expect("Bob can reply on the now-acknowledged session");

        let decrypted_reply = alice
            .receive(&address("bob"), &reply)
            .await
            .expect("Alice can decrypt Bob's reply with the ratchet advanced");
        assert_eq!(decrypted_reply, b"Toujours.");
    }

    #[tokio::test]
    async fn sending_without_an_established_session_fails_rather_than_silently_no_opping() {
        let mut csprng = OsRng.unwrap_err();
        let alice_identity = Identity::generate(&mut csprng);
        let mut alice = SessionManager::new(test_store(&alice_identity), address("alice"));

        let result = alice.send(&address("bob"), b"hello?").await;

        assert!(
            result.is_err(),
            "encrypting to a peer with no session and no bundle must fail, not fabricate a message"
        );
    }
}
