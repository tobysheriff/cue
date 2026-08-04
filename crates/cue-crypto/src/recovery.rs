//! Recovery phrase generation and restore (docs/02 "Recovery"): the sole
//! account recovery mechanism. A phrase shown once at registration
//! deterministically re-derives a device's long-term [`Identity`], so
//! losing every device but keeping the phrase still recovers the account —
//! there is no server-side reset path (docs/02: "no email, no support
//! override").
//!
//! docs/02 describes "a 40-word recovery phrase (BIP39-style, ~256 bits)".
//! Standard BIP39 ties word count to entropy precisely (24 words for 256
//! bits, at 11 bits/word over a 2048-word list), so this module uses the
//! audited, off-the-shelf 24-word/256-bit English BIP39 wordlist rather
//! than inventing a 40-word encoding to hit the doc's word count literally.

use bip39::Mnemonic;
use hkdf::Hkdf;
use rand::{CryptoRng, Rng};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::sessions::Identity;
use crate::CryptoError;

/// 256 bits of entropy -> a 24-word BIP39 mnemonic.
const ENTROPY_BYTES: usize = 32;

/// Domain-separation label for deriving identity key material from a BIP39
/// seed via HKDF, rather than using BIP39's own PBKDF2 seed bytes directly
/// — those are defined for BIP32 HD-wallet derivation, a different purpose,
/// and mixing purposes on one raw seed is the kind of thing that turns into
/// a real vulnerability if either derivation scheme ever changes.
const HKDF_INFO: &[u8] = b"cue-crypto/recovery-phrase-identity-v1";

/// A 24-word BIP39 recovery phrase. Shown once at registration (docs/02
/// "Registration flow"): the caller is responsible for having the user
/// confirm it before the account becomes usable, and for never sending it
/// to the server.
pub struct RecoveryPhrase(Mnemonic);

impl RecoveryPhrase {
    /// Generate a fresh recovery phrase from `csprng`.
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let mut entropy = [0u8; ENTROPY_BYTES];
        csprng.fill_bytes(&mut entropy);
        let mnemonic =
            Mnemonic::from_entropy(&entropy).expect("32 bytes is a valid BIP39 entropy length");
        Self(mnemonic)
    }

    /// Parse a phrase entered by a user restoring an account. Rejects
    /// anything that fails the BIP39 checksum — almost always a mistyped or
    /// misremembered word — rather than silently deriving the wrong
    /// identity.
    pub fn parse(phrase: &str) -> Result<Self, CryptoError> {
        Mnemonic::parse(phrase)
            .map(Self)
            .map_err(|e| CryptoError::InvalidRecoveryPhrase(e.to_string()))
    }

    /// The 24 words, in order, for display and confirmation at registration.
    pub fn words(&self) -> Vec<&'static str> {
        self.0.words().collect()
    }

    /// Deterministically re-derive this device's long-term [`Identity`]
    /// (docs/02: "It deterministically re-derives the identity key.").
    /// Calling this twice on equal phrases always yields equal identities.
    pub fn to_identity(&self) -> Identity {
        let seed = self.0.to_seed("");
        let hk = Hkdf::<Sha256>::new(None, &seed);
        let mut identity_seed = [0u8; 32];
        hk.expand(HKDF_INFO, &mut identity_seed)
            .expect("32 is a valid HKDF-SHA256 output length");
        let mut rng = ChaCha20Rng::from_seed(identity_seed);
        Identity::generate(&mut rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    #[test]
    fn generated_phrase_is_24_words_and_round_trips_through_parse() {
        let phrase = RecoveryPhrase::generate(&mut OsRng.unwrap_err());
        assert_eq!(phrase.words().len(), 24);

        let text = phrase.words().join(" ");
        let restored = RecoveryPhrase::parse(&text).expect("valid phrase must parse");
        assert_eq!(restored.words(), phrase.words());
    }

    #[test]
    fn same_phrase_always_derives_the_same_identity() {
        let phrase = RecoveryPhrase::generate(&mut OsRng.unwrap_err());

        let a = phrase.to_identity();
        let b = phrase.to_identity();

        assert_eq!(a.key_pair.public_key(), b.key_pair.public_key());
        assert_eq!(
            a.key_pair.private_key().serialize(),
            b.key_pair.private_key().serialize()
        );
        assert_eq!(a.registration_id, b.registration_id);
    }

    #[test]
    fn restoring_from_the_written_down_words_derives_the_same_identity_as_the_original() {
        let original = RecoveryPhrase::generate(&mut OsRng.unwrap_err());
        let text = original.words().join(" ");
        let restored = RecoveryPhrase::parse(&text).expect("valid phrase must parse");

        assert_eq!(
            original.to_identity().key_pair.public_key(),
            restored.to_identity().key_pair.public_key()
        );
    }

    #[test]
    fn different_phrases_derive_different_identities() {
        let a = RecoveryPhrase::generate(&mut OsRng.unwrap_err());
        let b = RecoveryPhrase::generate(&mut OsRng.unwrap_err());

        assert_ne!(
            a.to_identity().key_pair.public_key(),
            b.to_identity().key_pair.public_key()
        );
    }

    #[test]
    fn a_mistyped_word_is_rejected_rather_than_silently_misderived() {
        let phrase = RecoveryPhrase::generate(&mut OsRng.unwrap_err());
        let mut words = phrase.words();
        // Swapping two words keeps every word valid-in-isolation but almost
        // always breaks the BIP39 checksum, which is exactly the failure
        // mode this test wants: caught at parse time, not as a silently
        // wrong identity.
        let len = words.len();
        words.swap(0, len - 1);
        let tampered = words.join(" ");

        // The swap could coincidentally still checksum-validate; if so this
        // isn't testing what it claims to, so require the interesting case.
        assert!(
            RecoveryPhrase::parse(&tampered).is_err(),
            "swapping the first and last word happened to still checksum-validate; \
             pick a different tamper to keep this test meaningful"
        );
    }
}
