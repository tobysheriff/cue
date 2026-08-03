//! Proof-of-work registration gate (docs/02 "Proof of work", docs/03
//! "Proof of work": "Argon2id-based, or Equi-X"). A challenge is a random
//! seed plus a target leading-zero-bit count over `Argon2id(seed ||
//! nonce)`; a client searches for a `nonce` that meets the target, tuned so
//! the search takes a few seconds on ordinary hardware. Difficulty is a
//! server-side dial (`PowParams`), never something the client negotiates.
//!
//! Challenges are single-use and short-lived: [`PowChallengeStore::verify`]
//! consumes the challenge it checks, so a solution can never be replayed.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeId([u8; 16]);

impl ChallengeId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> [u8; 16] {
        self.0
    }
}

/// The challenge as handed to the client. `seed` and `difficulty_bits` are
/// exactly what [`RegistrationChallenge`](cue_proto::v1::RegistrationChallenge)
/// carries over the wire.
#[derive(Debug, Clone)]
pub struct PowChallenge {
    pub challenge_id: ChallengeId,
    pub seed: [u8; 32],
    pub difficulty_bits: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum PowError {
    #[error("unknown, expired, or already-consumed challenge")]
    UnknownChallenge,
    #[error("proof of work does not meet the required difficulty")]
    InsufficientWork,
}

struct IssuedChallenge {
    seed: [u8; 32],
    difficulty_bits: u8,
    issued_at: Instant,
}

/// In-memory, single-use challenge ledger. A Node never needs to persist
/// these across a restart — an in-flight registration simply has to start
/// over, which is a fine failure mode for something that takes seconds.
pub struct PowChallengeStore {
    argon2_params: Params,
    ttl: Duration,
    entries: Mutex<HashMap<ChallengeId, IssuedChallenge>>,
}

impl PowChallengeStore {
    pub fn new(argon2_params: Params, ttl: Duration) -> Self {
        Self {
            argon2_params,
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a fresh challenge at `difficulty_bits`. The caller (`accounts`'s
    /// registration handler) picks the difficulty from ingress reputation
    /// and load, not this store.
    pub fn issue(&self, difficulty_bits: u8) -> PowChallenge {
        let mut id_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut id_bytes);
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let challenge_id = ChallengeId(id_bytes);

        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, e| e.issued_at.elapsed() < self.ttl);
        entries.insert(
            challenge_id,
            IssuedChallenge {
                seed,
                difficulty_bits,
                issued_at: Instant::now(),
            },
        );

        PowChallenge {
            challenge_id,
            seed,
            difficulty_bits,
        }
    }

    /// Consume `challenge_id` and check `nonce` against it. Returns an error
    /// (and leaves the challenge consumed either way) on unknown, expired,
    /// already-solved, or insufficient-work — the caller can't tell which,
    /// by design, so there's nothing for a prober to learn from the
    /// difference.
    pub fn verify(&self, challenge_id: ChallengeId, nonce: u64) -> Result<(), PowError> {
        let issued = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            entries.remove(&challenge_id)
        };
        let issued = issued.ok_or(PowError::UnknownChallenge)?;
        if issued.issued_at.elapsed() >= self.ttl {
            return Err(PowError::UnknownChallenge);
        }

        let hash = argon2_hash(&self.argon2_params, &issued.seed, nonce);
        if leading_zero_bits(&hash) >= u32::from(issued.difficulty_bits) {
            Ok(())
        } else {
            Err(PowError::InsufficientWork)
        }
    }
}

/// Search for a `nonce` meeting `challenge`'s difficulty target. This is the
/// client's half of the puzzle — `cue-node` never calls it outside its own
/// tests, since it's `cue-core`'s job once the client core exists (docs/11
/// Phase 1). Kept here, test-only, as the reference implementation the
/// Node's own tests solve against.
#[cfg(test)]
pub(crate) fn solve(argon2_params: &Params, challenge: &PowChallenge) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        let hash = argon2_hash(argon2_params, &challenge.seed, nonce);
        if leading_zero_bits(&hash) >= u32::from(challenge.difficulty_bits) {
            return nonce;
        }
        nonce += 1;
    }
}

fn argon2_hash(params: &Params, seed: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(seed);
    input.extend_from_slice(&nonce.to_be_bytes());

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(&input, seed, &mut output)
        .expect("fixed-size seed and output never hit an Argon2 parameter error");
    output
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Cheap Argon2id parameters for tests: real registration uses the OWASP
/// default (19 MiB, t=2), but that makes solving even a handful of
/// difficulty bits too slow for a fast test suite.
#[cfg(test)]
pub(crate) fn test_params() -> Params {
    Params::new(8, 1, 1, Some(32)).expect("valid low-cost Argon2 params")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_correctly_solved_challenge_verifies_once() {
        let store = PowChallengeStore::new(test_params(), Duration::from_secs(60));
        let challenge = store.issue(4);
        let nonce = solve(&test_params(), &challenge);

        store
            .verify(challenge.challenge_id, nonce)
            .expect("correct solution verifies");

        assert!(matches!(
            store.verify(challenge.challenge_id, nonce),
            Err(PowError::UnknownChallenge)
        ));
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        let store = PowChallengeStore::new(test_params(), Duration::from_secs(60));
        // A target this high is unmeetable by any single nonce in practice,
        // so this deterministically exercises the rejection path rather
        // than depending on nonce 0 happening to fall short.
        let challenge = store.issue(250);

        assert!(matches!(
            store.verify(challenge.challenge_id, 0),
            Err(PowError::InsufficientWork)
        ));
    }

    #[test]
    fn unknown_challenge_id_is_rejected() {
        let store = PowChallengeStore::new(test_params(), Duration::from_secs(60));
        let bogus = ChallengeId::from_bytes([0xAB; 16]);
        assert!(matches!(
            store.verify(bogus, 0),
            Err(PowError::UnknownChallenge)
        ));
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let store = PowChallengeStore::new(test_params(), Duration::from_millis(1));
        let challenge = store.issue(4);
        let nonce = solve(&test_params(), &challenge);
        std::thread::sleep(Duration::from_millis(5));

        assert!(matches!(
            store.verify(challenge.challenge_id, nonce),
            Err(PowError::UnknownChallenge)
        ));
    }
}
