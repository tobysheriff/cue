//! Handle assignment (docs/02 "Handles"): `adjective-nounNNN`, assigned by
//! the Node from two wordlists, never chosen by the user. The embedded
//! lists here are a 128-word placeholder pair — docs/02 specs curated
//! 2,048-entry lists for the real keyspace, and docs/10 lets an operator
//! swap in their own per-Node — but the generation and collision logic
//! below is independent of list size, so dropping in the real lists later
//! is a data change, not a code change.

use std::fmt;

use rand::Rng;

use super::store::AccountStore;

const ADJECTIVES: &str = include_str!("wordlists/adjectives.txt");
const NOUNS: &str = include_str!("wordlists/nouns.txt");

fn wordlist(raw: &str) -> Vec<&str> {
    raw.lines()
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .collect()
}

/// An assigned handle: `{adjective}-{noun}{suffix:03}` (docs/02, e.g.
/// `brisk-otter472`). Display names are a separate, client-side,
/// server-invisible concept (docs/02) — this type has nothing to do with
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handle {
    adjective: String,
    noun: String,
    suffix: u16,
}

impl Handle {
    /// Draw a random handle from `adjectives`/`nouns`. `suffix` is in
    /// `0..1000`, giving the three-digit zero-padded tail docs/02 shows.
    fn draw<R: Rng>(adjectives: &[&str], nouns: &[&str], rng: &mut R) -> Self {
        Self {
            adjective: adjectives[rng.random_range(0..adjectives.len())].to_owned(),
            noun: nouns[rng.random_range(0..nouns.len())].to_owned(),
            suffix: rng.random_range(0..1000),
        }
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}{:03}", self.adjective, self.noun, self.suffix)
    }
}

impl Handle {
    /// Parse the `Display` form back into a `Handle` — used by the
    /// prekey-bundle-fetch route, which addresses an account by its handle
    /// in the URL path. Deliberately doesn't validate `adjective`/`noun`
    /// against the current wordlists: a handle assigned under a previous
    /// wordlist revision (docs/10: Nodes may swap lists) must keep parsing.
    pub fn parse(text: &str) -> Option<Self> {
        let (adjective, rest) = text.split_once('-')?;
        if adjective.is_empty() || rest.len() <= 3 {
            return None;
        }
        let (noun, suffix) = rest.split_at(rest.len() - 3);
        let suffix: u16 = suffix.parse().ok()?;
        Some(Self {
            adjective: adjective.to_owned(),
            noun: noun.to_owned(),
            suffix,
        })
    }
}

/// How many collisions to tolerate against the account store before giving
/// up — with a 128x128x1000 (~16.4M) keyspace and a Node of any realistic
/// size, this should never come close to firing; it exists so a pathological
/// store can't hang a registration forever.
const MAX_COLLISION_RETRIES: u32 = 1000;

#[derive(Debug, thiserror::Error)]
pub enum HandleError {
    #[error(
        "could not find a free handle after {0} attempts — wordlist keyspace may be exhausted"
    )]
    KeyspaceExhausted(u32),
}

/// Assign a fresh, currently-unused handle by drawing from the embedded
/// wordlists and re-rolling on collision against `store` (docs/02: "on
/// collision, re-roll the numeric suffix, then the words").
pub fn assign<R: Rng>(
    store: &(impl AccountStore + ?Sized),
    rng: &mut R,
) -> Result<Handle, HandleError> {
    let adjectives = wordlist(ADJECTIVES);
    let nouns = wordlist(NOUNS);

    for _ in 0..MAX_COLLISION_RETRIES {
        let candidate = Handle::draw(&adjectives, &nouns, rng);
        if !store.handle_taken(&candidate) {
            return Ok(candidate);
        }
    }
    Err(HandleError::KeyspaceExhausted(MAX_COLLISION_RETRIES))
}

/// Free rerolls before signup is complete, and the reroll cadence after
/// (docs/02: "3 free rerolls at signup then 1/30 days"). The 30-day gate
/// itself is tracked by the caller against the account's reroll history;
/// this type only carries the remaining free-reroll count.
pub const FREE_REROLLS_AT_SIGNUP: u8 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::store::InMemoryAccountStore;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn wordlists_are_non_trivial_and_disjoint_from_being_empty() {
        assert!(wordlist(ADJECTIVES).len() >= 100);
        assert!(wordlist(NOUNS).len() >= 100);
    }

    #[test]
    fn assigned_handle_matches_the_adjective_noun_nnn_format() {
        let store = InMemoryAccountStore::new();
        let mut rng = StdRng::seed_from_u64(42);
        let handle = assign(&store, &mut rng).unwrap();

        let text = handle.to_string();
        let (adjective, rest) = text.split_once('-').expect("has exactly one separator");
        assert!(wordlist(ADJECTIVES).contains(&adjective));
        assert!(rest.len() > 3, "noun plus a 3-digit suffix");
        let suffix = &rest[rest.len() - 3..];
        let noun = &rest[..rest.len() - 3];
        assert!(wordlist(NOUNS).contains(&noun));
        assert_eq!(suffix.len(), 3);
        assert!(suffix.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn parse_inverts_display() {
        let store = InMemoryAccountStore::new();
        let mut rng = StdRng::seed_from_u64(99);
        let handle = assign(&store, &mut rng).unwrap();

        let parsed = Handle::parse(&handle.to_string()).expect("parses its own Display output");
        assert_eq!(parsed, handle);
    }

    #[test]
    fn parse_rejects_malformed_input() {
        assert!(
            Handle::parse("missingsuffix").is_none(),
            "no separator at all"
        );
        assert!(Handle::parse("-otter472").is_none(), "empty adjective");
        assert!(
            Handle::parse("brisk-ab").is_none(),
            "too short for a 3-digit suffix"
        );
    }

    #[test]
    fn collision_forces_a_different_handle() {
        use crate::accounts::store::{current_week, AccountId, AccountRecord};
        use crate::accounts::trust::TrustLevel;

        let store = InMemoryAccountStore::new();
        let mut rng = StdRng::seed_from_u64(7);

        let first = assign(&store, &mut rng).unwrap();
        store
            .insert(AccountRecord {
                account_id: AccountId::generate(),
                handle: first.clone(),
                trust_level: TrustLevel::default(),
                created_week: current_week(),
                devices: vec![],
                free_rerolls_remaining: FREE_REROLLS_AT_SIGNUP,
            })
            .unwrap();

        // With the first handle now taken, repeated assignment must never
        // return it again, however many draws it takes to avoid it.
        for _ in 0..50 {
            let next = assign(&store, &mut rng).unwrap();
            assert_ne!(next, first);
        }
    }
}
