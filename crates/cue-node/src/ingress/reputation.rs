//! Ingress-bucket reputation (docs/02 "Ingress reputation, without identity
//! linkage", docs/04 #5, ADR-0009). The table here is keyed by an opaque
//! [`BucketKey`] derived from a client IP and a secret that rotates daily —
//! never by the IP itself, and never persisted to disk. It exists only to
//! decide *what challenge to issue next*, then the decision is handed
//! upstream and the entry is left to expire.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use rand::RngCore;
use sha2::Sha256;

/// An opaque, unreversible bucket identifier. Two requests from the same
/// `/24` (IPv4) or `/48` (IPv6) prefix on the same day hash to the same
/// key; requests from different prefixes, or the same prefix on different
/// days, do not collide with each other in any way that leaks the
/// relationship between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BucketKey([u8; 32]);

/// A daily-rotating HMAC secret, held only in process memory. Once a day
/// turns over, the old secret is dropped and every bucket key derived from
/// it becomes permanently unlinkable to whatever comes after — a Node
/// operator (or a seized Node) cannot recompute yesterday's buckets even
/// with full access to today's process.
pub struct RotatingSecret(Mutex<(u64, [u8; 32])>);

impl RotatingSecret {
    pub fn new() -> Self {
        Self(Mutex::new(Self::fresh(current_day())))
    }

    fn fresh(day: u64) -> (u64, [u8; 32]) {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        (day, key)
    }

    /// Derive today's bucket key for `ip`. This is the only function in the
    /// server allowed to take an [`IpAddr`] as input on the registration
    /// path — everything downstream of it sees only the returned
    /// [`BucketKey`] (`ingress/mod.rs`'s "must never forward a client IP
    /// address past this layer").
    pub fn bucket_key(&self, ip: IpAddr) -> BucketKey {
        let day = current_day();
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.0 != day {
            *state = Self::fresh(day);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&state.1)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(&ip_prefix(ip));
        BucketKey(mac.finalize().into_bytes().into())
    }
}

impl Default for RotatingSecret {
    fn default() -> Self {
        Self::new()
    }
}

fn current_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400
}

/// Truncate to the prefix bucketing operates on: `/24` for IPv4, `/48` for
/// IPv6 (docs/02) — coarse enough that the bucket doesn't distinguish
/// individual hosts behind CGNAT or a residential ISP.
fn ip_prefix(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets()[..3].to_vec(),
        IpAddr::V6(v6) => v6.octets()[..6].to_vec(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressDecision {
    Allow,
    RequireCaptcha,
    FlagForReview,
}

/// The `[registration]` strike thresholds from docs/05's Node config
/// (`captcha_after`, `review_after`), plus how long a bucket's counters
/// live before being swept.
#[derive(Debug, Clone, Copy)]
pub struct ReputationThresholds {
    pub captcha_after: u32,
    pub review_after: u32,
    pub entry_ttl: Duration,
}

impl Default for ReputationThresholds {
    fn default() -> Self {
        Self {
            captcha_after: 3,
            review_after: 8,
            entry_ttl: Duration::from_secs(48 * 60 * 60),
        }
    }
}

struct ReputationEntry {
    attempts: u32,
    strikes: u32,
    last_seen: Instant,
}

/// In-memory-only reputation counters per bucket (docs/02: "never joined to
/// the account record... read only to decide what challenge to issue, then
/// discarded"). Nothing here is ever written to durable storage.
pub struct ReputationTable {
    thresholds: ReputationThresholds,
    entries: Mutex<HashMap<BucketKey, ReputationEntry>>,
}

impl ReputationTable {
    pub fn new(thresholds: ReputationThresholds) -> Self {
        Self {
            thresholds,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Record a registration attempt from `bucket` and return the decision
    /// this attempt should be gated under. Sweeps entries older than
    /// `entry_ttl` first, so the table never grows without bound.
    pub fn record_attempt(&self, bucket: BucketKey) -> IngressDecision {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        entries.retain(|_, e| now.duration_since(e.last_seen) < self.thresholds.entry_ttl);

        let entry = entries.entry(bucket).or_insert_with(|| ReputationEntry {
            attempts: 0,
            strikes: 0,
            last_seen: now,
        });
        entry.attempts += 1;
        entry.last_seen = now;
        self.decide(entry)
    }

    /// Record a strike against `bucket` — a failed PoW solution, a failed
    /// CAPTCHA, or a rejected registration. Strikes, not raw attempt counts,
    /// are what the CAPTCHA/review thresholds gate on (docs/05).
    pub fn record_strike(&self, bucket: BucketKey) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let entry = entries.entry(bucket).or_insert_with(|| ReputationEntry {
            attempts: 0,
            strikes: 0,
            last_seen: now,
        });
        entry.strikes += 1;
        entry.last_seen = now;
    }

    fn decide(&self, entry: &ReputationEntry) -> IngressDecision {
        if entry.strikes >= self.thresholds.review_after {
            IngressDecision::FlagForReview
        } else if entry.strikes >= self.thresholds.captcha_after {
            IngressDecision::RequireCaptcha
        } else {
            IngressDecision::Allow
        }
    }
}

impl Default for ReputationTable {
    fn default() -> Self {
        Self::new(ReputationThresholds::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn same_v4_slash_24_maps_to_the_same_bucket() {
        let secret = RotatingSecret::new();
        let a = secret.bucket_key(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
        let b = secret.bucket_key(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)));
        assert_eq!(a, b);
    }

    #[test]
    fn different_v4_slash_24_maps_to_different_buckets() {
        let secret = RotatingSecret::new();
        let a = secret.bucket_key(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
        let b = secret.bucket_key(IpAddr::V4(Ipv4Addr::new(203, 0, 114, 5)));
        assert_ne!(a, b);
    }

    #[test]
    fn same_v6_slash_48_maps_to_the_same_bucket() {
        let secret = RotatingSecret::new();
        // Same /48 (first three hextets); differ in the 4th hextet onward,
        // which the bucket key must ignore.
        let a = secret.bucket_key(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0x1234, 0xa, 0, 0, 0, 1,
        )));
        let b = secret.bucket_key(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0x1234, 0xb, 0xffff, 0, 0, 9,
        )));
        assert_eq!(a, b, "matches within the /48 prefix");

        // Differ in the 3rd hextet, which is inside the /48 prefix.
        let c = secret.bucket_key(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0x1235, 0xa, 0, 0, 0, 1,
        )));
        assert_ne!(a, c, "differs within the /48 boundary");
    }

    #[test]
    fn decision_escalates_with_strikes() {
        let table = ReputationTable::new(ReputationThresholds {
            captcha_after: 2,
            review_after: 4,
            entry_ttl: Duration::from_secs(3600),
        });
        let secret = RotatingSecret::new();
        let bucket = secret.bucket_key(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));

        assert_eq!(table.record_attempt(bucket), IngressDecision::Allow);
        table.record_strike(bucket);
        table.record_strike(bucket);
        assert_eq!(
            table.record_attempt(bucket),
            IngressDecision::RequireCaptcha
        );
        table.record_strike(bucket);
        table.record_strike(bucket);
        assert_eq!(table.record_attempt(bucket), IngressDecision::FlagForReview);
    }

    #[test]
    fn expired_entries_are_swept() {
        let table = ReputationTable::new(ReputationThresholds {
            captcha_after: 1,
            review_after: 2,
            entry_ttl: Duration::from_millis(1),
        });
        let secret = RotatingSecret::new();
        let bucket = secret.bucket_key(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)));

        table.record_strike(bucket);
        std::thread::sleep(Duration::from_millis(5));
        // The strike above should have been swept, so a fresh attempt reads
        // as a brand-new, unflagged bucket.
        assert_eq!(table.record_attempt(bucket), IngressDecision::Allow);
    }
}
