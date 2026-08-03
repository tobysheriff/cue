//! In-memory mailbox queue: the deliver-and-delete store behind
//! `delivery`'s doc comment. Keyed by opaque [`MailboxId`] alone — this
//! module never sees an `account_id` or identity key, only what
//! `accounts`/registration already reduced a device to (docs/04 #2, #3).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use cue_proto::v1::Envelope;
use rand::RngCore;
use tokio::sync::broadcast;

/// Undelivered envelopes are dropped silently past this age (docs/05
/// `envelopes` retention; docs/09 "expire at a hard 30-day TTL").
pub const ENVELOPE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Bounds how far a slow WebSocket subscriber can lag behind live
/// enqueues before it starts missing pushes. Not a correctness knob: a
/// lagged subscriber still sees every undelivered envelope on its next
/// [`MailboxStore::fetch`], since nothing is deleted except on `ack`.
const LIVE_CHANNEL_CAPACITY: usize = 64;

/// Opaque, per-device mailbox identifier (docs/04 #3). The Node routes on
/// this value and never learns which account or device it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MailboxId([u8; 16]);

impl MailboxId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Delivery's dedup/ack handle for one envelope, scoped to the mailbox it
/// was issued for (docs/09 "client-side dedup by envelope ID").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvelopeId([u8; 16]);

impl EnvelopeId {
    fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> [u8; 16] {
        self.0
    }
}

struct StoredEnvelope {
    id: EnvelopeId,
    envelope: Envelope,
    expires_at: SystemTime,
}

/// The storage boundary `delivery`'s HTTP/WebSocket handlers depend on.
/// Backed by [`InMemoryMailboxStore`] today; a Postgres-backed `envelopes`
/// table (docs/05) is the natural next step, the same order `accounts`
/// took with its own storage trait.
pub trait MailboxStore: Send + Sync {
    /// Enqueue `envelope` into `mailbox_id`'s queue, assigning it a fresh
    /// [`EnvelopeId`] (overwriting whatever the sender put in
    /// `envelope.envelope_id`, if anything) and notifying any live
    /// WebSocket subscriber. Returns the assigned id.
    fn enqueue(&self, mailbox_id: MailboxId, envelope: Envelope) -> EnvelopeId;

    /// Every envelope currently queued for `mailbox_id`, oldest first.
    /// Does not delete anything — only [`MailboxStore::ack`] does.
    fn fetch(&self, mailbox_id: &MailboxId) -> Vec<Envelope>;

    /// Delete one envelope on delivery acknowledgement (docs/09 "deliver
    /// and delete"). An unknown or already-acked id is a silent no-op.
    fn ack(&self, mailbox_id: &MailboxId, envelope_id: &EnvelopeId);

    /// Subscribe to envelopes enqueued into `mailbox_id` from this point
    /// on, for live WebSocket fan-out.
    fn subscribe(&self, mailbox_id: MailboxId) -> broadcast::Receiver<Envelope>;

    /// Drop every envelope past its hard TTL, across all mailboxes, and
    /// prune mailboxes left with nothing queued and no live subscriber.
    /// Returns how many envelopes were dropped, for the caller's periodic
    /// sweep logging only.
    fn sweep_expired(&self) -> usize;
}

#[derive(Default)]
struct MailboxEntry {
    envelopes: Vec<StoredEnvelope>,
    live: Option<broadcast::Sender<Envelope>>,
}

#[derive(Default)]
pub struct InMemoryMailboxStore {
    mailboxes: Mutex<HashMap<MailboxId, MailboxEntry>>,
}

impl InMemoryMailboxStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn sweep_before(&self, cutoff: SystemTime) -> usize {
        let mut mailboxes = self.mailboxes.lock().unwrap_or_else(|e| e.into_inner());
        let mut dropped = 0;

        mailboxes.retain(|_, entry| {
            let before = entry.envelopes.len();
            entry.envelopes.retain(|stored| stored.expires_at > cutoff);
            dropped += before - entry.envelopes.len();

            let has_subscribers = entry
                .live
                .as_ref()
                .is_some_and(|live| live.receiver_count() > 0);
            !entry.envelopes.is_empty() || has_subscribers
        });

        dropped
    }
}

impl MailboxStore for InMemoryMailboxStore {
    fn enqueue(&self, mailbox_id: MailboxId, mut envelope: Envelope) -> EnvelopeId {
        let id = EnvelopeId::generate();
        envelope.envelope_id = id.as_bytes().to_vec();

        let mut mailboxes = self.mailboxes.lock().unwrap_or_else(|e| e.into_inner());
        let entry = mailboxes.entry(mailbox_id).or_default();
        if let Some(live) = &entry.live {
            // No receivers is the common case (recipient offline); that's
            // not an error, just nothing to fan out live right now.
            let _ = live.send(envelope.clone());
        }
        entry.envelopes.push(StoredEnvelope {
            id,
            envelope,
            expires_at: SystemTime::now() + ENVELOPE_TTL,
        });

        id
    }

    fn fetch(&self, mailbox_id: &MailboxId) -> Vec<Envelope> {
        let mailboxes = self.mailboxes.lock().unwrap_or_else(|e| e.into_inner());
        mailboxes
            .get(mailbox_id)
            .map(|entry| {
                entry
                    .envelopes
                    .iter()
                    .map(|stored| stored.envelope.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn ack(&self, mailbox_id: &MailboxId, envelope_id: &EnvelopeId) {
        let mut mailboxes = self.mailboxes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = mailboxes.get_mut(mailbox_id) {
            entry.envelopes.retain(|stored| stored.id != *envelope_id);
        }
    }

    fn subscribe(&self, mailbox_id: MailboxId) -> broadcast::Receiver<Envelope> {
        let mut mailboxes = self.mailboxes.lock().unwrap_or_else(|e| e.into_inner());
        let entry = mailboxes.entry(mailbox_id).or_default();
        entry
            .live
            .get_or_insert_with(|| broadcast::channel(LIVE_CHANNEL_CAPACITY).0)
            .subscribe()
    }

    fn sweep_expired(&self) -> usize {
        self.sweep_before(SystemTime::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cue_proto::v1::SizeBucket;

    fn sample_envelope() -> Envelope {
        Envelope {
            version: 1,
            mailbox_id: vec![0xAB; 16],
            size_bucket: SizeBucket::B1kb as i32,
            ciphertext: vec![0; 1024],
            envelope_id: vec![],
        }
    }

    fn mailbox() -> MailboxId {
        MailboxId::from_bytes([7; 16])
    }

    #[test]
    fn enqueue_then_fetch_assigns_and_returns_the_envelope_id() {
        let store = InMemoryMailboxStore::new();
        let id = store.enqueue(mailbox(), sample_envelope());

        let fetched = store.fetch(&mailbox());
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].envelope_id, id.as_bytes().to_vec());
    }

    #[test]
    fn enqueue_overwrites_whatever_envelope_id_the_sender_supplied() {
        let store = InMemoryMailboxStore::new();
        let mut envelope = sample_envelope();
        envelope.envelope_id = vec![0xFF; 16];

        let assigned = store.enqueue(mailbox(), envelope);

        let fetched = store.fetch(&mailbox());
        assert_eq!(fetched[0].envelope_id, assigned.as_bytes().to_vec());
        assert_ne!(
            fetched[0].envelope_id,
            vec![0xFF; 16],
            "a sender-chosen envelope_id must never survive enqueue"
        );
    }

    #[test]
    fn fetch_returns_envelopes_in_enqueue_order() {
        let store = InMemoryMailboxStore::new();
        let first = store.enqueue(mailbox(), sample_envelope());
        let second = store.enqueue(mailbox(), sample_envelope());
        let third = store.enqueue(mailbox(), sample_envelope());

        let ids: Vec<Vec<u8>> = store
            .fetch(&mailbox())
            .into_iter()
            .map(|e| e.envelope_id)
            .collect();

        assert_eq!(
            ids,
            vec![
                first.as_bytes().to_vec(),
                second.as_bytes().to_vec(),
                third.as_bytes().to_vec(),
            ]
        );
    }

    #[test]
    fn different_mailboxes_do_not_leak_into_each_other() {
        let store = InMemoryMailboxStore::new();
        let a = MailboxId::from_bytes([1; 16]);
        let b = MailboxId::from_bytes([2; 16]);

        store.enqueue(a, sample_envelope());

        assert_eq!(store.fetch(&a).len(), 1);
        assert!(
            store.fetch(&b).is_empty(),
            "mailbox_id is the only routing key; a neighbour mailbox must see nothing"
        );
    }

    #[test]
    fn ack_deletes_the_envelope_and_only_that_one() {
        let store = InMemoryMailboxStore::new();
        let first = store.enqueue(mailbox(), sample_envelope());
        let _second = store.enqueue(mailbox(), sample_envelope());

        store.ack(&mailbox(), &first);

        let remaining = store.fetch(&mailbox());
        assert_eq!(remaining.len(), 1);
        assert_ne!(remaining[0].envelope_id, first.as_bytes().to_vec());
    }

    #[test]
    fn ack_of_unknown_id_is_a_silent_no_op() {
        let store = InMemoryMailboxStore::new();
        store.enqueue(mailbox(), sample_envelope());

        store.ack(&mailbox(), &EnvelopeId::generate());

        assert_eq!(store.fetch(&mailbox()).len(), 1);
    }

    #[test]
    fn fetch_on_an_unknown_mailbox_is_empty_not_an_error() {
        let store = InMemoryMailboxStore::new();
        assert!(store.fetch(&mailbox()).is_empty());
    }

    #[test]
    fn subscribe_receives_a_live_enqueue() {
        let store = InMemoryMailboxStore::new();
        let mut rx = store.subscribe(mailbox());

        let id = store.enqueue(mailbox(), sample_envelope());

        let pushed = rx.try_recv().expect("live push");
        assert_eq!(pushed.envelope_id, id.as_bytes().to_vec());
    }

    #[test]
    fn sweep_drops_envelopes_past_their_ttl() {
        let store = InMemoryMailboxStore::new();
        store.enqueue(mailbox(), sample_envelope());

        let far_future = SystemTime::now() + ENVELOPE_TTL + Duration::from_secs(1);
        let dropped = store.sweep_before(far_future);

        assert_eq!(dropped, 1);
        assert!(store.fetch(&mailbox()).is_empty());
    }

    #[test]
    fn sweep_prunes_empty_mailboxes_with_no_subscriber() {
        let store = InMemoryMailboxStore::new();
        let id = store.enqueue(mailbox(), sample_envelope());
        store.ack(&mailbox(), &id);

        store.sweep_expired();

        let mailboxes = store.mailboxes.lock().unwrap();
        assert!(!mailboxes.contains_key(&mailbox()));
    }

    #[test]
    fn sweep_does_not_prune_an_empty_mailbox_with_a_live_subscriber() {
        let store = InMemoryMailboxStore::new();
        // A device connects (subscribes) before anything is ever enqueued —
        // the WebSocket handler's normal order of operations.
        let _rx = store.subscribe(mailbox());

        store.sweep_expired();

        let mailboxes = store.mailboxes.lock().unwrap();
        assert!(
            mailboxes.contains_key(&mailbox()),
            "an idle-but-connected mailbox must survive a sweep"
        );
    }

    /// Test-only seam for controlling an envelope's expiry directly —
    /// `ENVELOPE_TTL` is a fixed 30-day constant in production, too long to
    /// exercise by just waiting, so this bypasses `enqueue`'s hardcoded TTL
    /// the same way a mock clock would.
    fn enqueue_with_ttl(
        store: &InMemoryMailboxStore,
        mailbox_id: MailboxId,
        envelope: Envelope,
        ttl: Duration,
    ) -> EnvelopeId {
        let id = EnvelopeId::generate();
        let mut envelope = envelope;
        envelope.envelope_id = id.as_bytes().to_vec();
        let mut mailboxes = store.mailboxes.lock().unwrap_or_else(|e| e.into_inner());
        mailboxes
            .entry(mailbox_id)
            .or_default()
            .envelopes
            .push(StoredEnvelope {
                id,
                envelope,
                expires_at: SystemTime::now() + ttl,
            });
        id
    }

    #[test]
    fn sweep_drops_only_the_envelopes_past_their_own_ttl() {
        let store = InMemoryMailboxStore::new();
        let expiring_soon = enqueue_with_ttl(
            &store,
            mailbox(),
            sample_envelope(),
            Duration::from_millis(1),
        );
        let fresh = store.enqueue(mailbox(), sample_envelope());

        let cutoff = SystemTime::now() + Duration::from_millis(2);
        let dropped = store.sweep_before(cutoff);

        assert_eq!(dropped, 1);
        let remaining = store.fetch(&mailbox());
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].envelope_id, fresh.as_bytes().to_vec());
        assert_ne!(remaining[0].envelope_id, expiring_soon.as_bytes().to_vec());
    }

    #[tokio::test]
    async fn a_lagged_live_subscriber_still_sees_everything_through_fetch() {
        let store = InMemoryMailboxStore::new();
        let mut rx = store.subscribe(mailbox());

        // Push well past the live channel's ring buffer capacity without
        // ever draining it, so the subscriber falls behind.
        let total = LIVE_CHANNEL_CAPACITY * 2;
        for _ in 0..total {
            store.enqueue(mailbox(), sample_envelope());
        }

        let result = rx.recv().await;
        assert!(
            matches!(result, Err(broadcast::error::RecvError::Lagged(_))),
            "a slow subscriber is expected to lag, not silently miss without noticing"
        );

        // The durable queue is unaffected by the live channel falling
        // behind — this is exactly why `fetch`/the WebSocket handler's
        // initial flush exist alongside the live push.
        assert_eq!(store.fetch(&mailbox()).len(), total);
    }
}
