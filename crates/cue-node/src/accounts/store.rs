//! Account, device, and prekey records (docs/02's account-record field
//! table, docs/05 data model). In-memory only for this Phase 1 slice — a
//! Postgres-backed implementation of [`AccountStore`] is a follow-up once
//! this shape has proven itself, the same order `cue-crypto::sessions`
//! took with its in-memory-only session store.
//!
//! This module's fields are exactly docs/02's list and nothing more: no IP,
//! no plaintext handle history, no contacts, no message history, no display
//! name, no profile photo — `accounts/mod.rs`'s doc comment forbids all of
//! that, and adding a field here is a security review, not a schema tweak.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;

use super::handle::Handle;
use super::trust::TrustLevel;

/// Opaque 128-bit account identifier — not derived from anything
/// user-visible (docs/02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountId([u8; 16]);

impl AccountId {
    pub fn generate() -> Self {
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

/// A signed prekey's public components (EC or Kyber), as published to the
/// Node (docs/03 "Session establishment: PQXDH"). Stored as opaque bytes —
/// the Node never needs to interpret the key material itself, only serve it
/// back to a peer establishing a session.
#[derive(Debug, Clone)]
pub struct SignedPrekeyRecord {
    pub id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OneTimePrekeyRecord {
    pub id: u32,
    pub public_key: Vec<u8>,
}

/// One device's publishable key material and opaque mailbox identifier
/// (docs/02 "Devices"). Phase 1 registration creates exactly one (primary)
/// device; QR-based linking of up to five more is a follow-up.
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub identity_key: Vec<u8>,
    /// libsignal's own registration id (docs/03 "Session establishment:
    /// PQXDH") — opaque to the Node, required by a peer reconstructing a
    /// `PreKeyBundle` from `prekey_bundle`'s response.
    pub registration_id: u32,
    pub signed_prekey: SignedPrekeyRecord,
    pub kyber_prekey: SignedPrekeyRecord,
    pub one_time_prekeys: Vec<OneTimePrekeyRecord>,
    /// Opaque, epoch-rotating mailbox identifier (docs/04 #3). Registration
    /// only mints the first value and `delivery` routes on it as-is; daily
    /// epoch rotation is still a Phase 3 gap (see `PrekeyBundleResponse`'s
    /// `mailbox_id` doc comment).
    pub mailbox_id: [u8; 16],
    #[allow(dead_code)]
    pub linked_week: u32,
}

/// The server-stored account record.
#[derive(Debug, Clone)]
pub struct AccountRecord {
    pub account_id: AccountId,
    pub handle: Handle,
    // Populated at registration; read once request-gating (docs/02 "Trust
    // levels") and account-inspection endpoints exist. Not dead: just ahead
    // of its consumer.
    #[allow(dead_code)]
    pub trust_level: TrustLevel,
    /// Registration time rounded to the week (docs/02: avoids a
    /// registration-time fingerprint).
    #[allow(dead_code)]
    pub created_week: u32,
    pub devices: Vec<DeviceRecord>,
    pub free_rerolls_remaining: u8,
}

/// Weeks since the Unix epoch, for `created_week`/`linked_week` — deliberately
/// this coarse (docs/02).
pub fn current_week() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (secs / (7 * 24 * 60 * 60)) as u32
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("handle already taken")]
    HandleTaken,
    #[error("account id already exists")]
    DuplicateAccountId,
    #[error("no account with that id")]
    NotFound,
    #[error("no free rerolls remaining")]
    NoRerollsRemaining,
}

/// The storage boundary registration and handle-reroll depend on. Backed by
/// [`InMemoryAccountStore`] today; a Postgres-backed implementation of this
/// same trait is the natural next step once docs/05's `accounts`/`devices`/
/// `prekeys` tables are wired.
pub trait AccountStore: Send + Sync {
    fn handle_taken(&self, handle: &Handle) -> bool;
    fn insert(&self, record: AccountRecord) -> Result<(), StoreError>;
    fn get(&self, account_id: &AccountId) -> Option<AccountRecord>;
    fn find_by_handle(&self, handle: &Handle) -> Option<AccountRecord>;

    /// Atomically spend one free reroll: replace the handle and decrement
    /// the counter together, so a concurrent reroll can't double-spend the
    /// last one. Returns the remaining count on success.
    fn reroll_handle(&self, account_id: &AccountId, new_handle: Handle) -> Result<u8, StoreError>;

    /// Pop one buffered one-time prekey off the account's primary device
    /// (docs/02: "consumed on session setup"). `None` if the buffer is
    /// already empty — the peer then falls back to a signed-prekey-only
    /// PQXDH handshake.
    fn take_one_time_prekey(&self, account_id: &AccountId) -> Option<OneTimePrekeyRecord>;
}

#[derive(Default)]
pub struct InMemoryAccountStore {
    accounts: Mutex<HashMap<AccountId, AccountRecord>>,
    handles: Mutex<HashMap<Handle, AccountId>>,
}

impl InMemoryAccountStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AccountStore for InMemoryAccountStore {
    fn handle_taken(&self, handle: &Handle) -> bool {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(handle)
    }

    fn insert(&self, record: AccountRecord) -> Result<(), StoreError> {
        let mut handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());

        if handles.contains_key(&record.handle) {
            return Err(StoreError::HandleTaken);
        }
        if accounts.contains_key(&record.account_id) {
            return Err(StoreError::DuplicateAccountId);
        }

        handles.insert(record.handle.clone(), record.account_id);
        accounts.insert(record.account_id, record);
        Ok(())
    }

    fn get(&self, account_id: &AccountId) -> Option<AccountRecord> {
        self.accounts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(account_id)
            .cloned()
    }

    fn find_by_handle(&self, handle: &Handle) -> Option<AccountRecord> {
        let handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        let account_id = *handles.get(handle)?;
        drop(handles);
        self.get(&account_id)
    }

    fn take_one_time_prekey(&self, account_id: &AccountId) -> Option<OneTimePrekeyRecord> {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        let device = accounts.get_mut(account_id)?.devices.first_mut()?;
        if device.one_time_prekeys.is_empty() {
            None
        } else {
            Some(device.one_time_prekeys.remove(0))
        }
    }

    fn reroll_handle(&self, account_id: &AccountId, new_handle: Handle) -> Result<u8, StoreError> {
        let mut handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());

        if handles.contains_key(&new_handle) {
            return Err(StoreError::HandleTaken);
        }
        let record = accounts.get_mut(account_id).ok_or(StoreError::NotFound)?;
        if record.free_rerolls_remaining == 0 {
            return Err(StoreError::NoRerollsRemaining);
        }

        handles.remove(&record.handle);
        record.handle = new_handle.clone();
        record.free_rerolls_remaining -= 1;
        handles.insert(new_handle, *account_id);
        Ok(record.free_rerolls_remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(handle: Handle) -> AccountRecord {
        AccountRecord {
            account_id: AccountId::generate(),
            handle,
            trust_level: TrustLevel::default(),
            created_week: current_week(),
            devices: vec![],
            free_rerolls_remaining: super::super::handle::FREE_REROLLS_AT_SIGNUP,
        }
    }

    fn handle(text: &str) -> Handle {
        Handle::parse(text).unwrap()
    }

    #[test]
    fn insert_then_get_round_trips() {
        let store = InMemoryAccountStore::new();
        let record = sample_record(handle("brisk-otter472"));
        let id = record.account_id;

        store.insert(record.clone()).unwrap();
        assert_eq!(store.get(&id).unwrap().handle, record.handle);
    }

    #[test]
    fn duplicate_handle_is_rejected() {
        let store = InMemoryAccountStore::new();
        store
            .insert(sample_record(handle("brisk-otter472")))
            .unwrap();

        let err = store
            .insert(sample_record(handle("brisk-otter472")))
            .unwrap_err();
        assert_eq!(err, StoreError::HandleTaken);
    }

    #[test]
    fn reroll_handle_moves_the_handle_index_and_spends_a_reroll() {
        let store = InMemoryAccountStore::new();
        let record = sample_record(handle("brisk-otter472"));
        let id = record.account_id;
        let starting_rerolls = record.free_rerolls_remaining;
        store.insert(record).unwrap();

        let remaining = store.reroll_handle(&id, handle("quiet-fox001")).unwrap();

        assert_eq!(remaining, starting_rerolls - 1);
        assert!(!store.handle_taken(&handle("brisk-otter472")));
        assert!(store.handle_taken(&handle("quiet-fox001")));
        assert_eq!(store.get(&id).unwrap().handle, handle("quiet-fox001"));
        assert_eq!(
            store
                .find_by_handle(&handle("quiet-fox001"))
                .unwrap()
                .account_id,
            id
        );
    }

    #[test]
    fn reroll_fails_once_free_rerolls_are_exhausted() {
        let store = InMemoryAccountStore::new();
        let mut record = sample_record(handle("brisk-otter472"));
        record.free_rerolls_remaining = 0;
        let id = record.account_id;
        store.insert(record).unwrap();

        let err = store
            .reroll_handle(&id, handle("quiet-fox001"))
            .unwrap_err();
        assert_eq!(err, StoreError::NoRerollsRemaining);
    }

    #[test]
    fn take_one_time_prekey_consumes_it_once() {
        let store = InMemoryAccountStore::new();
        let mut record = sample_record(handle("brisk-otter472"));
        let id = record.account_id;
        record.devices.push(DeviceRecord {
            identity_key: vec![1, 2, 3],
            registration_id: 42,
            signed_prekey: SignedPrekeyRecord {
                id: 1,
                public_key: vec![4, 5, 6],
                signature: vec![7, 8, 9],
            },
            kyber_prekey: SignedPrekeyRecord {
                id: 2,
                public_key: vec![10, 11],
                signature: vec![12, 13],
            },
            one_time_prekeys: vec![OneTimePrekeyRecord {
                id: 9,
                public_key: vec![42],
            }],
            mailbox_id: [0; 16],
            linked_week: current_week(),
        });
        store.insert(record).unwrap();

        let taken = store
            .take_one_time_prekey(&id)
            .expect("one buffered prekey");
        assert_eq!(taken.id, 9);
        assert!(
            store.take_one_time_prekey(&id).is_none(),
            "consumed, not reusable"
        );
    }
}
