//! The encrypted local store (docs/06 "Local storage and ephemerality", docs/03 "Local
//! storage encryption"): a SQLCipher-backed replacement for
//! `libsignal_protocol::InMemSignalProtocolStore` that persists a device's identity,
//! sessions, and prekeys across process restarts, keyed by a random key held in the OS
//! keychain. This defends the threat docs/01 names as Adversary A6, "Endpoint
//! compromise": offline forensic seizure of a locked or powered-off device. It does not
//! and cannot defend a live, unlocked, or malware-compromised endpoint — nothing at this
//! layer can, and this module makes no claim otherwise (docs/01, docs/00 design principle
//! on not overclaiming).
//!
//! Deliberate, tracked Phase 1 scope, matching `SealedSenderStub`'s precedent for flagging
//! a trade-off rather than silently deferring it: no optional Argon2id app-lock passphrase
//! (docs/03's other keying mode — this module only implements "a random key stored in the
//! OS keychain"), no "panic wipe," no ephemerality timers or secure-deletion vacuum, no
//! local search index. Each is Phase 2 polish (`docs/11`), not this slice's job.
//!
//! [`EncryptedStore`] implements [`cue_crypto::sessions::ProtocolStoreParts`] so it plugs
//! directly into `cue_crypto::sessions`'s functions in place of
//! `InMemSignalProtocolStore` — see that trait's doc for why a store needs to expose its
//! sub-stores this way. Its five sub-stores share one `rusqlite::Connection` behind
//! `Arc<Mutex<_>>`. That's a real, if uncontended, mutex, not `Rc<RefCell<_>>`: everything
//! here does end up running on `Core`'s dedicated single-threaded `LocalSet`, but
//! `Core::spawn` builds the whole `Core` (including this store) on the caller's thread and
//! moves it into a fresh OS thread via `std::thread::spawn`, which requires that one-time
//! handoff to be `Send` — `Rc` never is, regardless of whether any clone actually escapes
//! elsewhere.

use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cue_crypto::sessions::{
    CiphertextMessageType, Direction, GenericSignedPreKey as _, Identity, IdentityChange,
    IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, ProtocolStoreParts,
    PublicKey, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
};
use rand::{CryptoRng, Rng, TryRngCore as _};
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

/// One `CREATE TABLE IF NOT EXISTS` migration, safe to run on every open (first run and
/// every restart alike). `sessions`/`pre_keys`/`signed_pre_keys`/`kyber_pre_keys` mirror
/// `InMemSignalProtocolStore`'s fields; `known_identities` mirrors
/// `InMemIdentityKeyStore`'s TOFU map; `kyber_used_base_keys` backs
/// `KyberPreKeyStore::mark_kyber_pre_key_used`'s replay guard.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    key_pair BLOB NOT NULL,
    registration_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS known_identities (
    address TEXT PRIMARY KEY,
    identity_key BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    address TEXT PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pre_keys (
    id INTEGER PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS signed_pre_keys (
    id INTEGER PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS kyber_pre_keys (
    id INTEGER PRIMARY KEY,
    record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS kyber_used_base_keys (
    kyber_prekey_id INTEGER NOT NULL,
    ec_prekey_id INTEGER NOT NULL,
    base_key BLOB NOT NULL,
    PRIMARY KEY (kyber_prekey_id, ec_prekey_id, base_key)
);
";

/// Errors from opening or creating an [`EncryptedStore`], distinct from
/// [`SignalProtocolError`] (used for the day-to-day store-trait methods, whose return type
/// libsignal's own API fixes) so callers of `create`/`open` — which fail for different,
/// higher-level reasons like "wrong key" or "no OS keychain entry" — get a purpose-built
/// error type instead.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Protocol(#[from] SignalProtocolError),
    #[error("no identity record found in an opened store")]
    IdentityNotFound,
    #[error(transparent)]
    Keychain(#[from] keyring::Error),
    #[error("the OS keychain returned a secret that isn't a valid 32-byte key")]
    InvalidKeychainSecret,
}

/// A plain string wrapper implementing `Error + Send + Sync + UnwindSafe` — what
/// [`SignalProtocolError::ApplicationCallbackError`] requires of its boxed source.
/// `rusqlite::Error` itself doesn't satisfy `UnwindSafe` (it can box an inner
/// `dyn Error + Send + Sync` with no such bound), so this carries just the rendered
/// message across instead of the structured error.
#[derive(Debug)]
struct SqlError(String);

impl std::fmt::Display for SqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SqlError {}

/// Convert a `rusqlite` failure into the `SignalProtocolError` libsignal's store traits
/// require, via its `ApplicationCallbackError` variant — the documented escape hatch for a
/// custom store implementation to surface its own backend's errors.
trait MapSqlErr<T> {
    fn store_err(self, context: &'static str) -> Result<T, SignalProtocolError>;
}

impl<T> MapSqlErr<T> for rusqlite::Result<T> {
    fn store_err(self, context: &'static str) -> Result<T, SignalProtocolError> {
        self.map_err(|e| {
            SignalProtocolError::ApplicationCallbackError(
                context,
                Box::new(SqlError(e.to_string())),
            )
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

/// A 256-bit key for [`EncryptedStore`], passed to SQLCipher via its raw-key
/// `PRAGMA key = "x'...'"` form rather than a passphrase — Cue supplies an
/// already-high-entropy key itself (random, from [`StoreKeySource`]), so SQLCipher's own
/// passphrase KDF is bypassed (docs/03: "a random key stored in the OS keychain", the mode
/// this slice implements; the Argon2id-passphrase alternative is the deferred app-lock
/// path).
pub struct StoreKey(Zeroizing<[u8; 32]>);

impl StoreKey {
    pub fn random<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Where an [`EncryptedStore`]'s key comes from. Implemented by [`OsKeychainKeySource`];
/// tests build a [`StoreKey`] directly instead, so `cargo test` never touches a real OS
/// keychain (the Linux Secret Service backend needs a running D-Bus session that headless
/// CI runners don't have by default).
pub trait StoreKeySource {
    fn key(&self) -> Result<StoreKey, StoreError>;
}

/// Generates a random key on first use and persists it in the OS keychain (macOS
/// Keychain, Windows Credential Manager, or Linux Secret Service via `zbus`), keyed by
/// `service`/`user`. Never escrowed anywhere else (docs/03 "Key escrow of any kind... No.").
pub struct OsKeychainKeySource {
    service: String,
    user: String,
}

impl OsKeychainKeySource {
    pub fn new(service: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
        }
    }
}

impl StoreKeySource for OsKeychainKeySource {
    fn key(&self) -> Result<StoreKey, StoreError> {
        let entry = keyring::Entry::new(&self.service, &self.user)?;
        match entry.get_secret() {
            Ok(bytes) => {
                let bytes: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::InvalidKeychainSecret)?;
                Ok(StoreKey::from_bytes(bytes))
            }
            Err(keyring::Error::NoEntry) => {
                let mut csprng = rand::rngs::OsRng.unwrap_err();
                let key = StoreKey::random(&mut csprng);
                entry.set_secret(key.as_bytes())?;
                Ok(key)
            }
            Err(e) => Err(StoreError::Keychain(e)),
        }
    }
}

fn open_connection(path: &Path, key: &StoreKey) -> Result<Connection, StoreError> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";",
        hex_encode(key.as_bytes())
    ))?;
    // SQLCipher doesn't reject a wrong key at open time — it only becomes apparent on the
    // first real read, which would otherwise look like generic corruption. Force that read
    // now, so a wrong key fails clearly, here, instead of confusingly later.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })?;
    Ok(conn)
}

/// A SQLCipher-backed replacement for `InMemSignalProtocolStore` — see the module doc.
pub struct EncryptedStore {
    session_store: SqliteSessionStore,
    identity_store: SqliteIdentityKeyStore,
    pre_key_store: SqlitePreKeyStore,
    signed_pre_key_store: SqliteSignedPreKeyStore,
    kyber_pre_key_store: SqliteKyberPreKeyStore,
}

impl EncryptedStore {
    /// First run: create a new encrypted store at `path` (or the special SQLite string
    /// `":memory:"` for a real-SQL, zero-disk-I/O store — what this crate's own tests and
    /// `cue-testkit`'s integration test use, so they exercise the exact SQL/trait-impl
    /// code production does without slowing down or touching the filesystem), seeded with
    /// `identity` (docs/02: identity is generated once and never regenerated; losing this
    /// file without the recovery phrase loses the ability to answer any session that
    /// references keys in it).
    pub fn create(
        path: impl AsRef<Path>,
        key: &StoreKey,
        identity: &Identity,
    ) -> Result<Self, StoreError> {
        let conn = open_connection(path.as_ref(), key)?;
        conn.execute_batch(SCHEMA)?;
        conn.execute(
            "INSERT INTO identity (id, key_pair, registration_id) VALUES (1, ?1, ?2)",
            params![
                identity.key_pair.serialize().as_ref(),
                identity.registration_id as i64
            ],
        )?;
        Ok(Self::from_connection(
            conn,
            identity.key_pair,
            identity.registration_id,
        ))
    }

    /// Restart: open an existing store, returning the [`Identity`] it was created with
    /// (persists across restarts; not re-derived except via the recovery phrase).
    pub fn open(path: impl AsRef<Path>, key: &StoreKey) -> Result<(Self, Identity), StoreError> {
        let conn = open_connection(path.as_ref(), key)?;
        conn.execute_batch(SCHEMA)?;
        let (key_pair_bytes, registration_id): (Vec<u8>, i64) = conn
            .query_row(
                "SELECT key_pair, registration_id FROM identity WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::IdentityNotFound)?;
        let key_pair = IdentityKeyPair::try_from(key_pair_bytes.as_slice())?;
        let registration_id = registration_id as u32;
        let identity = Identity {
            key_pair,
            registration_id,
        };
        let store = Self::from_connection(conn, key_pair, registration_id);
        Ok((store, identity))
    }

    fn from_connection(conn: Connection, key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        let conn = Arc::new(Mutex::new(conn));
        Self {
            session_store: SqliteSessionStore { conn: conn.clone() },
            identity_store: SqliteIdentityKeyStore {
                conn: conn.clone(),
                key_pair,
                registration_id,
            },
            pre_key_store: SqlitePreKeyStore { conn: conn.clone() },
            signed_pre_key_store: SqliteSignedPreKeyStore { conn: conn.clone() },
            kyber_pre_key_store: SqliteKyberPreKeyStore { conn },
        }
    }
}

impl ProtocolStoreParts for EncryptedStore {
    type Session = SqliteSessionStore;
    type Identity = SqliteIdentityKeyStore;
    type PreKey = SqlitePreKeyStore;
    type SignedPreKey = SqliteSignedPreKeyStore;
    type KyberPreKey = SqliteKyberPreKeyStore;

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

pub struct SqliteSessionStore {
    conn: Arc<Mutex<Connection>>,
}

#[async_trait(?Send)]
impl SessionStore for SqliteSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT record FROM sessions WHERE address = ?1",
                [address.to_string()],
                |row| row.get(0),
            )
            .optional()
            .store_err("load_session")?;
        bytes.map(|b| SessionRecord::deserialize(&b)).transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let bytes = record.serialize()?;
        let conn = self.conn.lock().expect("connection mutex poisoned");
        conn.execute(
            "INSERT INTO sessions (address, record) VALUES (?1, ?2)
             ON CONFLICT(address) DO UPDATE SET record = excluded.record",
            params![address.to_string(), bytes],
        )
        .store_err("store_session")?;
        Ok(())
    }
}

pub struct SqliteIdentityKeyStore {
    conn: Arc<Mutex<Connection>>,
    key_pair: IdentityKeyPair,
    registration_id: u32,
}

impl SqliteIdentityKeyStore {
    fn known_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<Vec<u8>>, SignalProtocolError> {
        self.conn
            .lock()
            .expect("connection mutex poisoned")
            .query_row(
                "SELECT identity_key FROM known_identities WHERE address = ?1",
                [address.to_string()],
                |row| row.get(0),
            )
            .optional()
            .store_err("known_identity")
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqliteIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let existing = self.known_identity(address)?;
        let changed = match &existing {
            None => false,
            Some(bytes) => bytes.as_slice() != identity.serialize().as_ref(),
        };
        self.conn
            .lock()
            .expect("connection mutex poisoned")
            .execute(
                "INSERT INTO known_identities (address, identity_key) VALUES (?1, ?2)
                 ON CONFLICT(address) DO UPDATE SET identity_key = excluded.identity_key",
                params![address.to_string(), identity.serialize().as_ref()],
            )
            .store_err("save_identity")?;
        Ok(IdentityChange::from_changed(changed))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        Ok(match self.known_identity(address)? {
            None => true, // trust on first use
            Some(bytes) => bytes.as_slice() == identity.serialize().as_ref(),
        })
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        self.known_identity(address)?
            .map(|b| IdentityKey::try_from(b.as_slice()))
            .transpose()
    }
}

pub struct SqlitePreKeyStore {
    conn: Arc<Mutex<Connection>>,
}

#[async_trait(?Send)]
impl PreKeyStore for SqlitePreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .lock()
            .expect("connection mutex poisoned")
            .query_row(
                "SELECT record FROM pre_keys WHERE id = ?1",
                [u32::from(prekey_id) as i64],
                |row| row.get(0),
            )
            .optional()
            .store_err("get_pre_key")?;
        match bytes {
            Some(b) => PreKeyRecord::deserialize(&b),
            None => Err(SignalProtocolError::InvalidPreKeyId),
        }
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let bytes = record.serialize()?;
        self.conn
            .lock()
            .expect("connection mutex poisoned")
            .execute(
                "INSERT INTO pre_keys (id, record) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET record = excluded.record",
                params![u32::from(prekey_id) as i64, bytes],
            )
            .store_err("save_pre_key")?;
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.conn
            .lock()
            .expect("connection mutex poisoned")
            .execute(
                "DELETE FROM pre_keys WHERE id = ?1",
                [u32::from(prekey_id) as i64],
            )
            .store_err("remove_pre_key")?;
        Ok(())
    }
}

pub struct SqliteSignedPreKeyStore {
    conn: Arc<Mutex<Connection>>,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqliteSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .lock()
            .expect("connection mutex poisoned")
            .query_row(
                "SELECT record FROM signed_pre_keys WHERE id = ?1",
                [u32::from(signed_prekey_id) as i64],
                |row| row.get(0),
            )
            .optional()
            .store_err("get_signed_pre_key")?;
        match bytes {
            Some(b) => SignedPreKeyRecord::deserialize(&b),
            None => Err(SignalProtocolError::InvalidSignedPreKeyId),
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let bytes = record.serialize()?;
        self.conn
            .lock()
            .expect("connection mutex poisoned")
            .execute(
                "INSERT INTO signed_pre_keys (id, record) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET record = excluded.record",
                params![u32::from(signed_prekey_id) as i64, bytes],
            )
            .store_err("save_signed_pre_key")?;
        Ok(())
    }
}

pub struct SqliteKyberPreKeyStore {
    conn: Arc<Mutex<Connection>>,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SqliteKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .lock()
            .expect("connection mutex poisoned")
            .query_row(
                "SELECT record FROM kyber_pre_keys WHERE id = ?1",
                [u32::from(kyber_prekey_id) as i64],
                |row| row.get(0),
            )
            .optional()
            .store_err("get_kyber_pre_key")?;
        match bytes {
            Some(b) => KyberPreKeyRecord::deserialize(&b),
            None => Err(SignalProtocolError::InvalidKyberPreKeyId),
        }
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let bytes = record.serialize()?;
        self.conn
            .lock()
            .expect("connection mutex poisoned")
            .execute(
                "INSERT INTO kyber_pre_keys (id, record) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET record = excluded.record",
                params![u32::from(kyber_prekey_id) as i64, bytes],
            )
            .store_err("save_kyber_pre_key")?;
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let base_key_bytes = base_key.serialize();
        let conn = self.conn.lock().expect("connection mutex poisoned");
        let already_seen: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM kyber_used_base_keys
                 WHERE kyber_prekey_id = ?1 AND ec_prekey_id = ?2 AND base_key = ?3",
                params![
                    u32::from(kyber_prekey_id) as i64,
                    u32::from(ec_prekey_id) as i64,
                    base_key_bytes.as_ref()
                ],
                |row| row.get(0),
            )
            .optional()
            .store_err("mark_kyber_pre_key_used")?;
        if already_seen.is_some() {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused base key".to_owned(),
            ));
        }
        conn.execute(
            "INSERT INTO kyber_used_base_keys (kyber_prekey_id, ec_prekey_id, base_key)
             VALUES (?1, ?2, ?3)",
            params![
                u32::from(kyber_prekey_id) as i64,
                u32::from(ec_prekey_id) as i64,
                base_key_bytes.as_ref()
            ],
        )
        .store_err("mark_kyber_pre_key_used")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cue_crypto::sessions::{self, generate_prekeys, DeviceId};
    use rand::rngs::OsRng;
    use std::time::SystemTime;

    fn test_key() -> StoreKey {
        StoreKey::from_bytes([0x42; 32])
    }

    fn address(name: &str) -> ProtocolAddress {
        ProtocolAddress::new(name.to_owned(), DeviceId::new(1).unwrap())
    }

    #[tokio::test]
    async fn an_in_memory_store_round_trips_a_pqxdh_handshake() {
        let mut csprng = OsRng.unwrap_err();
        let alice_identity = Identity::generate(&mut csprng);
        let bob_identity = Identity::generate(&mut csprng);

        let mut alice_store =
            EncryptedStore::create(":memory:", &test_key(), &alice_identity).unwrap();
        let mut bob_store = EncryptedStore::create(":memory:", &test_key(), &bob_identity).unwrap();

        let bob_prekeys = generate_prekeys(
            &bob_identity,
            DeviceId::new(1).unwrap(),
            1.into(),
            1.into(),
            1.into(),
            &mut csprng,
        )
        .unwrap();
        sessions::save_generated_prekeys(&mut bob_store, &bob_prekeys)
            .await
            .unwrap();

        sessions::establish_session(
            &mut alice_store,
            &address("alice"),
            &address("bob"),
            &bob_prekeys.bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("Alice can establish a session from Bob's published bundle");

        let message = sessions::encrypt_message(
            &mut alice_store,
            &address("alice"),
            &address("bob"),
            b"hello from a real SQLCipher store",
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .unwrap();

        let plaintext = sessions::decrypt_message(
            &mut bob_store,
            &address("bob"),
            &address("alice"),
            &message,
            &mut csprng,
        )
        .await
        .unwrap();
        assert_eq!(plaintext, b"hello from a real SQLCipher store");
    }

    #[tokio::test]
    async fn a_session_survives_closing_and_reopening_the_store_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alice.sqlite3");
        let key = test_key();

        let mut csprng = OsRng.unwrap_err();
        let alice_identity = Identity::generate(&mut csprng);
        let bob_identity = Identity::generate(&mut csprng);

        let mut alice_store = EncryptedStore::create(&path, &key, &alice_identity).unwrap();
        let mut bob_store = EncryptedStore::create(":memory:", &test_key(), &bob_identity).unwrap();

        let bob_prekeys = generate_prekeys(
            &bob_identity,
            DeviceId::new(1).unwrap(),
            1.into(),
            1.into(),
            1.into(),
            &mut csprng,
        )
        .unwrap();
        sessions::save_generated_prekeys(&mut bob_store, &bob_prekeys)
            .await
            .unwrap();
        sessions::establish_session(
            &mut alice_store,
            &address("alice"),
            &address("bob"),
            &bob_prekeys.bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .unwrap();
        let first_message = sessions::encrypt_message(
            &mut alice_store,
            &address("alice"),
            &address("bob"),
            b"before restart",
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .unwrap();

        // Close Alice's store entirely and reopen it from the same file, proving this
        // isn't just reading back the same in-process connection.
        drop(alice_store);
        let (mut reopened, reloaded_identity) = EncryptedStore::open(&path, &key)
            .expect("a store created at `path` with `key` must be reopenable with the same key");
        assert_eq!(
            reloaded_identity.key_pair.identity_key().serialize(),
            alice_identity.key_pair.identity_key().serialize(),
            "the reopened store must have the same identity it was created with"
        );

        let plaintext = sessions::decrypt_message(
            &mut bob_store,
            &address("bob"),
            &address("alice"),
            &first_message,
            &mut csprng,
        )
        .await
        .expect("Bob can decrypt Alice's pre-restart message using her persisted prekeys");
        assert_eq!(plaintext, b"before restart");

        let reply = sessions::encrypt_message(
            &mut bob_store,
            &address("bob"),
            &address("alice"),
            b"after restart",
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .unwrap();
        let decrypted_reply = sessions::decrypt_message(
            &mut reopened,
            &address("alice"),
            &address("bob"),
            &reply,
            &mut csprng,
        )
        .await
        .expect("the reopened store can continue the ratchet using the persisted session");
        assert_eq!(decrypted_reply, b"after restart");
    }

    #[tokio::test]
    async fn opening_with_the_wrong_key_fails_instead_of_returning_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.sqlite3");
        let mut csprng = OsRng.unwrap_err();
        let identity = Identity::generate(&mut csprng);
        EncryptedStore::create(&path, &StoreKey::from_bytes([1; 32]), &identity).unwrap();

        let result = EncryptedStore::open(&path, &StoreKey::from_bytes([2; 32]));
        assert!(
            result.is_err(),
            "opening with the wrong key must fail, not silently return garbage"
        );
    }
}
