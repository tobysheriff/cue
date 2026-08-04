//! Client core (docs/06, ADR-0007). Everything security-relevant lives
//! here: session management, KT verification, the local encrypted store,
//! transport (padding, cover traffic, Tor via `arti`), anonymous credential
//! lifecycle, franking. Shells (Electron via NAPI-RS, web via
//! `wasm-bindgen`, mobile later via UniFFI) are deliberately dumb — they
//! render and dispatch `Command`s, and cannot make a cryptographic
//! decision, because they never get FFI access to anything below this
//! module boundary.
//!
//! Interface shape: a `Command` in, `Event` stream out — not a
//! request/response RPC surface — to keep the boundary narrow and
//! auditable. All types here are `#[non_exhaustive]` and versioned, since a
//! shell built against an older core must fail closed, not guess.
//!
//! Core owns its own Tokio runtime; shells communicate over channels. No
//! blocking calls are allowed across the FFI boundary.

#![forbid(unsafe_code)]

use cue_crypto::sessions::{CiphertextMessage, PreKeyBundle, ProtocolAddress};
use tokio::sync::mpsc;

/// Session management (docs/03 "Direct messages"): the `SessionManager`
/// wrapping `cue_crypto::sessions` that `Core` drives.
pub mod session;

/// Turns `Core`'s raw ratchet output into wire-ready `cue_proto::v1::Envelope`s
/// and talks to a `cue-node`'s delivery HTTP surface (docs/06 "Transport").
/// A separate layer composed with `Core` over its public `Command`/`Event`
/// channels, not a new `Command` variant — see `transport`'s own doc
/// comment for why.
pub mod transport;

/// The encrypted local store (docs/06 "Local storage and ephemerality"): a
/// SQLCipher-backed replacement for `InMemSignalProtocolStore` that
/// persists identity, sessions, and prekeys across restarts. See its own
/// module doc for what's implemented here versus deferred to a later
/// phase.
pub mod store;

use session::SessionManager;

/// Commands a shell can issue to the core. Covers 1:1 session
/// establishment and messaging (docs/03) — group sessions, KT-verified
/// prekey fetches, transport, and franking commands land as their own
/// modules become real (docs/11).
#[non_exhaustive]
pub enum Command {
    /// Establish an outbound session to `peer` from their published
    /// prekey bundle (docs/03 "Session establishment: PQXDH"). Emits
    /// [`Event::SessionEstablished`] or [`Event::CommandFailed`].
    EstablishSession {
        peer: ProtocolAddress,
        bundle: Box<PreKeyBundle>,
    },
    /// Encrypt `plaintext` under `peer`'s session, establishing one via a
    /// fresh PQXDH handshake message if none exists yet (docs/03 "Ongoing
    /// messages: Double Ratchet"). Emits [`Event::MessageSent`] or
    /// [`Event::CommandFailed`].
    SendMessage {
        peer: ProtocolAddress,
        plaintext: Vec<u8>,
    },
    /// Decrypt a message received from `peer`, transparently completing
    /// an inbound handshake if this is the first message of a new
    /// session. Emits [`Event::MessageReceived`] or
    /// [`Event::CommandFailed`].
    ReceiveMessage {
        peer: ProtocolAddress,
        ciphertext: Box<CiphertextMessage>,
    },
}

/// Hand-written rather than derived: `SendMessage` carries plaintext and
/// `EstablishSession` carries key material (and `PreKeyBundle` itself
/// isn't `Debug`). Print shapes and lengths only, so an accidental
/// `tracing::debug!(?command)` can't leak either.
impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::EstablishSession { peer, .. } => f
                .debug_struct("EstablishSession")
                .field("peer", peer)
                .finish_non_exhaustive(),
            Command::SendMessage { peer, plaintext } => f
                .debug_struct("SendMessage")
                .field("peer", peer)
                .field("plaintext_len", &plaintext.len())
                .finish(),
            Command::ReceiveMessage { peer, .. } => f
                .debug_struct("ReceiveMessage")
                .field("peer", peer)
                .finish_non_exhaustive(),
        }
    }
}

/// Events the core emits back to a shell.
#[non_exhaustive]
pub enum Event {
    SessionEstablished {
        peer: ProtocolAddress,
    },
    /// The Double Ratchet output for `peer`. Turning this into a padded,
    /// sealed-sender `cue_proto::v1::Envelope` addressed to `peer`'s
    /// mailbox is transport's job and still undesigned (docs/04) — this
    /// event carries raw ratchet output, not a wire-ready envelope.
    MessageSent {
        peer: ProtocolAddress,
        ciphertext: Box<CiphertextMessage>,
    },
    MessageReceived {
        peer: ProtocolAddress,
        plaintext: Vec<u8>,
    },
    /// A command failed. `reason` is a human-readable summary and must
    /// never carry plaintext or key material.
    CommandFailed {
        reason: String,
    },
}

/// See [`Command`]'s `Debug` impl: hand-written to keep plaintext out of
/// logs.
impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::SessionEstablished { peer } => f
                .debug_struct("SessionEstablished")
                .field("peer", peer)
                .finish(),
            Event::MessageSent { peer, .. } => f
                .debug_struct("MessageSent")
                .field("peer", peer)
                .finish_non_exhaustive(),
            Event::MessageReceived { peer, plaintext } => f
                .debug_struct("MessageReceived")
                .field("peer", peer)
                .field("plaintext_len", &plaintext.len())
                .finish(),
            Event::CommandFailed { reason } => f
                .debug_struct("CommandFailed")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Errors from the core's own operations. Deliberately does not implement
/// `Clone`, matching [`cue_crypto::CryptoError`] — an error may transiently
/// wrap something derived from key material.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error(transparent)]
    Crypto(#[from] cue_crypto::CryptoError),
    #[error(transparent)]
    Store(#[from] store::StoreError),
}

/// The `Command`-in/`Event`-out actor (docs/06). `Core::spawn` starts it on
/// its own Tokio task and hands back the only surface a shell ever
/// touches: a command sender and an event receiver. No blocking calls
/// cross that boundary — every command is handled by an `.await`.
pub struct Core {
    commands: mpsc::UnboundedReceiver<Command>,
    events: mpsc::UnboundedSender<Event>,
    session: SessionManager,
}

impl Core {
    /// Start the core on its own thread, driving `session`. Runs until the
    /// returned command sender is dropped.
    ///
    /// This is a dedicated OS thread with a single-threaded runtime rather
    /// than a task on a shared multi-threaded one: `libsignal-protocol`'s
    /// store traits return futures that aren't `Send` (their own
    /// implementation detail, not a choice made here), so `core.run()`
    /// can't satisfy `tokio::spawn`'s bound. A `LocalSet` on its own
    /// thread has no such requirement and is still "its own Tokio
    /// runtime" per docs/06 — just not the shell's.
    pub fn spawn(
        session: SessionManager,
    ) -> (
        mpsc::UnboundedSender<Command>,
        mpsc::UnboundedReceiver<Event>,
    ) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let core = Core {
            commands: command_rx,
            events: event_tx,
            session,
        };

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build the core's single-threaded runtime");
            tokio::task::LocalSet::new().block_on(&runtime, core.run());
        });

        (command_tx, event_rx)
    }

    async fn run(mut self) {
        while let Some(command) = self.commands.recv().await {
            let event = self.handle(command).await;
            // The shell dropped its event receiver; nothing left to notify,
            // and no further command will be handled either.
            if self.events.send(event).is_err() {
                return;
            }
        }
    }

    async fn handle(&mut self, command: Command) -> Event {
        match command {
            Command::EstablishSession { peer, bundle } => {
                match self.session.establish_session(&peer, &bundle).await {
                    Ok(()) => Event::SessionEstablished { peer },
                    Err(err) => Event::CommandFailed {
                        reason: err.to_string(),
                    },
                }
            }
            Command::SendMessage { peer, plaintext } => {
                match self.session.send(&peer, &plaintext).await {
                    Ok(ciphertext) => Event::MessageSent {
                        peer,
                        ciphertext: Box::new(ciphertext),
                    },
                    Err(err) => Event::CommandFailed {
                        reason: err.to_string(),
                    },
                }
            }
            Command::ReceiveMessage { peer, ciphertext } => {
                match self.session.receive(&peer, &ciphertext).await {
                    Ok(plaintext) => Event::MessageReceived { peer, plaintext },
                    Err(err) => Event::CommandFailed {
                        reason: err.to_string(),
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Drives two `Core` actors purely through their public `Command`/
    //! `Event` channels — the boundary a shell (Electron, web, future
    //! mobile) actually uses (docs/06) — rather than reaching into
    //! `SessionManager` directly the way `session::tests` does. This is
    //! the closest thing to Phase 1's "two people message each other"
    //! exit criterion (docs/11) that exists on the client side so far.

    use cue_crypto::sessions::{generate_prekeys, DeviceId, Identity};
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    use super::*;
    use crate::store::{EncryptedStore, StoreKey};

    fn address(name: &str) -> ProtocolAddress {
        ProtocolAddress::new(name.to_owned(), DeviceId::new(1).unwrap())
    }

    fn test_store(identity: &Identity) -> EncryptedStore {
        EncryptedStore::create(":memory:", &StoreKey::from_bytes([0x24; 32]), identity)
            .expect("an in-memory store always opens")
    }

    #[tokio::test]
    async fn two_core_actors_establish_a_session_and_exchange_messages_over_their_channels() {
        let mut csprng = OsRng.unwrap_err();

        let alice_identity = Identity::generate(&mut csprng);
        let bob_identity = Identity::generate(&mut csprng);

        let bob_prekeys = generate_prekeys(
            &bob_identity,
            DeviceId::new(1).unwrap(),
            1.into(),
            1.into(),
            1.into(),
            &mut csprng,
        )
        .unwrap();

        let mut bob_session = SessionManager::new(test_store(&bob_identity), address("bob"));
        bob_session
            .register_own_prekeys(&bob_prekeys)
            .await
            .unwrap();
        let alice_session = SessionManager::new(test_store(&alice_identity), address("alice"));

        let (alice_tx, mut alice_rx) = Core::spawn(alice_session);
        let (bob_tx, mut bob_rx) = Core::spawn(bob_session);

        alice_tx
            .send(Command::EstablishSession {
                peer: address("bob"),
                bundle: Box::new(bob_prekeys.bundle),
            })
            .unwrap();
        assert!(
            matches!(
                alice_rx.recv().await.unwrap(),
                Event::SessionEstablished { peer } if peer == address("bob")
            ),
            "alice's session establishes from bob's published bundle"
        );

        alice_tx
            .send(Command::SendMessage {
                peer: address("bob"),
                plaintext: b"En handling, camarade.".to_vec(),
            })
            .unwrap();
        let first_ciphertext = match alice_rx.recv().await.unwrap() {
            Event::MessageSent { peer, ciphertext } => {
                assert_eq!(peer, address("bob"));
                ciphertext
            }
            other => panic!("expected MessageSent, got {other:?}"),
        };

        bob_tx
            .send(Command::ReceiveMessage {
                peer: address("alice"),
                ciphertext: first_ciphertext,
            })
            .unwrap();
        match bob_rx.recv().await.unwrap() {
            Event::MessageReceived { peer, plaintext } => {
                assert_eq!(peer, address("alice"));
                assert_eq!(plaintext, b"En handling, camarade.");
            }
            other => panic!("expected MessageReceived, got {other:?}"),
        }

        // The reply, completing the round trip in the other direction.
        bob_tx
            .send(Command::SendMessage {
                peer: address("alice"),
                plaintext: b"Toujours.".to_vec(),
            })
            .unwrap();
        let reply_ciphertext = match bob_rx.recv().await.unwrap() {
            Event::MessageSent { ciphertext, .. } => ciphertext,
            other => panic!("expected MessageSent, got {other:?}"),
        };

        alice_tx
            .send(Command::ReceiveMessage {
                peer: address("bob"),
                ciphertext: reply_ciphertext,
            })
            .unwrap();
        match alice_rx.recv().await.unwrap() {
            Event::MessageReceived { plaintext, .. } => assert_eq!(plaintext, b"Toujours."),
            other => panic!("expected MessageReceived, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_failed_command_reports_command_failed_and_does_not_kill_the_actor() {
        let mut csprng = OsRng.unwrap_err();
        let alice_identity = Identity::generate(&mut csprng);
        let alice_session = SessionManager::new(test_store(&alice_identity), address("alice"));
        let (alice_tx, mut alice_rx) = Core::spawn(alice_session);

        // No session and no bundle for "ghost" — this must fail, not
        // fabricate a message or panic the actor's task.
        alice_tx
            .send(Command::SendMessage {
                peer: address("ghost"),
                plaintext: b"hello?".to_vec(),
            })
            .unwrap();
        assert!(
            matches!(alice_rx.recv().await.unwrap(), Event::CommandFailed { .. }),
            "encrypting with no session and no bundle reports failure"
        );

        // The actor is still alive and correctly serving further commands.
        let bob_identity = Identity::generate(&mut csprng);
        let bob_prekeys = generate_prekeys(
            &bob_identity,
            DeviceId::new(1).unwrap(),
            1.into(),
            1.into(),
            1.into(),
            &mut csprng,
        )
        .unwrap();
        alice_tx
            .send(Command::EstablishSession {
                peer: address("bob"),
                bundle: Box::new(bob_prekeys.bundle),
            })
            .unwrap();
        assert!(matches!(
            alice_rx.recv().await.unwrap(),
            Event::SessionEstablished { .. }
        ));
    }
}
