//! Two `cue-core` clients exchange a message through a real `cue-node`
//! server (docs/11 Phase 1 exit criterion: "two people message each
//! other securely... two-clients-plus-Node integration test in CI"). Both
//! accounts go through the real HTTP registration flow — including
//! solving a real proof-of-work challenge — rather than being seeded
//! directly into the store, and messages cross a real bound TCP socket,
//! not an in-process `oneshot` call.
//!
//! This is also the first real exercise of `cue-core::transport`: the
//! padding/sealed-sender-stub framing (`seal_for_delivery`/
//! `open_received`) and the `NodeClient` HTTP surface, both introduced
//! alongside this test.

use argon2::Params;
use cue_core::session::SessionManager;
use cue_core::transport::{bundle_from_response, open_received, seal_for_delivery, NodeClient};
use cue_crypto::sessions::{generate_prekeys, DeviceId, Identity, ProtocolAddress};
use cue_node::accounts::pow::{self, ChallengeId, PowChallenge};
use cue_node::accounts::store::InMemoryAccountStore;
use cue_node::api::{self, AppState, NullCaptchaVerifier, RegistrationConfig};
use cue_node::delivery::mailbox::InMemoryMailboxStore;
use cue_proto::v1::{
    OneTimePrekey, RegisterRequest, RegisterResponse, RegistrationChallenge, SignedPrekey,
};
use prost::Message as _;
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use std::net::SocketAddr;
use std::sync::Arc;

/// Cheap Argon2id params so proof-of-work solving is fast in CI, matching
/// `cue-node`'s own test suite. A real deployment's params aren't
/// negotiated over the wire at all today (`RegistrationChallenge` carries
/// `seed`/`difficulty_bits` only) — a client and Node agree on them
/// out-of-band, currently just by both defaulting to the same constant.
/// That's a real, tracked Phase 1 gap this test works around rather than
/// papers over: server and "client" below construct these independently,
/// the way a real client and Node would.
fn fast_argon2_params() -> Params {
    Params::new(8, 1, 1, Some(32)).unwrap()
}

async fn spawn_test_node() -> (String, Arc<AppState>) {
    let state = Arc::new(AppState::new(
        Box::new(InMemoryAccountStore::new()),
        Box::new(NullCaptchaVerifier),
        Box::new(InMemoryMailboxStore::new()),
        RegistrationConfig {
            argon2_params: fast_argon2_params(),
            base_difficulty_bits: 4,
            elevated_difficulty_bits: 6,
            challenge_ttl: std::time::Duration::from_secs(60),
        },
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("listener has a local address");

    let router_state = state.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            api::router(router_state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("test server error");
    });

    (format!("http://{addr}"), state)
}

struct RegisteredClient {
    handle: String,
    session: SessionManager,
    address: ProtocolAddress,
}

/// Register a fresh account through the real HTTP surface (challenge,
/// solve, register), mirroring `cue-node`'s own `register_one` test
/// helper but over a real socket via `reqwest` instead of `oneshot`.
async fn register_client(http: &reqwest::Client, base_url: &str) -> RegisteredClient {
    let mut csprng = OsRng.unwrap_err();

    let challenge_response = http
        .post(format!("{base_url}/v1/register/challenge"))
        .send()
        .await
        .expect("send challenge request");
    assert_eq!(challenge_response.status(), 200);
    let wire_challenge =
        RegistrationChallenge::decode(challenge_response.bytes().await.unwrap()).unwrap();

    let challenge_id =
        ChallengeId::from_bytes(wire_challenge.challenge_id.clone().try_into().unwrap());
    let pow_challenge = PowChallenge {
        challenge_id,
        seed: wire_challenge.seed.clone().try_into().unwrap(),
        difficulty_bits: wire_challenge.difficulty_bits.try_into().unwrap(),
    };
    let nonce = pow::solve(&fast_argon2_params(), &pow_challenge);

    let identity = Identity::generate(&mut csprng);
    let prekeys = generate_prekeys(
        &identity,
        DeviceId::new(1).unwrap(),
        1.into(),
        1.into(),
        1.into(),
        &mut csprng,
    )
    .unwrap();
    let bundle = &prekeys.bundle;

    let register_request = RegisterRequest {
        challenge_id: challenge_id.as_bytes().to_vec(),
        pow_nonce: nonce,
        captcha_token: String::new(),
        identity_key: bundle.identity_key().unwrap().serialize().to_vec(),
        signed_prekey: Some(SignedPrekey {
            id: u32::from(bundle.signed_pre_key_id().unwrap()),
            public_key: bundle.signed_pre_key_public().unwrap().serialize().to_vec(),
            signature: bundle.signed_pre_key_signature().unwrap().to_vec(),
        }),
        kyber_prekey: Some(SignedPrekey {
            id: u32::from(bundle.kyber_pre_key_id().unwrap()),
            public_key: bundle.kyber_pre_key_public().unwrap().serialize().to_vec(),
            signature: bundle.kyber_pre_key_signature().unwrap().to_vec(),
        }),
        one_time_prekeys: vec![OneTimePrekey {
            id: u32::from(bundle.pre_key_id().unwrap().unwrap()),
            public_key: bundle
                .pre_key_public()
                .unwrap()
                .unwrap()
                .serialize()
                .to_vec(),
        }],
        registration_id: identity.registration_id,
    };

    let register_response = http
        .post(format!("{base_url}/v1/register"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .body(register_request.encode_to_vec())
        .send()
        .await
        .expect("send register request");
    assert_eq!(register_response.status(), 200, "registration succeeds");
    let response = RegisterResponse::decode(register_response.bytes().await.unwrap()).unwrap();

    let address = ProtocolAddress::new(response.handle.clone(), DeviceId::new(1).unwrap());
    let mut session = SessionManager::new(&identity, address.clone()).unwrap();
    session.register_own_prekeys(&prekeys).await.unwrap();

    RegisteredClient {
        handle: response.handle,
        session,
        address,
    }
}

#[tokio::test]
async fn two_cue_core_clients_exchange_a_message_through_a_real_cue_node() {
    let (base_url, _state) = spawn_test_node().await;
    let http = reqwest::Client::new();

    let mut alice = register_client(&http, &base_url).await;
    let mut bob = register_client(&http, &base_url).await;

    let node = NodeClient::new(base_url);

    // Alice learns Bob's published bundle and current mailbox id purely
    // through the real HTTP surface, then establishes a session from it.
    let bob_bundle_response = node.fetch_prekey_bundle(&bob.handle).await.unwrap();
    let (bob_bundle, bob_mailbox_id) = bundle_from_response(bob_bundle_response).unwrap();
    alice
        .session
        .establish_session(&bob.address, &bob_bundle)
        .await
        .expect("Alice establishes a session from Bob's real, HTTP-served bundle");

    let ciphertext = alice
        .session
        .send(&bob.address, b"En handling, camarade.")
        .await
        .unwrap();
    let envelope = seal_for_delivery(&alice.address, &ciphertext, bob_mailbox_id).unwrap();
    node.deliver(&envelope)
        .await
        .expect("deliver to Bob's mailbox");

    let queued = node.fetch_mailbox(bob_mailbox_id).await.unwrap();
    assert_eq!(
        queued.len(),
        1,
        "Bob's mailbox has exactly Alice's envelope"
    );
    let (sender, received_ciphertext) = open_received(&queued[0]).unwrap();
    assert_eq!(
        sender, alice.address,
        "transport recovers the real sender identity from the sealed-sender stub"
    );

    let plaintext = bob
        .session
        .receive(&sender, &received_ciphertext)
        .await
        .expect("Bob completes the handshake and decrypts Alice's first message");
    assert_eq!(plaintext, b"En handling, camarade.");

    node.ack(bob_mailbox_id, vec![queued[0].envelope_id.clone()])
        .await
        .unwrap();
    let after_ack = node.fetch_mailbox(bob_mailbox_id).await.unwrap();
    assert!(
        after_ack.is_empty(),
        "ack deletes the envelope (docs/09 deliver-and-delete)"
    );

    // The reply, completing the round trip in the other direction. Bob
    // already has a ratcheted session with Alice, so this doesn't need a
    // fresh bundle fetch to encrypt — only to learn her mailbox id, a
    // Phase 1 gap (mailbox ids don't yet rotate/derive locally, docs/04 #3)
    // noted on `PrekeyBundleResponse.mailbox_id`.
    let alice_bundle_response = node.fetch_prekey_bundle(&alice.handle).await.unwrap();
    let (_alice_bundle, alice_mailbox_id) = bundle_from_response(alice_bundle_response).unwrap();

    let reply_ciphertext = bob.session.send(&sender, b"Toujours.").await.unwrap();
    let reply_envelope =
        seal_for_delivery(&bob.address, &reply_ciphertext, alice_mailbox_id).unwrap();
    node.deliver(&reply_envelope).await.unwrap();

    let alice_queue = node.fetch_mailbox(alice_mailbox_id).await.unwrap();
    assert_eq!(alice_queue.len(), 1);
    let (reply_sender, reply_ciphertext) = open_received(&alice_queue[0]).unwrap();
    assert_eq!(reply_sender, bob.address);

    let reply_plaintext = alice
        .session
        .receive(&reply_sender, &reply_ciphertext)
        .await
        .expect("Alice decrypts Bob's reply with the ratchet advanced");
    assert_eq!(reply_plaintext, b"Toujours.");
}

/// The live half of mailbox delivery (`NodeClient::watch_mailbox`), as
/// opposed to the polling half the test above exercises. Connects *before*
/// Alice delivers, so a passing `recv()` proves the envelope arrived via
/// the server's live fan-out (`handle_mailbox_socket`'s `live.recv()`
/// branch), not its connect-time queue flush.
#[tokio::test]
async fn bobs_mailbox_websocket_receives_a_live_envelope_and_it_can_be_acked_over_the_socket() {
    let (base_url, _state) = spawn_test_node().await;
    let http = reqwest::Client::new();

    let mut alice = register_client(&http, &base_url).await;
    let mut bob = register_client(&http, &base_url).await;

    let node = NodeClient::new(base_url);
    let bob_bundle_response = node.fetch_prekey_bundle(&bob.handle).await.unwrap();
    let (bob_bundle, bob_mailbox_id) = bundle_from_response(bob_bundle_response).unwrap();
    alice
        .session
        .establish_session(&bob.address, &bob_bundle)
        .await
        .unwrap();

    let mut stream = node
        .watch_mailbox(bob_mailbox_id)
        .await
        .expect("connect to Bob's mailbox before anything is queued");

    let ciphertext = alice
        .session
        .send(&bob.address, b"live push, not a poll")
        .await
        .unwrap();
    let envelope = seal_for_delivery(&alice.address, &ciphertext, bob_mailbox_id).unwrap();
    node.deliver(&envelope).await.unwrap();

    let pushed = stream
        .recv()
        .await
        .expect("the connection is still open")
        .expect("a well-formed envelope arrives live");
    let (sender, received_ciphertext) = open_received(&pushed).unwrap();
    assert_eq!(sender, alice.address);
    let plaintext = bob
        .session
        .receive(&sender, &received_ciphertext)
        .await
        .expect("Bob decrypts the live-pushed envelope");
    assert_eq!(plaintext, b"live push, not a poll");

    // Ack over the socket itself, not `NodeClient::ack`'s HTTP endpoint.
    stream.ack(&pushed.envelope_id).await.unwrap();

    let remaining = node.fetch_mailbox(bob_mailbox_id).await.unwrap();
    assert!(
        remaining.is_empty(),
        "a websocket ack deletes the envelope the same as an HTTP one (docs/09)"
    );
}
