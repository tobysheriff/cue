//! The registration HTTP surface (docs/05: axum over hyper). Everything
//! that talks to a raw [`std::net::IpAddr`] lives in [`register_challenge`]
//! and nowhere else — the moment a bucket key is derived, the address
//! itself is dropped (`ingress/mod.rs`'s "must never forward a client IP
//! address past this layer").

mod captcha;
mod protobuf;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use argon2::Params;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use cue_crypto::sessions::PublicKey;
use cue_proto::v1::{
    AckRequest, Envelope, MailboxEnvelopes, OneTimePrekey, PrekeyBundleResponse, RegisterRequest,
    RegisterResponse, RegistrationChallenge, RerollHandleRequest, RerollHandleResponse,
    SignedPrekey, SizeBucket,
};
use prost::Message as _;
use tokio::sync::broadcast;

use crate::accounts::handle::{self, Handle, FREE_REROLLS_AT_SIGNUP};
use crate::accounts::pow::{ChallengeId, PowChallengeStore};
use crate::accounts::store::{
    current_week, AccountId, AccountRecord, AccountStore, DeviceRecord, OneTimePrekeyRecord,
    SignedPrekeyRecord as StoredSignedPrekey, StoreError,
};
use crate::accounts::trust::TrustLevel;
use crate::delivery::mailbox::{EnvelopeId, MailboxId, MailboxStore};
use crate::ingress::reputation::{BucketKey, IngressDecision, ReputationTable, RotatingSecret};

pub use captcha::{CaptchaVerifier, NullCaptchaVerifier};
use protobuf::Protobuf;

/// The Node's own tuning dials for registration (docs/05's
/// `[registration]` config block), expressed as PoW bit-targets rather than
/// `pow_seconds` directly — the seconds-to-bits mapping depends on
/// `argon2_params` and the hardware it runs on, so it isn't hard-coded here.
pub struct RegistrationConfig {
    pub argon2_params: Params,
    pub base_difficulty_bits: u8,
    pub elevated_difficulty_bits: u8,
    pub challenge_ttl: Duration,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self {
            argon2_params: Params::DEFAULT,
            // Approximate defaults, not yet load-tested against docs/02's
            // "3-8 seconds on a mid-range laptop" target — a real deployment
            // should benchmark `argon2_params` on its own hardware and
            // retune these.
            base_difficulty_bits: 8,
            elevated_difficulty_bits: 12,
            challenge_ttl: Duration::from_secs(5 * 60),
        }
    }
}

struct PendingChallenge {
    bucket: BucketKey,
    captcha_required: bool,
}

pub struct AppState {
    ingress_secret: RotatingSecret,
    reputation: ReputationTable,
    pow: PowChallengeStore,
    pending: Mutex<HashMap<ChallengeId, PendingChallenge>>,
    accounts: Box<dyn AccountStore>,
    captcha: Box<dyn CaptchaVerifier>,
    mailboxes: Box<dyn MailboxStore>,
    config: RegistrationConfig,
}

impl AppState {
    pub fn new(
        accounts: Box<dyn AccountStore>,
        captcha: Box<dyn CaptchaVerifier>,
        mailboxes: Box<dyn MailboxStore>,
        config: RegistrationConfig,
    ) -> Self {
        Self {
            ingress_secret: RotatingSecret::new(),
            reputation: ReputationTable::default(),
            pow: PowChallengeStore::new(config.argon2_params.clone(), config.challenge_ttl),
            pending: Mutex::new(HashMap::new()),
            accounts,
            captcha,
            mailboxes,
            config,
        }
    }

    /// Drop every envelope past its hard 30-day TTL (docs/09), across all
    /// mailboxes. Called on a periodic tick from `main`; exposed here so
    /// the caller doesn't need to reach into `mailboxes` directly.
    pub fn sweep_expired_envelopes(&self) -> usize {
        self.mailboxes.sweep_expired()
    }
}

pub fn router(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/register/challenge", post(register_challenge))
        .route("/v1/register", post(register))
        .route("/v1/register/reroll", post(reroll_handle))
        .route("/v1/accounts/{handle}/prekey-bundle", get(prekey_bundle))
        .route("/v1/deliver", post(deliver))
        .route("/v1/mailbox/{mailbox_id}", get(fetch_mailbox))
        .route("/v1/mailbox/{mailbox_id}/ack", post(ack_mailbox))
        .route("/v1/mailbox/{mailbox_id}/ws", get(mailbox_ws))
        .with_state(state)
}

enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    Conflict(String),
    NotFound(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
        };
        (status, message).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::HandleTaken => ApiError::Conflict(err.to_string()),
            StoreError::DuplicateAccountId => ApiError::Conflict(err.to_string()),
            StoreError::NotFound => ApiError::NotFound(err.to_string()),
            StoreError::NoRerollsRemaining => ApiError::Unauthorized(err.to_string()),
        }
    }
}

async fn register_challenge(
    State(state): State<std::sync::Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Protobuf<RegistrationChallenge> {
    let bucket = state.ingress_secret.bucket_key(addr.ip());
    let decision = state.reputation.record_attempt(bucket);

    let (difficulty_bits, captcha_required) = match decision {
        IngressDecision::Allow => (state.config.base_difficulty_bits, false),
        IngressDecision::RequireCaptcha => (state.config.base_difficulty_bits, true),
        // Moderator-review cohorts are `moderation`'s job once it exists
        // (docs/02); until then, the extra friction of a harder puzzle is
        // this bucket's only consequence.
        IngressDecision::FlagForReview => (state.config.elevated_difficulty_bits, true),
    };

    let challenge = state.pow.issue(difficulty_bits);
    state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            challenge.challenge_id,
            PendingChallenge {
                bucket,
                captcha_required,
            },
        );

    Protobuf(RegistrationChallenge {
        challenge_id: challenge.challenge_id.as_bytes().to_vec(),
        seed: challenge.seed.to_vec(),
        difficulty_bits: u32::from(challenge.difficulty_bits),
        captcha_required,
    })
}

fn challenge_id_from_bytes(bytes: &[u8]) -> Result<ChallengeId, ApiError> {
    let array: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("challenge_id must be 16 bytes".into()))?;
    Ok(ChallengeId::from_bytes(array))
}

async fn register(
    State(state): State<std::sync::Arc<AppState>>,
    Protobuf(req): Protobuf<RegisterRequest>,
) -> Result<Protobuf<RegisterResponse>, ApiError> {
    let challenge_id = challenge_id_from_bytes(&req.challenge_id)?;

    let pending = state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&challenge_id)
        .ok_or_else(|| ApiError::BadRequest("unknown or expired challenge".into()))?;

    if state.pow.verify(challenge_id, req.pow_nonce).is_err() {
        state.reputation.record_strike(pending.bucket);
        return Err(ApiError::Unauthorized(
            "proof of work did not verify".into(),
        ));
    }

    if pending.captcha_required && !state.captcha.verify(&req.captcha_token) {
        state.reputation.record_strike(pending.bucket);
        return Err(ApiError::Unauthorized("captcha did not verify".into()));
    }

    let signed_prekey = signed_prekey_from_wire(
        req.signed_prekey
            .ok_or_else(|| ApiError::BadRequest("missing signed_prekey".into()))?,
    );
    let kyber_prekey = signed_prekey_from_wire(
        req.kyber_prekey
            .ok_or_else(|| ApiError::BadRequest("missing kyber_prekey".into()))?,
    );
    let one_time_prekeys = req
        .one_time_prekeys
        .into_iter()
        .map(|p| OneTimePrekeyRecord {
            id: p.id,
            public_key: p.public_key,
        })
        .collect();

    let device = DeviceRecord {
        identity_key: req.identity_key,
        registration_id: req.registration_id,
        signed_prekey,
        kyber_prekey,
        one_time_prekeys,
        mailbox_id: rand::random(),
        linked_week: current_week(),
    };

    let handle = handle::assign(&*state.accounts, &mut rand::rng())
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let record = AccountRecord {
        account_id: AccountId::generate(),
        handle: handle.clone(),
        trust_level: TrustLevel::default(),
        created_week: current_week(),
        devices: vec![device],
        free_rerolls_remaining: FREE_REROLLS_AT_SIGNUP,
    };
    let account_id = record.account_id;
    state.accounts.insert(record)?;

    Ok(Protobuf(RegisterResponse {
        account_id: account_id.as_bytes().to_vec(),
        handle: handle.to_string(),
        rerolls_remaining: u32::from(FREE_REROLLS_AT_SIGNUP),
    }))
}

fn signed_prekey_from_wire(wire: SignedPrekey) -> StoredSignedPrekey {
    StoredSignedPrekey {
        id: wire.id,
        public_key: wire.public_key,
        signature: wire.signature,
    }
}

async fn reroll_handle(
    State(state): State<std::sync::Arc<AppState>>,
    Protobuf(req): Protobuf<RerollHandleRequest>,
) -> Result<Protobuf<RerollHandleResponse>, ApiError> {
    let account_id_bytes: [u8; 16] = req
        .account_id
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::BadRequest("account_id must be 16 bytes".into()))?;
    let account_id = AccountId::from_bytes(account_id_bytes);

    let record = state
        .accounts
        .get(&account_id)
        .ok_or_else(|| ApiError::NotFound("no such account".into()))?;
    let primary_device = record
        .devices
        .first()
        .ok_or_else(|| ApiError::NotFound("account has no primary device".into()))?;

    let identity_key = PublicKey::deserialize(&primary_device.identity_key)
        .map_err(|_| ApiError::BadRequest("malformed stored identity key".into()))?;
    if !identity_key.verify_signature(&account_id_bytes, &req.signature) {
        return Err(ApiError::Unauthorized(
            "signature does not match the account's identity key".into(),
        ));
    }

    let new_handle = handle::assign(&*state.accounts, &mut rand::rng())
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let remaining = state
        .accounts
        .reroll_handle(&account_id, new_handle.clone())?;

    Ok(Protobuf(RerollHandleResponse {
        handle: new_handle.to_string(),
        rerolls_remaining: u32::from(remaining),
    }))
}

/// Serve the public prekey material a peer needs to open a PQXDH session
/// with this account's primary device (docs/03 "Session establishment").
/// Consumes one buffered one-time prekey per fetch (docs/02).
async fn prekey_bundle(
    State(state): State<std::sync::Arc<AppState>>,
    Path(handle_text): Path<String>,
) -> Result<Protobuf<PrekeyBundleResponse>, ApiError> {
    let handle = Handle::parse(&handle_text)
        .ok_or_else(|| ApiError::BadRequest("malformed handle".into()))?;
    let record = state
        .accounts
        .find_by_handle(&handle)
        .ok_or_else(|| ApiError::NotFound("no such account".into()))?;
    let primary_device = record
        .devices
        .first()
        .ok_or_else(|| ApiError::NotFound("account has no primary device".into()))?;

    let one_time_prekey = state
        .accounts
        .take_one_time_prekey(&record.account_id)
        .map(|p| OneTimePrekey {
            id: p.id,
            public_key: p.public_key,
        });

    Ok(Protobuf(PrekeyBundleResponse {
        identity_key: primary_device.identity_key.clone(),
        signed_prekey: Some(signed_prekey_to_wire(&primary_device.signed_prekey)),
        kyber_prekey: Some(signed_prekey_to_wire(&primary_device.kyber_prekey)),
        one_time_prekey,
        mailbox_id: primary_device.mailbox_id.to_vec(),
        registration_id: primary_device.registration_id,
    }))
}

fn signed_prekey_to_wire(record: &StoredSignedPrekey) -> SignedPrekey {
    SignedPrekey {
        id: record.id,
        public_key: record.public_key.clone(),
        signature: record.signature.clone(),
    }
}

/// The exact ciphertext length a `size_bucket` claim commits to (docs/04
/// "fixed-size padded envelopes"). `delivery` rejects anything that
/// doesn't match rather than accepting whatever length shows up — a
/// mismatched bucket is either a broken client or an attempt to leak
/// message length past the padding scheme.
fn expected_ciphertext_len(bucket: SizeBucket) -> Option<usize> {
    match bucket {
        SizeBucket::B1kb => Some(1024),
        SizeBucket::B4kb => Some(4 * 1024),
        SizeBucket::B16kb => Some(16 * 1024),
        SizeBucket::B64kb => Some(64 * 1024),
        SizeBucket::Unspecified => None,
    }
}

fn mailbox_id_from_hex(text: &str) -> Result<MailboxId, ApiError> {
    if text.len() != 32 {
        return Err(ApiError::BadRequest(
            "mailbox_id must be 32 hex characters".into(),
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        let byte = std::str::from_utf8(pair)
            .ok()
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            .ok_or_else(|| ApiError::BadRequest("mailbox_id must be hex".into()))?;
        bytes[i] = byte;
    }
    Ok(MailboxId::from_bytes(bytes))
}

/// `POST /v1/deliver` — enqueue one envelope (docs/05 delivery pipeline's
/// "validate envelope shape + padding bucket" then "enqueue to recipient
/// mailbox"). The Node never inspects `mailbox_id` against `accounts`: it
/// is an opaque routing key, and validating it against a real account
/// would be exactly the correlation sealed mailboxes exist to prevent.
async fn deliver(
    State(state): State<std::sync::Arc<AppState>>,
    Protobuf(envelope): Protobuf<Envelope>,
) -> Result<StatusCode, ApiError> {
    let bucket = SizeBucket::try_from(envelope.size_bucket)
        .map_err(|_| ApiError::BadRequest("unknown size_bucket".into()))?;
    let expected_len = expected_ciphertext_len(bucket)
        .ok_or_else(|| ApiError::BadRequest("size_bucket must be set".into()))?;
    if envelope.ciphertext.len() != expected_len {
        return Err(ApiError::BadRequest(
            "ciphertext length does not match size_bucket".into(),
        ));
    }

    let mailbox_id_bytes: [u8; 16] = envelope
        .mailbox_id
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::BadRequest("mailbox_id must be 16 bytes".into()))?;

    state
        .mailboxes
        .enqueue(MailboxId::from_bytes(mailbox_id_bytes), envelope);

    Ok(StatusCode::ACCEPTED)
}

/// `GET /v1/mailbox/{mailbox_id}` — peek at what's currently queued,
/// without deleting anything (docs/09: only an ack deletes). Phase 1's
/// polling fallback alongside `mailbox_ws`'s live push.
async fn fetch_mailbox(
    State(state): State<std::sync::Arc<AppState>>,
    Path(mailbox_id_hex): Path<String>,
) -> Result<Protobuf<MailboxEnvelopes>, ApiError> {
    let mailbox_id = mailbox_id_from_hex(&mailbox_id_hex)?;
    Ok(Protobuf(MailboxEnvelopes {
        envelopes: state.mailboxes.fetch(&mailbox_id),
    }))
}

/// `POST /v1/mailbox/{mailbox_id}/ack` — delete-on-ack (docs/09 "deliver
/// and delete"). Unknown ids are a silent no-op, matching
/// [`MailboxStore::ack`].
async fn ack_mailbox(
    State(state): State<std::sync::Arc<AppState>>,
    Path(mailbox_id_hex): Path<String>,
    Protobuf(req): Protobuf<AckRequest>,
) -> Result<StatusCode, ApiError> {
    let mailbox_id = mailbox_id_from_hex(&mailbox_id_hex)?;
    for envelope_id in req.envelope_ids {
        let id_bytes: [u8; 16] = envelope_id
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::BadRequest("envelope_id must be 16 bytes".into()))?;
        state
            .mailboxes
            .ack(&mailbox_id, &EnvelopeId::from_bytes(id_bytes));
    }
    Ok(StatusCode::OK)
}

/// `GET /v1/mailbox/{mailbox_id}/ws` — the long-lived connection docs/05's
/// delivery pipeline fans out to. On connect: flush whatever's already
/// queued, then push new envelopes live as they're enqueued. Each
/// server→client frame is one protobuf-encoded [`Envelope`]; each
/// client→server frame is one 16-byte envelope_id to ack.
async fn mailbox_ws(
    State(state): State<std::sync::Arc<AppState>>,
    Path(mailbox_id_hex): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let mailbox_id = mailbox_id_from_hex(&mailbox_id_hex)?;
    Ok(ws.on_upgrade(move |socket| handle_mailbox_socket(state, mailbox_id, socket)))
}

async fn handle_mailbox_socket(
    state: std::sync::Arc<AppState>,
    mailbox_id: MailboxId,
    mut socket: WebSocket,
) {
    // Subscribe before draining the current queue: an envelope enqueued
    // between `fetch` and `subscribe` would otherwise be missed by both.
    let mut live = state.mailboxes.subscribe(mailbox_id);

    for envelope in state.mailboxes.fetch(&mailbox_id) {
        if socket
            .send(Message::Binary(envelope.encode_to_vec().into()))
            .await
            .is_err()
        {
            return;
        }
    }

    loop {
        tokio::select! {
            pushed = live.recv() => {
                match pushed {
                    Ok(envelope) => {
                        if socket.send(Message::Binary(envelope.encode_to_vec().into())).await.is_err() {
                            return;
                        }
                    }
                    // Missed some live pushes; the next `fetch` (or this
                    // connection's next successful recv) still sees
                    // everything undelivered, so just keep going.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    // The channel is genuinely gone — `recv` would return
                    // `Closed` immediately forever, so looping on it would
                    // busy-spin. Nothing more can arrive live; end the task
                    // rather than hold the socket open uselessly.
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Ok(id_bytes) = <[u8; 16]>::try_from(bytes.as_ref()) {
                            state.mailboxes.ack(&mailbox_id, &EnvelopeId::from_bytes(id_bytes));
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => return,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Drives the whole registration surface through the real axum `Router`
    //! (docs/11 Phase 1 exit: "two people message each other securely" —
    //! this is the registration half of that). No TCP socket is bound;
    //! `tower::ServiceExt::oneshot` calls the router directly, with a
    //! `ConnectInfo` extension standing in for what `axum::serve` would
    //! normally attach from the accepted connection.

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::Request;
    use cue_crypto::sessions::Identity;
    use prost::Message;
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;
    use tower::ServiceExt;

    use super::*;
    use crate::accounts::pow::PowChallenge;
    use crate::accounts::store::InMemoryAccountStore;
    use crate::ingress::reputation::ReputationThresholds;

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState::new(
            Box::new(InMemoryAccountStore::new()),
            Box::new(NullCaptchaVerifier),
            Box::new(crate::delivery::mailbox::InMemoryMailboxStore::new()),
            RegistrationConfig {
                argon2_params: Params::new(8, 1, 1, Some(32)).unwrap(),
                base_difficulty_bits: 4,
                elevated_difficulty_bits: 6,
                challenge_ttl: Duration::from_secs(60),
            },
        ))
    }

    fn client_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)), 4242)
    }

    async fn decode<T: Message + Default>(response: axum::response::Response) -> T {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        T::decode(body).expect("decode response as protobuf")
    }

    async fn fetch_challenge(router: &Router) -> RegistrationChallenge {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/register/challenge")
            .extension(ConnectInfo(client_addr()))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        decode(response).await
    }

    fn solve_challenge(state: &AppState, wire: &RegistrationChallenge) -> (ChallengeId, u64) {
        let challenge_id = ChallengeId::from_bytes(wire.challenge_id.clone().try_into().unwrap());
        let challenge = PowChallenge {
            challenge_id,
            seed: wire.seed.clone().try_into().unwrap(),
            difficulty_bits: wire.difficulty_bits.try_into().unwrap(),
        };
        let nonce = crate::accounts::pow::solve(&state.config.argon2_params, &challenge);
        (challenge_id, nonce)
    }

    struct Registered {
        identity: Identity,
        account_id: Vec<u8>,
        handle: String,
        signed_prekey: SignedPrekey,
        kyber_prekey: SignedPrekey,
        one_time_prekey: OneTimePrekey,
    }

    async fn register_one(router: &Router, state: &AppState) -> Registered {
        let wire_challenge = fetch_challenge(router).await;
        let (challenge_id, nonce) = solve_challenge(state, &wire_challenge);

        let identity = Identity::generate(&mut OsRng.unwrap_err());
        let identity_key = identity.key_pair.identity_key().serialize().to_vec();
        let signed_prekey = SignedPrekey {
            id: 1,
            public_key: vec![0xAA; 33],
            signature: vec![0xBB; 64],
        };
        let kyber_prekey = SignedPrekey {
            id: 2,
            public_key: vec![0xCC; 1568],
            signature: vec![0xDD; 64],
        };
        let one_time_prekey = OneTimePrekey {
            id: 9,
            public_key: vec![0xEE; 33],
        };

        let register_request = RegisterRequest {
            challenge_id: challenge_id.as_bytes().to_vec(),
            pow_nonce: nonce,
            captcha_token: String::new(),
            identity_key,
            signed_prekey: Some(signed_prekey.clone()),
            kyber_prekey: Some(kyber_prekey.clone()),
            one_time_prekeys: vec![one_time_prekey.clone()],
            registration_id: identity.registration_id,
        };

        let request = Request::builder()
            .method("POST")
            .uri("/v1/register")
            .extension(ConnectInfo(client_addr()))
            .header("content-type", "application/x-protobuf")
            .body(Body::from(register_request.encode_to_vec()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "registration succeeds");
        let register_response: RegisterResponse = decode(response).await;

        Registered {
            identity,
            account_id: register_response.account_id,
            handle: register_response.handle,
            signed_prekey,
            kyber_prekey,
            one_time_prekey,
        }
    }

    #[tokio::test]
    async fn full_registration_flow_ends_with_a_usable_prekey_bundle() {
        let state = test_state();
        let router = router(state.clone());

        let registered = register_one(&router, &state).await;
        assert!(
            registered.handle.contains('-'),
            "handle is adjective-nounNNN: {}",
            registered.handle
        );

        // Fetching the bundle serves back exactly what was published, and
        // consumes the one buffered one-time prekey.
        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/accounts/{}/prekey-bundle", registered.handle))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bundle: PrekeyBundleResponse = decode(response).await;

        assert_eq!(
            bundle.identity_key,
            registered
                .identity
                .key_pair
                .identity_key()
                .serialize()
                .to_vec()
        );
        assert_eq!(bundle.signed_prekey, Some(registered.signed_prekey));
        assert_eq!(bundle.kyber_prekey, Some(registered.kyber_prekey));
        assert_eq!(bundle.one_time_prekey, Some(registered.one_time_prekey));

        // A second fetch finds the one-time prekey buffer already empty.
        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/accounts/{}/prekey-bundle", registered.handle))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let bundle_again: PrekeyBundleResponse = decode(response).await;
        assert_eq!(bundle_again.one_time_prekey, None);
    }

    #[tokio::test]
    async fn reroll_requires_a_valid_signature_from_the_identity_key() {
        let state = test_state();
        let router = router(state.clone());
        let registered = register_one(&router, &state).await;

        let mut csprng = OsRng.unwrap_err();
        let good_signature = registered
            .identity
            .key_pair
            .private_key()
            .calculate_signature(&registered.account_id, &mut csprng)
            .unwrap();

        // A signature from the wrong key is rejected.
        let impostor = Identity::generate(&mut csprng);
        let bad_signature = impostor
            .key_pair
            .private_key()
            .calculate_signature(&registered.account_id, &mut csprng)
            .unwrap();
        let bad_request = Request::builder()
            .method("POST")
            .uri("/v1/register/reroll")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(
                RerollHandleRequest {
                    account_id: registered.account_id.clone(),
                    signature: bad_signature.to_vec(),
                }
                .encode_to_vec(),
            ))
            .unwrap();
        let response = router.clone().oneshot(bad_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // The real owner's signature succeeds and spends a free reroll.
        let good_request = Request::builder()
            .method("POST")
            .uri("/v1/register/reroll")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(
                RerollHandleRequest {
                    account_id: registered.account_id.clone(),
                    signature: good_signature.to_vec(),
                }
                .encode_to_vec(),
            ))
            .unwrap();
        let response = router.clone().oneshot(good_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let reroll_response: RerollHandleResponse = decode(response).await;

        assert_ne!(reroll_response.handle, registered.handle);
        assert_eq!(
            reroll_response.rerolls_remaining,
            u32::from(FREE_REROLLS_AT_SIGNUP) - 1
        );
    }

    #[tokio::test]
    async fn repeated_failed_registration_attempts_eventually_require_a_captcha() {
        // A near-unmeetable base difficulty makes nonce 0 deterministically
        // wrong, so every attempt below is a guaranteed strike rather than
        // one that occasionally succeeds by chance.
        let state = Arc::new(AppState::new(
            Box::new(InMemoryAccountStore::new()),
            Box::new(NullCaptchaVerifier),
            Box::new(crate::delivery::mailbox::InMemoryMailboxStore::new()),
            RegistrationConfig {
                argon2_params: Params::new(8, 1, 1, Some(32)).unwrap(),
                base_difficulty_bits: 200,
                elevated_difficulty_bits: 200,
                challenge_ttl: Duration::from_secs(60),
            },
        ));
        let router = router(state.clone());

        // Force enough strikes from the same bucket (submitting nonsense
        // nonces against real challenges) to cross `captcha_after`.
        for _ in 0..(ReputationThresholds::default().captcha_after + 1) {
            let wire_challenge = fetch_challenge(&router).await;
            let request = Request::builder()
                .method("POST")
                .uri("/v1/register")
                .extension(ConnectInfo(client_addr()))
                .header("content-type", "application/x-protobuf")
                .body(Body::from(
                    RegisterRequest {
                        challenge_id: wire_challenge.challenge_id,
                        pow_nonce: 0,
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ))
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let escalated = fetch_challenge(&router).await;
        assert!(
            escalated.captcha_required,
            "repeated PoW failures from one bucket escalate to a captcha requirement"
        );
    }

    fn sample_envelope(mailbox_id: [u8; 16]) -> Envelope {
        Envelope {
            version: 1,
            mailbox_id: mailbox_id.to_vec(),
            size_bucket: SizeBucket::B1kb as i32,
            ciphertext: vec![0x42; 1024],
            envelope_id: vec![],
        }
    }

    fn to_hex(bytes: &[u8; 16]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[tokio::test]
    async fn deliver_fetch_and_ack_round_trip_through_the_http_surface() {
        let state = test_state();
        let router = router(state.clone());
        let mailbox_id = [9u8; 16];

        let deliver_request = Request::builder()
            .method("POST")
            .uri("/v1/deliver")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(sample_envelope(mailbox_id).encode_to_vec()))
            .unwrap();
        let response = router.clone().oneshot(deliver_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let fetch_request = Request::builder()
            .method("GET")
            .uri(format!("/v1/mailbox/{}", to_hex(&mailbox_id)))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(fetch_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let fetched: MailboxEnvelopes = decode(response).await;
        assert_eq!(fetched.envelopes.len(), 1);
        let envelope_id = fetched.envelopes[0].envelope_id.clone();
        assert_eq!(
            envelope_id.len(),
            16,
            "delivery assigned a real envelope_id"
        );

        let ack_request = Request::builder()
            .method("POST")
            .uri(format!("/v1/mailbox/{}/ack", to_hex(&mailbox_id)))
            .header("content-type", "application/x-protobuf")
            .body(Body::from(
                AckRequest {
                    envelope_ids: vec![envelope_id],
                }
                .encode_to_vec(),
            ))
            .unwrap();
        let response = router.clone().oneshot(ack_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let refetch_request = Request::builder()
            .method("GET")
            .uri(format!("/v1/mailbox/{}", to_hex(&mailbox_id)))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(refetch_request).await.unwrap();
        let refetched: MailboxEnvelopes = decode(response).await;
        assert!(
            refetched.envelopes.is_empty(),
            "acked envelope is deleted, not just marked"
        );
    }

    #[tokio::test]
    async fn deliver_rejects_a_ciphertext_length_that_does_not_match_its_size_bucket() {
        let state = test_state();
        let router = router(state.clone());

        let mut envelope = sample_envelope([1u8; 16]);
        envelope.ciphertext = vec![0; 999]; // not any bucket's exact size

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deliver")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(envelope.encode_to_vec()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn deliver_rejects_an_unspecified_size_bucket() {
        let state = test_state();
        let router = router(state.clone());

        let mut envelope = sample_envelope([1u8; 16]);
        envelope.size_bucket = SizeBucket::Unspecified as i32;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deliver")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(envelope.encode_to_vec()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn deliver_rejects_a_mailbox_id_that_is_not_sixteen_bytes() {
        let state = test_state();
        let router = router(state.clone());

        let mut envelope = sample_envelope([1u8; 16]);
        envelope.mailbox_id = vec![0xAB; 4]; // too short

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deliver")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(envelope.encode_to_vec()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn deliver_overwrites_a_sender_supplied_envelope_id_end_to_end() {
        let state = test_state();
        let router = router(state.clone());
        let mailbox_id = [3u8; 16];

        let mut envelope = sample_envelope(mailbox_id);
        envelope.envelope_id = vec![0xFF; 16];

        let request = Request::builder()
            .method("POST")
            .uri("/v1/deliver")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(envelope.encode_to_vec()))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::ACCEPTED
        );

        let fetch_request = Request::builder()
            .method("GET")
            .uri(format!("/v1/mailbox/{}", to_hex(&mailbox_id)))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(fetch_request).await.unwrap();
        let fetched: MailboxEnvelopes = decode(response).await;

        assert_eq!(fetched.envelopes.len(), 1);
        assert_eq!(fetched.envelopes[0].envelope_id.len(), 16);
        assert_ne!(
            fetched.envelopes[0].envelope_id,
            vec![0xFF; 16],
            "the client-supplied envelope_id must not survive the wire round trip"
        );
    }

    #[tokio::test]
    async fn fetch_and_ack_reject_a_malformed_mailbox_id_path_segment() {
        let state = test_state();
        let router = router(state.clone());

        for uri in [
            "/v1/mailbox/not-hex-at-all-xxxxxxxxxxxxxxxx".to_string(),
            "/v1/mailbox/abcd".to_string(), // too short
        ] {
            let request = Request::builder()
                .method("GET")
                .uri(uri.clone())
                .body(Body::empty())
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "GET {uri} should reject a malformed mailbox_id"
            );
        }

        let ack_request = Request::builder()
            .method("POST")
            .uri("/v1/mailbox/zz/ack")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(AckRequest::default().encode_to_vec()))
            .unwrap();
        let response = router.clone().oneshot(ack_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let ws_request = Request::builder()
            .method("GET")
            .uri("/v1/mailbox/zz/ws")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(ws_request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "a malformed mailbox_id is rejected before any WebSocket upgrade is attempted"
        );
    }

    #[tokio::test]
    async fn mailbox_id_hex_parsing_is_case_insensitive() {
        let state = test_state();
        let router = router(state.clone());
        let mailbox_id = [0xABu8; 16];

        let deliver_request = Request::builder()
            .method("POST")
            .uri("/v1/deliver")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(sample_envelope(mailbox_id).encode_to_vec()))
            .unwrap();
        assert_eq!(
            router
                .clone()
                .oneshot(deliver_request)
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );

        let uppercase_hex: String = to_hex(&mailbox_id).to_uppercase();
        let fetch_request = Request::builder()
            .method("GET")
            .uri(format!("/v1/mailbox/{uppercase_hex}"))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(fetch_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let fetched: MailboxEnvelopes = decode(response).await;
        assert_eq!(fetched.envelopes.len(), 1);
    }

    #[tokio::test]
    async fn ack_rejects_an_envelope_id_that_is_not_sixteen_bytes() {
        let state = test_state();
        let router = router(state.clone());
        let mailbox_id = [5u8; 16];

        let ack_request = Request::builder()
            .method("POST")
            .uri(format!("/v1/mailbox/{}/ack", to_hex(&mailbox_id)))
            .header("content-type", "application/x-protobuf")
            .body(Body::from(
                AckRequest {
                    envelope_ids: vec![vec![0x01, 0x02, 0x03]],
                }
                .encode_to_vec(),
            ))
            .unwrap();
        let response = router.clone().oneshot(ack_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn two_registered_accounts_exchange_an_envelope_through_registration_and_delivery() {
        // The Phase 1 exit criterion end to end at the API layer: alice
        // learns bob's mailbox_id from his prekey bundle (docs/03 "session
        // establishment"), addresses an envelope to it, and bob retrieves
        // and acks it (docs/09 "deliver and delete"). Actual E2EE content
        // is cue-core's job; this proves the two Node-side halves wire
        // together correctly.
        let state = test_state();
        let router = router(state.clone());

        let _alice = register_one(&router, &state).await;
        let bob = register_one(&router, &state).await;

        let bundle_request = Request::builder()
            .method("GET")
            .uri(format!("/v1/accounts/{}/prekey-bundle", bob.handle))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(bundle_request).await.unwrap();
        let bundle: PrekeyBundleResponse = decode(response).await;
        assert_eq!(
            bundle.mailbox_id.len(),
            16,
            "bundle carries a routable mailbox_id"
        );

        let mailbox_id: [u8; 16] = bundle.mailbox_id.clone().try_into().unwrap();
        let deliver_request = Request::builder()
            .method("POST")
            .uri("/v1/deliver")
            .header("content-type", "application/x-protobuf")
            .body(Body::from(sample_envelope(mailbox_id).encode_to_vec()))
            .unwrap();
        assert_eq!(
            router
                .clone()
                .oneshot(deliver_request)
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );

        let fetch_request = Request::builder()
            .method("GET")
            .uri(format!("/v1/mailbox/{}", to_hex(&mailbox_id)))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(fetch_request).await.unwrap();
        let fetched: MailboxEnvelopes = decode(response).await;
        assert_eq!(fetched.envelopes.len(), 1);
        assert_eq!(fetched.envelopes[0].ciphertext, vec![0x42; 1024]);

        let ack_request = Request::builder()
            .method("POST")
            .uri(format!("/v1/mailbox/{}/ack", to_hex(&mailbox_id)))
            .header("content-type", "application/x-protobuf")
            .body(Body::from(
                AckRequest {
                    envelope_ids: vec![fetched.envelopes[0].envelope_id.clone()],
                }
                .encode_to_vec(),
            ))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(ack_request).await.unwrap().status(),
            StatusCode::OK
        );

        let refetch_request = Request::builder()
            .method("GET")
            .uri(format!("/v1/mailbox/{}", to_hex(&mailbox_id)))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(refetch_request).await.unwrap();
        let refetched: MailboxEnvelopes = decode(response).await;
        assert!(
            refetched.envelopes.is_empty(),
            "bob's ack deleted it on the Node"
        );
    }

    #[tokio::test]
    async fn mailbox_websocket_flushes_queued_envelopes_then_pushes_live_ones_and_honours_acks() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let state = test_state();
        let mailbox_id_bytes = [42u8; 16];
        let mailbox_id = MailboxId::from_bytes(mailbox_id_bytes);

        // Queued before the socket ever connects.
        let queued_id = state
            .mailboxes
            .enqueue(mailbox_id, sample_envelope(mailbox_id_bytes));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        let url = format!("ws://{}/v1/mailbox/{}/ws", addr, to_hex(&mailbox_id_bytes));
        let (mut ws, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("websocket connects");

        let flushed = ws.next().await.expect("stream open").expect("no error");
        let WsMessage::Binary(bytes) = flushed else {
            panic!("expected a binary frame for the queued envelope")
        };
        let envelope = Envelope::decode(bytes.as_ref()).expect("valid envelope");
        assert_eq!(
            envelope.envelope_id,
            queued_id.as_bytes().to_vec(),
            "already-queued envelope is flushed on connect"
        );

        // Live push after the socket is already connected.
        let live_id = state
            .mailboxes
            .enqueue(mailbox_id, sample_envelope(mailbox_id_bytes));
        let pushed = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("live push arrives before the timeout")
            .expect("stream open")
            .expect("no error");
        let WsMessage::Binary(bytes) = pushed else {
            panic!("expected a binary frame for the live envelope")
        };
        let envelope = Envelope::decode(bytes.as_ref()).expect("valid envelope");
        assert_eq!(envelope.envelope_id, live_id.as_bytes().to_vec());

        // Acking over the socket deletes from the store, same as the REST ack.
        ws.send(WsMessage::Binary(queued_id.as_bytes().to_vec().into()))
            .await
            .expect("send ack frame");
        tokio::time::sleep(Duration::from_millis(200)).await;

        let remaining = state.mailboxes.fetch(&mailbox_id);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].envelope_id, live_id.as_bytes().to_vec());
    }

    #[tokio::test]
    async fn mailbox_websocket_ignores_a_malformed_ack_frame_and_keeps_streaming() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let state = test_state();
        let mailbox_id_bytes = [11u8; 16];
        let mailbox_id = MailboxId::from_bytes(mailbox_id_bytes);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        let url = format!("ws://{}/v1/mailbox/{}/ws", addr, to_hex(&mailbox_id_bytes));
        let (mut ws, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("websocket connects");

        // Neither a text frame nor a too-short binary frame is a valid ack;
        // the connection must survive both rather than dropping.
        ws.send(WsMessage::Text("not an envelope_id".into()))
            .await
            .expect("send text frame");
        ws.send(WsMessage::Binary(vec![0x01, 0x02].into()))
            .await
            .expect("send undersized binary frame");

        let live_id = state
            .mailboxes
            .enqueue(mailbox_id, sample_envelope(mailbox_id_bytes));
        let pushed = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("connection still alive and delivers the live push")
            .expect("stream open")
            .expect("no error");
        let WsMessage::Binary(bytes) = pushed else {
            panic!("expected a binary frame for the live envelope")
        };
        let envelope = Envelope::decode(bytes.as_ref()).expect("valid envelope");
        assert_eq!(envelope.envelope_id, live_id.as_bytes().to_vec());
    }

    #[tokio::test]
    async fn mailbox_websocket_fans_out_a_live_envelope_to_every_connected_device() {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let state = test_state();
        let mailbox_id_bytes = [77u8; 16];
        let mailbox_id = MailboxId::from_bytes(mailbox_id_bytes);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        let url = format!("ws://{}/v1/mailbox/{}/ws", addr, to_hex(&mailbox_id_bytes));
        let (mut first_device, _) = tokio_tungstenite::connect_async(url.clone())
            .await
            .expect("first device connects");
        let (mut second_device, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("second device connects");

        // Give both sockets a moment to complete their subscribe() before
        // the live push, since subscribing is what makes fan-out possible.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let pushed_id = state
            .mailboxes
            .enqueue(mailbox_id, sample_envelope(mailbox_id_bytes));

        for device in [&mut first_device, &mut second_device] {
            let received = tokio::time::timeout(Duration::from_secs(2), device.next())
                .await
                .expect("each connected device receives the fan-out")
                .expect("stream open")
                .expect("no error");
            let WsMessage::Binary(bytes) = received else {
                panic!("expected a binary frame")
            };
            let envelope = Envelope::decode(bytes.as_ref()).expect("valid envelope");
            assert_eq!(envelope.envelope_id, pushed_id.as_bytes().to_vec());
        }
    }
}
