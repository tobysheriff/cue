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
use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use cue_crypto::sessions::PublicKey;
use cue_proto::v1::{
    OneTimePrekey, PrekeyBundleResponse, RegisterRequest, RegisterResponse, RegistrationChallenge,
    RerollHandleRequest, RerollHandleResponse, SignedPrekey,
};

use crate::accounts::handle::{self, Handle, FREE_REROLLS_AT_SIGNUP};
use crate::accounts::pow::{ChallengeId, PowChallengeStore};
use crate::accounts::store::{
    current_week, AccountId, AccountRecord, AccountStore, DeviceRecord, OneTimePrekeyRecord,
    SignedPrekeyRecord as StoredSignedPrekey, StoreError,
};
use crate::accounts::trust::TrustLevel;
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
    config: RegistrationConfig,
}

impl AppState {
    pub fn new(
        accounts: Box<dyn AccountStore>,
        captcha: Box<dyn CaptchaVerifier>,
        config: RegistrationConfig,
    ) -> Self {
        Self {
            ingress_secret: RotatingSecret::new(),
            reputation: ReputationTable::default(),
            pow: PowChallengeStore::new(config.argon2_params.clone(), config.challenge_ttl),
            pending: Mutex::new(HashMap::new()),
            accounts,
            captcha,
            config,
        }
    }
}

pub fn router(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/register/challenge", post(register_challenge))
        .route("/v1/register", post(register))
        .route("/v1/register/reroll", post(reroll_handle))
        .route("/v1/accounts/{handle}/prekey-bundle", get(prekey_bundle))
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
    }))
}

fn signed_prekey_to_wire(record: &StoredSignedPrekey) -> SignedPrekey {
    SignedPrekey {
        id: record.id,
        public_key: record.public_key.clone(),
        signature: record.signature.clone(),
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
}
