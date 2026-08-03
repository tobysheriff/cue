//! The Cue Node server binary entry point — see `lib.rs` for the crate's
//! own design constraints and module map.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use cue_node::accounts::store::InMemoryAccountStore;
use cue_node::api::{self, AppState, NullCaptchaVerifier, RegistrationConfig};
use cue_node::delivery::mailbox::InMemoryMailboxStore;

#[tokio::main]
async fn main() {
    // In-memory only, matching cue-crypto::sessions's own starting point —
    // a Postgres-backed AccountStore is the natural next step (docs/05),
    // and NullCaptchaVerifier is a placeholder for a real provider
    // (hCaptcha/Turnstile) that Phase 1's registration slice doesn't wire in.
    let state = Arc::new(AppState::new(
        Box::new(InMemoryAccountStore::new()),
        Box::new(NullCaptchaVerifier),
        Box::new(InMemoryMailboxStore::new()),
        RegistrationConfig::default(),
    ));

    // Undelivered envelopes get a hard 30-day TTL, not indefinite storage
    // (docs/09 "deliver and delete") — this is what enforces that in the
    // absence of a database TTL/cron job.
    tokio::spawn({
        let state = state.clone();
        async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
            loop {
                ticker.tick().await;
                let dropped = state.sweep_expired_envelopes();
                if dropped > 0 {
                    tracing::debug!(dropped, "swept expired envelopes");
                }
            }
        }
    });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443")
        .await
        .expect("bind registration listener");
    tracing::info!(
        addr = %listener.local_addr().expect("listener has a local address"),
        "cue-node listening"
    );

    axum::serve(
        listener,
        api::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("axum server error");
}
