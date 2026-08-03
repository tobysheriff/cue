//! The Cue Node server binary (docs/05).
//!
//! Design constraints, in priority order: forget by default, operable by
//! one person, readable by an auditor who doesn't trust us, boring
//! dependencies. Every module below carries a doc comment stating what it
//! must never do — that comment is a security control, not decoration.

#![forbid(unsafe_code)]

mod accounts;
mod admin;
mod api;
mod auth;
mod blobs;
mod delivery;
mod halls;
mod ingress;
mod mls_ds;
mod moderation;
mod policy;

use std::net::SocketAddr;
use std::sync::Arc;

use accounts::store::InMemoryAccountStore;
use api::{AppState, NullCaptchaVerifier, RegistrationConfig};

#[tokio::main]
async fn main() {
    // In-memory only, matching cue-crypto::sessions's own starting point —
    // a Postgres-backed AccountStore is the natural next step (docs/05),
    // and NullCaptchaVerifier is a placeholder for a real provider
    // (hCaptcha/Turnstile) that Phase 1's registration slice doesn't wire in.
    let state = Arc::new(AppState::new(
        Box::new(InMemoryAccountStore::new()),
        Box::new(NullCaptchaVerifier),
        RegistrationConfig::default(),
    ));

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
