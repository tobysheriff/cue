//! The Cue Node server binary (docs/05).
//!
//! Design constraints, in priority order: forget by default, operable by
//! one person, readable by an auditor who doesn't trust us, boring
//! dependencies. Every module below carries a doc comment stating what it
//! must never do — that comment is a security control, not decoration.

#![forbid(unsafe_code)]

mod accounts;
mod admin;
mod auth;
mod blobs;
mod delivery;
mod halls;
mod ingress;
mod mls_ds;
mod moderation;
mod policy;

fn main() {
    todo!(
        "cue-node has no runtime yet — Phase 1 (docs/11) wires ingress, \
         accounts, and delivery into an axum server. This binary exists so \
         the workspace builds end to end from the first commit."
    );
}
