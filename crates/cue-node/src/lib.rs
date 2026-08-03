//! The Cue Node (docs/05).
//!
//! Design constraints, in priority order: forget by default, operable by
//! one person, readable by an auditor who doesn't trust us, boring
//! dependencies. Every module below carries a doc comment stating what it
//! must never do — that comment is a security control, not decoration.
//!
//! Split into a library and a thin `main.rs` binary so integration tests
//! outside this crate (`cue-testkit`'s two-clients-plus-Node test, docs/11
//! Phase 1 exit criterion) can drive a real [`api::router`] over a real
//! socket, the same way `api::tests` already does in-process.

#![forbid(unsafe_code)]

pub mod accounts;
mod admin;
pub mod api;
mod auth;
mod blobs;
pub mod delivery;
mod halls;
mod ingress;
mod mls_ds;
mod moderation;
mod policy;
