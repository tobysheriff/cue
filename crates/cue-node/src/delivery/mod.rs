//! Mailboxes, queues, fan-out, batching, Quiet Mode ticks (docs/05, docs/09
//! "deliver and delete"). An envelope must be deleted on delivery ack, full
//! stop; undelivered envelopes expire at a hard 30-day TTL. This module
//! must never grow a durable archive or a queue backup — `docs/05` singles
//! out `envelopes` as the one table backup tooling must refuse to include.
//!
//! `mailbox` is the pure queue: keyed by opaque [`mailbox::MailboxId`]
//! alone, with no knowledge of `accounts`. Batching and Quiet Mode ticks
//! are Phase 3+ (`docs/11`); this Phase 1 slice fans out immediately to
//! whatever's subscribed and otherwise just holds the queue.

pub mod mailbox;
