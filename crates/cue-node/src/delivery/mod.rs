//! Mailboxes, queues, fan-out, batching, Quiet Mode ticks (docs/05, docs/09
//! "deliver and delete"). An envelope must be deleted on delivery ack, full
//! stop; undelivered envelopes expire at a hard 30-day TTL. This module
//! must never grow a durable archive or a queue backup — `docs/05` singles
//! out `envelopes` as the one table backup tooling must refuse to include.
