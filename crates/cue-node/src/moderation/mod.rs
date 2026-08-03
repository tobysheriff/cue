//! Reports, franking verification, moderation queues, audit log (docs/08,
//! docs/05). Franking must stay "not retroactive": the Node learns content
//! only for messages actually reported, never proactively. `mod_audit` is
//! append-only by design — moderator actions must be attributable, even to
//! the operator.
