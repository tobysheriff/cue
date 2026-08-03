//! Operator and moderator API (docs/05). Every action taken here that
//! touches user data must be written to `moderation`'s append-only audit
//! log — an operator acting outside the audit trail is exactly the
//! unaccountable-operator scenario the rest of the Node is designed
//! against.
