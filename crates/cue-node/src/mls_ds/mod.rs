//! MLS Delivery Service: ordering and fan-out of handshake and application
//! messages (docs/03 "Encrypted groups", docs/05). Must never learn a
//! group's member list — it orders and relays ciphertext only, and
//! enforces the membership cap by counting ratchet-tree leaves in the
//! commit structure, not by reading who's in the group.
