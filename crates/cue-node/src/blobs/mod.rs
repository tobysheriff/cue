//! Attachment upload/download, quota, garbage collection (docs/05, docs/09
//! "Attachments"). Blobs are opaque ciphertext to this module — metadata
//! stripping happens client-side before upload, never here. Garbage
//! collected when the owning message expires, and at a 30-day hard TTL
//! regardless.
