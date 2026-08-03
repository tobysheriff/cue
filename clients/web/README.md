# Web shell (WASM)

Not started. Lands in Phase 4 (`docs/11-roadmap.md`) as a Rust→WASM PWA
around `cue-core` (bound via `wasm-bindgen`,
`docs/06-client-architecture.md`, [ADR-0007](../../docs/adr/0007-rust-core-clients.md)).

Materially less secure than the desktop shell (IndexedDB key storage, no
verifiable code delivery) — the client must say so in a persistent,
non-dismissible notice, per `docs/06`. That notice is part of the feature,
not a nice-to-have to add later.

Licensed GPL-3.0-or-later, see [`/LICENSE-GPL-3.0`](../../LICENSE-GPL-3.0).
