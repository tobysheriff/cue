# Desktop shell (Electron)

Not started. Lands in Phase 1 (`docs/11-roadmap.md`) as a minimal Electron
shell around `cue-core` (bound via NAPI-RS, `docs/06-client-architecture.md`,
[ADR-0007](../../docs/adr/0007-rust-core-clients.md)): register, add contact
by handle, send/receive text.

The Electron hardening checklist in `docs/06` (context isolation, no renderer
network access, strict CSP, no remote content) is **non-negotiable and
CI-enforced** once this shell exists — it is not a follow-up task.

Licensed GPL-3.0-or-later, see [`/LICENSE-GPL-3.0`](../../LICENSE-GPL-3.0).
