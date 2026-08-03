# 06 — Client Architecture

One protocol implementation in Rust, two shells around it now, and a binding path for
mobile later. The crypto is never written twice.

```
        ┌─────────────────────────────────────────┐
        │             cue-core (Rust)             │
        │  sessions · ratchets · MLS · KT · store  │
        │  transport · padding · cover traffic     │
        └────────────┬───────────────┬─────────────┘
                     │ NAPI-RS       │ wasm-bindgen
              ┌──────┴──────┐  ┌─────┴──────┐   (future: UniFFI)
              │  Electron   │  │    Web     │ ──► iOS / Android
              └─────────────┘  └────────────┘
```

## cue-core

Everything security-relevant lives here. The UI layer is deliberately dumb: it can render,
it can call commands, it cannot make a cryptographic decision.

Responsibilities:
- Session management (Double Ratchet, MLS group state, prekey replenishment)
- Key transparency verification — inclusion and consistency proofs, auditor gossip
- Local encrypted store (SQLCipher), ephemerality timers, mutual-save state
- Transport: connection management, padding buckets, cover traffic scheduler, Tor via `arti`
- Anonymous credential lifecycle (batch fetch, spend, rotation)
- Franking commitments and report bundle construction
- Protocol validation — the client, not the server, enforces invariants

Interface: a command/event API (`Command` in, `Event` stream out) rather than a
request/response RPC surface. This keeps the boundary narrow and auditable, and means the
shells can't reach into crypto state. All types are `#[non_exhaustive]` and versioned.

**Threading:** core owns a Tokio runtime; shells communicate over channels. No blocking
calls across the FFI boundary.

**Testing:** the core is testable headlessly, which is the point. Two clients + a Node in
one integration test, scripted conversations, deterministic-seed fuzzing of the wire
parser, and a protocol conformance suite in `cue-testkit` that any future client must pass.

## Desktop shell — Electron

Electron is the pragmatic choice (one UI codebase, three platforms, good notification and
tray integration) and it is also the largest attack surface in the project. It gets treated
as hostile:

**Hardening — non-negotiable, enforced in CI:**

| Setting | Value |
|---|---|
| `nodeIntegration` | `false` |
| `contextIsolation` | `true` |
| `sandbox` | `true` |
| `webSecurity` | `true` |
| `allowRunningInsecureContent` | `false` |
| Remote module | Disabled |
| Preload | Minimal, typed, allow-listed IPC only |
| CSP | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:` — no `unsafe-inline`, no remote origins |
| Navigation | `will-navigate` and `setWindowOpenHandler` deny everything; external links open in the OS browser after an explicit confirm |
| ASAR integrity | Enabled (macOS/Windows) |
| Renderer network access | **None.** All network I/O happens in the Rust core in the main process. The renderer cannot make a request. |

**Why that last row matters most:** a renderer XSS in a normal Electron app is game over.
Here, the renderer has no network, no Node, no filesystem, and no keys — it can render a
malicious message badly, and that's the extent of it.

Additional:
- No remote content of any kind. No link previews fetched by the client (a link preview is
  a request to an attacker-chosen server the moment a message arrives — Cue generates
  previews **sender-side** and sends them as part of the encrypted message, or not at all).
- No remote fonts, no analytics, no auto-loading remote images. Attachments render from
  the local decrypted blob only.
- Electron version pinned and updated promptly; a stale Chromium is the realistic CVE path.
- Auto-update over a signed, verified channel with a published update key, reproducible
  builds, and no silent update-server-chosen behaviour.

**UI stack:** TypeScript + React (or Svelte) with strict CSP compatibility, no runtime CSS
-in-JS that requires `unsafe-inline`. Markdown rendering through a hardened, allow-list
sanitiser; no raw HTML from messages, ever.

## Web shell

Rust → WASM, running as an installable PWA. Shipped because it removes the install barrier
and because it works where installing software is dangerous or impossible.

It is also **materially less secure**, and Cue says so in the UI rather than hiding it:
- Key material lives in IndexedDB (non-extractable WebCrypto keys where possible), which is
  weaker than an OS keychain and vulnerable to XSS in a way the Electron design isn't.
- The user cannot verify what code the server sent them today. Mitigations: subresource
  integrity, a published build hash the user can check, and — Phase 5 — a binary
  transparency log for web builds so a targeted malicious bundle is detectable.
- No reliable background delivery; messages arrive when the tab is open.

The web client shows a persistent, non-dismissible notice explaining these limits and
recommending the desktop app for anyone whose threat model includes a targeted adversary.
It defaults to a shorter local-retention window.

## Node selection and branding

The first screen is Node selection, not registration:

```
┌──────────────────────────────────────────────┐
│  Where should your account live?             │
│                                              │
│  ● Cue           cue.example                 │
│    Default · Iceland · Open registration     │
│    Groups up to 20 · 4 moderators · Onion ✓  │
│                                              │
│  ○ Enter another Node…                       │
│                                              │
│  Your Node relays your messages. It can      │
│  never read them, but it does know when      │
│  you're connected. Pick one you trust,       │
│  or run your own.                            │
└──────────────────────────────────────────────┘
```

The card is populated from the Node's public capability descriptor (`docs/05`):
jurisdiction, registration mode, group cap, whether it has moderators, retention policy,
onion availability, terms link.

**Branding is sandboxed.** A Node supplies a logo, accent colour, wordmark, and welcome
text. Those theme the Node card, registration flow, and Node info screen. They **cannot**
touch: the encryption tier indicators, the Hall/private visual distinction, safety-number
warnings, or any security-relevant chrome. A hostile operator must not be able to make an
unencrypted Hall look like an encrypted conversation, and the client enforces that by
simply not exposing those surfaces to Node styling.

## The two-tier visual language

The most important UI work in the project. Encrypted and public spaces must be
distinguishable at a glance, half-asleep, on a small screen:

- **Private (encrypted):** dark, calm surface; a closed-lock glyph in the header; message
  bubbles in the accent colour; an ephemerality countdown on messages.
- **Halls (public):** visibly different surface treatment (lighter/tinted), an open-lock
  glyph, a persistent header strip reading *"Public Hall — the Node and its moderators can
  read this"*, and different bubble geometry entirely.
- Joining a Hall shows a one-time interstitial stating what's visible to whom, requiring an
  explicit acknowledgement.
- Composing in a Hall for the first time in a session shows an inline reminder above the
  composer.

Nobody should ever have to *check* which mode they're in.

## Local storage and ephemerality

- SQLCipher DB, key in the OS keychain, optional app-lock passphrase (Argon2id) that also
  gates the keychain entry.
- Ephemerality timers run in core, not in the UI: expiry is enforced even if the app is
  closed, and expired rows are securely removed on next launch.
- Optional local-only search over what remains — the index is inside the encrypted DB.
- "Panic wipe": a keyboard shortcut and a menu item that destroys the local database and
  keys immediately, with a confirmation. Documented as *local* only — it cannot unsend, and
  the docs will not imply otherwise.

## Accessibility and internationalisation

Not decoration: this project's users include people for whom the tool must work under
stress, on old hardware, in their own language.
- Full keyboard navigation, screen-reader labels on every security indicator (an
  encryption state that's only conveyed by colour is a bug), WCAG AA contrast minimum.
- The two-tier distinction must survive colour-blindness — hence glyph + geometry + text,
  not just colour.
- i18n from the first release; RTL layout support; translations community-managed with a
  review process, because a mistranslated security warning is a security bug.
