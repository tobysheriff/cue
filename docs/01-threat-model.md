# 01 — Threat Model

A protection you can't name an adversary for is decoration. This document names them.

## Assets, ranked

1. **Message content** — what was said.
2. **Social graph** — who talks to whom, and when. In practice this is more damaging than
   content; it is also far harder to protect, which is why most messengers quietly don't.
3. **Identity linkage** — the mapping between a Cue handle and a real person (via IP,
   payment, device, behaviour, or timing).
4. **Group and Hall membership** — which encrypted groups an account belongs to.
5. **Existence of an account** — whether a given person uses Cue at all.
6. **Availability** — the service functioning.

## Adversaries

### A1 — Passive network observer (ISP, coffee-shop Wi-Fi, national backbone tap)
**Capability:** sees the client's IP, packet sizes, and timing; sees that the client is
talking to a Cue server.
**Mitigated:** content (TLS 1.3 + E2EE), message sizes (fixed-size padded envelopes),
message counts and burst patterns in high-security mode (cover traffic, batching).
**Not mitigated in default mode:** the fact that you use Cue, and coarse activity timing.
Cue's transport is designed to be indistinguishable from generic HTTP/3, but a determined
national observer with the server's IP can see you connect to it.
**User remedy:** high-security transport tier, onion routing, or a VPN.

### A2 — The server operator (including me), acting in good faith but compromised or coerced
**Capability:** full read/write on server storage, memory, and network; can modify
deployed server code.
**Mitigated:** message content (E2EE — server holds no keys); sender identity on
individual messages (sealed sender); encrypted group membership (anonymous credentials);
identity-to-IP linkage (IP-blind ingress + unlinkable auth tokens); silent key
substitution (key transparency log with third-party auditors).
**Not mitigated:** public Hall content (by design — that's the deal), delivery timing
against a specific targeted mailbox, and denial of service. A malicious server can always
refuse to deliver.
**Note:** a *modified* server can log more than the shipped one does. This is why the
protections that matter live in the client and the cryptography, not in server policy.
Server policy ("we don't log IPs") is a promise; sealed sender is a proof.

### A3 — Law enforcement with valid legal process
**Capability:** compels the operator to hand over everything held, and possibly to not
disclose it.
**Mitigated:** by holding almost nothing. The honest answer to a subpoena should be a
short list: an opaque account identifier, its registration date bucket, and its public
keys. No IPs, no contacts, no message history, no group memberships.
**Not mitigated:** compelled future action (targeted logging, malicious updates to a
specific user). Countered by transparency reports, a warrant canary, reproducible builds,
and — most importantly — clients that verify what they run.

### A4 — Server seizure or hosting-provider compromise
**Capability:** offline access to all disks; possibly memory capture of a running host.
**Mitigated:** deliver-and-delete means the message queue holds only in-flight ciphertext;
full-disk encryption; no IP logs; ephemeral state (rate-limit counters, presence, IP
reputation) kept in memory or in a store with persistence disabled.
**Not mitigated:** a live host captured with RAM intact leaks current connection state.
Documented, not solved.

### A5 — Another user (harassment, spam, scraping, social engineering)
**Capability:** creates accounts, sends messages, joins Halls, tries to enumerate users
or map the social graph.
**Mitigated:** proof-of-work registration + IP-reputation-triggered CAPTCHA (`docs/02`),
message-request gating for strangers, blocking, rate-limited handle lookup to resist
enumeration, verifiable reporting via message franking, per-Node moderator teams.
**Not mitigated:** a motivated individual with time. Anonymity helps them too. This is the
honest cost of the identity model.

### A6 — Endpoint compromise (malware, forensic device seizure, coerced unlock)
**Capability:** everything the user can see.
**Mitigated:** encrypted local database (SQLCipher, Argon2id-derived key), OS keychain for
key material, forward secrecy so past messages can't be decrypted from a stolen current
key, ephemerality so there's usually little history to seize, hardened Electron
configuration (`docs/06`).
**Not mitigated:** live compromise, keyloggers, screen capture, or an unlocked device.
Nothing at this layer can. Cue will not claim otherwise, will not offer a fake "hidden
chat" feature, and will not implement screenshot detection as if it were a security
control (it isn't — see `docs/09`).

### A7 — Global passive adversary correlating traffic across the whole network
**Capability:** observes every link simultaneously; correlates timing and volume.
**Mitigated:** only in high-security mode, and only partially — constant-rate cover
traffic and batched random-delay delivery raise the cost substantially.
**Not mitigated in default mode.** Stated plainly in the docs and in the app's security
settings screen. Full protection requires a mixnet and the latency budget that implies;
`docs/04` sketches the path but v1 does not claim it.

### A8 — Malicious or hostile Cue server (someone else's Node)
**Capability:** everything A2 has, against its own users, without good faith.
**Mitigated:** the client's security does not depend on the server being honest. Key
transparency detects key substitution; safety-number verification detects MITM; the client
enforces protocol invariants rather than trusting server assertions.
**Not mitigated:** metadata visible to any server about its own users (connection times,
mailbox activity). Choosing a server is a trust decision; the client says so at signup.

## Explicit non-protections

Written down so nobody is surprised later:

- Cue does not hide **that you use Cue** from your network operator in default mode.
- Cue does not protect **public Hall content** from the operator or from Hall moderators.
- Cue does not prevent your **conversation partner** from screenshotting, recording, or
  reporting a message. Mutual-save makes retention *visible*, not impossible.
- Cue does not protect against **compelled disclosure by the user** (rubber-hose, border
  search, coerced unlock). There is no duress PIN in v1; fake-unlock features usually
  endanger the people who rely on them.
- Cue does not defend a user from **their own device** being backdoored.
- Cue does not guarantee **availability**. A blocked or seized Node is a dead Node
  for its users; self-hosting is the answer, not the operator's promises.

## Security process

- Threat model is a living document, reviewed at every phase boundary in `docs/11`.
- Every protocol change requires an ADR referencing which adversary it addresses.
- External cryptographic audit before 1.0, scoped to protocol + implementation, published
  in full including findings we chose not to fix and why.
- Reproducible builds for server and clients; release artefacts signed; build verification
  documented so third parties can confirm the binary matches the source.
- Coordinated disclosure policy with a published PGP key and a target response time.
- No telemetry, no crash reporting to a third party, no analytics SDKs — not "anonymised",
  not "aggregate". Opt-in local diagnostic export the user can read and send manually.
