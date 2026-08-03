# 04 — Metadata Resistance

You asked for full metadata resistance: cover traffic, padding, timing decorrelation, and
private discovery. This document takes that seriously — and is honest that the strongest
techniques carry costs that make them wrong to force on every user by default.

**The structure:** a mandatory floor that every Cue client always does, and a **Quiet Mode**
tier that adds the expensive protections for users who need them. Both are described here;
what's in each, and why the line is drawn where it is, is the substance of this document.

## Why not just make everything maximal?

Constant-rate cover traffic at a rate high enough to hide real conversation costs roughly
50–200 MB/day and meaningfully drains a battery. On a laptop that's invisible; on a phone
over cellular it is not, and a privacy tool that flattens the battery gets uninstalled,
which protects nobody. Worse, a *rare* protection is a fingerprint: if 200 users out of
50,000 run cover traffic, that traffic pattern identifies them as the interesting 0.4%.

So the floor must be genuinely strong on its own, Quiet Mode must be presented as a
*context* choice rather than a paranoia dial, and the design must aim for enough Quiet Mode
adoption that its users aren't a distinguishable minority. This is a real unsolved tension
and it is tracked in `docs/12`.

---

## The mandatory floor — always on, no setting

### 1. Fixed-size padded envelopes
Every message is padded to the next size bucket before encryption: **1 KB, 4 KB, 16 KB,
64 KB**. Anything larger becomes an attachment (separate encrypted blob, uploaded through
a different path, fetched at a decorrelated time). Padding is inside the AEAD, so the
observer sees only the bucket, and the buckets are coarse enough that "short reply" vs
"long paragraph" is indistinguishable.

Typing indicators, read receipts, presence, and delivery acknowledgements are padded to
the same 1 KB bucket as a short message. Otherwise they leak conversation rhythm perfectly.

### 2. Sealed sender
The envelope's sender field is encrypted to the recipient. The Node routes on an opaque
**mailbox ID** only. Combined with anonymous delivery credentials (below), the Node
authorises a send without learning who sent it.

### 3. Rotating mailbox identifiers
A device's mailbox ID is not static. It rotates on an epoch schedule (default 24h) using a
value derived from a secret shared with the account's contacts, so long-term observation of
"mailbox X receives messages" cannot be stitched into a lifetime activity profile. Contacts
derive the current epoch's mailbox locally; the Node just sees a new opaque identifier.

### 4. Anonymous authentication credentials
Cue does not authenticate connections with an account identity. Instead:

- Periodically, the client redeems its account credential for a **batch of blind-signed,
  single-use tokens** (Privacy Pass / VOPRF, RFC 9497). The Node signs blinded values and
  cannot link an issued token to the token later spent.
- Issuance happens on a **batch schedule decorrelated from use** — tokens are fetched in
  bulk at randomised times, days before they're spent. Issuing tokens at the moment you
  need one would let the Node correlate issuance with send and defeat the whole thing.
- Rate limits are enforced against token spend rates, not against IPs or accounts. This is
  how Cue keeps abuse limits while being blind to identity.

### 5. IP-blind ingress
The Node's application layer never receives client IPs.

- Ingress terminates TLS at an edge that strips the client address before the request
  reaches the application. The application receives an **ingress bucket token** — an
  HMAC of the IP prefix under a secret that rotates daily and lives only in memory — for
  rate-limiting purposes, never a routable address (see `docs/02`).
- Access logs are **disabled**, not rotated. `nginx`/`envoy` access logging off; no request
  logs at any tier. Error logs scrubbed of addresses at source.
- Strongly recommended for the default Node, planned for Phase 4: an **Oblivious HTTP**
  (RFC 9458) deployment where an independent third party operates the relay. The relay
  sees IPs but not requests; the Node sees requests but not IPs. Collusion is required to
  link them, and the relay operator being genuinely independent of the Node operator is
  the whole point — this is the strongest available answer to "trust me, I don't log".

### 6. No contact upload, ever
Because handles are assigned rather than chosen and there's no phone number, Cue never
needs to match your address book against its user base. The entire private-contact-discovery
problem — the reason Signal built SGX enclaves — simply doesn't exist here. Contacts are
added by explicit handle entry, QR scan, or invite link.

### 7. Encrypted group state
Group membership, names, and roles are encrypted client-side under keys derived from the
group master key; the Node holds ciphertext and authorises operations via zero-knowledge
proofs (`docs/03`). The Node cannot answer "which groups is account X in?" — it has never
had that mapping.

### 8. Attachment decorrelation
Attachments are uploaded to blob storage under an anonymous upload token, keyed and
encrypted independently, and referenced by an opaque ID in the message. Recipients fetch
them after a small randomised delay so upload and download aren't trivially paired.

---

## Quiet Mode — opt-in, per-account, with a plain-language explanation

Presented in the UI not as "paranoid mode" but as a description of a situation: *"Use Quiet
Mode when it matters that nobody can tell you're messaging at all — not just what you
said. Costs more battery and data, and messages may take up to a minute to arrive."*

### 9. Constant-rate cover traffic
The client sends a padded envelope on a fixed schedule whether or not there is a real
message. Real messages take the place of a scheduled cover message. Rates are adaptive to
context, not to secrecy needs:

| Context | Rate | Approx. daily cost |
|---|---|---|
| Desktop, mains power | 1 envelope / 5 s | ~70 MB |
| Desktop, battery | 1 / 30 s | ~12 MB |
| Metered connection | 1 / 120 s | ~3 MB |

The Node also sends cover traffic *down* to connected clients, so an observer cannot infer
"this user is receiving messages" from downstream volume. This is essential and often
forgotten — upstream-only cover traffic protects only half the conversation.

### 10. Timing decorrelation via batched delivery
Messages destined for Quiet Mode recipients are held at the Node and released in batches on
a fixed tick (default 15 s, jitter up to 60 s), so send time and delivery time cannot be
matched by an observer watching both endpoints. This is the single most effective anti-
correlation measure and the reason Quiet Mode has a latency cost.

### 11. Onion transport
The client can route over Tor to a `.onion` service published by the Node, removing
network-level deanonymisation entirely and hiding *that you use Cue* from your ISP. Cue
bundles `arti` (Tor's Rust implementation) rather than requiring a separate Tor install.
The protocol is designed for this: no assumptions about latency, no UDP requirement in the
messaging path, tolerance for connection churn.

### 12. Decoy-resistant presence
In Quiet Mode, typing indicators and read receipts are disabled outright, presence is never
published, and the client fetches on a fixed schedule rather than holding a long-lived
push connection.

---

## What this still does not defeat

Written plainly in the security settings screen, not buried:

- An adversary who compromises your device.
- A global adversary correlating an entire network *outside* Quiet Mode.
- Intersection attacks over long periods: if the same set of users is online whenever a
  particular group is active, that leaks, and batching only slows it down. Full defence
  needs a mixnet with cover traffic from a large, uniform user population — Cue is not
  that and won't pretend to be.
- Your conversation partner being the adversary.
- Traffic analysis by a Node operator who has modified their server. The client-side
  protections (padding, cover traffic, blinding) hold; the server-side ones (not logging,
  batching honestly) do not. Choose your Node accordingly.

## The mixnet question

True protection against A7 (global passive adversary) requires a mixnet: multiple hops,
each operated independently, with mixing and cover traffic at every hop. That is a
different project — Nym and Loopix exist and are hard. Cue's position for v1: build the
transport abstraction so a mixnet backend can be added as a third tier without protocol
changes, ship Tor onion support as the practical near-term answer, and do not claim
mixnet-grade properties. Revisit post-1.0 (`docs/12`).

## Verification

Metadata claims are worthless unaudited. Phase 5 includes:

- **A traffic-analysis test suite:** a harness capturing client traffic during scripted
  conversations, asserting that envelope sizes are uniform within buckets, that inter-
  packet timing in Quiet Mode is statistically indistinguishable from idle, and that no
  distinguisher above a set threshold exists between "sending", "receiving", and "idle".
  Run in CI, because this is exactly the property a refactor silently breaks.
- **A data-at-rest audit:** the seizure simulation from `docs/00` — take a production-shaped
  Node, run realistic traffic, kill it, image the disks, and publish an inventory of
  everything recoverable.
