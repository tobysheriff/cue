# 03 — Cryptographic Design

Design rule: **no novel primitives.** Every construction here is either standardised, has
a production Rust implementation, or has a peer-reviewed paper plus an implementation plan
that goes through external review before shipping.

## Primitive inventory

| Purpose | Choice | Rust crate |
|---|---|---|
| Signatures | Ed25519 | `ed25519-dalek` (via libsignal) |
| Key agreement | X25519 | `curve25519-dalek` |
| Post-quantum KEM | ML-KEM-1024 (Kyber) | libsignal / `ml-kem` |
| AEAD | ChaCha20-Poly1305 (XChaCha20 for local storage) | `chacha20poly1305` |
| Hash / KDF | SHA-256, HKDF-SHA256 | `sha2`, `hkdf` |
| Password/passphrase KDF | Argon2id | `argon2` |
| 1:1 session | PQXDH + Double Ratchet | `libsignal-protocol` |
| Group session | MLS (RFC 9420) | `openmls` |
| Anonymous credentials | zkgroup-style (algebraic MAC, Chase–Perrin–Zaverucha) | `zkgroup` / `poksho` |
| Blind tokens | Privacy Pass / VOPRF (RFC 9497) | `voprf` |
| Key transparency | Merkle prefix tree + append-only log | own, modelled on Signal KT / Parakeet |
| Message franking | Asymmetric Message Franking (Tyagi et al.) | own, external review required |
| Proof of work | Argon2id-based, or Equi-X | `argon2` / `equix` |
| Local DB encryption | SQLCipher (AES-256) or `sqlite` + XChaCha20 page cipher | `rusqlite` + SQLCipher |

## Direct messages — Signal protocol

Unchanged from Signal, because it is correct and there is no reason to be creative:

**Session establishment: PQXDH.** The initiator fetches the recipient's prekey bundle
(identity key, signed prekey, one-time prekey, Kyber prekey), performs the X25519 DH
combination *and* an ML-KEM encapsulation, and mixes both into the root key. This gives
harvest-now-decrypt-later resistance for session setup.

**Ongoing messages: Double Ratchet.** Per-message key derivation with a DH ratchet and a
symmetric-key ratchet: forward secrecy (past messages safe if current keys leak) and
post-compromise security (future messages recover after a compromise ends).

**Implementation:** use `libsignal` directly as a dependency rather than reimplementing.
It is Rust, it is audited, and it is the reference. Cue's own crypto crate is a thin,
well-documented wrapper that owns *policy* (which keys rotate when, how many one-time
prekeys to keep buffered) and never touches primitive internals.

**Multi-device:** Sesame — each device pair maintains its own session; sending to an
account means encrypting once per recipient device. A 5-device account in a 10-person
group is 50 ciphertexts, which is exactly why groups above ~50 use MLS instead.

## Encrypted groups — MLS

Group chats are fully end-to-end encrypted, exactly like DMs. The Node cannot read them,
cannot enumerate their members, and cannot add a member.

Signal uses sender keys over pairwise sessions for groups. That works, but membership
changes cost O(n) pairwise messages and forward secrecy on removal is weak. MLS (RFC 9420)
is the better tool: a TreeKEM ratchet tree giving O(log n) membership updates, forward
secrecy, and post-compromise security across the whole group. Critically, removing a
member **actually removes them** — the group ratchets forward and their key material is
useless for everything after the removal commit. With sender keys, removal requires every
remaining member to rotate and redistribute, and a single lazy client leaves a hole.

### Size limits

| Scope | Value | Set by |
|---|---|---|
| Default Node (`cue.example`) | **20 members** | Node policy, `groups.max_members` |
| Other Nodes | Operator's choice | Node policy |
| Protocol hard ceiling | 1,000 members | Client + protocol, not configurable |

The default Node caps encrypted groups at **20**. That is a deliberate product stance, not
a technical limit: a 20-person group is a group of people who know each other, which is
the threat model E2EE actually serves. Anything larger is a broadcast channel wearing a
group's clothes — every additional member is another device that can screenshot, another
endpoint to compromise, and another person who was invited by someone you don't know.
Communities belong in Halls (`docs/07`), where the encryption claim isn't quietly false.

Node operators can raise or lower `groups.max_members` up to the protocol ceiling of 1,000
(see `docs/10`). The cap is advertised in the Node's capability descriptor, and the client
displays it on the Node-selection card and in group creation, so a user always knows the
policy of the Node they're on. Above ~200 members, operators should expect noticeable
commit-processing cost on low-end clients; the ceiling of 1,000 exists because MLS
membership-change traffic and client-side state stop being comfortable beyond it.

- **Library:** `openmls`, with the RustCrypto provider.
- **Ciphersuite:** `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`, with a migration
  path to a PQ hybrid ciphersuite when one is standardised.
- **Delivery Service:** the Node acts as MLS DS — it orders and fans out handshake and
  application messages but cannot read them. It must not learn the member list; see
  anonymous credentials below.
- **Authentication Service:** replaced by Cue's key transparency log; MLS credentials are
  Cue identity keys with a KT inclusion proof.
- **Cap enforcement:** the client refuses to build a commit that exceeds the Node's
  advertised cap, and the DS rejects one for what little that's worth — the DS can't see
  the member list, so it enforces via the count of leaves in the ratchet tree, which is
  visible in the commit structure.

> **Decision note:** using two different group mechanisms (sender keys for small, MLS for
> large) was rejected as unnecessary complexity. All groups ≥3 participants use MLS.
> 1:1 stays on Double Ratchet. See [ADR-0003](adr/0003-mls-for-groups.md).

## Anonymous group membership

The Node must route group messages without learning who is in the group. Signal's zkgroup
solves this and Cue adopts the pattern:

1. A group has a **group master key**, known only to members, from which the group's
   server-visible identifier and the encryption of member entries are derived.
2. Each member holds an **auth credential** — a blind-issued algebraic MAC over their
   `account_id` and a role — issued by the Node without the Node learning which account it
   is being used for later.
3. To act on the group, the client presents a zero-knowledge proof that it holds a valid
   credential for a member of that group. The Node verifies the proof, learns nothing else.
4. Membership lists, roles, titles, and avatars are stored server-side **encrypted** under
   keys derived from the group master key.

Result: the Node sees "an authorised member of group `0x9f3a…` sent an update", never who.

## Key transparency

With no phone number to anchor identity, key substitution is the top attack: a malicious
Node hands out its own key for `brisk-otter472`. Countermeasures, in order of strength:

1. **QR / in-person verification** — best, unconditional, always available. The client
   nags for it on the first message to a new contact and shows a persistent unverified
   indicator until done.
2. **Safety numbers** — comparable fingerprint of both identity keys, with a loud in-thread
   warning on any change.
3. **Key transparency log** — the Node publishes an append-only log of handle→key bindings
   in a Merkle prefix tree, with signed tree heads. Clients verify inclusion proofs for
   contacts and consistency proofs between tree heads over time. Third-party auditors
   (ideally including at least one party independent of the operator) gossip tree heads
   so the Node cannot serve split views.

KT catches an equivocating Node *after the fact but reliably*. It is a v1 requirement, not
a nice-to-have — it is the single mechanism that makes trusting someone else's Node
tolerable.

## Sealed sender

Envelopes carry the sender identity encrypted to the recipient, so the Node routes on
recipient mailbox only. Delivery is authorised by an **anonymous delivery credential**
(unlinkable to the sender account) rather than by authenticating the sender.

Signal's sealed sender is defeated if the server correlates delivery-token issuance with
use; Cue uses blind-issued single-use tokens with a batch-issuance schedule that
decorrelates issuance from send time. See `docs/04`.

Abuse cost: sealed sender removes the Node's ability to rate-limit by sender identity.
Mitigation is rate-limiting anonymous credentials themselves (a credential can be spent
N times per epoch), plus recipient-side message-request gating.

## Message franking (accountability under E2EE)

To let a recipient prove "this account really sent me this exact message" without the Node
ever reading messages, and while sealed sender hides senders:

- Sender computes a commitment to the plaintext and includes it in the ciphertext.
- The Node blind-signs the commitment in transit (it signs an opaque value).
- If the recipient reports, they reveal: plaintext, opening, sender identity, and the
  Node's signature. The Node verifies the signature and the opening.
- **Asymmetric** franking (Tyagi–Grubbs–Len–Miers–Ristenpart) is required rather than the
  simpler symmetric scheme, because the reporter must be able to prove the *sender's*
  identity to a moderator who was not party to the conversation.

Properties that matter and must be tested:
- **Unforgeable:** you cannot fabricate a report about a message someone didn't send.
- **Deniable to third parties:** a report is only verifiable by the Node that franked it,
  so a franked message is not a universally verifiable receipt usable in court against
  the sender by an arbitrary party.
- **Not retroactive:** the Node learns content only for reported messages, at report time.

This construction has no production Rust implementation. It is the one place Cue writes
novel crypto code, and it is gated on external review before release.

## Local storage encryption

- SQLCipher database, key derived Argon2id(passphrase) if app lock is on, else a random
  key stored in the OS keychain (Keychain / DPAPI / libsecret).
- Attachments encrypted individually; keys in the DB.
- Explicit memory zeroisation for key material (`zeroize`), no swap for the key buffer
  where the OS permits (`mlock`).
- Ephemeral messages are deleted with a page-overwriting vacuum, not just a `DELETE`.

## Cryptographic agility and versioning

Every wire object carries a version byte. Ciphersuite negotiation is **not** dynamic —
clients implement exactly one suite per protocol version, and version transitions are
coordinated releases with a defined overlap window. Downgrade attacks are prevented by
refusing lower versions than the last one seen for a peer.

## Things explicitly rejected

- **Rolling our own ratchet.** No.
- **Post-compromise-free "simple" modes** (e.g. static-key encryption for speed). No.
- **Key escrow of any kind**, including "for account recovery". No.
- **Server-assisted plaintext search** in private tiers, including via encrypted search
  indices — the leakage profiles of practical searchable encryption are bad enough to
  undermine the whole design.
- **Any AI/ML feature that reads private message content**, on-device or otherwise, in v1.
