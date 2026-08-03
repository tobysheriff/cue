# 02 — Identity & Accounts

## Handles

Every account gets an auto-generated handle in the form `adjective-nounNNN`:

```
brisk-otter472
candid-harbor019
molten-jackdaw883
```

- Two curated wordlists of 2,048 entries each, plus a 3-digit suffix (000–999).
  Keyspace ≈ 4.2 billion. Collisions are handled by re-rolling the suffix, then the words.
- Wordlists are ASCII, lowercase, 4–9 characters, unambiguous when spoken aloud, and
  screened against slurs, brand names, and unfortunate adjacent pairings (both lists are
  cross-checked as a product, not individually — `sticky-finger` problems are found by
  generating the full cross-product and reviewing it).
- Handles are **assigned, not chosen**. This is deliberate: chosen handles leak identity
  (people reuse them across services), enable squatting, and create a namespace to police.
- **Rerolls:** 3 free at signup before the account is finalised, then 1 per 30 days. Each
  reroll is a full identity rotation — see below.
- **Display names** are freely chosen, client-side only, unverified, up to 32 characters,
  and shown next to the handle, never instead of it. The handle is always visible in
  profile views and message-request prompts, so a display name cannot be used to
  impersonate someone.

### Handle rotation
Rerolling publishes a new handle→key binding in the key transparency log and marks the old
one tombstoned. Existing conversations survive (they're bound to the identity key, not the
handle) and show an in-thread "brisk-otter472 is now candid-harbor019" event. New contacts
can't find the old handle. This gives users a cheap way to shed a burned identifier.

### Lookup and enumeration resistance
Handles are looked up by the client sending a salted hash of the handle, not the handle
itself, and lookups are rate-limited per anonymous credential and per ingress bucket.
Because handles are assigned from a 4.2-billion keyspace and not human-guessable, bulk
enumeration is expensive and yields little. There is **no** directory, **no** search by
display name, and **no** address-book upload — Cue never asks for your contacts, which
neatly deletes the entire private-contact-discovery problem that Signal spends enormous
effort on.

Adding a contact is done by:
1. Typing their handle exactly, or
2. Scanning a QR code (contains handle + identity key fingerprint — this path is
   MITM-proof without needing key transparency at all), or
3. A one-time invite link with an embedded short-lived token.

## Cryptographic identity

An account is fundamentally a long-term **identity key pair** (Ed25519 for signatures,
X25519 for key agreement, plus an ML-KEM-1024 key for PQXDH). The handle is a label bound
to it in the key transparency log; the account record on the server is an opaque
identifier derived from the identity key.

The server stores, per account:

| Field | Notes |
|---|---|
| `account_id` | Opaque 128-bit random. Not derived from anything user-visible. |
| `identity_key` | Public. |
| `signed_prekey`, `kyber_prekey` | Public, rotated periodically. |
| `one_time_prekeys[]` | Public, consumed on session setup, replenished by client. |
| `devices[]` | Per-device public keys and an opaque mailbox identifier. |
| `created_at` | Rounded to the week, to avoid a registration-time fingerprint. |
| `zk_credential_state` | Blinded issuance state for anonymous auth tokens. |

The server stores, per account: **no IP, no handle in plaintext, no contacts, no group
memberships, no message history, no display name, no profile photo in readable form.**
(Profile name and avatar are E2E encrypted with a profile key shared only with contacts —
the Signal approach.)

## Devices and multi-device

- One **primary device**, up to 5 **linked devices**. Linking is done by QR code scan with
  the primary, transferring the identity key material over an authenticated channel.
- Each device has its own Double Ratchet sessions and its own mailbox; a message to an
  account fans out to all its devices. This is the Signal Sesame model.
- **A newly linked device starts empty** (deliver-and-delete, `docs/09`). Optional
  device-to-device history transfer over the local network, encrypted, user-initiated,
  never via the server.
- Devices are listed in-app with linking dates; removing one revokes its sessions and
  triggers a ratchet reset with all contacts.

## Recovery

There is exactly one recovery mechanism: a **40-word recovery phrase** (BIP39-style,
~256 bits) shown once at registration, which the user must confirm before the account
becomes usable. It deterministically re-derives the identity key.

- The server cannot reset an account. There is no email, no support override, no
  "verify your identity" path. This is stated at signup in plain language and confirmed
  with an explicit acknowledgement, because it *will* generate angry users.
- Optional: encrypted recovery blob stored server-side, unlocked by the recovery phrase +
  a server-held rate-limited secret (Signal's SVR pattern, needs an HSM/enclave to be
  meaningful). **Deferred past v1** — see `docs/12`; without secure hardware it's theatre.
- Losing the phrase and all devices = losing the account. Contacts see the identity key
  change and get a loud, unmissable safety-number warning if a new account claims the
  handle.

## Registration and anti-abuse

The full gate, in order:

**1. Proof of work.** The client solves a memory-hard puzzle (Argon2id-based, or Equi-X
as used by Tor's PoW defence) over a server-issued challenge. Cost is tuned to ~3–8
seconds on a mid-range laptop. Difficulty is a server-side dial that rises automatically
under registration load — a flood makes registration slower for everyone, which is the
correct failure mode.

**2. Ingress reputation, without identity linkage.** This is the delicate part, because
you asked for repeat-offender IPs to face extra friction while IPs are never stored
against accounts. The design:

- The ingress layer maintains an **in-memory, never-persisted** reputation table keyed by
  `HMAC(rotating_daily_secret, ip_prefix)` — /24 for IPv4, /48 for IPv6. The rotating
  secret is held in memory only and regenerated daily; yesterday's table cannot be
  reconstructed even from a memory dump plus disk.
- Entries hold counters only: registration attempts, rate-limit strikes, and a decay
  timestamp. TTL of 24–72 hours, then gone.
- **The reputation table is never joined to an account record.** The registration flow
  reads it to decide *what challenge to issue*, then discards the association. The
  resulting account carries no marker of which bucket it came from.
- Crossing a strike threshold moves that bucket to **CAPTCHA required** (self-hosted,
  privacy-preserving — no reCAPTCHA, no third-party beacon; likely a self-hosted
  Altcha/Friendly-Captcha-style challenge or an image challenge served by the Node).
- Crossing a higher threshold moves it to **held for moderator review**: the account is
  created but starts in a restricted trust level (see below) and appears in the moderation
  queue as an anonymous "cohort" entry — moderators see *"12 registrations from one
  bucket in 6 minutes"*, never an IP and never a handle-to-IP mapping.

**3. Trust levels.** New accounts start restricted and graduate on time and behaviour:

| Level | What you can do |
|---|---|
| L0 Restricted | Reply to message requests only. Cannot initiate DMs, cannot join Halls. |
| L1 New | Send message requests, join Halls, limited rate. Cannot create Halls. |
| L2 Established | Normal limits. Can create Halls and groups. |
| L3 Trusted | Higher rate limits, can mint invite tokens. |

Trust level is computed from data the server already needs (account age, accepted-request
counts, upheld report count) and is stored as a single integer. It deliberately does not
incorporate anything that would require new data collection.

**Multiple paths to the same level.** There is no single gate, because any single gate
either excludes people who need Cue or is cheap for an attacker to buy. An account reaches
L2 by *any* of these, and a Node operator sets the weight of each:

| Path | Reaches | Cost to a legitimate user | Cost to an attacker at 10,000 accounts |
|---|---|---|---|
| **Time + clean behaviour** | L2 at 7d, L3 at 30d | Patience | 7 days of dormancy per wave — cheap but slow, and slow is most of the point |
| **Invite from an L3** | L2 immediately | Knowing one person | 10,000 social vouches, or a market in stolen invites |
| **Device attestation** | L2 immediately | A supported device | Bounded per device per period; a device farm |
| **Payment** *(optional, off by default)* | L2 immediately | A few units of currency | Directly priced — the only path with a hard floor |

Nobody is *required* to have a device Apple or Google will vouch for, a friend already
inside, or money. That is the whole design constraint: each path is a shortcut past the
waiting period, never a condition of entry. See [ADR-0009](adr/0009-sybil-and-ban-evasion.md)
for the full analysis of each mechanism and what it does and doesn't buy.

**4. Message-request gating.** A stranger's first message to you arrives as a *request*:
sender handle, one message, no attachments, no link previews rendered. Accept, block, or
report. Unaccepted requests are rate-limited hard per sender. This is what actually stops
DM spam being usable at scale, more than any registration gate.

**5. Rate limits everywhere**, enforced against anonymous credentials (`docs/04`) rather
than IPs, so limits survive the IP-blind ingress design.

### Per-Node moderator teams
Every Cue Node is expected to run its own moderation team — the software ships with
the roles, tooling, audit log, and queue built in (`docs/08`), not as an afterthought.
A Node with no moderators should say so on its server-selection card, so users can
make an informed choice.

## Registration flow (client's view)

```
1. Choose server        → default: cue.example (operator's), or enter another
2. Solve PoW            → ~5s, progress shown, explained in one line
3. [If flagged bucket]  → CAPTCHA
4. Handle assigned      → "brisk-otter472"  [Reroll (3 left)] [Keep]
5. Recovery phrase      → shown once, confirm 4 random words back
6. Acknowledge          → "If I lose this phrase and my devices, my account is gone."
7. Done                 → no email, no phone, no password
```

Target: under 90 seconds. Note there is no password — the identity key *is* the
credential, protected at rest by the OS keychain and an optional app passphrase.
