# 05 — Node Architecture

The Node is the Rust backend. One binary, one config file, one Postgres database, one
object store. Someone should be able to run it on a €10 VPS for a few hundred users and
scale the same code to a hundred thousand.

## Design constraints, in priority order

1. **Forget by default.** Any new table needs a justification and a retention policy.
2. **Operable by one person.** A single static binary, no orchestration required, sane
   defaults, `cue-node doctor` that tells you what's wrong.
3. **Readable.** This code will be audited by people who don't trust us. Clarity beats
   cleverness; every module has a doc comment explaining what it must never do.
4. **Boring dependencies.** Tokio, axum, sqlx, Postgres. No exotic infrastructure.

## Workspace layout

```
cue/
├── crates/
│   ├── cue-proto/          # Wire format: protobuf definitions + generated types
│   ├── cue-crypto/         # Thin policy wrapper over libsignal / openmls / zkgroup
│   ├── cue-kt/             # Key transparency: Merkle prefix tree, proofs, auditor API
│   ├── cue-node/           # The server binary
│   │   ├── ingress/        # TLS termination, IP stripping, bucket tokens, OHTTP gateway
│   │   ├── auth/           # Blind token issuance & verification, credential rotation
│   │   ├── accounts/       # Registration, PoW, handles, devices, prekeys
│   │   ├── delivery/       # Mailboxes, queues, fan-out, batching, Quiet Mode ticks
│   │   ├── mls_ds/         # MLS Delivery Service: ordering, fan-out
│   │   ├── halls/          # Public communities: rooms, roles, history, search
│   │   ├── moderation/     # Reports, franking verification, queues, audit log
│   │   ├── policy/         # Node policy engine: config, automod rules, branding
│   │   ├── blobs/          # Attachment upload/download, quota, GC
│   │   └── admin/          # Operator + moderator API
│   ├── cue-core/           # Client core (see docs/06) — shared by all clients
│   └── cue-testkit/        # Protocol conformance suite, traffic-analysis harness
├── clients/
│   ├── desktop/            # Electron shell
│   └── web/                # Web shell (WASM)
└── docs/
```

`cue-proto`, `cue-crypto`, and `cue-core` are shared between server and clients — one
implementation of the protocol, not two that drift.

## Runtime stack

| Concern | Choice | Why |
|---|---|---|
| Async runtime | Tokio | Default, mature |
| HTTP / transport | `axum` over `hyper`, HTTP/2 + HTTP/3 via `quinn` | HTTP/3 matters: fewer distinguishable connection patterns, better on lossy links |
| Client connection | WebSocket over HTTP/2, or HTTP/3 datagrams | Long-lived socket for delivery; falls back to polling for Quiet Mode / Tor |
| Serialisation | Protobuf (`prost`) | Canonical, schema-versioned, cross-language for future mobile |
| Database | PostgreSQL 16 + `sqlx` | Compile-time checked queries; no ORM |
| Cache / ephemeral | In-process (`moka`) first; Redis only when horizontally scaled, **persistence disabled, `maxmemory-policy allkeys-lru`** | Ephemeral state must not survive a restart, let alone a seizure |
| Blob storage | S3-compatible (MinIO for self-host) | Encrypted blobs only |
| Onion service | `arti` | Bundled, not a separate daemon |
| Metrics | Prometheus, **aggregate counters only** | Explicitly forbidden: any per-account or per-IP label |
| Tracing | `tracing`, structured, redaction layer in the subscriber | The redaction layer is a security control and is unit-tested |

## Data model and retention

Every table, what it holds, and when it dies:

| Table | Contents | Retention |
|---|---|---|
| `accounts` | `account_id`, identity key, trust level, `created_week` | Until deletion; 30-day tombstone then purge |
| `devices` | Device pubkeys, mailbox root, linked date | With account |
| `prekeys` | Signed/one-time/Kyber prekeys | Consumed or rotated out |
| `kt_log` | Append-only handle→key bindings, tree heads | Permanent (that's the point) |
| `envelopes` | Ciphertext awaiting delivery, mailbox ID, expiry | **Deleted on delivery ack**; hard TTL 30 days undelivered |
| `mls_groups` | Encrypted group state blob, opaque group ID, epoch | Until group deleted |
| `credentials` | Blind signature state, spend counters per epoch | Epoch + 1 |
| `halls`, `rooms`, `hall_messages` | Public community content | Per-Hall policy; Node default 1 year |
| `hall_members` | Membership, roles | While member |
| `reports` | Franked report bundles, revealed plaintext | 90 days after resolution |
| `mod_audit` | Every moderator action, actor, timestamp, reason | 2 years, append-only |
| `blobs` | Encrypted attachments | 30 days, or Hall retention |

**Not stored, anywhere, ever:** IP addresses against accounts; access logs; contact lists;
encrypted-group membership rosters in readable form; message plaintext outside Halls and
resolved reports; handle→IP or account→IP mappings; delivery receipts after delivery.

The in-memory-only structures (ingress reputation, presence, rate-limit counters, daily
HMAC secrets) are enumerated in a single module with a comment stating that persisting any
of them is a security regression, and a test asserting they have no persistence backend.

## Delivery pipeline

```
send → [ingress: TLS, strip IP, bucket token]
     → [auth: verify blind token, decrement epoch budget]
     → [delivery: validate envelope shape + padding bucket]
     → [franking: blind-sign commitment]
     → [enqueue to recipient mailbox(es)]
     → [fan-out to connected devices | hold for Quiet Mode tick]
     → [on ack: DELETE]
```

Guarantees: at-least-once delivery with client-side dedup by envelope ID; ordering per
sender-device pair only (not global — global ordering would require metadata Cue refuses to
keep). Undelivered envelopes expire at 30 days and are dropped silently.

## Node policy engine

The single most important thing for making self-hosting real: **operators get genuine
control, expressed in one declarative config file** that the Node validates on boot and
exposes (the public parts) as a capability descriptor clients read before registration.

```toml
[node]
name          = "Cue"
description   = "The default Cue Node."
contact       = "abuse@cue.example"
jurisdiction  = "IS"                    # shown to users before they register
onion         = "auto"                  # publishes a .onion via bundled arti

[node.branding]                          # see docs/06 for how clients render this
logo          = "./branding/logo.svg"
accent        = "#5B8CFF"
wordmark      = "Cue"
welcome_md    = "./branding/welcome.md"
terms_url     = "https://cue.example/terms"
# Branding is scoped: it themes the Node-selection card, the registration flow, and the
# Node's info screen. It never restyles the message list or the encryption indicators —
# a hostile operator must not be able to make an unencrypted Hall look encrypted.

[registration]
mode          = "open"                  # open | invite | closed | approval
pow_seconds   = 5                       # target solve time; auto-scales under load
captcha_after = 3                       # ingress-bucket strikes before CAPTCHA
review_after  = 8                       # strikes before flagged-for-moderator cohort

[trust]                                  # paths to L2 — see ADR-0009
# The time path is always available and cannot be disabled. Everything else is a
# shortcut past the waiting period, never a condition of entry.
time_to_l2    = "7d"
time_to_l3    = "30d"
invite        = true                    # an invite from an L3 grants L2 immediately
invite_mint   = "L3"                    # minimum trust level that can mint invites
invite_uses   = 5
invite_ttl    = "7d"
invite_edge_ttl = "90d"                 # provenance deleted at L2 or this, whichever first
attestation   = "optional"              # off | optional — never "required"
payment       = "off"                   # off | optional — never "required"

[groups]
max_members   = 20                      # protocol ceiling is 1000

[halls]
enabled       = true
max_members   = 10000
who_can_create = "L2"
default_retention = "365d"
public_directory = true                 # list Halls in the Node's browse view

[automod]                               # applies to Halls only — see docs/08
enabled       = true
profile       = "standard"              # off | minimal | standard | strict | custom
rules         = "./automod.d/"          # custom rule files

[limits]
max_attachment_mb = 100
storage_quota_gb  = 500
messages_per_min  = 60

[privacy]
quiet_mode_default = false
ohttp_relay   = "https://relay.independent-party.example"   # optional, recommended
metrics       = "aggregate"             # aggregate | off
```

`cue-node validate` type-checks it; `cue-node doctor` checks the running system (TLS,
storage, onion, KT auditor reachability, whether access logs are somehow on) and prints
a privacy self-assessment the operator can publish.

## Scaling path

- **Small (<5k accounts):** one binary, one Postgres, local MinIO. Single VPS.
- **Medium (<100k):** stateless Node replicas behind the ingress edge, shared Postgres,
  Redis for presence/rate-limits (persistence off), S3 for blobs.
- **Large:** partition mailboxes by ID range; delivery becomes a separate service; Postgres
  read replicas for Hall history. No design work is needed before this is a real problem —
  and it should be noted that a Node at this scale is itself a metadata risk, which is an
  argument for many small Nodes rather than one big one.

## Operations

- **Deployment:** static binary, Docker image, `docker-compose.yml`, systemd unit, and a
  Nix flake. Documented from scratch, tested by someone who didn't write it.
- **Backups:** the KT log and Hall content need backing up. `envelopes` deliberately does
  not — backing up undelivered ciphertext creates a persistent copy of exactly the thing
  the design promises to delete. The backup tooling refuses to include it by default.
- **Upgrades:** online schema migrations, protocol version overlap of at least one release.
- **Abuse response runbook:** written before launch, not after the first incident.
- **Transparency:** `cue-node report` generates the aggregate numbers for a transparency
  report (accounts, legal requests received, data actually produced) with no per-user data.
