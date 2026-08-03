# 10 — Running a Node

A Node is a full Cue backend that someone runs. `cue.example` is the default one; it has
no special powers, no privileged protocol position, and no capability another Node lacks.
If self-hosting is second-class, decentralisation is marketing — so the design goal is that
a self-hosted Node is *the same software with a different config*, and that its operator
has real authority over their own space.

## What a Node operator controls

Everything in this table is a config setting (`docs/05`), validated on boot and published
in the Node's capability descriptor so users see it before they register.

### Identity and presentation
- **Branding:** name, description, logo, wordmark, accent colour, welcome text (Markdown),
  terms and privacy URLs, abuse contact.
- **Scope of branding:** themes the Node card, registration flow, welcome screen, and Node
  info panel. It cannot restyle encryption indicators or the private/Hall distinction —
  see `docs/06` for why that boundary is enforced in the client.
- **Jurisdiction disclosure:** shown to users before registration. Required, not optional.
- **Custom domain**, and an auto-published `.onion` address via bundled `arti`.

### Registration and membership
- **Mode:** `open` · `invite` (token required) · `approval` (moderator reviews each
  registration) · `closed` (nobody new, existing accounts unaffected).
- **Invite policy:** who can mint invites (by trust level), uses per invite, TTL, whether
  an invite grants an elevated starting trust level, and revocation.
- **Trust paths** (ADR-0009): how long the time-based path to L2 and L3 takes, and which
  optional shortcuts are enabled — invite, device attestation, payment. The time path
  cannot be disabled and no shortcut can be made mandatory, so a Node cannot lock out
  users who have no invite, no supported device, and no money.
- **Proof-of-work difficulty** target, and whether it auto-scales under load.
- **CAPTCHA and review thresholds** on ingress-bucket strike counts (`docs/02`).
- **Allowed handle wordlists** — a Node can supply its own adjective/noun lists, which is
  how a themed or non-English Node gets handles in its own language.
- **Account deletion and inactivity policy.**

### Limits
- **`groups.max_members`** — encrypted group cap. 20 on the default Node; any value up to
  the protocol ceiling of 1,000. Advertised to clients, enforced client-side.
- Halls: enabled/disabled, max members, who can create one, default and maximum retention.
- Attachment size, per-account storage quota, message rate limits, Node storage cap.
- Whether bots and webhooks are permitted at all.

### Safety
- **Automod baseline** applied to every Hall on the Node, which Halls may tighten but not
  loosen; plus custom rule files (`docs/07`).
- **Moderator roster and roles**, the moderation queue, and the audit log.
- Federation-ready **blocklist import** for known-bad invite domains and link targets.
- Whether the Node appears in the public Node directory.

### Privacy
- OHTTP relay URL (strongly recommended — `docs/04`), metrics on/off/aggregate, Hall
  retention defaults, whether Quiet Mode is on by default for new accounts.

## Getting a Node running

Target: **under 15 minutes** from a fresh VPS to a working Node, using one command and one
config file.

```bash
# Docker (recommended for most)
curl -O https://cue.example/deploy/docker-compose.yml
cue-node init --domain chat.myorg.net --email admin@myorg.net
docker compose up -d

# Or the static binary
cue-node init --domain chat.myorg.net
cue-node validate ./cue.toml
cue-node migrate
cue-node serve
```

`cue-node init` generates config, provisions TLS via ACME, creates the database schema,
generates the KT log's signing key, optionally publishes an onion service, and prints the
first owner-account invite token.

`cue-node doctor` audits the running system and prints a privacy self-assessment: access
logging state, whether the reputation table has a persistence backend (it must not),
whether the KT auditor endpoint is reachable, backup configuration, TLS grade, onion
status. Operators are encouraged to publish its output.

Documentation ships with: a hardware sizing table, a security-hardening guide, a backup
and restore runbook, an upgrade guide, an abuse-response runbook template, and a template
transparency report. Success criterion from `docs/00`: someone unaffiliated with the
project runs a Node from the docs alone, without asking for help.

## The Node directory

An opt-in, signed list of public Nodes shown in the client's Node picker, with each Node's
self-declared jurisdiction, registration mode, group cap, moderator count, and uptime as
observed by the directory.

- Listing is opt-in and requires a contact address and terms URL.
- The directory is **advisory, not authoritative** — the client can always take a manually
  entered domain, and being delisted doesn't break anyone's account.
- The directory is a piece of centralisation and is treated as such: it's published as a
  signed, reproducible file in a public repository, so anyone can mirror it, fork it, or
  point their client at a different one. If the default directory becomes a gatekeeper,
  that's a project failure.

## Trust between users and Nodes

An account's Node sees connection times, mailbox activity, and Hall content — everything in
`docs/01` A8. That is unavoidable and the client says so at signup rather than implying
that choosing any Node is risk-free.

What protects a user on a Node they don't fully trust:
- Message content and encrypted-group membership are cryptographically out of reach.
- Key transparency, with independent auditors, detects a Node that lies about keys.
- QR verification is unconditional and doesn't rely on the Node at all.
- Quiet Mode and onion transport reduce what the Node learns about connection patterns.
- The client enforces protocol invariants rather than trusting server assertions.

## Federation (not in v1)

An account lives on one Node and talks to accounts on that Node. Cross-Node messaging is
out of scope for v1 — it roughly doubles the protocol surface, and it leaks metadata to
every participating server, which sits badly with the metadata goals.

The design keeps the door open rather than closing it:
- Addressing is already `handle@node` internally, even though the UI hides the domain
  while there's only one Node in play.
- Identity keys are Node-independent; the Node hosts a binding, it doesn't own the identity.
- The wire protocol is versioned and transport-agnostic; a Node-to-Node transport can be
  added without changing client-to-Node.
- Key transparency is designed with cross-Node auditing in mind.

If federation happens, the likely shape is **DM-and-group federation only, never Halls**
(a federated Hall means every peer Node holds a copy of the content and the membership,
which is a much worse privacy story than a single Node holding it). Tracked in `docs/12`.

## Account portability

The realistic near-term substitute for federation, and worth building even if federation
never happens:
- Export identity + contacts + saved messages as an encrypted archive.
- Import on another Node, keeping the same identity key so contacts' safety numbers stay
  valid; the handle changes because handles are Node-scoped.
- Contacts see a Node-migration event in-thread and can re-verify with one tap.

This gives users the exit that makes trusting a Node reasonable: if the operator turns
hostile or disappears, you leave and keep your identity.
