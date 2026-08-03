# 07 — Halls

A **Hall** is a public community hosted on a Node: Discord/Telegram-shaped, with Rooms
(channels), roles, persistent history, search, and moderation that actually works.

Halls are **not end-to-end encrypted.** They are TLS-encrypted in transit and encrypted at
rest, and the Node and the Hall's moderators can read them. This is the deal, it is stated
every time it could matter, and it is what makes a 5,000-person community moderatable.

## Why Halls are honest about not being E2EE

A 5,000-member "encrypted" group is a lie of omission: every member's device holds the
keys, so the content is one screenshot away from public, while the encryption claim blocks
every tool that would keep the space liveable — spam filtering, search, ban enforcement,
scrollback for people who join later. Telegram's failure mode is that users believe their
groups are private; Cue refuses to inherit it.

If you want secrecy, use a group (20 members by default, E2EE, `docs/03`). If you want a
community, use a Hall and know who can read it.

## Structure

```
Hall  "Brighton Climbers"
├── Rooms
│   ├── #general           (text)
│   ├── #routes            (text, slow mode 30s)
│   ├── #announcements     (text, post: Moderator+)
│   ├── Voice: Thursday    (voice/video, SFU)
│   └── #mods              (text, private to role)
├── Roles: Owner · Admin · Moderator · Member · Restricted
├── Threads (per message, in any text Room)
├── Invites (link, one-time, or approval-gated)
└── Settings: visibility · joining · automod · retention · branding
```

Deliberately **not** in v1: nested categories beyond one level, voice stages/audio events,
per-Room permission matrices with dozens of toggles, bot marketplaces, monetisation,
"boosts", server discovery ranking algorithms. Discord's complexity is an end state, not a
starting point. What's here is what a community actually needs on day one.

## Roles and permissions

Five built-in roles, plus custom roles that are combinations of a fixed permission set:

| Permission | Member | Mod | Admin | Owner |
|---|---|---|---|---|
| Read / post in public Rooms | ✓ | ✓ | ✓ | ✓ |
| Attach files, react, thread | ✓ | ✓ | ✓ | ✓ |
| Delete others' messages | | ✓ | ✓ | ✓ |
| Timeout / kick / ban members | | ✓ | ✓ | ✓ |
| Manage automod rules | | | ✓ | ✓ |
| Create / delete Rooms, manage roles | | | ✓ | ✓ |
| Manage invites, visibility, retention | | | ✓ | ✓ |
| Manage branding | | | ✓ | ✓ |
| Transfer or delete the Hall | | | | ✓ |

Every moderation action writes to an append-only Hall audit log visible to Admins, with
actor, target, action, reason, and timestamp. Moderator accountability is a feature.

## Joining and visibility

Per-Hall settings, all operator-of-the-Hall's choice:

| Visibility | Behaviour |
|---|---|
| **Public** | Listed in the Node's Hall directory, joinable by anyone at or above a set trust level |
| **Unlisted** | Not in the directory; joinable with a link |
| **Invite-only** | Requires a valid invite token minted by a member with permission |
| **Approval** | Anyone can request; a moderator approves, optionally with a joining question |

### Admission requirements

Layered on top of visibility, and the place where ban evasion is actually fought
([ADR-0009](adr/0009-sybil-and-ban-evasion.md)) — a Hall under attack can raise its own
drawbridge without the Node closing registration for everybody:

- Minimum trust level (`L1`/`L2`/`L3`, `docs/02`) and minimum account age
- Require **device attestation**, or require **invite provenance** (joined via an invite
  from an existing member), or require both
- A rules-acknowledgement gate on first post
- **Lockdown:** a one-switch mode that suspends all joins, triggered manually or
  automatically by the raid detector below

Requirements are shown on the Hall's join screen before a request is made, so nobody
bounces off an invisible wall.

Invites are tokens with configurable max uses, expiry, and an optional role grant. Revoking
an invite is immediate and shows in the audit log.

## Automod

Runs on the Node, only on Hall content (never on E2EE traffic — it cannot see it):

- **Rule types:** term/regex match lists, link and domain policy (allow/deny/require role),
  attachment type and size limits, mention flooding, message rate and duplication, new-
  account posting restrictions, invite-link spam, Unicode confusable/zalgo normalisation,
  and raid detection (join-rate anomalies → temporary lockdown).
- **Actions:** allow · flag for review · silently hold for approval · delete · timeout ·
  kick · ban, each with a configurable notification to the member.
- **Profiles:** `off` · `minimal` · `standard` · `strict`, so a new Hall gets something
  sane immediately, with custom rule files for anyone who wants them.
- **Two levels:** the Node operator sets a baseline (`automod.profile` in Node config,
  `docs/05`) that Halls can tighten but not loosen below; each Hall layers its own rules
  on top. This is how a Node operator enforces Node-wide standards without reading
  everything themselves.
- Every automod action is logged with the triggering rule, and appealable (`docs/08`).

Automod is deliberately dumb and deterministic in v1 — no ML classifiers. Explainable
rules that a moderator can read, test against a sample, and correct beat a black box that
nobody can debug, and they don't require shipping community content to a third party.

## Search and history

Halls have server-side full-text search (Postgres FTS to start; a dedicated index only if
it's genuinely needed), scoped by permission. History retention is per-Hall within limits
the Node sets — from "keep forever" to "delete after 24 hours", set by Admins and displayed
in the Hall's info panel so members know what's being kept.

## Voice and video

- Group calls via an SFU (`mediasoup`-style, or a Rust SFU) hosted by the Node. In Halls,
  media is transport-encrypted to the SFU — same honesty as text.
- **1:1 and encrypted-group calls are different:** E2EE media (SRTP with keys from the
  Signal/MLS session) and **always relayed through a TURN server**, never peer-to-peer, so
  a call never leaks your IP to the other party. Signal made direct P2P an option for
  contacts only; Cue relays unconditionally, because with anonymous accounts "contact"
  doesn't imply "knows my IP is fine to reveal".
- Voice is Phase 6 — after messaging is solid. It is a large sub-project of its own.

## Bots and integrations

- A minimal HTTP + WebSocket bot API scoped to a single Hall, with a permission model
  identical to a member's, an explicitly granted scope list, and a visible "Bot" badge.
- Bots cannot exist in encrypted spaces. There is nowhere for them to stand.
- Webhooks are outbound-only and rate-limited. No arbitrary inbound integrations in v1.
- A Node operator can disable bots entirely.

## Relationship to the Node

A Hall lives on exactly one Node and is subject to that Node's policy: its size cap, its
automod baseline, its retention limits, its terms, and its moderators' authority to act on
Halls that violate them. A Hall cannot outrank the Node it lives on, and the Node's rules
are published in the capability descriptor so members can see what applies before joining.
