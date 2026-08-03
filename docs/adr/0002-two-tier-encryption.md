# ADR-0002 — Two explicit encryption tiers, never blurred

**Status:** Accepted · **Adversaries addressed:** A5 (abusive users), A2 (operator, by
being honest about what it can read)

## Context

End-to-end encryption and Discord/Telegram-style communities are in direct tension. A
5,000-member "encrypted" group is a lie of omission — every member holds the keys, so the
content is one screenshot from public — while the encryption claim blocks spam filtering,
search, scrollback, and enforceable bans, which is everything that keeps a large space
liveable.

Telegram's core failure is that "chat" and "secret chat" look alike, so users routinely
believe they're protected when they aren't.

## Decision

Two tiers, distinguished unmistakably in the UI:

- **Private:** DMs and groups (20 members by default). E2EE. The Node cannot read content
  or enumerate membership. Ephemeral by default. No server-side moderation.
- **Halls:** public communities. Transport-encrypted only. The Node and Hall moderators can
  read them. Persistent history, search, automod, full moderation.

The distinction is carried by glyph, geometry, surface treatment, and words — not colour
alone — plus a one-time interstitial on joining a Hall and a persistent header strip.
Node branding cannot restyle any of it (`docs/06`).

## Consequences

**Good:** users can tell what they're in. Large communities get moderation that actually
works. The encryption claim, where made, is true. Legal exposure in Halls is manageable
because the operator can act on content.

**Bad:** "not E2EE" is a competitive disadvantage against products willing to overclaim.
Halls are a smaller privacy promise than some users will want, and some will use them for
things that deserved a group. Two rendering paths and two moderation models to maintain.

## Alternatives rejected

- **E2EE everywhere with a size cap:** no server-side spam filtering or search, expensive
  key rotation on every join/leave, moderation reduced to client reports — a large
  community becomes unmoderatable in practice.
- **E2EE everywhere with no cap:** unproven above a few thousand members; a high risk of
  the project stalling permanently on one problem.
- **One tier with an "encryption" toggle per conversation:** exactly Telegram's mistake.
