# 12 — Open Questions

Decisions that are genuinely unresolved. Each has a recommendation, because an open
question with no default is just a stalled decision.

## Q1 — Does Quiet Mode's rarity fingerprint its users?

If a small minority run cover traffic, that traffic pattern *identifies them as the
minority worth watching* — the protection becomes a signal. Making it default fixes the
anonymity set and breaks battery life on mobile.

**Recommendation:** ship Quiet Mode opt-in, and instrument nothing (we can't measure
adoption without telemetry, which we won't add). Make it the default on desktop-when-
plugged-in in a later release, which is where the cost is near zero, so the anonymity set
grows without hurting anyone. Revisit before mobile ships. **Decide by Phase 5.**

## Q2 — Push notifications on mobile

APNs and FCM mean Apple/Google learn that a device received a message and when. That is a
serious metadata leak, and it is unavoidable for a mobile app that wants to wake up.

**Options:** content-free push with randomised delay and batching (leaks timing, coarsely);
UnifiedPush/ntfy self-hosted (Android only, requires user setup); persistent background
socket (iOS won't allow it reliably); periodic polling (battery cost, latency).

**Recommendation:** content-free push with jittered batching as the default, UnifiedPush
supported for Android, and the leak documented in the app rather than in a footnote.
**Decide before mobile work starts.**

## Q3 — Secure recovery backup

The recovery phrase means real users will permanently lose accounts. An SVR-style
server-held encrypted backup, unlocked by a PIN and rate-limited by secure hardware, fixes
that — but "trust our enclave" is exactly the kind of claim this project exists to avoid,
and SGX in particular has a poor security record.

**Recommendation:** no server-side recovery in v1. Instead invest in the phrase UX: a
printable recovery card, an OS-keychain-backed copy, and a strong nudge to link a second
device (a second device *is* a backup). Revisit post-1.0 only if a credible hardware story
exists. **Deferred.**

## Q4 — Funding

There is no revenue model, and there must be one, because a default Node has real running
costs and moderation is labour. Ads and data are excluded by construction. Options:
donations, grants (OTF and similar fund exactly this), optional paid features that don't
touch privacy (extra storage, custom Node hosting), paid Node hosting as a service, or
foundation/nonprofit structure.

**Recommendation:** grants plus donations for v1; paid *Node hosting* (not paid user
features) as the sustainable model — it aligns revenue with decentralisation instead of
against it. Any payment path must be separable from account identity: paying must never
link a payment method to a handle. **Decide before the default Node opens.**

## Q5 — Jurisdiction for the default Node

Determines lawful-interception obligations, data-retention mandates, and whether
client-side-scanning legislation could compel a change that breaks the design. This is a
founding decision with a long lead time.

**Recommendation:** get real legal advice comparing candidate jurisdictions on: mandatory
data retention, technical-capability notices, encryption mandates, and the practical
independence of the courts. Publish the reasoning. Design so that moving Nodes is possible.
**Blocking for Phase 5.**

## Q6 — Do we ever need a Hall size above 10,000?

Halls are the growth surface, and large ones are where legal exposure concentrates.

**Recommendation:** cap at 10,000 on the default Node, let other operators choose. Revisit
with evidence, not ambition.

## Q7 — Federation, seriously?

Deferred in v1 (`docs/10`). The honest question is whether it's ever worth it: it roughly
doubles the protocol surface and leaks metadata to every peer.

**Recommendation:** treat **account portability** (`docs/10`) as the real deliverable — it
provides the exit rights that make Node choice meaningful, at a fraction of the cost.
Reconsider federation only if portability proves insufficient in practice.

## Q8 — Handle wordlist governance

Who curates the lists? A bad cross-product pairing is embarrassing and lands on a user who
didn't choose it. Non-English Nodes need their own lists.

**Recommendation:** ship English lists reviewed as a full cross-product before launch, make
lists a Node-config file, and treat list changes as a normal reviewed contribution. Add a
free reroll for anyone who gets a genuinely bad handle, no questions asked.

## Q9 — Web client: does it undermine the security story?

The web client can't offer verifiable code delivery, and its key storage is weaker. It also
reaches people who cannot install software.

**Recommendation:** ship it, mark it clearly, default it to shorter retention, and add
binary transparency for web builds in Phase 5. Do not let its limitations set the ceiling
for the desktop client.

## Q10 — Franking implementation risk

Asymmetric message franking is the one novel construction. There is no production Rust
implementation, and getting it wrong means either unforgeable reports that aren't (moderation
breaks) or franking that leaks (deniability breaks).

**Recommendation:** budget for a specialist, external review before merge, and a fallback:
if AMF isn't ready, ship Phase 4 with reports that are *unverifiable* but clearly labelled
as such in the moderation console, and require corroboration before action. Better a
weaker, honest mechanism than a broken cryptographic one.

## Q11 — What happens to a Hall when its Node dies?

Halls are Node-scoped. If a Node shuts down, its Halls vanish with it.

**Recommendation:** Hall export (content + member list + settings) as an encrypted archive,
importable to another Node, with members re-invited by link. Not v1, but the file format
should be designed in Phase 4 so exports written then remain importable later.

## Q12 — Abuse at scale on the default Node

Every anonymous, free, encrypted platform gets a serious abuse wave. The plan (`docs/08`)
is reasonable and completely untested.

**Recommendation:** before opening registration publicly, write the incident runbook,
recruit moderators, define the criteria for switching the default Node to invite-only, and
be genuinely willing to pull that lever early. An invite-only default Node with a healthy
community beats an open one that becomes unusable.

---

## Resolved (recorded here so they stay resolved)

| Question | Decision | Where |
|---|---|---|
| Phone number or username? | Auto-assigned `adjective-nounNNN` handles, no PII | `docs/02`, ADR-0001 |
| E2EE everywhere or tiers? | Two explicit tiers: encrypted private, readable Halls | `docs/00`, ADR-0002 |
| Sender keys or MLS for groups? | MLS for all groups ≥3; Double Ratchet for 1:1 | `docs/03`, ADR-0003 |
| Encrypted group size? | 20 default on the default Node, Node-configurable, 1,000 ceiling | `docs/03`, ADR-0003 |
| Federation in v1? | No. Independent Nodes; design keeps the door open | `docs/10`, ADR-0004 |
| Server-side history? | Deliver-and-delete, with mutual save as the only exception | `docs/09`, ADR-0005 |
| Metadata ambition? | Mandatory floor + opt-in Quiet Mode | `docs/04`, ADR-0006 |
| Client platforms? | Rust core + Electron + web; mobile post-1.0 | `docs/06`, ADR-0007 |
| Moderation model? | Blind for E2EE (franked reports), full tools for Halls | `docs/08` |
| Anti-abuse gate? | PoW + ingress-bucket reputation → CAPTCHA → moderator review | `docs/02` |
| Ban evasion? | Trust ramp as the floor; invite, attestation, or payment as optional shortcuts; Hall-level admission | ADR-0009 |
