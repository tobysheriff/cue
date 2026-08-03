# ADR-0009 — Sybil resistance and ban evasion

**Status:** Accepted · **Adversaries addressed:** A5 (abusive users) · **Supersedes** the
"ban evasion is unsolved" note in `docs/08`

## Context

With no phone number, a banned user can re-register. ADR-0001 accepted this as the cost of
the identity model. That was an honest statement of the problem and an inadequate answer to
it, because "ban evasion" is really four different attacks with four different fixes:

| Attack | What the attacker wants | What actually stops it |
|---|---|---|
| **Mass automated registration** | 10,000 accounts for spam or raids | PoW, ingress reputation, CAPTCHA — cost per account |
| **Targeted harassment** | To reach one specific person who blocked them | Blocking + message requests. **Already solved**, independent of registration |
| **Community disruption** | To get back into a Hall they were banned from | Admission requirements at the Hall, invite provenance |
| **Persistent well-resourced abuse** | To keep doing all of the above | Nothing fully. Only cost |

Conflating these produces bad design: it makes people reach for identity anchors to solve a
problem that blocking already handles. Note the second row especially — **the case that
matters most to a victim is the one already solved**, and no mechanism below improves it.

## Evaluation of the candidate mechanisms

Cost model throughout: what does it cost an attacker to obtain 10,000 usable accounts?

### Proof of work — *adopted, but weak alone*
Argon2id/Equi-X, ~5 s target on a mid-range laptop.

10,000 accounts at 5 s is ~14 CPU-hours: roughly 13 minutes and well under a dollar on a
rented 64-core box. Raising the target to 60 s costs the attacker maybe $5–10 and costs
every legitimate user a minute of staring at a progress bar. **PoW's asymmetry runs the
wrong way** — the attacker's hardware is always better than the median user's.

Keep it: it stops casual scripting and it raises the floor under everything else. Do not
mistake it for a defence against a funded adversary.

### Ingress-bucket reputation and CAPTCHA — *adopted*
Already in `docs/02`. Forces the attacker onto distributed infrastructure. Residential
proxy pools defeat it and cost roughly $1–5/GB, which is real money at volume but not
prohibitive. Same category as PoW: friction, not a wall.

### Payment — *adopted as an optional path, off by default*
The only mechanism with a genuinely hard price floor. At $1/account, 10,000 accounts costs
$10,000, and that number does not fall with better hardware or more proxies.

Four objections, in descending order of seriousness:

1. **It excludes the users the project exists for.** An activist in a sanctioned country,
   someone without banked money, a teenager. A payment *requirement* would make Cue a tool
   for people who already have options.
2. **It creates records where there were none.** Taking payment means the operator holds a
   wallet with a transaction history that correlates in time with registrations. Monero's
   on-chain privacy is strong; the *timing* correlation between "payment received" and
   "account created" is a linkage the design otherwise refuses to create. Mandatory
   mitigation: payment buys a **blind-signed credential** redeemed at a randomised later
   time (the same VOPRF machinery as `docs/04`), so the two events cannot be paired.
3. **It creates legal surface.** Handling money invites AML/KYC questions in some
   jurisdictions — potentially imposing exactly the identity collection the project rejects.
   This is a question for the lawyer in `docs/12` Q5, before any payment path ships.
4. **Acquiring Monero is itself a barrier** for most people, and volatile pricing makes a
   "small payment" hard to keep small.

**Decision:** payment is a Node-configurable *optional shortcut* to L2, defaulting to off,
never a condition of registration. If the default Node ever enables it, the free
time-based path stays open alongside it.

### Hardware attestation (Private Access Tokens / Play Integrity) — *adopted as an optional path*
The strongest per-device Sybil bound available without PII, and genuinely unlinkable to the
server — PAT is Privacy Pass underneath, so the issuer learns "a genuine device asked",
not which one.

But:

- **It requires trusting Apple and Google**, and it excludes everyone they won't vouch for:
  Linux desktops, de-Googled Android, custom ROMs, VMs, older hardware. That is
  disproportionately Cue's core audience. Play Integrity in particular actively fails on
  exactly the devices privacy-conscious users choose.
- **It leaks to Apple/Google that you use Cue.** The attestation request identifies the
  issuer. It does not reveal your account, but "this Apple ID requested a token for Cue"
  is a new disclosure to a third party, and it must be stated in the UI before a user
  opts into this path.
- **Device farms exist.** Attestation bounds accounts per device per period; it does not
  bound accounts per attacker who rents a thousand real phones. It reprices the attack to
  perhaps $0.10–1/account rather than preventing it.

**Decision:** offer attestation as one path to L2 for users who want to skip the waiting
period and have a supported device. Never required, never a higher ceiling than the other
paths reach, and always disclosed as a third-party interaction before use.

### Invitation graph — *adopted, with a strict privacy constraint*
The most effective mechanism against the *community disruption* case, and the one with the
sharpest privacy problem in this entire document.

**A stored invite tree is a social graph.** That is asset #2 in `docs/01` — the thing the
threat model ranks as more damaging than message content, because it maps organisational
structure. A seized Node holding a full invite tree tells an adversary who recruited whom
across an activist network. Building one would undo a substantial part of the project.

So the graph is adopted with these constraints, which are not negotiable:

1. **Single-hop edges only.** An account stores a reference to its *direct* inviter. No
   ancestry chain is stored, assembled, or queryable. "Ban the subtree" becomes "ban the
   inviter's direct invitees", which is where nearly all of the signal is anyway.
2. **Edges expire.** The inviter reference is deleted when the invitee reaches L2 (7 days
   clean) or after 90 days, whichever comes first. Invite provenance matters while an
   account is new and is worthless afterwards — so it does not persist.
3. **Edges are moderator-visible only under a triggered review**, never browsable, never
   exported, and every access is written to the moderation audit log.
4. **Subtree action is a review trigger, not an automatic ban.** Auto-banning everyone an
   abuser invited punishes people who did nothing; it also hands an attacker a weapon
   (invite your target's friends, then get banned). Default action on a flagged inviter is
   to drop their outstanding invitees to L0 and queue them for a human.
5. **A future hardening path exists** and is worth doing if invites become central:
   commit to the inviter under a threshold-encrypted token so the edge is *cryptographically
   unreadable* until an abuse threshold is crossed, rather than merely policy-protected.
   Out of scope for v1; noted so the storage format doesn't preclude it.

Also worth stating plainly: **every invite-only network eventually grows an invite market.**
Once Cue is valuable, invites will be sold, and the mechanism decays toward the payment
mechanism with worse ergonomics. Invite provenance is a delay, not a wall.

### Reputation ramp — *already adopted, and the load-bearing one*
This is correct, and it is most of how Discord and Matrix actually cope. Already in
`docs/02` as L0–L3.

The key property: evasion isn't blocked, it's **repriced to near-worthlessness**, because
every returning attacker restarts at L0 with no ability to DM strangers, no Hall access,
and hard rate limits. An abuser who must spend seven days behaving well before they can
harass anyone is an abuser with a hobby, not a campaign.

One refinement: the ramp must gate the *harm vectors* (DMs to strangers, Hall joins, invite
minting, group creation) and not general usage. Punishing new users for being new is how
you lose the users who arrived for a good reason.

## Decision

**Layered, with multiple independent paths to the same trust level**, rather than one gate.

- **Floor for everyone:** PoW + ingress reputation + CAPTCHA on flagged buckets.
- **Ramp for everyone:** L0→L3 on time and clean behaviour, gating harm vectors only.
- **Shortcuts past the ramp, any one of which suffices:** an invite from an L3, device
  attestation, or (if a Node enables it) payment.
- **Hall-level admission:** a Hall can require any combination — minimum trust level,
  minimum account age, attestation, invite provenance, or manual approval. This is where
  the real anti-evasion work happens, because it lets a community under attack raise its
  own drawbridge without the Node closing registration for everyone.
- **Node-level policy:** operators weight all of the above (`docs/10`), including switching
  the whole Node to invite-only under pressure.

The unifying principle: **no path is mandatory, every path is optional, and abuse arriving
through any one path can be throttled by adjusting that path alone** without locking out
people who came another way.

## Consequences

**Good:** mass registration gets priced, community disruption gets real friction, and
targeted harassment stays solved by blocking. Users with no money, no invite, and no
attested device can still get a full account — they wait a week. Communities set their own
bar. A Node under attack has levers short of shutting registration.

**Bad:** more mechanisms means more code, more moderation surface, and more ways to
misconfigure a Node. The invite graph, even constrained as above, is a privacy regression
against the current design and must be justified continuously rather than assumed. A
determined, funded adversary still gets in — this ADR reprices ban evasion, it does not
eliminate it, and no design that refuses identity anchors can.

**Rejected outright, again:** device fingerprinting, hardware IDs, persistent IP bans, and
any linkage signal that would identify a returning user by who they *are* rather than by
what they have earned.
