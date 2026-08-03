# 08 — Moderation & Trust and Safety

The hard part. A system that hides everything from its operator has no moderation levers,
and an anonymous, encrypted, free messenger with no moderation becomes uninhabitable and
legally radioactive. Cue's answer is to be **blind where it promises to be blind, and
genuinely capable everywhere else** — and to build the tooling as a first-class feature
rather than bolting it on after the first crisis.

Every Node is expected to run its own moderation team. The software ships with the roles,
queue, tooling, and audit log; running a Node with no moderators is a choice a Node
operator can make, and one that is disclosed to users before they register.

## What moderators can and cannot see

| Where | Operator/Node moderators can see | Can act on |
|---|---|---|
| DMs | Nothing. Ever. | Only what a user reports, via a franked report |
| Encrypted groups | Nothing. Not even the member list. | Only what a member reports |
| Halls | All content in Rooms they have access to | Everything |
| Accounts | `account_id`, trust level, account age, upheld-report count | Restrict, suspend, ban |

There is no override. No "break glass" switch, no admin decryption key, no lawful-access
tier. If such a mechanism existed it would be the first thing an attacker or a court went
for, so it does not exist.

## Reporting in E2EE spaces — franked reports

The mechanism from `docs/03`, from the user's side:

1. Alice reports a message from `brisk-otter472` in a DM.
2. Her client builds a **report bundle**: the plaintext of the reported message, the
   sender's identity, the commitment opening, and the Node's blind signature over the
   commitment — plus, optionally, up to N surrounding messages for context, each
   individually franked and each individually consented to by Alice in the report UI.
3. The Node verifies its own signature and the opening. If it verifies, the message
   provably transited this Node from that account. If it doesn't, the report is discarded —
   **you cannot frame someone by fabricating a report.**
4. The report enters the moderation queue with only what Alice chose to include.

What this does *not* do: give moderators access to anything unreported, let them read the
rest of the conversation, or let them verify a report from a different Node. Those are all
deliberate.

**The reporter's context problem.** A single reported message ("fine, do it then") is often
meaningless without context, and asking for context means asking the reporter to disclose
more of their own conversation. Cue's approach: the report UI shows exactly what will be
sent, message by message, with individual toggles, defaulting to the reported message plus
the two before it. No silent expansion.

**Deniability.** Asymmetric franking means the report is verifiable only by the Node that
franked it. A franked message is not a portable, universally verifiable receipt that could
be used to prove authorship to an arbitrary third party — an important property that
symmetric franking schemes lose.

## The moderation queue

One console, used by Node moderators and Hall moderators with different scopes:

- **Inbox:** franked DM/group reports, Hall reports, automod flags, registration cohort
  flags, appeal requests. Sorted by severity and age, deduplicated by target.
- **Case view:** the evidence, the target's account facts (age, trust level, prior upheld
  reports — *not* their IP, contacts, or other conversations), and the action panel.
- **Actions:** dismiss · warn · restrict (drop trust level) · timeout · suspend · ban ·
  escalate to Node operator. Each requires a reason from a structured list plus free text.
- **Audit log:** append-only, 2-year retention, every action with actor and reason.
  Reviewable by other moderators — moderators watching moderators is the only workable
  check when nobody else can see anything.
- **Rate-limit signals:** anonymous cohort information ("14 accounts from one ingress
  bucket in 8 minutes") without ever exposing the bucket value or an IP.

## Sanctions and account state

| Sanction | Effect | Duration |
|---|---|---|
| Warning | In-app notice, acknowledgement required | — |
| Restriction | Trust level dropped to L0: replies only, no new DMs, no Hall joins | 1–30 days |
| Timeout (Hall) | Cannot post in one Hall | 1h–30d |
| Suspension | Cannot send anything; can read and export | 1–90 days |
| Ban | Account disabled | Permanent |
| Node-wide ban | Ban + registration friction raised for the associated cohort for its short TTL | Permanent |

### Ban evasion

With anonymous registration, a banned user can re-register. Cue's answer is to stop
treating "ban evasion" as one problem — it is four, and they have different fixes
([ADR-0009](adr/0009-sybil-and-ban-evasion.md) has the full analysis and cost model):

| The attack | The answer |
|---|---|
| Mass automated registration | Proof of work + ingress reputation + CAPTCHA. Friction, priced per account |
| **Coming back for one specific person** | **Blocking + message requests. Already solved** — blocking is per identity key, so a returning abuser is a new stranger who must get past a request their target simply declines |
| Getting back into a Hall | Hall admission requirements: minimum trust level, account age, attestation, invite provenance, or approval — set by the Hall, not the Node |
| A funded, persistent adversary | Cost only. Not prevented, and no design that refuses identity anchors can prevent it |

The load-bearing mechanism is the **trust ramp**: every returning attacker restarts at L0
with no ability to DM strangers, no Hall access, and hard rate limits. Evasion isn't
blocked, it's repriced — an abuser who must behave well for seven days before they can
harass anyone has a hobby, not a campaign.

Beyond that, an account can skip the waiting period by *any* of three optional paths — an
invite from an L3 account, device attestation, or (if the Node enables it) a small payment.
None is required, so nobody without money, contacts, or an Apple-blessed device is locked
out; and abuse arriving through one path can be throttled by adjusting that path alone.

Invite provenance is stored under strict constraints, because **an invite tree is a social
graph** — asset #2 in the threat model. Single-hop edges only, deleted at L2 or 90 days,
readable only under a triggered review that is itself audit-logged, and a flagged inviter
drops their outstanding invitees to L0 for human review rather than auto-banning them.

Explicitly rejected: device fingerprinting, hardware IDs, persistent IP-based bans, or any
identity-linkage signal. Each would work, and each would destroy the property the project
exists for.

## User-level tools

Most abuse should be handled by users without a moderator ever being involved:

- **Block** (per identity key) — invisible to the blocked party. No messages, no calls, no
  Hall DMs, no group re-adds.
- **Message requests** — the primary spam defence (`docs/02`).
- **Who can message me:** anyone · contacts of contacts (no — this requires a social graph
  Cue doesn't have; dropped) · contacts only · nobody. Two real options plus off.
- **Group-add consent:** you are never silently added to a group. You get an invitation
  naming the inviter, and the group doesn't exist for you until you accept.
- **Mute / leave / hide** at conversation, Hall, and Room level.
- **Report and block in one action**, always available, never more than two taps away.

## Appeals

Every sanction includes the reason and an appeal path. Appeals go to a different moderator
than the one who acted where the team is large enough, and are answered within a published
target window. This is not just fairness: with no identity verification, mistaken bans are
unrecoverable for the user, so the appeal path is the only correction mechanism.

## Illegal content, and the operator's exposure

This needs real legal advice for your jurisdiction, and the following is engineering
planning, not legal counsel. But the plan has to account for it:

- **In Halls:** the Node operator can see content and therefore has both the ability and,
  in most jurisdictions, some obligation to act on illegal material. Automod, reporting,
  and a documented takedown process with response targets.
- **In E2EE spaces:** the operator cannot see content and cannot scan it. Cue will not
  implement client-side scanning of any kind — it is a general-purpose surveillance
  capability that breaks the core promise the moment it exists, regardless of what it is
  first pointed at. If a jurisdiction mandates it, the correct response is to not operate
  there, and to say so publicly.
- **Known-material hashing (e.g. PhotoDNA-style):** applicable to Hall attachments only,
  where content is already visible. Never in encrypted spaces.
- **Reporting obligations:** where the operator is legally required to report specific
  categories of material found in Halls, that process is documented, logged, and included
  in the transparency report in aggregate.

## Legal and transparency posture

- **Jurisdiction:** choose deliberately, disclose it on the Node card, and understand its
  data-retention and lawful-interception law *before* launch. This is a founding decision,
  not an afterthought — some jurisdictions mandate logging that would make the whole design
  impossible to honour.
- **Transparency report:** quarterly. Requests received, by type and jurisdiction; data
  actually produced (which should be a very short list); accounts actioned by category.
- **Warrant canary:** signed, dated, updated on a fixed schedule. Its absence is the signal.
- **Law-enforcement guide:** publish exactly what the Node can and cannot provide, so
  requests aren't fishing expeditions and so the operator's answers are consistent.
- **Named abuse contact** and a published response-time target.
- **A documented policy for what the operator does when compelled to backdoor the service:**
  decided in advance, in writing, while nobody is under pressure.

## Moderator wellbeing

Non-optional if you expect people to do this work: content warnings and blur-by-default on
reported media, the ability to hand off a case, rotation limits, no requirement for any one
moderator to review everything, and clear written policy so moderators aren't improvising
under stress. Burned-out moderators make bad decisions and then quit.
