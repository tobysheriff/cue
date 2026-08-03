# ADR-0008 — AGPL-3.0 server, GPL-3.0 clients

**Status:** Accepted

## Context

The Node must be open source: users are asked to trust it with delivery, and an unverifiable
server undermines the whole argument for self-hosting. The question is which licence, and
the answer determines whether a hostile operator can run a modified, user-hostile Node
without disclosing what they changed.

## Decision

| Component | Licence |
|---|---|
| `cue-node` (server) | **AGPL-3.0** |
| `cue-core`, clients | **GPL-3.0** |
| `cue-proto`, protocol spec | **CC-BY-4.0** (spec) / **Apache-2.0** (generated types) |

Contributions under a DCO (`Signed-off-by`), **not** a CLA. No copyright assignment.

## Consequences

**Good:** AGPL means anyone running a modified Node for users must offer those users the
source — which is precisely the transparency the trust model depends on. GPL on clients
keeps forks open. The permissive protocol licence lets anyone build an interoperable
client, which is good for the ecosystem and costs nothing.

**Bad:** AGPL deters some corporate deployment. No CLA means relicensing later is
effectively impossible without contacting every contributor — accepted deliberately, since
the inability to relicense is itself a guarantee to contributors and users that the project
cannot be quietly taken proprietary.

## Alternatives rejected

- **MIT/Apache everywhere:** permits a modified, surveilling Node with no disclosure
  obligation. Defeats the point.
- **CLA with copyright assignment:** enables a future relicense, which is exactly the risk
  users should not have to take on.
- **Source-available / BSL:** not open source; would rightly damage credibility with the
  people this project needs to be trusted by.

## Also required at launch

Trademark policy for the name "Cue" and the logo. The code is free to fork; the *name*
should not be usable for a modified Node that users would mistake for the official one.
This is the standard Mozilla/Signal arrangement and is not in tension with the licence.
