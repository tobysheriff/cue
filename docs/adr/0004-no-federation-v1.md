# ADR-0004 — Independent Nodes, no federation in v1

**Status:** Accepted · **Adversaries addressed:** A2/A8 (server operators), by limiting how
many of them see anything

## Context

"Decentralised" can mean two very different things: anyone can run a server (independent
instances), or servers talk to each other (federation, à la Matrix/ActivityPub).

Federation roughly doubles the protocol surface — a server-to-server transport, cross-server
identity, trust and blocklist propagation, abuse handling across administrative boundaries —
and it leaks metadata to *every* participating server, which sits badly against Cue's
metadata goals.

## Decision

v1 ships **independent Nodes**. An account lives on one Node and communicates with accounts
on that Node. Anyone can run a Node; the default one has no privileged position.

The design keeps federation possible without committing to it: addressing is internally
`handle@node`, identity keys are Node-independent, the wire protocol is versioned and
transport-agnostic, and key transparency is designed with cross-Node auditing in mind.

## Consequences

**Good:** a far smaller protocol to build, audit, and reason about. Metadata stays with one
operator rather than spreading. Abuse handling has one clear administrative authority.
Users understand it — it works like Discord or an email provider.

**Bad:** network effects fragment; your friends must be on your Node to talk to you. The
default Node will attract most users, which is centralisation by gravity even though the
software doesn't require it. If a Node dies, its Halls die with it.

**Mitigation:** account portability (`docs/10`) — export identity, contacts, and saved
messages; import on another Node keeping the same identity key. This provides the exit
rights that make choosing a Node reasonable, at a fraction of federation's cost, and is
the recommended long-term answer (`docs/12` Q7).

## Alternatives rejected

- **Full federation in v1:** the surface area would likely consume the whole project.
- **Federation of Halls:** every peer Node would hold a copy of the content *and* the
  membership — strictly worse privacy than one Node holding it. Ruled out permanently, not
  just deferred.
- **P2P with no servers:** unsolved for asynchronous delivery, mobile, and abuse handling.
