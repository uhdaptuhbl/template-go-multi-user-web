---
status: accepted
date: 2026-09-15
---

# 1. Record architecture decisions

## Context and Problem Statement

This project uses specification-driven development, so feature behavior is captured in
`specs/NNN-slug/`. That structure has no home for decisions that outlive a single feature:
which database, how authentication works, how the frontend talks to the backend. Recorded
only in commit messages or chat, the reasoning is lost, and a later contributor cannot tell
a deliberate constraint from an accident. The cost lands as decisions silently reversed and
rediscovered.

## Decision Drivers

- Cross-cutting decisions need a home that is not tied to one feature's lifecycle.
- Rationale must survive after the people and conversations are gone.
- The overhead must be low enough that it actually gets done.

## Considered Options

- Architecture Decision Records in `docs/adr/`, MADR template.
- A single long-lived architecture document.
- No formal record; rely on commit messages and code comments.

## Decision Outcome

Chosen: **Architecture Decision Records in `docs/adr/`, using the MADR template.**

One file per decision, numbered sequentially, committed alongside the change it justifies. A
record is written when a decision is costly to reverse or when a future reader would
reasonably ask why it was made. Accepted records are immutable; a changed decision gets a new
record that supersedes the old one, and the old one is marked superseded with a link forward.

### Consequences

- Good: rationale is versioned next to the code, and reviewable in the same pull request.
- Good: the immutable log preserves why a rejected option was rejected, so it is not
  relitigated from scratch.
- Bad: adds a step to architectural changes, and records go stale if superseding is skipped.

## Pros and Cons of the Options

### ADRs in `docs/adr/`

- Good: decision-scoped, so no merge contention on a shared document.
- Good: widely understood convention, with tooling available.
- Bad: requires discipline to supersede rather than quietly edit.

### Single architecture document

- Good: one place to read the current state.
- Bad: loses history, since edits overwrite the reasoning that produced them.
- Bad: becomes a merge bottleneck and drifts from the code.

### No formal record

- Good: zero overhead.
- Bad: the failure mode this ADR exists to prevent. Commit messages are not discoverable by
  topic, and code comments explain what, not why this over that.

## More Information

- [Documenting Architecture Decisions, Michael Nygard](https://www.cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
- [MADR: Markdown Any Decision Records](https://adr.github.io/madr/)
