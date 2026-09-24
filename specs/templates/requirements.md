---
feature: NNN-slug
created: YYYY-MM-DD
updated: YYYY-MM-DD
status: draft
---

# Requirements: <Feature name>

`status` is one of `draft`, `approved`, `implemented`, `unverified`, `superseded`; see the
feature lifecycle in `CLAUDE.md`.

## Problem

What is missing or broken, for whom, and what it costs them today. Problem only, no
solution.

## Goal

One or two sentences on what is different for the user once this ships.

## Non-goals

What this deliberately does not do, and where that work lives instead if it is planned.
Bounds the change and prevents scope creep during implementation.

## User stories

One numbered story per distinct user need, each with its own acceptance criteria.

### Story 1: <short title>

As a `<role>`, I want `<capability>`, so that `<benefit>`.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-NNN.1`: WHEN `<trigger>`, the system SHALL `<observable response>`.
- `AC-NNN.2`: IF `<error condition>`, THEN the system SHALL `<observable response>`.

## Constraints

Non-functional requirements that shape the solution: latency and throughput budgets,
compatibility, accessibility, security and privacy obligations, operational limits. Give
numbers where numbers exist, since an unquantified constraint cannot be tested.

## Open questions

Unresolved items blocking approval. An open question here is a reason to ask rather than
assume.

## Change log

Amendments after approval, newest first. Records what implementation taught and why a
criterion changed, so the spec stays trustworthy.

- `YYYY-MM-DD`: <what changed and why>
