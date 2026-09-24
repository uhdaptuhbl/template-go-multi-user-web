---
feature: NNN-slug
created: YYYY-MM-DD
updated: YYYY-MM-DD
---

# Design: <Feature name>

How the approved requirements will be met. Free to change as implementation proceeds;
changing this file does not require amending `requirements.md`.

## Overview

The approach in a short paragraph, and which acceptance criteria it satisfies.

## Alternatives considered

Each option weighed, with the reason it was not chosen. Include doing nothing where that is
a real option. A design with no rejected alternatives has usually not been designed.

| Option | Trade-off | Verdict |
| --- | --- | --- |

If a rejected alternative is a decision that will outlive this feature, record an ADR in
`docs/adr/` and link it here rather than burying it in a feature spec.

## Architecture

Components touched or added, and how they fit the existing system. Packages, ownership, and
dependency direction. Diagrams as fenced ASCII where they clarify.

## Interfaces

Public surfaces this introduces or changes: HTTP endpoints with methods, status codes, and
payload shapes; exported Go types and functions; frontend component contracts. Specify
error responses, not just success paths.

## Data

Schema additions or migrations, persisted shapes, retention, and indexing. State the
migration and rollback path for anything that changes existing data.

## Failure modes

What can fail, how the system detects it, and what the user sees. Timeouts, retries and
their limits, partial failure, and what is deliberately left to fail loudly.

## Security and privacy

Trust boundaries crossed, authentication and authorization decisions, input validation
points, and any personal data handled.

## Test strategy

Which layer of the pyramid covers which criteria, and why anything is tested higher than
unit level. Name the test doubles required and the process boundary each stands in for.

## Observability

Logs, metrics, and traces added, and the specific question each one answers in production.
