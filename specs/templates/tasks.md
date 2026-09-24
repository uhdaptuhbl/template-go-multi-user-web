---
feature: NNN-slug
created: YYYY-MM-DD
updated: YYYY-MM-DD
---

# Tasks: <Feature name>

Ordered decomposition of the design into increments. Each task is independently verifiable,
small enough to complete in one sitting, and cites the acceptance criteria it advances. Each
is built test-first.

Order tasks so the suite is green at every boundary; no task should depend on a later one.

## Checklist

- [ ] **T1** `<imperative description>`
  - Satisfies: `AC-NNN.1`
  - Verify: `<exact command that proves it, e.g. go test ./internal/foo -run TestBar>`
- [ ] **T2** `<imperative description>`
  - Satisfies: `AC-NNN.2`, `AC-NNN.3`
  - Verify: `<exact command>`

## Traceability

Every criterion appears at least once, confirming nothing was dropped in decomposition.

| Criterion | Tasks | Test |
| --- | --- | --- |
| `AC-NNN.1` | T1 | `<test name>` |

## Deferred

Work identified during implementation but deliberately not done here, with where it went:
a new feature spec, an ADR, or an issue. Keeps scope honest without losing the finding.
