---
status: proposed
date: 2026-09-15
---

# 2. Frontend stack

**This decision is open.** It is recorded as `proposed` so the options and their trade-offs
are in version control rather than in conversation. Do not build frontend code against an
assumed stack before this is accepted.

## Context and Problem Statement

This project is a Go backend serving a browser-based UI. The frontend framework choice
determines the build toolchain, the testing tools, the shape of the backend's HTTP contract,
and how much of the rendering logic lives in Go versus JavaScript. It is expensive to
reverse once components exist.

The testing standards in `CLAUDE.md` already name Vitest, Testing Library, and Playwright in
the test pyramid. Those are placeholders pending this decision and carry no weight until it is
accepted.

## Decision Drivers

- Product shape is not yet defined. How much client-side interactivity the service actually
  needs is the dominant input and is currently unknown.
- Team size, which sets how much toolchain complexity is affordable. On a small team the total
  cost is real rather than abstract; a larger one can absorb more and should weigh this driver
  lower, or strike it.
- Possible open-sourcing, which favours a stack outside contributors already know.
- Must support the testing standards: unit-testable components and a driveable end-to-end
  layer.
- Determines the JSON field-naming convention, which is currently set to `snake_case` by
  `tagliatelle` in `.golangci.yaml` and should be decided together with this.

## Considered Options

- React with TypeScript, built with Vite
- Svelte or SvelteKit
- Vue 3 with TypeScript, built with Vite
- Server-rendered Go templates with HTMX, minimal hand-written JavaScript

## Decision Outcome

Not yet decided.

This record is inherited open on purpose. A template cannot know what the service built from
it will need, and choosing a client-side framework before knowing whether the product needs
one is how projects acquire a build pipeline they do not use. So the decision travels with
its analysis rather than being made on a future project's behalf, and each project closes it
for itself.

Closing this ADR requires all of the following:

1. The first feature spec of the service built from this template is approved, and its
   criteria make the required degree of client-side state explicit. The specs this template
   ships with, `001-` through `008-`, describe the template's own behaviour and specify only
   the server and its JSON API, so they do not satisfy this condition; the first that can is
   the project's own, numbered `009-` or later.
2. A stack is chosen from the options below, and the Vitest and Testing Library references in
   the `CLAUDE.md` test pyramid are either confirmed or replaced.
3. **The handling of built frontend assets is settled**: whether the output the frontend build
   writes into `internal/web/dist/` is committed, so a clean clone builds without a frontend
   toolchain, or ignored and produced by CI. Only `index.html` is tracked today, as a
   placeholder that keeps `go:embed` satisfiable. Related: whether unmatched paths should fall
   back to `index.html` for client-side routing, which `internal/web` currently does not do.
4. **The JSON field-naming convention is settled**, because it is the wire contract between
   the Go backend and whatever consumes it. `.golangci.yaml` currently sets
   `tagliatelle.case.rules.json: snake`, inherited rather than chosen. A JavaScript framework
   argues for `camel`, since camelCase is the convention on the consuming side and avoids a
   transformation layer; the server-rendered option makes the question nearly moot for the UI.
   Renaming JSON fields after clients exist is a breaking change, so this is decided here and
   not later. The `/api/v1` routes added by `specs/008-users-and-auth/` already ship
   `snake_case` members, so choosing `camel` means renaming them. That rename is cheap only
   until the service built from this template ships a release or a frontend that consumes
   them.

## Pros and Cons of the Options

### React with TypeScript and Vite

- Good: largest ecosystem and contributor pool, which matters most if this is open sourced.
- Good: Testing Library and Playwright support is the best-documented of any option.
- Bad: the most boilerplate and the largest dependency surface to keep patched.

### Svelte or SvelteKit

- Good: least ceremony per component and smaller shipped bundles.
- Good: compiles away, so runtime overhead is minimal.
- Bad: smaller contributor pool. SvelteKit also wants to own routing and server rendering,
  which overlaps awkwardly with a Go backend that already does both.

### Vue 3 with TypeScript and Vite

- Good: gentler learning curve than React, with a coherent first-party tooling story.
- Bad: ecosystem is smaller than React's without being meaningfully simpler than Svelte.

### Server-rendered Go templates with HTMX

- Good: no JavaScript build pipeline, no `node_modules`, one language for all logic, and the
  test pyramid collapses almost entirely into Go tests.
- Good: by far the lowest maintenance burden, which counts for most where there are fewest
  people to carry it.
- Bad: hits a wall if the product needs genuinely rich client-side state, and the wall is
  expensive to discover late.
- Bad: contradicts the current `.gitignore` and the "browser-based JavaScript frontend"
  framing in `CLAUDE.md`, both of which would need updating. Neither is a real obstacle: both
  were written before this decision was examined.

## More Information

The server-rendered option has the widest blast radius on files that already exist: it would
mean rewriting the frontend column of the `CLAUDE.md` test pyramid, dropping the JavaScript
entries from `.gitignore`, and revising the "browser-based JavaScript frontend" framing at the
top of `CLAUDE.md`. The three framework options leave all of that intact, which is a reason to
examine the assumption rather than a reason to keep it.
