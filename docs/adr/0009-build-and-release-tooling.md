---
status: accepted
date: 2026-09-17
---

# 9. Build and release tooling

## Context and Problem Statement

The repository has no build entry point, no container image, and no CI. A contributor builds
and tests by remembering the right `go` invocations, and nothing checks that a change still
builds or passes lint before it merges. "It builds on my machine" is the only gate that
exists. That gap grows more expensive the longer it is left: every additional build step
(version stamping, lint, cross-compilation, image assembly) that gets added ad hoc to a
README instead of to a runnable target is a step a contributor can silently skip.

The choice of task runner and packaging format is not free to reverse once contributors and
CI both depend on it: CI workflows, container build steps, and any release automation all
call through whatever is chosen here.

## Decision Drivers

- Contributors already need Go; a second required toolchain (`make`, a shell-script runner)
  is an avoidable dependency.
- Targets should be checked by the same tools that check the rest of the codebase, not
  hand-verified shell.
- The runtime artifact should minimize attack surface: no shell, no package manager, no
  unnecessary files.
- Local and CI must run the same commands, or they drift apart and CI stops meaning anything.
- A running binary should be able to report its own version, commit, and build date.

## Considered Options

- `mage`, consumed through a `tool` directive in `go.mod`
- A `Makefile`
- `just`
- Plain `go` commands invoked directly in CI, with no local entry point

## Decision Outcome

Chosen: **mage as the task runner, consumed through a `tool` directive in `go.mod`; a
distroless multi-stage container image; GitHub Actions for CI.**

### Consequences

- Targets are written in Go rather than shell, so they are cross-platform, type-checked, and
  lintable by the same toolchain as the rest of the project. Contributors already need Go;
  they do not additionally need `make`.
- mage is invoked as `go tool mage <target>` via a `tool` directive, so no global install is
  required and the version is pinned in `go.mod`.
- The magefile carries the `//go:build mage` constraint, so it is excluded from ordinary
  builds.
- The runtime image is `gcr.io/distroless/static-debian12:nonroot`: no shell, no package
  manager, non-root by default. A shell in the runtime image is a debugging convenience that
  is also an attacker's first tool.
- Version, commit, and build date are stamped with `-ldflags -X`, so a running process can
  report what it is. An unstamped build reports `dev`.

## Pros and Cons of the Options

### mage (chosen)

- Good: targets are ordinary Go functions, so they get compile-time checking, `go vet`, and
  `golangci-lint` for free.
- Good: no shell quoting, no tab-versus-space sensitivity, no second language to maintain.
- Good: the `tool` directive in `go.mod` pins the version and needs no global install step.
- Bad: a contributor unfamiliar with mage has one more thing to learn, even though it is
  plain Go.

### Makefile

- Bad: shell quoting and tab sensitivity are a recurring source of subtle breakage.
- Bad: a second language to maintain, with no type checking and no linting from the rest of
  the toolchain.
- Good: near-universally available and understood.

### just

- Good: simpler syntax than `make`, without `make`'s tab sensitivity.
- Bad: an extra binary every contributor must install; not something Go already ships.

### Plain go commands in CI, no local entry point

- Good: zero additional tooling.
- Bad: local and CI then drift, which is the failure mode CI exists to prevent. A contributor
  who cannot run the exact CI steps locally discovers a failure only after pushing.

## More Information

- [mage](https://magefile.org/)
- [Go tool directives](https://go.dev/ref/mod#tool-directive)
- [Distroless images](https://github.com/GoogleContainerTools/distroless)
