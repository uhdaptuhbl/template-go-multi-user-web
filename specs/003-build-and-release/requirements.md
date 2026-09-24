---
feature: 003-build-and-release
created: 2026-09-17
updated: 2026-09-24
status: implemented
---

# Requirements: Build and release

## Problem

The repository has no build entry point, no container image, and no CI. A contributor
builds and tests by remembering the right `go` invocations, and nothing checks that a
change still builds, lints, or passes tests before it merges. A pushed binary cannot say
what version it is, and there is no container image to run it in. Every build step a
contributor works out by hand and writes into a README instead of a runnable target is a
step the next contributor can silently skip, and a step CI cannot enforce.

## Goal

A contributor runs the same small set of task-runner targets locally that CI runs on every
push or pull request against `main`, the built binary can report its own version, and the
container image that ships it runs as a non-root user with no shell.

## Non-goals

This does not cover release automation (tagging, publishing images to a registry,
generating changelogs) or multi-architecture image builds. It does not select or configure
a deployment platform. Those are separate, later decisions.

## User stories

### Story 1: Contributor runs one command to build, test, and check the code

As a `contributor`, I want a small set of task-runner targets, so that I do not need to
remember or hand-assemble the right `go` invocations for building, testing, and checking
the codebase.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-003.1`: The build SHALL provide the targets `Build`, `Test`, `Race`, `Lint`, `Cover`, `Vuln`, `Tidy`, `Docker`, `Run`, and `Clean`.
- `AC-003.2`: WHEN `Build` runs, the build SHALL stamp the version, the git commit, and the build date into the binary through linker flags.
- `AC-003.3`: IF a binary is built without those flags, THEN it SHALL report its version as `dev`.

### Story 2: Operator runs a minimal, non-root container image

As an `operator`, I want the shipped container image to run as a non-root user with no
shell, so that a compromise of the process cannot pivot into a shell or a package manager
inside the container.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-003.4`: The container image SHALL run as a non-root user and SHALL contain no shell.
- `AC-003.7`: WHEN the container image runs with no environment set, the process SHALL bind the application listener on `:8080` and the administrative listener on `127.0.0.1:9090`.

### Story 3: Maintainer trusts that a merged change passed lint, tests, and a vulnerability scan

As a `maintainer`, I want every change pushed to or proposed against `main` to be checked by
CI, so that "it builds on my machine" is never the only gate a change passes through.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-003.5`: WHEN a change is pushed to `main` or proposed against it, CI SHALL run lint, unit tests with the race detector, a build, and a vulnerability scan, and SHALL fail if any of them fails.
- `AC-003.6`: CI SHALL fail if `go.mod` or `go.sum` is not tidy.

## Constraints

- The task runner and its version must be reproducible without a global install step: a
  contributor with only the Go toolchain installed must be able to run every target.
- The runtime container image must not include a shell or a package manager.
- Local task-runner targets and CI steps must run the same underlying commands, so that a
  failure discovered in CI is reproducible locally with the same command.
- CI must run on every push to `main` and on every pull request proposed against `main`.

## Open questions

None. See `docs/adr/0009-build-and-release-tooling.md` for the settled tooling choice.

## Change log

Amendments after approval, newest first.

- `2026-09-17`: Implementation complete; every criterion is cited by a passing test.
- `2026-09-17`: Initial version, approved.
