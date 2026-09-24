---
feature: 003-build-and-release
created: 2026-09-17
updated: 2026-09-24
---

# Design: Build and release

How the approved requirements will be met. Free to change as implementation proceeds;
changing this file does not require amending `requirements.md`.

## Overview

A `magefile.go` at the repository root defines the task-runner targets in ordinary Go,
invoked as `go tool mage <target>`, pinned by a `tool` directive in `go.mod`. `Build`
compiles `cmd/service` with `-ldflags -X` stamping `main.version`, `main.commit`, and
`main.buildDate`; an unstamped build reports `dev`. This satisfies `AC-003.1`, `AC-003.2`,
and `AC-003.3`. A two-stage `Dockerfile` compiles a `CGO_ENABLED=0` binary on
`golang:1.27-bookworm` and copies it into `gcr.io/distroless/static-debian12:nonroot`,
running as `nonroot:nonroot` with no shell present, and the process binds its default
listeners on `:8080` and `127.0.0.1:9090` when no environment overrides them. This
satisfies `AC-003.4` and `AC-003.7`. `.github/workflows/ci.yml` runs lint, test, build,
tidy, and vuln jobs on every push to `main` and every pull request against it, satisfying
`AC-003.5` and `AC-003.6`. (The workflow has since grown a `container` job and a
`release-config` job, added by `specs/004-release-automation/`; those are out of this
feature's scope and covered there.)

Why mage is consumed through a `go.mod` `tool` directive rather than installed globally,
why the magefile carries `//go:build mage`, and why the runtime image is distroless are
settled in `docs/adr/0009-build-and-release-tooling.md`; this document does not restate
that argument.

## Alternatives considered

| Option | Trade-off | Verdict |
| --- | --- | --- |
| `mage` via `go.mod` tool directive | Targets are Go, get compile-time checking and lint for free, and are pinned per-module; adds one concept a contributor must learn | Chosen |
| `Makefile` | Universally available, but shell quoting and tab sensitivity are a recurring source of subtle breakage, and it gets no type checking or linting | Rejected |
| `just` | Simpler syntax than `make` with no tab sensitivity, but is an extra binary every contributor must install that Go does not already ship | Rejected |
| Plain `go` commands invoked directly in CI, no local entry point | Zero additional tooling, but local and CI then drift, which is the exact failure mode CI exists to prevent; a contributor cannot reproduce a CI failure locally with the same command | Rejected |

See `docs/adr/0009-build-and-release-tooling.md` for the full decision record.

## Architecture

```
repository root
  magefile.go          //go:build mage; defines Build, Test, Race, Lint, Cover, Vuln,
                        Tidy, Docker, Run, Clean
  go.mod                tool directive pins the mage version
  Dockerfile            two-stage build: golang:1.27-bookworm -> distroless/static-debian12:nonroot
  cmd/service/           entrypoint; main.version, main.commit, main.buildDate vars stamped
                        by -ldflags -X, defaulting to "dev" and "unknown"
  .github/workflows/
    ci.yml              lint, test, build, tidy, vuln jobs
```

The magefile depends only on the standard library and the mage API; it does not import
application packages, so it can build and run even if `cmd/service` fails to compile for an
unrelated reason (for example, while `Lint` or `Tidy` are being exercised in isolation).

## Interfaces

Task-runner targets, each an exported Go function in `magefile.go`, run as
`go tool mage <target>`:

- `Build` -- compiles `cmd/service` to a local binary, stamping version metadata.
- `Test` -- runs `go test ./...`.
- `Race` -- runs `go test -race ./...` and `go test -race -tags=integration ./...`.
- `Lint` -- runs `go tool golangci-lint run`, the version pinned in `go.mod` (since `specs/005-service-scaffolding/`).
- `Cover` -- runs the unit test suite with coverage profiling enabled.
- `Vuln` -- runs `govulncheck ./...`.
- `Tidy` -- runs `go mod tidy` and fails if it changes `go.mod` or `go.sum`.
- `Docker` -- builds the container image via `docker build`.
- `Run` -- builds and runs the binary locally.
- `Clean` -- removes build artifacts.

Container image: exposes `8080` (application) and `9090` (administrative, bound to
`127.0.0.1` only), entrypoint is the compiled binary, no shell, user `nonroot`.

CI workflow (`.github/workflows/ci.yml`), triggered on push to `main` and on pull requests
against `main`:

- `lint` -- `go tool mage lint`, the same pinned linter a contributor runs.
- `test` -- `go test -race ./...` then `go test -race -tags=integration ./...`.
- `build` -- `go tool mage build`.
- `tidy` -- `go mod tidy` followed by `git diff --exit-code go.mod go.sum`.
- `vuln` -- `govulncheck ./...`.

Each job fails the workflow run on a non-zero exit; there is no job that can fail silently.

## Data

No persisted schema or data migration is introduced by this feature.

## Failure modes

- A missing or misconfigured `tool` directive causes `go tool mage` to fail immediately
  with a clear error rather than silently falling back to a different mage version.
- `Tidy` failing locally or in CI means `go.mod`/`go.sum` drifted from the import graph;
  the fix is to run `go mod tidy` and commit the result, not to loosen the check.
- A `Docker` build failure on the `golang:1.27-bookworm` stage fails loudly at compile
  time; there is no fallback runtime image, since a shell-bearing fallback would defeat the
  purpose of the distroless final stage.
- If the administrative listener is reachable from outside `127.0.0.1`, that is a
  configuration error the operator introduced by overriding the default; the default itself
  keeps it loopback-only.

## Security and privacy

The distroless runtime image has no shell and no package manager, so a code-execution
vulnerability in the application cannot be escalated into interactive shell access inside
the container. Running as `nonroot:nonroot` means a container breakout does not hand an
attacker root on the host. The administrative listener defaults to `127.0.0.1:9090`, so
metrics and profiling endpoints are not reachable from outside the container's network
namespace unless an operator deliberately republishes that port. `Vuln` (`govulncheck`)
and the CI `vuln` job catch known vulnerabilities in the dependency graph before merge. No
personal data is handled by the build or release tooling itself.

## Test strategy

- Unit level: none of these targets have meaningful unit tests of their own, since they are
  thin wrappers over `go`, `docker`, and `golangci-lint` invocations; their correctness is
  verified by running them directly (see `tasks.md`).
- Integration level: `go tool mage build` run in CI is itself the integration check that
  the magefile, `go.mod` tool directive, and the module compile together correctly.
- End-to-end level: `docker build` producing a runnable image, followed by starting a
  container with no environment set and confirming the two listeners bind where
  `AC-003.7` requires, is the end-to-end check for the container image.
- CI workflow correctness is verified by inspecting job definitions and, where practical,
  by a local dry run of the same commands the workflow invokes.

## Observability

No new logs, metrics, or traces are added by the build pipeline itself. The stamped
version, commit, and build date (`AC-003.2`, `AC-003.3`) are the one piece of
build-time observability this feature adds: they let an operator identify exactly what is
running in production from the binary or the running process alone.
