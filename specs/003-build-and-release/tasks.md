---
feature: 003-build-and-release
created: 2026-09-17
updated: 2026-09-19
---

# Tasks: Build and release

Ordered decomposition of the design into increments. Each task is independently verifiable,
small enough to complete in one sitting, and cites the acceptance criteria it advances. Each
is built test-first.

Order tasks so the suite is green at every boundary; no task should depend on a later one.

## Checklist

- [x] **T1** Add the `tool` directive pinning mage to `go.mod` and create `magefile.go` at
      the repository root with the `//go:build mage` constraint, defining the `Build`,
      `Test`, `Race`, `Lint`, `Cover`, `Vuln`, `Tidy`, `Docker`, `Run`, and `Clean` targets.
  - Satisfies: `AC-003.1`
  - Verify: `go tool mage -l`

- [x] **T2** Add `main.version`, `main.commit`, and `main.buildDate` variables to
      `cmd/service`, defaulting to `dev` and `unknown`, and wire `Build` in `magefile.go`
      to stamp them via `-ldflags -X`.
  - Satisfies: `AC-003.2`, `AC-003.3`
  - Verify: `go tool mage build && timeout 2s ./bin/service 2>&1 | head -1` reports a non-`dev` version, git commit, and build date in the `build information` entry; `go build ./cmd/service && timeout 2s ./service 2>&1 | head -1` reports version `dev`

- [x] **T3** Write the two-stage `Dockerfile`: `golang:1.27-bookworm` builder stage with
      `CGO_ENABLED=0`, runtime stage on `gcr.io/distroless/static-debian12:nonroot`
      running as `nonroot:nonroot`, exposing `8080`.
  - Satisfies: `AC-003.4`
  - Verify: `docker build -t service:spec-check .`, then `docker run --rm --entrypoint sh service:spec-check -c true` fails with `"sh": executable file not found in $PATH` because no shell exists in the image, and `docker inspect service:spec-check --format '{{.Config.User}}'` reports `nonroot`. The entrypoint override is required: without it the arguments are passed to the binary, which ignores them and starts the server

- [x] **T4** Configure the application's default listener addresses so the process binds
      the application listener on `:8080` and the administrative listener on
      `127.0.0.1:9090` when no environment variable overrides them, and confirm the
      container entrypoint runs with no environment set.
  - Satisfies: `AC-003.7`
  - Verify: `docker run --rm -p 8080:8080 -d --name spec-check service:spec-check && sleep 1 && curl -sf http://localhost:8080/ ; docker exec spec-check sh -c "true" ; docker stop spec-check` (container must serve on 8080 with no environment set; the administrative port must not be reachable from outside the container's network namespace)

- [x] **T5** Add `.github/workflows/ci.yml` with `lint`, `test`, `build`, `tidy`, and
      `vuln` jobs, triggered on push to `main` and on pull requests against `main`.
  - Satisfies: `AC-003.5`
  - Verify: `golangci-lint run && go test -race ./... && go test -race -tags=integration ./... && go tool mage build && govulncheck ./...` (the same commands the workflow runs) all exit `0`

- [x] **T6** Add the `tidy` job's check to `.github/workflows/ci.yml`: run `go mod tidy`
      then fail the job if `go.mod` or `go.sum` changed.
  - Satisfies: `AC-003.6`
  - Verify: `go mod tidy && git diff --exit-code go.mod go.sum`

- [x] **T7** Add a `container` job to `.github/workflows/ci.yml` that builds the image and
      asserts the properties `AC-003.4` and `AC-003.7` describe: the configured user, the
      absence of a shell, the application listener answering on `:8080` with no environment
      set, the administrative port being unreachable from outside the container, and the
      administrative endpoints answering once `SERVICE_ADMIN_ADDR` binds an interface.
  - Satisfies: `AC-003.4`, `AC-003.7`
  - Verify: the `container` job passes. It supersedes the hand-run commands under T3 and T4
    as the citation for both criteria, because a command nobody runs verifies nothing: two
    of the three written there did not test what they claimed.

## Traceability

| Criterion | Tasks | Test |
| --- | --- | --- |
| `AC-003.1` | T1 | `go tool mage -l` |
| `AC-003.2` | T2 | `go tool mage build && ./bin/service`, reading the `build information` start-up entry |
| `AC-003.3` | T2 | `go build ./cmd/service && ./service`, reading the same entry |
| `AC-003.4` | T3, T7 | The `container` job in `ci.yml`: `docker inspect` user check and `--entrypoint sh` no-shell check |
| `AC-003.5` | T5 | `golangci-lint run && go test -race ./... && go tool mage build && govulncheck ./...` |
| `AC-003.6` | T6 | `go mod tidy && git diff --exit-code go.mod go.sum` |
| `AC-003.7` | T4, T7 | The `container` job in `ci.yml`: `curl` against `:8080` with no environment set, and the admin port unreachable from outside |

## Deferred

Release automation (tagging, publishing images to a registry, changelog generation) and
multi-architecture image builds are out of scope per `requirements.md`'s non-goals; they
would need their own feature spec if taken up later.
