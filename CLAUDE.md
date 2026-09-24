<!--
created: 2026-09-15
updated: 2026-09-23
-->

# Engineering Standards

Go backend, browser-based JavaScript frontend.

This file is the project constitution: the standards every change is held to. Feature intent
lives in `specs/`, architecture rationale in `docs/adr/`. This file states policy and does
not restate either.

## Development Model

Specification-driven development (SDD) and test-driven development (TDD) operate at
different scales and compose without conflict:

- **SDD at feature scale.** A feature is specified, designed, and decomposed into tasks
  before implementation begins. Follows the three-document pattern common to GitHub Spec Kit
  and AWS Kiro: requirements, design, tasks.
- **TDD at task scale.** Each task from the decomposition is built red/green/refactor.

The two are joined by **requirement traceability**: every acceptance criterion carries a
stable ID, every task cites the IDs it satisfies, and every ID is cited by at least one
test. A criterion no test cites is unimplemented by definition. The one exception is a
criterion about a built artifact or a pipeline rather than the running code, such as an
image's base layer or a signature on a release: no unit test can observe it, so its
`tasks.md` names the command that verifies it instead, and that command is the citation.

### Feature lifecycle

| Phase | Artifact | Exit gate |
| --- | --- | --- |
| 1. Requirements | `specs/NNN-slug/requirements.md` | Criteria are unambiguous, testable, and ID'd |
| 2. Design | `specs/NNN-slug/design.md` | Approach, interfaces, and data flow settled; alternatives considered |
| 3. Tasks | `specs/NNN-slug/tasks.md` | Each task is small, ordered, and cites criterion IDs |
| 4. Implement | Code and tests | TDD per task; CI green |
| 5. Close | Updated `requirements.md` | Criteria match shipped behavior; `status: implemented`, or `unverified` where one cannot yet be observed |

A `requirements.md` carries a `status` in its front matter, one of:

| Status | Meaning |
| --- | --- |
| `draft` | Being written. Criteria are not yet agreed and may change without notice. |
| `approved` | Criteria are agreed. Implementation has not started, or is in progress. |
| `implemented` | Every criterion has been observed to hold. |
| `unverified` | Merged and believed complete, but at least one criterion has never been observed, because observing it requires an event that has not happened. |
| `superseded` | Replaced by a later spec, which the record names. |

`unverified` exists because "the code is written" and "the criteria were observed" are
separate claims, and collapsing them is how a spec comes to describe software nobody has
run. It is not a softer `implemented`: it names which criteria are unobserved and what
would observe them, so the gap is a known quantity rather than an assumption. A release
pipeline is the ordinary case, since its criteria cannot be observed until a tag is pushed.
Move the record to `implemented` once that event has occurred and the criteria held.

Features are numbered sequentially (`001-`, `002-`) in directory names to keep chronology
readable. A trivial change (typo, dependency bump, one-line fix) needs no spec. Exploratory
spikes need no spec or tests, but spike code is deleted rather than promoted.

Requirements and design are written before code, not reconstructed after. When
implementation proves a requirement wrong, amend `requirements.md` and say why in its
change log; do not leave the spec describing software that does not exist.

### Requirements notation

Acceptance criteria use **EARS** (Easy Approach to Requirements Syntax), which constrains
each requirement to one of five sentence patterns and eliminates most requirement ambiguity:

| Pattern | Form |
| --- | --- |
| Ubiquitous | The system SHALL `<response>` |
| Event-driven | WHEN `<trigger>`, the system SHALL `<response>` |
| State-driven | WHILE `<state>`, the system SHALL `<response>` |
| Unwanted behavior | IF `<condition>`, THEN the system SHALL `<response>` |
| Optional feature | WHERE `<feature is included>`, the system SHALL `<response>` |

Criterion IDs are `AC-<feature number>.<n>`, for example `AC-001.3`. IDs are never reused or
renumbered once implemented; a withdrawn criterion is struck and left in place.

Requirements state observable behavior only. No function names, no schemas, no
implementation steps: those belong in `design.md`, which is free to change without touching
requirements.

## Code Standards

### Go

Idiomatic Go per Effective Go and the Google Go Style Guide, with one deliberate deviation
noted first. `gofmt` output is not negotiable.

- **One declaration per line.** No grouped `var ( ... )` or `const ( ... )` blocks: each
  variable and constant takes its own keyword on its own line, keeping every diff
  attributable to a single declaration. Grouped `import` blocks are standard and expected.
  This is the project's one intentional departure from common Go idiom.
- **Short variable declarations (`:=`) are fine** wherever they read well, per standard Go
  practice. Do not use one that shadows a variable from an enclosing scope.
- **Handle every error explicitly.** Never discard one on a production path, whether with `_`
  or by leaving it unchecked. The exception is a call whose error carries nothing to act on,
  such as `Close` on a handle that was only read, or `Sync` on a terminal-backed logger: discard
  it with a `//nolint:errcheck` that names the reason, so a deliberate discard reads differently
  from a forgotten check. `Close` on anything written to is never discarded, because that is
  where a buffered-write failure surfaces. Wrap when propagating, with context naming the
  operation: `fmt.Errorf("fetching manifest: %w", err)`.
- **No global mutable state.** Pass dependencies (logger, config, clients) explicitly via
  struct fields or function arguments. This is also what makes the code testable with real
  collaborators instead of mocks.
- **`context.Context` first parameter** on anything that crosses a goroutine boundary,
  performs I/O, or can block. Propagate it; never store it in a struct.
- **Always take the context-aware form of an API that offers one.** `http.NewRequestWithContext`
  over `http.NewRequest`, `net.ListenConfig.Listen` and `net.Dialer.DialContext` over
  `net.Listen` and `net.Dial`, `exec.CommandContext` over `exec.Command`, `QueryContext` and
  `ExecContext` over `Query` and `Exec`. The context-free form is the same call with cancellation
  removed: it either cannot be interrupted at all or substitutes `context.Background()` inside,
  so a shutdown that should take milliseconds instead waits out a dial, a query, or a DNS
  lookup nobody can reach. This holds in tests too, where `t.Context()` is already cancelled at
  cleanup and is the context to pass. `noctx` flags every context-free form named here, along
  with the `net` lookup and `crypto/tls` dial functions, though `.golangci.yaml` currently
  exempts test files from it, so the test half of this rule is caught in review.
- **Log through `go.uber.org/zap`,** using its typed field API and injected as a dependency.
  Not `logrus`, not the standard `log` package, and not `log/slog` in application code:
  `depguard` denies all three. Two packages are excepted, each with a recorded reason and no
  logging of their own: `internal/logging` bridges dependency `slog` records into the same zap
  core so they reach the same sink, and `internal/secret` needs `slog.LogValuer` to redact
  secrets, because `slog` does not consult `fmt.Stringer` for a string-kinded value. Rationale
  in `docs/adr/0003-use-uber-zap-for-logging.md` and `docs/adr/0006-configuration-loading.md`.
- **No `fmt.Print*` and no builtin `print`/`println`,** enforced by `forbidigo`. They write to
  stdout and stderr with no level, no fields, and no correlation ID. `fmt.Errorf`,
  `fmt.Sprintf`, and `fmt.Fprintf` to an explicit writer remain correct and expected.
- **Instrument through OpenTelemetry.** Spans via `go.opentelemetry.io/otel/trace`, metrics via
  the OpenTelemetry metric API. Not `prometheus/client_golang` for instrumentation: it is
  permitted only for the metrics registry and the exposition handler in `internal/telemetry`.
  Providers are passed in like any other dependency, never read from the `otel` package's
  globals: `internal/telemetry` hands back what it built and the caller wires it through. The
  one exception is `otel.SetErrorHandler`, which the SDK offers no non-global alternative to.
  Tracing is off unless a collector endpoint is configured, so instrumentation must stay correct
  and cheap when the provider it is given is the no-op one. Rationale in
  `docs/adr/0004-use-opentelemetry-for-tracing.md` and
  `docs/adr/0005-use-opentelemetry-metrics-with-prometheus.md`.
- **Operational endpoints belong on the administrative listener,** not the application one.
  Metrics, profiling, and anything else that describes the process rather than serving a user
  goes there, because metric and route names disclose more than the public port should.
- **No `init()` functions.** They hide initialization order and cannot be tested directly.
- **No named return values.** Naked returns obscure what is actually returned.
- **Small, single-purpose functions.** Flat composition over deep nesting; return early.
- **Doc comments on every exported symbol,** written as full sentences that begin with the
  symbol name and end with a period. Describe purpose and behavior: restating the name is
  not documentation.
- **Package documentation lives in `doc.go`** for every package under `internal/` and
  `pkg/`, containing the package clause and its doc comment and nothing else.
- **`golangci-lint` passes** against `.golangci.yaml` at the repository root.

#### Concurrency

- **Default to `golang.org/x/sync/errgroup` whenever the goroutines can fail.** It propagates
  the first error back to the caller and, constructed with `errgroup.WithContext`, cancels the
  remaining goroutines the moment one of them fails, so a doomed fan-out stops paying for work
  whose result is already going to be discarded. `SetLimit` bounds the pool where the work is
  wide enough that unbounded goroutines would matter. It is in the `depguard` allow list,
  scoped to `errgroup` rather than all of `x/sync`; the module joins `go.mod` on the first real
  import, because `go mod tidy` drops a module nothing imports.
- **Honor the derived context in every goroutine.** Cancellation is cooperative: a bare
  `errgroup.Group`, or one whose goroutines never check `ctx.Err()`, gives up the cancellation
  half of the type and waits for all of them regardless, which is the behavior a `WaitGroup`
  would already have given you. Call `SetLimit` before the first `Go`, never while goroutines
  are running. Call `Wait` exactly once, on every path, and never discard its error.
- **`Wait` returns only the first non-nil error; the rest are dropped.** That is the right
  trade when the errors are variations on the same failure. Where each goroutine's failure is
  independently meaningful, have each one record its own error in a pre-sized slice slot,
  return nil to the group, and `errors.Join(errs...)` after `Wait` so nothing is lost. A slot
  per goroutine needs no mutex.
- **Use `sync.WaitGroup.Go` for fan-out that cannot fail,** and for long-lived goroutines whose
  shutdown is driven by a context or a closed channel rather than by an error. Start them with
  `WaitGroup.Go`, not `wg.Add(1)` plus a `go func()` that `defer wg.Done()`: one call cannot
  drift out of balance with the other. Manual `Add`/`Done` pairs are acceptable only where the
  count is genuinely not one-per-goroutine.
- **The function handed to `WaitGroup.Go` must not panic.** It has no recovery of its own, so a
  panic there takes the process down rather than failing one request. `errgroup.Group.Go` gives
  you no recovery either. Anything that can panic recovers inside its own goroutine and
  converts the panic into an error, the way `internal/server/recovery.go` does for handlers.
- **Every goroutine has a bounded lifetime.** It ends because its work is done, because a
  context it honors was cancelled, or because a channel it reads was closed. A goroutine whose
  exit no one waits on is a leak.
- **One goroutine is exempt: the one whose whole job is to act after the orderly path has
  given up.** It cannot honor the shutdown context, because that context is exactly what it
  exists to overrule, and nothing can wait for it, because on the ordinary path the process
  exits underneath it while it is still blocked. `signals.ForceExitOnSecond` is the example
  and, today, the only one: it parks on a channel read so that a second interrupt can
  terminate a wedged drain. Such a goroutine is not a leak, because the process is leaving
  either way; a parked channel read costs one goroutine until it does. Write it only for an
  escape hatch from shutdown itself, give it no context to honor, and say in its doc comment
  why it has none.

#### Error composition and inspection

- **Match with `errors.Is`, never `==`.** Equality stops at the outermost error and silently
  stops matching the day someone wraps it one layer deeper. `errorlint` enforces this.
- **Prefer `errors.AsType[T](err)` to `errors.As`.** The generic form returns the typed value
  and a bool instead of writing through a pointer, so it needs no pre-declared target variable
  and reads as one expression:
  `if maxErr, ok := errors.AsType[*http.MaxBytesError](err); ok`. See
  `internal/server/limits_test.go`. Use classic `errors.As` only where the target type is not
  known at the call site.
- **Wrapping and joining are different operations.** `fmt.Errorf("...: %w", err)` adds context
  to one failure and builds a chain. `errors.Join(a, b)` states that several independent
  failures happened and builds a flat tree. Do not use `Join` where a caller would expect a
  sentence describing what went wrong, and do not lose sibling failures by wrapping only the
  first one. `fmt.Errorf` accepts more than one `%w` when several causes genuinely belong to
  one message.
- **`errors.Join` drops nils and returns nil when every argument is nil,** so the guard clauses
  around it are unnecessary. Collect candidate errors, join once, return the result.
- **Cleanup errors are joined explicitly, not captured in a `defer`.** Named returns are banned
  here, so the usual "`defer func() { err = errors.Join(err, f.Close()) }()`" trick is
  unavailable by design. Assign the cleanup error to its own variable and join it at the return
  site, which also makes the ordering of the two failures visible.
- **`errors.Is` and `errors.As` traverse joined trees,** so joining does not cost callers their
  ability to match a specific cause. What it does cost is the message: `Join` renders one error
  per line, which is wrong for a single-line log field. Log the causes as structured zap fields
  rather than pasting a multi-line string into a message.
- **Sentinels are `ErrFoo`, error types end in `Error`,** and both are documented with what a
  caller is expected to do when they match. `errname` enforces the naming; the documentation is
  on you.

#### Layout

Layout follows conventional Go structure with the module at the repository root:
`cmd/<binary>/` for entrypoints, `internal/` for code not intended for outside import, and
`pkg/` only for packages deliberately published for external consumption.

Frontend source belongs in `ui/`. Because `go:embed` cannot reference paths outside its own
package directory, the frontend build must write its output into `internal/web/dist/`, which
is the directory compiled into the binary. `internal/web/dist/index.html` is a tracked
placeholder so the Go build works without a frontend toolchain installed; everything else in
that directory is ignored.

### Frontend

The frontend stack is not yet selected. The open decision, its options, and the condition for
closing it are recorded in `docs/adr/0002-frontend-stack.md`, which must be accepted before
any frontend code is written. The frontend tools named in the test pyramid below follow from
that decision and are placeholders until it is made.

## Testing Standards

### Test pyramid

Many unit tests, fewer integration tests, fewest end-to-end tests. Push each test to the
lowest layer that can still fail for the right reason.

| Layer | Go | Frontend | Scope |
| --- | --- | --- | --- |
| Unit | `go test ./...`, table-driven | Vitest and Testing Library | One package or component, no I/O |
| Integration | build-tagged, real dependencies | Component plus real API | Across a boundary: HTTP, database, filesystem |
| End-to-end | Driven through the HTTP API | Playwright | A user-visible flow through the running system |

### Rules

- **Test first.** Write the test, confirm it fails for the intended reason, write the
  minimum code to pass, then refactor with tests green. A test that has never failed has not
  been shown to test anything.
- **A test is never edited to match what the code does.** When a test fails, the default
  conclusion is that the code is wrong. Changing the assertion to match observed behavior
  destroys the only evidence that the behavior was ever specified, and it does so silently:
  the suite goes green and the record of intent is gone. An expectation may be revised only
  for one of these reasons, and the reason goes in the commit message:
  - The requirement changed. Amend `requirements.md` first, then the test, in that order.
  - The test encoded a wrong assumption about a third party's behavior, not about this
    project's. Leave a comment at the assertion naming the actual documented behavior, so the
    next reader does not re-derive it.

  A bug found in shipped code is not an exception: it gets a new failing test, per the rule
  below, rather than a loosened existing one.
- **Code that exists without tests gets them under mutation check.** Writing a test after the
  code cannot demonstrate the test would have failed first, so the demonstration is made
  directly: break the specific line the test is meant to cover, confirm the test fails with
  the message you expect, and restore. An assertion that survives its own mutant is not
  testing what its name claims. This is a repair path for untested code, not an alternative to
  testing first.
- **Bug fixes begin with a failing regression test** that reproduces the report, committed
  in the same change as the fix.
- **Arrange, Act, Assert.** One behavior per test. The test name states the behavior and
  cites its criterion ID. Five kinds of test cite none, and say in a comment why instead:
  one that guards an exported contract's behavior on a zero value, one that pins a third
  party's documented behavior so an upgrade that changes it fails here, one that is
  documentation which happens to execute (a runnable `Example`), one that asserts a
  property over every input rather than one criterion's case (a `Fuzz` target), and one
  that constrains something other than the running service at all: a build input, or a
  mistake only reachable from source rather than from a request. Writing criteria for
  these would produce criteria about Go, about the build, or about mistakes no operator
  can make, rather than about this service. This is an exception for the test side only:
  the rule that every criterion is cited by at least one test is unaffected, and a test
  that verifies this service's own behavior still cites the criterion that requires it,
  or the criterion gets written.
- **FIRST properties:** fast, independent, repeatable, self-validating, timely. No ordering
  dependence between tests, no shared mutable fixtures.
- **Prefer real collaborators to test doubles.** Fake only at process boundaries the test
  cannot control: network, clock, randomness, filesystem, third-party APIs. Do not mock
  types owned by this project; a mock that encodes an assumption about your own code passes
  while production breaks.
- **Determinism is mandatory.** Inject clocks and seeds. No `time.Sleep` for
  synchronization, no reliance on map iteration order or wall-clock timing. Waiting for an
  event another goroutine or another process produces is the one case a bare channel receive
  cannot always cover, and there the permitted form is a bounded poll: retry an observable
  check on a short interval until it holds, with a deadline that exists only so a condition
  that never holds fails by name instead of hanging until the package timeout. Neither
  duration may decide the outcome of a passing run. `internal/server`'s `pollUntil` is the
  helper; do not hand-roll the loop again.
- **`go test -race ./...` must pass.** Concurrency bugs that only appear under load are not
  acceptable to defer.
- **Coverage is a diagnostic, not a target.** No numeric gate: a percentage becomes a metric
  to game rather than a measure of confidence. Uncovered branches are justified during
  review or covered.

## Architecture Decisions

Decisions that are costly to reverse, or that a future reader would reasonably ask "why"
about, are recorded as ADRs in `docs/adr/` using the MADR template. See
`docs/adr/0001-record-architecture-decisions.md`.

Status runs `proposed` to `accepted` to `superseded`, or `rejected`. **An open decision is
recorded as `proposed`** with its Decision Outcome left empty and the condition for closing it
stated, so pending choices live in version control instead of in someone's memory. A
`proposed` record stays editable; an `accepted` record is immutable and is replaced by a new
record that supersedes it.

## Version Control

- **Conventional Commits** for every commit message, which keeps history machine-readable and
  makes changelog generation possible.
- **Semantic Versioning** for released artifacts.
- **Short-lived branches off `main`.** `main` stays releasable at all times.

## Definition of Done

A change is done when all of the following hold. Report failures with their output rather
than describing the work as complete.

1. Every acceptance criterion in scope is cited by at least one passing test.
2. Full unit and integration suites pass, including `go test -race ./...`.
3. `go tool golangci-lint run` passes with no new findings, formatters included. It runs
   `go vet` as one of its linters, so there is no separate vet step, and the tool directive
   in `go.mod` pins the version so local and CI runs cannot differ.
4. Where the change touches the frontend, it builds and its tests pass.
5. `requirements.md` reflects shipped behavior; any new architectural decision has an ADR.
6. Commit messages follow Conventional Commits.
