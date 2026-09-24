---
feature: 005-service-scaffolding
created: 2026-09-19
updated: 2026-09-24
---

# Design: Service scaffolding

How the approved requirements will be met. Free to change as implementation proceeds;
changing this file does not require amending `requirements.md`.

## Overview

Everything a feature route will need, put in place before the first one exists, so that the
first author is composing pieces rather than inventing them. Four groups: JSON request and
response helpers (`AC-005.1` to `AC-005.6`, `AC-005.20`), a readiness registry checks can
be added to (`AC-005.7` to `AC-005.12`), baseline security headers (`AC-005.13`,
`AC-005.14`), and the tooling and wiring that make the rest testable, which is the local
Compose stack (`AC-005.15`), the pinned linter (`AC-005.16`), telemetry providers passed as
parameters rather than read from globals (`AC-005.17`, `AC-005.18`, `AC-005.21` to
`AC-005.23`), and an entry point with a seam a test can drive (`AC-005.19`).

Everything lands in `internal/server`, next to the middleware it composes with, and is
exported only where a feature package outside `internal/server` will need to call it:
`WriteJSON`, `WriteError`, `DecodeJSON`, `ClientError`, `Check`, and `Readiness.AddCheck`.
Nothing else changes shape.

## Alternatives considered

| Option | Trade-off | Verdict |
| --- | --- | --- |
| Stream responses through `json.NewEncoder` after `WriteHeader` | One less allocation, but an encoding failure arrives with the status line already on the wire and cannot be turned into a 500 | Rejected: marshal first |
| `http.TimeoutHandler` for readiness checks | Buffers the response and cannot tell a slow check from a slow write | Rejected: a context deadline the checks honour is cheaper and names the failing check |
| A `Readiness` interface with pluggable strategies | Nothing needs a second strategy | Rejected |
| A configurable readiness check timeout | Would have to reach `NewReadiness` from `config.Load`, changing a constructor every test calls, for a knob whose right value is fixed by the prober's own timeout | Rejected: a constant, on a field a test can shorten |
| Error responses that include the cause in a debug build | A build flag that changes what a client can learn is a flag that will be set in production | Rejected |
| Keeping the OpenTelemetry globals, with tests installing their own providers | Works only while tests run serially, and makes what a handler records a property of process start-up order rather than of the handler | Rejected: providers are parameters |
| A `Telemetry` interface rather than a struct of providers | The three providers are already interfaces; wrapping them adds a name and no behaviour | Rejected |
| An OpenTelemetry Collector in the Compose file | Correct topology, one more container and one more config file for no local benefit | Rejected: Jaeger accepts OTLP/HTTP directly |
| Installing golangci-lint as a binary, as its own documentation prefers | Keeps roughly two hundred indirect requirement lines out of `go.mod` and avoids a one-off compile, but pins the version in two places | Rejected: a `go.mod` tool directive, so the version changes in one place under a Dependabot pull request CI gates |

The error document's shape outlives this feature and is recorded separately, in
`docs/adr/0010-json-api-response-conventions.md`.

## Architecture

```
internal/server
  |-- json.go        WriteJSON, WriteError, DecodeJSON, ClientError
  |-- errors.go      the error document, its member titles, writeJSONError
  |-- readiness.go   Readiness, Check, AddCheck, the /readyz handler
  |-- headers.go     withSecurityHeaders
  `-- handler.go     NewMux, which composes the above with the middleware chain

internal/telemetry   SetupTracing and SetupMetrics return providers; install nothing
cmd/service          main installs signal handlers; run takes its dependencies
deploy/local         Compose: the image, Jaeger v2 all-in-one, Prometheus
```

Dependency direction is unchanged: `cmd/service` depends on `internal/*`, and no
`internal` package imports another except `internal/server` importing `internal/buildinfo`
and `internal/web`. `internal/telemetry` gains no importer; it loses one, because nothing
reads the `otel` package's globals any more.

Mechanisms worth stating, because each is a choice that is invisible once made:

- **`WriteJSON` marshals before writing.** One allocation per response buys the ability to
  turn an encoding failure into a clean 500.
- **`DecodeJSON` decodes twice.** The second `Decode`, expecting `io.EOF`, is how
  `encoding/json` distinguishes "one value then end" from "one value then more". The
  unknown-field case matches on the decoder's message prefix, because `encoding/json`
  exposes no typed error for it. A type mismatch names the JSON type expected rather than
  the Go type reported, which would disclose a package and type name and tell the client
  nothing it can act on.
- **Readiness checks run concurrently under `sync.WaitGroup.Go`,** each writing into its
  own pre-sized slot. That is the standard in `CLAUDE.md` for fan-out where every failure
  is independently meaningful; an `errgroup` would keep only the first. Failing names are
  sorted, so the body is identical across probes and across replicas.
- **Draining is checked before the checks are run,** and skips them entirely: a process on
  its way out is not a routing target whatever its dependencies say (`AC-005.11`).
- **`withSecurityHeaders` sets its headers before calling the next handler,** which is what
  lets the frontend handler override the policy with the fuller one `AC-002.20` requires
  (`AC-005.14`). A later `Set` wins, so there is no conflict to resolve. It sits outermost
  in both chains, directly inside tracing on the application listener.
- **`Telemetry`'s zero value substitutes a no-op for each signal** and an empty composite
  propagator, so a test that does not care about telemetry writes `Telemetry{}` and gets a
  handler that records nothing and reads no inbound trace context.
- **The linter is a `go.mod` tool directive,** added with `go get -tool` and run with
  `go tool golangci-lint`. Both the `Lint` target and the CI job call it, replacing the
  GitHub Action that pinned the version a second time (`AC-005.16`).
- **`main` keeps only what it alone can do:** install the signal handlers and turn an error
  into an exit status. `run` takes the shutdown context, the second-signal channel, an
  `envconfig.Lookuper`, and the termination function (`AC-005.19`).

## Interfaces

Exported Go surface, all in `internal/server`:

- `WriteJSON(w, logger, status, v)` -- encodes `v`, sets `Content-Type: application/json`,
  writes `status`. Encoding happens before anything is written (`AC-005.1`, `AC-005.2`).
- `WriteError(w, r, logger, err)` -- writes the error document for `err` (`AC-005.6`,
  `AC-005.20`).
- `DecodeJSON(r, dst) error` -- reads exactly one JSON value into `dst` (`AC-005.3` to
  `AC-005.5`).
- `ClientError{Status, Code, Message, Pointer, Err}` -- the one error type a handler uses to
  say something to the client. `Err` is the cause and is logged, never sent. `Pointer` is a
  JSON Pointer to the member the failure is about, empty where it is not about one.
- `Check func(ctx context.Context) error` and `Readiness.AddCheck(name, check)`
  (`AC-005.7` to `AC-005.12`).
- `Telemetry{TracerProvider, MeterProvider, Propagator}`, a parameter of `NewMux`
  (`AC-005.17`).

Error responses carry the document
`docs/adr/0010-json-api-response-conventions.md` settles: a top-level `errors` array whose
members use JSON:API's names, with the `application/json` media type and no conformance
claim.

```json
{"errors": [{"status": "400", "code": "invalid_body", "title": "Invalid request body",
             "detail": "field \"age\" must be a JSON number", "source": {"pointer": "/age"}}]}
```

`WriteError` collects every `ClientError` in the error's tree rather than the first, so a
handler that joins one per bad field reports them all at once. A document whose errors
disagree about status is sent with the most generally applicable one: 400 where all of them
are client errors, 500 as soon as one is not (`AC-005.20`).

`GET /readyz`, on both listeners:

| Condition | Status | Body |
| --- | --- | --- |
| Ready | 200 | `{"status":"ready"}` |
| A check failed | 503 | `{"status":"not_ready","failing":["<name>", ...]}` |
| Draining | 503 | `{"status":"draining"}` |

## Data

No persisted state, no schema, and no migration. Configuration is read once at startup and
held in memory. The only state this feature adds is the readiness check registry, which
lives for the process's lifetime and is written only during start-up.

## Failure modes

| Failure | Detection | What the client sees |
| --- | --- | --- |
| A response value cannot be encoded | `json.Marshal` fails before anything is written | 500 with the generic document; the cause is logged at error level (`AC-005.2`) |
| A request's `Content-Type` is not JSON | `requireJSONContentType` checks the header before decoding | 415 `unsupported_media_type`, with no attempt to decode the body (`AC-005.3`) |
| A request body is malformed, mistyped, or carries an unknown field | The decoder, plus a second `Decode` expecting `io.EOF` to catch a trailing value | 400 naming which of those is wrong, with a pointer to the member where one is known, and no echo of the body (`AC-005.4`) |
| A request body exceeds the limit mid-read | `*http.MaxBytesError` surfaces through the decoder | The same 413 the limit middleware produces, so the trip point is invisible (`AC-005.5`) |
| A readiness check fails | Its error reaches the probe | 503 naming the check; the error text goes to the log at warn level, never the body (`AC-005.8`) |
| A readiness check hangs | The shared context's deadline, `DefaultReadinessCheckTimeout` | The check counts as failed at one second. A check that ignores its context is not interrupted; the probe answers regardless (`AC-005.9`) |
| A readiness check panics | Recovered inside that check's own goroutine | The check counts as failed. Recovery is in the goroutine because one started by `WaitGroup.Go` has none, and would otherwise end the process (`AC-005.10`) |
| A check is registered twice | `AddCheck` panics | Nothing: this happens at start-up and is a programming error, which is how `http.ServeMux` treats a duplicate pattern (`AC-005.12`) |
| The trace exporter cannot reach its collector | The SDK reports through `otel.Handle` | Nothing. The error is logged; requests are unaffected, which is the point of tracing being optional (`AC-005.23`) |

Deliberately left to fail loudly: a duplicate check name, and a configuration failure at
start-up. Both happen before the process serves anything.

## Security and privacy

Trust boundaries are unchanged by this feature; it adds no authentication and no
authorization, and there is still nothing to authenticate against.

What it does add is three rules about what leaves the process:

- **A cause never reaches a client.** `ClientError.Err` is logged and dropped from the
  response, and `WriteJSON`'s encoding failure produces a message that names nothing. A
  decode failure names the member and the JSON type expected, never the value sent, and
  never the Go type, which would disclose a package and type name.
- **A readiness body names checks, not reasons.** The endpoint is served on the application
  listener, and a dependency's error string routinely names a host or a port.
- **Security headers on every response from both listeners** (`AC-005.13`), including
  responses middleware writes before any handler runs, which is where the 413 and the 503
  come from. HSTS is deliberately absent: a process that does not terminate TLS cannot know
  whether the connection was secure, and it is the reverse proxy's job under
  `docs/adr/0007-deployment-topology.md`.

No personal data is handled, because no endpoint accepts any yet. The first that does will
need this section revisited, and the request logging in `specs/002-server-hardening` with
it.

## Test strategy

Unit tests cover every criterion here except `AC-005.15` and `AC-005.16`, which are about
build artefacts rather than running code and are verified by the commands `tasks.md` names,
under the artefact-criterion exception in `CLAUDE.md`.

Two things are tested above unit level, each for a reason:

- **`cmd/service/main_test.go`** starts every listener and drives a complete shutdown. The
  criterion is that the entry point has a seam at all (`AC-005.19`), and a seam is only
  demonstrated by something driving it. Ports are reserved by binding and closing rather
  than passing `:0`, because `Addr` is validated as a `hostname_port` and `0` is not one.
- **`TestRequestBodyLimitClosesTheConnection`** needs a real server. The signal under test
  is delivered by type-asserting the `ResponseWriter` to an unexported `net/http` interface
  that only `*http.response` implements, which a recorder cannot observe at all.

No test doubles stand in for a process boundary in this feature. The readiness tests use
real functions as checks, the JSON tests use `httptest.NewRecorder`, and the telemetry
tests use the SDK with an in-memory reader, because all three are cheap enough to be real.

Tests that speak to a real listener use a client of their own with `MaxConnsPerHost: 1`
rather than `http.DefaultClient`. The default transport may dial a spare connection when a
request races the previous response returning its connection to the pool; the spare carries
no request, so the server holds it in `StateNew`, and `Shutdown` only treats such a
connection as idle after five seconds. That was the cause of an intermittent five-second
test.

## Observability

- **Runtime metrics** are collected through the same registry as application metrics
  (`AC-005.21`), so one scrape answers both "is this service healthy" and "is this process
  healthy" without a second endpoint.
- **A service name and version label everything exported** (`AC-005.22`). Without them two
  services' metrics are indistinguishable in one Prometheus, and a regression cannot be
  attributed to a release.
- **SDK errors go to the application logger** (`AC-005.23`). The SDK reports its own
  failures, an export rejected by a collector above all, through `otel.Handle` and nowhere
  else, and the default writes to standard error through the standard log package that
  `docs/adr/0003-use-uber-zap-for-logging.md` rules out. `otel.SetErrorHandler` is the one
  global this project keeps, because the SDK offers no non-global alternative.
- **A failing readiness check logs at warn** with the check's name and its error, which is
  the only place the error appears. The question it answers is which dependency took the
  replica out of rotation.
- **The local Compose stack** (`AC-005.15`) exists so that a trace and a scrape can be
  looked at during development rather than first in production. Jaeger v2 accepts OTLP/HTTP
  directly, so no collector is configured; a production pipeline would have one, and this
  is not a production pipeline.

No metric is added for the JSON helpers. A decode failure is already visible as a 4xx in
the request log and in the HTTP metrics `otelhttp` records, and a counter that duplicates
them would answer no question those two do not.
