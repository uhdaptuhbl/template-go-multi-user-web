---
feature: 006-outbound-http
created: 2026-09-20
updated: 2026-09-24
---

# Design: Outbound HTTP

## Overview

A new leaf package, `internal/httpclient`, whose whole surface is a `Config`, a `Default()`
for it, and a `New` that turns one into an `*http.Client`. The client it returns is an
ordinary standard-library client with a private `*http.Transport` underneath and an
`otelhttp.Transport` wrapped around that. There is no client type of this project's own,
because every third-party SDK worth passing one to takes an `*http.Client`, and a wrapper
would have to be unwrapped again at each of those boundaries.

The package is a leaf: it imports `net/http`, `internal/configtype`, and the OpenTelemetry
API and instrumentation, and nothing of this repository's own beyond the configuration
types. `internal/server` does not import it and it does not import `internal/server`.

## Alternatives considered

| Option | Why not |
| --- | --- |
| Use `http.DefaultClient` and document the risks | It has no timeout, its transport is process-global, and documentation is not a control. The first caller to forget is the one that hangs. |
| Return a project-defined `Client` interface | Every SDK takes `*http.Client`. An interface would be unwrapped at each boundary, and the unwrapping is where a caller substitutes the default client by accident. |
| Set the timeouts on `http.DefaultTransport` at start-up | Global mutable state, banned by `CLAUDE.md`, and it gives every dependency the same pool whether or not that suits it. |
| Put the instrumentation in a `RoundTripper` of this project's own | `otelhttp.Transport` already implements the semantic conventions, the metric names, and the propagation. Reimplementing them produces spans that look almost right. |
| One package-level client built once | A dependency's limits are a property of the dependency. A single client means the limits are a property of the process, which is the problem this feature exists to fix. |
| Add retries behind an idempotency flag | Out of scope by decision, and the flag is the tell: the caller already has to know, so the retry belongs where the knowledge is. |

## Architecture

`New(cfg, telemetry)` builds three layers, innermost first.

The base is an `*http.Transport` constructed field by field rather than cloned from
`http.DefaultTransport`. Cloning would inherit whatever a future Go release changes in the
default and would silently pick up any mutation another package made to it; constructing
means every value in the pool is one this package chose and can be read off in one place.
`DialContext` comes from a `net.Dialer` with the configured connection timeout, so the dial
honors the request context.

Around it goes `otelhttp.NewTransport`, given the tracer provider, meter provider, and
propagator from the `Telemetry` struct passed in. That struct mirrors the one
`internal/server` already takes, so the wiring in `cmd/service` reads the same in both
directions. Its zero value is the no-op case: `otelhttp` is still installed, and is handed
no-op providers, which is what makes an untraced build behave identically to a traced one
minus the export.

`otelhttp.NewTransport` returns a type with no `CloseIdleConnections` method, so
`http.Client.CloseIdleConnections` (which finds that method by type assertion) would
silently become a no-op if the instrumented transport were handed to the client directly:
it still compiles, still returns, and leaves every connection open. A `closeable` wrapper
around the instrumented transport restores that method by delegating it to the pooled
transport underneath, which is the one actually holding the idle connections.

The outer layer is the `*http.Client` itself, carrying the total timeout. `http.Client.Timeout`
covers the whole exchange including reading the body, which is the only one of the timeouts
that does; the transport's three cover their phases and stop.

`Config.Validate` runs the same way every other config in this repository does, through the
struct tags the shared decoder already applies, so a caller who loads this from the
environment gets the failures named by variable at start-up rather than at the first
request.

## Interfaces

```go
// Config holds one outbound dependency's timeouts and pool limits.
type Config struct { ... }

// Default returns the settings a client is built with when nothing overrides them.
func Default() Config

// Telemetry carries the providers an outbound client records through.
type Telemetry struct { ... }

// New returns a client configured by cfg and instrumented through telemetry.
func New(cfg Config, telemetry Telemetry) (*http.Client, error)
```

`New` returns an error rather than panicking or silently substituting a default, because
the settings can come from the environment and an operator's mistake belongs in the
start-up failure beside every other one.

Closing is the standard library's call, `client.CloseIdleConnections()`, but it reaches the
pooled transport through the `closeable` wrapper described in Architecture, not directly:
`otelhttp`'s transport has no such method of its own, and `closeable` is what makes the
call actually close something rather than silently doing nothing. The package adds no
`Close` of its own beyond that delegation, because there is nothing else of its own to
close, and adding one would imply the client is unusable afterwards, which is not true.

## Data

`Config`'s fields are `configtype.Duration` and `int`, read from the environment under a
prefix the composing struct supplies, exactly as `server.Config` is. Durations use
`configtype.Duration` so that the effective configuration logs `"30s"` rather than
`30000000000`, which is `AC-006.14` and is the behaviour `internal/configtype` already
provides.

No credential is held. If a caller needs one it belongs in the request, not in the client,
and if that changes the field is declared `config.SecretString`.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Peer accepts the connection then sends nothing | The response header timeout fires; the error wraps `context.DeadlineExceeded` and `os.IsTimeout` reports true. |
| Peer is unreachable | The dial timeout fires. Distinguishable from the above by which phase timed out, which is why the two are separate settings. |
| Peer streams a body slowly forever | `http.Client.Timeout` fires. This is the timeout the transport's three do not cover. |
| Caller's context is cancelled | The request is abandoned at once; `errors.Is(err, context.Canceled)` holds. The timeout does not have to expire first. |
| A setting is not positive, or a limit is negative | `New` returns an error naming the field. No client is returned. |
| Pool is exhausted | The request waits for a connection until its own timeout or context ends it. It is not refused: a bounded wait is the point of the bound. |

## Security and privacy

The client sends whatever the caller asks it to. Two things it does on the caller's behalf
are worth stating. It injects trace context into outbound headers, which discloses this
service's trace and span IDs to the peer; that is the intent, and it is the same disclosure
the inbound side already accepts. It does not disable TLS verification, and offers no
setting that would: a caller with a genuine need constructs its own transport rather than
being given a switch that is one environment variable away from disabling verification in
production.

## Test strategy

Unit tests against an `httptest.Server`, which is a real server over a real socket and so
needs no double. Timeouts are tested by having the handler block on a channel the test
closes, not by sleeping: the test asserts that the client gave up, and the deadline it gave
up against is set small in the test's own config.

Instrumentation is tested with an SDK tracer provider backed by a recording exporter, the
way `internal/telemetry`'s tests already do, so what the client recorded is asserted rather
than assumed. Propagation is tested by having the handler read the `traceparent` header the
client sent.

The pool limits are configuration passed through to a standard-library struct. The test
asserts the constructed transport carries them, and does not attempt to prove that
`net/http` honors them, which is the standard library's test to have.

## Observability

Spans are named and attributed by `otelhttp` following the HTTP client semantic
conventions, so they need no naming decision here. Client metrics come from the same
wrapper through the supplied meter provider and reach the same registry the server metrics
do.

The package logs nothing. It has no logger, and a request failure is returned to a caller
who has the context to describe it; logging it here would produce one line per failure with
none of that context, duplicated by whatever the caller logs.
