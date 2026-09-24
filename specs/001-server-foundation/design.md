---
feature: 001-server-foundation
created: 2026-09-17
updated: 2026-09-24
---

# Design: Server foundation

How the requirements in `requirements.md` are met by the code already on `main`. Written
after the fact, describing the shipped shape rather than proposing a new one.

## Overview

`cmd/service/main.go` is the composition root: it loads configuration
(`internal/config`), builds a logger (`internal/logging`), installs tracing and metrics
(`internal/telemetry`), builds the embedded frontend handler (`internal/web`), and runs two
`internal/server.Server` instances (`internal/server`) concurrently until a termination
signal or a listener failure stops them (`internal/signals`). This satisfies every criterion
in `requirements.md`: AC-001.1 through AC-001.3 are configuration, AC-001.4 through
AC-001.10 are the two listeners and their routes, AC-001.7 and AC-001.8 are the embedded
frontend, AC-001.11 through AC-001.13 are shutdown, and AC-001.14 through AC-001.17 are
request logging and tracing.

## Alternatives considered

Three of the choices below are project-wide decisions recorded as ADRs; this feature is
their first consumer, not the place their arguments were weighed. Rejected options and the
full reasoning live in the linked records.

| Option | Trade-off | Verdict |
| --- | --- | --- |
| Logging: `go.uber.org/zap` with an inbound `slog` bridge (chosen) vs. `log/slog` as the primary API with a zap backend, `log/slog` alone, or `zerolog` | See `docs/adr/0003-use-uber-zap-for-logging.md` | Zap chosen; alternatives rejected there |
| Tracing: OpenTelemetry over OTLP/HTTP (chosen) vs. OTLP/gRPC, a vendor SDK, or no tracing | See `docs/adr/0004-use-opentelemetry-for-tracing.md` | OTLP/HTTP chosen; alternatives rejected there |
| Metrics: OpenTelemetry metric API exposed for Prometheus to scrape (chosen) vs. OTLP push, `client_golang` directly, or deferring the decision | See `docs/adr/0005-use-opentelemetry-metrics-with-prometheus.md` | Prometheus scrape chosen; alternatives rejected there |
| Two listeners, application and administrative (chosen) vs. one listener with all routes | A single listener is one less port to run and firewall | Rejected: metric names and profiling data disclose process internals; ADR 0005 requires the administrative surface off the public port |
| 404 on a missing embedded asset (chosen) vs. falling back to `index.html` for client-side routing | A fallback is what a single-page-app router typically wants | Rejected here: the frontend stack is not yet chosen (`docs/adr/0002-frontend-stack.md` is still open), so whether a fallback is correct cannot be decided yet |

## Architecture

```
cmd/service/main.go
  |-- internal/config      Config, Load, Decode (env -> struct -> validate)
  |-- internal/logging     zap.Logger construction, slog bridge
  |-- internal/telemetry   SetupTracing, SetupMetrics
  |-- internal/web         embedded frontend http.Handler
  |-- internal/server      Server, NewMux, NewAdminMux, RunAll
  `-- internal/signals     ForceExitOnSecond
```

`internal/config` composes `logging.Config`, `server.Config` (used twice, once per
listener), and `telemetry.Config` into one `config.Config`, so each package keeps ownership
of its own settings and validation rules rather than `internal/config` restating them.

`config.Decode` resolves and validates in a fixed order, which `AC-001.18` through
`AC-001.20`, `AC-001.31`, and `AC-001.32` describe only by their outcomes. The mechanism:

1. Environment values are read over each group's defaults, a nested group under the prefix
   its field declares.
2. Declared field constraints are checked. A failure here stops the sequence, so a group's
   own validation never runs against a value already known to be wrong and cannot report a
   second, derivative complaint about it.
3. Each group composed directly into the configuration runs its own validation, then the
   whole configuration runs its own. Both layers run regardless of the other's result and
   their failures are joined, so one startup names every settings group that is wrong.
   A group nested inside another group is not reached: validation that spans two packages
   belongs to whichever of them composes both.
4. A failure names the environment variable from the field's tag, falling back to the
   field's own name where it carries none, and preserves the cause the group reported so a
   caller can tell one kind of startup failure from another.

`internal/server` is used for both listeners: `server.New(cfg.Server, ...)` builds the
application listener and `server.New(cfg.Admin, ...)` builds the administrative one, each
with its own `http.Handler` built by `NewMux` and `NewAdminMux` respectively. `RunAll` runs
both `Server.Run` calls concurrently and treats either one stopping with an error as cause
to stop the other (AC-001.13).

## Interfaces

Application listener (`internal/server.NewMux`), default `:8080` (AC-001.4):

- `GET /healthz` -> 200, `application/json`, `{"status":"ok"}` (AC-001.6).
- `GET /readyz` -> readiness probe, added by a later feature; see `specs/002-server-hardening/`.
- Any other path -> the embedded frontend handler (AC-001.7, AC-001.8).

Administrative listener (`internal/server.NewAdminMux`), default `:9090`, separate from the
application listener (AC-001.5):

- `GET /healthz` -> 200, `{"status":"ok"}`, same handler as the application listener
  (AC-001.6).
- `GET /metrics` -> Prometheus text exposition (AC-001.9).
- `GET /debug/pprof/`, `/debug/pprof/cmdline`, `/debug/pprof/profile`, `/debug/pprof/symbol`,
  `/debug/pprof/trace` -> `net/http/pprof` handlers, registered explicitly rather than via
  `net/http/pprof`'s `init()`-time registration on `http.DefaultServeMux` (AC-001.10).
- `GET /readyz` and `GET /version`, added by later features; see
  `specs/002-server-hardening/`.
- No other route is registered beyond the ones listed above; an unmatched path is 404, and
  there is no catch-all that would otherwise let the application leak onto this listener.

Neither mux registers a fallback handler for a method mismatch on the administrative side,
so an unsupported method on a registered path yields the `http.ServeMux` default of 405. The
application mux's `/` catch-all matches any method, so a method mismatch on `/healthz` there
falls through to the frontend handler instead.

## Data

No persisted state. Configuration is read once at startup into `config.Config` and held in
memory; nothing is written back.

## Failure modes

- A setting failing `go-playground/validator` struct-tag validation, or `Decode`'s type and
  target checks, stops `config.Load` before anything else runs, naming the failing field and
  the validation tag that rejected it (AC-001.2).
- A listener that cannot bind (`net.ListenConfig.Listen` failing, for example on an
  out-of-range port) causes `Server.Run` to return an error; `RunAll` cancels the shared
  context so the other listener shuts down too, and the process exits non-zero rather than
  running with only one listener up (AC-001.13).
- On the first `SIGINT`/`SIGTERM`, `signal.NotifyContext`'s context is cancelled, each
  `Server.Serve` stops accepting new connections and calls `http.Server.Shutdown` bounded by
  `ShutdownTimeout`; requests still in flight when that timeout expires are cut off
  (AC-001.11).
- On a second `SIGINT`/`SIGTERM` while shutdown is in progress, `signals.ForceExitOnSecond`
  calls `os.Exit(1)` immediately, abandoning whatever is still in flight (AC-001.12).
- An OpenTelemetry SDK-internal failure (for example a failed span export) is routed to the
  application logger through a custom `otel.ErrorHandler` rather than the SDK's own default,
  which would otherwise write unstructured output via the standard `log` package.
- Writing the health response body can fail (client disconnect mid-write); the handler logs
  the error and does not treat it as a request failure, since the status code has already
  been written.

## Security and privacy

- The administrative listener is a trust boundary: it must not be reachable from an
  untrusted network. `/debug/pprof/*` on it discloses the heap, every goroutine's stack, and
  the process command line to anyone who can reach it. Nothing in the code enforces this; it
  is a deployment obligation stated in `docs/adr/0005-use-opentelemetry-metrics-with-prometheus.md`.
- `secret.String` in `internal/secret`, which `config.SecretString` aliases, redacts in every
  string, `slog`, JSON, and text representation, and exposes the plaintext only through an
  explicit `Expose()` call, so a config value marked secret cannot leak through an accidental
  `%v` or log field. It began as `config.SecretString` and moved to its own package with
  spec 008, because the packages whose settings `internal/config` composes need it and cannot
  import `internal/config` back. No field used it at the time this feature shipped; spec
  008's `store.Config.DSN`, `mail.Config.Password`, and `oidc.ProviderConfig.ClientSecret`
  now do. See `docs/adr/0006-configuration-loading.md`.
- No authentication is implemented on either listener. Access control is entirely a network
  boundary (which port is reachable from where), not an application-level check.

## Test strategy

Every criterion is proven at the unit layer, against real collaborators rather than mocks:
real `net.Listener`s bound to `127.0.0.1:0`, a real `zap.Logger` backed by
`zaptest/observer` or `zapcore.NewTee`+`observer.New` to inspect emitted fields, a real
`sdktrace.TracerProvider` with a `tracetest.SpanRecorder` standing in for an exported
collector, and `envconfig.MapLookuper` standing in for the process environment so
environment-reading tests do not mutate real process state or need to run serially. No test
double replaces a type this project owns.

The full mapping from criterion to test is `tasks.md`'s traceability table.

## Observability

- One `zap` log entry per served application request (`method`, `path`, `route`, `status`,
  `duration`, plus `trace_id`/`span_id` when a span is active) answers "what happened for
  this one request" (AC-001.14, AC-001.15).
- A span per application request, named `"{method} {matched route}"`, answers "where did the
  time go and which requests belong to the same distributed trace", when a collector is
  configured (AC-001.15, AC-001.17). Liveness probes are excluded so they do not dominate
  trace storage or push real requests out of a sampled view (AC-001.16).
- `/metrics` on the administrative listener answers "what is the shape of all requests", via
  OpenTelemetry HTTP instrumentation (`otelhttp`) plus Go runtime metrics, both collected
  regardless of whether anything is scraping (AC-001.9).
- `/debug/pprof/*` answers "what is this specific process doing right now" for an operator
  who already suspects a problem and needs a profile, not a standing metric (AC-001.10).
