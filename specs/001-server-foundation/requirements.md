---
feature: 001-server-foundation
created: 2026-09-17
updated: 2026-09-24
status: implemented
---

# Requirements: Server foundation

`status` is one of `draft`, `approved`, `implemented`, `unverified`, `superseded`; see the
feature lifecycle in `CLAUDE.md`.

## Problem

The configuration, logging, telemetry, two-listener, shutdown, and embedded-frontend code
already on `main` was built without a spec. Nothing states what its behavior is supposed to
be, so no test can cite a criterion, and a future change has no written contract to check
itself against or to knowingly break.

## Goal

This document names the behavior the shipped foundation already provides, so it can be held
to a criterion instead of only to "the code does what it does."

## Non-goals

This is a retrospective record of shipped behavior. It does not add behavior, does not
propose new settings or endpoints, and does not evaluate whether the existing design is the
right one. Any gap found while writing it (behavior worth having that the code does not
provide) is out of scope here and belongs in a future feature spec.

## User stories

### Story 1: Configuration from the environment

As an `operator`, I want the process configured entirely from environment variables with
sane defaults, so that I can deploy it without a config file and be told immediately if I
misconfigured it.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-001.1`: The system SHALL read every setting from the process environment over a
  built-in default.
- `AC-001.2`: IF a setting fails validation, THEN the system SHALL stop at startup and name
  the failing field.
- `AC-001.3`: WHEN a variable is set but empty, the system SHALL treat it as unset.
- `AC-001.18`: IF more than one setting fails validation, THEN the system SHALL report every
  failure in one startup failure rather than stopping at the first.
- `AC-001.19`: IF a setting fails validation, THEN the system SHALL identify it by the
  environment variable it is read from, or by the field's own name where it declares no
  variable.
- `AC-001.20`: The system SHALL take each settings group's defaults from the package that
  owns that group, and SHALL read that group's variables under the prefix the group
  declares.
- `AC-001.31`: The system SHALL apply a settings group's own validation only to a group
  composed directly into the configuration, and SHALL NOT apply it to a group nested inside
  another group.
- `AC-001.32`: WHERE a setting declares a transformation of its resolved value, the system
  SHALL apply it; IF the transformation fails, THEN the system SHALL stop at startup.
- `AC-001.21`: The system SHALL read OpenTelemetry settings from the variable names that
  specification fixes, without this project's variable prefix.
- `AC-001.22`: WHERE both a general and a traces-specific collector endpoint are configured,
  the system SHALL use the traces-specific one.
- `AC-001.33`: WHERE only the general collector endpoint is configured, the system SHALL
  export traces to the `v1/traces` path beneath it, as the OpenTelemetry specification
  defines for OTLP/HTTP.
- `AC-001.23`: The system SHALL take the service version from the build rather than from the
  environment.
- `AC-001.26`: WHERE a setting holds a credential, the system SHALL render a fixed
  placeholder in place of its value in every string, structured-logging, JSON, and
  plain-text representation.
- `AC-001.27`: The system SHALL provide exactly one explicit accessor returning a
  credential's plaintext value, and SHALL expose that value through no other representation.
- `AC-001.28`: WHEN a credential-bearing setting is loaded, the system SHALL store the value
  verbatim and validate it as it does any other setting, and SHALL NOT reveal it in a
  validation failure.

`AC-001.26` through `AC-001.28` constrain a capability no setting uses yet: nothing this
service loads is a credential today. They are stated in advance because the alternative is
that the first one added is declared as a plain string, and the first log line rendering the
effective configuration leaks it.

### Story 2: Separate application and administrative listeners

As an `operator`, I want the operational surface (health, metrics, profiling) on a different
port than the application, so that exposing the application does not expose the process
internals with it.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-001.4`: The system SHALL serve the application listener on `:8080` by default.
- `AC-001.5`: The system SHALL serve the administrative listener on a port separate from the
  application listener.
- `AC-001.6`: WHEN `GET /healthz` is requested on either listener, the system SHALL respond
  200 with `{"status":"ok"}`.
- `AC-001.9`: The system SHALL expose Prometheus exposition at `GET /metrics` on the
  administrative listener only.
- `AC-001.10`: The system SHALL expose runtime profiling under `/debug/pprof/` on the
  administrative listener only.

### Story 3: Serving the embedded frontend

As a `user`, I want the browser UI served directly by the process with no separate static
file server to deploy, so that the whole application ships as one binary.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-001.7`: The system SHALL serve the embedded frontend for any application path that is
  not an operational endpoint.
- `AC-001.8`: IF an embedded asset does not exist, THEN the system SHALL respond 404.

### Story 4: Graceful shutdown

As an `operator`, I want the process to drain in-flight requests on termination and to still
be killable if the drain hangs, so that a rolling deploy neither drops requests nor wedges
forever.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-001.11`: WHEN a termination signal arrives, the system SHALL stop accepting new
  connections and allow in-flight requests up to the configured shutdown timeout to finish.
- `AC-001.12`: WHEN a second termination signal arrives during shutdown, the system SHALL
  exit immediately with status 1.
- `AC-001.13`: IF either listener fails to start, THEN the system SHALL stop the whole
  process.

### Story 5: Structured request logging and tracing

As an `operator`, I want every served request logged with enough identifying detail to find
it, and correlated with a trace when tracing is enabled, so that I can diagnose a specific
request after the fact.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-001.14`: The system SHALL emit one structured log entry per served application
  request, naming method, path, matched route, status, and duration.
- `AC-001.15`: WHERE a trace collector is configured, the system SHALL create a span per
  application request and include its trace and span identifiers in that request's log
  entry.
- `AC-001.16`: The system SHALL NOT create spans for `GET /healthz`.
- `AC-001.17`: WHERE no collector endpoint is configured, the system SHALL install a no-op
  tracer provider.

- `AC-001.24`: The system SHALL emit log entries at a configurable level in a configurable
  format, defaulting to console encoding at info level.
- `AC-001.25`: The system SHALL route records written through the standard library's
  structured logger to the same destination and the same level filter as its own entries.
- `AC-001.29`: WHEN a span is created for a request, the system SHALL name it after the
  route pattern the request matched rather than the request's raw path.
- `AC-001.30`: WHILE a span is active, the system SHALL include its trace and span
  identifiers in that request's log entry, and SHALL omit both fields where none is.

## Constraints

- Logging goes through `go.uber.org/zap`; see `docs/adr/0003-use-uber-zap-for-logging.md`.
- Tracing goes through OpenTelemetry, exported over OTLP/HTTP, and is disabled unless a
  collector endpoint is configured; see
  `docs/adr/0004-use-opentelemetry-for-tracing.md`.
- Metrics go through the OpenTelemetry metric API, exposed for Prometheus to scrape rather
  than pushed; see
  `docs/adr/0005-use-opentelemetry-metrics-with-prometheus.md`.
- The administrative listener is not safe to expose to an untrusted network: its profiling
  endpoints dump heap, goroutine stacks, and command line to anyone who can reach it. This is
  a deployment obligation, not something the code enforces.

## Open questions

None. This document describes behavior already shipped on `main`.

## Change log

Amendments after approval, newest first.

- `2026-09-24`: No criterion changed. `design.md` now names `internal/secret` as the home of
  the redacting secret type, which moved there from `internal/config` with spec 008, and
  names the fields that use it. The `AC-001.4` traceability row in `tasks.md` no longer lists
  `TestNewMuxRouting`, which stopped citing that criterion in an earlier cleanup.
- `2026-09-24`: `AC-001.33` added. The general collector endpoint was passed to the exporter
  as a complete URL, so every export went to `/` and a collector answered 404; no span had
  ever reached one configured that way. The OpenTelemetry specification treats that variable
  as a base URL and appends `v1/traces`. Found by running the local Compose stack.
- `2026-09-24`: `AC-001.3` and `AC-001.30` reworded to the EARS pattern each one follows:
  `AC-001.3` states a trigger, so it opens with WHEN, and `AC-001.30` a state, so it opens
  with WHILE. Both had used WHERE, which EARS reserves for an optional feature. Neither
  criterion's meaning changed.
- `2026-09-20`: `AC-001.18` through `AC-001.32` added. A triage of every test with no
  criterion citation found fifteen behaviours this feature ships and specifies nowhere:
  how a startup failure reports more than one wrong setting and what it calls each one,
  where a settings group's defaults and variable prefix come from, the two limits on a
  group's own validation, the OpenTelemetry variable names and the traces-specific
  endpoint, the service version's source, the logger's configurable level and format and
  the bridge that carries a dependency's records to the same place, span naming and log
  correlation, and the three credential-redaction rules. The tests existed first in every
  case; these criteria state what they were already checking.
- `2026-09-17`: Implementation complete; every criterion is cited by a passing test.
- `2026-09-17`: Initial retrospective write-up of shipped behavior.
