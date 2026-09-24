---
feature: 005-service-scaffolding
created: 2026-09-19
updated: 2026-09-24
status: implemented
---

# Requirements: Service scaffolding

`status` is one of `draft`, `approved`, `implemented`, `unverified`, `superseded`; see the
feature lifecycle in `CLAUDE.md`.

## Problem

This repository is about to become the template every new service starts from, and the
first feature route in each of those services would have to invent the same things: how to
decode a JSON request and say what was wrong with it, how to write a JSON response, how to
turn an error into a response without leaking its cause, how to take the process out of
rotation when a dependency it cannot serve without is down, and which browser-hardening
headers an API response carries. Each service that invents them invents them slightly
differently, and the first one to get error handling wrong sends a database address to a
client. A developer who wants to see a trace or a metric from a local build has to stand up
a collector by hand, and the linter a contributor runs is whatever version happens to be on
their `PATH`, which is not necessarily the one CI runs.

## Goal

Once this ships, a feature route decodes and responds with two helper calls and one error
type, readiness reflects registered dependency checks, every application response carries
the baseline hardening headers, a developer sees traces and metrics locally with one
command, and the linter a contributor runs is byte-for-byte the one CI runs.

## Non-goals

This feature does not add authentication, authorization, CORS, rate limiting per client, or
request validation beyond JSON shape. Those are properties of a specific service, not of
the foundation.

This feature does not register any readiness check. The template has no dependency to check;
the registry exists so the first service that does has somewhere to put it.

This feature does not add HSTS or a full Content-Security-Policy to API responses. HSTS is
the reverse proxy's job under `docs/adr/0007-deployment-topology.md`, and the frontend
handler already carries the policy its assets need (`AC-002.20`).

This feature does not rename the project or add the template bootstrap tooling. That work
happens after the repository is copied into the template, when its final name is known.

## User stories

### Story 1: JSON request and response helpers

As a developer adding a feature route, I want one way to decode a request body and one way
to write a response or an error, so that every endpoint reports the same error shape and
none of them can leak an internal failure to a client.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-005.1`: WHEN a handler writes a value through the JSON response helper, the system
  SHALL respond with the given status, `Content-Type: application/json`, and the value
  encoded as JSON.
- `AC-005.2`: IF the value cannot be encoded, THEN the system SHALL respond 500 with
  `{"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}` and log the failure,
  writing nothing of the intended response first.
- `AC-005.3`: IF a request body is decoded and its `Content-Type` is not `application/json`,
  THEN the system SHALL report a client error with status 415 and code
  `unsupported_media_type`. A media type parameter such as `charset` does not change the
  outcome.
- `AC-005.4`: IF a request body is empty, is not well-formed JSON, is not the JSON type the
  endpoint expects, contains a field the endpoint does not define, or contains more than one
  JSON value, THEN the system SHALL report a client error with status 400, code
  `invalid_body`, and a message naming which of those is wrong, without echoing the body.
  WHERE the failure is about one top-level member of the body, the client error SHALL also
  carry a JSON Pointer to it.
- `AC-005.5`: IF a request body exceeds the configured limit while being decoded, THEN the
  system SHALL respond 413 with the same body `AC-002.4` specifies.
- `AC-005.6`: WHEN a handler writes an error through the error response helper, the system
  SHALL respond with one error object per client error found anywhere in the error's tree,
  or, when there is none, respond 500 with
  `{"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}` and log the error at
  error level with the request identifier. The underlying error text SHALL NOT appear in
  any response.
- `AC-005.20`: WHEN an error response carries several client errors at differing statuses,
  the system SHALL respond 400 where every one of them is a client status, and 500
  otherwise.

### Story 2: Readiness dependency checks

As an operator, I want the readiness endpoint to reflect whether the dependencies this
process cannot serve without are reachable, so that a replica whose database is unreachable
stops receiving traffic instead of failing every request it is sent.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-005.7`: WHERE readiness checks are registered, WHEN `GET /readyz` is requested while
  the process is serving, the system SHALL run every check and respond 200 with
  `{"status":"ready"}` only when all of them pass.
- `AC-005.8`: IF any registered check fails, THEN the system SHALL respond 503 with
  `{"status":"not_ready","failing":[...]}` listing the failing checks' names in sorted
  order, and SHALL log each failure at warn level with the check's name and its error. The
  error text SHALL NOT appear in the response.
- `AC-005.9`: The system SHALL cancel the context passed to every check once the readiness
  check timeout elapses, and SHALL report a check that returns an error as failing.
- `AC-005.10`: IF a check panics, THEN the system SHALL report that check as failing and
  continue serving.
- `AC-005.11`: WHILE the process is draining, the system SHALL respond
  `{"status":"draining"}` as `AC-002.14` specifies without running any check.
- `AC-005.12`: IF a check is registered under a name already in use, THEN the system SHALL
  refuse the registration by panicking, as `http.ServeMux` does for a duplicate pattern.

### Story 3: Response hardening

As an operator, I want every response from the application listener to carry the headers
that stop a browser from sniffing or framing it, so that an API response or an error body is
no less protected than a frontend asset.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-005.13`: The system SHALL set `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, and `Content-Security-Policy: frame-ancestors 'none'` on every
  response it serves, on the application and administrative listeners alike, including
  responses written by middleware before any handler runs.
- `AC-005.14`: WHERE a handler sets its own `Content-Security-Policy`, the system SHALL
  preserve the handler's value.

### Story 4: Development tooling

As a contributor, I want to see traces and metrics from a local build and to run the same
linter CI runs, so that observability is checked before a change is pushed and a lint
finding never appears for the first time in CI.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-005.15`: The repository SHALL provide a Compose file that runs the service, a trace
  backend the service exports to over OTLP/HTTP, and a Prometheus instance scraping the
  administrative listener, and the stack SHALL start, with Prometheus reporting the
  service as an `up` target.
- `AC-005.16`: The repository SHALL pin golangci-lint as a `go.mod` tool at the version CI
  runs, and both the `Lint` build target and CI SHALL invoke that pinned tool.

### Story 5: Telemetry without global state

As a developer, I want the OpenTelemetry providers passed in like any other dependency, so
that what a handler records is decided by how it was built and a test can observe exactly
what it recorded.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-005.17`: The system SHALL record HTTP spans and metrics through the tracer provider,
  meter provider, and propagator supplied to the router, and WHERE none is supplied the
  system SHALL record nothing and extract no inbound trace context.
- `AC-005.18`: The telemetry package SHALL NOT install a tracer provider, meter provider, or
  context propagator on the OpenTelemetry package-level globals. The SDK error handler is
  excepted: the SDK reports its own failures through no other channel.
- `AC-005.19`: The entry point SHALL accept its shutdown trigger, signal channel,
  environment, and termination function as parameters, so that a test can run a complete
  start-up and shutdown in process.
- `AC-005.21`: The system SHALL expose Go runtime metrics through the same registry as its
  application metrics.
- `AC-005.22`: The system SHALL label exported telemetry with the service name and version.
- `AC-005.23`: The system SHALL report OpenTelemetry SDK errors through the application
  logger rather than to standard error.

## Constraints

- The readiness check timeout defaults to 1s, under the default probe timeout of the
  orchestrators the README documents.
- The hardening headers add no measurable latency: three header writes per request.
- The tool directive adds golangci-lint's module graph to `go.mod` as indirect
  requirements. They are not compiled into the service and `govulncheck ./...` does not
  scan them.

## Open questions

None.

## Change log

Amendments after approval, newest first.

- `2026-09-20`: `AC-005.21` through `AC-005.23` added by the uncited-test triage.
  `AC-005.17` and `AC-005.18` settled where the providers come from and that they are not
  installed globally, and said nothing about what they carry: the runtime metrics that make
  a scrape worth taking, the resource labels without which two services' metrics are
  indistinguishable, and the SDK's own errors, which otherwise reach standard error where
  no log pipeline collects them.
- `2026-09-20`: `AC-005.15` now requires the stack to start rather than the file to
  validate. It asked only for `docker compose config`, which parses the file and resolves
  nothing, so the stack passed its own criterion for a day while being unable to start at
  all: `jaegertracing/jaeger:2` does not exist, because that repository publishes no
  floating major tag. Found by `specs/007-local-gateway/`, which had to bring the stack up
  to verify anything, and fixed there. The lesson is the same one `AC-005.16` and the
  release pipeline taught: a criterion satisfied by a syntax check is satisfied by a
  configuration that cannot run.
- `2026-09-20`: `AC-005.2` and `AC-005.6` restated for the error document
  `docs/adr/0010-json-api-response-conventions.md` settles, `AC-005.6` now requiring one
  error object per client error in the tree rather than only the first. `AC-005.4` extended
  to require a JSON Pointer to the offending member, and `AC-005.20` added for the status a
  document with several differing statuses is sent with. Reporting one failure per round
  trip is the behaviour the plural document exists to remove; the pointer is what lets a
  frontend attach a message to the field it is about.
- `2026-09-20`: `AC-005.13` widened from the application listener to every listener. The
  administrative mux carried no security headers, no panic recovery, and no body limit,
  which was never a decision: the handler grew from a metrics endpoint nobody thought of as
  browser-facing, and pprof's index is HTML while `/debug/pprof/symbol` reads a request
  body. Recovery and the body limit needed no amendment, because `AC-002.1` and `AC-002.4`
  are written about handlers and requests rather than about one listener.
- `2026-09-19`: A review pass changed the wrong-type message under `AC-005.4` to name the
  expected JSON type rather than the Go type, which had disclosed an internal package and
  type name to the client. The criterion is unchanged; the message it requires is.
- `2026-09-19`: Added Story 5 (`AC-005.17` through `AC-005.19`) after the same review found
  the telemetry providers installed globally and `main` untestable.
- `2026-09-19`: Initial version, written and implemented in the same change as part of the
  review preparing this repository to become a template.
