---
status: accepted
date: 2026-09-15
---

# 5. Instrument metrics with the OpenTelemetry API, expose them for Prometheus

## Context and Problem Statement

ADR 0004 adopted OpenTelemetry for tracing, which leaves metrics to be settled separately.
They are a genuinely different decision: traces answer "what happened in this one request",
metrics answer "what is the shape of all requests", and the delivery models are opposites.
Tracing pushes; metrics are conventionally pulled.

Two choices are entangled and both are expensive to reverse:

1. **The instrumentation API**, which appears at every call site that records a measurement.
2. **The delivery model**, push or pull, which determines what infrastructure must exist before
   anyone can read a number.

The second is the harder one. A push pipeline shows nothing at all without a collector running,
which is a real barrier for a project whose deployment story does not exist yet. A pull endpoint
works with `curl` and nothing else, but is a surface that must not be publicly reachable.

## Decision Drivers

- One instrumentation vocabulary shared with tracing, so a developer learns one set of
  concepts rather than two.
- Visible with zero infrastructure. Metrics nobody can read are metrics nobody maintains.
- The delivery model must be changeable without editing call sites, because it is the part
  most likely to change when deployment is finally decided.
- Useful on day one, before any feature-specific instrumentation exists.
- Metrics exposition must not widen the application's public attack surface.

## Considered Options

- OpenTelemetry metric API with a Prometheus exporter, scraped from `/metrics`
- OpenTelemetry metric API with OTLP push to the same collector as traces
- `prometheus/client_golang` used directly for instrumentation
- Defer the decision, recording it as `proposed` with nothing implemented

## Decision Outcome

Chosen: **the OpenTelemetry metric API, exposed for Prometheus to scrape.**

This separates the two entangled choices instead of settling them together. Call sites create
instruments from a meter provider they are given, the same vocabulary and the same wiring as
tracing, so switching from a scrape endpoint to OTLP push later changes only
`internal/telemetry` setup and not one line of instrumentation. Pull
delivery means a developer can read real numbers with `curl localhost:9090/metrics` and nothing
else running, which the push option cannot offer.

Unlike tracing, metrics are **not** conditional on configuration. Collection is pull-based, so a
running process with nothing scraping it costs only the memory holding current values, and there
is no endpoint to misconfigure.

Three supporting decisions:

- **A dedicated `prometheus.Registry`, not `prometheus.DefaultRegisterer`.** Any dependency can
  register collectors on the default registry from an `init()` function. What this process
  exposes should be what this process chose to expose.
- **Go runtime metrics are collected** via
  `go.opentelemetry.io/contrib/instrumentation/runtime`. Without them a service that has no
  custom instrumentation yet exposes almost nothing, and the endpoint gets written off as
  useless before it has anything to say. The OpenTelemetry runtime package is used rather than
  client_golang's collectors so that runtime metrics travel the same pipeline as everything
  else.
- **`client_golang` is allowed only for the registry and the HTTP handler.** It is not an
  instrumentation API in this project. `depguard` permits the import; this record is what makes
  the narrower intent reviewable.

### Exposition surface

`/metrics` lives on a **separate administrative listener** (`:9090` by default), not on the
application port. Metric names alone disclose route names, traffic volume, and error rates, so
exposing the application must not expose its internals. The administrative listener also carries
the liveness endpoint and runtime profiling.

**The administrative listener must not be reachable from an untrusted network.** The profiling
endpoints on it will dump the heap, every goroutine's stack, and the process command line to
anyone who asks. This is the main cost of the decision and it is a deployment obligation, not
something the code can enforce.

A failure of either listener stops the whole process, rather than leaving a half-started service
that looks healthy while missing something the operator asked for.

### Consequences

- Good: one instrumentation API across traces and metrics.
- Good: readable with no collector, no backend, and no account anywhere.
- Good: the delivery model can change later without touching call sites, which is the whole
  point of separating the two choices.
- Good: operational surface is off the public port by construction.
- Bad: metric names are not what was written. The exporter translates OpenTelemetry names,
  replacing dots with underscores, appending units, and adding `_total` to monotonic counters,
  and attaches `otel_scope_*` labels to every sample. Dashboards must be written against the
  translated names.
- Bad: a second listener to configure, run, and firewall, and a second port in every deployment
  manifest.
- Bad: pull delivery loses whatever was not scraped before shutdown. Inherent to the model.
- Bad: `client_golang` and its transitive dependencies are now in the tree despite being used
  for two things.

## Pros and Cons of the Options

### OpenTelemetry metric API with a Prometheus exporter

- Good: one API shared with tracing; works with zero infrastructure.
- Good: Prometheus and everything that speaks its format can scrape it unchanged.
- Bad: name translation means the metric you wrote is not the metric you query.
- Bad: needs an endpoint, and therefore a decision about who can reach it.

### OpenTelemetry metric API with OTLP push

- Good: single pipeline and endpoint shared with traces; native exemplars linking metrics to
  traces; no name translation.
- Good: no exposition surface to protect at all.
- Bad: nothing is observable without a collector, which does not exist yet. That is a barrier
  during exactly the period when the instrumentation habit is being formed.

### prometheus/client_golang directly

- Good: the Go ecosystem default, with the most examples and prebuilt dashboards.
- Good: names are exactly what was written, with no translation layer.
- Bad: a second instrumentation vocabulary alongside OpenTelemetry tracing.
- Bad: linking a metric to a trace through exemplars needs wiring the OpenTelemetry path
  provides.

### Defer the decision

- Good: consistent with how ADR 0002 handles the frontend stack, and costs nothing.
- Bad: unlike the frontend stack, this is not blocked on unknown requirements. Runtime and HTTP
  metrics are valuable regardless of what the service turns out to do, and the tracing work had the
  pipeline half-built already.

## More Information

HTTP server metrics come free from the instrumentation added in ADR 0004: `otelhttp` records
request duration and in-flight counts against the meter provider `NewMux` is given, so no
per-route metric code is needed.

Revisit this record when a deployment target is chosen. If that environment runs an
OpenTelemetry collector anyway, moving metrics onto OTLP push becomes nearly free and removes
both the exposition surface and the name translation. That migration is the reason the
instrumentation API and the delivery model were decided separately here.
