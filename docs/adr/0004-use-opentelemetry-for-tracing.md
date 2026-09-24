---
status: accepted
date: 2026-09-15
---

# 4. Use OpenTelemetry for tracing, exported over OTLP/HTTP

## Context and Problem Statement

This is a Go service fronting a browser UI, so a request's cost is spread across HTTP
handling, whatever backing work a feature performs, and eventually calls to things outside the
process. Logs alone answer "what happened" but not "where the time went" or "which of these
forty log lines belong to the same request".

Instrumentation is not a local choice. Whatever API is chosen appears wherever a span is
started, which over time means most packages. Replacing it later is the same mechanical
sweep that replacing the logger would be, which is why ADR 0003 treated that choice as
effectively permanent and why this one is recorded rather than defaulted into.

The secondary question is delivery. A tracing API is useless without somewhere to send spans,
and the wire protocol determines what infrastructure has to exist, what gets linked into the
binary, and how much of the pipeline is vendor-specific.

## Decision Drivers

- Vendor neutrality. The backend that stores traces should be replaceable without touching
  instrumentation, because a single maintainer's hosting choices change more often than their
  code.
- Correlation with the existing logging decision. A trace ID that does not appear in logs
  leaves two disconnected views of the same request.
- Zero cost when unconfigured. A developer running the binary locally must not need a
  collector, and must not be punished with connection errors for not having one.
- Bounded dependency surface, since every added module is one more thing to keep patched.
- Propagation correctness. This process may sit behind or in front of others; it must not be
  the hop where a distributed trace breaks.

## Considered Options

- OpenTelemetry with the OTLP/HTTP exporter
- OpenTelemetry with the OTLP/gRPC exporter
- A vendor SDK, such as Datadog's or Honeycomb's native tracing library
- No tracing; rely on request logs and durations

## Decision Outcome

Chosen: **OpenTelemetry with the OTLP/HTTP exporter.**

OpenTelemetry is the only option that is both vendor-neutral and the ecosystem default, so
instrumentation written now survives a change of backend. OTLP/HTTP over gRPC because the
HTTP exporter does not link gRPC into the binary, verified with
`go list -deps ./cmd/service | grep -c google.golang.org/grpc`, which reports zero. gRPC does
appear in `go.mod` as an indirect requirement of the OTLP protobuf definitions, so the cost is
confined to `go.sum` and dependency updates rather than the built artifact. Switching to gRPC
later is one import and one constructor.

Tracing is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` or
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` names a collector. With neither set, `SetupTracing`
hands back the SDK's no-op tracer provider, and the instrumentation in `internal/server`
costs a few comparisons per request. Providers are passed to that instrumentation
explicitly rather than installed on the `otel` package's globals, so what a handler records
is a property of how it was built. Reading those specific variables is not
a project configuration decision, which remains deliberately open: the names and their
precedence are fixed by the OpenTelemetry specification, so every collector and deployment tool
already knows how to set them.

Context propagation is installed **whether or not this process exports**. A process that does
not trace itself must still read an inbound `traceparent` and pass it onward, or it becomes a
hole in someone else's trace. This is the one piece of behaviour that is easy to get wrong and
invisible when wrong, so `internal/telemetry` has a test for it specifically.

Two further choices follow from ADR 0003:

- The SDK's error handler is replaced with one that logs through zap. The default writes to
  stderr via the standard `log` package, which ADR 0003 rules out, so leaving it would create
  exactly the unstructured output that decision exists to prevent.
- The request-logging middleware attaches `trace_id` and `span_id` when a recording span is
  active, and omits both when one is not. Emitting the zero trace ID would imply a trace that
  does not exist and would poison any log-to-trace query.

### Consequences

- Good: a backend change is a configuration change. Nothing in the code names a vendor.
- Good: local development needs nothing running. The disabled path is the default path.
- Good: log lines carry the trace they belong to, so the two views join.
- Bad: the dependency tree grew substantially, including gRPC as an indirect module
  requirement it does not build with. This is the price of the OTLP protobuf definitions.
- Bad: OpenTelemetry's Go modules version independently, with the SDK on 1.x and contrib
  packages on 0.x. Upgrades require checking compatibility rather than bumping one number.

## Pros and Cons of the Options

### OpenTelemetry with OTLP/HTTP

- Good: vendor-neutral, and the default every backend accepts.
- Good: no gRPC in the built binary, and works through ordinary HTTP proxies.
- Bad: marginally larger payloads than gRPC's streaming, which does not matter at any volume
  this project will see soon.

### OpenTelemetry with OTLP/gRPC

- Good: the more common production default, with streaming and better compression.
- Bad: links gRPC into the binary for no benefit at current scale.

### A vendor SDK

- Good: the smoothest experience with that one vendor, and often richer automatic
  instrumentation.
- Bad: every instrumented call site becomes a switching cost. Directly contrary to the first
  decision driver.

### No tracing

- Good: nothing to run, nothing to pay for, no dependencies.
- Bad: the decision gets made later anyway, after instrumentation-shaped holes have been left
  all through the code. Adding tracing early is cheap precisely because there is little code to
  instrument.

## More Information

Span names come from the matched `ServeMux` pattern rather than the request path, because a
path-based name has unbounded cardinality and the instrumentation's default name is identical
for every endpoint. The pattern is read after the mux has routed, which works because
`ServeMux.ServeHTTP` assigns `r.Pattern` on the same `*http.Request` value the middleware
holds.

Liveness probes are excluded from tracing. They arrive continuously, describe nothing about
application behaviour, and would otherwise dominate trace storage.

Head sampling is always-on, with upstream sampling decisions honoured via a parent-based
sampler. Volume-based sampling is deliberately left to the collector, which can decide with a
whole trace in hand rather than guessing at the first span. Revisit when trace volume is
measurable rather than hypothetical.

Metrics are a separate decision, recorded in
`0005-use-opentelemetry-metrics-with-prometheus.md`.
