// Package telemetry initialises the OpenTelemetry pipeline this process
// exports through.
//
// Nothing here is installed on the otel package's global providers. Each
// pipeline hands back the provider it built, and the caller passes that to the
// instrumentation that records through it, the same way a logger is passed
// rather than fetched. A test can therefore build a pipeline of its own and
// observe exactly what a handler recorded, and no package can record through a
// provider it was not given.
//
// Tracing is opt-in: with no collector endpoint configured the pipeline hands
// out a no-op tracer provider, so instrumentation elsewhere costs nothing.
// Context propagation is built either way, so a process that does not export
// traces itself still reads an inbound traceparent header and passes it onward
// rather than breaking the trace at this hop.
//
// Metrics work the other way round and are always collected, because delivery is
// pull-based: a process nobody scrapes pays only for the memory holding current
// values. They are exposed for Prometheus on the administrative listener rather
// than the application one, since metric names alone disclose route names,
// traffic volume, and error rates.
//
// The one piece of global OpenTelemetry state the package sets is the SDK
// error handler, because the SDK has no other channel for its own failures:
// an exporter that cannot reach its collector reports through otel.Handle and
// nothing else. Left unset, that writes to stderr through the standard log
// package, which docs/adr/0003-use-uber-zap-for-logging.md rules out.
//
// See docs/adr/0004-use-opentelemetry-for-tracing.md and
// docs/adr/0005-use-opentelemetry-metrics-with-prometheus.md.
package telemetry
