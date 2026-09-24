package httpclient

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// instrument wraps next so each outbound request is recorded as a client span
// and carries this service's trace context to the peer.
//
// The providers come from telemetry rather than from the otel package's
// globals, so what a client records is decided by how it was built and a test
// can observe exactly what it recorded. A missing provider becomes its no-op
// rather than a nil check at each use: the wrapper is installed either way, so
// a build without tracing runs the same code path as one with it, minus the
// export.
//
// otelhttp.NewTransport already implements the HTTP client semantic
// conventions, the metric names, and the injection. Writing that here would
// produce spans that look almost right, which is worse than none.
func instrument(next http.RoundTripper, telemetry Telemetry) closeable {
	tracer := telemetry.TracerProvider
	if tracer == nil {
		tracer = tracenoop.NewTracerProvider()
	}

	meter := telemetry.MeterProvider
	if meter == nil {
		meter = metricnoop.NewMeterProvider()
	}

	// An empty composite injects nothing, which is what an unconfigured
	// service should send: a header naming a trace nobody is recording tells
	// the peer to join a trace that will never have a parent span.
	propagator := telemetry.Propagator
	if propagator == nil {
		propagator = propagation.NewCompositeTextMapPropagator()
	}

	return closeable{
		RoundTripper: otelhttp.NewTransport(next,
			otelhttp.WithTracerProvider(tracer),
			otelhttp.WithMeterProvider(meter),
			otelhttp.WithPropagators(propagator),
		),
		pool: next,
	}
}

// closeable restores CloseIdleConnections to an instrumented transport.
//
// http.Client.CloseIdleConnections finds the method by type assertion on its
// Transport, and otelhttp.Transport does not have one. Wrapping therefore
// makes the call a silent no-op: it still compiles, still returns, and leaves
// every connection open. Delegating to the transport underneath is the whole
// of the fix.
type closeable struct {
	http.RoundTripper

	// pool is the transport the connections actually belong to.
	pool http.RoundTripper
}

// CloseIdleConnections closes the connections the underlying transport is
// holding idle. A transport that has no such method keeps none this call could
// close, so there is nothing to do and nothing to report.
func (c closeable) CloseIdleConnections() {
	if pool, ok := c.pool.(interface{ CloseIdleConnections() }); ok {
		pool.CloseIdleConnections()
	}
}
