package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// Tests in this package run in parallel, with one exception. The providers
// are no longer global, but the SDK error handler still is, so the one test
// that asserts against that handler,
// TestSetupTracingRoutesSDKErrorsToTheLogger, is serial: Go starts parallel
// tests only after every serial test in the package has finished, so no other
// test's SetupTracing can replace the handler while it runs.

// TestDefaultConfigNamesTheServiceAndLeavesExportDisabled covers AC-001.17.
// DefaultConfig and TracesEndpoint are the whole of this package's
// configuration behaviour. Reading the environment into a Config is the
// config package's job and is tested there, against a lookuper rather than
// against process state.
func TestDefaultConfigNamesTheServiceAndLeavesExportDisabled(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	if cfg.ServiceName != DefaultServiceName {
		t.Errorf("ServiceName is %q, want %q", cfg.ServiceName, DefaultServiceName)
	}

	// Export stays off until an endpoint is configured, so a process that is
	// never told about a collector does not spend anything trying to reach one.
	if endpoint := cfg.TracesEndpoint(); endpoint != "" {
		t.Errorf("TracesEndpoint() is %q, want tracing disabled", endpoint)
	}
}

// TestTracesEndpointPrefersTheSignalSpecificSetting covers AC-001.22.
func TestTracesEndpointPrefersTheSignalSpecificSetting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "neither is set",
			cfg:  Config{},
			want: "",
		},
		{
			// The OpenTelemetry specification's OTLP exporter section: the
			// general variable is a base URL, to which an OTLP/HTTP exporter
			// appends v1/traces. This row once expected the base URL back
			// unchanged, which sent every export to "/".
			name: "only the general endpoint is set",
			cfg:  Config{OTLPEndpoint: "http://general:4318"},
			want: "http://general:4318/v1/traces",
		},
		{
			name: "only the traces endpoint is set",
			cfg:  Config{OTLPTracesEndpoint: "http://traces:4318"},
			want: "http://traces:4318",
		},
		{
			// Required by the OpenTelemetry specification: the
			// signal-specific variable takes precedence over the general one.
			name: "both are set",
			cfg: Config{
				OTLPEndpoint:       "http://general:4318",
				OTLPTracesEndpoint: "http://traces:4318",
			},
			want: "http://traces:4318",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.cfg.TracesEndpoint(); got != test.want {
				t.Errorf("TracesEndpoint() is %q, want %q", got, test.want)
			}
		})
	}
}

// TestTracesEndpointAppendsTheSignalPathToTheGeneralEndpoint covers AC-001.33.
func TestTracesEndpointAppendsTheSignalPathToTheGeneralEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "a base URL with no path",
			cfg:  Config{OTLPEndpoint: "http://collector:4318"},
			want: "http://collector:4318/v1/traces",
		},
		{
			name: "a base URL with a trailing slash",
			cfg:  Config{OTLPEndpoint: "http://collector:4318/"},
			want: "http://collector:4318/v1/traces",
		},
		{
			name: "a base URL with a path prefix",
			cfg:  Config{OTLPEndpoint: "http://collector:4318/otlp"},
			want: "http://collector:4318/otlp/v1/traces",
		},
		{
			// The signal-specific variable is already the full URL, so it is
			// used exactly as given.
			name: "a traces-specific endpoint",
			cfg:  Config{OTLPTracesEndpoint: "http://collector:4318/custom"},
			want: "http://collector:4318/custom",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.cfg.TracesEndpoint(); got != test.want {
				t.Errorf("TracesEndpoint() is %q, want %q", got, test.want)
			}
		})
	}
}

// TestSetupTracingExportsToTheSignalPathOfTheGeneralEndpoint covers AC-001.33.
func TestSetupTracingExportsToTheSignalPathOfTheGeneralEndpoint(t *testing.T) {
	t.Parallel()

	paths := make(chan string, 8)
	collector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths <- request.URL.Path
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	tracing, err := SetupTracing(t.Context(), Config{
		ServiceName:  "test",
		OTLPEndpoint: collector.URL,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("SetupTracing returned error: %v", err)
	}

	_, span := tracing.TracerProvider().Tracer("test").Start(t.Context(), "span")
	span.End()

	// Shutdown flushes the batcher, so the export has been attempted by the
	// time it returns.
	if shutdownErr := tracing.Shutdown(t.Context()); shutdownErr != nil {
		t.Fatalf("Shutdown returned error: %v", shutdownErr)
	}

	select {
	case path := <-paths:
		if path != "/v1/traces" {
			t.Errorf("the exporter posted to %q, want %q", path, "/v1/traces")
		}
	default:
		t.Fatal("the exporter sent nothing to the collector")
	}
}

// TestSetupTracingWithoutAnEndpointLeavesExportDisabled covers AC-001.17.
func TestSetupTracingWithoutAnEndpointLeavesExportDisabled(t *testing.T) {
	t.Parallel()

	tracing, err := SetupTracing(t.Context(), Config{ServiceName: "test"}, zap.NewNop())
	if err != nil {
		t.Fatalf("SetupTracing returned error: %v", err)
	}

	if tracing.Enabled() {
		t.Error("Enabled() is true with no collector endpoint configured")
	}

	// Callers pass this to instrumentation unconditionally, so a disabled
	// pipeline has to hand back something usable rather than nil.
	_, span := tracing.TracerProvider().Tracer("test").Start(t.Context(), "span")
	defer span.End()

	if span.IsRecording() {
		t.Error("the disabled pipeline's tracer provider records spans")
	}

	if shutdownErr := tracing.Shutdown(t.Context()); shutdownErr != nil {
		t.Errorf("Shutdown on a disabled pipeline returned error: %v", shutdownErr)
	}
}

// TestSetupTracingProvidesPropagationEvenWhenDisabled covers AC-001.17.
func TestSetupTracingProvidesPropagationEvenWhenDisabled(t *testing.T) {
	t.Parallel()

	// The point of the behaviour: a process that exports nothing must still
	// carry an inbound trace onward rather than terminating it at this hop.
	tracing, err := SetupTracing(t.Context(), Config{ServiceName: "test"}, zap.NewNop())
	if err != nil {
		t.Fatalf("SetupTracing returned error: %v", err)
	}

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const spanID = "00f067aa0ba902b7"

	header := http.Header{}
	// Canonical form here; http.Header canonicalises on both Set and Get, so this
	// is the same header the lowercase wire form produces.
	header.Set("Traceparent", "00-"+traceID+"-"+spanID+"-01")

	ctx := tracing.Propagator().Extract(t.Context(), propagation.HeaderCarrier(header))

	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		t.Fatal("propagator did not extract a valid span context from a traceparent header")
	}

	if sc.TraceID().String() != traceID {
		t.Errorf("extracted trace ID %q, want %q", sc.TraceID().String(), traceID)
	}
}

// TestSetupTracingWithAnEndpointEnablesExport covers AC-001.15.
func TestSetupTracingWithAnEndpointEnablesExport(t *testing.T) {
	t.Parallel()

	// No collector has to exist: the OTLP/HTTP exporter connects lazily, so
	// construction succeeding is what is under test here, not reachability.
	tracing, err := SetupTracing(t.Context(), Config{
		ServiceName:  "test",
		OTLPEndpoint: "http://127.0.0.1:4318",
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("SetupTracing returned error: %v", err)
	}

	t.Cleanup(func() {
		if shutdownErr := tracing.Shutdown(context.Background()); shutdownErr != nil {
			t.Errorf("Shutdown returned error: %v", shutdownErr)
		}
	})

	if !tracing.Enabled() {
		t.Error("Enabled() is false after configuring a collector endpoint")
	}

	_, span := tracing.TracerProvider().Tracer("test").Start(t.Context(), "span")
	defer span.End()

	if !span.IsRecording() {
		t.Error("the enabled pipeline's tracer provider does not record spans")
	}
}

// TestSetupInstallsNoGlobalProviders covers AC-005.18.
func TestSetupInstallsNoGlobalProviders(t *testing.T) {
	t.Parallel()

	// Each pipeline hands its provider back rather than installing it, so a
	// package that was not given one cannot record through it by accident.
	tracing, err := SetupTracing(t.Context(), Config{
		ServiceName:  "test",
		OTLPEndpoint: "http://127.0.0.1:4318",
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("SetupTracing returned error: %v", err)
	}

	t.Cleanup(func() {
		if shutdownErr := tracing.Shutdown(context.Background()); shutdownErr != nil {
			t.Errorf("Shutdown returned error: %v", shutdownErr)
		}
	})

	metrics, err := SetupMetrics(Config{ServiceName: "test"}, zap.NewNop())
	if err != nil {
		t.Fatalf("SetupMetrics returned error: %v", err)
	}

	t.Cleanup(func() {
		if shutdownErr := metrics.Shutdown(context.Background()); shutdownErr != nil {
			t.Errorf("Shutdown returned error: %v", shutdownErr)
		}
	})

	if otel.GetTracerProvider() == tracing.TracerProvider() {
		t.Error("SetupTracing installed its tracer provider as the global one")
	}

	if otel.GetMeterProvider() == metrics.MeterProvider() {
		t.Error("SetupMetrics installed its meter provider as the global one")
	}

	// The global propagator carries no fields until something installs one,
	// which is how a missing explicit propagator stays visible as a bug here
	// rather than silently working through process-wide state.
	if fields := otel.GetTextMapPropagator().Fields(); len(fields) != 0 {
		t.Errorf("SetupTracing installed the global propagator; it carries fields %v", fields)
	}
}

// TestSetupTracingRoutesSDKErrorsToTheLogger covers AC-005.23.
// Deliberately not parallel. SetupTracing installs a process-global error
// handler through otel.SetErrorHandler, which the SDK offers no non-global
// alternative to, and this test asserts that the error reached the logger it
// installed. A concurrent SetupTracing would replace the handler and send the
// error somewhere else. Serial tests complete before any parallel test starts,
// so the other tests here can still run together.
func TestSetupTracingRoutesSDKErrorsToTheLogger(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)

	if _, err := SetupTracing(t.Context(), Config{ServiceName: "test"}, zap.New(core)); err != nil {
		t.Fatalf("SetupTracing returned error: %v", err)
	}

	// Without an installed handler the SDK writes this to stderr through the
	// standard log package, which ADR 0003 rules out.
	otel.Handle(errors.New("exporter fell over"))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if got := entries[0].ContextMap()["error"]; got != "exporter fell over" {
		t.Errorf("got error field %v, want the SDK error message", got)
	}
}

// TestZeroValueTracingYieldsUsableProviders cites no criterion: it guards
// the exported type's behaviour on its zero value, which SetupTracing never
// produces.
func TestZeroValueTracingYieldsUsableProviders(t *testing.T) {
	t.Parallel()

	// Tracing is documented as obtained from SetupTracing, but neither accessor
	// may hand back something a caller would have to nil-check before using.
	var tracing Tracing

	_, span := tracing.TracerProvider().Tracer("test").Start(t.Context(), "span")
	defer span.End()

	if span.IsRecording() {
		t.Error("a zero-value Tracing recorded a span")
	}

	header := http.Header{}
	header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	ctx := tracing.Propagator().Extract(t.Context(), propagation.HeaderCarrier(header))

	if trace.SpanContextFromContext(ctx).IsValid() {
		t.Error("a zero-value Tracing extracted a span context it was never given a propagator for")
	}
}
