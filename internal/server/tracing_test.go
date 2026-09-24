package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// recordingSpanRequest returns a request whose context carries a live recording
// span, plus the recorder that will hold it once ended, standing in for the
// span the HTTP instrumentation creates in production.
func recordingSpanRequest(t *testing.T, method, target string) (*http.Request, *tracetest.SpanRecorder, func()) {
	t.Helper()

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	ctx, span := provider.Tracer("test").Start(t.Context(), "http.server")
	req := httptest.NewRequest(method, target, http.NoBody).WithContext(ctx)

	return req, recorder, func() { span.End() }
}

// TestWithRequestLoggingNamesTheSpanAfterTheMatchedRoute covers AC-001.29.
func TestWithRequestLoggingNamesTheSpanAfterTheMatchedRoute(t *testing.T) {
	t.Parallel()

	// A span named after the raw path has unbounded cardinality; one named after
	// the handler's default is identical for every endpoint. The matched route is
	// the useful middle ground.
	tests := []struct {
		name     string
		target   string
		wantName string
	}{
		{name: "specific route", target: "/healthz", wantName: "GET /healthz"},
		{name: "catch-all route", target: "/anything/at/all", wantName: "GET /"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			req, recorder, end := recordingSpanRequest(t, http.MethodGet, test.target)

			withRequestLogging(TrustedProxies{}, zap.NewNop(), testRoutes(t)).ServeHTTP(httptest.NewRecorder(), req)
			end()

			spans := recorder.Ended()
			if len(spans) != 1 {
				t.Fatalf("got %d ended spans, want 1", len(spans))
			}

			if spans[0].Name() != test.wantName {
				t.Errorf("span name is %q, want %q", spans[0].Name(), test.wantName)
			}
		})
	}
}

// TestWithRequestLoggingCorrelatesTheLogEntryWithTheTrace covers AC-001.14 and AC-001.15.
func TestWithRequestLoggingCorrelatesTheLogEntryWithTheTrace(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)
	req, _, end := recordingSpanRequest(t, http.MethodGet, "/healthz")

	withRequestLogging(TrustedProxies{}, zap.New(core), testRoutes(t)).ServeHTTP(httptest.NewRecorder(), req)
	end()

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	fields := entries[0].ContextMap()

	// Correlation is the whole point: without these a log line cannot be joined
	// to the trace that produced it. Comparing against the actual span context
	// rather than just checking non-emptiness catches a field wired to the wrong
	// identifier.
	sc := trace.SpanContextFromContext(req.Context())

	if fields["trace_id"] != sc.TraceID().String() {
		t.Errorf("got trace_id %v, want %q", fields["trace_id"], sc.TraceID().String())
	}

	if fields["span_id"] != sc.SpanID().String() {
		t.Errorf("got span_id %v, want %q", fields["span_id"], sc.SpanID().String())
	}

	if fields["route"] != "GET /healthz" {
		t.Errorf("got route field %v, want %q", fields["route"], "GET /healthz")
	}
}

// TestWithRequestLoggingOmitsTraceFieldsWhenNoSpanIsActive covers AC-001.30.
func TestWithRequestLoggingOmitsTraceFieldsWhenNoSpanIsActive(t *testing.T) {
	t.Parallel()

	// Tracing is off by default. Emitting the zero trace ID would imply a trace
	// that does not exist and pollute any log-to-trace query.
	core, logs := observer.New(zapcore.InfoLevel)

	withRequestLogging(TrustedProxies{}, zap.New(core), testRoutes(t)).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	fields := entries[0].ContextMap()

	if _, ok := fields["trace_id"]; ok {
		t.Errorf("log entry carries trace_id %v with no active span", fields["trace_id"])
	}

	if _, ok := fields["span_id"]; ok {
		t.Errorf("log entry carries span_id %v with no active span", fields["span_id"])
	}
}

// TestShouldTraceExcludesTheLivenessProbe covers AC-001.16.
func TestShouldTraceExcludesTheLivenessProbe(t *testing.T) {
	t.Parallel()

	// Liveness probes arrive continuously and describe nothing about
	// application behaviour, so tracing them crowds out real requests.
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "liveness probe is excluded", target: healthPath, want: false},
		{name: "application request is traced", target: "/", want: true},
		{name: "asset request is traced", target: "/app.js", want: true},
		{name: "path merely containing the health route is traced", target: "/healthz/sub", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := shouldTrace(httptest.NewRequest(http.MethodGet, test.target, http.NoBody))
			if got != test.want {
				t.Errorf("shouldTrace(%q) is %t, want %t", test.target, got, test.want)
			}
		})
	}
}
