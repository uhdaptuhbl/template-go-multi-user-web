package httpclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// echoTraceparent returns a server that records the traceparent header of the
// last request it served, which is how the header the client actually sent is
// observed rather than assumed.
func echoTraceparent(t *testing.T, seen chan<- string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Cleanup(server.Close)

	return server
}

// get performs one request through client and closes the response.
func get(t *testing.T, client *http.Client, url string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("Do error = %v, want nil", err)
	}

	response.Body.Close()
}

// TestClientRecordsASpanThroughTheSuppliedProvider covers AC-006.10.
func TestClientRecordsASpanThroughTheSuppliedProvider(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 1)
	server := echoTraceparent(t, seen)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	client, err := New(Default(), Telemetry{TracerProvider: provider})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	get(t, client, server.URL)
	<-seen

	if forceFlushErr := provider.ForceFlush(t.Context()); forceFlushErr != nil {
		t.Fatalf("flushing the provider: %v", forceFlushErr)
	}

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Fatal("no span was recorded: an outbound request that appears in no trace cannot be joined to the inbound one that caused it")
	}

	if kind := spans[len(spans)-1].SpanKind(); kind != trace.SpanKindClient {
		t.Errorf("span kind is %v, want %v", kind, trace.SpanKindClient)
	}
}

// TestClientRecordsNothingWithoutAProvider covers AC-006.10.
func TestClientRecordsNothingWithoutAProvider(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 1)
	server := echoTraceparent(t, seen)

	client, err := New(Default(), Telemetry{})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	get(t, client, server.URL)

	if header := <-seen; header != "" {
		t.Errorf("traceparent was %q, want it absent: an untraced build must not inject a context it is not recording", header)
	}
}

// TestClientInjectsNothingWithoutAPropagator covers AC-006.10.
//
// The tracer is supplied here and the propagator is not, which is the case
// that distinguishes the two fallbacks: with neither supplied there is no
// valid span context to inject and any propagator would send nothing. Each
// provider is opted into separately, the same way internal/server does it, so
// a service that has not asked to propagate does not start doing so because
// it turned tracing on.
func TestClientInjectsNothingWithoutAPropagator(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 1)
	server := echoTraceparent(t, seen)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	client, err := New(Default(), Telemetry{TracerProvider: provider})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	ctx, span := provider.Tracer("test").Start(t.Context(), "caller")

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, http.NoBody)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("Do error = %v, want nil", err)
	}

	response.Body.Close()
	span.End()

	if header := <-seen; header != "" {
		t.Errorf("traceparent was %q, want it absent: propagation was never asked for", header)
	}
}

// TestClientPropagatesTheTraceContext covers AC-006.12.
func TestClientPropagatesTheTraceContext(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 1)
	server := echoTraceparent(t, seen)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	client, err := New(Default(), Telemetry{
		TracerProvider: provider,
		Propagator:     propagation.TraceContext{},
	})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	ctx, span := provider.Tracer("test").Start(t.Context(), "caller")

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, http.NoBody)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("Do error = %v, want nil", err)
	}

	response.Body.Close()
	span.End()

	header := <-seen
	if header == "" {
		t.Fatal("no traceparent header was sent: the peer starts a second trace and the two halves of one action cannot be joined")
	}

	// A W3C traceparent is version-traceid-spanid-flags. Comparing the field
	// rather than searching the string, so a header that merely happens to
	// contain the ID somewhere does not pass.
	fields := strings.Split(header, "-")
	if len(fields) < 2 || fields[1] != span.SpanContext().TraceID().String() {
		t.Errorf("traceparent %q does not carry the caller's trace ID %s", header, span.SpanContext().TraceID())
	}
}

// TestClientIgnoresTheOpenTelemetryGlobals covers AC-006.11.
//
// The two tests above establish that a client with no providers records and
// injects nothing, but neither of them can fail for this criterion's reason:
// the package-level globals are no-ops in a test binary unless something
// installs one, so a client reading them would have recorded nothing either.
// Installing a recording global is what makes the difference observable.
//
// Not parallel, because it replaces process-global state. The other tests in
// this package never read the globals, so they are unaffected either way.
func TestClientIgnoresTheOpenTelemetryGlobals(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	previousTracer := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()

	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	t.Cleanup(func() {
		otel.SetTracerProvider(previousTracer)
		otel.SetTextMapPropagator(previousPropagator)
	})

	seen := make(chan string, 1)
	server := echoTraceparent(t, seen)

	client, err := New(Default(), Telemetry{})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	// Through the global tracer, so the context carries a span context the
	// global propagator would happily inject if the client consulted it.
	ctx, span := otel.GetTracerProvider().Tracer("test").Start(t.Context(), "caller")

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, http.NoBody)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("Do error = %v, want nil", err)
	}

	response.Body.Close()
	span.End()

	if header := <-seen; header != "" {
		t.Errorf("traceparent was %q, want it absent: the propagator was taken from the globals", header)
	}

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("the global provider recorded %d spans, want 1: only the caller's span belongs to it", len(spans))
	}

	if name := spans[0].Name(); name != "caller" {
		t.Errorf("the global provider recorded a span named %q, want only %q", name, "caller")
	}
}
