package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// testMux builds the root handler with a stand-in UI handler, so route tests do
// not depend on the embedded frontend.
func testMux(t *testing.T) http.Handler {
	t.Helper()

	return NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), zap.NewNop(), Telemetry{}, testUI(t), nil)
}

// testUI is a stand-in for the embedded frontend handler.
func testUI(t *testing.T) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// testRoutes is the route table alone, without the tracing and logging wrappers
// NewMux applies. Middleware tests wrap it themselves so that the middleware
// under test is the only one in the chain.
func testRoutes(t *testing.T) http.Handler {
	t.Helper()

	mux := http.NewServeMux()
	mux.Handle("GET "+healthPath, newHealthHandler(zap.NewNop()))
	mux.Handle("/", testUI(t))

	return mux
}

// TestNewMuxRouting covers AC-001.6 and AC-001.7.
func TestNewMuxRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int
	}{
		{name: "health responds ok", method: http.MethodGet, target: "/healthz", wantStatus: http.StatusOK},
		{name: "unmatched path falls through to ui", method: http.MethodGet, target: "/anything", wantStatus: http.StatusOK},
		// The "/" catch-all matches any method, so a method mismatch on a
		// specific route reaches the UI handler instead of yielding 405.
		// ServeMux only synthesises 405 when nothing else matches the request.
		{name: "wrong method on health falls through to ui", method: http.MethodPost, target: "/healthz", wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			testMux(t).ServeHTTP(recorder, httptest.NewRequest(test.method, test.target, http.NoBody))

			if recorder.Code != test.wantStatus {
				t.Errorf("%s %s returned status %d, want %d", test.method, test.target, recorder.Code, test.wantStatus)
			}
		})
	}
}

// TestHealthResponseBody covers AC-001.6.
func TestHealthResponseBody(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	testMux(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))

	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("got Content-Type %q, want %q", got, "application/json")
	}

	var body healthResponse
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decoding health response: %v", err)
	}

	if body.Status != "ok" {
		t.Errorf("got status %q, want %q", body.Status, "ok")
	}
}

// TestStatusRecorderExposesTheUnderlyingWriter cites no criterion: Unwrap is
// internal plumbing between this middleware and net/http, observable only as
// the absence of the failures described at the assertion.
func TestStatusRecorderExposesTheUnderlyingWriter(t *testing.T) {
	t.Parallel()

	// http.ResponseController walks a wrapper chain by calling Unwrap. Without
	// it, any handler behind this middleware loses the ability to flush, hijack,
	// or set a deadline, which is how net/http/pprof keeps a long profile from
	// tripping the server's write timeout.
	var flushed bool

	handler := withRequestLogging(TrustedProxies{}, zap.NewNop(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush through the middleware failed: %v", err)

			return
		}

		flushed = true
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if !flushed {
		t.Error("handler behind the middleware could not reach the underlying writer")
	}
}

// TestWithRequestLoggingPreservesTheResponse covers AC-001.14.
func TestWithRequestLoggingPreservesTheResponse(t *testing.T) {
	t.Parallel()

	handler := withRequestLogging(TrustedProxies{}, zap.NewNop(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if recorder.Code != http.StatusTeapot {
		t.Errorf("got status %d, want %d: middleware must not alter the response", recorder.Code, http.StatusTeapot)
	}
}

// TestWithRequestLoggingEmitsOneEntryDescribingTheRequest covers AC-001.14.
func TestWithRequestLoggingEmitsOneEntryDescribingTheRequest(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)
	handler := withRequestLogging(TrustedProxies{}, zap.New(core), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/some/path", http.NoBody))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want exactly 1 per request", len(entries))
	}

	fields := entries[0].ContextMap()

	if fields["method"] != http.MethodPost {
		t.Errorf("got method field %v, want %q", fields["method"], http.MethodPost)
	}

	if fields["path"] != "/some/path" {
		t.Errorf("got path field %v, want %q", fields["path"], "/some/path")
	}

	if fields["status"] != int64(http.StatusTeapot) {
		t.Errorf("got status field %v, want %d", fields["status"], http.StatusTeapot)
	}

	if _, ok := fields["duration"]; !ok {
		t.Error("log entry has no duration field")
	}
}

// TestWithRequestLoggingReportsOKWhenTheHandlerOmitsWriteHeader covers AC-001.14.
func TestWithRequestLoggingReportsOKWhenTheHandlerOmitsWriteHeader(t *testing.T) {
	t.Parallel()

	// net/http implies 200 for a handler that writes a body without setting a
	// status. statusRecorder must report that, not the zero value it would
	// otherwise hold.
	core, logs := observer.New(zapcore.InfoLevel)
	handler := withRequestLogging(TrustedProxies{}, zap.New(core), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, "body with no explicit status"); err != nil {
			t.Errorf("writing response body: %v", err)
		}
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want exactly 1 per request", len(entries))
	}

	if got := entries[0].ContextMap()["status"]; got != int64(http.StatusOK) {
		t.Errorf("got status field %v, want %d", got, http.StatusOK)
	}
}

// TestRequestLogLevelFollowsStatus covers AC-002.12.
func TestRequestLogLevelFollowsStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		status    int
		wantLevel zapcore.Level
	}{
		{name: "200 logs at info", status: http.StatusOK, wantLevel: zapcore.InfoLevel},
		{name: "204 logs at info", status: http.StatusNoContent, wantLevel: zapcore.InfoLevel},
		{name: "404 logs at warn", status: http.StatusNotFound, wantLevel: zapcore.WarnLevel},
		{name: "418 logs at warn", status: http.StatusTeapot, wantLevel: zapcore.WarnLevel},
		{name: "500 logs at error", status: http.StatusInternalServerError, wantLevel: zapcore.ErrorLevel},
		{name: "503 logs at error", status: http.StatusServiceUnavailable, wantLevel: zapcore.ErrorLevel},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			core, logs := observer.New(zapcore.DebugLevel)
			handler := withRequestLogging(TrustedProxies{}, zap.New(core), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
			}))

			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))

			entries := logs.All()
			if len(entries) != 1 {
				t.Fatalf("got %d log entries, want exactly 1 per request", len(entries))
			}

			if entries[0].Level != test.wantLevel {
				t.Errorf("got level %v, want %v", entries[0].Level, test.wantLevel)
			}
		})
	}
}

// TestRequestLogCarriesCorrelationFields covers AC-002.9 and AC-002.11.
func TestRequestLogCarriesCorrelationFields(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	handler := withRequestID(TrustedProxies{}, withRequestLogging(TrustedProxies{}, logger, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	request := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	request.RemoteAddr = "203.0.113.7:54321"

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want exactly 1 per request", len(entries))
	}

	fields := entries[0].ContextMap()

	requestID, _ := fields["request_id"].(string)
	if requestID == "" {
		t.Error("got empty request_id field, want a non-empty identifier")
	}

	if got := recorder.Header().Get(RequestIDHeader); got != requestID {
		t.Errorf("got %s header %q, want it to match logged request_id %q", RequestIDHeader, got, requestID)
	}

	if fields["client_ip"] != "203.0.113.7" {
		t.Errorf("got client_ip field %v, want %q", fields["client_ip"], "203.0.113.7")
	}
}

// TestMuxServesReadiness covers AC-002.13.
func TestMuxServesReadiness(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	testMux(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))

	if recorder.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusOK)
	}

	if got := strings.TrimSuffix(recorder.Body.String(), "\n"); got != `{"status":"ready"}` {
		t.Errorf("got body %q, want %q", got, `{"status":"ready"}`)
	}
}

// TestMuxRecoversHandlerPanic covers AC-002.1.
func TestMuxRecoversHandlerPanic(t *testing.T) {
	t.Parallel()

	panicUI := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	})

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), zap.NewNop(), Telemetry{}, panicUI, nil)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusInternalServerError)
	}

	want := `{"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}`
	if got := strings.TrimSuffix(recorder.Body.String(), "\n"); got != want {
		t.Errorf("got body %q, want %q", got, want)
	}
}

// TestMuxRecordsThroughTheSuppliedTelemetry covers AC-005.17.
func TestMuxRecordsThroughTheSuppliedTelemetry(t *testing.T) {
	t.Parallel()

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"

	spans := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))

	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutting down tracer provider: %v", err)
		}
	})

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), zap.NewNop(), Telemetry{
		TracerProvider: provider,
		Propagator:     propagation.TraceContext{},
	}, testUI(t), nil)

	request := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	request.Header.Set("Traceparent", "00-"+traceID+"-00f067aa0ba902b7-01")

	mux.ServeHTTP(httptest.NewRecorder(), request)

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(ended))
	}

	// The span exists only if NewMux passed the provider to the
	// instrumentation, and its trace ID matches the inbound one only if the
	// supplied propagator read the header. Neither is reachable through a
	// global here, because nothing in this test installs one.
	if got := ended[0].SpanContext().TraceID().String(); got != traceID {
		t.Errorf("span has trace ID %q, want the inbound %q", got, traceID)
	}
}

// TestMuxWithZeroTelemetryIgnoresInboundTraceHeaders covers AC-005.17.
func TestMuxWithZeroTelemetryIgnoresInboundTraceHeaders(t *testing.T) {
	t.Parallel()

	var captured trace.SpanContext

	ui := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = trace.SpanContextFromContext(r.Context())
	})

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), zap.NewNop(), Telemetry{}, ui, nil)

	request := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	request.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	mux.ServeHTTP(httptest.NewRecorder(), request)

	// A zero value records nothing and reads nothing: the inbound header is not
	// extracted, so whatever a process installed globally cannot change what
	// this handler sees.
	if captured.IsValid() {
		t.Errorf("zero-value Telemetry extracted a span context from an inbound traceparent: %v", captured)
	}
}

// TestNewMuxRegistersAPIRoutesAheadOfTheFrontendFallback cites no criterion:
// it guards NewMux's api parameter itself, the plumbing every authentication
// route (AC-008.33, AC-008.34, and the rest of the routes and error shapes
// in design.md's "Interfaces" section) depends on to reach the mux at all,
// rather than one criterion's case.
func TestNewMuxRegistersAPIRoutesAheadOfTheFrontendFallback(t *testing.T) {
	t.Parallel()

	sentinel := "api route"
	api := func(mux *http.ServeMux) {
		mux.Handle("GET /api/v1/ping", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := io.WriteString(w, sentinel); err != nil {
				t.Errorf("writing sentinel body: %v", err)
			}
		}))
	}

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), zap.NewNop(), Telemetry{}, testUI(t), api)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/ping", http.NoBody))

	if got := recorder.Body.String(); got != sentinel {
		t.Errorf("GET /api/v1/ping returned body %q, want the api-registered handler's %q", got, sentinel)
	}

	frontend := httptest.NewRecorder()
	mux.ServeHTTP(frontend, httptest.NewRequest(http.MethodGet, "/something-else", http.NoBody))

	if frontend.Code != http.StatusOK {
		t.Errorf("GET /something-else returned status %d, want %d from the frontend fallback", frontend.Code, http.StatusOK)
	}
}

// TestNewMuxSuppliedMiddlewareRunsInsideEveryOtherLayer cites no criterion: it
// guards NewMux's own variadic middleware parameter, the plumbing that lets a
// caller such as cmd/service/main.go put session resolution inside the whole
// chain (tracing, security headers, request ID, access logging, panic
// recovery, the in-flight limit, the handler timeout, and the body limit)
// instead of wrapping NewMux's result from the outside, where none of those
// layers would see the request.
//
// A middleware that answers 403 on its own is the case that matters: before
// this change, a caller-supplied auth layer wrapped outside NewMux produced a
// response with no security headers, no request ID, and no access log entry.
func TestNewMuxSuppliedMiddlewareRunsInsideEveryOtherLayer(t *testing.T) {
	t.Parallel()

	rejecting := func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSONError(w, zap.NewNop(), http.StatusForbidden, ErrorCodeCrossSite, "")
		})
	}

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), logger, Telemetry{}, testUI(t), nil, rejecting)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/anything", http.NoBody))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", recorder.Code, http.StatusForbidden)
	}

	wantHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
	}

	for name, want := range wantHeaders {
		if got := recorder.Header().Get(name); got != want {
			t.Errorf("got %s %q, want %q", name, got, want)
		}
	}

	if got := recorder.Header().Get(RequestIDHeader); got == "" {
		t.Error("got empty X-Request-Id header on a response a supplied middleware wrote itself")
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d access log entries, want exactly 1 for a request a supplied middleware answered", len(entries))
	}

	if got := entries[0].ContextMap()["status"]; got != int64(http.StatusForbidden) {
		t.Errorf("got logged status %v, want %d", got, http.StatusForbidden)
	}
}

// TestNewMuxRecoversASuppliedMiddlewaresPanic cites no criterion: it guards
// the same variadic parameter as
// TestNewMuxSuppliedMiddlewareRunsInsideEveryOtherLayer against a panic
// specifically, since a panic in an authentication layer wrapped outside
// the chain was a case withPanicRecovery could not reach.
func TestNewMuxRecoversASuppliedMiddlewaresPanic(t *testing.T) {
	t.Parallel()

	panicking := func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			panic("boom from supplied middleware")
		})
	}

	core, logs := observer.New(zapcore.ErrorLevel)
	logger := zap.New(core)

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), logger, Telemetry{}, testUI(t), nil, panicking)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusInternalServerError)
	}

	// Two entries at error level are expected here, not one: the panic
	// recovery entry itself, and the access log entry withRequestLogging
	// writes at error level because levelForStatus maps the resulting 500 to
	// it. What matters is that the panic recovery entry is among them.
	entries := logs.All()

	var sawRecovery bool

	for _, entry := range entries {
		if entry.Message == "recovered panic serving request" {
			sawRecovery = true
		}
	}

	if !sawRecovery {
		t.Errorf("got log messages %v, want one of them to be the panic recovery entry", entries)
	}
}

// TestNewMuxOrdersSuppliedMiddlewareOutermostFirstInsideRequestID cites no
// criterion: it guards NewMux's documented ordering that the first supplied
// middleware is outermost of the ones supplied, and that both run inside the
// request-ID layer so RequestIDFromContext is populated by the time either
// one sees the request.
func TestNewMuxOrdersSuppliedMiddlewareOutermostFirstInsideRequestID(t *testing.T) {
	t.Parallel()

	var calls []string

	var requestIDInFirst string

	var requestIDInSecond string

	first := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, "first")
			requestIDInFirst = RequestIDFromContext(r.Context())
			next.ServeHTTP(w, r)
		})
	}

	second := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, "second")
			requestIDInSecond = RequestIDFromContext(r.Context())
			next.ServeHTTP(w, r)
		})
	}

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), zap.NewNop(), Telemetry{}, testUI(t), nil, first, second)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if len(calls) != 2 || calls[0] != "first" || calls[1] != "second" {
		t.Errorf("got call order %v, want [first second]", calls)
	}

	if requestIDInFirst == "" {
		t.Error("got empty request ID inside the first supplied middleware, want the request-ID layer to have already run")
	}

	if requestIDInSecond == "" {
		t.Error("got empty request ID inside the second supplied middleware, want the request-ID layer to have already run")
	}
}

// TestAccessLogAndSpanNameSurviveASuppliedMiddlewaresRequestClone is a
// regression test: a supplied middleware that calls r.WithContext before
// next, the way auth.Service.Authenticate does at
// internal/auth/middleware.go by wrapping the context in authz.WithSubject,
// hands the mux a different *http.Request than the one withRequestLogging
// is still holding once next.ServeHTTP returns. ServeMux sets Pattern only
// on the instance that reaches it, so reading r.Pattern from
// withRequestLogging's own copy after such a clone finds it empty; both the
// access log's "route" field and the span's name must instead reflect the
// route the mux actually matched. Cites no criterion: it guards
// withRequestLogging's own correctness against a class of middleware
// (anything that clones the request) rather than one product-facing
// criterion's case.
func TestAccessLogAndSpanNameSurviveASuppliedMiddlewaresRequestClone(t *testing.T) {
	t.Parallel()

	spans := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))

	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutting down tracer provider: %v", err)
		}
	})

	cloning := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// r.WithContext always returns a new *http.Request, even handed
			// its own context back, which is enough to reproduce the clone
			// auth.Service.Authenticate performs for real.
			next.ServeHTTP(w, r.WithContext(r.Context()))
		})
	}

	api := func(mux *http.ServeMux) {
		mux.Handle("GET /api/v1/ping", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), logger, Telemetry{TracerProvider: provider}, testUI(t), api, cloning)

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/ping", http.NoBody))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if got := entries[0].ContextMap()["route"]; got != "GET /api/v1/ping" {
		t.Errorf("got route field %v, want %q", got, "GET /api/v1/ping")
	}

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("got %d ended spans, want 1", len(ended))
	}

	if got := ended[0].Name(); got != "GET /api/v1/ping" {
		t.Errorf("got span name %q, want %q", got, "GET /api/v1/ping")
	}
}

// TestAccessLogAndSpanNameSurviveHandlerTimeoutsRequestClone is a regression
// test for the same class of bug as
// TestAccessLogAndSpanNameSurviveASuppliedMiddlewaresRequestClone, this time
// from withHandlerTimeout's own r.WithContext(ctx) at
// internal/server/limits.go, which runs whenever cfg.HandlerTimeout is
// configured above zero with no supplied middleware involved at all. Cites
// no criterion for the same reason as its sibling.
func TestAccessLogAndSpanNameSurviveHandlerTimeoutsRequestClone(t *testing.T) {
	t.Parallel()

	spans := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))

	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutting down tracer provider: %v", err)
		}
	})

	api := func(mux *http.ServeMux) {
		mux.Handle("GET /api/v1/ping", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}

	cfg := DefaultConfig()
	cfg.HandlerTimeout = configtype.Duration(5 * time.Second)

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	mux := NewMux(cfg, TrustedProxies{}, NewReadiness(), logger, Telemetry{TracerProvider: provider}, testUI(t), api)

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/ping", http.NoBody))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if got := entries[0].ContextMap()["route"]; got != "GET /api/v1/ping" {
		t.Errorf("got route field %v, want %q", got, "GET /api/v1/ping")
	}

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("got %d ended spans, want 1", len(ended))
	}

	if got := ended[0].Name(); got != "GET /api/v1/ping" {
		t.Errorf("got span name %q, want %q", got, "GET /api/v1/ping")
	}
}

// TestNewMuxDoesNotServeAdministrativeRoutes covers AC-001.9 and AC-001.10.
func TestNewMuxDoesNotServeAdministrativeRoutes(t *testing.T) {
	t.Parallel()

	// net/http/pprof registers its handlers on http.DefaultServeMux from an
	// init function, and this package imports it for the administrative mux.
	// A root mux built from the default one would therefore serve profiling
	// on the public listener without a line of code saying so. The sentinel
	// proves the frontend answered instead: these paths are not routes here,
	// so they fall through the "/" catch-all like any other unmatched path.
	sentinel := "frontend fallthrough"
	ui := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)

		if _, err := io.WriteString(w, sentinel); err != nil {
			t.Errorf("writing sentinel body: %v", err)
		}
	})

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), zap.NewNop(), Telemetry{}, ui, nil)

	administrative := []string{
		"/metrics",
		"/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/symbol",
		"/debug/pprof/trace",
	}

	for _, path := range administrative {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, http.NoBody))

			if got := recorder.Body.String(); got != sentinel {
				t.Errorf("GET %s on the application listener returned %q, want the frontend handler's %q",
					path, got, sentinel)
			}
		})
	}
}
