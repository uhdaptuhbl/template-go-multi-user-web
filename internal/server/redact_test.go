package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// redactTestSecret is the bearer value a route under test carries in its
// path. Any log field or span attribute containing it is a leak.
const redactTestSecret = "abc123SECRET"

// redactTestHarness builds a mux with two routes registered through api:
// "GET /i/{file}", whose path NewMux redacts by prefix, and
// "GET /control/{token}", which it does not, so a test can compare redacted
// and unredacted behavior against the same request shape. The mux runs through NewMux's full
// middleware chain, backed by an observed zap logger and an in-memory span
// recorder.
func redactTestHarness(t *testing.T, handle func(http.ResponseWriter, *http.Request)) (http.Handler, *observer.ObservedLogs, *tracetest.SpanRecorder) {
	t.Helper()

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutting down tracer provider: %v", err)
		}
	})

	api := func(mux *http.ServeMux) {
		mux.Handle("GET /i/{file}", http.HandlerFunc(handle))
		mux.Handle("GET /control/{token}", http.HandlerFunc(handle))
	}

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), logger,
		Telemetry{TracerProvider: provider}, testUI(t), api)

	return mux, logs, recorder
}

// assertNoFieldContains fails the test if any field logged in entries
// contains want, and reports the message plus fields for a message
// containing it too.
func assertNoFieldContains(t *testing.T, entries []observer.LoggedEntry, want string) {
	t.Helper()

	for _, entry := range entries {
		if strings.Contains(entry.Message, want) {
			t.Errorf("log message %q contains %q", entry.Message, want)
		}

		for key, value := range entry.ContextMap() {
			if s, ok := value.(string); ok && strings.Contains(s, want) {
				t.Errorf("log field %q = %q contains %q", key, s, want)
			}
		}
	}
}

// TestInvitePathRedactionRewritesTheAccessLogEntry covers AC-008.40: a
// request under /i/ logs the redacted path, not the raw request path
// carrying the secret, and the raw secret appears in no logged field.
func TestInvitePathRedactionRewritesTheAccessLogEntry(t *testing.T) {
	t.Parallel()

	mux, logs, _ := redactTestHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/i/"+redactTestSecret, http.NoBody))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if got := entries[0].ContextMap()["path"]; got != "/i/{token}" {
		t.Errorf("got path field %v, want %q", got, "/i/{token}")
	}

	assertNoFieldContains(t, entries, redactTestSecret)
}

// TestInvitePathRedactionSetsTheSpanURLPathAttribute covers AC-008.40: the
// span's url.path attribute, which the HTTP instrumentation records from the
// request path, holds the redacted form once the span ends.
func TestInvitePathRedactionSetsTheSpanURLPathAttribute(t *testing.T) {
	t.Parallel()

	mux, _, spans := redactTestHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/i/"+redactTestSecret, http.NoBody))

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("got %d ended spans, want 1", len(ended))
	}

	var sawURLPath bool

	for _, attr := range ended[0].Attributes() {
		if string(attr.Key) != "url.path" {
			continue
		}

		sawURLPath = true

		if attr.Value.AsString() != "/i/{token}" {
			t.Errorf("url.path attribute = %q, want %q", attr.Value.AsString(), "/i/{token}")
		}

		if strings.Contains(attr.Value.AsString(), redactTestSecret) {
			t.Errorf("url.path attribute %q contains the secret", attr.Value.AsString())
		}
	}

	if !sawURLPath {
		t.Fatal("ended span has no url.path attribute")
	}

	for _, attr := range ended[0].Attributes() {
		if strings.Contains(attr.Value.String(), redactTestSecret) {
			t.Errorf("span attribute %s = %q contains the secret", attr.Key, attr.Value.String())
		}
	}
}

// TestInvitePathRedactionAppliesToAWriteErrorResponse covers AC-008.40: a
// route under /i/ that answers a 5xx through WriteError still logs the redacted path
// in WriteError's own log line, not the raw one.
func TestInvitePathRedactionAppliesToAWriteErrorResponse(t *testing.T) {
	t.Parallel()

	mux, logs, _ := redactTestHarness(t, func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, zap.NewNop(), &ClientError{Status: http.StatusInternalServerError, Code: errorCodeInternal, Message: "boom"})
	})

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/i/"+redactTestSecret, http.NoBody))

	entries := logs.All()
	if len(entries) == 0 {
		t.Fatal("got 0 log entries, want at least the access log entry")
	}

	assertNoFieldContains(t, entries, redactTestSecret)
}

// TestInvitePathRedactionAppliesToAPanicRecoveryLogLine covers AC-008.40: a
// route under /i/ that panics still logs the redacted path in the panic recovery log
// line, not the raw one.
func TestInvitePathRedactionAppliesToAPanicRecoveryLogLine(t *testing.T) {
	t.Parallel()

	mux, logs, _ := redactTestHarness(t, func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/i/"+redactTestSecret, http.NoBody))

	entries := logs.All()
	if len(entries) == 0 {
		t.Fatal("got 0 log entries, want at least the panic recovery log entry")
	}

	var sawPanicEntry bool

	for _, entry := range entries {
		if entry.Message == "recovered panic serving request" {
			sawPanicEntry = true

			if got := entry.ContextMap()["path"]; got != "/i/{token}" {
				t.Errorf("panic log path field = %v, want %q", got, "/i/{token}")
			}
		}
	}

	if !sawPanicEntry {
		t.Fatal("no panic recovery log entry found")
	}

	assertNoFieldContains(t, entries, redactTestSecret)
}

// TestUnwrappedRouteStillLogsTheRawPath covers AC-008.40's converse: a
// control route outside /i/ keeps logging the true request path, proving
// the redaction is confined to the invite prefix rather than a blanket
// change to how every route is logged.
func TestUnwrappedRouteStillLogsTheRawPath(t *testing.T) {
	t.Parallel()

	mux, logs, _ := redactTestHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/control/"+redactTestSecret, http.NoBody))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	want := "/control/" + redactTestSecret
	if got := entries[0].ContextMap()["path"]; got != want {
		t.Errorf("got path field %v, want %q (control route must not be redacted)", got, want)
	}
}
