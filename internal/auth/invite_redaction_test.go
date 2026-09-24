package auth

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

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
)

// redactionTestToken is the invite token the test in this file puts in a
// request path. Any log field or span attribute carrying it is a leak.
const redactionTestToken = "crossS1teINVITEsecret"

// redactionTestCookieName is the session cookie name the test hands
// RejectCrossSite, so that the request's cookie brings it under the check.
const redactionTestCookieName = "service_session"

// redactionTestOrigin is the public origin the test hands RejectCrossSite.
const redactionTestOrigin = "https://service.example"

// TestInviteTokenNotLoggedByCrossSiteRejection covers AC-008.87: a
// cross-site POST to /i/<token> carrying a session cookie is rejected by
// RejectCrossSite inside server.NewMux's chain, and neither the rejection's
// warn line, the access log, nor the span carries the token.
func TestInviteTokenNotLoggedByCrossSiteRejection(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	spans := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))

	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutting down tracer provider: %v", err)
		}
	})

	crossSite := func(next http.Handler) http.Handler {
		return RejectCrossSite(redactionTestOrigin, redactionTestCookieName, logger, next)
	}

	mux := server.NewMux(server.DefaultConfig(), server.TrustedProxies{}, server.NewReadiness(), logger,
		server.Telemetry{TracerProvider: provider}, http.NotFoundHandler(), nil, crossSite)

	req := httptest.NewRequest(http.MethodPost, redactionTestOrigin+"/i/"+redactionTestToken, http.NoBody)
	req.AddCookie(&http.Cookie{Name: redactionTestCookieName, Value: "session"}) //nolint:gosec // a request cookie, not a response one
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	if len(logs.FilterMessage("auth: rejecting cross-site request").All()) != 1 {
		t.Fatal("want exactly one cross-site rejection warn line")
	}

	assertNoInviteTokenObserved(t, logs, spans)
}

// assertNoInviteTokenObserved fails the test if redactionTestToken appears in
// any log message or string field in logs, or in any ended span's name,
// attributes, or event attributes in spans.
func assertNoInviteTokenObserved(t *testing.T, logs *observer.ObservedLogs, spans *tracetest.SpanRecorder) {
	t.Helper()

	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, redactionTestToken) {
			t.Errorf("log message %q contains the invite token", entry.Message)
		}

		for key, value := range entry.ContextMap() {
			if s, ok := value.(string); ok && strings.Contains(s, redactionTestToken) {
				t.Errorf("log field %q = %q contains the invite token", key, s)
			}
		}
	}

	for _, span := range spans.Ended() {
		if strings.Contains(span.Name(), redactionTestToken) {
			t.Errorf("span name %q contains the invite token", span.Name())
		}

		for _, attr := range span.Attributes() {
			if strings.Contains(attr.Value.String(), redactionTestToken) {
				t.Errorf("span attribute %s = %q contains the invite token", attr.Key, attr.Value.String())
			}
		}

		for _, event := range span.Events() {
			for _, attr := range event.Attributes {
				if strings.Contains(attr.Value.String(), redactionTestToken) {
					t.Errorf("span event attribute %s = %q contains the invite token", attr.Key, attr.Value.String())
				}
			}
		}
	}
}
