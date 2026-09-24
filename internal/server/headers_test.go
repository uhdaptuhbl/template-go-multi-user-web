package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestMuxSetsSecurityHeadersOnEveryResponse covers AC-005.13.
func TestMuxSetsSecurityHeadersOnEveryResponse(t *testing.T) {
	t.Parallel()

	// A body limit of one byte makes the middleware reject the POST before any
	// handler runs, which is the response most likely to be missing headers.
	cfg := DefaultConfig()
	cfg.MaxRequestBodyBytes = 1

	mux := NewMux(cfg, TrustedProxies{}, NewReadiness(), zap.NewNop(), Telemetry{}, testUI(t), nil)

	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		wantStatus int
	}{
		{name: "health", method: http.MethodGet, target: healthPath, wantStatus: http.StatusOK},
		{name: "ui", method: http.MethodGet, target: "/anything", wantStatus: http.StatusOK},
		{name: "rejected by middleware", method: http.MethodPost, target: "/anything", body: "too long", wantStatus: http.StatusRequestEntityTooLarge},
	}

	wantHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(test.method, test.target, strings.NewReader(test.body)))

			if recorder.Code != test.wantStatus {
				t.Errorf("got status %d, want %d", recorder.Code, test.wantStatus)
			}

			for name, want := range wantHeaders {
				if got := recorder.Header().Get(name); got != want {
					t.Errorf("got %s %q, want %q", name, got, want)
				}
			}
		})
	}
}

// TestSecurityHeadersYieldToAHandlersOwnPolicy covers AC-005.14.
func TestSecurityHeadersYieldToAHandlersOwnPolicy(t *testing.T) {
	t.Parallel()

	const ownPolicy = "default-src 'self'; frame-ancestors 'none'"

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", ownPolicy)
		w.WriteHeader(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	withSecurityHeaders(inner).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if got := recorder.Header().Get("Content-Security-Policy"); got != ownPolicy {
		t.Errorf("got Content-Security-Policy %q, want the handler's own %q", got, ownPolicy)
	}

	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("got X-Content-Type-Options %q, want %q", got, "nosniff")
	}
}
