package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// testAdminMux builds the administrative handler with a stand-in metrics
// handler, so route tests do not depend on a metrics pipeline.
func testAdminMux(t *testing.T) http.Handler {
	t.Helper()

	metrics := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write([]byte("# metrics")); err != nil {
			t.Errorf("writing stub metrics body: %v", err)
		}
	})

	return NewAdminMux(DefaultAdminConfig(), zap.NewNop(), NewReadiness(), testProcessInfo(), metrics)
}

// TestNewAdminMuxRefusesAnOversizedBody covers AC-002.4.
func TestNewAdminMuxRefusesAnOversizedBody(t *testing.T) {
	t.Parallel()

	// Symbol is the only administrative route that reads a body at all, so it
	// is the only one where an unbounded read is reachable. Without a limit,
	// anyone who can reach this listener can make the process allocate as
	// much as they care to send.
	cfg := DefaultAdminConfig()
	cfg.MaxRequestBodyBytes = 16

	mux := NewAdminMux(cfg, zap.NewNop(), NewReadiness(), testProcessInfo(), http.NotFoundHandler())

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/debug/pprof/symbol", strings.NewReader(strings.Repeat("0x0+", 64)))
	mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("POST /debug/pprof/symbol with an oversized body returned status %d, want %d",
			recorder.Code, http.StatusRequestEntityTooLarge)
	}
}

// TestNewAdminMuxSetsSecurityHeaders covers AC-005.13.
func TestNewAdminMuxSetsSecurityHeaders(t *testing.T) {
	t.Parallel()

	// pprof's index is HTML served to a browser. Everything the application
	// listener needs these headers for applies here at least as strongly.
	recorder := httptest.NewRecorder()
	testAdminMux(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/debug/pprof/", http.NoBody))

	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
	}

	for header, value := range want {
		if got := recorder.Header().Get(header); got != value {
			t.Errorf("admin response %s = %q, want %q", header, got, value)
		}
	}
}

// TestNewAdminMuxRecoversFromAPanic covers AC-002.1.
func TestNewAdminMuxRecoversFromAPanic(t *testing.T) {
	t.Parallel()

	// The metrics handler is third-party code reached through a registry this
	// process fills. A panic there is not hypothetical, and without recovery
	// it drops the scraper's connection with no log entry naming the cause.
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("metrics exposition failed")
	})

	mux := NewAdminMux(DefaultAdminConfig(), zap.NewNop(), NewReadiness(), testProcessInfo(), panicking)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("GET /metrics from a panicking handler returned status %d, want %d",
			recorder.Code, http.StatusInternalServerError)
	}
}

// TestNewAdminMuxRouting covers AC-001.9, AC-001.10, and AC-002.26.
func TestNewAdminMuxRouting(t *testing.T) {
	t.Parallel()

	// The profiling routes that accept a duration are deliberately absent:
	// /debug/pprof/profile and /debug/pprof/trace block for their full sample
	// window, so exercising them would make this suite slow rather than
	// informative. Their registration is covered by the index below.
	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int
	}{
		{name: "metrics is served", method: http.MethodGet, target: "/metrics", wantStatus: http.StatusOK},
		{name: "health is served", method: http.MethodGet, target: "/healthz", wantStatus: http.StatusOK},
		{name: "version is served", method: http.MethodGet, target: "/version", wantStatus: http.StatusOK},
		{name: "pprof index is served", method: http.MethodGet, target: "/debug/pprof/", wantStatus: http.StatusOK},
		{name: "pprof cmdline is served", method: http.MethodGet, target: "/debug/pprof/cmdline", wantStatus: http.StatusOK},
		{name: "pprof symbol is served", method: http.MethodGet, target: "/debug/pprof/symbol", wantStatus: http.StatusOK},
		{name: "pprof heap is served through the index", method: http.MethodGet, target: "/debug/pprof/heap", wantStatus: http.StatusOK},
		{name: "unknown path is not found", method: http.MethodGet, target: "/nope", wantStatus: http.StatusNotFound},
		// No catch-all is registered here, unlike the application mux, so a
		// method mismatch does surface as 405.
		{name: "wrong method on metrics is rejected", method: http.MethodPost, target: "/metrics", wantStatus: http.StatusMethodNotAllowed},
		{name: "wrong method on pprof symbol is rejected", method: http.MethodDelete, target: "/debug/pprof/symbol", wantStatus: http.StatusMethodNotAllowed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			testAdminMux(t).ServeHTTP(recorder, httptest.NewRequest(test.method, test.target, http.NoBody))

			if recorder.Code != test.wantStatus {
				t.Errorf("%s %s returned status %d, want %d", test.method, test.target, recorder.Code, test.wantStatus)
			}
		})
	}
}

// TestNewAdminMuxServesSymbolOverPost covers AC-001.10.
func TestNewAdminMuxServesSymbolOverPost(t *testing.T) {
	t.Parallel()

	// pprof resolves addresses to function names by POSTing them: `go tool
	// pprof` sends the address list in the request body, and only falls back
	// to a query string for a handful of them. Registering the route for GET
	// alone makes symbolization fail against this process, which is the whole
	// point of exposing the endpoint.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/debug/pprof/symbol", strings.NewReader("0x0"))
	testAdminMux(t).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf("POST /debug/pprof/symbol returned status %d, want %d", recorder.Code, http.StatusOK)
	}
}

// TestNewAdminMuxDoesNotServeTheApplication covers AC-002.29.
func TestNewAdminMuxDoesNotServeTheApplication(t *testing.T) {
	t.Parallel()

	// The administrative listener exists to be separable from the application.
	// If a stray catch-all were ever registered here, exposing the admin port
	// would expose the UI with it.
	recorder := httptest.NewRecorder()
	testAdminMux(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if recorder.Code != http.StatusNotFound {
		t.Errorf("GET / on the admin mux returned status %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

// TestDefaultAdminConfigUsesItsOwnPort cover AC-001.5 and AC-002.17.
func TestDefaultAdminConfigUsesItsOwnPort(t *testing.T) {
	t.Parallel()

	admin := DefaultAdminConfig()

	if admin.Addr != DefaultAdminAddr {
		t.Errorf("admin Addr is %q, want %q", admin.Addr, DefaultAdminAddr)
	}

	if admin.Addr == DefaultConfig().Addr {
		t.Error("admin listener shares the application's address, which defeats the point of separating them")
	}
}

// TestDefaultAdminConfigKeepsANonZeroWriteTimeout cites no criterion: it
// pins net/http/pprof's documented behaviour, which is what makes the
// non-zero default correct rather than incidental.
func TestDefaultAdminConfigKeepsANonZeroWriteTimeout(t *testing.T) {
	t.Parallel()

	// net/http/pprof extends the write deadline by the requested profile
	// duration, but only when the server has a WriteTimeout set at all. Setting
	// it to zero to "allow long profiles" would in fact remove the extension
	// along with the timeout, so this is load-bearing rather than incidental.
	if admin := DefaultAdminConfig(); admin.WriteTimeout <= 0 {
		t.Errorf("admin WriteTimeout is %v; pprof's deadline extension only applies when it is positive", admin.WriteTimeout)
	}
}

// TestDefaultAdminConfigBindsLoopback covers AC-002.17.
func TestDefaultAdminConfigBindsLoopback(t *testing.T) {
	t.Parallel()

	if admin := DefaultAdminConfig(); admin.Addr != "127.0.0.1:9090" {
		t.Errorf("admin Addr is %q, want %q", admin.Addr, "127.0.0.1:9090")
	}
}

// TestAdminMuxServesReadiness covers AC-002.13 and AC-002.16.
// It also covers AC-001.6.
func TestAdminMuxServesReadiness(t *testing.T) {
	t.Parallel()

	ready := NewReadiness()
	mux := NewAdminMux(DefaultAdminConfig(), zap.NewNop(), ready, testProcessInfo(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))

	if recorder.Code != http.StatusOK {
		t.Errorf("GET /readyz returned status %d, want %d", recorder.Code, http.StatusOK)
	}

	wantReady, err := json.Marshal(readinessResponse{Status: "ready"})
	if err != nil {
		t.Fatalf("marshalling expected ready body: %v", err)
	}

	if got := strings.TrimSuffix(recorder.Body.String(), "\n"); got != string(wantReady) {
		t.Errorf("GET /readyz body is %q, want %q", got, string(wantReady))
	}

	ready.SetDraining()

	drainingRecorder := httptest.NewRecorder()
	mux.ServeHTTP(drainingRecorder, httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))

	if drainingRecorder.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz after draining returned status %d, want %d", drainingRecorder.Code, http.StatusServiceUnavailable)
	}

	wantDraining, err := json.Marshal(readinessResponse{Status: "draining"})
	if err != nil {
		t.Fatalf("marshalling expected draining body: %v", err)
	}

	if got := strings.TrimSuffix(drainingRecorder.Body.String(), "\n"); got != string(wantDraining) {
		t.Errorf("GET /readyz body after draining is %q, want %q", got, string(wantDraining))
	}

	healthRecorder := httptest.NewRecorder()
	mux.ServeHTTP(healthRecorder, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))

	if healthRecorder.Code != http.StatusOK {
		t.Errorf("GET /healthz while draining returned status %d, want %d", healthRecorder.Code, http.StatusOK)
	}

	wantHealth, err := json.Marshal(healthResponse{Status: "ok"})
	if err != nil {
		t.Fatalf("marshalling expected health body: %v", err)
	}

	if got := strings.TrimSuffix(healthRecorder.Body.String(), "\n"); got != string(wantHealth) {
		t.Errorf("GET /healthz body is %q, want %q", got, string(wantHealth))
	}
}
