package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// inviteTestToken is the invite token the tests in this file put in a
// request path. Any log field, span name, span attribute, or span event
// carrying it is a leak.
const inviteTestToken = "inv1teT0kenSECRETvalue"

// startAttributeRecorder is a span processor that keeps a copy of every
// span's attributes as they stand when the span starts, which is what a
// sampler or a start-time span processor would see, before anything later
// in the request has a chance to overwrite them.
type startAttributeRecorder struct {
	mu         sync.Mutex
	attributes [][]attribute.KeyValue
}

// OnStart records span's attributes at start.
func (recorder *startAttributeRecorder) OnStart(_ context.Context, span sdktrace.ReadWriteSpan) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	recorder.attributes = append(recorder.attributes, span.Attributes())
}

// OnEnd does nothing; ended spans are recorded by a tracetest.SpanRecorder.
func (*startAttributeRecorder) OnEnd(sdktrace.ReadOnlySpan) {}

// Shutdown does nothing.
func (*startAttributeRecorder) Shutdown(context.Context) error { return nil }

// ForceFlush does nothing.
func (*startAttributeRecorder) ForceFlush(context.Context) error { return nil }

// snapshot returns the attribute sets recorded so far.
func (recorder *startAttributeRecorder) snapshot() [][]attribute.KeyValue {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	return append([][]attribute.KeyValue(nil), recorder.attributes...)
}

// inviteHarness is NewMux's full chain backed by an observed logger and two
// span recorders, one for ended spans and one for start-time attributes.
type inviteHarness struct {
	handler http.Handler
	logs    *observer.ObservedLogs
	ended   *tracetest.SpanRecorder
	started *startAttributeRecorder
}

// newInviteHarness builds NewMux with cfg, the routes api registers, and the
// supplied middleware, recording through an observed logger and an SDK
// tracer provider that samples every span.
func newInviteHarness(t *testing.T, cfg Config, api func(*http.ServeMux), middleware ...func(http.Handler) http.Handler) inviteHarness {
	t.Helper()

	core, logs := observer.New(zapcore.DebugLevel)
	ended := tracetest.NewSpanRecorder()
	started := &startAttributeRecorder{}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(started),
		sdktrace.WithSpanProcessor(ended),
	)

	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutting down tracer provider: %v", err)
		}
	})

	handler := NewMux(cfg, TrustedProxies{}, NewReadiness(), zap.New(core),
		Telemetry{TracerProvider: provider}, testUI(t), api, middleware...)

	return inviteHarness{handler: handler, logs: logs, ended: ended, started: started}
}

// inviteRoute registers "GET /i/{file}" the way internal/auth does, answering
// 200 and passing the matched file value to seen when seen is non-nil.
func inviteRoute(seen func(string)) func(*http.ServeMux) {
	return func(mux *http.ServeMux) {
		mux.Handle("GET /i/{file}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if seen != nil {
				seen(r.PathValue("file"))
			}

			w.WriteHeader(http.StatusOK)
		}))
	}
}

// assertTokenNotObserved fails the test if token appears in any log message
// or string log field, or in any span's name, attributes at start or end,
// event names, event attributes, or status description.
func (harness inviteHarness) assertTokenNotObserved(t *testing.T, token string) {
	t.Helper()

	assertNoFieldContains(t, harness.logs.All(), token)

	for _, attrs := range harness.started.snapshot() {
		for _, attr := range attrs {
			if strings.Contains(attr.Value.String(), token) {
				t.Errorf("span attribute at start %s = %q contains the token", attr.Key, attr.Value.String())
			}
		}
	}

	for _, span := range harness.ended.Ended() {
		if strings.Contains(span.Name(), token) {
			t.Errorf("span name %q contains the token", span.Name())
		}

		if strings.Contains(span.Status().Description, token) {
			t.Errorf("span status %q contains the token", span.Status().Description)
		}

		for _, attr := range span.Attributes() {
			if strings.Contains(attr.Value.String(), token) {
				t.Errorf("span attribute %s = %q contains the token", attr.Key, attr.Value.String())
			}
		}

		for _, event := range span.Events() {
			if strings.Contains(event.Name, token) {
				t.Errorf("span event name %q contains the token", event.Name)
			}

			for _, attr := range event.Attributes {
				if strings.Contains(attr.Value.String(), token) {
					t.Errorf("span event attribute %s = %q contains the token", attr.Key, attr.Value.String())
				}
			}
		}
	}
}

// TestInviteTokenNotLoggedOrTracedOnMatchedRoute covers AC-008.87: a
// request that matches GET /i/{file} leaves its token in no log field and no
// span attribute, including the attributes a sampler sees at span start.
func TestInviteTokenNotLoggedOrTracedOnMatchedRoute(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"/i/" + inviteTestToken, "/i/" + inviteTestToken + ".png"} {
		harness := newInviteHarness(t, DefaultConfig(), inviteRoute(nil))

		recorder := httptest.NewRecorder()
		harness.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, http.NoBody))

		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", target, recorder.Code)
		}

		if len(harness.ended.Ended()) != 1 {
			t.Fatalf("GET %s ended %d spans, want 1", target, len(harness.ended.Ended()))
		}

		harness.assertTokenNotObserved(t, inviteTestToken)
	}
}

// TestInviteTokenNotLoggedOrTracedOnUnmatchedMethod covers AC-008.87: a
// POST to /i/<token> misses the GET route and falls through to the
// catch-all, and its token still appears in no log field or span attribute.
func TestInviteTokenNotLoggedOrTracedOnUnmatchedMethod(t *testing.T) {
	t.Parallel()

	harness := newInviteHarness(t, DefaultConfig(), inviteRoute(nil))

	harness.handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/i/"+inviteTestToken, http.NoBody))

	if len(harness.logs.All()) == 0 {
		t.Fatal("got 0 log entries, want at least the access log entry")
	}

	harness.assertTokenNotObserved(t, inviteTestToken)
}

// TestInviteTokenNotLoggedOrTracedOnUnmatchedSubpath covers AC-008.87: a
// path under /i/<token>/ misses the route, whether it continues into a
// further segment, ends in a trailing slash, or is unclean enough that
// ServeMux answers it with a redirect, and its token still appears in no log
// field or span attribute. The redirect's Location carries the token back
// to the requester, who sent it; nothing logs or traces that header.
func TestInviteTokenNotLoggedOrTracedOnUnmatchedSubpath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		target       string
		wantStatus   int
		wantLocation string
	}{
		{name: "further segment", target: "/i/" + inviteTestToken + "/x", wantStatus: http.StatusOK},
		{name: "trailing slash", target: "/i/" + inviteTestToken + "/", wantStatus: http.StatusOK},
		// net/http's ServeMux answers a path that cleanPath would change
		// with 307 Temporary Redirect to the cleaned path, not 301.
		{
			name:         "unclean path redirected by the mux",
			target:       "/i/" + inviteTestToken + "/./x",
			wantStatus:   http.StatusTemporaryRedirect,
			wantLocation: "/i/" + inviteTestToken + "/x",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			harness := newInviteHarness(t, DefaultConfig(), inviteRoute(nil))

			recorder := httptest.NewRecorder()
			harness.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.target, http.NoBody))

			if recorder.Code != test.wantStatus {
				t.Fatalf("GET %s status = %d, want %d", test.target, recorder.Code, test.wantStatus)
			}

			if got := recorder.Header().Get("Location"); got != test.wantLocation {
				t.Errorf("GET %s Location = %q, want %q", test.target, got, test.wantLocation)
			}

			harness.assertTokenNotObserved(t, inviteTestToken)
		})
	}
}

// TestInviteTokenNotLoggedOrTracedWhenShedBeforeTheMux covers AC-008.87: a
// request to /i/<token> shed with 503 by the in-flight limit never reaches
// the mux, and its token still appears in no log field or span attribute.
func TestInviteTokenNotLoggedOrTracedWhenShedBeforeTheMux(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 1)
	release := make(chan struct{})

	api := func(mux *http.ServeMux) {
		inviteRoute(nil)(mux)
		mux.Handle("GET /block", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			started <- struct{}{}
			<-release
			w.WriteHeader(http.StatusOK)
		}))
	}

	cfg := DefaultConfig()
	cfg.MaxInFlight = 1

	harness := newInviteHarness(t, cfg, api)

	var wg sync.WaitGroup

	wg.Go(func() {
		harness.handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/block", http.NoBody))
	})

	<-started

	shed := httptest.NewRecorder()
	harness.handler.ServeHTTP(shed, httptest.NewRequest(http.MethodGet, "/i/"+inviteTestToken, http.NoBody))

	close(release)
	wg.Wait()

	if shed.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", shed.Code)
	}

	harness.assertTokenNotObserved(t, inviteTestToken)
}

// TestInviteTokenNotLoggedOrTracedOnNonCanonicalPath covers AC-008.87: a
// request whose raw path is not canonical but cleans to /i/<token> -- a
// leading double slash, a "." segment, a ".." segment, or a percent-encoded
// dot segment -- leaves its token in no log field and no span attribute,
// whatever ServeMux itself goes on to do with the request.
func TestInviteTokenNotLoggedOrTracedOnNonCanonicalPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		target       string
		wantStatus   int
		wantLocation string
	}{
		{name: "leading double slash", target: "//i/" + inviteTestToken, wantStatus: http.StatusTemporaryRedirect, wantLocation: "/i/" + inviteTestToken},
		{name: "dot segment", target: "/./i/" + inviteTestToken, wantStatus: http.StatusTemporaryRedirect, wantLocation: "/i/" + inviteTestToken},
		{name: "dot-dot segment", target: "/x/../i/" + inviteTestToken, wantStatus: http.StatusTemporaryRedirect, wantLocation: "/i/" + inviteTestToken},
		// A percent-encoded dot segment leaves RawPath and Path disagreeing
		// enough that net/http's ServeMux neither matches the invite route
		// nor redirects: it falls through to the catch-all. That is
		// unchanged by this test; what must hold regardless is that the
		// token never reaches a log or a span.
		{name: "percent-encoded dot segment", target: "/%2e/i/" + inviteTestToken, wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			harness := newInviteHarness(t, DefaultConfig(), inviteRoute(nil))

			recorder := httptest.NewRecorder()
			harness.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.target, http.NoBody))

			if recorder.Code != test.wantStatus {
				t.Fatalf("GET %s status = %d, want %d", test.target, recorder.Code, test.wantStatus)
			}

			if got := recorder.Header().Get("Location"); got != test.wantLocation {
				t.Errorf("GET %s Location = %q, want %q", test.target, got, test.wantLocation)
			}

			harness.assertTokenNotObserved(t, inviteTestToken)
		})
	}
}

// TestInviteLandingStillRoutesTheRealToken covers AC-008.87: redacting the
// path for everything that observes it does not change what the route
// handler receives, which is the real token through r.PathValue("file").
func TestInviteLandingStillRoutesTheRealToken(t *testing.T) {
	t.Parallel()

	var seen string

	harness := newInviteHarness(t, DefaultConfig(), inviteRoute(func(file string) { seen = file }))

	recorder := httptest.NewRecorder()
	harness.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/i/"+inviteTestToken, http.NoBody))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	if seen != inviteTestToken {
		t.Errorf("r.PathValue(\"file\") = %q, want %q", seen, inviteTestToken)
	}
}
