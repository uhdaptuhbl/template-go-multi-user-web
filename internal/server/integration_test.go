//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/buildinfo"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/web"
)

// TestDrainSequence covers AC-002.14, AC-002.15, and AC-002.16.
// It also covers AC-001.11.
func TestDrainSequence(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)

	addr := freeLoopbackAddr(t)
	cfg := DefaultConfig()
	cfg.Addr = addr

	ready := NewReadiness()

	ui, err := web.Handler()
	if err != nil {
		t.Fatalf("building ui handler: %v", err)
	}

	mux := NewMux(cfg, TrustedProxies{}, ready, zap.NewNop(), Telemetry{}, ui, nil)
	srv := New(cfg, zap.NewNop(), mux)

	lifecycle := LifecycleConfig{PreDrainDelay: configtype.Duration(300 * time.Millisecond)}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- RunAll(ctx, lifecycle, ready, zap.NewNop(), srv)
	}()

	readyURL := "http://" + addr + readyPath
	healthURL := "http://" + addr + healthPath

	pollForStatusAndBody(t, client, readyURL, http.StatusOK, `{"status":"ready"}`, 5*time.Second)

	cancel()

	// The window is comfortably under the 300ms pre-drain delay, so a 503
	// observed here proves readiness fails while the listener is still
	// accepting connections.
	pollForStatusAndBody(t, client, readyURL, http.StatusServiceUnavailable, `{"status":"draining"}`, 200*time.Millisecond)

	health := getOnce(t, client, healthURL)
	if health.status != http.StatusOK {
		t.Errorf("GET %s during drain window returned status %d, want %d", healthURL, health.status, http.StatusOK)
	}

	if got := string(health.body); got != `{"status":"ok"}` {
		t.Errorf("GET %s during drain window returned body %q, want %q", healthURL, got, `{"status":"ok"}`)
	}

	select {
	case runErr := <-runDone:
		if runErr != nil {
			t.Fatalf("RunAll returned error: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunAll did not return within 5s of the pre-drain delay elapsing")
	}

	pollForDialFailure(t, addr, 2*time.Second)
}

// TestInFlightRequestCompletesDuringDrain covers AC-002.15.
// It also covers AC-001.11.
func TestInFlightRequestCompletesDuringDrain(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)

	addr := freeLoopbackAddr(t)
	cfg := DefaultConfig()
	cfg.Addr = addr

	started := make(chan struct{})
	release := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	})

	srv := New(cfg, zap.NewNop(), handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Run(ctx)
	}()

	waitForListening(t, addr, 5*time.Second)

	type outcome struct {
		status int
		err    error
	}

	reqDone := make(chan outcome, 1)

	go func() {
		req, buildErr := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/", http.NoBody)
		if buildErr != nil {
			reqDone <- outcome{err: buildErr}

			return
		}

		resp, doErr := client.Do(req)
		if doErr != nil {
			reqDone <- outcome{err: doErr}

			return
		}

		_, readErr := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()

		if readErr != nil {
			reqDone <- outcome{err: readErr}

			return
		}

		if closeErr != nil {
			reqDone <- outcome{err: closeErr}

			return
		}

		reqDone <- outcome{status: resp.StatusCode}
	}()

	<-started

	cancel()
	close(release)

	select {
	case result := <-reqDone:
		if result.err != nil {
			t.Fatalf("in-flight request failed: %v", result.err)
		}

		if result.status != http.StatusOK {
			t.Errorf("in-flight request returned status %d, want %d", result.status, http.StatusOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not complete within 5s of the context being cancelled")
	}

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of the in-flight request completing")
	}
}

// TestRequestBodyLimitOverTheWire covers AC-002.4.
func TestRequestBodyLimitOverTheWire(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)

	addr := freeLoopbackAddr(t)
	cfg := DefaultConfig()
	cfg.Addr = addr

	ready := NewReadiness()
	ui := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux := NewMux(cfg, TrustedProxies{}, ready, zap.NewNop(), Telemetry{}, ui, nil)
	srv := New(cfg, zap.NewNop(), mux)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- srv.Run(ctx)
	}()

	waitForListening(t, addr, 5*time.Second)

	oversized := bytes.Repeat([]byte("a"), int(cfg.MaxRequestBodyBytes)+1)

	resp := requestOverTheWire(t, client, http.MethodPost, "http://"+addr+"/", bytes.NewReader(oversized), nil)

	if resp.status != http.StatusRequestEntityTooLarge {
		t.Errorf("got status %d, want %d", resp.status, http.StatusRequestEntityTooLarge)
	}

	want := `{"errors":[{"status":"413","code":"payload_too_large","title":"Request body too large"}]}`
	if got := strings.TrimSpace(string(resp.body)); got != want {
		t.Errorf("got body %q, want %q", got, want)
	}

	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of context cancellation")
	}
}

// TestFrontendRevalidationOverTheWire covers AC-002.18.
func TestFrontendRevalidationOverTheWire(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)

	addr := freeLoopbackAddr(t)
	cfg := DefaultConfig()
	cfg.Addr = addr

	ready := NewReadiness()

	ui, err := web.Handler()
	if err != nil {
		t.Fatalf("building ui handler: %v", err)
	}

	mux := NewMux(cfg, TrustedProxies{}, ready, zap.NewNop(), Telemetry{}, ui, nil)
	srv := New(cfg, zap.NewNop(), mux)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- srv.Run(ctx)
	}()

	waitForListening(t, addr, 5*time.Second)

	url := "http://" + addr + "/"

	first := requestOverTheWire(t, client, http.MethodGet, url, http.NoBody, nil)
	if first.status != http.StatusOK {
		t.Fatalf("got status %d, want %d", first.status, http.StatusOK)
	}

	etag := first.header.Get("ETag")
	if etag == "" {
		t.Fatal("ETag header is empty, want a validator")
	}

	second := requestOverTheWire(t, client, http.MethodGet, url, http.NoBody, map[string]string{"If-None-Match": etag})

	if second.status != http.StatusNotModified {
		t.Errorf("got status %d, want %d", second.status, http.StatusNotModified)
	}

	if len(second.body) != 0 {
		t.Errorf("got body %q, want empty", string(second.body))
	}

	cancel()

	select {
	case runErr := <-runDone:
		if runErr != nil {
			t.Fatalf("Run returned error: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of context cancellation")
	}
}

// TestRequestIDEchoedOverTheWire covers AC-002.9.
func TestRequestIDEchoedOverTheWire(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)

	addr := freeLoopbackAddr(t)
	cfg := DefaultConfig()
	cfg.Addr = addr

	ready := NewReadiness()
	ui := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux := NewMux(cfg, TrustedProxies{}, ready, zap.NewNop(), Telemetry{}, ui, nil)
	srv := New(cfg, zap.NewNop(), mux)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- srv.Run(ctx)
	}()

	waitForListening(t, addr, 5*time.Second)

	resp := requestOverTheWire(t, client, http.MethodGet, "http://"+addr+"/", http.NoBody, nil)

	id := resp.header.Get(RequestIDHeader)
	if len(id) != 32 {
		t.Fatalf("got %s header %q with length %d, want 32", RequestIDHeader, id, len(id))
	}

	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("got %s header %q, want only lowercase hexadecimal characters", RequestIDHeader, id)
		}
	}

	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of context cancellation")
	}
}

// TestVersionOverTheWire covers AC-002.26 and AC-002.27.
//
// Both listeners are started so the pair of criteria is checked against one
// running process: the administrative port reports the build, and the
// application port does not.
func TestVersionOverTheWire(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)

	adminAddr := freeLoopbackAddr(t)
	appAddr := freeLoopbackAddr(t)

	adminCfg := DefaultAdminConfig()
	adminCfg.Addr = adminAddr

	appCfg := DefaultConfig()
	appCfg.Addr = appAddr

	ready := NewReadiness()

	process := ProcessInfo{
		Build:   buildinfo.Info{Version: "9.9.9", Commit: "deadbee", Date: "2026-09-18T00:00:00Z"},
		Started: time.Date(2026, time.September, 19, 12, 30, 0, 0, time.UTC),
	}

	metrics := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ui := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	admin := New(adminCfg, zap.NewNop(), NewAdminMux(adminCfg, zap.NewNop(), ready, process, metrics))
	app := New(appCfg, zap.NewNop(), NewMux(appCfg, TrustedProxies{}, ready, zap.NewNop(), Telemetry{}, ui, nil))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- RunAll(ctx, LifecycleConfig{PreDrainDelay: 0}, ready, zap.NewNop(), admin, app)
	}()

	waitForListening(t, adminAddr, 5*time.Second)
	waitForListening(t, appAddr, 5*time.Second)

	resp := requestOverTheWire(t, client, http.MethodGet, "http://"+adminAddr+versionPath, http.NoBody, nil)

	if resp.status != http.StatusOK {
		t.Errorf("GET %s on the administrative listener returned status %d, want %d",
			versionPath, resp.status, http.StatusOK)
	}

	var body versionResponse
	if err := json.Unmarshal(resp.body, &body); err != nil {
		t.Fatalf("decoding version response: %v", err)
	}

	if body.Version != "9.9.9" {
		t.Errorf("got version %q, want %q", body.Version, "9.9.9")
	}

	if body.BuildDate != "2026-09-18T00:00:00Z" {
		t.Errorf("got build_date %q, want %q", body.BuildDate, "2026-09-18T00:00:00Z")
	}

	if body.StartedAt != "2026-09-19T12:30:00Z" {
		t.Errorf("got started_at %q, want %q", body.StartedAt, "2026-09-19T12:30:00Z")
	}

	// The same path on the public port must not answer with a build report.
	public := requestOverTheWire(t, client, http.MethodGet, "http://"+appAddr+versionPath, http.NoBody, nil)

	if strings.Contains(string(public.body), "go_version") {
		t.Errorf("the application listener disclosed a version report: %q", string(public.body))
	}

	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("RunAll returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunAll did not return within 5s of context cancellation")
	}
}

// wireResponse is one HTTP response as observed over a real socket by the
// helpers below.
type wireResponse struct {
	status int
	header http.Header
	body   []byte
}

// freeLoopbackAddr returns a loopback address on a port the kernel currently
// has free, by binding to port 0, reading back what was assigned, and
// releasing it. The tests in this file need an address to configure a Config
// with before the server owning the real listener exists.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()

	var config net.ListenConfig

	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on an ephemeral port: %v", err)
	}

	addr := listener.Addr().String()

	if closeErr := listener.Close(); closeErr != nil {
		t.Fatalf("closing ephemeral listener: %v", closeErr)
	}

	return addr
}

// waitForListening polls addr by dialing it until a connection succeeds or
// timeout elapses, so a test does not send its first request before the
// server under test has bound its listener.
func waitForListening(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()

	var last error

	pollUntil(t, timeout, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		last = err

		if err != nil {
			return false
		}

		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("closing probe connection to %s: %v", addr, closeErr)
		}

		return true
	}, func() string {
		return fmt.Sprintf("server at %s was not accepting connections (last dial: %v)", addr, last)
	})
}

// requestOverTheWire issues method to url carrying body and headers, and
// requires the round trip to succeed: building the request, completing it,
// reading the response body, and closing it. It is used once a caller has
// already confirmed the server is accepting connections.
func requestOverTheWire(t *testing.T, client *http.Client, method, url string, body io.Reader, headers map[string]string) wireResponse {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, url, body)
	if err != nil {
		t.Fatalf("building %s %s request: %v", method, url, err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("requesting %s %s: %v", method, url, err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body from %s %s: %v", method, url, err)
	}

	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("closing response body from %s %s: %v", method, url, closeErr)
	}

	return wireResponse{status: resp.StatusCode, header: resp.Header, body: data}
}

// tryGetOverTheWire issues a GET to url and reports its response, or false
// when the request could not be completed at all, which is expected while a
// listener is still starting up or has just stopped accepting.
func tryGetOverTheWire(t *testing.T, client *http.Client, url string) (wireResponse, bool) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("building GET %s request: %v", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return wireResponse{}, false
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body from GET %s: %v", url, err)
	}

	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("closing response body from GET %s: %v", url, closeErr)
	}

	return wireResponse{status: resp.StatusCode, header: resp.Header, body: data}, true
}

// getOnce issues one GET to url and requires it to succeed, for a point in a
// test where the listener is already known to be accepting connections. The
// returned body has any trailing newline from json.Encoder trimmed.
func getOnce(t *testing.T, client *http.Client, url string) wireResponse {
	t.Helper()

	resp, ok := tryGetOverTheWire(t, client, url)
	if !ok {
		t.Fatalf("GET %s failed", url)
	}

	resp.body = []byte(strings.TrimSuffix(string(resp.body), "\n"))

	return resp
}

// pollForStatusAndBody polls url with GET until a response with status
// wantStatus and body wantBody arrives, or timeout elapses.
func pollForStatusAndBody(t *testing.T, client *http.Client, url string, wantStatus int, wantBody string, timeout time.Duration) {
	t.Helper()

	var last wireResponse

	pollUntil(t, timeout, func() bool {
		resp, ok := tryGetOverTheWire(t, client, url)
		if !ok {
			return false
		}

		resp.body = []byte(strings.TrimSuffix(string(resp.body), "\n"))
		last = resp

		return resp.status == wantStatus && string(resp.body) == wantBody
	}, func() string {
		return fmt.Sprintf("GET %s did not return status %d body %q (last observed status %d body %q)",
			url, wantStatus, wantBody, last.status, string(last.body))
	})
}

// pollForDialFailure polls addr by dialing it until a connection attempt
// fails, or timeout elapses, proving the listener has stopped accepting.
func pollForDialFailure(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()

	pollUntil(t, timeout, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return true
		}

		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("closing unexpectedly accepted connection to %s: %v", addr, closeErr)
		}

		return false
	}, func() string {
		return fmt.Sprintf("listener at %s was still accepting connections", addr)
	})
}

// TestRequestBodyLimitClosesTheConnection covers AC-002.4.
func TestRequestBodyLimitClosesTheConnection(t *testing.T) {
	t.Parallel()

	// Over a real server rather than httptest.NewRecorder, because the
	// signal under test is delivered by type-asserting the ResponseWriter to
	// an unexported net/http interface that only *http.response implements.
	// A recorder cannot observe it at all.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)

			return
		}

		w.WriteHeader(http.StatusOK)
	})

	// The recorder sits between the body limit and the real writer in
	// production, installed by withRequestLogging. Reproduced here because
	// its presence is precisely what breaks the signal.
	limited := withRequestBodyLimit(10, zap.NewNop(), inner)
	stack := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limited.ServeHTTP(&statusRecorder{ResponseWriter: w}, r)
	})

	server := httptest.NewServer(stack)
	defer server.Close()

	// ContentLength unknown, so the declared-length check cannot fire and
	// MaxBytesReader is what has to catch this.
	body := io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("a"), 100)))

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, body)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v, want nil", err)
	}

	request.ContentLength = -1

	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}

	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Errorf("closing response body: %v", closeErr)
		}
	}()

	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("got status %d, want %d", response.StatusCode, http.StatusRequestEntityTooLarge)
	}

	// net/http sets this from requestTooLarge. Without it the connection is
	// kept alive and the server drains the rest of an oversized body it has
	// already refused.
	if !response.Close {
		t.Errorf("response did not ask to close the connection; Connection header = %q", response.Header.Get("Connection"))
	}
}
