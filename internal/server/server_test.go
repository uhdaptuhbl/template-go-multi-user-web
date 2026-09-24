package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// TestServeShutsDownWhenContextIsCancelled covers AC-001.11.
func TestServeShutsDownWhenContextIsCancelled(t *testing.T) {
	t.Parallel()

	var config net.ListenConfig

	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	srv := New(DefaultConfig(), zap.NewNop(), testMux(t))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, listener)
	}()

	// The listener is already bound, so a request issued now is accepted even
	// if Serve has not yet reached its accept loop.
	endpoint := "http://" + listener.Addr().String() + "/healthz"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	resp, err := newTestClient(t).Do(req)
	if err != nil {
		t.Fatalf("requesting %s: %v", endpoint, err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Errorf("closing response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d from %s, want %d", resp.StatusCode, endpoint, http.StatusOK)
	}

	cancel()

	select {
	case serveResult := <-serveErr:
		if serveResult != nil {
			t.Fatalf("Serve returned error after cancellation: %v", serveResult)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10s of context cancellation")
	}
}

// TestRunReportsUnusableAddress covers AC-001.13.
func TestRunReportsUnusableAddress(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Addr = "127.0.0.1:99999"

	srv := New(cfg, zap.NewNop(), testMux(t))

	if err := srv.Run(t.Context()); err == nil {
		t.Fatal("Run returned nil error for an out-of-range port")
	}
}

// TestRunAllStopsEveryServerWhenTheContextIsCancelled covers AC-001.11.
func TestRunAllStopsEveryServerWhenTheContextIsCancelled(t *testing.T) {
	t.Parallel()

	first := New(listenOnAnyPort(t), zap.NewNop(), testMux(t))
	second := New(listenOnAnyPort(t), zap.NewNop(), testAdminMux(t))

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- RunAll(ctx, LifecycleConfig{PreDrainDelay: 0}, NewReadiness(), zap.NewNop(), first, second)
	}()

	// Safe to cancel without first waiting for the listeners to bind:
	// net.ListenConfig.Listen consults the context only while resolving a name,
	// and these addresses are literal IPs, so an already-cancelled context does
	// not turn into a listen error.
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunAll returned error after cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunAll did not return within 10s of context cancellation")
	}
}

// TestRunAllReturnsWhenOneServerFails covers AC-001.13.
func TestRunAllReturnsWhenOneServerFails(t *testing.T) {
	t.Parallel()

	// The healthy server is never cancelled by the caller. RunAll returning at
	// all proves it shut the healthy one down in response to the failure; before
	// that behaviour existed this test would block until the timeout.
	broken := DefaultConfig()
	broken.Addr = "127.0.0.1:99999"

	failing := New(broken, zap.NewNop(), testMux(t))
	healthy := New(listenOnAnyPort(t), zap.NewNop(), testAdminMux(t))

	done := make(chan error, 1)
	go func() {
		done <- RunAll(t.Context(), LifecycleConfig{PreDrainDelay: 0}, NewReadiness(), zap.NewNop(), failing, healthy)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunAll returned nil error when one server failed to listen")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunAll did not return within 10s of a server failing, so the healthy server was never shut down")
	}
}

// listenOnAnyPort returns a config bound to a port the kernel picks, so
// concurrent tests cannot collide on a fixed one.
func listenOnAnyPort(t *testing.T) Config {
	t.Helper()

	cfg := DefaultConfig()
	cfg.Addr = "127.0.0.1:0"

	return cfg
}

// TestServeReportsAListenerFailure covers AC-001.13.
func TestServeReportsAListenerFailure(t *testing.T) {
	t.Parallel()

	var config net.ListenConfig

	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	// Closing the listener before Serve accepts on it makes the accept loop fail
	// with something other than http.ErrServerClosed, which Serve must surface
	// rather than treat as an ordinary shutdown.
	if closeErr := listener.Close(); closeErr != nil {
		t.Fatalf("closing listener: %v", closeErr)
	}

	srv := New(DefaultConfig(), zap.NewNop(), testMux(t))

	if serveErr := srv.Serve(t.Context(), listener); serveErr == nil {
		t.Fatal("Serve returned nil error for a closed listener")
	}
}

// TestNewAppliesEveryConfiguredTimeout covers AC-002.28.
func TestNewAppliesEveryConfiguredTimeout(t *testing.T) {
	t.Parallel()

	// Distinct values so a field wired to the wrong source is visible rather
	// than masked by DefaultConfig's repeated 30s.
	cfg := Config{
		Addr:              "127.0.0.1:1",
		ReadHeaderTimeout: configtype.Duration(1 * time.Second),
		ReadTimeout:       configtype.Duration(2 * time.Second),
		WriteTimeout:      configtype.Duration(3 * time.Second),
		IdleTimeout:       configtype.Duration(4 * time.Second),
		ShutdownTimeout:   configtype.Duration(5 * time.Second),
	}

	srv := New(cfg, zap.NewNop(), testMux(t))

	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{name: "ReadHeaderTimeout", got: srv.httpServer.ReadHeaderTimeout, want: cfg.ReadHeaderTimeout.Duration()},
		{name: "ReadTimeout", got: srv.httpServer.ReadTimeout, want: cfg.ReadTimeout.Duration()},
		{name: "WriteTimeout", got: srv.httpServer.WriteTimeout, want: cfg.WriteTimeout.Duration()},
		{name: "IdleTimeout", got: srv.httpServer.IdleTimeout, want: cfg.IdleTimeout.Duration()},
		{name: "ShutdownTimeout", got: srv.shutdownTimeout, want: cfg.ShutdownTimeout.Duration()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.got != test.want {
				t.Errorf("%s is %v, want %v", test.name, test.got, test.want)
			}
		})
	}

	if srv.httpServer.Addr != cfg.Addr {
		t.Errorf("Addr is %q, want %q", srv.httpServer.Addr, cfg.Addr)
	}
}

// TestDefaultConfigSetsEveryTimeout covers AC-002.28.
func TestDefaultConfigSetsEveryTimeout(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	tests := []struct {
		name  string
		value configtype.Duration
	}{
		{name: "ReadHeaderTimeout", value: cfg.ReadHeaderTimeout},
		{name: "ReadTimeout", value: cfg.ReadTimeout},
		{name: "WriteTimeout", value: cfg.WriteTimeout},
		{name: "IdleTimeout", value: cfg.IdleTimeout},
		{name: "ShutdownTimeout", value: cfg.ShutdownTimeout},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.value <= 0 {
				t.Errorf("%s is %v, want a positive duration: an unset timeout lets a stalled client hold a connection open", test.name, test.value)
			}
		})
	}
}

// TestDefaultLifecycleConfigHoldsBeforeDraining covers AC-002.15.
func TestDefaultLifecycleConfigHoldsBeforeDraining(t *testing.T) {
	t.Parallel()

	cfg := DefaultLifecycleConfig()

	if cfg.PreDrainDelay != DefaultPreDrainDelay {
		t.Fatalf("PreDrainDelay is %v, want %v", cfg.PreDrainDelay, DefaultPreDrainDelay)
	}

	if cfg.PreDrainDelay <= 0 {
		t.Fatal("PreDrainDelay is not positive: an orchestrator gets no window to observe readiness failing before the listeners close")
	}
}

// TestServerSetsMaxHeaderBytes covers AC-002.5.
func TestServerSetsMaxHeaderBytes(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.MaxHeaderBytes = 4096

	srv := New(cfg, zap.NewNop(), testMux(t))

	if int64(srv.httpServer.MaxHeaderBytes) != cfg.MaxHeaderBytes.Bytes() {
		t.Fatalf("MaxHeaderBytes is %d, want %d", srv.httpServer.MaxHeaderBytes, cfg.MaxHeaderBytes.Bytes())
	}

	var config net.ListenConfig

	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, listener)
	}()

	var dialer net.Dialer

	conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dialing %s: %v", listener.Addr(), err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("closing connection: %v", closeErr)
		}
	}()

	// 16 KiB of header comfortably exceeds the 4096-byte ceiling configured
	// above.
	request := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: " + strings.Repeat("a", 16*1024) + "\r\n\r\n"

	if _, writeErr := conn.Write([]byte(request)); writeErr != nil {
		t.Fatalf("writing request: %v", writeErr)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Errorf("closing response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}

	cancel()

	select {
	case serveResult := <-serveErr:
		if serveResult != nil {
			t.Fatalf("Serve returned error after cancellation: %v", serveResult)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10s of context cancellation")
	}
}

// TestServerErrorLogGoesToZap covers AC-002.3.
//
// The trigger is a handler that calls WriteHeader twice rather than a
// malformed request line: in the Go version this project builds with,
// net/http's own connection-level malformed-request path returns 400 without
// calling ErrorLog at all, so it exercises nothing. A superfluous WriteHeader
// call is one of the few connection-level conditions net/http still reports
// through ErrorLog by contract, and it is deterministic where a raw
// malformed-request race is not.
func TestServerErrorLogGoesToZap(t *testing.T) {
	t.Parallel()

	core, observed := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.WriteHeader(http.StatusOK)
	})

	var config net.ListenConfig

	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	srv := New(DefaultConfig(), logger, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx, listener)
	}()

	endpoint := "http://" + listener.Addr().String() + "/"

	resp, err := getWithContext(t, newTestClient(t), endpoint)
	if err != nil {
		t.Fatalf("requesting %s: %v", endpoint, err)
	}

	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("closing response body: %v", closeErr)
	}

	pollUntil(t, 5*time.Second, func() bool {
		return observed.FilterLoggerName("http").Len() > 0
	}, func() string {
		return "no log entry from the http-named logger after a superfluous WriteHeader call"
	})

	cancel()

	select {
	case serveResult := <-serveErr:
		if serveResult != nil {
			t.Fatalf("Serve returned error after cancellation: %v", serveResult)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10s of context cancellation")
	}
}

// TestRunAllFailsReadinessBeforeClosingListeners covers AC-002.14 and AC-002.15.
func TestRunAllFailsReadinessBeforeClosingListeners(t *testing.T) {
	t.Parallel()

	// A free port is found and released rather than kept bound, since Server
	// picks its own listener internally and does not expose it: this is the
	// only way the test can know an address to poll.
	var config net.ListenConfig

	probe, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	addr := probe.Addr().String()

	if closeErr := probe.Close(); closeErr != nil {
		t.Fatalf("closing probe listener: %v", closeErr)
	}

	cfg := DefaultConfig()
	cfg.Addr = addr

	ready := NewReadiness()

	// A bare mux with only the readiness route, rather than NewMux: this test
	// is about shutdown sequencing, and the middleware chain would only add
	// noise to what it observes.
	mux := http.NewServeMux()
	mux.Handle("GET "+readyPath, newReadinessHandler(ready, zap.NewNop()))

	srv := New(cfg, zap.NewNop(), mux)

	lifecycle := LifecycleConfig{PreDrainDelay: configtype.Duration(200 * time.Millisecond)}

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- RunAll(ctx, lifecycle, ready, zap.NewNop(), srv)
	}()

	endpoint := "http://" + addr + readyPath

	// Polled rather than slept for: Run's internal listener bind happens
	// asynchronously, and the wait time it takes is not a value this test
	// should assume.
	client := newTestClient(t)

	readyResp := waitForStatus(t, client, endpoint, http.StatusOK, 5*time.Second)
	if closeErr := readyResp.Body.Close(); closeErr != nil {
		t.Errorf("closing response body: %v", closeErr)
	}

	cancel()

	// The window is well under the 200ms pre-drain delay, so a 503 observed
	// here proves readiness failed before the listener had any chance to close.
	drainingResp := waitForStatus(t, client, endpoint, http.StatusServiceUnavailable, 150*time.Millisecond)
	if closeErr := drainingResp.Body.Close(); closeErr != nil {
		t.Errorf("closing response body: %v", closeErr)
	}

	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("RunAll returned error after cancellation: %v", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunAll did not return within 10s of context cancellation")
	}
}

// waitForStatus polls url with GET until a response with status want arrives
// or timeout elapses, and returns that response. Polling stands in for a fixed
// sleep because the wait is for an occurrence, not for a known duration.
func waitForStatus(t *testing.T, client *http.Client, url string, want int, timeout time.Duration) *http.Response {
	t.Helper()

	var found *http.Response

	pollUntil(t, timeout, func() bool {
		resp, err := getWithContext(t, client, url)
		if err != nil {
			return false
		}

		if resp.StatusCode == want {
			found = resp

			return true
		}

		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Errorf("closing response body: %v", closeErr)
		}

		return false
	}, func() string {
		return fmt.Sprintf("did not observe status %d from %s", want, url)
	})

	return found
}

// pollInterval is how long pollUntil waits between attempts. Short enough that
// a test spends no measurable time asleep once its condition holds, long
// enough not to spin a core while it does not.
const pollInterval = 5 * time.Millisecond

// pollUntil calls check until it reports true, and fails the test with the
// message describe returns if timeout elapses first.
//
// This is the sanctioned form of the wait that CLAUDE.md's determinism rule
// otherwise bans. The banned thing is a fixed sleep standing in for
// synchronization, which asserts a duration nobody measured and is flaky on a
// loaded machine and slow on an idle one at the same time. Here the test waits
// on an observable condition and nothing else: the interval only paces the
// polling, and the deadline exists so a condition that never holds fails as a
// named test failure rather than hanging until the package timeout. Neither
// duration can change the outcome of a passing run.
//
// describe is a function rather than a string so a caller can report what it
// last observed, which is usually the only clue a timeout leaves behind.
func pollUntil(t *testing.T, timeout time.Duration, check func() bool, describe func() string) {
	t.Helper()

	deadline := time.Now().Add(timeout)

	for {
		if check() {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("%s within %s", describe(), timeout)
		}

		time.Sleep(pollInterval)
	}
}

// newTestClient returns a client private to the test, limited to one connection
// per host and closed when the test ends.
//
// http.DefaultClient would work, but its transport may dial a spare connection
// when a request races the previous response's Body.Close returning the
// keep-alive connection to the pool. The spare never carries a request, so the
// server holds it in StateNew, and Shutdown treats a StateNew connection as
// idle only after five seconds: every such race costs a test five seconds.
// One connection per host means there is never a spare to dial.
//
// The trade is that a test which leaves a response body unclosed blocks on its
// next request rather than quietly opening a second connection, which is the
// louder of the two failures.
func newTestClient(t *testing.T) *http.Client {
	t.Helper()

	transport := &http.Transport{MaxConnsPerHost: 1}
	t.Cleanup(transport.CloseIdleConnections)

	return &http.Client{Transport: transport}
}

// getWithContext issues a GET to url through client, using an explicit request
// so that a caller-supplied address never reaches http.Get. The response body
// is the caller's to close.
func getWithContext(t *testing.T, client *http.Client, url string) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("building GET %s request: %v", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", url, err)
	}

	return resp, nil
}
