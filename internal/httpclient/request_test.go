package httpclient

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// blockingServer returns a server whose handler waits until the test ends,
// which is how a peer that has stopped answering is modelled without sleeping
// for a fixed time in the test.
func blockingServer(t *testing.T) *httptest.Server {
	t.Helper()

	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))

	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	return server
}

// doAsync performs request and returns its error, failing the test by name
// rather than hanging until the package timeout if the client never returns.
// The deadline is an escape hatch and not part of any assertion: a passing run
// never reaches it.
func doAsync(t *testing.T, client *http.Client, request *http.Request) error {
	t.Helper()

	done := make(chan error, 1)

	go func() {
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
		}

		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the client did not return within 5s: it is bounded by nothing the test configured")

		return nil
	}
}

// TestClientTimeoutEndsARequestAPeerWillNotAnswer covers AC-006.3.
func TestClientTimeoutEndsARequestAPeerWillNotAnswer(t *testing.T) {
	t.Parallel()

	server := blockingServer(t)

	cfg := Default()
	cfg.Timeout = configtype.Duration(50 * time.Millisecond)
	// Left long on purpose, so the only bound that can fire is the total one
	// this criterion is about.
	cfg.ResponseHeaderTimeout = configtype.Duration(time.Hour)

	client, err := New(cfg, Telemetry{})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	err = doAsync(t, client, request)
	if err == nil {
		t.Fatal("Do error = nil, want a timeout: a peer that never answers must not hold the caller")
	}

	if !os.IsTimeout(err) {
		t.Errorf("Do error = %v, want one os.IsTimeout reports: a caller cannot distinguish a slow peer from a broken one otherwise", err)
	}
}

// TestClientAbandonsARequestWhenItsContextIsCancelled covers AC-006.4.
func TestClientAbandonsARequestWhenItsContextIsCancelled(t *testing.T) {
	t.Parallel()

	server := blockingServer(t)

	cfg := Default()
	cfg.Timeout = configtype.Duration(time.Hour)

	client, err := New(cfg, Telemetry{})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(t.Context())

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, http.NoBody)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	cancel()

	if doErr := doAsync(t, client, request); !errors.Is(doErr, context.Canceled) {
		t.Errorf("Do error = %v, want context.Canceled: the request is waiting out its hour-long timeout instead of honouring the context", doErr)
	}
}

// TestCloseIdleConnectionsReleasesThePool covers AC-006.8.
func TestCloseIdleConnectionsReleasesThePool(t *testing.T) {
	t.Parallel()

	// Counted from the server's own goroutines, so it is atomic rather than a
	// plain int: the race detector is part of this suite.
	var connections atomic.Int64

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}

	server.Start()
	t.Cleanup(server.Close)

	client, err := New(Default(), Telemetry{})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	get := func() {
		request, reqErr := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
		if reqErr != nil {
			t.Fatalf("building the request: %v", reqErr)
		}

		response, doErr := client.Do(request)
		if doErr != nil {
			t.Fatalf("Do error = %v, want nil", doErr)
		}

		if _, copyErr := io.Copy(io.Discard, response.Body); copyErr != nil {
			t.Errorf("draining the body: %v", copyErr)
		}

		response.Body.Close()
	}

	get()
	get()

	if got := connections.Load(); got != 1 {
		t.Fatalf("the server saw %d connections for two requests, want 1: the pool is not reusing the idle connection", got)
	}

	client.CloseIdleConnections()

	get()

	if got := connections.Load(); got != 2 {
		t.Errorf("the server saw %d connections after CloseIdleConnections, want 2: the idle connection was not closed", got)
	}
}
