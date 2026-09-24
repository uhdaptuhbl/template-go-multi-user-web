package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestRequestBodyLimitRejectsDeclaredOversizedBody covers AC-002.4.
func TestRequestBodyLimitRejectsDeclaredOversizedBody(t *testing.T) {
	t.Parallel()

	var called bool

	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	})

	handler := withRequestBodyLimit(10, zap.NewNop(), inner)

	body := bytes.Repeat([]byte("a"), 100)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}

	wantBody := `{"errors":[{"status":"413","code":"payload_too_large","title":"Request body too large"}]}`
	if got := strings.TrimSpace(recorder.Body.String()); got != wantBody {
		t.Errorf("got body %q, want %q", got, wantBody)
	}

	if called {
		t.Error("inner handler was called, want it skipped for an oversized body")
	}
}

// TestRequestBodyLimitRejectsUndeclaredOversizedBody covers AC-002.4.
func TestRequestBodyLimitRejectsUndeclaredOversizedBody(t *testing.T) {
	t.Parallel()

	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if _, ok := errors.AsType[*http.MaxBytesError](err); !ok {
			t.Errorf("got error %v, want a *http.MaxBytesError", err)
		}
	})

	handler := withRequestBodyLimit(10, zap.NewNop(), inner)

	body := bytes.Repeat([]byte("a"), 100)
	req := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(bytes.NewReader(body)))
	req.ContentLength = -1

	handler.ServeHTTP(httptest.NewRecorder(), req)
}

// TestRequestBodyLimitDisabled covers AC-002.4.
func TestRequestBodyLimitDisabled(t *testing.T) {
	t.Parallel()

	body := bytes.Repeat([]byte("a"), 100)

	var gotLen int

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		read, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}

		gotLen = len(read)

		w.WriteHeader(http.StatusOK)
	})

	handler := withRequestBodyLimit(0, zap.NewNop(), inner)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusOK)
	}

	if gotLen != len(body) {
		t.Errorf("got body length %d, want %d", gotLen, len(body))
	}
}

// TestInFlightLimitShedsExcess covers AC-002.21.
func TestInFlightLimitShedsExcess(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 1)
	release := make(chan struct{})

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	handler := withInFlightLimit(1, zap.NewNop(), inner)

	firstRecorder := httptest.NewRecorder()

	var wg sync.WaitGroup

	wg.Go(func() {
		handler.ServeHTTP(firstRecorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	})

	<-started

	secondRecorder := httptest.NewRecorder()
	handler.ServeHTTP(secondRecorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if secondRecorder.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want %d", secondRecorder.Code, http.StatusServiceUnavailable)
	}

	if got := secondRecorder.Header().Get("Retry-After"); got != "1" {
		t.Errorf("got Retry-After %q, want %q", got, "1")
	}

	wantBody := `{"errors":[{"status":"503","code":"overloaded","title":"Server overloaded"}]}`
	if got := strings.TrimSpace(secondRecorder.Body.String()); got != wantBody {
		t.Errorf("got body %q, want %q", got, wantBody)
	}

	close(release)
	wg.Wait()

	if firstRecorder.Code != http.StatusOK {
		t.Errorf("got first request status %d, want %d", firstRecorder.Code, http.StatusOK)
	}

	thirdRecorder := httptest.NewRecorder()
	handler.ServeHTTP(thirdRecorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if thirdRecorder.Code != http.StatusOK {
		t.Errorf("got third request status %d, want %d", thirdRecorder.Code, http.StatusOK)
	}
}

// TestHandlerTimeoutCancelsContext covers AC-002.22.
func TestHandlerTimeoutCancelsContext(t *testing.T) {
	t.Parallel()

	var gotErr error

	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		gotErr = r.Context().Err()
	})

	handler := withHandlerTimeout(time.Millisecond, inner)

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if !errors.Is(gotErr, context.DeadlineExceeded) {
		t.Errorf("got context error %v, want %v", gotErr, context.DeadlineExceeded)
	}
}

// TestHandlerTimeoutDisabled covers AC-002.22.
func TestHandlerTimeoutDisabled(t *testing.T) {
	t.Parallel()

	var hasDeadline bool

	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, ok := r.Context().Deadline()
		hasDeadline = ok
	})

	handler := withHandlerTimeout(0, inner)

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if hasDeadline {
		t.Error("got a deadline on the request context, want none when the timeout is disabled")
	}
}
