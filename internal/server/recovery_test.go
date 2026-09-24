package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestPanicRecoveryWritesInternalError covers AC-002.1.
func TestPanicRecoveryWritesInternalError(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.ErrorLevel)
	logger := zap.New(core)

	handler := withPanicRecovery(logger, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	wantBody := `{"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}`
	if got := strings.TrimSuffix(rec.Body.String(), "\n"); got != wantBody {
		t.Errorf("got body %q, want %q", got, wantBody)
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if entries[0].Level != zapcore.ErrorLevel {
		t.Errorf("got log level %v, want %v", entries[0].Level, zapcore.ErrorLevel)
	}

	if entries[0].Message != "recovered panic serving request" {
		t.Errorf("got log message %q, want %q", entries[0].Message, "recovered panic serving request")
	}
}

// TestPanicRecoveryPreservesWrittenResponse covers AC-002.1.
func TestPanicRecoveryPreservesWrittenResponse(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	handler := withPanicRecovery(logger, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	recorder := &statusRecorder{ResponseWriter: rec}

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)

	handler.ServeHTTP(recorder, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusTeapot)
	}

	if strings.Contains(rec.Body.String(), "error") {
		t.Errorf("got body %q, want no error body appended", rec.Body.String())
	}
}

// TestPanicRecoveryRepanicsOnErrAbortHandler covers AC-002.2.
func TestPanicRecoveryRepanicsOnErrAbortHandler(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.ErrorLevel)
	logger := zap.New(core)

	handler := withPanicRecovery(logger, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()

	func() {
		defer func() {
			recovered := recover()
			if recovered == nil {
				t.Fatal("expected a panic, got none")
			}

			err, ok := recovered.(error)
			if !ok || !errors.Is(err, http.ErrAbortHandler) {
				t.Errorf("recovered panic value = %v, want %v", recovered, http.ErrAbortHandler)
			}
		}()

		handler.ServeHTTP(rec, req)
	}()

	if entries := logs.All(); len(entries) != 0 {
		t.Errorf("got %d log entries, want 0", len(entries))
	}
}
