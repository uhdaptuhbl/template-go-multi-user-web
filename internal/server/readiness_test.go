package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestReadinessHandlerReady covers AC-002.13.
func TestReadinessHandlerReady(t *testing.T) {
	t.Parallel()

	ready := NewReadiness()
	recorder := httptest.NewRecorder()

	newReadinessHandler(ready, zap.NewNop()).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, readyPath, http.NoBody))

	if recorder.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusOK)
	}

	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("got Content-Type %q, want %q", got, "application/json")
	}

	got := strings.TrimSuffix(recorder.Body.String(), "\n")
	if diff := cmp.Diff(`{"status":"ready"}`, got); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
}

// TestReadinessHandlerDraining covers AC-002.14.
func TestReadinessHandlerDraining(t *testing.T) {
	t.Parallel()

	ready := NewReadiness()
	ready.SetDraining()

	recorder := httptest.NewRecorder()
	newReadinessHandler(ready, zap.NewNop()).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, readyPath, http.NoBody))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}

	got := strings.TrimSuffix(recorder.Body.String(), "\n")
	if diff := cmp.Diff(`{"status":"draining"}`, got); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}

	// Calling SetDraining a second time must be a no-op: still draining, same body.
	ready.SetDraining()

	secondRecorder := httptest.NewRecorder()
	newReadinessHandler(ready, zap.NewNop()).ServeHTTP(secondRecorder, httptest.NewRequest(http.MethodGet, readyPath, http.NoBody))

	if secondRecorder.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want %d", secondRecorder.Code, http.StatusServiceUnavailable)
	}

	secondGot := strings.TrimSuffix(secondRecorder.Body.String(), "\n")
	if diff := cmp.Diff(`{"status":"draining"}`, secondGot); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
}

// TestReadinessHandlerConsultsRegisteredChecks covers AC-005.7 and AC-005.8.
func TestReadinessHandlerConsultsRegisteredChecks(t *testing.T) {
	t.Parallel()

	pass := func(context.Context) error { return nil }
	fail := func(context.Context) error { return errors.New("connection refused") }

	tests := []struct {
		name         string
		checks       map[string]Check
		wantStatus   int
		wantBody     string
		wantFailures int
	}{
		{
			name:       "all pass",
			checks:     map[string]Check{"cache": pass, "database": pass},
			wantStatus: http.StatusOK,
			wantBody:   `{"status":"ready"}`,
		},
		{
			name:         "one fails",
			checks:       map[string]Check{"cache": pass, "database": fail},
			wantStatus:   http.StatusServiceUnavailable,
			wantBody:     `{"status":"not_ready","failing":["database"]}`,
			wantFailures: 1,
		},
		{
			name:         "several fail, reported in name order",
			checks:       map[string]Check{"queue": fail, "cache": pass, "database": fail},
			wantStatus:   http.StatusServiceUnavailable,
			wantBody:     `{"status":"not_ready","failing":["database","queue"]}`,
			wantFailures: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ready := NewReadiness()

			for name, check := range test.checks {
				ready.AddCheck(name, check)
			}

			core, observed := observer.New(zap.WarnLevel)
			recorder := httptest.NewRecorder()

			newReadinessHandler(ready, zap.New(core)).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, readyPath, http.NoBody))

			if recorder.Code != test.wantStatus {
				t.Errorf("got status %d, want %d", recorder.Code, test.wantStatus)
			}

			if diff := cmp.Diff(test.wantBody, strings.TrimSpace(recorder.Body.String())); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}

			// One warning per failed check, carrying the cause the body omits.
			entries := observed.FilterMessage("readiness check failed").All()
			if len(entries) != test.wantFailures {
				t.Errorf("got %d failure log entries, want %d", len(entries), test.wantFailures)
			}

			for _, entry := range entries {
				if got := entry.ContextMap()["error"]; got != "connection refused" {
					t.Errorf("got logged error %v, want %q", got, "connection refused")
				}
			}
		})
	}
}

// TestReadinessCheckIsCancelledAtTheTimeout covers AC-005.9.
func TestReadinessCheckIsCancelledAtTheTimeout(t *testing.T) {
	t.Parallel()

	ready := NewReadiness()
	ready.checkTimeout = time.Millisecond

	// The check returns only when its context is cancelled, so the outcome does
	// not depend on how long anything takes: either the timeout fires and this
	// returns the cancellation error, or the test hangs.
	ready.AddCheck("slow", func(ctx context.Context) error {
		<-ctx.Done()

		return ctx.Err()
	})

	recorder := httptest.NewRecorder()
	newReadinessHandler(ready, zap.NewNop()).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, readyPath, http.NoBody))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}

	if diff := cmp.Diff(`{"status":"not_ready","failing":["slow"]}`, strings.TrimSpace(recorder.Body.String())); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
}

// TestReadinessCheckPanicCountsAsFailed covers AC-005.10.
func TestReadinessCheckPanicCountsAsFailed(t *testing.T) {
	t.Parallel()

	ready := NewReadiness()
	ready.AddCheck("broken", func(context.Context) error { panic("nil pointer dereference") })
	ready.AddCheck("fine", func(context.Context) error { return nil })

	core, observed := observer.New(zap.WarnLevel)
	recorder := httptest.NewRecorder()

	// Reaching the assertions at all is the proof the panic was contained.
	newReadinessHandler(ready, zap.New(core)).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, readyPath, http.NoBody))

	if diff := cmp.Diff(`{"status":"not_ready","failing":["broken"]}`, strings.TrimSpace(recorder.Body.String())); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}

	entries := observed.FilterMessage("readiness check failed").All()
	if len(entries) != 1 {
		t.Fatalf("got %d failure log entries, want 1", len(entries))
	}

	if got := entries[0].ContextMap()["error"]; got != "check panicked: nil pointer dereference" {
		t.Errorf("got logged error %v, want the panic value", got)
	}
}

// TestReadinessDrainingSkipsChecks covers AC-005.11.
func TestReadinessDrainingSkipsChecks(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	ready := NewReadiness()
	ready.AddCheck("database", func(context.Context) error {
		calls.Add(1)

		return errors.New("connection refused")
	})
	ready.SetDraining()

	recorder := httptest.NewRecorder()
	newReadinessHandler(ready, zap.NewNop()).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, readyPath, http.NoBody))

	if diff := cmp.Diff(`{"status":"draining"}`, strings.TrimSpace(recorder.Body.String())); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}

	if got := calls.Load(); got != 0 {
		t.Errorf("check ran %d times while draining, want 0", got)
	}
}

// TestAddCheckRejectsADuplicateName covers AC-005.12.
func TestAddCheckRejectsADuplicateName(t *testing.T) {
	t.Parallel()

	ready := NewReadiness()
	ready.AddCheck("database", func(context.Context) error { return nil })

	defer func() {
		if recover() == nil {
			t.Error("AddCheck accepted a duplicate name, want a panic")
		}
	}()

	ready.AddCheck("database", func(context.Context) error { return nil })
}

// TestZeroValueReadinessRunsChecksWithTheDefaultTimeout covers AC-005.9.
func TestZeroValueReadinessRunsChecksWithTheDefaultTimeout(t *testing.T) {
	t.Parallel()

	// A Readiness composed as a struct literal rather than through NewReadiness
	// carries a zero timeout. Handing that to context.WithTimeout unguarded
	// would expire every check before it ran and take a healthy process out of
	// rotation.
	var ready Readiness

	ready.AddCheck("dependency", func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("check ran without a deadline")
		}

		if time.Until(deadline) <= 0 {
			return errors.New("check ran with an already-expired deadline")
		}

		return nil
	})

	recorder := httptest.NewRecorder()
	newReadinessHandler(&ready, zap.NewNop()).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, readyPath, http.NoBody))

	if recorder.Code != http.StatusOK {
		t.Errorf("got status %d, want %d; body was %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}
