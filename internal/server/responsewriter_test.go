package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStatusRecorderWritten covers AC-002.12.
func TestStatusRecorderWritten(t *testing.T) {
	t.Parallel()

	recorder := &statusRecorder{ResponseWriter: httptest.NewRecorder()}

	if recorder.Written() {
		t.Error("Written reported true before any write")
	}

	recorder.WriteHeader(http.StatusTeapot)

	if !recorder.Written() {
		t.Error("Written reported false after WriteHeader")
	}

	bareWriteRecorder := &statusRecorder{ResponseWriter: httptest.NewRecorder()}

	if _, err := bareWriteRecorder.Write([]byte("body")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	if !bareWriteRecorder.Written() {
		t.Error("Written reported false after a bare Write")
	}

	firstStatusWins := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	firstStatusWins.WriteHeader(http.StatusTeapot)
	firstStatusWins.WriteHeader(http.StatusInternalServerError)

	if firstStatusWins.status != http.StatusTeapot {
		t.Errorf("got status %d, want %d: first WriteHeader call should win", firstStatusWins.status, http.StatusTeapot)
	}
}
