package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/buildinfo"
)

// testProcessInfo returns a ProcessInfo with fixed values, so an assertion on
// the rendered body is exact rather than approximate.
func testProcessInfo() ProcessInfo {
	return ProcessInfo{
		Build: buildinfo.Info{
			Version: "1.2.3",
			Commit:  "abc1234",
			Date:    "2026-09-18T00:00:00Z",
		},
		// Deliberately not UTC. The handler has to normalise, so that two
		// instances in different zones report comparable timestamps.
		Started: time.Date(2026, time.September, 19, 14, 30, 0, 0, time.FixedZone("test", 2*60*60)),
	}
}

// TestNewVersionHandler covers AC-002.26.
func TestNewVersionHandler(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	newVersionHandler(testProcessInfo(), zap.NewNop()).
		ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/version", http.NoBody))

	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", recorder.Code, http.StatusOK)
	}

	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("got Content-Type %q, want %q", got, "application/json")
	}

	var body versionResponse
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decoding version response: %v", err)
	}

	if body.Version != "1.2.3" {
		t.Errorf("got version %q, want %q", body.Version, "1.2.3")
	}

	if body.Commit != "abc1234" {
		t.Errorf("got commit %q, want %q", body.Commit, "abc1234")
	}

	if body.BuildDate != "2026-09-18T00:00:00Z" {
		t.Errorf("got build_date %q, want %q", body.BuildDate, "2026-09-18T00:00:00Z")
	}

	if body.GoVersion != runtime.Version() {
		t.Errorf("got go_version %q, want %q", body.GoVersion, runtime.Version())
	}

	// Rendered from a fixed value rather than a clock, which is what keeps this
	// assertion exact instead of a range check, and in UTC rather than the
	// +02:00 zone it was built in.
	if body.StartedAt != "2026-09-19T12:30:00Z" {
		t.Errorf("got started_at %q, want %q", body.StartedAt, "2026-09-19T12:30:00Z")
	}
}

// TestVersionResponseJSONKeys covers AC-002.26. The key names are the operator's
// interface and match the fields the start-up log entry uses, so they are
// asserted literally rather than through the struct.
func TestVersionResponseJSONKeys(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	newVersionHandler(testProcessInfo(), zap.NewNop()).
		ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/version", http.NoBody))

	var body map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decoding version response: %v", err)
	}

	want := []string{"version", "commit", "build_date", "go_version", "started_at"}
	for _, key := range want {
		if _, ok := body[key]; !ok {
			t.Errorf("version response has no %q key; got keys %v", key, body)
		}
	}

	if len(body) != len(want) {
		t.Errorf("got %d keys %v, want exactly %d", len(body), body, len(want))
	}
}

// TestUnstampedBuildReportsUnknown covers AC-002.26. An ordinary "go build" with
// no linker flags is a case an operator really does hit, and it has to produce a
// well formed answer rather than empty strings.
func TestUnstampedBuildReportsUnknown(t *testing.T) {
	t.Parallel()

	process := ProcessInfo{
		Build:   buildinfo.Info{Version: buildinfo.Unknown, Commit: buildinfo.Unknown, Date: buildinfo.Unknown},
		Started: time.Date(2026, time.September, 19, 12, 30, 0, 0, time.UTC),
	}

	recorder := httptest.NewRecorder()
	newVersionHandler(process, zap.NewNop()).
		ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/version", http.NoBody))

	var body versionResponse
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decoding version response: %v", err)
	}

	if body.Version != buildinfo.Unknown {
		t.Errorf("got version %q, want %q", body.Version, buildinfo.Unknown)
	}

	// The Go version is read from the runtime rather than stamped, so it is
	// present even when nothing else is.
	if body.GoVersion == "" {
		t.Error("go_version is empty on an unstamped build")
	}
}

// TestApplicationMuxDoesNotServeVersion covers AC-002.27.
//
// The application listener falls through to the frontend handler for anything
// it does not route itself, so the assertion is that /version reaches that
// handler rather than a version report: build identity names the exact release
// to attack, and must not be readable from the port that serves users.
func TestApplicationMuxDoesNotServeVersion(t *testing.T) {
	t.Parallel()

	sentinel := "frontend fallthrough"
	ui := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)

		if _, err := io.WriteString(w, sentinel); err != nil {
			t.Errorf("writing sentinel body: %v", err)
		}
	})

	mux := NewMux(DefaultConfig(), TrustedProxies{}, NewReadiness(), zap.NewNop(), Telemetry{}, ui, nil)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, versionPath, http.NoBody))

	if got := recorder.Body.String(); got != sentinel {
		t.Errorf("GET %s on the application listener returned %q, want the frontend handler's %q",
			versionPath, got, sentinel)
	}

	if strings.Contains(recorder.Body.String(), "go_version") {
		t.Error("the application listener disclosed a version report")
	}
}
