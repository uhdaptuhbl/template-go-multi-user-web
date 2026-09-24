package buildinfo

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestInfoLog covers AC-002.23.
func TestInfoLog(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)
	info := Info{Version: "1.2.3", Commit: "abc123", Date: "2026-09-18T00:00:00Z"}

	info.Log(zap.New(core))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Level != zapcore.InfoLevel {
		t.Errorf("got level %v, want %v", entry.Level, zapcore.InfoLevel)
	}

	fields := entry.ContextMap()

	if fields["version"] != "1.2.3" {
		t.Errorf("got version field %v, want %q", fields["version"], "1.2.3")
	}

	if fields["commit"] != "abc123" {
		t.Errorf("got commit field %v, want %q", fields["commit"], "abc123")
	}

	if fields["build_date"] != "2026-09-18T00:00:00Z" {
		t.Errorf("got build_date field %v, want %q", fields["build_date"], "2026-09-18T00:00:00Z")
	}

	goVersion, ok := fields["go_version"].(string)
	if !ok || goVersion == "" {
		t.Errorf("got go_version field %v, want non-empty string", fields["go_version"])
	}
}
