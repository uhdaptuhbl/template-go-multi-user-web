package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestNew covers AC-001.24.
func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		format  Format
		wantErr bool
	}{
		{name: "json format builds a logger", format: FormatJSON, wantErr: false},
		{name: "console format builds a logger", format: FormatConsole, wantErr: false},
		{name: "unrecognised format is rejected", format: Format("yaml"), wantErr: true},
		{name: "empty format is rejected", format: Format(""), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			logger, err := New(zapcore.InfoLevel, test.format)

			if test.wantErr {
				if err == nil {
					t.Fatalf("New(%q) returned no error, want one", test.format)
				}

				return
			}

			if err != nil {
				t.Fatalf("New(%q) returned error: %v", test.format, err)
			}

			if logger == nil {
				t.Fatalf("New(%q) returned a nil logger", test.format)
			}
		})
	}
}

// TestNewSlogHandlerRoutesRecordsToZap covers AC-001.25.
func TestNewSlogHandlerRoutesRecordsToZap(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)
	bridged := slog.New(NewSlogHandler(zap.New(core)))

	bridged.Info("emitted by a dependency", slog.String("component", "third-party"))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if entries[0].Message != "emitted by a dependency" {
		t.Errorf("got message %q, want %q", entries[0].Message, "emitted by a dependency")
	}

	if got := entries[0].ContextMap()["component"]; got != "third-party" {
		t.Errorf("got component field %v, want %q", got, "third-party")
	}
}

// TestInstallSlogDefaultRoutesThePackageLevelSlogLoggerToZap covers AC-001.25.
func TestInstallSlogDefaultRoutesThePackageLevelSlogLoggerToZap(t *testing.T) {
	// Not parallel: this mutates the process-wide slog default, which is the
	// whole behavior under test.
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })

	core, logs := observer.New(zapcore.InfoLevel)

	InstallSlogDefault(zap.New(core))

	slog.Info("emitted through the slog default")

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if entries[0].Message != "emitted through the slog default" {
		t.Errorf("got message %q, want the record emitted through slog's default logger", entries[0].Message)
	}
}

// TestNewSlogHandlerAppliesZapLevelFiltering covers AC-001.25.
func TestNewSlogHandlerAppliesZapLevelFiltering(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.WarnLevel)
	bridged := slog.New(NewSlogHandler(zap.New(core)))

	bridged.Info("below the threshold")
	bridged.Warn("at the threshold")

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if entries[0].Message != "at the threshold" {
		t.Errorf("got message %q, want the warning to be the entry that survived", entries[0].Message)
	}
}

// TestDefaultConfigProducesAUsableLogger covers AC-001.24.
func TestDefaultConfigProducesAUsableLogger(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	// The default must build: it is what the process falls back to when the
	// environment says nothing, so a broken one fails at startup every time.
	logger, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig(DefaultConfig()) returned error: %v", err)
	}

	if logger == nil {
		t.Fatal("NewFromConfig(DefaultConfig()) returned a nil logger")
	}

	// Console rather than JSON, and info rather than debug: the default is
	// tuned for someone running the binary directly, and a deployment turns
	// both up through configuration.
	if cfg.Format != FormatConsole {
		t.Errorf("default Format is %q, want %q", cfg.Format, FormatConsole)
	}

	if cfg.Level != zapcore.InfoLevel {
		t.Errorf("default Level is %v, want %v", cfg.Level, zapcore.InfoLevel)
	}
}

// TestNewFromConfigPassesBothSettingsThrough covers AC-001.24.
func TestNewFromConfigPassesBothSettingsThrough(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "json at debug",
			cfg:     Config{Level: zapcore.DebugLevel, Format: FormatJSON},
			wantErr: false,
		},
		{
			name:    "console at error",
			cfg:     Config{Level: zapcore.ErrorLevel, Format: FormatConsole},
			wantErr: false,
		},
		{
			name:    "unrecognised format is rejected",
			cfg:     Config{Level: zapcore.InfoLevel, Format: Format("yaml")},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			logger, err := NewFromConfig(test.cfg)

			if test.wantErr {
				if err == nil {
					t.Fatalf("NewFromConfig(%+v) returned no error, want one", test.cfg)
				}

				return
			}

			if err != nil {
				t.Fatalf("NewFromConfig(%+v) returned error: %v", test.cfg, err)
			}

			// The configured level reaches the logger rather than being
			// dropped on the way: a logger built at error level must not
			// report that it will emit a debug entry.
			if got := logger.Core().Enabled(zapcore.DebugLevel); got != (test.cfg.Level <= zapcore.DebugLevel) {
				t.Errorf("debug enabled = %t at level %v, want %t", got, test.cfg.Level, !got)
			}
		})
	}
}

// TestJSONFormatEmitsEveryRequestEntry covers AC-001.14.
func TestJSONFormatEmitsEveryRequestEntry(t *testing.T) {
	t.Parallel()

	// zap's production preset samples: past 100 entries sharing a level and
	// message within one second, it keeps only every hundredth. The request
	// log writes one constant message for every request, so the whole stream
	// collapses into that one bucket and most request lines are dropped above
	// 100 req/s, which is the rate at which they start to matter.
	cfg, err := configFor(FormatJSON)
	if err != nil {
		t.Fatalf("configFor(FormatJSON) error = %v, want nil", err)
	}

	path := filepath.Join(t.TempDir(), "entries.log")
	cfg.OutputPaths = []string{path}

	logger, err := cfg.Build()
	if err != nil {
		t.Fatalf("cfg.Build() error = %v, want nil", err)
	}

	const entries = 300

	for range entries {
		logger.Info("request served")
	}

	if err = logger.Sync(); err != nil {
		t.Fatalf("logger.Sync() error = %v, want nil", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v, want nil", err)
	}

	got := strings.Count(string(written), "\n")
	if got != entries {
		t.Errorf("wrote %d entries, want %d: sampling is discarding request logs", got, entries)
	}
}

// consoleLoggerTo builds a console-format logger writing to path, so a test
// can read back exactly what was emitted.
func consoleLoggerTo(t *testing.T, path string) *zap.Logger {
	t.Helper()

	cfg, err := configFor(FormatConsole)
	if err != nil {
		t.Fatalf("configFor(FormatConsole) error = %v, want nil", err)
	}

	cfg.OutputPaths = []string{path}

	logger, err := cfg.Build()
	if err != nil {
		t.Fatalf("cfg.Build() error = %v, want nil", err)
	}

	return logger
}

// TestConsoleFormatDoesNotMakeDPanicFatal cites no criterion: it pins zap's
// Development-flag semantics, so a zap upgrade that recouples encoding to
// crash policy fails here.
func TestConsoleFormatDoesNotMakeDPanicFatal(t *testing.T) {
	t.Parallel()

	// Choosing console output is a statement about encoding, not about
	// whether a DPanic entry should take the process down with it. zap's
	// development preset couples the two, so a deployment that set the format
	// for readability would get a different crash policy with it.
	logger := consoleLoggerTo(t, filepath.Join(t.TempDir(), "entries.log"))

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("DPanic panicked with %v; console format must not change crash policy", recovered)
		}
	}()

	logger.DPanic("inconsistent state")
}

// TestConsoleFormatDoesNotAttachStacktracesToWarnings cites no criterion,
// for the same reason as the test above: it pins zap's Development-flag
// semantics rather than a requirement of this service.
func TestConsoleFormatDoesNotAttachStacktracesToWarnings(t *testing.T) {
	t.Parallel()

	// zap's development preset lowers the stacktrace threshold from error to
	// warn. A warning is a thing an operator reads, not a thing they debug,
	// and a stack trace on every one buries the message.
	path := filepath.Join(t.TempDir(), "entries.log")
	logger := consoleLoggerTo(t, path)

	logger.Warn("disk is filling up")

	if err := logger.Sync(); err != nil {
		t.Fatalf("logger.Sync() error = %v, want nil", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v, want nil", err)
	}

	// zap does not emit runtime.Stack's "goroutine" header; a stacktrace
	// shows up as extra "function\n\tfile:line" pairs appended to the entry.
	// One console entry without one is exactly one line.
	if lines := strings.Count(string(written), "\n"); lines != 1 {
		t.Errorf("warn entry spans %d lines, want 1; it carries a stacktrace:\n%s", lines, written)
	}
}
