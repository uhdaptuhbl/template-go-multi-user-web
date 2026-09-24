package logging

import (
	"fmt"
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

// Format selects how log entries are encoded.
type Format string

// FormatJSON encodes one JSON object per entry, for machine consumption.
const FormatJSON Format = "json"

// FormatConsole encodes human-readable entries, for local development.
const FormatConsole Format = "console"

// Config selects the logger's verbosity and encoding.
type Config struct {
	// Level is the minimum severity an entry must carry to be emitted. It
	// accepts the zapcore level names: debug, info, warn, error, dpanic, panic,
	// and fatal.
	Level zapcore.Level `env:"LEVEL, overwrite" json:"level"`
	// Format selects the encoding. See FormatJSON and FormatConsole.
	Format Format `env:"FORMAT, overwrite" json:"format" validate:"required,oneof=json console"`
}

// DefaultConfig returns the logging configuration used when nothing overrides
// it: human-readable output at info level, which suits a developer running the
// binary directly. Deployments are expected to select FormatJSON.
func DefaultConfig() Config {
	return Config{
		Level:  zapcore.InfoLevel,
		Format: FormatConsole,
	}
}

// NewFromConfig builds a logger from cfg. It is the form the composition root
// uses; New remains available for callers that already hold the two values.
func NewFromConfig(cfg Config) (*zap.Logger, error) {
	return New(cfg.Level, cfg.Format)
}

// New builds a logger that writes entries at or above level in the given
// format. The caller owns the returned logger and is responsible for calling
// Sync before exit.
func New(level zapcore.Level, format Format) (*zap.Logger, error) {
	cfg, err := configFor(format)
	if err != nil {
		return nil, err
	}

	cfg.Level = zap.NewAtomicLevelAt(level)

	logger, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("building zap logger: %w", err)
	}

	return logger, nil
}

// configFor returns the zap configuration backing the given format, before
// the caller's level is applied. It is separate from New so a test can build
// a logger over a sink it controls and assert on what is actually emitted.
func configFor(format Format) (zap.Config, error) {
	switch format {
	case FormatJSON:
		cfg := zap.NewProductionConfig()

		// The production preset samples: past 100 entries sharing a level and
		// message in one second, it keeps only every hundredth. The request
		// log emits one constant message for every request, so the entire
		// stream falls in that one bucket and AC-001.14's "one entry per
		// served request" stops holding at exactly the traffic level where
		// the entries start to matter. Volume control belongs in the log
		// pipeline, which sees the whole stream and can drop by rule; a
		// process cannot make that judgement from inside one bucket.
		cfg.Sampling = nil

		return cfg, nil
	case FormatConsole:
		cfg := zap.NewDevelopmentConfig()

		// The console encoder is all that is wanted from the development
		// preset. Its Development flag also makes DPanic terminate the
		// process and attaches a stacktrace to every entry from warn upward,
		// and neither should follow from a choice about output format: a
		// deployment that picks console output for readability would get a
		// different crash policy along with it.
		cfg.Development = false

		return cfg, nil
	default:
		return zap.Config{}, fmt.Errorf("unknown log format %q", format)
	}
}

// NewSlogHandler returns a slog.Handler that writes records into the core
// backing logger, so slog output is encoded and filtered identically to
// entries logged through zap directly.
func NewSlogHandler(logger *zap.Logger) slog.Handler {
	return zapslog.NewHandler(logger.Core())
}

// InstallSlogDefault points the standard library's default slog logger at
// logger. It mutates process-wide state in log/slog and is intended to be
// called once, from the composition root, so that dependencies logging through
// slog's package-level functions are captured.
func InstallSlogDefault(logger *zap.Logger) {
	slog.SetDefault(slog.New(NewSlogHandler(logger)))
}
