package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// secretHolder stands in for a Config that carries a secret. Config has no
// SecretString field today, so there is nothing in the real value for
// LogEffective to redact; this type is what a descendant's config looks like
// once it grows one.
type secretHolder struct {
	Value SecretString `json:"value"`
}

// TestLogEffectiveEmitsTheResolvedConfig covers AC-002.24.
func TestLogEffectiveEmitsTheResolvedConfig(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)

	LogEffective(zap.New(core), Default())

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Message != "configuration loaded" {
		t.Errorf("got message %q, want %q", entry.Message, "configuration loaded")
	}

	rendered, err := json.Marshal(entry.ContextMap()["config"])
	if err != nil {
		t.Fatalf("json.Marshal() error = %v, want nil", err)
	}

	if !strings.Contains(string(rendered), "pre_drain_delay") {
		t.Errorf("rendered config %s does not contain %q", rendered, "pre_drain_delay")
	}
}

// TestLogEffectiveRedactsSecrets covers AC-002.24.
func TestLogEffectiveRedactsSecrets(t *testing.T) {
	t.Parallel()

	// Rendered through a real zap core rather than by calling json.Marshal on
	// the struct. LogEffective redacts only because zap.Any falls through to
	// the reflected encoder, which honours json.Marshaler; asserting on
	// json.Marshal directly would pass just as happily if zap stopped doing
	// that, which is the failure that would actually leak a secret.
	var buffer bytes.Buffer
	var encoder = zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	var core = zapcore.NewCore(encoder, zapcore.AddSync(&buffer), zapcore.InfoLevel)

	zap.New(core).Info("configuration loaded", zap.Any("config", secretHolder{Value: "super-secret-value"}))

	rendered := buffer.String()

	if strings.Contains(rendered, "super-secret-value") {
		t.Errorf("rendered entry %s leaks the plaintext value", rendered)
	}

	if !strings.Contains(rendered, redacted) {
		t.Errorf("rendered entry %s does not contain redaction placeholder %q", rendered, redacted)
	}
}
