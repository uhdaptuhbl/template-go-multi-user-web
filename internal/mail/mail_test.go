package mail

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
)

// completeConfig returns a Config with everything NewSMTPSender needs to
// succeed, so each failure test only has to unset the one field it means to
// test.
func completeConfig() Config {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Host = "smtp.example.com"
	cfg.From = "codes@example.com"

	return cfg
}

// TestNewSMTPSenderRejectsDisabledConfig cites no criterion: it
// constrains the mail transport's configuration, a mistake reachable only
// from a deployment's own configuration, the fifth exception in CLAUDE.md's Testing Standards.
func TestNewSMTPSenderRejectsDisabledConfig(t *testing.T) {
	t.Parallel()

	cfg := completeConfig()
	cfg.Enabled = false

	_, err := NewSMTPSender(cfg, zap.NewNop())
	if err == nil {
		t.Fatal("NewSMTPSender() error = nil, want an error for a disabled config")
	}
}

// TestNewSMTPSenderRejectsMissingHost cites no criterion: it
// constrains the mail transport's configuration, a mistake reachable only
// from a deployment's own configuration, the fifth exception in CLAUDE.md's Testing Standards.
func TestNewSMTPSenderRejectsMissingHost(t *testing.T) {
	t.Parallel()

	cfg := completeConfig()
	cfg.Host = ""

	_, err := NewSMTPSender(cfg, zap.NewNop())
	if err == nil {
		t.Fatal("NewSMTPSender() error = nil, want an error for a missing host")
	}
}

// TestNewSMTPSenderRejectsMissingFrom cites no criterion: it
// constrains the mail transport's configuration, a mistake reachable only
// from a deployment's own configuration, the fifth exception in CLAUDE.md's Testing Standards.
func TestNewSMTPSenderRejectsMissingFrom(t *testing.T) {
	t.Parallel()

	cfg := completeConfig()
	cfg.From = ""

	_, err := NewSMTPSender(cfg, zap.NewNop())
	if err == nil {
		t.Fatal("NewSMTPSender() error = nil, want an error for a missing from address")
	}
}

// TestNewSMTPSenderSucceedsWithCompleteConfig cites no criterion: it
// constrains the mail transport's configuration, a mistake reachable only
// from a deployment's own configuration, the fifth exception in CLAUDE.md's Testing Standards.
func TestNewSMTPSenderSucceedsWithCompleteConfig(t *testing.T) {
	t.Parallel()

	sender, err := NewSMTPSender(completeConfig(), zap.NewNop())
	if err != nil {
		t.Fatalf("NewSMTPSender() error = %v, want nil", err)
	}

	if sender == nil {
		t.Fatal("NewSMTPSender() sender = nil, want a non-nil sender")
	}
}

// TestDisabledSenderSendReturnsErrDisabled cites no criterion: a send through
// the disabled sender is reachable only from source wiring, because the
// email code routes are not registered at all while codes are disabled,
// the fifth exception in CLAUDE.md's Testing Standards.
func TestDisabledSenderSendReturnsErrDisabled(t *testing.T) {
	t.Parallel()

	sender := NewDisabledSender()

	err := sender.Send(t.Context(), Message{To: "user@example.com", Subject: "code", Body: "123456"})
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("Send() error = %v, want it to satisfy errors.Is(err, ErrDisabled)", err)
	}
}

// TestConfigValidate cites no criterion: it
// constrains the mail transport's configuration, a mistake reachable only
// from a deployment's own configuration, the fifth exception in CLAUDE.md's Testing Standards.
func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "enabled with host and from",
			cfg: Config{
				Enabled: true,
				Host:    "smtp.example.com",
				From:    "codes@example.com",
			},
			wantErr: false,
		},
		{
			name: "enabled without host",
			cfg: Config{
				Enabled: true,
				Host:    "",
				From:    "codes@example.com",
			},
			wantErr: true,
		},
		{
			name: "enabled without from",
			cfg: Config{
				Enabled: true,
				Host:    "smtp.example.com",
				From:    "",
			},
			wantErr: true,
		},
		{
			name:    "disabled and empty",
			cfg:     Config{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate(t.Context())
			if tt.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// TestConfigPasswordRedactsInFmtAndJSON covers AC-008.40.
func TestConfigPasswordRedactsInFmtAndJSON(t *testing.T) {
	t.Parallel()

	cfg := Config{Password: secret.String("hunter2")}

	if got := fmt.Sprintf("password=%v", cfg.Password); got != "password="+secret.Redacted {
		t.Errorf("fmt.Sprintf(password=%%v, cfg.Password) = %q, want %q", got, "password="+secret.Redacted)
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v, want nil", err)
	}

	if strings.Contains(string(data), "hunter2") {
		t.Errorf("json.Marshal() output = %s, want no plaintext secret", data)
	}

	if !strings.Contains(string(data), secret.Redacted) {
		t.Errorf("json.Marshal() output = %s, want %q", data, secret.Redacted)
	}
}
