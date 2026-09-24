package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
)

// validConfig returns a Config that Validate accepts, so each failure test
// only has to unset the one field it means to test.
func validConfig() Config {
	cfg := DefaultConfig()
	cfg.DSN = secret.String("postgres://user:secret@localhost:5432/service")

	return cfg
}

// TestConfigValidateRejectsWhatCannotNameAReachableServer covers AC-008.2 for
// the empty and unparseable DSN cases: a connection string that is empty or
// does not parse can never name a server this process could reach, so
// Validate refuses it before Open ever dials out. The min-conns-exceeds-max
// case cites no criterion: it constrains a mistake only reachable from a
// deployment's own configuration, not a property of the running service, the
// fifth exception in CLAUDE.md's Testing Standards.
func TestConfigValidateRejectsWhatCannotNameAReachableServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid config",
			mutate:  func(_ *Config) {},
			wantErr: false,
		},
		{
			name: "min conns exceeds max conns",
			mutate: func(c *Config) {
				c.MaxConns = 5
				c.MinConns = 6
			},
			wantErr: true,
		},
		{
			name: "empty dsn",
			mutate: func(c *Config) {
				c.DSN = secret.String("")
			},
			wantErr: true,
		},
		{
			name: "unparseable dsn",
			mutate: func(c *Config) {
				c.DSN = secret.String("not a dsn :: nope")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			tt.mutate(&cfg)

			err := cfg.Validate(t.Context())
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConfigDSNRedactsThroughFmtAndJSON cites no criterion: it pins the
// secret.String contract (see internal/secret) as it applies to this field,
// which is the "guards an exported contract's behavior" exception in
// CLAUDE.md's Testing Standards rather than a property of this spec.
func TestConfigDSNRedactsThroughFmtAndJSON(t *testing.T) {
	t.Parallel()

	const leakCanary = "hunter2"

	cfg := validConfig()
	cfg.DSN = secret.String("postgres://user:" + leakCanary + "@localhost:5432/service")

	wantFmt := "dsn=" + secret.Redacted

	gotFmt := fmt.Sprintf("dsn=%v", cfg.DSN)
	if gotFmt != wantFmt {
		t.Errorf("fmt.Sprintf(%%v) = %q, want %q", gotFmt, wantFmt)
	}

	if strings.Contains(gotFmt, leakCanary) {
		t.Errorf("fmt.Sprintf(%%v) = %q, leaked the password", gotFmt)
	}

	marshaled, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v, want nil", err)
	}

	if strings.Contains(string(marshaled), leakCanary) {
		t.Errorf("json.Marshal() = %s, leaked the password", marshaled)
	}

	if !strings.Contains(string(marshaled), secret.Redacted) {
		t.Errorf("json.Marshal() = %s, want it to contain %q", marshaled, secret.Redacted)
	}
}
