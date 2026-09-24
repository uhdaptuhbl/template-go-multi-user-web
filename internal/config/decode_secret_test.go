package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sethvargo/go-envconfig"
)

// leakCanary is the plaintext every redaction test looks for. Finding it in
// output is the failure; the tests assert its absence as well as the
// placeholder's presence, because a formatter that silently emits nothing
// would satisfy the second check alone.
const leakCanary = "hunter2"

// TestDecodeLoadsSecretStringFieldsWithoutRevealingThem cover AC-001.26 and AC-001.28.
func TestDecodeLoadsSecretStringFieldsWithoutRevealingThem(t *testing.T) {
	t.Parallel()

	type withSecret struct {
		Token SecretString `env:"API_TOKEN" validate:"required"`
		Inner struct {
			Key SecretString `env:"KEY" validate:"required"`
		} `env:",prefix=INNER_"`
		Optional SecretString `env:"OPTIONAL"`
	}

	var got withSecret

	err := Decode(t.Context(), &got, envconfig.MapLookuper(map[string]string{
		"API_TOKEN": leakCanary,
		"INNER_KEY": "nested-" + leakCanary,
	}))
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	if got.Token.Expose() != leakCanary {
		t.Errorf("Token.Expose() = %q, want %q", got.Token.Expose(), leakCanary)
	}

	if got.Inner.Key.Expose() != "nested-"+leakCanary {
		t.Errorf("Inner.Key.Expose() = %q, want the prefixed value", got.Inner.Key.Expose())
	}

	if got.Optional.Expose() != "" {
		t.Errorf("Optional.Expose() = %q, want it left unset", got.Optional.Expose())
	}

	// Printing the whole struct is what a hurried debugging session does, so
	// that is the case worth pinning.
	if dump := fmt.Sprintf("%v", got); strings.Contains(dump, leakCanary) {
		t.Errorf("formatted config = %s, want no plaintext secret", dump)
	}
}

// TestDecodeValidatesSecretStringFields covers AC-001.28.
func TestDecodeValidatesSecretStringFields(t *testing.T) {
	t.Parallel()

	type withSecret struct {
		Token SecretString `env:"API_TOKEN" validate:"required"`
	}

	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "absent", env: map[string]string{}},
		{name: "present but empty", env: map[string]string{"API_TOKEN": ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cfg withSecret

			err := Decode(t.Context(), &cfg, envconfig.MapLookuper(tt.env))
			if err == nil {
				t.Fatal("Decode() error = nil, want a validation failure")
			}

			if !strings.Contains(err.Error(), "validating configuration") {
				t.Errorf("Decode() error = %q, want it to name the validation stage", err)
			}
		})
	}
}
