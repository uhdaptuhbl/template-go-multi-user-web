package httpclient

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// TestDefaultBoundsEveryPhase covers AC-006.1 and AC-006.2.
func TestDefaultBoundsEveryPhase(t *testing.T) {
	t.Parallel()

	cfg := Default()

	phases := []struct {
		name  string
		value configtype.Duration
	}{
		{name: "ConnectTimeout", value: cfg.ConnectTimeout},
		{name: "TLSHandshakeTimeout", value: cfg.TLSHandshakeTimeout},
		{name: "ResponseHeaderTimeout", value: cfg.ResponseHeaderTimeout},
	}

	if cfg.Timeout <= 0 {
		t.Fatalf("Timeout is %v, want a positive duration: an unbounded request can outlive the process that made it", cfg.Timeout)
	}

	for _, phase := range phases {
		t.Run(phase.name, func(t *testing.T) {
			t.Parallel()

			if phase.value <= 0 {
				t.Errorf("%s is %v, want a positive duration", phase.name, phase.value)
			}

			if phase.value >= cfg.Timeout {
				t.Errorf("%s is %v, want less than the total timeout %v: a phase bound that cannot fire before the total is not a bound", phase.name, phase.value, cfg.Timeout)
			}
		})
	}
}

// TestDefaultBoundsThePool covers AC-006.7.
func TestDefaultBoundsThePool(t *testing.T) {
	t.Parallel()

	cfg := Default()

	limits := []struct {
		name  string
		value int
	}{
		{name: "MaxConnsPerHost", value: cfg.MaxConnsPerHost},
		{name: "MaxIdleConns", value: cfg.MaxIdleConns},
		{name: "MaxIdleConnsPerHost", value: cfg.MaxIdleConnsPerHost},
	}

	for _, limit := range limits {
		t.Run(limit.name, func(t *testing.T) {
			t.Parallel()

			if limit.value <= 0 {
				t.Errorf("%s is %d, want a positive limit: zero leaves the pool unbounded, which is what this package exists to stop", limit.name, limit.value)
			}
		})
	}

	if cfg.IdleConnTimeout <= 0 {
		t.Errorf("IdleConnTimeout is %v, want a positive duration", cfg.IdleConnTimeout)
	}
}

// TestConfigRendersInTheNotationAnOperatorWrites covers AC-006.14.
func TestConfigRendersInTheNotationAnOperatorWrites(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Timeout = configtype.Duration(30 * time.Second)

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal error = %v, want nil", err)
	}

	var decoded map[string]any

	if unmarshalErr := json.Unmarshal(encoded, &decoded); unmarshalErr != nil {
		t.Fatalf("json.Unmarshal error = %v, want nil", unmarshalErr)
	}

	if got := decoded["timeout"]; got != "30s" {
		t.Errorf("timeout rendered as %v, want %q: a duration logged as an integer has to be counted in digits", got, "30s")
	}
}

// TestEverySettingDeclaresItsVariable covers AC-006.13.
//
// Nothing in this repository composes Config yet, so there is no variable to
// set and no loaded value to assert. What can be asserted is that composing it
// is all a service will have to do: every field carries an env tag, and every
// tag says overwrite, without which go-envconfig leaves a field that already
// holds a default exactly as it found it and the whole environment is ignored.
func TestEverySettingDeclaresItsVariable(t *testing.T) {
	t.Parallel()

	for field := range reflect.TypeFor[Config]().Fields() {
		t.Run(field.Name, func(t *testing.T) {
			t.Parallel()

			tag, ok := field.Tag.Lookup("env")
			if !ok {
				t.Fatalf("%s declares no env tag: composing Config would not make it configurable", field.Name)
			}

			if !strings.Contains(tag, "overwrite") {
				t.Errorf("%s has env tag %q, want it to say overwrite: Default() leaves the field non-zero, and go-envconfig skips a non-zero field without it", field.Name, tag)
			}

			if _, hasJSON := field.Tag.Lookup("json"); !hasJSON {
				t.Errorf("%s declares no json tag: it would appear in the logged effective configuration under its Go name", field.Name)
			}
		})
	}
}
