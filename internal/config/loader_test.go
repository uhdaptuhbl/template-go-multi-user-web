package config

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/go-cmp/cmp"
	"github.com/sethvargo/go-envconfig"
)

// basicConfig exercises the two validation layers at once: PORT has an
// envconfig tag and a validator tag, so a missing value reaches the validator
// as a zero rather than failing during decode.
type basicConfig struct {
	Host string `env:"HOST" validate:"required"`
	Port int    `env:"PORT" validate:"required,gt=0"`
}

// requiredEnvConfig marks DSN required to envconfig rather than to the
// validator, so its absence fails during decode.
type requiredEnvConfig struct {
	DSN  string `env:"DSN,required"`
	Port int    `env:"PORT,default=8080"`
}

type defaultsConfig struct {
	Host         string        `env:"HOST,default=localhost"`
	Port         int           `env:"PORT,default=8080"`
	ReadTimeout  time.Duration `env:"READ_TIMEOUT,default=30s"`
	WriteTimeout time.Duration `env:"WRITE_TIMEOUT,default=60s"`
	Debug        bool          `env:"DEBUG,default=false"`
}

type prefixedConfig struct {
	Primary  dbConfig `env:",prefix=PRIMARY_"`
	Replica  dbConfig `env:",prefix=REPLICA_"`
	LogLevel string   `env:"LOG_LEVEL,default=info"`
}

type dbConfig struct {
	DSN         string        `env:"DSN" validate:"required"`
	MaxConns    int           `env:"MAX_CONNS,default=10"`
	IdleTimeout time.Duration `env:"IDLE_TIMEOUT,default=5m"`
}

// dateRangeConfig implements CustomValidator with a check that struct tags
// cannot express: one field must be after another, and both must parse.
type dateRangeConfig struct {
	Start string `env:"START" validate:"required"`
	End   string `env:"END" validate:"required"`

	start time.Time
	end   time.Time
}

// Validate parses both bounds and rejects a range that does not move forward.
func (c *dateRangeConfig) Validate(_ context.Context) error {
	var err error

	c.start, err = time.Parse(time.DateOnly, c.Start)
	if err != nil {
		return errors.New("START must be YYYY-MM-DD")
	}

	c.end, err = time.Parse(time.DateOnly, c.End)
	if err != nil {
		return errors.New("END must be YYYY-MM-DD")
	}

	if !c.end.After(c.start) {
		return errors.New("END must be after START")
	}

	return nil
}

var errCustomAlwaysFails = errors.New("always fails")

type alwaysFailsConfig struct {
	Name string `env:"NAME,default=ok"`
}

// Validate always fails, so a test can assert the custom error survives
// wrapping.
func (*alwaysFailsConfig) Validate(_ context.Context) error {
	return errCustomAlwaysFails
}

type emptyConfig struct{}

type optionalConfig struct {
	Name    string `env:"NAME"`
	Verbose bool   `env:"VERBOSE"`
}

// suffixMutator appends a marker to the value resolved for one key, standing in
// for a real mutator such as a secret-manager lookup.
type suffixMutator struct {
	key string
}

// EnvMutate implements envconfig.Mutator.
func (m *suffixMutator) EnvMutate(_ context.Context, _, resolvedKey, _, currentValue string) (string, bool, error) {
	if resolvedKey == m.key {
		return currentValue + "-mutated", false, nil
	}

	return currentValue, false, nil
}

var errMutatorFailed = errors.New("secret resolution failed")

// failingMutator fails for one key, standing in for a secret lookup that cannot
// be resolved.
type failingMutator struct {
	key string
}

// EnvMutate implements envconfig.Mutator.
func (m *failingMutator) EnvMutate(_ context.Context, _, resolvedKey, _, currentValue string) (string, bool, error) {
	if resolvedKey == m.key {
		return "", true, errMutatorFailed
	}

	return currentValue, false, nil
}

// TestDecodeReadsValuesIntoTheTarget covers AC-001.1.
func TestDecodeReadsValuesIntoTheTarget(t *testing.T) {
	t.Parallel()

	var got basicConfig

	err := Decode(t.Context(), &got, envconfig.MapLookuper(map[string]string{
		"HOST": "api.example.com",
		"PORT": "9090",
	}))
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	want := basicConfig{Host: "api.example.com", Port: 9090}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("decoded config mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodeAppliesDefaultsAndLetsValuesOverrideThem covers AC-001.1.
func TestDecodeAppliesDefaultsAndLetsValuesOverrideThem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want defaultsConfig
	}{
		{
			name: "nothing set uses every default",
			env:  map[string]string{},
			want: defaultsConfig{
				Host:         "localhost",
				Port:         8080,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 60 * time.Second,
				Debug:        false,
			},
		},
		{
			name: "values replace the defaults",
			env: map[string]string{
				"HOST":          "prod.example.com",
				"PORT":          "443",
				"READ_TIMEOUT":  "10s",
				"WRITE_TIMEOUT": "120s",
				"DEBUG":         "true",
			},
			want: defaultsConfig{
				Host:         "prod.example.com",
				Port:         443,
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 120 * time.Second,
				Debug:        true,
			},
		},
		{
			name: "one value set leaves the rest defaulted",
			env:  map[string]string{"PORT": "443"},
			want: defaultsConfig{
				Host:         "localhost",
				Port:         443,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 60 * time.Second,
				Debug:        false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got defaultsConfig

			if err := Decode(t.Context(), &got, envconfig.MapLookuper(tt.env)); err != nil {
				t.Fatalf("Decode() error = %v, want nil", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("decoded config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDecodeResolvesNestedStructsUnderTheirPrefix covers AC-001.20.
func TestDecodeResolvesNestedStructsUnderTheirPrefix(t *testing.T) {
	t.Parallel()

	var got prefixedConfig

	err := Decode(t.Context(), &got, envconfig.MapLookuper(map[string]string{
		"PRIMARY_DSN":          "postgres://primary/db",
		"PRIMARY_MAX_CONNS":    "25",
		"PRIMARY_IDLE_TIMEOUT": "10m",
		"REPLICA_DSN":          "postgres://replica/db",
		"LOG_LEVEL":            "debug",
	}))
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	// Replica takes its own defaults: two instances of the same type are
	// configured independently, which is what lets one struct describe both.
	want := prefixedConfig{
		Primary: dbConfig{
			DSN:         "postgres://primary/db",
			MaxConns:    25,
			IdleTimeout: 10 * time.Minute,
		},
		Replica: dbConfig{
			DSN:         "postgres://replica/db",
			MaxConns:    10,
			IdleTimeout: 5 * time.Minute,
		},
		LogLevel: "debug",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("decoded config mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodeReportsDecodeFailures covers AC-001.2.
func TestDecodeReportsDecodeFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target func() any
		env    map[string]string
	}{
		{
			name:   "value required by envconfig is absent",
			target: func() any { return &requiredEnvConfig{} },
			env:    map[string]string{"PORT": "9090"},
		},
		{
			name:   "value is not a number",
			target: func() any { return &basicConfig{} },
			env:    map[string]string{"HOST": "localhost", "PORT": "not-a-number"},
		},
		{
			name:   "value is not a duration",
			target: func() any { return &defaultsConfig{} },
			env:    map[string]string{"READ_TIMEOUT": "forever"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := Decode(t.Context(), tt.target(), envconfig.MapLookuper(tt.env))
			if err == nil {
				t.Fatal("Decode() error = nil, want a decode failure")
			}

			if !strings.Contains(err.Error(), "reading environment values") {
				t.Errorf("Decode() error = %q, want it to name the decode stage", err)
			}

			if errors.Unwrap(err) == nil {
				t.Error("Decode() error does not wrap the underlying envconfig error")
			}
		})
	}
}

// TestDecodeReportsStructTagValidationFailures covers AC-001.2.
func TestDecodeReportsStructTagValidationFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		env      map[string]string
		wantTag  string
		wantName string
	}{
		{
			name:     "value below the minimum",
			env:      map[string]string{"HOST": "localhost", "PORT": "-1"},
			wantTag:  "gt",
			wantName: "Port",
		},
		{
			name:     "zero value where one is required",
			env:      map[string]string{"HOST": "localhost", "PORT": "0"},
			wantTag:  "required",
			wantName: "Port",
		},
		{
			name:     "empty string where one is required",
			env:      map[string]string{"HOST": "", "PORT": "8080"},
			wantTag:  "required",
			wantName: "Host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cfg basicConfig

			err := Decode(t.Context(), &cfg, envconfig.MapLookuper(tt.env))
			if err == nil {
				t.Fatal("Decode() error = nil, want a validation failure")
			}

			if !strings.Contains(err.Error(), "validating configuration") {
				t.Errorf("Decode() error = %q, want it to name the validation stage", err)
			}

			// The individual failures stay reachable, so a caller can report
			// which setting is wrong rather than only that something is.
			var validationErrs validator.ValidationErrors
			if !errors.As(err, &validationErrs) {
				t.Fatalf("Decode() error = %v, want it to wrap validator.ValidationErrors", err)
			}

			var found bool

			for _, fieldErr := range validationErrs {
				if fieldErr.Field() == tt.wantName && fieldErr.Tag() == tt.wantTag {
					found = true
				}
			}

			if !found {
				t.Errorf("validation errors = %v, want %s to fail the %q rule", validationErrs, tt.wantName, tt.wantTag)
			}
		})
	}
}

// TestDecodeReportsEveryValidationFailureAtOnce covers AC-001.2.
func TestDecodeReportsEveryValidationFailureAtOnce(t *testing.T) {
	t.Parallel()

	type multiRequired struct {
		A string `env:"A,default=x" validate:"required,min=3"`
		B int    `env:"B,default=0"  validate:"required,gt=0"`
		C string `env:"C,default=y" validate:"required,email"`
	}

	var cfg multiRequired

	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{
		"A": "ab",
		"B": "0",
		"C": "not-an-email",
	}))
	if err == nil {
		t.Fatal("Decode() error = nil, want a validation failure")
	}

	var validationErrs validator.ValidationErrors
	if !errors.As(err, &validationErrs) {
		t.Fatalf("Decode() error = %v, want it to wrap validator.ValidationErrors", err)
	}

	// An operator fixing configuration should learn about all three problems
	// from one run rather than one problem per restart.
	if len(validationErrs) != 3 {
		t.Errorf("len(validationErrs) = %d, want 3: %v", len(validationErrs), validationErrs)
	}
}

// TestDecodeValidatesNestedStructFields covers AC-001.2.
func TestDecodeValidatesNestedStructFields(t *testing.T) {
	t.Parallel()

	var cfg prefixedConfig

	// REPLICA_DSN is absent, so the second instance fails its own required
	// rule even though the first one is fully configured.
	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{
		"PRIMARY_DSN": "postgres://primary/db",
	}))
	if err == nil {
		t.Fatal("Decode() error = nil, want a validation failure")
	}

	var validationErrs validator.ValidationErrors
	if !errors.As(err, &validationErrs) {
		t.Fatalf("Decode() error = %v, want it to wrap validator.ValidationErrors", err)
	}

	if got := validationErrs[0].Namespace(); !strings.Contains(got, "Replica.DSN") {
		t.Errorf("failing field = %q, want the replica's DSN", got)
	}
}

// TestDecodeRunsTheCustomValidatorWhenTheTargetImplementsIt covers AC-001.2.
func TestDecodeRunsTheCustomValidatorWhenTheTargetImplementsIt(t *testing.T) {
	t.Parallel()

	var got dateRangeConfig

	err := Decode(t.Context(), &got, envconfig.MapLookuper(map[string]string{
		"START": "2026-01-01",
		"END":   "2026-12-31",
	}))
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	// The custom validator parsed both bounds into unexported fields, which is
	// the observable evidence it ran rather than being skipped.
	if !got.end.After(got.start) {
		t.Errorf("parsed range = %v..%v, want the custom validator to have parsed both bounds", got.start, got.end)
	}
}

// TestDecodeReportsCustomValidationFailures covers AC-001.2.
func TestDecodeReportsCustomValidationFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		wantMsg string
	}{
		{
			name:    "start is not a date",
			env:     map[string]string{"START": "not-a-date", "END": "2026-12-31"},
			wantMsg: "START must be YYYY-MM-DD",
		},
		{
			name:    "end is not a date",
			env:     map[string]string{"START": "2026-01-01", "END": "not-a-date"},
			wantMsg: "END must be YYYY-MM-DD",
		},
		{
			name:    "range runs backwards",
			env:     map[string]string{"START": "2026-12-31", "END": "2026-01-01"},
			wantMsg: "END must be after START",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cfg dateRangeConfig

			err := Decode(t.Context(), &cfg, envconfig.MapLookuper(tt.env))
			if err == nil {
				t.Fatal("Decode() error = nil, want a custom validation failure")
			}

			if !strings.Contains(err.Error(), "running custom validation") {
				t.Errorf("Decode() error = %q, want it to name the custom validation stage", err)
			}

			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Decode() error = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}

// TestDecodeKeepsTheCustomValidatorErrorMatchable covers AC-001.2.
func TestDecodeKeepsTheCustomValidatorErrorMatchable(t *testing.T) {
	t.Parallel()

	var cfg alwaysFailsConfig

	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{}))
	if err == nil {
		t.Fatal("Decode() error = nil, want a custom validation failure")
	}

	if !errors.Is(err, errCustomAlwaysFails) {
		t.Errorf("Decode() error = %v, want errors.Is to match the sentinel the validator returned", err)
	}
}

// TestDecodeValidatesStructTagsBeforeTheCustomValidator covers AC-001.2.
func TestDecodeValidatesStructTagsBeforeTheCustomValidator(t *testing.T) {
	t.Parallel()

	var cfg dateRangeConfig

	// END is absent, so it arrives as an empty string. Struct-tag validation
	// must reject it before the custom validator tries to parse it: reaching
	// the custom validator would report a date-format problem for a value the
	// operator never set.
	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{
		"START": "2026-01-01",
	}))
	if err == nil {
		t.Fatal("Decode() error = nil, want a validation failure")
	}

	if !strings.Contains(err.Error(), "validating configuration") {
		t.Errorf("Decode() error = %q, want it to fail struct-tag validation", err)
	}

	if strings.Contains(err.Error(), "END must be") {
		t.Errorf("Decode() error = %q, want the custom validator not to have run", err)
	}
}

// TestDecodeAppliesMutatorsToResolvedValues covers AC-001.32.
func TestDecodeAppliesMutatorsToResolvedValues(t *testing.T) {
	t.Parallel()

	var got optionalConfig

	err := Decode(t.Context(), &got, envconfig.MapLookuper(map[string]string{
		"NAME": "svc",
	}), &suffixMutator{key: "NAME"})
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	want := optionalConfig{Name: "svc-mutated"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("decoded config mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodeReportsMutatorFailures covers AC-001.32.
func TestDecodeReportsMutatorFailures(t *testing.T) {
	t.Parallel()

	var cfg optionalConfig

	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{
		"NAME": "sm://prod/secret",
	}), &failingMutator{key: "NAME"})
	if err == nil {
		t.Fatal("Decode() error = nil, want the mutator failure")
	}

	if !errors.Is(err, errMutatorFailed) {
		t.Errorf("Decode() error = %v, want errors.Is to match the mutator's error", err)
	}
}

// TestDecodeRejectsTargetsItCannotWriteInto cites no criterion: every case
// here is a programming error at a call site, not behaviour a running service
// exhibits. What it guards is that the error names which mistake was made.
func TestDecodeRejectsTargetsItCannotWriteInto(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target any
		want   error
	}{
		{name: "nil interface", target: nil, want: ErrNilTarget},
		{name: "typed nil pointer", target: (*basicConfig)(nil), want: ErrNilTarget},
		{name: "struct value rather than a pointer", target: basicConfig{}, want: ErrNotPointer},
		{name: "pointer to a string", target: new(string), want: ErrNotStruct},
		{name: "pointer to an int", target: new(int), want: ErrNotStruct},
		{name: "pointer to a slice", target: new([]string), want: ErrNotStruct},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := Decode(t.Context(), tt.target, envconfig.MapLookuper(map[string]string{}))
			if !errors.Is(err, tt.want) {
				t.Errorf("Decode() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestDecodeAcceptsAStructWithNothingToConfigure cites no criterion: it pins
// the degenerate input, so that a package composing an empty settings struct
// is not rejected for having nothing to read.
func TestDecodeAcceptsAStructWithNothingToConfigure(t *testing.T) {
	t.Parallel()

	var got emptyConfig

	if err := Decode(t.Context(), &got, envconfig.MapLookuper(map[string]string{})); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}
}

// TestDecodeLeavesUnsetOptionalFieldsAtTheirZeroValue covers AC-001.3.
func TestDecodeLeavesUnsetOptionalFieldsAtTheirZeroValue(t *testing.T) {
	t.Parallel()

	var got optionalConfig

	if err := Decode(t.Context(), &got, envconfig.MapLookuper(map[string]string{})); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	if diff := cmp.Diff(optionalConfig{}, got); diff != "" {
		t.Errorf("decoded config mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodeReadsTheProcessEnvironmentWhenNoLookuperIsGiven covers AC-001.1.
func TestDecodeReadsTheProcessEnvironmentWhenNoLookuperIsGiven(t *testing.T) {
	// Not parallel: t.Setenv mutates process state, which is the whole point
	// of this test and the reason every other test here injects a lookuper
	// instead.
	type hostOnly struct {
		Host string `env:"SERVICE_TEST_HOST"`
	}

	t.Setenv("SERVICE_TEST_HOST", "from-the-environment")

	var got hostOnly

	if err := Decode(t.Context(), &got, nil); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	if got.Host != "from-the-environment" {
		t.Errorf("Host = %q, want the value read from the process environment", got.Host)
	}
}

// TestDecodeIgnoresACancelledContext cites no criterion: it pins a third
// party's measured behaviour so an upgrade that changes it fails here rather
// than somewhere further away. The reasoning is at the assertion.
func TestDecodeIgnoresACancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var got basicConfig

	// Measured go-envconfig behaviour, not a project guarantee: ProcessWith
	// does not check ctx itself, and no lookuper used here performs I/O, so a
	// cancelled context changes nothing. Decode adds no check of its own,
	// because refusing to read a value that is already in memory would only
	// turn a clean shutdown into a startup error.
	if err := Decode(ctx, &got, envconfig.MapLookuper(map[string]string{
		"HOST": "localhost",
		"PORT": "8080",
	})); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	want := basicConfig{Host: "localhost", Port: 8080}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("decoded config mismatch (-want +got):\n%s", diff)
	}
}

var errRangeBackwards = errors.New("HIGH must be above LOW")

var errTargetRejected = errors.New("the whole thing is wrong")

// rangeConfig is validated as a field of something else rather than as a decode
// target, which is how a package validates settings only it understands.
type rangeConfig struct {
	Low  int `env:"LOW, default=1"`
	High int `env:"HIGH, default=9"`
}

// Validate rejects a range that does not move upwards.
func (c *rangeConfig) Validate(_ context.Context) error {
	if c.High <= c.Low {
		return errRangeBackwards
	}

	return nil
}

// composedConfig mirrors the shape of the real configuration: two instances of
// one type told apart only by their prefix, a field whose variables carry no
// prefix at all, an unexported field reflection must not reach into, and a hook
// of its own over the whole thing.
type composedConfig struct {
	// Primary and Secondary spell the same option differently on purpose: a
	// space after the comma is accepted by go-envconfig, so reading the prefix
	// back out of the tag has to tolerate both spellings.
	Primary   rangeConfig `env:", prefix=PRIMARY_"`
	Secondary rangeConfig `env:",prefix=SECONDARY_"`
	Bare      rangeConfig
	Plain     optionalConfig `env:", prefix=PLAIN_"`

	// Reject makes the target's own hook fail, so a test can set a field hook
	// and this one failing at the same time.
	Reject string `env:"TARGET_REJECT"`

	hidden rangeConfig

	targetValidated bool
}

// Validate records that the target's own hook ran, so a test can tell it apart
// from the field hooks that run beside it, and fails on demand.
func (c *composedConfig) Validate(_ context.Context) error {
	c.targetValidated = true

	if c.Reject != "" {
		return errTargetRejected
	}

	return nil
}

// outerConfig reaches rangeConfig two levels down, which is past the one level
// Decode walks.
type outerConfig struct {
	Middle middleConfig `env:", prefix=MIDDLE_"`
}

type middleConfig struct {
	Inner rangeConfig `env:", prefix=INNER_"`
}

// TestDecodeRunsTheCustomValidatorOnEachImmediateField covers AC-001.18.
func TestDecodeRunsTheCustomValidatorOnEachImmediateField(t *testing.T) {
	t.Parallel()

	var cfg composedConfig

	// Only the primary range runs backwards. Two instances of one type are
	// configured independently, so they must be validated independently too.
	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{
		"PRIMARY_LOW":  "9",
		"PRIMARY_HIGH": "1",
	}))
	if err == nil {
		t.Fatal("Decode() error = nil, want the field validator to fail")
	}

	if !errors.Is(err, errRangeBackwards) {
		t.Errorf("Decode() error = %v, want errors.Is to match the field validator's error", err)
	}

	// The field's own validator knows the range is backwards but not which
	// instance it belongs to, so the prefix has to come from the composing
	// struct or the message names nothing an operator can act on.
	if !strings.Contains(err.Error(), "PRIMARY_") {
		t.Errorf("Decode() error = %q, want it to name the failing field's prefix", err)
	}

	if strings.Contains(err.Error(), "SECONDARY_") {
		t.Errorf("Decode() error = %q, want the valid instance not to be reported", err)
	}
}

// TestDecodeJoinsFailuresFromEveryFieldValidator covers AC-001.2.
func TestDecodeJoinsFailuresFromEveryFieldValidator(t *testing.T) {
	t.Parallel()

	var cfg composedConfig

	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{
		"PRIMARY_LOW":    "9",
		"PRIMARY_HIGH":   "1",
		"SECONDARY_LOW":  "9",
		"SECONDARY_HIGH": "1",
	}))
	if err == nil {
		t.Fatal("Decode() error = nil, want both field validators to fail")
	}

	// One run, every wrong settings group. Stopping at the first would cost an
	// operator a restart per mistake.
	for _, want := range []string{"PRIMARY_", "SECONDARY_"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Decode() error = %q, want it to name %s", err, want)
		}
	}
}

// TestDecodeLabelsAnUntaggedFieldByItsName covers AC-001.19.
func TestDecodeLabelsAnUntaggedFieldByItsName(t *testing.T) {
	t.Parallel()

	var cfg composedConfig

	// Bare declares no prefix, as a settings group whose variable names are
	// fixed outside this project does. The Go field name is then the only name
	// the failure can be attributed to.
	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{
		"LOW":  "9",
		"HIGH": "1",
	}))
	if err == nil {
		t.Fatal("Decode() error = nil, want the field validator to fail")
	}

	if !strings.Contains(err.Error(), "Bare") {
		t.Errorf("Decode() error = %q, want it to name the untagged field", err)
	}
}

// TestDecodeReportsFieldAndTargetValidationFailuresTogether covers AC-001.2.
func TestDecodeReportsFieldAndTargetValidationFailuresTogether(t *testing.T) {
	t.Parallel()

	var cfg composedConfig

	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{
		"PRIMARY_LOW":   "9",
		"PRIMARY_HIGH":  "1",
		"TARGET_REJECT": "yes",
	}))
	if err == nil {
		t.Fatal("Decode() error = nil, want both validators to fail")
	}

	// The two layers check different things, so one failing says nothing about
	// the other. Stopping at the field hooks would hide a mistake in the
	// composed settings until the operator had fixed this one and restarted.
	if !cfg.targetValidated {
		t.Error("the target's validator did not run after a field failed, want it to run anyway")
	}

	for _, want := range []error{errRangeBackwards, errTargetRejected} {
		if !errors.Is(err, want) {
			t.Errorf("Decode() error = %v, want errors.Is to match %v", err, want)
		}
	}
}

// TestDecodeRunsTheTargetValidatorAfterItsFields covers AC-001.18.
func TestDecodeRunsTheTargetValidatorAfterItsFields(t *testing.T) {
	t.Parallel()

	var cfg composedConfig

	if err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{})); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	if !cfg.targetValidated {
		t.Error("the target's validator did not run, want it to run once its fields passed")
	}

	// An unexported field is neither decoded into nor reached for a hook:
	// reflection cannot call a method on one, and trying would panic.
	if diff := cmp.Diff(rangeConfig{}, cfg.hidden); diff != "" {
		t.Errorf("unexported field mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodeDoesNotRunCustomValidatorsBelowTheFirstLevel covers AC-001.31.
func TestDecodeDoesNotRunCustomValidatorsBelowTheFirstLevel(t *testing.T) {
	t.Parallel()

	var cfg outerConfig

	// Inner's range runs backwards, and Inner sits two levels down. Decode
	// walks one level by design, so this decodes cleanly; a rule that has to
	// hold here belongs on Middle, which is the level that is walked.
	err := Decode(t.Context(), &cfg, envconfig.MapLookuper(map[string]string{
		"MIDDLE_INNER_LOW":  "9",
		"MIDDLE_INNER_HIGH": "1",
	}))
	if err != nil {
		t.Fatalf("Decode() error = %v, want the deeper hook not to run", err)
	}

	if cfg.Middle.Inner.Low != 9 || cfg.Middle.Inner.High != 1 {
		t.Errorf("Middle.Inner = %+v, want the values to have decoded regardless", cfg.Middle.Inner)
	}
}
