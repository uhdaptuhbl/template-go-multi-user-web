package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// leakCanary is the plaintext every redaction test looks for. Finding it in
// output is the failure; the tests assert its absence as well as the
// placeholder's presence, because a formatter that silently emits nothing
// would satisfy the second check alone.
const leakCanary = "hunter2"

// TestSecretStringRedactsInEveryStringRepresentation covers AC-001.26.
func TestSecretStringRedactsInEveryStringRepresentation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format func(String) string
	}{
		{
			name:   "String",
			format: func(s String) string { return s.String() },
		},
		{
			name: "fmt %s",
			// Calling String directly, as gocritic suggests, would test the
			// method rather than the routing: the point is that fmt finds it.
			//nolint:gocritic,staticcheck // see comment above
			format: func(s String) string { return fmt.Sprintf("%s", s) },
		},
		{
			name: "fmt %v",
			//nolint:gocritic // see the %s case above
			format: func(s String) string { return fmt.Sprintf("%v", s) },
		},
		{
			name:   "fmt %q",
			format: func(s String) string { return fmt.Sprintf("%q", s) },
		},
		{
			name:   "LogValue",
			format: func(s String) string { return s.LogValue().String() },
		},
		{
			// %#v consults fmt.GoStringer, not fmt.Stringer, so it needs
			// its own method.
			name:   "fmt %#v",
			format: func(s String) string { return fmt.Sprintf("%#v", s) },
		},
		{
			// The shape that reaches %#v in practice: a whole
			// configuration struct dumped while debugging.
			name: "fmt %#v on a struct field",
			format: func(s String) string {
				return fmt.Sprintf("%#v", struct{ Password String }{Password: s})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.format(String(leakCanary))

			if strings.Contains(got, leakCanary) {
				t.Errorf("formatted secret = %q, want the plaintext absent", got)
			}

			if !strings.Contains(got, Redacted) {
				t.Errorf("formatted secret = %q, want it to contain %q", got, Redacted)
			}
		})
	}
}

// TestSecretStringRedactsWhenItHoldsNothing covers AC-001.26.
func TestSecretStringRedactsWhenItHoldsNothing(t *testing.T) {
	t.Parallel()

	// An empty secret redacts too. Passing the value through unchanged when it
	// happens to be empty would make the output depend on the secret's
	// contents, which is a side channel however small.
	if got := String("").String(); got != Redacted {
		t.Errorf("String(\"\").String() = %q, want %q", got, Redacted)
	}
}

// TestSecretStringLogValueIsAString covers AC-001.26.
func TestSecretStringLogValueIsAString(t *testing.T) {
	t.Parallel()

	// slog does not consult fmt.Stringer for a string-kinded value, so the
	// LogValuer implementation is what stands between a secret and the log.
	if got := String(leakCanary).LogValue().Kind(); got != slog.KindString {
		t.Errorf("LogValue().Kind() = %v, want %v", got, slog.KindString)
	}
}

// TestSecretStringDoesNotReachAnSlogHandler covers AC-001.26.
func TestSecretStringDoesNotReachAnSlogHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("msg", "password", String(leakCanary))

	if strings.Contains(buf.String(), leakCanary) {
		t.Errorf("log output = %s, want the plaintext absent", buf.String())
	}

	if !strings.Contains(buf.String(), Redacted) {
		t.Errorf("log output = %s, want it to contain %q", buf.String(), Redacted)
	}
}

// TestSecretStringExposeReturnsThePlaintext covers AC-001.27.
func TestSecretStringExposeReturnsThePlaintext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    String
		want string
	}{
		{name: "a secret", s: String(leakCanary), want: leakCanary},
		{name: "no secret", s: String(""), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.s.Expose(); got != tt.want {
				t.Errorf("Expose() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSecretStringMarshalsAsRedactedText covers AC-001.26.
func TestSecretStringMarshalsAsRedactedText(t *testing.T) {
	t.Parallel()

	got, err := String(leakCanary).MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v, want nil", err)
	}

	if string(got) != Redacted {
		t.Errorf("MarshalText() = %q, want %q", got, Redacted)
	}
}

// TestSecretStringUnmarshalsTextVerbatim covers AC-001.28.
func TestSecretStringUnmarshalsTextVerbatim(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text []byte
		want string
	}{
		{name: "a value", text: []byte(leakCanary), want: leakCanary},
		{name: "an empty value", text: []byte(""), want: ""},
		{name: "no value at all", text: nil, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Decoding keeps the plaintext: redaction applies on the way out,
			// not on the way in, or the loaded secret would be unusable.
			var got String

			if err := got.UnmarshalText(tt.text); err != nil {
				t.Fatalf("UnmarshalText() error = %v, want nil", err)
			}

			if got.Expose() != tt.want {
				t.Errorf("Expose() after UnmarshalText = %q, want %q", got.Expose(), tt.want)
			}
		})
	}
}

// TestSecretStringMarshalsAsRedactedJSON covers AC-001.26.
func TestSecretStringMarshalsAsRedactedJSON(t *testing.T) {
	t.Parallel()

	type payload struct {
		Public string `json:"public"`
		Hidden String `json:"hidden"`
	}

	secret := String(leakCanary)

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "on its own", value: secret, want: `"` + Redacted + `"`},
		// Marshalling through a pointer must redact as well, or taking the
		// address of a secret anywhere along the way would defeat it.
		{name: "through a pointer", value: &secret, want: `"` + Redacted + `"`},
		{
			name:  "as a struct field beside a public one",
			value: payload{Public: "ok", Hidden: secret},
			want:  `{"public":"ok","hidden":"` + Redacted + `"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v, want nil", err)
			}

			if string(got) != tt.want {
				t.Errorf("json.Marshal() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestSecretStringUnmarshalsJSONStrings covers AC-001.28.
func TestSecretStringUnmarshalsJSONStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "a string", data: `"` + leakCanary + `"`, want: leakCanary},
		{name: "an empty string", data: `""`, want: ""},
		{name: "null", data: jsonNull, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Seeded with a prior value so that null is shown to clear the
			// field rather than merely leaving an already-empty one alone.
			got := String("prior")

			if err := json.Unmarshal([]byte(tt.data), &got); err != nil {
				t.Fatalf("json.Unmarshal() error = %v, want nil", err)
			}

			if got.Expose() != tt.want {
				t.Errorf("Expose() after json.Unmarshal = %q, want %q", got.Expose(), tt.want)
			}
		})
	}
}

// TestSecretStringUnmarshalsJSONIntoAStructField covers AC-001.28.
func TestSecretStringUnmarshalsJSONIntoAStructField(t *testing.T) {
	t.Parallel()

	type envelope struct {
		Public string `json:"public"`
		Token  String `json:"token"`
	}

	var got envelope

	if err := json.Unmarshal([]byte(`{"public":"ok","token":"`+leakCanary+`"}`), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v, want nil", err)
	}

	want := envelope{Public: "ok", Token: String(leakCanary)}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("decoded envelope mismatch (-want +got):\n%s", diff)
	}

	// Still redacts after decoding: the plaintext arrived, the representation
	// did not change with it.
	if got.Token.String() != Redacted {
		t.Errorf("String() after decoding = %q, want %q", got.Token.String(), Redacted)
	}
}

// TestSecretStringRejectsJSONThatIsNotAString covers AC-001.28.
func TestSecretStringRejectsJSONThatIsNotAString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{name: "a number", data: `42`},
		{name: "a boolean", data: `true`},
		{name: "an object", data: `{"nested":true}`},
		{name: "an array", data: `["a"]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var s String

			err := json.Unmarshal([]byte(tt.data), &s)
			if err == nil {
				t.Fatalf("json.Unmarshal(%s) error = nil, want a type failure", tt.data)
			}

			if !strings.Contains(err.Error(), "secret string") {
				t.Errorf("error = %q, want it to name the secret string", err)
			}

			if s.Expose() != "" {
				t.Errorf("Expose() = %q, want the secret left unset after a failure", s.Expose())
			}
		})
	}
}

// TestSecretStringWrapsMalformedJSONErrors covers AC-001.28.
func TestSecretStringWrapsMalformedJSONErrors(t *testing.T) {
	t.Parallel()

	// UnmarshalJSON is called directly: json.Unmarshal rejects a truncated
	// escape in its own scanner before any custom unmarshaler runs, so going
	// through it would not exercise this wrapping at all.
	var s String

	err := s.UnmarshalJSON([]byte(`"\u`))
	if err == nil {
		t.Fatal("UnmarshalJSON() error = nil, want a syntax failure")
	}

	if !strings.Contains(err.Error(), "secret string") {
		t.Errorf("error = %q, want it to name the secret string", err)
	}
}

// TestSecretStringSurvivesAJSONRoundTripAsRedactedText covers AC-001.26.
func TestSecretStringSurvivesAJSONRoundTripAsRedactedText(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(String(leakCanary))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v, want nil", err)
	}

	var decoded String

	if unmarshalErr := json.Unmarshal(encoded, &decoded); unmarshalErr != nil {
		t.Fatalf("json.Unmarshal() error = %v, want nil", unmarshalErr)
	}

	// The secret does not survive the round trip, by design: marshalling emits
	// the placeholder, so re-reading that output yields the placeholder. A
	// marshalled config is a report, never a source to reload from.
	if decoded.Expose() != Redacted {
		t.Errorf("Expose() after a round trip = %q, want %q", decoded.Expose(), Redacted)
	}
}
