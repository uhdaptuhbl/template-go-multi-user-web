package configtype

import (
	"encoding/json"
	"testing"
	"time"
)

// TestDurationReadsWhatAnOperatorWrites covers AC-001.1.
func TestDurationReadsWhatAnOperatorWrites(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want time.Duration
	}{
		{name: "seconds", text: "30s", want: 30 * time.Second},
		{name: "minutes", text: "2m", want: 2 * time.Minute},
		{name: "compound", text: "1h30m", want: 90 * time.Minute},
		{name: "milliseconds", text: "250ms", want: 250 * time.Millisecond},
		{name: "zero", text: "0s", want: 0},
		{name: "bare zero", text: "0", want: 0},
		{name: "negative", text: "-1s", want: -time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var got Duration

			if err := got.UnmarshalText([]byte(test.text)); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v, want nil", test.text, err)
			}

			if got.Duration() != test.want {
				t.Errorf("UnmarshalText(%q) = %v, want %v", test.text, got.Duration(), test.want)
			}
		})
	}
}

// TestDurationRejectsWhatIsNotADuration covers AC-001.2.
func TestDurationRejectsWhatIsNotADuration(t *testing.T) {
	t.Parallel()

	// Empty text is not in this list. It is not a malformed value but the
	// shape of an unset variable; see TestEmptyTextLeavesTheValueAlone.
	for _, text := range []string{"thirty", "30", "30 s", "s30"} {
		t.Run(text, func(t *testing.T) {
			t.Parallel()

			var got Duration

			if err := got.UnmarshalText([]byte(text)); err == nil {
				t.Errorf("UnmarshalText(%q) error = nil, want a failure", text)
			}
		})
	}
}

// TestDurationRendersAsADurationString covers AC-002.24.
func TestDurationRendersAsADurationString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   Duration
		want string
	}{
		{name: "seconds", in: Duration(30 * time.Second), want: `"30s"`},
		{name: "minutes", in: Duration(2 * time.Minute), want: `"2m0s"`},
		{name: "zero", in: 0, want: `"0s"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(test.in)
			if err != nil {
				t.Fatalf("json.Marshal error = %v, want nil", err)
			}

			if string(got) != test.want {
				t.Errorf("json.Marshal(%v) = %s, want %s", time.Duration(test.in), got, test.want)
			}
		})
	}
}

// TestByteSizeReadsWhatAnOperatorWrites covers AC-001.1.
func TestByteSizeReadsWhatAnOperatorWrites(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want int64
	}{
		{name: "plain count", text: "1048576", want: 1 << 20},
		{name: "zero", text: "0", want: 0},
		{name: "binary kibibytes", text: "64KiB", want: 64 << 10},
		{name: "binary mebibytes", text: "1MiB", want: 1 << 20},
		{name: "binary gibibytes", text: "2GiB", want: 2 << 30},
		{name: "decimal kilobytes", text: "1KB", want: 1000},
		{name: "decimal megabytes", text: "2MB", want: 2_000_000},
		{name: "lowercase suffix", text: "1mib", want: 1 << 20},
		{name: "space before the suffix", text: "1 MiB", want: 1 << 20},
		{name: "bare bytes suffix", text: "512B", want: 512},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var got ByteSize

			if err := got.UnmarshalText([]byte(test.text)); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v, want nil", test.text, err)
			}

			if got.Bytes() != test.want {
				t.Errorf("UnmarshalText(%q) = %d, want %d", test.text, got.Bytes(), test.want)
			}
		})
	}
}

// TestByteSizeRejectsWhatIsNotASize covers AC-001.2.
func TestByteSizeRejectsWhatIsNotASize(t *testing.T) {
	t.Parallel()

	// Empty text is not in this list. It is not a malformed value but the
	// shape of an unset variable; see TestEmptyTextLeavesTheValueAlone.
	for _, text := range []string{"big", "1XiB", "1.5MiB", "MiB", "1MiB2"} {
		t.Run(text, func(t *testing.T) {
			t.Parallel()

			var got ByteSize

			if err := got.UnmarshalText([]byte(text)); err == nil {
				t.Errorf("UnmarshalText(%q) error = nil, want a failure", text)
			}
		})
	}
}

// TestByteSizeRejectsASizeThatOverflows covers AC-001.2.
//
// Regression test. The multiplication by the unit was unchecked, so a count
// large enough to pass the digit parse silently wrapped: "9223372036854775807TiB"
// became -1TiB, and "12582912TiB" a number that was not the one
// written. A limit that is not the number the operator wrote is exactly what
// UnmarshalText refuses to produce for "1.5MiB", and the same refusal belongs
// here.
func TestByteSizeRejectsASizeThatOverflows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
	}{
		{name: "wraps to a negative size", text: "9223372036854775807TiB"},
		{name: "wraps to a size that was not written", text: "12582912TiB"},
		{name: "exactly one past the maximum", text: "8388608TiB"},
		{name: "wraps to zero", text: "16777216TiB"},
		{name: "negative and wrapping", text: "-9223372036854775808TiB"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var got ByteSize

			if err := got.UnmarshalText([]byte(test.text)); err == nil {
				t.Errorf("UnmarshalText(%q) = %d with a nil error, want a failure", test.text, got.Bytes())
			}
		})
	}
}

// TestByteSizeAcceptsTheLargestSizeThatFits covers AC-001.2.
//
// The boundary on the other side of the test above: the overflow check must
// not reject a value that does fit.
func TestByteSizeAcceptsTheLargestSizeThatFits(t *testing.T) {
	t.Parallel()

	var got ByteSize

	if err := got.UnmarshalText([]byte("8388607TiB")); err != nil {
		t.Fatalf("UnmarshalText error = %v, want nil", err)
	}

	if want := ByteSize(8388607) * (1 << 40); got != want {
		t.Errorf("UnmarshalText(\"8388607TiB\") = %d, want %d", got.Bytes(), want.Bytes())
	}
}

// TestByteSizeRendersWithASuffixWhenItIsExact covers AC-002.24.
func TestByteSizeRendersWithASuffixWhenItIsExact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   ByteSize
		want string
	}{
		{name: "mebibyte", in: 1 << 20, want: `"1MiB"`},
		{name: "kibibyte", in: 64 << 10, want: `"64KiB"`},
		{name: "gibibyte", in: 3 << 30, want: `"3GiB"`},
		{name: "zero", in: 0, want: `"0B"`},
		{name: "not a whole unit", in: 1500, want: `"1500B"`},
		{name: "negative", in: -1, want: `"-1B"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(test.in)
			if err != nil {
				t.Fatalf("json.Marshal error = %v, want nil", err)
			}

			if string(got) != test.want {
				t.Errorf("json.Marshal(%d) = %s, want %s", int64(test.in), got, test.want)
			}
		})
	}
}

// TestBothTypesSurviveAJSONRoundTrip covers AC-002.24.
func TestBothTypesSurviveAJSONRoundTrip(t *testing.T) {
	t.Parallel()

	type settings struct {
		Timeout Duration `json:"timeout"`
		MaxBody ByteSize `json:"max_body"`
	}

	want := settings{Timeout: Duration(90 * time.Second), MaxBody: 4 << 20}

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal error = %v, want nil", err)
	}

	if string(encoded) != `{"timeout":"1m30s","max_body":"4MiB"}` {
		t.Errorf("encoded as %s", encoded)
	}

	var got settings

	if unmarshalErr := json.Unmarshal(encoded, &got); unmarshalErr != nil {
		t.Fatalf("json.Unmarshal error = %v, want nil", unmarshalErr)
	}

	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

// TestEmptyTextLeavesTheValueAlone covers AC-001.3.
//
// go-envconfig hands a decoder the empty string when the variable is unset and
// the field is still at its zero value, deliberately, so that a decoder may
// treat empty as a special case (envconfig.go, processField: "We don't check if
// the value is empty earlier, because the user might want to define a custom
// decoder and treat the empty variable as a special case"). Both types must
// therefore read an empty input as "nothing was configured" rather than as a
// malformed value, or every zero-defaulted setting fails at startup.
func TestEmptyTextLeavesTheValueAlone(t *testing.T) {
	t.Parallel()

	t.Run("duration", func(t *testing.T) {
		t.Parallel()

		got := Duration(90 * time.Second)

		if err := got.UnmarshalText(nil); err != nil {
			t.Fatalf("UnmarshalText(nil) error = %v, want nil", err)
		}

		if got != Duration(90*time.Second) {
			t.Errorf("UnmarshalText(nil) changed the value to %v", got)
		}
	})

	t.Run("byte size", func(t *testing.T) {
		t.Parallel()

		got := ByteSize(1 << 20)

		if err := got.UnmarshalText([]byte("")); err != nil {
			t.Fatalf("UnmarshalText(\"\") error = %v, want nil", err)
		}

		if got != ByteSize(1<<20) {
			t.Errorf("UnmarshalText(\"\") changed the value to %v", got)
		}
	})
}
