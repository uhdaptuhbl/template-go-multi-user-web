package configtype

import (
	"fmt"
	"time"
)

// Duration is a time.Duration that reads and renders as a duration string.
//
// It is a distinct type rather than an alias because the behaviour is carried
// by the methods below, and an alias would share time.Duration's.
type Duration time.Duration

// Duration returns the underlying time.Duration, for handing to an API that
// takes one.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// String returns the duration in the form time.Duration renders, such as
// "1m30s".
func (d Duration) String() string {
	return time.Duration(d).String()
}

// UnmarshalText parses a duration string such as "30s" or "1h30m".
//
// A bare "0" is accepted because time.ParseDuration accepts it and it is the
// one unitless value with no ambiguity. Every other unitless number is
// rejected: "30" could mean seconds or milliseconds depending on who is
// reading, and guessing is how a shutdown timeout becomes thirty nanoseconds.
//
// Empty text leaves the value untouched rather than failing, because that is
// what an unset variable looks like: go-envconfig calls a decoder before it
// checks whether the value is empty, so rejecting empty would fail startup for
// every setting whose default is the zero value.
func (d *Duration) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return nil
	}

	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("parsing duration %q: %w", text, err)
	}

	*d = Duration(parsed)

	return nil
}

// MarshalText renders the duration as a string. encoding/json uses this for a
// type that is not a json.Marshaler, so it covers JSON output too.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}
