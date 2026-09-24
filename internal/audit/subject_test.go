package audit

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mustParseTime parses s as RFC 3339 with nanoseconds, failing t on error.
func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()

	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("time.Parse(%q) error = %v", s, err)
	}

	return parsed
}

// mustParseUUID parses s as a UUID, failing t on error.
func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()

	parsed, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("uuid.Parse(%q) error = %v", s, err)
	}

	return parsed
}

// TestValidateSubjectRestrictsKinds covers AC-008.39: validateSubject accepts
// only the permitted "<kind>:<value>" subjects and rejects everything else,
// including a kind not on the permitted list.
func TestValidateSubjectRestrictsKinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject string
		wantErr bool
	}{
		{name: "user kind", subject: "user:abc", wantErr: false},
		{name: "email kind", subject: "email:abc", wantErr: false},
		{name: "provider kind", subject: "provider:abc", wantErr: false},
		{name: "settings kind", subject: "settings:abc", wantErr: false},
		{name: "invite kind", subject: "invite:abc", wantErr: false},
		{name: "session kind", subject: "session:abc", wantErr: false},
		{name: "credential kind", subject: "credential:abc", wantErr: false},
		{name: "identity kind", subject: "identity:abc", wantErr: false},
		{name: "anonymous kind", subject: "anonymous:abc", wantErr: false},
		{name: "unpermitted kind", subject: "bogus:x", wantErr: true},
		{name: "no colon", subject: "user", wantErr: true},
		{name: "empty value", subject: "user:", wantErr: true},
		{name: "empty kind", subject: ":x", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateSubject(tt.subject)

			if tt.wantErr && !errors.Is(err, ErrMalformedSubject) {
				t.Errorf("validateSubject(%q) error = %v, want ErrMalformedSubject", tt.subject, err)
			}

			if !tt.wantErr && err != nil {
				t.Errorf("validateSubject(%q) error = %v, want nil", tt.subject, err)
			}
		})
	}
}

// TestParseCursorRoundTripAndRejectsGarbage covers AC-008.49: ParseCursor
// decodes exactly what Cursor.String encoded, and returns ErrInvalidCursor
// for anything else.
func TestParseCursorRoundTripAndRejectsGarbage(t *testing.T) {
	t.Parallel()

	t.Run("round trips through String", func(t *testing.T) {
		t.Parallel()

		want := Cursor{OccurredAt: mustParseTime(t, "2026-01-02T03:04:05.123456789Z"), ID: mustParseUUID(t, "018e0000-0000-7000-8000-000000000001")}

		got, err := ParseCursor(want.String())
		if err != nil {
			t.Fatalf("ParseCursor(%q) error = %v, want nil", want.String(), err)
		}

		if !got.OccurredAt.Equal(want.OccurredAt) || got.ID != want.ID {
			t.Errorf("ParseCursor(%q) = %+v, want %+v", want.String(), got, want)
		}
	})

	t.Run("rejects garbage", func(t *testing.T) {
		t.Parallel()

		tests := []string{
			"",
			"not-a-cursor",
			"2026-01-02T03:04:05Z",
			"2026-01-02T03:04:05Z_not-a-uuid",
			"not-a-timestamp_018e0000-0000-7000-8000-000000000001",
		}

		for _, garbage := range tests {
			if _, err := ParseCursor(garbage); !errors.Is(err, ErrInvalidCursor) {
				t.Errorf("ParseCursor(%q) error = %v, want ErrInvalidCursor", garbage, err)
			}
		}
	})
}
