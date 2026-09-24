package secret

import (
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
)

// Redacted is the placeholder text substituted for a secret value in every
// string, log and JSON representation of String.
const Redacted = "[REDACTED]"

// jsonNull is the JSON literal for an absent value. Decoding it clears the
// secret rather than storing the four characters.
const jsonNull = "null"

// String holds a sensitive value loaded from configuration. It always
// redacts in string and slog representations; use Expose when passing the raw
// value into APIs that need a plain string (see Expose godoc).
//
// The value and pointer receivers below are intentional: reading a secret must
// work on a value, while unmarshalling into one needs a pointer.
//
// Every credential-bearing setting is declared with it: store.Config's DSN,
// mail.Config's Password, and oidc.ProviderConfig's ClientSecret. A package
// whose settings internal/config composes imports this package directly,
// because internal/config imports that package and cannot be imported back.
// It uses the type like any other field type,
//
//	type Config struct {
//		DSN secret.String `env:"DSN, overwrite" json:"dsn" validate:"required"`
//	}
//
// and every renderer of the composed configuration -- LogEffective, JSON
// encoding, fmt verbs, slog -- then redacts it with nothing further to write.
type String string

// Compile-time checks that redaction and JSON contracts stay wired.
var _ fmt.Stringer = String("")
var _ fmt.GoStringer = String("")
var _ slog.LogValuer = String("")
var _ encoding.TextMarshaler = String("")
var _ encoding.TextUnmarshaler = (*String)(nil)
var _ json.Marshaler = String("")
var _ json.Unmarshaler = (*String)(nil)

// Expose returns the underlying secret for constructors, drivers, and other
// call sites that require the real value. Never log the return value.
//
// Expose is not required by any standard interface. It is an explicit,
// grep-friendly escape hatch so that a review can tell an intentional use of
// the plaintext value from an accidental one. Because the underlying type is
// string, callers could also write string(s); prefer Expose for clarity.
// See docs/adr/0006-configuration-loading.md.
func (s String) Expose() string {
	return string(s)
}

// String implements fmt.Stringer and always returns a redacted placeholder so
// accidental use with fmt or legacy string-based loggers does not leak secrets.
func (String) String() string {
	return Redacted
}

// GoString implements fmt.GoStringer and returns the quoted placeholder, so
// the %#v verb, which does not consult fmt.Stringer, redacts too. That verb
// is the one a debugging dump of a whole configuration struct reaches for.
func (String) GoString() string {
	return strconv.Quote(Redacted)
}

// LogValue implements slog.LogValuer so structured loggers record a redacted value.
func (String) LogValue() slog.Value {
	return slog.StringValue(Redacted)
}

// MarshalText implements encoding.TextMarshaler so go-envconfig (and
// other plain-text encoders) can encode secrets as raw strings without JSON
// quoting.
func (String) MarshalText() ([]byte, error) {
	return []byte(Redacted), nil
}

// UnmarshalText implements encoding.TextUnmarshaler so go-envconfig (and
// other plain-text decoders) can populate secrets from raw env values without
// JSON quoting.
func (s *String) UnmarshalText(text []byte) error {
	*s = String(text)
	return nil
}

// MarshalJSON always encodes the redacted placeholder so JSON payloads and
// logs never leak the secret.
func (String) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // this doesn't need to wrap the error.
	return json.Marshal(Redacted)
}

// UnmarshalJSON decodes a JSON string into the secret (for example config
// files or API bodies). It does not accept non-string JSON kinds.
func (s *String) UnmarshalJSON(data []byte) error {
	if string(data) == jsonNull {
		*s = ""
		return nil
	}
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("secret string: %w", err)
	}
	*s = String(v)
	return nil
}
