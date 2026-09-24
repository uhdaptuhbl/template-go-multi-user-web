// Package configtype provides setting types that read the way an operator
// writes them and render in units a reader can act on.
//
// A time.Duration field loaded from the environment accepts "30s", which is
// right, and then renders through encoding/json as 30000000000, which is not:
// the entry that says what configuration a process resolved is the one place
// those values are read by a human, and a nanosecond count is not a value
// anybody set. A byte count has the same problem in reverse, accepting only a
// plain integer where an operator would write 1MiB.
//
// Rendering is not quite the inverse of reading, and deliberately so. A byte
// count accepts both the binary suffixes (KiB, MiB) and the decimal ones (KB,
// MB), because both are written in the wild, but it renders only with binary
// ones: 2MB reads as 2000000 and renders as "2000000B" rather than "2MB", so
// that a rendered "2MB" can never be mistaken for the 2097152 an adjacent
// "2MiB" means. The value is preserved exactly either way; only the spelling
// is normalised. See the comment on renderUnits.
//
// Both types here fix both halves by implementing encoding.TextUnmarshaler
// and encoding.TextMarshaler. That one pair covers the environment loader,
// which looks for TextUnmarshaler, and encoding/json, which falls back to
// TextMarshaler for a type that is not a json.Marshaler. Implementing
// MarshalJSON as well would be a second way to say the same thing, and a
// second place for the two to disagree.
//
// The package deliberately depends on nothing but the standard library, so
// that any package defining settings can use it without inverting the
// dependency between itself and internal/config.
package configtype
