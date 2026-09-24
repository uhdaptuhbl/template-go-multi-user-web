package configtype

import (
	"fmt"
	"strconv"
	"strings"
)

// ByteSize is a count of bytes that reads and renders with a unit suffix.
type ByteSize int64

// byteUnits maps each accepted suffix to its multiplier. Both the binary
// (IEC) and decimal (SI) families are accepted, because both are written in
// the wild and silently treating one as the other is a 4.9% error that nobody
// notices until a limit is the wrong limit.
var byteUnits = map[string]int64{
	"b":   1,
	"kib": 1 << 10,
	"mib": 1 << 20,
	"gib": 1 << 30,
	"tib": 1 << 40,
	"kb":  1_000,
	"mb":  1_000_000,
	"gb":  1_000_000_000,
	"tb":  1_000_000_000_000,
}

// renderUnits are the suffixes a value is rendered with, largest first. Only
// the binary family: a value is rendered with a suffix only when it is an
// exact multiple, and rendering 1000000 as "1MB" while 1048576 also renders
// with an M would make the two indistinguishable at a glance.
var renderUnits = []struct {
	suffix string
	size   int64
}{
	{suffix: "TiB", size: 1 << 40},
	{suffix: "GiB", size: 1 << 30},
	{suffix: "MiB", size: 1 << 20},
	{suffix: "KiB", size: 1 << 10},
}

// Bytes returns the count as an int64, for handing to an API that takes one.
func (b ByteSize) Bytes() int64 {
	return int64(b)
}

// String renders the count with the largest binary suffix it is an exact
// multiple of, and with a plain "B" otherwise, so no rendering ever loses
// precision.
func (b ByteSize) String() string {
	for _, unit := range renderUnits {
		if b != 0 && int64(b)%unit.size == 0 {
			return strconv.FormatInt(int64(b)/unit.size, 10) + unit.suffix
		}
	}

	return strconv.FormatInt(int64(b), 10) + "B"
}

// UnmarshalText parses a byte count, with or without a unit suffix: "1048576",
// "1MiB", and "1 MiB" are the same value, and the suffix is case-insensitive.
//
// Only whole numbers are accepted, and only counts that still fit in an int64
// once the unit is applied. "1.5MiB" is rejected rather than rounded and
// "9223372036854775807TiB" rejected rather than wrapped, because a limit that
// is not the number the operator wrote is worse than a startup failure naming
// the line to fix.
//
// Empty text leaves the value untouched rather than failing, for the reason
// given on Duration.UnmarshalText.
func (b *ByteSize) UnmarshalText(text []byte) error {
	trimmed := strings.TrimSpace(string(text))
	if trimmed == "" {
		return nil
	}

	digits := strings.TrimRight(trimmed, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ")

	count, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing byte size %q: %w", text, err)
	}

	suffix := strings.ToLower(strings.TrimSpace(trimmed[len(digits):]))
	if suffix == "" {
		*b = ByteSize(count)

		return nil
	}

	multiplier, ok := byteUnits[suffix]
	if !ok {
		return fmt.Errorf("parsing byte size %q: unknown unit %q", text, suffix)
	}

	// The digits parsed as an int64 on their own, which says nothing about
	// whether they still fit once multiplied by the unit. Unchecked, the
	// product wraps: "9223372036854775807TiB" becomes -1TiB, and a limit that
	// is not the number the operator wrote is what this function refuses to
	// produce for "1.5MiB". The division is exact on both signs, so it
	// answers the question without a second multiplication that could wrap.
	scaled := count * multiplier
	if scaled/multiplier != count {
		return fmt.Errorf("parsing byte size %q: %d%s does not fit in an int64", text, count, suffix)
	}

	*b = ByteSize(scaled)

	return nil
}

// MarshalText renders the count as a string. encoding/json uses this for a
// type that is not a json.Marshaler, so it covers JSON output too.
func (b ByteSize) MarshalText() ([]byte, error) {
	return []byte(b.String()), nil
}
