// Package authflow holds short-lived, single-use, server-side state for
// multi-request authentication ceremonies. Consumption is atomic, so a
// replayed identifier finds nothing.
package authflow
