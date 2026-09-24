package otp

import (
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// Config holds whether the email code path is available and the limits a code
// is subject to.
type Config struct {
	// Enabled registers the email code routes. It defaults to false, so a
	// deployment with no mail sender configured does not advertise a login
	// method that cannot work.
	Enabled bool `json:"enabled"`
	// CodeTTL is how long an emailed code remains valid.
	CodeTTL configtype.Duration `json:"code_ttl"`
	// MaxAttempts is the number of wrong guesses that invalidates a code:
	// the guess that brings the count to MaxAttempts invalidates it, so a
	// code allows at most MaxAttempts guesses in total.
	MaxAttempts int `json:"max_attempts"`
}

// DefaultConfig returns a Config with the email code path disabled, a ten
// minute code lifetime, and a code invalidated by its fifth wrong guess.
func DefaultConfig() Config {
	return Config{
		Enabled:     false,
		CodeTTL:     configtype.Duration(10 * time.Minute),
		MaxAttempts: 5,
	}
}
