package session

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// DefaultCookieName is the session cookie's name. The __Host- prefix makes a
// browser reject the cookie unless it is Secure, has Path=/, and carries no
// Domain, which removes an entire class of subdomain cookie-fixation attacks.
const DefaultCookieName = "__Host-service_session"

// DefaultIdleTimeout bounds how long a session survives without being used
// when nothing overrides it.
const DefaultIdleTimeout = configtype.Duration(720 * time.Hour)

// DefaultAbsoluteTimeout bounds a session's hard lifetime when nothing
// overrides it.
const DefaultAbsoluteTimeout = configtype.Duration(2160 * time.Hour)

// DefaultCleanupInterval is how often expired sessions are swept when nothing
// overrides it.
const DefaultCleanupInterval = configtype.Duration(time.Hour)

// hostCookiePrefix is the prefix that requires Secure, Path=/, and no Domain
// from a browser before it will store the cookie.
const hostCookiePrefix = "__Host-"

// errHostCookieRequiresSecure reports that a cookie name carrying the
// __Host- prefix was configured with CookieSecure false. A browser silently
// drops such a cookie, so every login would appear to succeed and then fail.
var errHostCookieRequiresSecure = errors.New("session: cookie name uses the __Host- prefix but CookieSecure is false")

// errIdleTimeoutExceedsAbsoluteTimeout reports that IdleTimeout is longer
// than AbsoluteTimeout, which would make the idle expiry unreachable.
var errIdleTimeoutExceedsAbsoluteTimeout = errors.New("session: IdleTimeout exceeds AbsoluteTimeout")

// Config holds the session cookie's identity and the two independent expiries
// a session is subject to.
type Config struct {
	// CookieName is the session cookie's name.
	CookieName string `env:"COOKIE_NAME, overwrite" json:"cookie_name" validate:"required"`
	// CookieSecure sets the Secure attribute. It is false only for local
	// development over plain HTTP; every real deployment sits behind a
	// TLS-terminating proxy.
	CookieSecure bool `env:"COOKIE_SECURE, overwrite" json:"cookie_secure"`
	// IdleTimeout is how long a session survives without being used. It
	// advances on every authenticated request.
	IdleTimeout configtype.Duration `env:"IDLE_TIMEOUT, overwrite" json:"idle_timeout" validate:"gt=0"`
	// AbsoluteTimeout is the session's hard lifetime. It never advances, so a
	// continuously active session still ends.
	AbsoluteTimeout configtype.Duration `env:"ABSOLUTE_TIMEOUT, overwrite" json:"absolute_timeout" validate:"gt=0"`
	// CleanupInterval is how often expired sessions, ceremony state, and
	// one-time codes are swept from the database.
	CleanupInterval configtype.Duration `env:"CLEANUP_INTERVAL, overwrite" json:"cleanup_interval" validate:"gt=0"`
}

// DefaultConfig returns a Config with the standard cookie name, Secure
// enabled, a thirty day idle timeout, a ninety day absolute timeout, and an
// hourly cleanup sweep.
func DefaultConfig() Config {
	return Config{
		CookieName:      DefaultCookieName,
		CookieSecure:    true,
		IdleTimeout:     DefaultIdleTimeout,
		AbsoluteTimeout: DefaultAbsoluteTimeout,
		CleanupInterval: DefaultCleanupInterval,
	}
}

// Validate reports the cross-field problems the struct tags cannot express.
//
// It is the CustomValidator hook internal/config's Decode calls on this
// field once it is composed. That interface is Validate(ctx
// context.Context) error, looked up on the addressable field, so the
// receiver must be a pointer and the parameter must be present even
// though nothing here reads it: a Validate() error would satisfy nothing
// and would simply never be called.
func (c *Config) Validate(_ context.Context) error {
	errs := make([]error, 0, 2)

	if strings.HasPrefix(c.CookieName, hostCookiePrefix) && !c.CookieSecure {
		errs = append(errs, errHostCookieRequiresSecure)
	}

	if c.IdleTimeout.Duration() > c.AbsoluteTimeout.Duration() {
		errs = append(errs, errIdleTimeoutExceedsAbsoluteTimeout)
	}

	return errors.Join(errs...)
}
