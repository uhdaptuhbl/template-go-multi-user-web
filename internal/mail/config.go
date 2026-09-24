package mail

import (
	"context"
	"errors"
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
)

// DefaultPort is the SMTP submission port used when nothing overrides it.
const DefaultPort = 587

// DefaultTLSPolicy is the transport policy used when nothing overrides it.
// starttls is the ordinary choice for the submission port.
const DefaultTLSPolicy = "starttls"

// DefaultTimeout bounds a single send when nothing overrides it.
const DefaultTimeout = configtype.Duration(10 * time.Second)

// errMailEnabledWithoutHost reports that mail is enabled but no SMTP host is
// configured to send through.
var errMailEnabledWithoutHost = errors.New("mail: enabled but no host is configured")

// errMailEnabledWithoutFrom reports that mail is enabled but no sender
// address is configured to send from.
var errMailEnabledWithoutFrom = errors.New("mail: enabled but no from address is configured")

// Config holds the SMTP endpoint, credentials, and transport policy used to
// deliver mail.
type Config struct {
	// Enabled controls whether mail can be sent at all. It defaults to false
	// so a deployment with no mail server configured is inert rather than
	// failing at the first send.
	Enabled bool `env:"ENABLED, overwrite" json:"enabled"`
	// Host is the SMTP server's hostname.
	Host string `env:"HOST, overwrite" json:"host"`
	// Port is the SMTP server's port.
	Port int `env:"PORT, overwrite" json:"port" validate:"gt=0,lte=65535"`
	// Username authenticates to the SMTP server. An empty value sends
	// unauthenticated.
	Username string `env:"USERNAME, overwrite" json:"username"`
	// Password authenticates to the SMTP server.
	Password secret.String `env:"PASSWORD, overwrite" json:"password"`
	// From is the envelope and header sender address.
	From string `env:"FROM, overwrite" json:"from" validate:"omitempty,email"`
	// TLSPolicy selects how the connection is secured: starttls upgrades a
	// plaintext connection, tls connects with TLS from the first byte, and
	// none sends in the clear and is intended only for a local test relay.
	TLSPolicy string `env:"TLS_POLICY, overwrite" json:"tls_policy" validate:"required,oneof=starttls tls none"`
	// Timeout bounds a single send.
	Timeout configtype.Duration `env:"TIMEOUT, overwrite" json:"timeout" validate:"gt=0"`
}

// DefaultConfig returns a Config that is disabled and otherwise holds the
// settings a complete configuration would need: the submission port, the
// starttls policy, and a ten second send timeout.
func DefaultConfig() Config {
	return Config{
		Enabled:   false,
		Host:      "",
		Port:      DefaultPort,
		Username:  "",
		Password:  "",
		From:      "",
		TLSPolicy: DefaultTLSPolicy,
		Timeout:   DefaultTimeout,
	}
}

// Validate reports the cross-field problems the struct tags cannot express: a
// sender that is enabled needs both a host and a from address.
//
// It is the CustomValidator hook internal/config's Decode calls on this
// field once it is composed. That interface is Validate(ctx
// context.Context) error, looked up on the addressable field, so the
// receiver must be a pointer and the parameter must be present even
// though nothing here reads it: a Validate() error would satisfy nothing
// and would simply never be called.
func (c *Config) Validate(_ context.Context) error {
	if !c.Enabled {
		return nil
	}

	errs := make([]error, 0, 2)

	if c.Host == "" {
		errs = append(errs, errMailEnabledWithoutHost)
	}

	if c.From == "" {
		errs = append(errs, errMailEnabledWithoutFrom)
	}

	return errors.Join(errs...)
}
