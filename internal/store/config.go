package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
)

// DefaultMaxConns caps pooled connections when nothing overrides it.
const DefaultMaxConns = 25

// DefaultMinConns is how many connections are kept warm when nothing
// overrides it.
const DefaultMinConns = 2

// DefaultMaxConnLifetime bounds how long a connection is reused when nothing
// overrides it.
const DefaultMaxConnLifetime = configtype.Duration(30 * time.Minute)

// DefaultMaxConnIdleTime bounds how long an unused connection is kept when
// nothing overrides it.
const DefaultMaxConnIdleTime = configtype.Duration(5 * time.Minute)

// DefaultConnectTimeout bounds the startup connection and its verifying ping
// when nothing overrides it.
const DefaultConnectTimeout = configtype.Duration(10 * time.Second)

// errDSNRequired reports that no Postgres connection string was configured.
var errDSNRequired = errors.New("store: DSN is required")

// errDSNInvalid reports that the configured connection string does not parse
// as a Postgres connection string. The message deliberately does not include
// the underlying parse error, which may otherwise echo the connection
// string's contents, including its password.
var errDSNInvalid = errors.New("store: DSN does not parse as a Postgres connection string")

// errMinConnsExceedsMaxConns reports that the pool was configured to keep
// more connections warm than it is allowed to hold at all.
var errMinConnsExceedsMaxConns = errors.New("store: MinConns must not exceed MaxConns")

// Config holds the Postgres connection string and the pool's limits.
type Config struct {
	// DSN is the Postgres connection string. It is required and has no
	// default: a service that silently starts against the wrong database is
	// worse than one that refuses to start. It is a secret because it carries
	// the database password.
	DSN secret.String `env:"DSN, overwrite" json:"dsn" validate:"required"`
	// MaxConns caps pooled connections.
	MaxConns int32 `env:"MAX_CONNS, overwrite" json:"max_conns" validate:"gt=0"`
	// MinConns is how many connections are kept warm, so a cold pool does not
	// make the first requests after a restart pay connection setup.
	MinConns int32 `env:"MIN_CONNS, overwrite" json:"min_conns" validate:"gte=0"`
	// MaxConnLifetime bounds how long a connection is reused before being
	// replaced, so a rolling database restart does not strand the pool.
	MaxConnLifetime configtype.Duration `env:"MAX_CONN_LIFETIME, overwrite" json:"max_conn_lifetime" validate:"gt=0"`
	// MaxConnIdleTime bounds how long an unused connection is kept.
	MaxConnIdleTime configtype.Duration `env:"MAX_CONN_IDLE_TIME, overwrite" json:"max_conn_idle_time" validate:"gt=0"`
	// ConnectTimeout bounds the startup connection and its verifying ping.
	ConnectTimeout configtype.Duration `env:"CONNECT_TIMEOUT, overwrite" json:"connect_timeout" validate:"gt=0"`
	// MigrateOnStart applies every pending migration before the process serves
	// traffic.
	MigrateOnStart bool `env:"MIGRATE_ON_START, overwrite" json:"migrate_on_start"`
}

// DefaultConfig returns a Config with an empty DSN and pool limits sized for
// an ordinary deployment. The empty DSN is deliberate: see the field's doc
// comment.
func DefaultConfig() Config {
	return Config{
		DSN:             "",
		MaxConns:        DefaultMaxConns,
		MinConns:        DefaultMinConns,
		MaxConnLifetime: DefaultMaxConnLifetime,
		MaxConnIdleTime: DefaultMaxConnIdleTime,
		ConnectTimeout:  DefaultConnectTimeout,
		MigrateOnStart:  true,
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

	switch {
	case c.DSN.Expose() == "":
		errs = append(errs, errDSNRequired)
	case !dsnParses(c.DSN.Expose()):
		errs = append(errs, errDSNInvalid)
	}

	if c.MinConns > c.MaxConns {
		errs = append(errs, errMinConnsExceedsMaxConns)
	}

	return errors.Join(errs...)
}

// dsnParses reports whether dsn parses as a Postgres connection string. It
// discards the underlying parse error rather than returning it, because that
// error may otherwise echo the connection string's contents, including its
// password.
func dsnParses(dsn string) bool {
	_, err := pgxpool.ParseConfig(dsn)

	return err == nil
}
