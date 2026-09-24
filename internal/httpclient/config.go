package httpclient

import (
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// DefaultTimeout bounds a whole request, from dial to the last byte of the
// response body. It matches the application listener's write timeout, so an
// outbound call cannot by default outlive the inbound request that caused it.
const DefaultTimeout = configtype.Duration(30 * time.Second)

// DefaultConnectTimeout bounds establishing a TCP connection.
const DefaultConnectTimeout = configtype.Duration(5 * time.Second)

// DefaultTLSHandshakeTimeout bounds completing a TLS handshake.
const DefaultTLSHandshakeTimeout = configtype.Duration(5 * time.Second)

// DefaultResponseHeaderTimeout bounds waiting for a peer's response headers
// after the request has been written.
const DefaultResponseHeaderTimeout = configtype.Duration(5 * time.Second)

// DefaultMaxConnsPerHost caps connections to one host, counting active and
// idle together. net/http leaves this unbounded, which lets one slow peer open
// as many connections as the service has goroutines wanting them.
const DefaultMaxConnsPerHost = 100

// DefaultMaxIdleConns caps idle connections held across all hosts. It is
// net/http's own default.
const DefaultMaxIdleConns = 100

// DefaultMaxIdleConnsPerHost caps idle connections held per host. net/http
// holds 2, which makes a busy caller reconnect constantly for no benefit when
// the client talks to one host by design.
const DefaultMaxIdleConnsPerHost = 10

// DefaultIdleConnTimeout bounds how long an idle connection is kept before it
// is closed. It is net/http's own default.
const DefaultIdleConnTimeout = configtype.Duration(90 * time.Second)

// Config holds one outbound dependency's timeouts and pool limits.
//
// It is per dependency rather than per process: the right pool size and the
// right patience are properties of the peer being called, and a service that
// calls two of them wants two of these.
//
// The env tags carry no prefix of their own, the way server.Config's do not,
// so the struct composing this one decides what the variables are called and
// a service with two dependencies gets two distinct sets.
type Config struct {
	// Timeout bounds the whole request, including reading the response body.
	// It is the only bound that covers a peer which answers promptly and then
	// streams a body slowly forever.
	Timeout configtype.Duration `env:"TIMEOUT, overwrite" json:"timeout" validate:"gt=0"`
	// ConnectTimeout bounds establishing the TCP connection. Separate from the
	// timeouts below so that "cannot reach the peer" and "the peer is slow"
	// are distinguishable in what fails.
	ConnectTimeout configtype.Duration `env:"CONNECT_TIMEOUT, overwrite" json:"connect_timeout" validate:"gt=0"`
	// TLSHandshakeTimeout bounds completing the TLS handshake.
	TLSHandshakeTimeout configtype.Duration `env:"TLS_HANDSHAKE_TIMEOUT, overwrite" json:"tls_handshake_timeout" validate:"gt=0"`
	// ResponseHeaderTimeout bounds waiting for response headers once the
	// request has been written.
	ResponseHeaderTimeout configtype.Duration `env:"RESPONSE_HEADER_TIMEOUT, overwrite" json:"response_header_timeout" validate:"gt=0"`
	// MaxConnsPerHost caps active and idle connections to one host together.
	MaxConnsPerHost int `env:"MAX_CONNS_PER_HOST, overwrite" json:"max_conns_per_host" validate:"gte=0"`
	// MaxIdleConns caps idle connections held across every host.
	MaxIdleConns int `env:"MAX_IDLE_CONNS, overwrite" json:"max_idle_conns" validate:"gte=0"`
	// MaxIdleConnsPerHost caps idle connections held per host.
	MaxIdleConnsPerHost int `env:"MAX_IDLE_CONNS_PER_HOST, overwrite" json:"max_idle_conns_per_host" validate:"gte=0"`
	// IdleConnTimeout bounds how long an idle connection is kept.
	IdleConnTimeout configtype.Duration `env:"IDLE_CONN_TIMEOUT, overwrite" json:"idle_conn_timeout" validate:"gt=0"`
}

// Default returns the settings a client is built with when nothing overrides
// them: patient enough for an ordinary call across a datacenter, impatient
// enough that a peer which has stopped answering is given up on.
func Default() Config {
	return Config{
		Timeout:               DefaultTimeout,
		ConnectTimeout:        DefaultConnectTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
		MaxConnsPerHost:       DefaultMaxConnsPerHost,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:       DefaultIdleConnTimeout,
	}
}
