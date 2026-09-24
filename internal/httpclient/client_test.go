package httpclient

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// TestNewAppliesTheTotalTimeout covers AC-006.1.
func TestNewAppliesTheTotalTimeout(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Timeout = configtype.Duration(7 * time.Second)

	client, err := New(cfg, Telemetry{})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	if client.Timeout != 7*time.Second {
		t.Errorf("Timeout is %v, want %v", client.Timeout, 7*time.Second)
	}
}

// TestNewAppliesEveryPhaseTimeoutAndPoolLimit covers AC-006.2 and AC-006.7.
func TestNewAppliesEveryPhaseTimeoutAndPoolLimit(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Timeout:               configtype.Duration(30 * time.Second),
		ConnectTimeout:        configtype.Duration(1 * time.Second),
		TLSHandshakeTimeout:   configtype.Duration(2 * time.Second),
		ResponseHeaderTimeout: configtype.Duration(3 * time.Second),
		MaxConnsPerHost:       11,
		MaxIdleConns:          12,
		MaxIdleConnsPerHost:   13,
		IdleConnTimeout:       configtype.Duration(4 * time.Second),
	}

	transport, err := newTransport(cfg)
	if err != nil {
		t.Fatalf("newTransport error = %v, want nil", err)
	}

	durations := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{name: "TLSHandshakeTimeout", got: transport.TLSHandshakeTimeout, want: 2 * time.Second},
		{name: "ResponseHeaderTimeout", got: transport.ResponseHeaderTimeout, want: 3 * time.Second},
		{name: "IdleConnTimeout", got: transport.IdleConnTimeout, want: 4 * time.Second},
	}

	for _, test := range durations {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.got != test.want {
				t.Errorf("%s is %v, want %v", test.name, test.got, test.want)
			}
		})
	}

	counts := []struct {
		name string
		got  int
		want int
	}{
		{name: "MaxConnsPerHost", got: transport.MaxConnsPerHost, want: 11},
		{name: "MaxIdleConns", got: transport.MaxIdleConns, want: 12},
		{name: "MaxIdleConnsPerHost", got: transport.MaxIdleConnsPerHost, want: 13},
	}

	for _, test := range counts {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.got != test.want {
				t.Errorf("%s is %d, want %d", test.name, test.got, test.want)
			}
		})
	}
}

// TestNewGivesEachClientItsOwnPool covers AC-006.6.
func TestNewGivesEachClientItsOwnPool(t *testing.T) {
	t.Parallel()

	first, err := New(Default(), Telemetry{})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	second, err := New(Default(), Telemetry{})
	if err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}

	if first.Transport == second.Transport {
		t.Error("two clients share one transport: a pool exhausted by one dependency would starve the other")
	}

	if first.Transport == http.DefaultTransport {
		t.Error("the client uses http.DefaultTransport: its pool is shared with every other user of the standard library in this process")
	}
}

// TestNewRejectsSettingsThatCannotBeMeant covers AC-006.5 and AC-006.9.
func TestNewRejectsSettingsThatCannotBeMeant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		spoil func(*Config)
		field string
	}{
		{name: "zero total timeout", spoil: func(c *Config) { c.Timeout = 0 }, field: "Timeout"},
		{name: "negative total timeout", spoil: func(c *Config) { c.Timeout = -1 }, field: "Timeout"},
		{name: "zero connect timeout", spoil: func(c *Config) { c.ConnectTimeout = 0 }, field: "ConnectTimeout"},
		{name: "zero TLS handshake timeout", spoil: func(c *Config) { c.TLSHandshakeTimeout = 0 }, field: "TLSHandshakeTimeout"},
		{name: "zero response header timeout", spoil: func(c *Config) { c.ResponseHeaderTimeout = 0 }, field: "ResponseHeaderTimeout"},
		{name: "zero idle connection timeout", spoil: func(c *Config) { c.IdleConnTimeout = 0 }, field: "IdleConnTimeout"},
		{name: "negative connections per host", spoil: func(c *Config) { c.MaxConnsPerHost = -1 }, field: "MaxConnsPerHost"},
		{name: "negative idle connections", spoil: func(c *Config) { c.MaxIdleConns = -1 }, field: "MaxIdleConns"},
		{name: "negative idle connections per host", spoil: func(c *Config) { c.MaxIdleConnsPerHost = -1 }, field: "MaxIdleConnsPerHost"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := Default()
			test.spoil(&cfg)

			client, err := New(cfg, Telemetry{})
			if err == nil {
				t.Fatalf("New error = nil, want a failure naming %s", test.field)
			}

			if client != nil {
				t.Error("New returned a client alongside an error: a caller who ignores the error gets an unbounded one")
			}

			if !strings.Contains(err.Error(), test.field) {
				t.Errorf("New error = %q, want it to name %s", err, test.field)
			}
		})
	}
}

// TestNewReportsEveryBadSettingAtOnce covers AC-006.5 and AC-006.9.
func TestNewReportsEveryBadSettingAtOnce(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Timeout = 0
	cfg.MaxIdleConns = -1

	_, err := New(cfg, Telemetry{})
	if err == nil {
		t.Fatal("New error = nil, want a failure")
	}

	for _, field := range []string{"Timeout", "MaxIdleConns"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("New error = %q, want it to name %s: an operator who fixes one mistake should not have to restart to find the next", err, field)
		}
	}
}

// TestNewTransportHonoursTheProxyEnvironment covers AC-006.15.
func TestNewTransportHonoursTheProxyEnvironment(t *testing.T) {
	t.Parallel()

	transport, err := newTransport(Default())
	if err != nil {
		t.Fatalf("newTransport error = %v, want nil", err)
	}

	if transport.Proxy == nil {
		t.Fatal("Proxy is nil: every request would bypass a proxy HTTP_PROXY names")
	}

	// Identity rather than behaviour, because http.ProxyFromEnvironment reads
	// the environment through a sync.Once and caches the answer for the life
	// of the process. Setting HTTP_PROXY in a test therefore changes nothing
	// if anything has already called it, so the assertion that would look
	// more convincing would in fact be the one that could not fail.
	want := reflect.ValueOf(http.ProxyFromEnvironment).Pointer()
	if got := reflect.ValueOf(transport.Proxy).Pointer(); got != want {
		t.Error("Proxy is not http.ProxyFromEnvironment: the proxy rule must be the standard library's, not one of this package's own")
	}
}
