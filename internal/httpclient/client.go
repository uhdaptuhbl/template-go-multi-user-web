package httpclient

import (
	"errors"
	"fmt"
	"net"
	"net/http"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// Telemetry carries the providers an outbound client records through.
//
// It mirrors server.Telemetry rather than reusing it, so that this package
// stays a leaf and the wiring in cmd reads the same in both directions. A zero
// value records nothing: each provider falls back to its no-op, which keeps an
// untraced build on exactly the code path a traced one takes.
type Telemetry struct {
	// TracerProvider creates the span for each outbound request.
	TracerProvider trace.TracerProvider
	// MeterProvider records request duration and size.
	MeterProvider metric.MeterProvider
	// Propagator injects this service's trace context into outbound headers.
	Propagator propagation.TextMapPropagator
}

// New returns an HTTP client configured by cfg and instrumented through
// telemetry.
//
// It returns an error rather than substituting a default for a setting that
// cannot be meant, because these settings can come from the environment and an
// operator's mistake belongs in the start-up failure beside every other one. A
// client silently given a working timeout in place of the one that was asked
// for is the failure this package exists to prevent, arriving by another door.
func New(cfg Config, telemetry Telemetry) (*http.Client, error) {
	transport, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: instrument(transport, telemetry),
		Timeout:   cfg.Timeout.Duration(),
	}, nil
}

// newTransport builds the connection pool cfg describes.
//
// The transport is constructed field by field rather than cloned from
// http.DefaultTransport. A clone would inherit whatever a future Go release
// changes in the default, and would pick up any mutation another package in
// the process made to it; constructing means every value in the pool is one
// this package chose and can be read off in one place. The one default worth
// keeping is named explicitly below.
func newTransport(cfg Config) (*http.Transport, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: cfg.ConnectTimeout.Duration()}

	return &http.Transport{
		// The standard library's rule, not one of this package's own.
		// Constructing the transport field by field rather than cloning
		// http.DefaultTransport leaves this nil, and a nil Proxy is not "no
		// proxy configured" but "ignore the proxy the operator configured":
		// every request would go direct, which behind an egress gateway
		// fails and behind a corporate proxy leaks past it. That is a
		// surprise a service inherits silently, so it is taken back
		// deliberately rather than dropped as a side effect of not cloning.
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout.Duration(),
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout.Duration(),
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout.Duration(),
		ForceAttemptHTTP2:     true,
	}, nil
}

// validate reports every setting that cannot be meant, joined, so that an
// operator who mistyped two variables is told about both rather than made to
// restart to discover the second.
//
// The struct tags say the same thing for the environment path, where the
// shared decoder applies them. This is the code path for a Config built in
// code, which the decoder never sees.
func (c Config) validate() error {
	durations := []struct {
		name  string
		value configtype.Duration
	}{
		{name: "Timeout", value: c.Timeout},
		{name: "ConnectTimeout", value: c.ConnectTimeout},
		{name: "TLSHandshakeTimeout", value: c.TLSHandshakeTimeout},
		{name: "ResponseHeaderTimeout", value: c.ResponseHeaderTimeout},
		{name: "IdleConnTimeout", value: c.IdleConnTimeout},
	}

	counts := []struct {
		name  string
		value int
	}{
		{name: "MaxConnsPerHost", value: c.MaxConnsPerHost},
		{name: "MaxIdleConns", value: c.MaxIdleConns},
		{name: "MaxIdleConnsPerHost", value: c.MaxIdleConnsPerHost},
	}

	errs := make([]error, 0, len(durations)+len(counts))

	for _, duration := range durations {
		if duration.value <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive, not %s", duration.name, duration.value))
		}
	}

	// Zero is allowed here and means unlimited, which net/http already
	// documents for each of these. It is a deliberate choice an operator can
	// make; a negative one is not a choice at all.
	for _, count := range counts {
		if count.value < 0 {
			errs = append(errs, fmt.Errorf("%s must not be negative, not %d", count.name, count.value))
		}
	}

	return errors.Join(errs...)
}
