package telemetry

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
)

// DefaultServiceName is reported as service.name when the environment does not
// name the service.
const DefaultServiceName = "service"

// EnvOTLPEndpoint is the OpenTelemetry environment variable naming the collector
// to export to. Setting it is what enables tracing. It exists so that the log
// line reporting tracing as disabled can name the variable that turns it on;
// the variables themselves are declared on Config's struct tags, which stay the
// single source of truth.
const EnvOTLPEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"

// Config describes how this process identifies itself in telemetry and where it
// sends it.
//
// The environment variable names are not a project configuration choice: they
// and their precedence are fixed by the OpenTelemetry specification, so every
// collector, agent, and deployment tool already knows how to set them. That is
// why they are absolute here rather than carrying this project's prefix.
type Config struct {
	// ServiceName is reported as the service.name resource attribute, which is
	// the primary key backends group traces by.
	ServiceName string `env:"OTEL_SERVICE_NAME, overwrite" json:"service_name" validate:"required"`
	// ServiceVersion is reported as the service.version resource attribute. It
	// comes from the build rather than the environment, so it carries no env
	// tag at all: go-envconfig has no skip directive and would read "-" as a
	// variable name. An empty value is omitted rather than reported as blank.
	ServiceVersion string `json:"service_version"`
	// OTLPEndpoint is the base URL of an OTLP/HTTP collector, for example
	// http://localhost:4318. An empty value disables trace export. It has no
	// bearing on metrics, which are scraped rather than pushed.
	//
	// Validated as an HTTP URL rather than as a URL: the export path here is
	// OTLP/HTTP, and the bare host:port form that OTLP/gRPC deployments use
	// parses as a URL with "localhost" for a scheme. WithEndpointURL would
	// reject it after tracing had already been reported as enabled, so it is
	// refused at startup instead.
	OTLPEndpoint string `env:"OTEL_EXPORTER_OTLP_ENDPOINT, overwrite" json:"otlp_endpoint" validate:"omitempty,http_url"`
	// OTLPTracesEndpoint is the signal-specific form of OTLPEndpoint. When both
	// are set this one wins, which is what the specification requires. Read it
	// through TracesEndpoint rather than directly. It is validated as an HTTP
	// URL for the same reason OTLPEndpoint is.
	OTLPTracesEndpoint string `env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, overwrite" json:"otlp_traces_endpoint" validate:"omitempty,http_url"`
}

// DefaultConfig returns the telemetry configuration used when nothing overrides
// it: the default service name and no collector, which leaves trace export
// disabled.
func DefaultConfig() Config {
	return Config{ServiceName: DefaultServiceName}
}

// tracesPath is the path an OTLP/HTTP exporter appends to the general
// collector endpoint to reach the traces receiver.
const tracesPath = "v1/traces"

// TracesEndpoint returns the full URL traces are exported to, applying the
// rules the OpenTelemetry specification defines: the signal-specific variable
// wins over the general one and is used exactly as given, while the general
// one is a base URL to which the traces path is appended. An empty result
// means export is disabled.
func (c Config) TracesEndpoint() string {
	if c.OTLPTracesEndpoint != "" {
		return c.OTLPTracesEndpoint
	}

	if c.OTLPEndpoint == "" {
		return ""
	}

	return strings.TrimSuffix(c.OTLPEndpoint, "/") + "/" + tracesPath
}

// Tracing is an initialised tracing pipeline. Its zero value is not usable;
// obtain one from SetupTracing.
type Tracing struct {
	provider   *sdktrace.TracerProvider
	propagator propagation.TextMapPropagator
}

// Enabled reports whether spans are being exported. It is false when no
// collector endpoint was configured, in which case instrumentation still runs
// against a no-op provider.
func (t *Tracing) Enabled() bool {
	return t.provider != nil
}

// TracerProvider returns the provider instrumentation should create spans
// from: the exporting one when tracing is enabled, and otherwise a no-op that
// still carries an inbound span context through, so that a trace this process
// does not record is not broken at this hop either.
func (t *Tracing) TracerProvider() trace.TracerProvider {
	if t.provider == nil {
		return tracenoop.NewTracerProvider()
	}

	return t.provider
}

// Propagator returns the context propagator instrumentation should read
// inbound trace headers with. It is the same whether or not tracing is
// enabled: propagation is what keeps an inbound trace intact across this hop,
// and it costs nothing when there is no local exporter.
//
// Like TracerProvider, it is never nil: a zero-value Tracing yields a
// propagator that reads and writes nothing.
func (t *Tracing) Propagator() propagation.TextMapPropagator {
	if t.propagator == nil {
		return propagation.NewCompositeTextMapPropagator()
	}

	return t.propagator
}

// Shutdown flushes any spans the exporter has buffered and releases its
// resources. It is safe to call when tracing is disabled, and bounded by ctx:
// callers should pass a context with a deadline so a wedged collector cannot
// delay process exit indefinitely.
func (t *Tracing) Shutdown(ctx context.Context) error {
	if t.provider == nil {
		return nil
	}

	if err := t.provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutting down tracer provider: %w", err)
	}

	return nil
}

// SetupTracing builds the tracing pipeline: a context propagator, and, when cfg
// names a collector endpoint, a tracer provider exporting to it over OTLP/HTTP.
// Nothing is installed on the otel package's globals; callers pass the result's
// providers to the instrumentation that records through them.
//
// The one process-wide effect is the SDK error handler. The SDK reports its own
// failures, such as a rejected export, only through otel.Handle, and left alone
// that writes to stderr through the standard log package, which
// docs/adr/0003-use-uber-zap-for-logging.md rules out.
//
// It returns a usable Tracing even when tracing is disabled, so callers always
// have something to defer Shutdown on.
func SetupTracing(ctx context.Context, cfg Config, logger *zap.Logger) (*Tracing, error) {
	otel.SetErrorHandler(&errorHandler{logger: logger})

	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)

	endpoint := cfg.TracesEndpoint()

	if endpoint == "" {
		logger.Info("tracing disabled: no collector endpoint configured",
			zap.String("set_to_enable", EnvOTLPEndpoint),
		)

		return &Tracing{propagator: propagator}, nil
	}

	res, err := newResource(cfg)
	if err != nil {
		return nil, err
	}

	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter for %s: %w", endpoint, err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		// Every locally started trace is sampled, and a sampling decision
		// arriving from upstream is honoured. Volume-based sampling is left to
		// the collector, which can decide with the whole trace in hand rather
		// than guessing at the first span.
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	)

	logger.Info("tracing enabled",
		zap.String("endpoint", endpoint),
		zap.String("service", cfg.ServiceName),
	)

	return &Tracing{provider: provider, propagator: propagator}, nil
}

// newResource describes this process to the telemetry backend.
func newResource(cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{semconv.ServiceName(cfg.ServiceName)}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, attrs...),
	)
	if err != nil {
		return nil, fmt.Errorf("building telemetry resource for service %s: %w", cfg.ServiceName, err)
	}

	return res, nil
}

// errorHandler routes errors the OpenTelemetry SDK reports internally, such as
// a failed export, into the application logger.
type errorHandler struct {
	logger *zap.Logger
}

// Handle logs err against the application logger at error level.
func (h *errorHandler) Handle(err error) {
	h.logger.Error("opentelemetry sdk reported an error", zap.Error(err))
}
