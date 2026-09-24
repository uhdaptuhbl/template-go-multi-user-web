package telemetry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/buildinfo"
)

// meterName is the instrumentation scope this package's own instruments are
// created under. The module path is the convention OpenTelemetry asks for,
// because a scope is meant to identify the code that produced a measurement.
const meterName = "github.com/uhdaptuhbl/template-go-multi-user-web"

// Metrics is an initialised metrics pipeline. Its zero value is not usable;
// obtain one from SetupMetrics.
type Metrics struct {
	provider *sdkmetric.MeterProvider
	registry *prometheus.Registry
}

// MeterProvider returns the provider instrumentation should create instruments
// from. Everything recorded through it reaches the scrape endpoint.
//
// A zero-value Metrics yields a no-op provider rather than its nil field: a nil
// *sdkmetric.MeterProvider inside a metric.MeterProvider interface is not a nil
// interface, so returning it would defeat every caller's nil check and panic on
// the first measurement instead.
func (m *Metrics) MeterProvider() metric.MeterProvider {
	if m.provider == nil {
		return metricnoop.NewMeterProvider()
	}

	return m.provider
}

// Handler returns the HTTP handler that serves the collected metrics in
// Prometheus text format. It belongs on an administrative listener, not a public
// one: metric names alone disclose route names, traffic volume, and error rates.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		// Report scrape-time failures through the response rather than only in
		// the body, so a broken collector surfaces as a failed scrape.
		ErrorHandling: promhttp.HTTPErrorOnError,
	})
}

// RecordBuildInfo publishes a constant gauge carrying info, so that a scrape
// answers which binary is running.
//
// The value is always 1; the information is in the labels. That is the
// established convention for build metadata in Prometheus, and it composes: a
// query can join on the labels without the value perturbing an aggregation.
func (m *Metrics) RecordBuildInfo(info buildinfo.Info) error {
	// Through MeterProvider, not m.provider, which is nil on a zero-value
	// Metrics and panics when a Meter is taken from it. SetupMetrics never
	// hands back such a value, but MeterProvider and Shutdown both document
	// tolerating one, so a caller constructing Metrics{} has every reason to
	// expect this method to tolerate it too.
	meter := m.MeterProvider().Meter(meterName)

	gauge, err := meter.Int64ObservableGauge(
		"build_info",
		metric.WithDescription("Always 1, labelled with the identity of the running build."),
	)
	if err != nil {
		return fmt.Errorf("creating the build_info instrument: %w", err)
	}

	// The build date and the Go version are here because they reach a scrape no
	// other way: both are named only in the start-up log entry, which is gone
	// once logs have rotated. All four labels are constant for the life of the
	// process, so they add no cardinality over time.
	attributes := metric.WithAttributes(
		attribute.String("version", info.Version),
		attribute.String("commit", info.Commit),
		attribute.String("build_date", info.Date),
		attribute.String("go_version", buildinfo.GoVersion()),
	)

	// The registration is deliberately not retained: the gauge lives for the
	// life of the process, and unregistering it would only ever happen at
	// shutdown, when the whole meter provider is torn down anyway.
	_, err = meter.RegisterCallback(
		func(_ context.Context, observer metric.Observer) error {
			observer.ObserveInt64(gauge, 1, attributes)

			return nil
		},
		gauge,
	)
	if err != nil {
		return fmt.Errorf("registering the build_info callback: %w", err)
	}

	return nil
}

// Shutdown stops metric collection and releases the meter provider's resources.
// Nothing is flushed anywhere: collection is pull-based, so metrics not yet
// scraped are simply lost, which is inherent to the delivery model rather than a
// shortcoming of this call.
func (m *Metrics) Shutdown(ctx context.Context) error {
	if m.provider == nil {
		return nil
	}

	if err := m.provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutting down meter provider: %w", err)
	}

	return nil
}

// SetupMetrics builds an OpenTelemetry meter provider whose measurements are
// exposed for Prometheus to scrape, and starts collection of Go runtime metrics
// through it. Nothing is installed on the otel package's globals; callers pass
// MeterProvider to the instrumentation that records through it.
//
// Unlike tracing, this is not conditional on an endpoint: collection is
// pull-based, so a running process with nothing scraping it costs only the
// memory holding the current values.
func SetupMetrics(cfg Config, logger *zap.Logger) (*Metrics, error) {
	res, err := newResource(cfg)
	if err != nil {
		return nil, err
	}

	// A dedicated registry rather than prometheus.DefaultRegisterer, which any
	// dependency can write to via init(). What this process exposes should be
	// what this process chose to expose.
	registry := prometheus.NewRegistry()

	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, fmt.Errorf("creating prometheus metrics exporter: %w", err)
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithResource(res),
	)

	// Go runtime metrics: heap, goroutine count, GC pauses. Started here because
	// without them a service carrying no custom instrumentation yet exposes
	// almost nothing worth scraping.
	if startErr := runtime.Start(runtime.WithMeterProvider(provider)); startErr != nil {
		return nil, fmt.Errorf("starting runtime metrics collection: %w", startErr)
	}

	logger.Info("metrics enabled",
		zap.String("exposition", "prometheus"),
		zap.String("service", cfg.ServiceName),
	)

	return &Metrics{provider: provider, registry: registry}, nil
}
