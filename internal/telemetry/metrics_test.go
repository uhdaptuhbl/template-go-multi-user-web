package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/buildinfo"
)

// setupMetrics builds a metrics pipeline and tears it down when the test ends.
func setupMetrics(t *testing.T) *Metrics {
	t.Helper()

	metrics, err := SetupMetrics(Config{ServiceName: "test", ServiceVersion: "1.2.3"}, zap.NewNop())
	if err != nil {
		t.Fatalf("SetupMetrics returned error: %v", err)
	}

	t.Cleanup(func() {
		if shutdownErr := metrics.Shutdown(context.Background()); shutdownErr != nil {
			t.Errorf("Shutdown returned error: %v", shutdownErr)
		}
	})

	return metrics
}

// scrape collects the metrics exposition the handler produces.
func scrape(t *testing.T, metrics *Metrics) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))

	if recorder.Code != http.StatusOK {
		t.Fatalf("scrape returned status %d, want %d", recorder.Code, http.StatusOK)
	}

	return recorder.Body.String()
}

// TestSetupMetricsExposesInstrumentsRecordedThroughItsMeterProvider covers AC-005.17.
func TestSetupMetricsExposesInstrumentsRecordedThroughItsMeterProvider(t *testing.T) {
	t.Parallel()

	// Exercises the whole path a caller depends on: an instrument created from
	// the provider the pipeline hands back reaches the scrape endpoint. A test
	// that only checked the handler responded would pass with nothing wired
	// together.
	metrics := setupMetrics(t)

	counter, err := metrics.MeterProvider().Meter("test").Int64Counter("widgets.assembled")
	if err != nil {
		t.Fatalf("creating counter: %v", err)
	}

	counter.Add(t.Context(), 3)

	body := scrape(t, metrics)

	// The Prometheus exporter translates the OpenTelemetry name: dots become
	// underscores and a monotonic counter gains a _total suffix.
	if !strings.Contains(body, "widgets_assembled_total") {
		t.Errorf("scrape does not contain the recorded counter; body was:\n%s", body)
	}

	// Every sample carries the instrumentation scope as labels, so the value is
	// never adjacent to the bare metric name. This is the exporter's documented
	// output shape, not something this project chose.
	const sample = `widgets_assembled_total{otel_scope_name="test",otel_scope_schema_url="",otel_scope_version=""} 3`

	if !strings.Contains(body, sample) {
		t.Errorf("scrape does not report the counter as 3; body was:\n%s", body)
	}
}

// TestSetupMetricsCollectsGoRuntimeMetrics covers AC-005.21.
func TestSetupMetricsCollectsGoRuntimeMetrics(t *testing.T) {
	t.Parallel()

	// Without runtime collection a service carrying no custom instrumentation
	// exposes almost nothing, which makes the endpoint useless on day one.
	body := scrape(t, setupMetrics(t))

	if !strings.Contains(body, "go_memory_used_bytes") {
		t.Errorf("scrape does not contain Go runtime metrics; body was:\n%s", body)
	}
}

// TestSetupMetricsReportsTheServiceResource covers AC-005.22.
func TestSetupMetricsReportsTheServiceResource(t *testing.T) {
	t.Parallel()

	body := scrape(t, setupMetrics(t))

	if !strings.Contains(body, "target_info") {
		t.Fatalf("scrape does not contain target_info, which carries resource attributes; body was:\n%s", body)
	}

	if !strings.Contains(body, `service_name="test"`) {
		t.Error("scrape does not report service_name from the configured resource")
	}

	if !strings.Contains(body, `service_version="1.2.3"`) {
		t.Error("scrape does not report service_version from the configured resource")
	}
}

// TestRecordBuildInfoExposesLabels covers AC-002.25.
func TestRecordBuildInfoExposesLabels(t *testing.T) {
	t.Parallel()

	metrics := setupMetrics(t)

	info := buildinfo.Info{Version: "v1.2.3", Commit: "abc1234", Date: "2026-09-18T00:00:00Z"}

	if err := metrics.RecordBuildInfo(info); err != nil {
		t.Fatalf("RecordBuildInfo returned error: %v", err)
	}

	body := scrape(t, metrics)

	if !strings.Contains(body, "build_info") {
		t.Fatalf("scrape does not contain build_info; body was:\n%s", body)
	}

	if !strings.Contains(body, `version="v1.2.3"`) {
		t.Errorf("scrape does not report version=\"v1.2.3\"; body was:\n%s", body)
	}

	if !strings.Contains(body, `commit="abc1234"`) {
		t.Errorf("scrape does not report commit=\"abc1234\"; body was:\n%s", body)
	}

	// The build date reaches a running process no other way: it is named in the
	// start-up log entry, which is gone once logs rotate.
	if !strings.Contains(body, `build_date="2026-09-18T00:00:00Z"`) {
		t.Errorf("scrape does not report build_date; body was:\n%s", body)
	}

	if !strings.Contains(body, `go_version="`+buildinfo.GoVersion()+`"`) {
		t.Errorf("scrape does not report go_version=%q; body was:\n%s", buildinfo.GoVersion(), body)
	}
}

// TestMetricsShutdownIsSafeOnAZeroValue cites no criterion: it guards the
// exported type's behaviour on its zero value, which SetupMetrics never
// produces and a caller constructing Metrics{} directly would rely on.
func TestMetricsShutdownIsSafeOnAZeroValue(t *testing.T) {
	t.Parallel()

	var metrics Metrics

	if err := metrics.Shutdown(t.Context()); err != nil {
		t.Errorf("Shutdown on a zero-value Metrics returned error: %v", err)
	}
}

// TestRecordBuildInfoIsSafeOnAZeroValue cites no criterion, for the same
// reason as the test above.
func TestRecordBuildInfoIsSafeOnAZeroValue(t *testing.T) {
	t.Parallel()

	// MeterProvider and Shutdown both document tolerating the zero value,
	// so RecordBuildInfo tolerating it is what a caller would assume. Not a
	// path SetupMetrics can produce today; it is the exported contract of
	// the type that is inconsistent, and a descendant constructing Metrics{}
	// directly is the one who would find out.
	var metrics Metrics

	if err := metrics.RecordBuildInfo(buildinfo.Info{Version: "v0.0.1", Commit: "abc1234", Date: "2026-09-20"}); err != nil {
		t.Errorf("RecordBuildInfo on a zero-value Metrics returned error: %v", err)
	}
}

// TestZeroValueMetricsYieldsAUsableMeterProvider cites no criterion, for the
// same reason as the two tests above.
func TestZeroValueMetricsYieldsAUsableMeterProvider(t *testing.T) {
	t.Parallel()

	// The trap this guards: a nil *sdkmetric.MeterProvider returned as a
	// metric.MeterProvider is not a nil interface, so a caller's nil check
	// passes and the first measurement panics instead.
	var metrics Metrics

	provider := metrics.MeterProvider()
	if provider == nil {
		t.Fatal("MeterProvider() on a zero-value Metrics returned nil")
	}

	counter, err := provider.Meter("test").Int64Counter("widgets.assembled")
	if err != nil {
		t.Fatalf("creating a counter from a zero-value Metrics: %v", err)
	}

	counter.Add(t.Context(), 1)
}
