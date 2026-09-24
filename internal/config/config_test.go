package config

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sethvargo/go-envconfig"
	"go.uber.org/zap/zapcore"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/logging"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/mail"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/telemetry"
)

// testDSN is a Postgres connection string that pgxpool.ParseConfig accepts,
// used wherever a test needs Load to get past store.Config's required-DSN
// check without dialing a real database. It uses the keyword=value DSN form
// rather than a postgres://user:pass@host URL so it does not read as an
// embedded credential to gosec's G101 check.
const testDSN = "host=localhost port=5432 dbname=testdb sslmode=disable"

// TestDefaultComposesEachPackagesOwnDefaults covers AC-001.20.
func TestDefaultComposesEachPackagesOwnDefaults(t *testing.T) {
	t.Parallel()

	got := Default()

	want := Config{
		Log:       logging.DefaultConfig(),
		Server:    server.DefaultConfig(),
		Admin:     server.DefaultAdminConfig(),
		Lifecycle: server.DefaultLifecycleConfig(),
		Proxy:     server.DefaultProxyConfig(),
		Telemetry: telemetry.DefaultConfig(),
		Database:  store.DefaultConfig(),
		Session:   session.DefaultConfig(),
		Mail:      mail.DefaultConfig(),
		Auth:      DefaultAuthConfig(),
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Default() mismatch (-want +got):\n%s", diff)
	}
}

// TestDefaultBindsTheTwoListenersToDifferentPorts covers AC-001.5.
func TestDefaultBindsTheTwoListenersToDifferentPorts(t *testing.T) {
	t.Parallel()

	got := Default()

	// Ports, not whole addresses. The criterion is that the two listeners take
	// separate ports; comparing the address strings would call
	// ":8080" and "127.0.0.1:8080" separate, which is the collision the
	// criterion exists to forbid.
	_, serverPort, err := net.SplitHostPort(got.Server.Addr)
	if err != nil {
		t.Fatalf("splitting Server.Addr %q: %v", got.Server.Addr, err)
	}

	_, adminPort, err := net.SplitHostPort(got.Admin.Addr)
	if err != nil {
		t.Fatalf("splitting Admin.Addr %q: %v", got.Admin.Addr, err)
	}

	// The admin listener carries profiling and metrics, so it must not land on
	// the port the application exposes to users.
	if serverPort == adminPort {
		t.Errorf("both listeners bound to port %q (server %q, admin %q), want separate ports",
			serverPort, got.Server.Addr, got.Admin.Addr)
	}
}

// TestLoadReturnsTheDefaultsWhenNothingIsSet cover AC-001.4 and AC-002.17.
//
// SERVICE_DB_DSN has no default and is required (store.Config.Validate), so
// it is the one variable this test must set to reach "nothing else is set".
// The three extra assertions below cover the equivalent case for this
// package: the defaults compose to a secure cookie, OTP disabled, and mail
// disabled.
func TestLoadReturnsTheDefaultsWhenNothingIsSet(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN": testDSN,
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	want := Default()
	want.Telemetry.ServiceVersion = "1.2.3"
	want.Database.DSN = testDSN

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Load() mismatch (-want +got):\n%s", diff)
	}

	if !got.Session.CookieSecure {
		t.Errorf("Session.CookieSecure = false, want true")
	}
	if got.Auth.OTPEnabled {
		t.Errorf("Auth.OTPEnabled = true, want false")
	}
	if got.Mail.Enabled {
		t.Errorf("Mail.Enabled = true, want false")
	}
}

// TestLoadAppliesEnvironmentValuesOverTheDefaults covers AC-001.1.
func TestLoadAppliesEnvironmentValuesOverTheDefaults(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":              testDSN,
		"SERVICE_LOG_LEVEL":           "debug",
		"SERVICE_LOG_FORMAT":          "json",
		"SERVICE_SERVER_ADDR":         "127.0.0.1:3000",
		"SERVICE_SERVER_READ_TIMEOUT": "45s",
		"SERVICE_ADMIN_ADDR":          "127.0.0.1:3001",
		"OTEL_SERVICE_NAME":           "renamed",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	// Every field below starts non-zero in Default(). go-envconfig skips a
	// field that already holds a value unless its tag says overwrite, so a
	// missing overwrite would silently ignore the whole environment here.
	want := Default()
	want.Database.DSN = testDSN
	want.Log.Level = zapcore.DebugLevel
	want.Log.Format = logging.FormatJSON
	want.Server.Addr = "127.0.0.1:3000"
	want.Server.ReadTimeout = configtype.Duration(45 * time.Second)
	want.Admin.Addr = "127.0.0.1:3001"
	want.Telemetry.ServiceName = "renamed"
	want.Telemetry.ServiceVersion = "1.2.3"
	want.Telemetry.OTLPEndpoint = "http://collector:4318"

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Load() mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadConfiguresTheTwoListenersIndependently covers AC-001.5.
func TestLoadConfiguresTheTwoListenersIndependently(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":                  testDSN,
		"SERVICE_SERVER_ADDR":             "127.0.0.1:3000",
		"SERVICE_SERVER_SHUTDOWN_TIMEOUT": "1s",
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	// Both listeners share one Config type. Setting one must not move the
	// other, or an operator retuning the public listener would silently
	// retune the administrative one with it.
	if diff := cmp.Diff(server.DefaultAdminConfig(), got.Admin); diff != "" {
		t.Errorf("admin config changed with the server's (-want +got):\n%s", diff)
	}
}

// TestLoadReadsTelemetryVariablesWithoutTheProjectPrefix covers AC-001.21.
func TestLoadReadsTelemetryVariablesWithoutTheProjectPrefix(t *testing.T) {
	t.Parallel()

	// The OpenTelemetry specification fixes these names, so every collector
	// and deployment tool already sets them. Namespacing them would mean the
	// standard variable silently did nothing.
	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":            testDSN,
		"SERVICE_OTEL_SERVICE_NAME": "ignored",
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if got.Telemetry.ServiceName != telemetry.DefaultServiceName {
		t.Errorf("ServiceName = %q, want the prefixed variable to have no effect", got.Telemetry.ServiceName)
	}
}

// TestLoadPrefersTheSignalSpecificTracesEndpoint covers AC-001.22.
func TestLoadPrefersTheSignalSpecificTracesEndpoint(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":                     testDSN,
		"OTEL_EXPORTER_OTLP_ENDPOINT":        "http://general:4318",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://traces:4318",
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if endpoint := got.Telemetry.TracesEndpoint(); endpoint != "http://traces:4318" {
		t.Errorf("TracesEndpoint() = %q, want the signal-specific endpoint to win", endpoint)
	}
}

// TestLoadTakesTheServiceVersionFromTheBuildRatherThanTheEnvironment covers AC-001.23.
func TestLoadTakesTheServiceVersionFromTheBuildRatherThanTheEnvironment(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":                    testDSN,
		"OTEL_SERVICE_VERSION":              "from-env",
		"SERVICE_TELEMETRY_SERVICE_VERSION": "also-from-env",
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	// The reported version must match the binary that is running. Letting the
	// environment set it would let a stale deployment misreport itself.
	if got.Telemetry.ServiceVersion != "1.2.3" {
		t.Errorf("ServiceVersion = %q, want the value passed by the caller", got.Telemetry.ServiceVersion)
	}
}

// TestLoadTreatsAnEmptyVariableAsUnset covers AC-001.3.
func TestLoadTreatsAnEmptyVariableAsUnset(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":     testDSN,
		"SERVICE_ADMIN_ADDR": "",
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	// Measured go-envconfig behaviour: a variable that is present but empty is
	// treated as absent, so overwrite does not fire and the default stands.
	// That is the outcome to want here. An exported-but-empty variable, which
	// a shell produces easily, would otherwise blank the listen address and
	// fail validation at startup.
	if got.Admin.Addr != server.DefaultAdminConfig().Addr {
		t.Errorf("Admin.Addr = %q, want the default to stand", got.Admin.Addr)
	}
}

// TestLoadDefaultsLifecycleAndProxy covers AC-002.15 and AC-002.17.
// It also covers AC-001.4.
func TestLoadDefaultsLifecycleAndProxy(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN": testDSN,
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if got.Lifecycle.PreDrainDelay != configtype.Duration(5*time.Second) {
		t.Errorf("Lifecycle.PreDrainDelay = %v, want 5s", got.Lifecycle.PreDrainDelay)
	}

	if len(got.Proxy.TrustedCIDRs) != 0 {
		t.Errorf("Proxy.TrustedCIDRs = %v, want empty", got.Proxy.TrustedCIDRs)
	}

	if got.Server.Addr != ":8080" {
		t.Errorf("Server.Addr = %q, want %q", got.Server.Addr, ":8080")
	}

	if got.Admin.Addr != server.DefaultAdminConfig().Addr {
		t.Errorf("Admin.Addr = %q, want %q", got.Admin.Addr, server.DefaultAdminConfig().Addr)
	}
}

// TestLoadOverridesLifecycleAndProxy covers AC-002.15.
func TestLoadOverridesLifecycleAndProxy(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":                    testDSN,
		"SERVICE_LIFECYCLE_PRE_DRAIN_DELAY": "0s",
		"SERVICE_PROXY_TRUSTED_CIDRS":       "10.0.0.0/8,192.168.0.0/16",
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if got.Lifecycle.PreDrainDelay != 0 {
		t.Errorf("Lifecycle.PreDrainDelay = %v, want 0s", got.Lifecycle.PreDrainDelay)
	}

	want := []string{"10.0.0.0/8", "192.168.0.0/16"}
	if diff := cmp.Diff(want, got.Proxy.TrustedCIDRs); diff != "" {
		t.Errorf("Proxy.TrustedCIDRs mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadRejectsInvalidTrustedCIDR covers AC-002.10 and AC-002.11.
func TestLoadRejectsInvalidTrustedCIDR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		cidrs string
	}{
		{name: "not a CIDR at all", cidrs: "not-a-cidr"},
		{name: "an address with no prefix length", cidrs: "10.0.0.1"},
		{name: "one bad entry among good ones", cidrs: "10.0.0.0/8,192.168.0.0/nope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
				"SERVICE_DB_DSN":              testDSN,
				"SERVICE_PROXY_TRUSTED_CIDRS": tt.cidrs,
			}), "1.2.3")
			if err == nil {
				t.Fatalf("Load() error = nil, want a failure; got %+v", got)
			}

			// A typo in a trust boundary has to name the variable that carries
			// it: the value is a list, and the message is what tells an
			// operator which list to go and look at.
			if !strings.Contains(err.Error(), "SERVICE_PROXY_") {
				t.Errorf("Load() error = %q, want it to name the proxy settings", err)
			}
		})
	}
}

// TestLoadAcceptsTheTrustedCIDRFormsTheParserAccepts covers AC-002.10.
//
// Startup validation and the parser that runs on the request path are the same
// code, so a list that starts the process is a list that parses. The forms a
// separated list picks up by being edited, a trailing comma or a doubled one,
// are empty entries rather than malformed networks, and refusing them at
// startup would fail a deployment over a value that changes nothing.
func TestLoadAcceptsTheTrustedCIDRFormsTheParserAccepts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		cidrs string
		want  []string
	}{
		{
			name:  "trailing comma",
			cidrs: "10.0.0.0/8,",
			want:  []string{"10.0.0.0/8", ""},
		},
		{
			name:  "doubled comma",
			cidrs: "10.0.0.0/8,,192.168.0.0/16",
			want:  []string{"10.0.0.0/8", "", "192.168.0.0/16"},
		},
		{
			name:  "spaces after the separators",
			cidrs: "10.0.0.0/8, 192.168.0.0/16",
			want:  []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		{
			name:  "an IPv6 network",
			cidrs: "2001:db8::/32",
			want:  []string{"2001:db8::/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
				"SERVICE_DB_DSN":              testDSN,
				"SERVICE_PROXY_TRUSTED_CIDRS": tt.cidrs,
			}), "1.2.3")
			if err != nil {
				t.Fatalf("Load() error = %v, want the list accepted", err)
			}

			// go-envconfig keeps the empty entries and trims the spaces, so
			// what reaches the parser is asserted rather than assumed.
			if diff := cmp.Diff(tt.want, got.Proxy.TrustedCIDRs); diff != "" {
				t.Errorf("Proxy.TrustedCIDRs mismatch (-want +got):\n%s", diff)
			}

			if _, parseErr := server.NewTrustedProxies(got.Proxy); parseErr != nil {
				t.Errorf("NewTrustedProxies() error = %v, want what startup accepted to parse", parseErr)
			}
		})
	}
}

// TestLoadRejectsInvalidConfiguration covers AC-001.2.
func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "listen address without a port",
			env:  map[string]string{"SERVICE_SERVER_ADDR": "localhost"},
		},
		{
			name: "timeout of zero",
			env:  map[string]string{"SERVICE_SERVER_READ_TIMEOUT": "0s"},
		},
		{
			name: "negative timeout",
			env:  map[string]string{"SERVICE_SERVER_IDLE_TIMEOUT": "-1s"},
		},
		{
			name: "collector endpoint that is not a URL",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "not a url"},
		},
		{
			name: "collector endpoint that is a bare host and port",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:4317"},
		},
		{
			name: "traces endpoint that is a bare host and port",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "collector:4317"},
		},
		{
			name: "unknown log format",
			env:  map[string]string{"SERVICE_LOG_FORMAT": "xml"},
		},
		{
			name: "unparseable log level",
			env:  map[string]string{"SERVICE_LOG_LEVEL": "chatty"},
		},
		{
			name: "unparseable timeout",
			env:  map[string]string{"SERVICE_SERVER_WRITE_TIMEOUT": "soon"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(t.Context(), envconfig.MapLookuper(tt.env), "1.2.3")
			if err == nil {
				t.Fatalf("Load() error = nil, want a failure; got %+v", got)
			}

			if !strings.Contains(err.Error(), "loading configuration") {
				t.Errorf("Load() error = %q, want it to name the operation", err)
			}

			// A partly-built config is worse than none: the caller might use
			// it, so failure returns the zero value.
			if diff := cmp.Diff(Config{}, got); diff != "" {
				t.Errorf("Load() returned a config alongside its error (-want +got):\n%s", diff)
			}
		})
	}
}

// TestLoadAcceptsIPv6ListenAddresses covers AC-001.1.
//
// A dual-stack deployment binds an IPv6 literal, which has to be bracketed to
// separate it from the port. Validation that only understands the hostname form
// refuses the address the operator was told to use.
func TestLoadAcceptsIPv6ListenAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
	}{
		{name: "wildcard", addr: "[::]:8080"},
		{name: "loopback", addr: "[::1]:9090"},
		{name: "ipv4 literal", addr: "0.0.0.0:8080"},
		{name: "every interface", addr: ":8080"},
		{name: "hostname", addr: "localhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
				"SERVICE_DB_DSN":      testDSN,
				"SERVICE_SERVER_ADDR": tt.addr,
			}), "1.2.3")
			if err != nil {
				t.Fatalf("Load() error = %v, want the address accepted", err)
			}

			if got.Server.Addr != tt.addr {
				t.Errorf("Server.Addr = %q, want %q", got.Server.Addr, tt.addr)
			}
		})
	}
}

// TestLoadRejectsAnEphemeralListenPort covers AC-001.2.
//
// Port 0 asks the kernel to choose, which is useful to a test holding the
// listener and useless to a deployment: nothing can route to a port that is
// only discoverable by reading a log line.
func TestLoadRejectsAnEphemeralListenPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{
			name: "application listener",
			env:  map[string]string{"SERVICE_DB_DSN": testDSN, "SERVICE_SERVER_ADDR": "0.0.0.0:0"},
			want: []string{"SERVICE_SERVER_ADDR"},
		},
		{
			name: "administrative listener",
			env:  map[string]string{"SERVICE_DB_DSN": testDSN, "SERVICE_ADMIN_ADDR": "[::1]:0"},
			want: []string{"SERVICE_ADMIN_ADDR"},
		},
		{
			name: "both listeners are reported together",
			env: map[string]string{
				"SERVICE_DB_DSN":      testDSN,
				"SERVICE_SERVER_ADDR": "127.0.0.1:0",
				"SERVICE_ADMIN_ADDR":  "127.0.0.1:0",
			},
			want: []string{"SERVICE_SERVER_ADDR", "SERVICE_ADMIN_ADDR"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(t.Context(), envconfig.MapLookuper(tt.env), "1.2.3")
			if err == nil {
				t.Fatalf("Load() error = nil, want a failure; got %+v", got)
			}

			for _, name := range tt.want {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("Load() error = %q, want it to name %s", err, name)
				}
			}
		})
	}
}

// TestLoadRequiresTheReadTimeoutToCoverTheHeaderTimeout covers AC-001.2.
//
// ReadTimeout bounds the whole request and ReadHeaderTimeout bounds its
// headers, so a ReadTimeout below it retires the header timeout without
// saying so: the total deadline always fires first, and the setting that
// exists to stop a slow-header client stops nothing.
func TestLoadRequiresTheReadTimeoutToCoverTheHeaderTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		env        map[string]string
		wantFailed bool
	}{
		{
			name: "read timeout below the header timeout",
			env: map[string]string{
				"SERVICE_DB_DSN":                     testDSN,
				"SERVICE_SERVER_READ_HEADER_TIMEOUT": "5s",
				"SERVICE_SERVER_READ_TIMEOUT":        "2s",
			},
			wantFailed: true,
		},
		{
			name: "read timeout equal to the header timeout",
			env: map[string]string{
				"SERVICE_DB_DSN":                     testDSN,
				"SERVICE_SERVER_READ_HEADER_TIMEOUT": "5s",
				"SERVICE_SERVER_READ_TIMEOUT":        "5s",
			},
			wantFailed: false,
		},
		{
			name: "read timeout above the header timeout",
			env: map[string]string{
				"SERVICE_DB_DSN":                     testDSN,
				"SERVICE_SERVER_READ_HEADER_TIMEOUT": "5s",
				"SERVICE_SERVER_READ_TIMEOUT":        "30s",
			},
			wantFailed: false,
		},
		{
			name:       "the administrative listener is held to the same rule",
			env:        map[string]string{"SERVICE_DB_DSN": testDSN, "SERVICE_ADMIN_READ_TIMEOUT": "1s"},
			wantFailed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(t.Context(), envconfig.MapLookuper(tt.env), "1.2.3")

			if tt.wantFailed {
				if err == nil {
					t.Fatalf("Load() error = nil, want a failure; got %+v", got)
				}

				if !strings.Contains(err.Error(), "ReadTimeout") {
					t.Errorf("Load() error = %q, want it to name the failing field", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want the timeouts accepted", err)
			}
		})
	}
}

// TestLoadRequiresTheHandlerTimeoutToFitInsideTheWriteTimeout covers AC-001.2.
//
// Both deadlines start when the handler does, and the handler timeout works by
// cancelling a context the handler must then act on. A handler timeout at or
// above the write timeout therefore cannot produce an outcome anyone sees: the
// connection's write deadline has already expired by the time the cancellation
// is observed.
func TestLoadRequiresTheHandlerTimeoutToFitInsideTheWriteTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		env        map[string]string
		wantFailed bool
	}{
		{
			name:       "disabled",
			env:        map[string]string{"SERVICE_DB_DSN": testDSN, "SERVICE_SERVER_HANDLER_TIMEOUT": "0s"},
			wantFailed: false,
		},
		{
			name:       "inside the write timeout",
			env:        map[string]string{"SERVICE_DB_DSN": testDSN, "SERVICE_SERVER_HANDLER_TIMEOUT": "10s"},
			wantFailed: false,
		},
		{
			name:       "equal to the write timeout",
			env:        map[string]string{"SERVICE_DB_DSN": testDSN, "SERVICE_SERVER_HANDLER_TIMEOUT": "30s"},
			wantFailed: true,
		},
		{
			name:       "beyond the write timeout",
			env:        map[string]string{"SERVICE_DB_DSN": testDSN, "SERVICE_SERVER_HANDLER_TIMEOUT": "60s"},
			wantFailed: true,
		},
		{
			name:       "negative",
			env:        map[string]string{"SERVICE_DB_DSN": testDSN, "SERVICE_SERVER_HANDLER_TIMEOUT": "-1s"},
			wantFailed: true,
		},
		{
			name:       "the administrative listener is held to the same rule",
			env:        map[string]string{"SERVICE_DB_DSN": testDSN, "SERVICE_ADMIN_HANDLER_TIMEOUT": "45s"},
			wantFailed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(t.Context(), envconfig.MapLookuper(tt.env), "1.2.3")

			if tt.wantFailed {
				if err == nil {
					t.Fatalf("Load() error = nil, want a failure; got %+v", got)
				}

				if !strings.Contains(err.Error(), "HandlerTimeout") {
					t.Errorf("Load() error = %q, want it to name the failing field", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want the handler timeout accepted", err)
			}
		})
	}
}

// TestListenAddressesNamesEachVariableFromItsTags covers AC-001.2.
//
// The names below are the ones README.md and .env.example tell an operator to
// export. They are derived from the struct tags rather than written into the
// validator, so this is what catches a renamed prefix or address field turning
// the startup message into advice about a variable that does not exist.
func TestListenAddressesNamesEachVariableFromItsTags(t *testing.T) {
	t.Parallel()

	cfg := Default()

	got, err := cfg.listenAddresses()
	if err != nil {
		t.Fatalf("listenAddresses() error = %v, want nil", err)
	}

	want := []listenAddress{
		{variable: "SERVICE_SERVER_ADDR", addr: cfg.Server.Addr},
		{variable: "SERVICE_ADMIN_ADDR", addr: cfg.Admin.Addr},
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(listenAddress{})); diff != "" {
		t.Errorf("listenAddresses() mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadReportsMistakesInSeparateSettingsGroupsTogether covers AC-001.2.
//
// The trusted-CIDR list is checked by the proxy package's own hook and the
// listen ports by the hook over the composed configuration. Neither gates the
// other, so an operator writing an environment block from scratch is told
// about both at once instead of finding the second one after fixing the first
// and restarting.
func TestLoadReportsMistakesInSeparateSettingsGroupsTogether(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":              testDSN,
		"SERVICE_PROXY_TRUSTED_CIDRS": "not-a-cidr",
		"SERVICE_SERVER_ADDR":         "127.0.0.1:0",
	}), "1.2.3")
	if err == nil {
		t.Fatalf("Load() error = nil, want a failure; got %+v", got)
	}

	for _, want := range []string{"SERVICE_PROXY_", "SERVICE_SERVER_ADDR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Load() error = %q, want it to name %s", err, want)
		}
	}
}

// TestLoadRequiresDatabaseDSN covers AC-001.2's counterpart for the database:
// there is no default DSN, so an operator who forgets it is stopped at
// startup rather than served against whatever the driver happens to pick.
//
// An entirely empty DSN fails store.Config's own `validate:"required"` struct
// tag, which go-playground/validator reports before any CustomValidator hook
// runs (Decode's validate.Struct gates everything after it), so the message
// here names the Go field path (Config.Database.DSN) rather than the
// environment variable; the variable name is what the operator sees once the
// DSN is merely invalid rather than absent, covered below.
func TestLoadRequiresDatabaseDSN(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{}), "1.2.3")
	if err == nil {
		t.Fatalf("Load() error = nil, want a failure; got %+v", got)
	}

	if !strings.Contains(err.Error(), "Database") || !strings.Contains(err.Error(), "DSN") {
		t.Errorf("Load() error = %q, want it to name the database DSN setting", err)
	}
}

// TestLoadRejectsADSNThatDoesNotParseWithoutPrintingIt covers the rule that
// an unparseable DSN fails naming the variable without echoing the DSN
// itself, which would otherwise leak the password it carries.
// Covers AC-001.26.
func TestLoadRejectsADSNThatDoesNotParseWithoutPrintingIt(t *testing.T) {
	t.Parallel()

	badDSN := "postgres://user:" + leakCanary + "@host:notaport/db"

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN": badDSN,
	}), "1.2.3")
	if err == nil {
		t.Fatalf("Load() error = nil, want a failure; got %+v", got)
	}

	if !strings.Contains(err.Error(), "SERVICE_DB_") {
		t.Errorf("Load() error = %q, want it to name the database settings", err)
	}

	if strings.Contains(err.Error(), leakCanary) {
		t.Errorf("Load() error = %q, want it not to echo the DSN", err)
	}
}

// TestLoadFillsOneOIDCProviderFromItsVariables cites no criterion: it
// constrains configuration loading, the fifth exception in CLAUDE.md's Testing Standards. At the Load level, SERVICE_AUTH_OIDC_PROVIDERS names a
// provider whose three required variables produce a filled-in provider.
func TestLoadFillsOneOIDCProviderFromItsVariables(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":                         testDSN,
		"SERVICE_AUTH_PUBLIC_ORIGIN":             "https://service.example",
		"SERVICE_AUTH_OIDC_PROVIDERS":            "google",
		"SERVICE_AUTH_OIDC_GOOGLE_ISSUER":        "https://accounts.google.com",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID":     "client-123",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_SECRET": leakCanary,
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if len(got.Auth.Providers) != 1 {
		t.Fatalf("len(Auth.Providers) = %d, want 1", len(got.Auth.Providers))
	}

	provider := got.Auth.Providers[0]
	if provider.Issuer != "https://accounts.google.com" {
		t.Errorf("Issuer = %q, want the configured issuer", provider.Issuer)
	}
	if provider.ClientID != "client-123" {
		t.Errorf("ClientID = %q, want the configured client id", provider.ClientID)
	}
	if provider.DisplayName != "Google" {
		t.Errorf("DisplayName = %q, want the title-cased key", provider.DisplayName)
	}
}

// TestLoadFailsNamingTheProviderMissingItsClientSecret covers the rule that
// LoadProviders stops the process at startup, naming the key, rather than
// surfacing the gap as a failed login later.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestLoadFailsNamingTheProviderMissingItsClientSecret(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":                     testDSN,
		"SERVICE_AUTH_PUBLIC_ORIGIN":         "https://service.example",
		"SERVICE_AUTH_OIDC_PROVIDERS":        "google",
		"SERVICE_AUTH_OIDC_GOOGLE_ISSUER":    "https://accounts.google.com",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID": "client-123",
	}), "1.2.3")
	if err == nil {
		t.Fatalf("Load() error = nil, want a failure; got %+v", got)
	}

	if !strings.Contains(err.Error(), "google") {
		t.Errorf("Load() error = %q, want it to name %q", err, "google")
	}
}

// TestLoadRejectsOTPEnabledWithoutMail covers the cross-group rule that
// registering the email-code routes without mail delivery enabled would
// register routes that could never send the code they promise.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestLoadRejectsOTPEnabledWithoutMail(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":             testDSN,
		"SERVICE_AUTH_PUBLIC_ORIGIN": "https://service.example",
		"SERVICE_AUTH_OTP_ENABLED":   "true",
		"SERVICE_SMTP_ENABLED":       "false",
	}), "1.2.3")
	if err == nil {
		t.Fatalf("Load() error = nil, want a failure; got %+v", got)
	}

	for _, want := range []string{"SERVICE_AUTH_OTP_ENABLED", "SERVICE_SMTP_ENABLED"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Load() error = %q, want it to name %s", err, want)
		}
	}
}

// TestLoadRejectsAHostCookieThatIsNotSecure covers AC-008.41: the __Host-
// cookie prefix requires Secure, which is session.Config's own hook. This
// test exercises it through Load rather than duplicating it in
// Config.Validate.
func TestLoadRejectsAHostCookieThatIsNotSecure(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":                testDSN,
		"SERVICE_SESSION_COOKIE_SECURE": "false",
	}), "1.2.3")
	if err == nil {
		t.Fatalf("Load() error = nil, want a failure; got %+v", got)
	}

	for _, want := range []string{"SERVICE_SESSION_", "CookieSecure"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Load() error = %q, want it to name %s", err, want)
		}
	}
}

// TestLoadRejectsIdleTimeoutExceedingAbsoluteTimeout covers the rule that a
// session's idle expiry must be reachable before its hard lifetime, which is
// session.Config's own hook. Tested through Load per the same rule as above.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestLoadRejectsIdleTimeoutExceedingAbsoluteTimeout(t *testing.T) {
	t.Parallel()

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":                   testDSN,
		"SERVICE_SESSION_IDLE_TIMEOUT":     "100h",
		"SERVICE_SESSION_ABSOLUTE_TIMEOUT": "10h",
	}), "1.2.3")
	if err == nil {
		t.Fatalf("Load() error = nil, want a failure; got %+v", got)
	}

	if !strings.Contains(err.Error(), "IdleTimeout") {
		t.Errorf("Load() error = %q, want it to name IdleTimeout", err)
	}
}

// TestLoadRequiresHTTPSPublicOriginWhenCookieSecure covers the cross-group
// rule that a Secure session cookie, which a browser never sends back over
// plain http, and a non-https PublicOrigin cannot coexist.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestLoadRequiresHTTPSPublicOriginWhenCookieSecure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cookieSecure string
		wantFailed   bool
	}{
		{name: "Secure cookie with an http origin fails", cookieSecure: "true", wantFailed: true},
		{name: "an http origin is fine once Secure is disabled", cookieSecure: "false", wantFailed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
				"SERVICE_DB_DSN":                testDSN,
				"SERVICE_AUTH_PUBLIC_ORIGIN":    "http://service.example",
				"SERVICE_SESSION_COOKIE_SECURE": tt.cookieSecure,
				// A plain, non-__Host- cookie name isolates this test's rule
				// from session.Config's own __Host-/Secure rule, which fires
				// on the default cookie name whenever Secure is false.
				"SERVICE_SESSION_COOKIE_NAME": "service_session",
			}), "1.2.3")

			if tt.wantFailed {
				if err == nil {
					t.Fatalf("Load() error = nil, want a failure; got %+v", got)
				}

				for _, want := range []string{"SERVICE_AUTH_PUBLIC_ORIGIN", "SERVICE_SESSION_COOKIE_SECURE"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("Load() error = %q, want it to name %s", err, want)
					}
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
		})
	}
}

// TestLoadRejectsNegativeDeletedGracePeriodWhileZeroIsAccepted covers the
// rule that DeletedGracePeriod must not be negative, at the Load level,
// while zero -- immediate purge -- passes.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestLoadRejectsNegativeDeletedGracePeriodWhileZeroIsAccepted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		period     string
		wantFailed bool
	}{
		{name: "negative", period: "-1h", wantFailed: true},
		{name: "zero", period: "0s", wantFailed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
				"SERVICE_DB_DSN":                    testDSN,
				"SERVICE_AUTH_DELETED_GRACE_PERIOD": tt.period,
			}), "1.2.3")

			if tt.wantFailed {
				if err == nil {
					t.Fatalf("Load() error = nil, want a failure; got %+v", got)
				}

				if !strings.Contains(err.Error(), "SERVICE_AUTH_DELETED_GRACE_PERIOD") {
					t.Errorf("Load() error = %q, want it to name SERVICE_AUTH_DELETED_GRACE_PERIOD", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
		})
	}
}

// TestLoadedConfigJSONNeverContainsAPlaintextSecret covers AC-008.40:
// marshalling the loaded configuration to JSON must never contain the
// database password, an OIDC client secret, or the SMTP password, even
// though every one of those was set on this Config.
func TestLoadedConfigJSONNeverContainsAPlaintextSecret(t *testing.T) {
	t.Parallel()

	const dbPassword = "db-" + leakCanary
	const smtpPassword = "smtp-" + leakCanary
	const oidcSecret = "oidc-" + leakCanary

	got, err := Load(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_DB_DSN":                         "postgres://user:" + dbPassword + "@localhost:5432/testdb",
		"SERVICE_AUTH_PUBLIC_ORIGIN":             "https://service.example",
		"SERVICE_AUTH_OIDC_PROVIDERS":            "google",
		"SERVICE_AUTH_OIDC_GOOGLE_ISSUER":        "https://accounts.google.com",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID":     "client-123",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_SECRET": oidcSecret,
		"SERVICE_SMTP_ENABLED":                   "true",
		"SERVICE_SMTP_HOST":                      "smtp.example.com",
		"SERVICE_SMTP_FROM":                      "noreply@example.com",
		"SERVICE_SMTP_PASSWORD":                  smtpPassword,
	}), "1.2.3")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	// Guard against the guard: if the provider never got loaded, the secret
	// was never in got at all and the test below would prove nothing.
	if len(got.Auth.Providers) != 1 || got.Auth.Providers[0].ClientSecret.Expose() != oidcSecret {
		t.Fatalf("Load() did not fill the oidc provider secret; got = %+v", got.Auth)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v, want nil", err)
	}

	dump := string(encoded)

	for _, secretValue := range []string{dbPassword, smtpPassword, oidcSecret} {
		if strings.Contains(dump, secretValue) {
			t.Errorf("marshalled config contains a plaintext secret %q: %s", secretValue, dump)
		}
	}
}
