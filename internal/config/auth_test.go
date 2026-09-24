package config

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sethvargo/go-envconfig"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// TestDefaultAuthConfigMatchesTheDocumentedDefaults is a zero-value contract
// test: it pins every field DefaultAuthConfig sets so a change to any of them
// is visible here rather than discovered downstream.
// It cites no criterion: it guards an exported contract's behavior on a zero
// value, the first exception in CLAUDE.md's Testing Standards.
func TestDefaultAuthConfigMatchesTheDocumentedDefaults(t *testing.T) {
	t.Parallel()

	got := DefaultAuthConfig()

	want := AuthConfig{
		PublicOrigin:            "",
		OIDCProviders:           nil,
		WebAuthnEnabled:         true,
		WebAuthnRPID:            "",
		WebAuthnRPDisplayName:   "service",
		OTPEnabled:              false,
		OTPCodeTTL:              configtype.Duration(10 * time.Minute),
		OTPMaxAttempts:          5,
		FlowTTL:                 configtype.Duration(10 * time.Minute),
		RateLimitPerMinute:      10,
		RateLimitBurst:          20,
		BootstrapAdminEmails:    nil,
		SignupEnabled:           nil,
		InviteTokenBytes:        32,
		InviteRetainAfterExpiry: configtype.Duration(2160 * time.Hour),
		InviteMaxTTL:            configtype.Duration(336 * time.Hour),
		InviteDefaultMaxUses:    1,
		DeletedGracePeriod:      configtype.Duration(720 * time.Hour),
		Providers:               nil,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("DefaultAuthConfig() mismatch (-want +got):\n%s", diff)
	}
}

// TestDefaultAuthConfigInviteLimits covers AC-008.80 and AC-008.81: the
// invite lifetime ceiling defaults to 336h and the default redemption limit
// defaults to 1, and an operator override that empties either one out fails
// validation rather than silently taking effect.
func TestDefaultAuthConfigInviteLimits(t *testing.T) {
	t.Parallel()

	cfg := DefaultAuthConfig()

	if cfg.InviteMaxTTL.Duration() != 336*time.Hour {
		t.Errorf("DefaultAuthConfig().InviteMaxTTL = %v, want 336h", cfg.InviteMaxTTL.Duration())
	}

	if cfg.InviteDefaultMaxUses != 1 {
		t.Errorf("DefaultAuthConfig().InviteDefaultMaxUses = %d, want 1", cfg.InviteDefaultMaxUses)
	}

	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "invite max ttl of zero", env: map[string]string{"SERVICE_AUTH_INVITE_MAX_TTL": "0s"}},
		{name: "invite default max uses of zero", env: map[string]string{"SERVICE_AUTH_INVITE_DEFAULT_MAX_USES": "0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wrapper := struct {
				Auth AuthConfig `env:", prefix=SERVICE_AUTH_"`
			}{Auth: DefaultAuthConfig()}

			err := Decode(t.Context(), &wrapper, envconfig.MapLookuper(tt.env))
			if err == nil {
				t.Fatal("Decode() error = nil, want a validation failure")
			}
		})
	}
}

// TestAuthConfigValidateAcceptsTheDefaults cites no criterion: it constrains
// configuration validation, a mistake reachable only from a deployment's own
// configuration, the fifth exception in CLAUDE.md's Testing Standards. The
// zero-configuration case (WebAuthn enabled, nothing else) is not itself an
// error, since WebAuthn does not need a static PublicOrigin the way OTP and
// OIDC do.
func TestAuthConfigValidateAcceptsTheDefaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultAuthConfig()

	if err := cfg.Validate(t.Context()); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

// TestAuthConfigValidateRequiresPublicOriginForOTPOrOIDC cites no criterion:
// it constrains a mistake reachable only from a deployment's own
// configuration, the fifth exception in CLAUDE.md's Testing Standards. OTP and OIDC both promise a static callback address, so
// enabling either without PublicOrigin is rejected.
func TestAuthConfigValidateRequiresPublicOriginForOTPOrOIDC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  AuthConfig
	}{
		{
			name: "OTP enabled without PublicOrigin",
			cfg: func() AuthConfig {
				cfg := DefaultAuthConfig()
				cfg.OTPEnabled = true

				return cfg
			}(),
		},
		{
			name: "an OIDC provider configured without PublicOrigin",
			cfg: func() AuthConfig {
				cfg := DefaultAuthConfig()
				cfg.OIDCProviders = []string{"google"}

				return cfg
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate(t.Context())
			if err == nil {
				t.Fatal("Validate() error = nil, want a failure")
			}

			if !strings.Contains(err.Error(), "SERVICE_AUTH_PUBLIC_ORIGIN") {
				t.Errorf("Validate() error = %q, want it to name SERVICE_AUTH_PUBLIC_ORIGIN", err)
			}
		})
	}
}

// TestAuthConfigValidatePublicOriginCanonicalForm covers the orchestrator
// amendment on PublicOrigin's canonical form: scheme://host[:port] exactly,
// whether or not any method is enabled, because a browser's Origin header
// arrives in exactly this shape and is compared to it byte-for-byte.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestAuthConfigValidatePublicOriginCanonicalForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		origin  string
		wantErr bool
	}{
		{name: "https with no port", origin: "https://app.example.com", wantErr: false},
		{name: "http with an explicit port", origin: "http://localhost:8080", wantErr: false},
		{name: "https with a non-default port", origin: "https://app.example.com:8443", wantErr: false},
		{name: "trailing slash", origin: "https://app.example.com/", wantErr: true},
		{name: "a path", origin: "https://app.example.com/path", wantErr: true},
		{name: "upper-case scheme", origin: "HTTPS://App.example.com", wantErr: true},
		{name: "upper-case host", origin: "https://App.example.com", wantErr: true},
		{name: "the https default port spelled out", origin: "https://app.example.com:443", wantErr: true},
		{name: "the http default port spelled out", origin: "http://app.example.com:80", wantErr: true},
		{name: "userinfo", origin: "https://u@h", wantErr: true},
		{name: "a bare query", origin: "https://app.example.com?q", wantErr: true},
		{name: "a bare fragment", origin: "https://app.example.com#f", wantErr: true},
		{name: "an unsupported scheme", origin: "ftp://h", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := DefaultAuthConfig()
			cfg.PublicOrigin = tt.origin

			err := cfg.Validate(t.Context())
			if tt.wantErr && err == nil {
				t.Fatalf("Validate() error = nil for %q, want a failure", tt.origin)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() error = %v for %q, want nil", err, tt.origin)
			}

			if tt.wantErr && !strings.Contains(err.Error(), "SERVICE_AUTH_PUBLIC_ORIGIN") {
				t.Errorf("Validate() error = %q, want it to name SERVICE_AUTH_PUBLIC_ORIGIN", err)
			}
		})
	}
}

// TestAuthConfigValidateRejectsNegativeDeletedGracePeriod covers the rule
// that DeletedGracePeriod must not be negative, while zero -- immediate
// purge -- is accepted.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestAuthConfigValidateRejectsNegativeDeletedGracePeriod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		period  configtype.Duration
		wantErr bool
	}{
		{name: "negative", period: configtype.Duration(-time.Second), wantErr: true},
		{name: "zero", period: 0, wantErr: false},
		{name: "positive", period: configtype.Duration(time.Hour), wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := DefaultAuthConfig()
			cfg.DeletedGracePeriod = tt.period

			err := cfg.Validate(t.Context())
			if tt.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want a failure")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}

			if tt.wantErr && !strings.Contains(err.Error(), "SERVICE_AUTH_DELETED_GRACE_PERIOD") {
				t.Errorf("Validate() error = %q, want it to name SERVICE_AUTH_DELETED_GRACE_PERIOD", err)
			}
		})
	}
}

// TestAuthConfigValidateRejectsNegativeInviteRetainAfterExpiry covers the
// rule that InviteRetainAfterExpiry must not be negative.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestAuthConfigValidateRejectsNegativeInviteRetainAfterExpiry(t *testing.T) {
	t.Parallel()

	cfg := DefaultAuthConfig()
	cfg.InviteRetainAfterExpiry = configtype.Duration(-time.Second)

	err := cfg.Validate(t.Context())
	if err == nil {
		t.Fatal("Validate() error = nil, want a failure")
	}

	if !strings.Contains(err.Error(), "SERVICE_AUTH_INVITE_RETAIN_AFTER_EXPIRY") {
		t.Errorf("Validate() error = %q, want it to name SERVICE_AUTH_INVITE_RETAIN_AFTER_EXPIRY", err)
	}
}

// TestAuthConfigValidateRejectsNoAuthenticationMethod covers AC-008.85: a
// deployment that enables none of OTP, an OIDC provider, or WebAuthn would
// start a service nobody can sign in to, so Validate refuses it and names
// every variable that would enable a method. Any one method enabled passes.
func TestAuthConfigValidateRejectsNoAuthenticationMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     AuthConfig
		wantErr bool
	}{
		{
			name: "no method enabled",
			cfg: func() AuthConfig {
				cfg := DefaultAuthConfig()
				cfg.WebAuthnEnabled = false

				return cfg
			}(),
			wantErr: true,
		},
		{
			name: "webauthn enabled",
			cfg: func() AuthConfig {
				cfg := DefaultAuthConfig()
				cfg.WebAuthnEnabled = true

				return cfg
			}(),
			wantErr: false,
		},
		{
			name: "otp enabled",
			cfg: func() AuthConfig {
				cfg := DefaultAuthConfig()
				cfg.WebAuthnEnabled = false
				cfg.OTPEnabled = true
				cfg.PublicOrigin = "https://app.example.com"

				return cfg
			}(),
			wantErr: false,
		},
		{
			name: "an oidc provider enabled",
			cfg: func() AuthConfig {
				cfg := DefaultAuthConfig()
				cfg.WebAuthnEnabled = false
				cfg.OIDCProviders = []string{"google"}
				cfg.PublicOrigin = "https://app.example.com"

				return cfg
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate(t.Context())
			if tt.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want a failure")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}

			if tt.wantErr {
				for _, variable := range []string{
					"SERVICE_AUTH_OIDC_PROVIDERS",
					"SERVICE_AUTH_WEBAUTHN_ENABLED",
					"SERVICE_AUTH_OTP_ENABLED",
				} {
					if !strings.Contains(err.Error(), variable) {
						t.Errorf("Validate() error = %q, want it to name %q", err, variable)
					}
				}
			}
		})
	}
}

// TestLoadProvidersFillsOneProviderFromItsVariables cites no criterion: it
// constrains configuration loading, the fifth exception in CLAUDE.md's Testing Standards. The provider's secret is read without ever being logged or
// exposed, and its issuer, client id, and display name come through intact.
func TestLoadProvidersFillsOneProviderFromItsVariables(t *testing.T) {
	t.Parallel()

	cfg := AuthConfig{OIDCProviders: []string{"google"}}

	err := cfg.LoadProviders(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_AUTH_OIDC_GOOGLE_ISSUER":        "https://accounts.google.com",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID":     "client-123",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_SECRET": leakCanary,
	}))
	if err != nil {
		t.Fatalf("LoadProviders() error = %v, want nil", err)
	}

	if len(cfg.Providers) != 1 {
		t.Fatalf("len(Providers) = %d, want 1", len(cfg.Providers))
	}

	got := cfg.Providers[0]

	if got.Issuer != "https://accounts.google.com" {
		t.Errorf("Issuer = %q, want the configured issuer", got.Issuer)
	}
	if got.ClientID != "client-123" {
		t.Errorf("ClientID = %q, want the configured client id", got.ClientID)
	}
	if got.DisplayName != "Google" {
		t.Errorf("DisplayName = %q, want the title-cased key", got.DisplayName)
	}
	if got.ClientSecret.Expose() != leakCanary {
		t.Errorf("ClientSecret.Expose() = %q, want the configured secret", got.ClientSecret.Expose())
	}
	if diff := cmp.Diff(defaultProviderScopes, got.Scopes); diff != "" {
		t.Errorf("Scopes mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadProvidersHonoursScopesAndDisplayNameOverrides covers the two
// per-provider variables that have defaults: an explicit value wins over
// both.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestLoadProvidersHonoursScopesAndDisplayNameOverrides(t *testing.T) {
	t.Parallel()

	cfg := AuthConfig{OIDCProviders: []string{"google"}}

	err := cfg.LoadProviders(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_AUTH_OIDC_GOOGLE_ISSUER":        "https://accounts.google.com",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID":     "client-123",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_SECRET": leakCanary,
		"SERVICE_AUTH_OIDC_GOOGLE_SCOPES":        "openid, groups",
		"SERVICE_AUTH_OIDC_GOOGLE_DISPLAY_NAME":  "Company Google",
	}))
	if err != nil {
		t.Fatalf("LoadProviders() error = %v, want nil", err)
	}

	got := cfg.Providers[0]

	want := []string{"openid", "groups"}
	if diff := cmp.Diff(want, got.Scopes); diff != "" {
		t.Errorf("Scopes mismatch (-want +got):\n%s", diff)
	}

	if got.DisplayName != "Company Google" {
		t.Errorf("DisplayName = %q, want the configured override", got.DisplayName)
	}
}

// TestLoadProvidersFailsNamingTheKeyMissingAVariable covers the rule that a
// missing required per-provider variable stops the process at startup by
// naming which provider it is missing from.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestLoadProvidersFailsNamingTheKeyMissingAVariable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "missing issuer",
			env: map[string]string{
				"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID":     "client-123",
				"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_SECRET": leakCanary,
			},
		},
		{
			name: "missing client id",
			env: map[string]string{
				"SERVICE_AUTH_OIDC_GOOGLE_ISSUER":        "https://accounts.google.com",
				"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_SECRET": leakCanary,
			},
		},
		{
			name: "missing client secret",
			env: map[string]string{
				"SERVICE_AUTH_OIDC_GOOGLE_ISSUER":    "https://accounts.google.com",
				"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID": "client-123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := AuthConfig{OIDCProviders: []string{"google"}}

			err := cfg.LoadProviders(t.Context(), envconfig.MapLookuper(tt.env))
			if err == nil {
				t.Fatal("LoadProviders() error = nil, want a failure")
			}

			if !strings.Contains(err.Error(), "google") {
				t.Errorf("LoadProviders() error = %q, want it to name %q", err, "google")
			}
		})
	}
}

// TestLoadProvidersFillsEveryConfiguredProvider is a zero-value/shape guard:
// LoadProviders must not silently drop or reorder a key from OIDCProviders.
// It cites no criterion: it constrains a mistake reachable only from a
// deployment's own configuration, the fifth exception in CLAUDE.md's Testing
// Standards.
func TestLoadProvidersFillsEveryConfiguredProvider(t *testing.T) {
	t.Parallel()

	cfg := AuthConfig{OIDCProviders: []string{"google", "okta"}}

	err := cfg.LoadProviders(t.Context(), envconfig.MapLookuper(map[string]string{
		"SERVICE_AUTH_OIDC_GOOGLE_ISSUER":        "https://accounts.google.com",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID":     "client-123",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_SECRET": leakCanary,
		"SERVICE_AUTH_OIDC_OKTA_ISSUER":          "https://example.okta.com",
		"SERVICE_AUTH_OIDC_OKTA_CLIENT_ID":       "okta-client",
		"SERVICE_AUTH_OIDC_OKTA_CLIENT_SECRET":   "okta-" + leakCanary,
	}))
	if err != nil {
		t.Fatalf("LoadProviders() error = %v, want nil", err)
	}

	if len(cfg.Providers) != 2 {
		t.Fatalf("len(Providers) = %d, want 2", len(cfg.Providers))
	}

	keys := []string{cfg.Providers[0].Key, cfg.Providers[1].Key}
	if diff := cmp.Diff([]string{"google", "okta"}, keys); diff != "" {
		t.Errorf("provider key order mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadProvidersIgnoresACancelledContext is the package-level regression
// for AC-005.19, which the entry point's clean start-and-shutdown test covers:
// configuration must still load when the process is interrupted before
// startup finishes. Every read here is from memory, so a cancelled
// context changes nothing, the same rule TestDecodeIgnoresACancelledContext
// pins for Decode.
func TestLoadProvidersIgnoresACancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	cfg := AuthConfig{OIDCProviders: []string{"google"}}

	err := cfg.LoadProviders(ctx, envconfig.MapLookuper(map[string]string{
		"SERVICE_AUTH_OIDC_GOOGLE_ISSUER":        "https://accounts.google.com",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID":     "client-123",
		"SERVICE_AUTH_OIDC_GOOGLE_CLIENT_SECRET": leakCanary,
	}))
	if err != nil {
		t.Fatalf("LoadProviders() error = %v, want nil", err)
	}

	if len(cfg.Providers) != 1 {
		t.Errorf("len(Providers) = %d, want 1", len(cfg.Providers))
	}
}
