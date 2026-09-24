package main

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sethvargo/go-envconfig"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/config"
)

// Tests here are deliberately not parallel: run installs the slog default and
// the OpenTelemetry SDK error handler, both of which are process-wide.

// freeAddr returns a loopback address with a port the kernel has just handed
// out and nothing is listening on.
//
// Port 0 would be the direct way to ask for an ephemeral port, but
// configuration refuses one: nothing can be told to route to a port that is
// only known once the bind has happened. The address is therefore resolved
// before configuration is loaded rather than by it.
func freeAddr(t *testing.T) string {
	t.Helper()

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}

	addr := listener.Addr().String()

	if closeErr := listener.Close(); closeErr != nil {
		t.Fatalf("releasing the reserved port: %v", closeErr)
	}

	return addr
}

// testEnv is an environment for a process that binds free loopback ports and
// drains without delay, so a test can start and stop the real wiring in the
// time an ordinary unit test is allowed.
//
// SERVICE_DB_DSN is a syntactically valid connection string that names
// nothing reachable. That is enough for the tests in this file: run now opens
// the database, so a test that needs a working process belongs in
// main_integration_test.go instead, against storetest's real Postgres.
// TestRunReportsAConfigurationFailure below never reaches that far -- it
// fails at configuration validation, before store.Open is ever called -- so
// the placeholder DSN only has to satisfy store.Config's syntax check.
//
// SERVICE_AUTH_PUBLIC_ORIGIN is set because AuthConfig.WebAuthnEnabled
// defaults to true and process wiring now refuses to start WebAuthn without
// a public origin to scope its relying party to. It is canonical and https, which
// Config.Validate requires whenever session.Config.CookieSecure -- also true
// by default -- is set.
func testEnv(t *testing.T) map[string]string {
	t.Helper()

	return map[string]string{
		"SERVICE_SERVER_ADDR":               freeAddr(t),
		"SERVICE_ADMIN_ADDR":                freeAddr(t),
		"SERVICE_LIFECYCLE_PRE_DRAIN_DELAY": "0s",
		"SERVICE_LOG_LEVEL":                 "error",
		"SERVICE_DB_DSN":                    "postgres://service@127.0.0.1:1/service?sslmode=disable",
		"SERVICE_AUTH_PUBLIC_ORIGIN":        "https://app.example.com",
	}
}

// TestRunReportsAConfigurationFailure covers AC-005.19.
func TestRunReportsAConfigurationFailure(t *testing.T) {
	env := testEnv(t)
	env["SERVICE_SERVER_ADDR"] = "not-a-host-port"

	// Returns before anything blocks, so an uncancelled context is safe here
	// and a regression that started the servers anyway would fail the test by
	// hanging rather than by passing quietly.
	err := run(t.Context(), make(chan os.Signal), envconfig.MapLookuper(env), func(code int) {
		t.Errorf("exit(%d) was called for a configuration failure", code)
	})
	if err == nil {
		t.Fatal("run returned nil for an invalid server address")
	}

	if !strings.Contains(err.Error(), "configuration") {
		t.Errorf("run returned %q, which does not name configuration as the failing stage", err)
	}
}

// webAuthnRPIDCase is one row of TestWebAuthnRPID.
type webAuthnRPIDCase struct {
	name         string
	rpidOverride string
	publicOrigin string
	want         string
	wantErr      bool
}

// TestWebAuthnRPID cites no criterion: specs/008-users-and-auth/requirements.md
// has no acceptance criterion naming the WebAuthn relying party ID or its
// derivation from SERVICE_AUTH_PUBLIC_ORIGIN (grepped for "relying party",
// "RP ID", and "webauthn", case-insensitive; none matched). This guards
// buildWebAuthn's own contract instead: a relying party ID that included a
// port would not match the one a browser computes for its passkey ceremony,
// silently breaking every passkey on any deployment reached through a
// non-default port.
func TestWebAuthnRPID(t *testing.T) {
	t.Parallel()

	cases := []webAuthnRPIDCase{
		{
			name:         "override wins over public origin",
			rpidOverride: "custom.example",
			publicOrigin: "https://app.example.com",
			want:         "custom.example",
		},
		{
			name:         "origin without a port gives its host",
			publicOrigin: "https://app.example.com",
			want:         "app.example.com",
		},
		{
			name:         "origin with a port gives the host without the port",
			publicOrigin: "https://app.example.com:8443",
			want:         "app.example.com",
		},
		{
			name:         "unparseable origin returns an error",
			publicOrigin: "https://example.com/%zz",
			wantErr:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.AuthConfig{
				WebAuthnRPID: tc.rpidOverride,
				PublicOrigin: tc.publicOrigin,
			}

			got, err := webAuthnRPID(cfg)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("webAuthnRPID(%+v) returned nil error, want one", cfg)
				}

				return
			}

			if err != nil {
				t.Fatalf("webAuthnRPID(%+v) returned error %v, want nil", cfg, err)
			}

			if got != tc.want {
				t.Errorf("webAuthnRPID(%+v) = %q, want %q", cfg, got, tc.want)
			}
		})
	}
}

// reapSpy is a rateLimitReaper that reports each call to Reap on a channel,
// so a test can synchronize on it without sleeping or polling.
type reapSpy struct {
	called chan time.Duration
}

// Reap records idle on s.called.
func (s *reapSpy) Reap(idle time.Duration) {
	s.called <- idle
}

// TestReapRateLimiterReapsOnEveryTick cites no criterion: it guards the
// process-wiring loop that keeps the authentication rate limiter's bucket map
// from growing without bound, which no acceptance criterion states directly.
func TestReapRateLimiterReapsOnEveryTick(t *testing.T) {
	t.Parallel()

	tick := make(chan time.Time, 1)
	spy := &reapSpy{called: make(chan time.Duration, 1)}

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- reapRateLimiter(ctx, spy, tick)
	}()

	tick <- time.Now()

	select {
	case idle := <-spy.called:
		if idle != rateLimiterReapIdleThreshold {
			t.Errorf("Reap called with idle %v, want %v", idle, rateLimiterReapIdleThreshold)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reapRateLimiter did not call Reap after a tick")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reapRateLimiter returned error %v, want nil on context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reapRateLimiter did not return after its context was cancelled")
	}
}

// TestWarnIfSignupUnreachableUsesEffectiveSetting covers AC-008.74: the
// warning must reflect the effective signup policy -- environment override
// folded into the database row by settings.Store.Load -- rather than only the
// environment override, since a database signup_enabled=false with no
// bootstrap administrator configured is exactly as unreachable as an
// environment override would be.
func TestWarnIfSignupUnreachableUsesEffectiveSetting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		signupEnabled        bool
		bootstrapAdminEmails []string
		wantWarning          bool
	}{
		{
			name:                 "signup disabled and no bootstrap admin",
			signupEnabled:        false,
			bootstrapAdminEmails: nil,
			wantWarning:          true,
		},
		{
			name:                 "signup enabled",
			signupEnabled:        true,
			bootstrapAdminEmails: nil,
			wantWarning:          false,
		},
		{
			name:                 "signup disabled but a bootstrap admin is configured",
			signupEnabled:        false,
			bootstrapAdminEmails: []string{"admin@example.com"},
			wantWarning:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core, observed := observer.New(zap.WarnLevel)

			warnIfSignupUnreachable(zap.New(core), tt.signupEnabled, tt.bootstrapAdminEmails)

			entries := observed.FilterMessage("signup is disabled and no bootstrap admin is configured: no account can ever be created").All()
			if tt.wantWarning && len(entries) != 1 {
				t.Errorf("got %d warning entries, want 1", len(entries))
			}
			if !tt.wantWarning && len(entries) != 0 {
				t.Errorf("got %d warning entries, want 0", len(entries))
			}
		})
	}
}

// TestUTCNowIsUTC cites no criterion: it pins a build-level invariant of
// process wiring -- the clock every write and comparison shares one location
// -- rather than a request-observable behavior, which the repo's test rules
// exempt.
func TestUTCNowIsUTC(t *testing.T) {
	t.Parallel()

	if loc := utcNow().Location(); loc != time.UTC {
		t.Errorf("utcNow().Location() = %v, want %v", loc, time.UTC)
	}
}
