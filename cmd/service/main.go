// Command service runs the HTTP server.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sethvargo/go-envconfig"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/otp"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/passkey"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authflow"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/buildinfo"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/config"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/httpclient"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/logging"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/mail"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/ratelimit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/signals"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/migrations"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/telemetry"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/web"
)

// version is the build's reported version, overridden at link time with
// -ldflags "-X main.version=...". It is reported as service.version in
// telemetry.
var version = "dev"

// commit is the short git hash the binary was built from, overridden at link
// time with -ldflags "-X main.commit=...".
var commit = "unknown"

// buildDate is when the binary was built, in RFC 3339, overridden at link time
// with -ldflags "-X main.buildDate=...".
var buildDate = "unknown"

// telemetryShutdownTimeout bounds the final trace flush so an unreachable
// collector cannot hold up process exit.
const telemetryShutdownTimeout = 5 * time.Second

// rateLimiterReapInterval is how often idle rate limiter buckets are
// discarded. Nothing in configuration exposes this.
const rateLimiterReapInterval = time.Minute

// rateLimiterReapIdleThreshold is how long a rate limiter bucket may sit
// unused before a reap discards it.
const rateLimiterReapIdleThreshold = 10 * time.Minute

// sessionHostCookiePrefix is the "__Host-" prefix a browser only accepts on a
// cookie that is Secure, sent over HTTPS, and carries no Domain attribute. It
// is what stops a compromised or malicious subdomain from setting or
// shadowing this service's session cookie.
const sessionHostCookiePrefix = "__Host-"

// databaseReadinessCheckName is the name the database's readiness probe is
// registered under, and what a failing GET /readyz response reports in its
// "failing" list.
const databaseReadinessCheckName = "database"

func main() {
	os.Exit(start())
}

// start installs the process signal handlers, runs the server, and returns the
// status the process should exit with.
//
// It is separate from main so that os.Exit runs after its deferred cleanup
// rather than skipping it.
func start() int {
	// Cancelled by the first interrupt or SIGTERM, which is what starts the
	// graceful shutdown sequence.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A channel of its own, because NotifyContext does not expose the one it
	// uses. Every channel registered for a signal receives it, so this one
	// sees the first signal too, which ForceExitOnSecond discards.
	//
	// Registered before any start-up work rather than next to the goroutine
	// that reads it, which cannot start until there is a logger: buffering
	// from this point means a signal arriving during start-up is not lost.
	// Sized for both signals, since nothing reads the channel until then.
	forced := make(chan os.Signal, 2)
	signal.Notify(forced, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(forced)

	// A nil lookuper reads the real process environment.
	if err := run(ctx, forced, nil, os.Exit); err != nil {
		fmt.Fprintf(os.Stderr, "service: %v\n", err)

		return 1
	}

	return 0
}

// run wires the process together and blocks until ctx is cancelled and the
// listeners have drained.
//
// Everything it does not create itself arrives as a parameter: the shutdown
// trigger as ctx, the second-signal channel as forced, the environment as
// lookuper, and process termination as exit. main supplies the real ones, and a
// test supplies its own to drive a whole start-up and shutdown without sending
// signals, mutating the environment, or terminating the test binary.
//
// It returns an error rather than calling os.Exit from deep in the call stack,
// which would skip deferred cleanup.
func run(ctx context.Context, forced <-chan os.Signal, lookuper envconfig.Lookuper, exit func(int)) error {
	// Taken before any start-up work, so what the version endpoint reports is
	// when the process began rather than when its last dependency finished
	// initialising.
	var started = time.Now()

	// Configuration is resolved first, because everything below is built from
	// it.
	cfg, err := config.Load(ctx, lookuper, version)
	if err != nil {
		// Returned unwrapped: Load already names both the operation and the
		// stage that failed, so another layer would only repeat itself.
		//nolint:wrapcheck // see comment above
		return err
	}

	logger, err := logging.NewFromConfig(cfg.Log)
	if err != nil {
		return fmt.Errorf("initialising logger: %w", err)
	}

	// Syncing a terminal-backed stderr returns EINVAL on Linux and macOS, so
	// the error carries no information worth acting on or reporting here.
	//nolint:errcheck // see comment above
	defer logger.Sync()

	logging.InstallSlogDefault(logger)

	var build = buildinfo.Info{Version: version, Commit: commit, Date: buildDate}

	build.Log(logger)
	config.LogEffective(logger, cfg)
	warnIfCookieMissingHostPrefix(logger, cfg.Session)

	go signals.ForceExitOnSecond(forced, logger, exit)

	ui, err := web.Handler()
	if err != nil {
		return fmt.Errorf("preparing frontend handler: %w", err)
	}

	proxies, err := server.NewTrustedProxies(cfg.Proxy)
	if err != nil {
		return fmt.Errorf("configuring trusted proxies: %w", err)
	}

	// One instance shared by both listeners and by the shutdown sequencer:
	// readiness is a property of the process, not of a socket. A dependency
	// this process cannot serve without is registered here with AddCheck, for
	// example ready.AddCheck("database", db.PingContext), and takes the
	// process out of rotation while it is unreachable.
	ready := server.NewReadiness()

	tracing, err := telemetry.SetupTracing(ctx, cfg.Telemetry, logger)
	if err != nil {
		return fmt.Errorf("initialising tracing: %w", err)
	}

	// Registered before metrics is set up, not after both: a failure there would
	// otherwise leave the tracing pipeline running with spans unflushed.
	defer shutDown(ctx, logger, "traces", tracing.Shutdown)

	metrics, err := telemetry.SetupMetrics(cfg.Telemetry, logger)
	if err != nil {
		return fmt.Errorf("initialising metrics: %w", err)
	}

	defer shutDown(ctx, logger, "metrics", metrics.Shutdown)

	if err = metrics.RecordBuildInfo(build); err != nil {
		return fmt.Errorf("recording build information: %w", err)
	}

	// The providers are handed to the instrumentation explicitly: nothing in
	// internal/server reads them from the otel package's globals.
	var instrumentation = server.Telemetry{
		TracerProvider: tracing.TracerProvider(),
		MeterProvider:  metrics.MeterProvider(),
		Propagator:     tracing.Propagator(),
	}

	// Startup is a bounded, one-time sequence: store.Open's own ping derives
	// its deadline from the context it is given rather than from
	// cfg.Database.ConnectTimeout alone, so passing ctx directly would make a
	// shutdown signalled during start-up fail the connection attempt outright
	// instead of letting ConnectTimeout decide. RunAll's own serveCtx makes
	// the same decoupling for the same reason: the shutdown trigger reaches
	// the listeners through drain, which holds them open for the pre-drain
	// delay first, not by cancelling work already under way. A second signal
	// remains the abort path, through signals.ForceExitOnSecond.
	startupCtx := context.WithoutCancel(ctx)

	handle, err := openAndMigrate(startupCtx, cfg.Database, logger)
	if err != nil {
		return err
	}

	defer handle.Close()

	now := utcNow

	userRepo := user.NewRepository(handle, now)
	sessionStore := session.NewStore(handle, cfg.Session, now)
	flows := authflow.NewStore(handle, cfg.Auth.FlowTTL.Duration(), now)
	recorder := audit.NewRecorder(handle, logger, now)
	rolesRepo := authz.NewRepository(handle, now)
	checker := authz.NewChecker(rolesRepo)
	limiter := ratelimit.New(cfg.Auth.RateLimitPerMinute, cfg.Auth.RateLimitBurst, now)

	// settingsStore comes before inviteService: the invite service reads its
	// limits through it.
	settingsStore := settings.NewStore(handle, settings.Options{
		SignupEnabledOverride: cfg.Auth.SignupEnabled,
		InviteMaxTTL:          cfg.Auth.InviteMaxTTL.Duration(),
		InviteDefaultMaxUses:  cfg.Auth.InviteDefaultMaxUses,
	}, logger, now)

	inviteService, err := invite.NewService(handle, settingsStore, cfg.Auth.InviteTokenBytes, logger, now)
	if err != nil {
		return fmt.Errorf("configuring invites: %w", err)
	}

	//nolint:contextcheck // buildMailSender's only context-lacking call is internal/mail.NewSMTPSender, which takes no context.
	mailSender, err := buildMailSender(cfg.Mail, logger)
	if err != nil {
		return err
	}

	providers, err := buildOIDCRegistry(cfg.Auth, flows, instrumentation, logger)
	if err != nil {
		return err
	}

	// Built unconditionally, unlike the passkey service itself, because
	// RouteDeps.Credentials backs the two credential self-service routes
	// registered regardless of whether WebAuthn is enabled.
	credentialsRepo := passkey.NewRepository(handle, now)

	passkeys, err := buildWebAuthn(cfg.Auth, credentialsRepo, flows, logger)
	if err != nil {
		return err
	}

	codes := buildOTPService(cfg.Auth, handle, mailSender, logger, now)

	logger.Info("authentication methods enabled",
		zap.Bool("webauthn", cfg.Auth.WebAuthnEnabled),
		zap.Bool("otp", cfg.Auth.OTPEnabled),
		zap.Int("oidc_providers", len(cfg.Auth.Providers)),
	)

	if signupErr := logSignupPolicy(startupCtx, logger, settingsStore, cfg.Auth); signupErr != nil {
		return signupErr
	}

	authService := auth.NewService(
		handle,
		userRepo,
		sessionStore,
		rolesRepo,
		checker,
		recorder,
		inviteService,
		settingsStore,
		cfg.Auth.BootstrapAdminEmails,
		logger,
		now,
		auth.AccountDeps{
			Credentials:        credentialsRepo,
			Providers:          providers,
			OTPEnabled:         cfg.Auth.OTPEnabled,
			DeletedGracePeriod: cfg.Auth.DeletedGracePeriod.Duration(),
		},
	)

	// The check borrows the pool store.Open already opened rather than
	// opening a new one: Ping is cheap and must not retry, per
	// server.Readiness's own contract.
	ready.AddCheck(databaseReadinessCheckName, func(checkCtx context.Context) error {
		return handle.Ping(checkCtx)
	})

	routeDeps := auth.RouteDeps{
		Sessions:     sessionStore,
		Providers:    providers,
		Passkeys:     passkeys,
		Codes:        codes,
		Users:        userRepo,
		Roles:        rolesRepo,
		Limiter:      limiter,
		Proxies:      proxies,
		Logger:       logger,
		PublicOrigin: cfg.Auth.PublicOrigin,
		CookieSecure: cfg.Session.CookieSecure,
		Credentials:  credentialsRepo,
		FlowTTL:      cfg.Auth.FlowTTL.Duration(),
	}

	api := func(mux *http.ServeMux) {
		authService.Routes(mux, routeDeps)
	}

	// Cross-site rejection and authentication are passed to NewMux as its own
	// middleware parameter rather than wrapping its result, so both run
	// inside the whole chain NewMux builds -- tracing, security headers,
	// request identity, request logging, panic recovery, the in-flight
	// limiter, the handler timeout, and the body limit -- instead of outside
	// all of it where a panic would go unrecovered and a rejection would
	// carry none of those headers. Cross-site rejection runs outermost of
	// the two, and authentication runs before any route handler; the
	// per-route rate limiter registered inside routeDeps still runs after
	// both, since a route's own handler sits behind everything NewMux is
	// given here. Neither wraps the administrative listener.
	appHandler := server.NewMux(cfg.Server, proxies, ready, logger, instrumentation, ui, api,
		func(next http.Handler) http.Handler {
			return auth.RejectCrossSite(cfg.Auth.PublicOrigin, cfg.Session.CookieName, logger, next)
		},
		func(next http.Handler) http.Handler {
			return authService.Authenticate(sessionStore, next)
		},
	)

	app := server.New(cfg.Server, logger, appHandler)
	var process = server.ProcessInfo{Build: build, Started: started}

	admin := server.New(cfg.Admin, logger, server.NewAdminMux(cfg.Admin, logger, ready, process, metrics.Handler()))

	sweeper := auth.NewSweeper(cfg.Session.CleanupInterval.Duration(), logger, sessionStore, flows, codes, inviteService, cfg.Auth.InviteRetainAfterExpiry.Duration(), authService)

	return runServers(ctx, cfg.Lifecycle, ready, logger, sweeper, limiter, app, admin)
}

// runServers runs the authentication sweeper, the rate limiter reaper, and
// both listeners concurrently under one errgroup, so a failure in any of them
// cancels the rest rather than leaving the process half up. It returns the
// first error reported, wrapped to name this as the stage that failed.
func runServers(ctx context.Context, cfg server.LifecycleConfig, ready *server.Readiness, logger *zap.Logger, sweeper *auth.Sweeper, limiter rateLimitReaper, app, admin *server.Server) error {
	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		return sweeper.Run(groupCtx)
	})

	group.Go(func() error {
		ticker := time.NewTicker(rateLimiterReapInterval)
		defer ticker.Stop()

		return reapRateLimiter(groupCtx, limiter, ticker.C)
	})

	group.Go(func() error {
		return server.RunAll(groupCtx, cfg, ready, logger, app, admin)
	})

	if err := group.Wait(); err != nil {
		return fmt.Errorf("running server: %w", err)
	}

	return nil
}

// rateLimitReaper is the subset of *ratelimit.Limiter that reapRateLimiter
// needs, so a test can substitute a spy without driving a real limiter's
// clock.
type rateLimitReaper interface {
	// Reap discards buckets untouched for longer than idle.
	Reap(idle time.Duration)
}

// reapRateLimiter calls limiter.Reap(rateLimiterReapIdleThreshold) each time
// tick fires, until ctx is cancelled, then returns nil. Nothing else in this
// process calls Reap, so without this loop the rate limiter accumulates one
// bucket per client address that has ever reached an authentication route for
// as long as the process runs.
func reapRateLimiter(ctx context.Context, limiter rateLimitReaper, tick <-chan time.Time) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick:
			limiter.Reap(rateLimiterReapIdleThreshold)
		}
	}
}

// openAndMigrate opens the database and, when cfg.MigrateOnStart is true,
// applies every pending migration and logs the resulting schema version. ctx
// should not be tied to the process shutdown signal: see run's own comment on
// startupCtx for why. On any failure it closes whatever it opened, since the
// caller receives no handle to defer-close.
func openAndMigrate(ctx context.Context, cfg store.Config, logger *zap.Logger) (*store.Handle, error) {
	// A service that cannot read its own accounts must not serve traffic, so a
	// failure here stops the process rather than continuing degraded.
	handle, err := store.Open(ctx, cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if !cfg.MigrateOnStart {
		return handle, nil
	}

	migrationDB := handle.SQLDB()

	applyErr := migrations.Apply(ctx, migrationDB, logger)

	var schemaVersion int64

	var versionErr error

	if applyErr == nil {
		schemaVersion, versionErr = migrations.Version(ctx, migrationDB)
	}

	// SQLDB's own doc comment: closing the *sql.DB it returns does not close
	// the pool underneath it, so handle stays open regardless of this error.
	closeErr := migrationDB.Close()

	migrateErr := errors.Join(applyErr, versionErr, closeErr)
	if migrateErr != nil {
		handle.Close()

		return nil, fmt.Errorf("applying database migrations: %w", migrateErr)
	}

	logger.Info("applied database migrations", zap.Int64("schema_version", schemaVersion))

	return handle, nil
}

// buildMailSender returns the SMTP sender when mail is enabled, and the
// disabled sender otherwise, both behind the same mail.Sender interface so
// every caller downstream is indifferent to which one it holds.
//
//nolint:ireturn // mail.Sender is the constructor pattern internal/mail itself uses: NewDisabledSender and NewSMTPSender both return it so callers stay indifferent to which one they hold.
func buildMailSender(cfg mail.Config, logger *zap.Logger) (mail.Sender, error) {
	if !cfg.Enabled {
		return mail.NewDisabledSender(), nil
	}

	smtpSender, err := mail.NewSMTPSender(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("configuring mail sender: %w", err)
	}

	return smtpSender, nil
}

// buildOIDCRegistry returns nil when no OpenID Connect provider is
// configured. Otherwise it builds the outbound HTTP client the registry
// needs through httpclient.New -- the only permitted way to obtain one, see
// the note below -- and returns the resulting registry.
func buildOIDCRegistry(cfg config.AuthConfig, flows *authflow.Store, tel server.Telemetry, logger *zap.Logger) (*oidc.Registry, error) {
	if len(cfg.Providers) == 0 {
		//nolint:nilnil // a nil registry with a nil error is "no providers configured", not a failure: RouteDeps.Providers's own doc comment treats a nil Providers as meaning the two OIDC routes are not registered.
		return nil, nil
	}

	// This is the only permitted way to obtain a client. A bare
	// &http.Client{} or http.DefaultClient here would have no timeout, no
	// connection bound, and no trace context on the discovery, token, and
	// JWKS calls this registry makes.
	oidcClient, err := httpclient.New(httpclient.Default(), httpclient.Telemetry{
		TracerProvider: tel.TracerProvider,
		MeterProvider:  tel.MeterProvider,
		Propagator:     tel.Propagator,
	})
	if err != nil {
		return nil, fmt.Errorf("configuring the oidc http client: %w", err)
	}

	oidcCfg := oidc.DefaultConfig()
	oidcCfg.PublicOrigin = cfg.PublicOrigin
	oidcCfg.Providers = cfg.Providers

	registry, err := oidc.NewRegistry(oidcCfg, flows, oidcClient, logger)
	if err != nil {
		return nil, fmt.Errorf("configuring oidc providers: %w", err)
	}

	return registry, nil
}

// buildWebAuthn returns nil when WebAuthn is disabled. Otherwise it returns
// the passkey service, backed by credentials and keyed to a relying party ID
// and origin derived from cfg.
//
// WebAuthn's relying party ID and origins are static, set once here rather
// than derived per request: passkey.NewService rejects an empty RPID
// outright. A deployment with WebAuthn enabled and no PublicOrigin configured
// cannot start, and fails here with an error naming the variable to set.
func buildWebAuthn(cfg config.AuthConfig, credentials *passkey.Repository, flows *authflow.Store, logger *zap.Logger) (*passkey.Service, error) {
	if !cfg.WebAuthnEnabled {
		//nolint:nilnil // a nil service with a nil error is "WebAuthn disabled", not a failure: RouteDeps.Passkeys's own doc comment treats a nil Passkeys as meaning the four WebAuthn routes are not registered.
		return nil, nil
	}

	if cfg.PublicOrigin == "" {
		return nil, errors.New("SERVICE_AUTH_PUBLIC_ORIGIN is required: WebAuthn needs it to set its relying party origin (or set SERVICE_AUTH_WEBAUTHN_ENABLED=false)")
	}

	rpid, err := webAuthnRPID(cfg)
	if err != nil {
		return nil, err
	}

	passkeyCfg := passkey.Config{
		Enabled:       true,
		RPID:          rpid,
		RPDisplayName: cfg.WebAuthnRPDisplayName,
		RPOrigins:     []string{cfg.PublicOrigin},
	}

	service, err := passkey.NewService(passkeyCfg, credentials, flows, logger)
	if err != nil {
		return nil, fmt.Errorf("configuring webauthn: %w", err)
	}

	return service, nil
}

// webAuthnRPID returns cfg.WebAuthnRPID when it is set, and otherwise the
// host of cfg.PublicOrigin, with no port.
func webAuthnRPID(cfg config.AuthConfig) (string, error) {
	if cfg.WebAuthnRPID != "" {
		return cfg.WebAuthnRPID, nil
	}

	publicOriginURL, err := url.Parse(cfg.PublicOrigin)
	if err != nil {
		return "", fmt.Errorf("parsing SERVICE_AUTH_PUBLIC_ORIGIN for the webauthn relying party id: %w", err)
	}

	return publicOriginURL.Hostname(), nil
}

// buildOTPService returns nil when the emailed one-time code method is
// disabled, which is what keeps its two routes unregistered.
func buildOTPService(cfg config.AuthConfig, handle *store.Handle, mailSender mail.Sender, logger *zap.Logger, now func() time.Time) *otp.Service {
	if !cfg.OTPEnabled {
		return nil
	}

	return otp.NewService(otp.Config{
		Enabled:     true,
		CodeTTL:     cfg.OTPCodeTTL,
		MaxAttempts: cfg.OTPMaxAttempts,
	}, handle, mailSender, logger, now)
}

// utcNow is the process clock: time.Now in UTC, so every timestamp the service writes or
// compares carries the same location regardless of the host's time zone.
func utcNow() time.Time {
	return time.Now().UTC()
}

// warnIfCookieMissingHostPrefix logs a warning when the session cookie is
// Secure but its name does not carry the "__Host-" prefix. The prefix is what
// stops a compromised or malicious subdomain from setting or shadowing this
// service's session cookie in the browser; a Secure cookie without it is
// weaker than its name suggests, so an operator who configured a custom name
// loses that protection silently unless this says so.
func warnIfCookieMissingHostPrefix(logger *zap.Logger, cfg session.Config) {
	if !cfg.CookieSecure || strings.HasPrefix(cfg.CookieName, sessionHostCookiePrefix) {
		return
	}

	logger.Warn("session cookie is Secure but does not use the __Host- prefix: a subdomain can still set or shadow it",
		zap.String("cookie_secure_variable", "SERVICE_SESSION_COOKIE_SECURE"),
		zap.String("cookie_name_variable", "SERVICE_SESSION_COOKIE_NAME"),
		zap.String("cookie_name", cfg.CookieName),
	)
}

// warnIfSignupUnreachable logs a warning when signup is disabled -- by either
// the environment override or the database row, since signupEnabled is the
// effective setting with the override already folded in -- and no bootstrap
// administrator is configured, since that pair means no account can ever be
// created.
func warnIfSignupUnreachable(logger *zap.Logger, signupEnabled bool, bootstrapAdminEmails []string) {
	if signupEnabled || len(bootstrapAdminEmails) > 0 {
		return
	}

	logger.Warn("signup is disabled and no bootstrap admin is configured: no account can ever be created",
		zap.String("signup_enabled_variable", "SERVICE_AUTH_SIGNUP_ENABLED"),
		zap.String("bootstrap_admin_emails_variable", "SERVICE_AUTH_BOOTSTRAP_ADMIN_EMAILS"),
		zap.String("admin_settings_endpoint", "PATCH /api/v1/admin/settings"),
	)
}

// logSignupPolicy reads the effective settings row once and logs one info
// line naming the effective signup policy and any key the environment has
// locked. The value read here is logged and discarded, never retained: this
// is an operability step, not a caching step, and the signup admission rules
// (design.md's "Signup admission path") read the row again inside their own
// transaction. A missing row stops the process, because it means the seed
// migration did not run.
func logSignupPolicy(ctx context.Context, logger *zap.Logger, settingsStore *settings.Store, cfg config.AuthConfig) error {
	loadedSettings, err := settingsStore.Load(ctx)
	if err != nil {
		return fmt.Errorf("reading effective settings: %w", err)
	}

	logger.Info("effective signup policy",
		zap.Bool("signup_enabled", loadedSettings.SignupEnabled),
		zap.Strings("locked_settings", settingsStore.Locked()),
	)

	warnIfSignupUnreachable(logger, loadedSettings.SignupEnabled, cfg.BootstrapAdminEmails)

	return nil
}

// shutDown runs one telemetry pipeline's shutdown under its own deadline,
// logging rather than returning a failure: by the time it runs the process is
// already on its way out, and nothing upstream can act on the error.
func shutDown(ctx context.Context, logger *zap.Logger, what string, stop func(context.Context) error) {
	// ctx is cancelled by the time this runs, so the deadline comes from a
	// context that does not inherit that cancellation.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), telemetryShutdownTimeout)
	defer cancel()

	if err := stop(shutdownCtx); err != nil {
		logger.Error("shutting down telemetry", zap.String("pipeline", what), zap.Error(err))
	}
}
