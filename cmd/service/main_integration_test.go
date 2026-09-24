//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/sethvargo/go-envconfig"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/migrations"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// integrationEnv is testEnv's environment with SERVICE_DB_DSN replaced by a
// real, migrated Postgres database storetest starts for t, so run can
// actually open the database process wiring now requires. storetest.NewPool
// runs first and testEnv second: testEnv's freeAddr reserves a port by
// binding and immediately releasing it, and if that release happens before
// Docker's port proxy for the Postgres container claims its own port, the
// proxy can grab the just-released port out from under run before run gets a
// chance to bind it. Starting the pool first gives Docker's own port
// allocation nothing left to race against the reservation this makes right
// before run.
func integrationEnv(t *testing.T) map[string]string {
	t.Helper()

	dsn := storetest.NewPool(t).DSN.Expose()
	env := testEnv(t)
	env["SERVICE_DB_DSN"] = dsn

	return env
}

// TestRunStartsAndShutsDownCleanly covers AC-005.19. It moved here from
// main_test.go because run now opens the database during start-up:
// the placeholder DSN that used to be enough to satisfy configuration
// validation cannot be dialed, so this test needs storetest's real Postgres
// to reach the assertion it is actually making, which is that the whole
// process wiring -- database, migrations, every authentication collaborator,
// the sweeper, and both listeners -- builds and tears down without error.
func TestRunStartsAndShutsDownCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	// Cancelled before run is called: the listeners still bind, and the
	// shutdown sequence then runs immediately. What is under test is that the
	// whole process wiring builds and tears down without error, not how long it
	// stays up, so there is nothing here to wait for and nothing to race.
	cancel()

	// Never written to, so the force-exit goroutine stays parked and exit is
	// never reached on this path.
	forced := make(chan os.Signal)

	err := run(ctx, forced, envconfig.MapLookuper(integrationEnv(t)), func(code int) {
		t.Errorf("exit(%d) was called on the ordinary shutdown path", code)
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
}

// TestRunFailsStartupWhenWebAuthnHasNoPublicOrigin cites no criterion: it
// guards process wiring's own startup check that a
// deployment with WebAuthn enabled (the default) and no public origin
// configured must fail fast rather than reach passkey.NewService's own,
// less legible rejection of an empty relying party ID. It needs a real
// database, unlike the rest of this file's startup-failure sibling: the
// check under test runs after store.Open succeeds, not before it.
func TestRunFailsStartupWhenWebAuthnHasNoPublicOrigin(t *testing.T) {
	env := integrationEnv(t)
	delete(env, "SERVICE_AUTH_PUBLIC_ORIGIN")

	err := run(t.Context(), make(chan os.Signal), envconfig.MapLookuper(env), func(code int) {
		t.Errorf("exit(%d) was called for a missing public origin", code)
	})
	if err == nil {
		t.Fatal("run returned nil with WebAuthn enabled and no public origin configured")
	}

	if !strings.Contains(err.Error(), "PUBLIC_ORIGIN") {
		t.Errorf("run returned %q, which does not name SERVICE_AUTH_PUBLIC_ORIGIN as the problem", err)
	}
}

// TestRunFailsStartupAgainstAnUnreachableDatabase covers AC-008.2: a
// configured connection string that names no reachable PostgreSQL server
// makes run return an error rather than starting the listeners, instead of
// falling back to another store or serving traffic anyway.
func TestRunFailsStartupAgainstAnUnreachableDatabase(t *testing.T) {
	env := testEnv(t)
	env["SERVICE_DB_DSN"] = "postgres://service@" + freeAddr(t) + "/service?sslmode=disable"
	env["SERVICE_DB_CONNECT_TIMEOUT"] = "2s"

	// Bounded well past the 2s connect timeout above so a regression that
	// hangs instead of failing fast is reported as a failure rather than
	// left to the package timeout.
	done := make(chan error, 1)
	go func() {
		done <- run(t.Context(), make(chan os.Signal), envconfig.MapLookuper(env), func(code int) {
			t.Errorf("exit(%d) was called for an unreachable database", code)
		})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run returned nil for a database that names no reachable server")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of an unreachable database, want a fast failure")
	}
}

// wiringPollInterval is how long pollUntilStatus waits between attempts.
// internal/server's own pollUntil is not usable here: it is unexported and
// lives in a _test.go file, so it cannot be imported from another package.
// This mirrors its shape (a short interval, a deadline that exists only to
// fail by name) rather than introducing a different one.
const wiringPollInterval = 5 * time.Millisecond

// wiringStartupTimeout bounds how long pollUntilStatus waits for the
// application listener to start answering GET /healthz. It is generous
// because, unlike the rest of this file's tests, this path runs the full
// database migration sequence against a real, freshly created Postgres
// database before the listener binds.
const wiringStartupTimeout = 15 * time.Second

// pollUntilStatus polls targetURL with a fresh GET every wiringPollInterval,
// closing each response body, until one returns wantStatus or
// wiringStartupTimeout elapses. It fails t by name rather than hanging past
// the package timeout when the listener never comes up.
func pollUntilStatus(t *testing.T, client *http.Client, targetURL string, wantStatus int) {
	t.Helper()

	deadline := time.Now().Add(wiringStartupTimeout)

	for {
		req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodGet, targetURL, http.NoBody)
		if reqErr != nil {
			t.Fatalf("building the poll request for %s: %v", targetURL, reqErr)
		}

		resp, err := client.Do(req)
		if err == nil {
			closeErr := resp.Body.Close()
			if closeErr != nil {
				t.Fatalf("closing response body from %s: %v", targetURL, closeErr)
			}

			if resp.StatusCode == wantStatus {
				return
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("GET %s did not return %d within %s, last error: %v", targetURL, wantStatus, wiringStartupTimeout, err)
		}

		time.Sleep(wiringPollInterval)
	}
}

// assertCarriesMuxMiddlewareHeaders fails t by name unless resp carries the
// security headers server.NewMux's withSecurityHeaders layer sets on every
// response and a non-empty request identifier. It exists so a response a
// caller-supplied middleware -- passed to NewMux rather than wrapped around
// its result -- writes for itself is checked the same way any other response
// from the chain would be, per design.md's "Authorization path" section.
func assertCarriesMuxMiddlewareHeaders(t *testing.T, resp *http.Response) {
	t.Helper()

	wantHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
	}

	for name, want := range wantHeaders {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("response %s = %q, want %q", name, got, want)
		}
	}

	if got := resp.Header.Get(server.RequestIDHeader); got == "" {
		t.Errorf("response %s header is empty, want a request identifier", server.RequestIDHeader)
	}
}

// TestRunWiresCrossSiteRejectionAndReadiness drives the real run() end to
// end and covers the three wiring behaviors that no other test would fail if
// they broke: the application handler is wrapped in
// auth.RejectCrossSite(cfg.Auth.PublicOrigin, cfg.Session.CookieName, ...),
// readiness is registered and answers on the administrative listener, and
// both listeners drain when ctx is cancelled.
//
// It covers AC-008.18: a state-changing request carrying the session cookie
// and a Sec-Fetch-Site header naming another site is rejected with 403 and
// the exact body internal/auth's RejectCrossSite writes. There is no
// acceptance criterion for the readiness endpoint's presence on the
// administrative listener itself (grepped requirements.md for "readyz" and
// "readiness"; the only hits describe internal/server's own behavior, not an
// AC-008 criterion), so that assertion is uncited: it guards run's own wiring
// of ready.AddCheck and server.NewAdminMux against a mutant that drops the
// registration.
func TestRunWiresCrossSiteRejectionAndReadiness(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	env := integrationEnv(t)
	env["SERVICE_SESSION_COOKIE_NAME"] = session.DefaultCookieName

	appAddr := env["SERVICE_SERVER_ADDR"]
	adminAddr := env["SERVICE_ADMIN_ADDR"]

	// Never written to, so the force-exit goroutine stays parked and exit is
	// never reached on this path.
	forced := make(chan os.Signal)

	runDone := make(chan error, 1)
	go func() {
		runDone <- run(ctx, forced, envconfig.MapLookuper(env), func(code int) {
			t.Errorf("exit(%d) was called during cross-site/readiness wiring test", code)
		})
	}()

	client := &http.Client{Timeout: 5 * time.Second}

	pollUntilStatus(t, client, "http://"+appAddr+"/healthz", http.StatusOK)

	logoutReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+appAddr+"/api/v1/auth/logout", http.NoBody)
	if err != nil {
		t.Fatalf("building the logout request: %v", err)
	}

	logoutReq.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: "any-value"}) //nolint:gosec // a request cookie, not a response one
	logoutReq.Header.Set("Sec-Fetch-Site", "cross-site")

	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("POST /api/v1/auth/logout: %v", err)
	}

	logoutBody, readErr := io.ReadAll(logoutResp.Body)

	closeErr := logoutResp.Body.Close()
	if closeErr != nil {
		t.Fatalf("closing the logout response body: %v", closeErr)
	}

	if readErr != nil {
		t.Fatalf("reading the logout response body: %v", readErr)
	}

	if logoutResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /api/v1/auth/logout with a cross-site Sec-Fetch-Site status = %d, want %d, body %s", logoutResp.StatusCode, http.StatusForbidden, logoutBody)
	}

	wantLogoutBody := `{"errors":[{"status":"403","code":"cross_site","title":"Cross-site request rejected"}]}`

	gotLogoutBody := strings.TrimSuffix(string(logoutBody), "\n")
	if gotLogoutBody != wantLogoutBody {
		t.Fatalf("logout response body = %s, want %s", gotLogoutBody, wantLogoutBody)
	}

	// Per design.md's "Authorization path" section: session resolution ran
	// outside internal/server's whole middleware chain, because main.go
	// wrapped server.NewMux's result in auth.RejectCrossSite and Authenticate
	// from the outside instead of passing them in as NewMux's own middleware
	// parameter. A 403 this rejection wrote itself therefore carried none of
	// the security headers, the request ID, or the access log entry every
	// other response gets.
	assertCarriesMuxMiddlewareHeaders(t, logoutResp)

	readyReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+adminAddr+"/readyz", http.NoBody)
	if err != nil {
		t.Fatalf("building the readyz request: %v", err)
	}

	readyResp, err := client.Do(readyReq)
	if err != nil {
		t.Fatalf("GET /readyz on the admin listener: %v", err)
	}

	readyCloseErr := readyResp.Body.Close()
	if readyCloseErr != nil {
		t.Fatalf("closing the readyz response body: %v", readyCloseErr)
	}

	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /readyz on the admin listener status = %d, want %d", readyResp.StatusCode, http.StatusOK)
	}

	cancel()

	select {
	case runErr := <-runDone:
		if runErr != nil {
			t.Fatalf("run returned error %v, want nil after cancellation", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of its context being cancelled")
	}
}

// wantSchemaVersion is the schema version the embedded migrations bring an
// empty database to today. It mirrors
// TestApplyReachesVersion6AndIsIdempotent's own hardcoded 6 in
// internal/store/migrations/migrations_test.go rather than introducing a
// second way to compute it: a seventh migration file bumps both.
const wantSchemaVersion = 6

// openRawDB opens a raw database/sql connection to dsn, closed when t
// finishes. Migration-on-start tests use it to inspect the schema a run of
// the process left behind, or to corrupt a schema before run ever sees it.
func openRawDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("closing raw connection: %v", closeErr)
		}
	})

	return db
}

// TestRunAppliesEveryPendingMigrationBeforeAcceptingRequests covers
// AC-008.3: started against a schema storetest.NewUnmigratedPool has not
// migrated, with migrate-on-start left at its default of enabled
// (store.DefaultConfig's MigrateOnStart is true and testEnv sets no
// override), run applies every pending migration before the application
// listener answers a request. The listener answering /healthz is itself the
// signal that startup, including the migration step that precedes it in
// openAndMigrate, has completed, so the schema is inspected only after that
// poll succeeds.
func TestRunAppliesEveryPendingMigrationBeforeAcceptingRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	env := testEnv(t)
	dsn := storetest.NewUnmigratedPool(t).DSN.Expose()
	env["SERVICE_DB_DSN"] = dsn

	appAddr := env["SERVICE_SERVER_ADDR"]

	// Never written to, so the force-exit goroutine stays parked and exit is
	// never reached on this path.
	forced := make(chan os.Signal)

	runDone := make(chan error, 1)
	go func() {
		runDone <- run(ctx, forced, envconfig.MapLookuper(env), func(code int) {
			t.Errorf("exit(%d) was called while migrating an unmigrated database on start", code)
		})
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	pollUntilStatus(t, client, "http://"+appAddr+"/healthz", http.StatusOK)

	db := openRawDB(t, dsn)

	version, err := migrations.Version(t.Context(), db)
	if err != nil {
		t.Fatalf("migrations.Version() error = %v, want nil", err)
	}

	if version != wantSchemaVersion {
		t.Errorf("migrations.Version() = %d, want %d (every pending migration applied before /healthz answered)", version, wantSchemaVersion)
	}

	cancel()

	select {
	case runErr := <-runDone:
		if runErr != nil {
			t.Fatalf("run returned error %v, want nil after cancellation", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of its context being cancelled")
	}
}

// TestRunFailingMigrationStopsTheProcessAndNamesIt covers AC-008.4: a schema
// that already carries an object the first migration would create makes
// goose's own Up fail, and run must stop -- returning an error rather than
// starting the listeners -- with that error naming the migration that
// failed. internal/store/migrations/00001_users_and_auth.sql's first
// statement is "CREATE TABLE users (...)", so a users table pre-created with
// an incompatible shape (no columns) collides with it.
func TestRunFailingMigrationStopsTheProcessAndNamesIt(t *testing.T) {
	env := testEnv(t)
	dsn := storetest.NewUnmigratedPool(t).DSN.Expose()
	env["SERVICE_DB_DSN"] = dsn

	appAddr := env["SERVICE_SERVER_ADDR"]

	db := openRawDB(t, dsn)

	if _, err := db.ExecContext(t.Context(), `CREATE TABLE users ()`); err != nil {
		t.Fatalf("pre-creating a conflicting users table: %v", err)
	}

	// Never written to, so the force-exit goroutine stays parked and exit is
	// never reached on this path.
	forced := make(chan os.Signal)

	done := make(chan error, 1)
	go func() {
		done <- run(t.Context(), forced, envconfig.MapLookuper(env), func(code int) {
			t.Errorf("exit(%d) was called for a failing migration", code)
		})
	}()

	var runErr error

	select {
	case runErr = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return within 15s of a failing migration, want a fast failure")
	}

	if runErr == nil {
		t.Fatal("run returned nil for a schema that collides with the first migration")
	}

	if !strings.Contains(runErr.Error(), "00001_users_and_auth.sql") {
		t.Errorf("run returned %q, which does not name the migration that failed", runErr)
	}

	client := &http.Client{Timeout: 500 * time.Millisecond}

	req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+appAddr+"/healthz", http.NoBody)
	if reqErr != nil {
		t.Fatalf("building the healthz request: %v", reqErr)
	}

	if resp, err := client.Do(req); err == nil {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			t.Errorf("closing response body from a listener that should never have started: %v", closeErr)
		}

		t.Fatalf("GET %s succeeded with status %d, want the listener never to have come up", req.URL, resp.StatusCode)
	}
}

// sweepTestCleanupInterval is the SERVICE_SESSION_CLEANUP_INTERVAL this test
// configures the process with. It is short enough that the sweeper's first
// tick lands well inside sweepTestPollTimeout, but long enough that the row
// this test inserts (after the process has already reported itself ready)
// cannot lose a race against that first tick: auth.Sweeper.Run ticks with
// time.NewTicker, which fires no earlier than one full interval after Run
// starts, and Run starts at the same time as the listeners that
// pollUntilStatus waits on, so a row inserted immediately after readiness is
// inserted well before the sweeper's first sweep.
const sweepTestCleanupInterval = 2 * time.Second

// sweepTestPollTimeout bounds how long this test waits for the inserted row
// to be removed. It is well past sweepTestCleanupInterval so the fix passes
// comfortably, and far short of the five-minute constant the fix replaces, so
// the unfixed code fails this test by name instead of by hanging.
const sweepTestPollTimeout = 15 * time.Second

// sweepTestPollInterval paces polling for the swept row's removal. It only
// controls how often the test checks, never the outcome of a passing run.
const sweepTestPollInterval = 100 * time.Millisecond

// insertExpiredAuthFlow inserts a row into auth_flows that is already past
// its expiry, using columns valid enough to satisfy the table's constraints:
// a random 16 byte id, the "oidc" kind, no user, and an empty JSON data
// object. It returns the row's id so the caller can poll for its removal.
func insertExpiredAuthFlow(t *testing.T, db *sql.DB) []byte {
	t.Helper()

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("generating a random auth_flows id: %v", err)
	}

	now := time.Now()
	expiresAt := now.Add(-time.Hour)

	const insert = `INSERT INTO auth_flows (id, kind, user_id, data, created_at, expires_at) VALUES ($1, 'oidc', NULL, '{}', $2, $3)`

	if _, err := db.ExecContext(t.Context(), insert, id, now, expiresAt); err != nil {
		t.Fatalf("inserting an already-expired auth_flows row: %v", err)
	}

	return id
}

// authFlowExists reports whether an auth_flows row with the given id is still
// present.
func authFlowExists(t *testing.T, db *sql.DB, id []byte) bool {
	t.Helper()

	var exists bool

	const query = `SELECT EXISTS(SELECT 1 FROM auth_flows WHERE id = $1)`
	if err := db.QueryRowContext(t.Context(), query, id).Scan(&exists); err != nil {
		t.Fatalf("checking whether the auth_flows row survives: %v", err)
	}

	return exists
}

// TestRunSweepsExpiredCeremonyStateOnTheConfiguredInterval covers AC-008.21,
// which internal/authflow/authflow_test.go's own
// TestDeleteExpiredRemovesOnlyExpiredFlows already cites for
// authflow.Store.DeleteExpired directly: ceremony state past its expiry is
// removed. What that unit test cannot show is that the running process ever
// calls DeleteExpired at all, on the interval SERVICE_SESSION_CLEANUP_INTERVAL
// configures, rather than on run's own unconfigurable constant. This test
// sets that variable to a short interval, waits for the process to report
// itself ready, inserts an already-expired auth_flows row through its own
// database connection, and bounded-polls until the running process's sweeper
// has removed it. Before this change, main.go ignored
// cfg.Session.CleanupInterval and swept every five minutes regardless, so
// this test fails by hitting sweepTestPollTimeout rather than by any
// assertion this test makes explicitly.
func TestRunSweepsExpiredCeremonyStateOnTheConfiguredInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	env := integrationEnv(t)
	env["SERVICE_SESSION_CLEANUP_INTERVAL"] = sweepTestCleanupInterval.String()

	appAddr := env["SERVICE_SERVER_ADDR"]

	// Never written to, so the force-exit goroutine stays parked and exit is
	// never reached on this path.
	forced := make(chan os.Signal)

	runDone := make(chan error, 1)
	go func() {
		runDone <- run(ctx, forced, envconfig.MapLookuper(env), func(code int) {
			t.Errorf("exit(%d) was called during the sweeper interval test", code)
		})
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	pollUntilStatus(t, client, "http://"+appAddr+"/healthz", http.StatusOK)

	db := openRawDB(t, env["SERVICE_DB_DSN"])

	// Inserted only now, after the process has already reported itself ready:
	// see sweepTestCleanupInterval's comment for why this still lands before
	// the sweeper's first tick.
	id := insertExpiredAuthFlow(t, db)

	pollUntil(t, sweepTestPollTimeout, func() bool {
		return !authFlowExists(t, db, id)
	}, func() string {
		return "expired auth_flows row was not swept"
	})

	cancel()

	select {
	case runErr := <-runDone:
		if runErr != nil {
			t.Fatalf("run returned error %v, want nil after cancellation", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of its context being cancelled")
	}
}

// tcpForwarder relays every connection it accepts to a fixed backend
// address. Its stop function closes its own listener and severs every
// connection it is currently relaying, without touching the backend itself,
// so a test can simulate that backend becoming unreachable.
type tcpForwarder struct {
	addr string
	stop func()
}

// startTCPForwarder starts a tcpForwarder listening on a free loopback port
// and relaying every accepted connection to backendAddr. The forwarder is
// torn down, idempotently, in t.Cleanup if the test has not already called
// its stop function itself.
func startTCPForwarder(t *testing.T, backendAddr string) tcpForwarder {
	t.Helper()

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting the tcp forwarder listener: %v", err)
	}

	var connsMu sync.Mutex

	var conns []net.Conn

	track := func(conn net.Conn) {
		connsMu.Lock()
		conns = append(conns, conn)
		connsMu.Unlock()
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		for {
			clientConn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}

			track(clientConn)

			wg.Go(func() {
				relayForwarderConn(t, clientConn, backendAddr, track, &wg)
			})
		}
	})

	var stopOnce sync.Once

	stop := func() {
		stopOnce.Do(func() {
			if closeErr := listener.Close(); closeErr != nil {
				t.Logf("closing the tcp forwarder listener: %v", closeErr)
			}

			connsMu.Lock()
			for _, conn := range conns {
				if connCloseErr := conn.Close(); connCloseErr != nil {
					t.Logf("closing a relayed tcp forwarder connection: %v", connCloseErr)
				}
			}
			connsMu.Unlock()

			wg.Wait()
		})
	}

	t.Cleanup(stop)

	return tcpForwarder{addr: listener.Addr().String(), stop: stop}
}

// relayForwarderConn dials backendAddr for clientConn and copies bytes in
// both directions until either side closes or errors, registering the
// backend connection with track so the forwarder's stop function can sever
// it too. It starts one goroutine of its own, tracked on wg, for the
// client-to-backend direction, and runs the backend-to-client direction
// itself so its caller's own wg.Go call bounds this connection's lifetime as
// a whole.
func relayForwarderConn(t *testing.T, clientConn net.Conn, backendAddr string, track func(net.Conn), wg *sync.WaitGroup) {
	t.Helper()

	var dialer net.Dialer

	backendConn, dialErr := dialer.DialContext(t.Context(), "tcp", backendAddr)
	if dialErr != nil {
		if closeErr := clientConn.Close(); closeErr != nil {
			t.Logf("closing a client connection after a failed dial to %s: %v", backendAddr, closeErr)
		}

		return
	}

	track(backendConn)

	wg.Go(func() {
		if _, copyErr := io.Copy(backendConn, clientConn); copyErr != nil {
			t.Logf("relaying client to backend: %v", copyErr)
		}
	})

	if _, copyErr := io.Copy(clientConn, backendConn); copyErr != nil {
		t.Logf("relaying backend to client: %v", copyErr)
	}
}

// TestReadinessFailsClosedWhenTheDatabaseBecomesUnreachable covers
// AC-008.84: once a process that has already reported itself ready loses its
// database, /readyz on the administrative listener must fail closed and
// start answering 503 rather than continuing to report 200 for a dependency
// that no longer answers. It runs the real process against a tcpForwarder
// standing in for Postgres, waits for /readyz to report ready, severs every
// connection the forwarder is relaying to simulate the database becoming
// unreachable, and bounded-polls /readyz until it reports 503.
func TestReadinessFailsClosedWhenTheDatabaseBecomesUnreachable(t *testing.T) {
	backendDSN := storetest.NewPool(t).DSN.Expose()

	parsedDSN, err := url.Parse(backendDSN)
	if err != nil {
		t.Fatalf("parsing the storetest DSN: %v", err)
	}

	forwarder := startTCPForwarder(t, parsedDSN.Host)

	parsedDSN.Host = forwarder.addr

	env := testEnv(t)
	env["SERVICE_DB_DSN"] = parsedDSN.String()

	ctx, cancel := context.WithCancel(t.Context())

	adminAddr := env["SERVICE_ADMIN_ADDR"]

	// Never written to, so the force-exit goroutine stays parked and exit is
	// never reached on this path.
	forced := make(chan os.Signal)

	runDone := make(chan error, 1)
	go func() {
		runDone <- run(ctx, forced, envconfig.MapLookuper(env), func(code int) {
			t.Errorf("exit(%d) was called during the readiness-fails-closed test", code)
		})
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	readyzURL := "http://" + adminAddr + "/readyz"

	pollUntilStatus(t, client, readyzURL, http.StatusOK)

	forwarder.stop()

	pollUntilStatus(t, client, readyzURL, http.StatusServiceUnavailable)

	cancel()

	select {
	case runErr := <-runDone:
		if runErr != nil {
			t.Fatalf("run returned error %v, want nil after cancellation", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of its context being cancelled")
	}
}

// pollUntil calls check until it reports true, and fails the test with the
// message describe returns if timeout elapses first. This mirrors
// internal/server's own pollUntil, which is unexported and lives in a
// _test.go file in another package so it cannot be imported here; see
// wiringPollInterval's comment above for the same constraint on
// pollUntilStatus.
func pollUntil(t *testing.T, timeout time.Duration, check func() bool, describe func() string) {
	t.Helper()

	deadline := time.Now().Add(timeout)

	for {
		if check() {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("%s within %s", describe(), timeout)
		}

		time.Sleep(sweepTestPollInterval)
	}
}
