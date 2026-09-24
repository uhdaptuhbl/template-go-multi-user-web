//go:build integration

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/otp"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/passkey"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authflow"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/mail"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// sweeperIdleTimeout, sweeperFlowTTL, sweeperCodeTTL, and
// sweeperGracePeriod are the short expiries every sweeper test's
// collaborators use, so a "one minute" test clock advance is enough to
// expire a freshly created row of each kind.
const sweeperIdleTimeout = time.Minute
const sweeperFlowTTL = time.Minute
const sweeperCodeTTL = time.Minute
const sweeperAbsoluteTimeout = time.Hour
const sweeperGracePeriod = time.Minute

// sweeperNoopSender is a mail.Sender that succeeds without doing anything. A
// sweeper test only cares about the otp_codes row Request leaves behind, never
// about a delivered message.
type sweeperNoopSender struct{}

// Send always returns nil, recording nothing.
func (sweeperNoopSender) Send(_ context.Context, _ mail.Message) error {
	return nil
}

// sweeperDeps bundles the real collaborators a Sweeper test needs, all backed
// by one migrated database and one shared, manually advanced clock.
type sweeperDeps struct {
	handle   *store.Handle
	sess     *session.Store
	flows    *authflow.Store
	codes    *otp.Service
	invites  *invite.Service
	accounts *Service
	clock    *clock
}

// newSweeperDeps returns a sweeperDeps backed by a fresh migrated database,
// with every expiry short enough for a test to cross with one clock advance.
func newSweeperDeps(t *testing.T) sweeperDeps {
	t.Helper()

	c := newClock()
	h := storetest.NewWithClock(t, c.Now)

	sessCfg := session.Config{
		CookieName:      "test_session",
		CookieSecure:    false,
		IdleTimeout:     configtype.Duration(sweeperIdleTimeout),
		AbsoluteTimeout: configtype.Duration(sweeperAbsoluteTimeout),
		CleanupInterval: configtype.Duration(time.Hour),
	}
	sess := session.NewStore(h, sessCfg, c.Now)

	flows := authflow.NewStore(h, sweeperFlowTTL, c.Now)

	otpCfg := otp.Config{
		Enabled:     true,
		CodeTTL:     configtype.Duration(sweeperCodeTTL),
		MaxAttempts: 5,
	}
	codes := otp.NewService(otpCfg, h, sweeperNoopSender{}, zap.NewNop(), c.Now)

	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)

	invites, err := invite.NewService(h, policy, testTokenBytes, zap.NewNop(), c.Now)
	if err != nil {
		t.Fatalf("invite.NewService() error = %v", err)
	}

	users := user.NewRepository(h, c.Now)
	roles := authz.NewRepository(h, c.Now)
	checker := authz.NewChecker(roles)
	recorder := audit.NewRecorder(h, zap.NewNop(), c.Now)
	credentials := passkey.NewRepository(h, c.Now)

	accountDeps := AccountDeps{
		Credentials:        credentials,
		OTPEnabled:         otpCfg.Enabled,
		DeletedGracePeriod: sweeperGracePeriod,
	}

	accounts := NewService(h, users, sess, roles, checker, recorder, invites, policy, nil, zap.NewNop(), c.Now, accountDeps)

	return sweeperDeps{
		handle:   h,
		sess:     sess,
		flows:    flows,
		codes:    codes,
		invites:  invites,
		accounts: accounts,
		clock:    c,
	}
}

// createDeletedSweeperUser inserts a user row already marked deleted at
// deletedAt, directly, the same way createSweeperUser inserts an active one.
func createDeletedSweeperUser(t *testing.T, h *store.Handle, deletedAt time.Time) uuid.UUID {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}

	const insertDeletedUserQuery = `
INSERT INTO users (id, display_name, status, deleted_at, created_at, updated_at)
VALUES ($1, $2, 'deleted', $3, $3, $3)
`

	if _, execErr := h.Pool().Exec(t.Context(), insertDeletedUserQuery, id, "sweeper deleted test user", deletedAt); execErr != nil {
		t.Fatalf("inserting deleted test user: %v", execErr)
	}

	return id
}

// createSweeperUser inserts a minimal active user row directly. Sessions and
// invites both carry a foreign key to users, and the sweeper's own tests have
// no need for the full signup and identity machinery internal/user provides
// to satisfy it.
func createSweeperUser(t *testing.T, h *store.Handle, now time.Time) uuid.UUID {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}

	const insertUserQuery = `
INSERT INTO users (id, display_name, status, created_at, updated_at)
VALUES ($1, $2, 'active', $3, $3)
`

	if _, execErr := h.Pool().Exec(t.Context(), insertUserQuery, id, "sweeper test user", now); execErr != nil {
		t.Fatalf("inserting test user: %v", execErr)
	}

	return id
}

// flowRowExists reports whether the auth_flows row named by encodedID, the
// opaque identifier authflow.Begin returns, is still present.
func flowRowExists(t *testing.T, h *store.Handle, encodedID string) bool {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(encodedID)
	if err != nil {
		t.Fatalf("decoding flow id: %v", err)
	}

	return countRows(t, h, `SELECT count(*) FROM auth_flows WHERE id = $1`, raw) > 0
}

// TestSweeperRun_ContextAlreadyCancelled proves that Run returns nil promptly
// when its context is already cancelled, rather than waiting for the first
// tick.
// Covers AC-008.92.
func TestSweeperRun_ContextAlreadyCancelled(t *testing.T) {
	deps := newSweeperDeps(t)
	sweeper := NewSweeper(time.Hour, zap.NewNop(), deps.sess, deps.flows, deps.codes, deps.invites, time.Hour, deps.accounts)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- sweeper.Run(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly after its context was already cancelled")
	}
}

// TestSweeperSweepOnce_RemovesExpiredLeavesLive proves that one sweep removes
// an expired session, an expired flow, and an expired code, while leaving a
// live row of each kind untouched.
// Covers AC-008.92.
func TestSweeperSweepOnce_RemovesExpiredLeavesLive(t *testing.T) {
	deps := newSweeperDeps(t)
	ctx := t.Context()

	t0 := deps.clock.Now()
	userID := createSweeperUser(t, deps.handle, t0)

	expiredSess, _, err := deps.sess.Issue(ctx, userID, "", "ua", nil)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	expiredFlowID, err := deps.flows.Begin(ctx, authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	const expiredEmail = "expired@example.com"
	const liveEmail = "live@example.com"

	if err = deps.codes.Request(ctx, expiredEmail, "sweeper-test-binding", uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	// Cross every expiry configured in newSweeperDeps.
	deps.clock.Advance(2 * time.Minute)

	liveSess, _, err := deps.sess.Issue(ctx, userID, "", "ua", nil)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	liveFlowID, err := deps.flows.Begin(ctx, authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	if requestErr := deps.codes.Request(ctx, liveEmail, "sweeper-test-binding", uuid.NullUUID{}); requestErr != nil {
		t.Fatalf("Request() error = %v", requestErr)
	}

	sweeper := NewSweeper(time.Hour, zap.NewNop(), deps.sess, deps.flows, deps.codes, deps.invites, time.Hour, deps.accounts)
	sweeper.sweepOnce(ctx)

	if got := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE id = $1`, expiredSess.ID); got != 0 {
		t.Errorf("expired session rows = %d, want 0", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE id = $1`, liveSess.ID); got != 1 {
		t.Errorf("live session rows = %d, want 1", got)
	}

	if flowRowExists(t, deps.handle, expiredFlowID) {
		t.Error("expired flow row still exists, want removed")
	}

	if !flowRowExists(t, deps.handle, liveFlowID) {
		t.Error("live flow row missing, want present")
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM otp_codes WHERE email = $1`, expiredEmail); got != 0 {
		t.Errorf("expired code rows for %s = %d, want 0", expiredEmail, got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM otp_codes WHERE email = $1`, liveEmail); got != 1 {
		t.Errorf("live code rows for %s = %d, want 1", liveEmail, got)
	}
}

// TestSweeperSweepOnce_InviteRetainWindow proves that an invite expired for
// less than inviteRetain survives a sweep while one expired for longer is
// removed, and that a revoked invite and a fully spent invite both survive
// even though each is expired far longer than inviteRetain.
// Covers AC-008.92.
func TestSweeperSweepOnce_InviteRetainWindow(t *testing.T) {
	deps := newSweeperDeps(t)
	ctx := t.Context()

	const retain = 10 * time.Minute

	t0 := deps.clock.Now()
	issuer := createSweeperUser(t, deps.handle, t0)
	issuerRef := "user:" + issuer.String()

	// removed: expires at t0+1m, which will be 12m before the sweep runs,
	// beyond the 10m retain window.
	removed, err := deps.invites.Create(ctx, issuer, issuerRef, true, invite.Params{TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create(removed) error = %v", err)
	}

	// survives: expires at t0+5m, which will be 8m before the sweep runs,
	// inside the 10m retain window.
	survivesWithinRetain, err := deps.invites.Create(ctx, issuer, issuerRef, true, invite.Params{TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("Create(survivesWithinRetain) error = %v", err)
	}

	// survives: revoked immediately, then expired far longer than retain.
	revoked, err := deps.invites.Create(ctx, issuer, issuerRef, true, invite.Params{TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create(revoked) error = %v", err)
	}

	if _, err = deps.invites.Revoke(ctx, revoked.Invite.ID, issuer, false); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// survives: fully spent, then expired far longer than retain. Uses is
	// forced to max_uses directly: driving it through a real signup
	// redemption is unrelated machinery this test does not need.
	spent, err := deps.invites.Create(ctx, issuer, issuerRef, true, invite.Params{TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create(spent) error = %v", err)
	}

	if _, execErr := deps.handle.Pool().Exec(ctx, `UPDATE invites SET uses = max_uses WHERE id = $1`, spent.Invite.ID); execErr != nil {
		t.Fatalf("forcing invite spent: %v", execErr)
	}

	deps.clock.Advance(13 * time.Minute)

	sweeper := NewSweeper(time.Hour, zap.NewNop(), deps.sess, deps.flows, deps.codes, deps.invites, retain, deps.accounts)
	sweeper.sweepOnce(ctx)

	if got := countRows(t, deps.handle, `SELECT count(*) FROM invites WHERE id = $1`, removed.Invite.ID); got != 0 {
		t.Errorf("invite expired beyond retain rows = %d, want 0", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM invites WHERE id = $1`, survivesWithinRetain.Invite.ID); got != 1 {
		t.Errorf("invite expired within retain rows = %d, want 1", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM invites WHERE id = $1`, revoked.Invite.ID); got != 1 {
		t.Errorf("revoked invite rows = %d, want 1", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM invites WHERE id = $1`, spent.Invite.ID); got != 1 {
		t.Errorf("spent invite rows = %d, want 1", got)
	}
}

// TestSweeperSweepOnce_SessionsCleanerFailureDoesNotStopOtherCleaners proves
// that a single sweepOnce call still removes an expired flow and an expired
// invite past its retain window even when the sessions cleaner fails first:
// the "keep going after a cleaner fails" rule sweepOnce's doc comment states.
// The sessions table is dropped so the sessions cleaner fails deterministically
// on every call, the same technique TestSweeperRun_FailingCleanerDoesNotStopTheLoop
// uses. A warn entry names the sessions cleaner, and the sweep still ends
// with its usual "sweep completed" debug line.
// Covers AC-008.93.
func TestSweeperSweepOnce_SessionsCleanerFailureDoesNotStopOtherCleaners(t *testing.T) {
	deps := newSweeperDeps(t)
	ctx := t.Context()

	const retain = 10 * time.Minute

	t0 := deps.clock.Now()
	issuer := createSweeperUser(t, deps.handle, t0)
	issuerRef := "user:" + issuer.String()

	expiredFlowID, err := deps.flows.Begin(ctx, authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	expiredInvite, err := deps.invites.Create(ctx, issuer, issuerRef, true, invite.Params{TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if _, execErr := deps.handle.Pool().Exec(ctx, `DROP TABLE sessions`); execErr != nil {
		t.Fatalf("dropping sessions table: %v", execErr)
	}

	// Crosses the flow TTL, the invite TTL, and the invite retain window
	// configured below.
	deps.clock.Advance(13 * time.Minute)

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	sweeper := NewSweeper(time.Hour, logger, deps.sess, deps.flows, deps.codes, deps.invites, retain, deps.accounts)
	sweeper.sweepOnce(ctx)

	if flowRowExists(t, deps.handle, expiredFlowID) {
		t.Error("expired flow row still exists after a sweep, want removed despite the sessions cleaner failing")
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM invites WHERE id = $1`, expiredInvite.Invite.ID); got != 0 {
		t.Errorf("expired invite rows = %d, want 0, despite the sessions cleaner failing", got)
	}

	if got := countWarnEntriesForCleaner(logs, "sessions"); got != 1 {
		t.Fatalf("warn entries naming the sessions cleaner = %d, want 1", got)
	}

	if got := len(logs.FilterMessage("auth: sweep completed").All()); got != 1 {
		t.Fatalf("got %d completed-sweep debug entries, want 1", got)
	}
}

// TestSweeperSweepOnce_NilCodesSkipped proves that a nil codes collaborator is
// skipped without panicking, and that the sweep still logs a completed sweep.
// Covers AC-008.92.
func TestSweeperSweepOnce_NilCodesSkipped(t *testing.T) {
	deps := newSweeperDeps(t)
	ctx := t.Context()

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	sweeper := NewSweeper(time.Hour, logger, deps.sess, deps.flows, nil, deps.invites, time.Hour, deps.accounts)
	sweeper.sweepOnce(ctx)

	for _, entry := range logs.All() {
		if entry.Level == zapcore.WarnLevel {
			t.Errorf("unexpected warn entry with nil codes: %s %v", entry.Message, entry.Context)
		}
	}

	debugEntries := logs.FilterMessage("auth: sweep completed").All()
	if len(debugEntries) != 1 {
		t.Fatalf("got %d completed-sweep debug entries, want 1", len(debugEntries))
	}

	for _, f := range debugEntries[0].Context {
		if f.Key == "codes_removed" && f.Integer != 0 {
			t.Errorf("codes_removed = %d, want 0 when codes is nil", f.Integer)
		}
	}
}

// countWarnEntriesForCleaner returns how many warn-level entries logs holds
// naming cleaner in their "cleaner" field.
func countWarnEntriesForCleaner(logs *observer.ObservedLogs, cleaner string) int {
	count := 0

	for _, entry := range logs.All() {
		if entry.Level != zapcore.WarnLevel {
			continue
		}

		for _, f := range entry.Context {
			if f.Key == "cleaner" && f.String == cleaner {
				count++
			}
		}
	}

	return count
}

// TestSweeperRun_FailingCleanerDoesNotStopTheLoop proves that a cleaner
// returning an error on every sweep does not stop Run's loop: a second sweep
// is observed to run after the first one's cleaner failure, evidenced by a
// second warn line for the same cleaner.
// Covers AC-008.93.
func TestSweeperRun_FailingCleanerDoesNotStopTheLoop(t *testing.T) {
	deps := newSweeperDeps(t)

	// Breaks the sessions cleaner permanently and deterministically, on every
	// sweep, without needing to close and therefore risk double-closing the
	// pool storetest already cleans up.
	if _, err := deps.handle.Pool().Exec(t.Context(), `DROP TABLE sessions`); err != nil {
		t.Fatalf("dropping sessions table: %v", err)
	}

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	const tinyInterval = 5 * time.Millisecond

	sweeper := NewSweeper(tinyInterval, logger, deps.sess, deps.flows, deps.codes, deps.invites, time.Hour, deps.accounts)

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- sweeper.Run(ctx)
	}()

	deadline := time.After(5 * time.Second)
	poll := time.NewTicker(2 * time.Millisecond)
	defer poll.Stop()

	for countWarnEntriesForCleaner(logs, "sessions") < 2 {
		select {
		case <-poll.C:
		case <-deadline:
			t.Fatalf("timed out waiting for a second failed sweep, saw %d", countWarnEntriesForCleaner(logs, "sessions"))
		}
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancellation")
	}
}

// TestRunSweepsImmediatelyAtStart proves that Run sweeps once before it enters
// its ticker loop, covering AC-008.51: with a 1h interval, a process that
// restarts more than once an hour must still purge past-grace accounts and
// expired sessions rather than waiting out the first tick. An expired session
// and an account deleted past its grace period are created before Run starts;
// both are gone well inside the ticker's 1h period, proving the removal came
// from the immediate pre-loop sweep rather than from a tick.
func TestRunSweepsImmediatelyAtStart(t *testing.T) {
	deps := newSweeperDeps(t)
	ctx := t.Context()

	t0 := deps.clock.Now()
	userID := createSweeperUser(t, deps.handle, t0)

	expiredSess, _, err := deps.sess.Issue(ctx, userID, "", "ua", nil)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	expiredAccount := createDeletedSweeperUser(t, deps.handle, t0)

	// Crosses both the one-minute idle timeout and the one-minute grace
	// period configured in newSweeperDeps.
	deps.clock.Advance(2 * time.Minute)

	sweeper := NewSweeper(time.Hour, zap.NewNop(), deps.sess, deps.flows, deps.codes, deps.invites, time.Hour, deps.accounts)

	runCtx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- sweeper.Run(runCtx)
	}()

	deadline := time.After(5 * time.Second)
	poll := time.NewTicker(2 * time.Millisecond)
	defer poll.Stop()

	for {
		sessionsLeft := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE id = $1`, expiredSess.ID)
		accountsLeft := countRows(t, deps.handle, `SELECT count(*) FROM users WHERE id = $1`, expiredAccount)

		if sessionsLeft == 0 && accountsLeft == 0 {
			break
		}

		select {
		case <-poll.C:
		case <-deadline:
			t.Fatalf("timed out waiting for the pre-loop sweep, sessions left = %d, accounts left = %d", sessionsLeft, accountsLeft)
		}
	}

	cancel()

	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("Run() error = %v, want nil", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancellation")
	}
}

// infoEntriesForMessage returns how many info-level entries logs holds with
// the given message.
func infoEntriesForMessage(logs *observer.ObservedLogs, message string) int {
	count := 0

	for _, entry := range logs.All() {
		if entry.Level == zapcore.InfoLevel && entry.Message == message {
			count++
		}
	}

	return count
}

// TestSweeperSweepOnce_PurgesExpiredAccountsLeavesLiveAndLogsCount proves
// that sweepOnce's account-purge step, which runs after the four other
// cleaners, permanently removes an account whose deletion grace period has
// elapsed, leaves one still inside its grace period untouched, and logs one
// info line naming how many it purged.
// Covers AC-008.51.
func TestSweeperSweepOnce_PurgesExpiredAccountsLeavesLiveAndLogsCount(t *testing.T) {
	deps := newSweeperDeps(t)
	ctx := t.Context()

	t0 := deps.clock.Now()

	// expired: deleted at t0, grace period is one minute, and the sweep runs
	// after the clock advances two minutes, so this account's grace period
	// elapsed before the sweep ran.
	expired := createDeletedSweeperUser(t, deps.handle, t0)

	deps.clock.Advance(2 * time.Minute)

	// live: deleted right at the moment the sweep runs, so it is still
	// within its one-minute grace period.
	live := createDeletedSweeperUser(t, deps.handle, deps.clock.Now())

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	sweeper := NewSweeper(time.Hour, logger, deps.sess, deps.flows, deps.codes, deps.invites, time.Hour, deps.accounts)
	sweeper.sweepOnce(ctx)

	if got := countRows(t, deps.handle, `SELECT count(*) FROM users WHERE id = $1`, expired); got != 0 {
		t.Errorf("expired account rows = %d, want 0", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM users WHERE id = $1`, live); got != 1 {
		t.Errorf("live account rows = %d, want 1", got)
	}

	if got := infoEntriesForMessage(logs, "auth: sweep purged expired accounts"); got != 1 {
		t.Fatalf("info entries naming a purged count = %d, want 1", got)
	}

	entry := logs.FilterMessage("auth: sweep purged expired accounts").All()[0]

	for _, f := range entry.Context {
		if f.Key == "purged" && f.Integer != 1 {
			t.Errorf("purged = %d, want 1", f.Integer)
		}
	}
}

// TestSweeperSweepOnce_ZeroAccountsPurgedLogsNoInfoLine proves that a sweep
// which purges no accounts logs no "sweep purged expired accounts" line at
// all, so a routine sweep is not noise at info level every interval.
// Covers AC-008.51.
func TestSweeperSweepOnce_ZeroAccountsPurgedLogsNoInfoLine(t *testing.T) {
	deps := newSweeperDeps(t)
	ctx := t.Context()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	sweeper := NewSweeper(time.Hour, logger, deps.sess, deps.flows, deps.codes, deps.invites, time.Hour, deps.accounts)
	sweeper.sweepOnce(ctx)

	if got := infoEntriesForMessage(logs, "auth: sweep purged expired accounts"); got != 0 {
		t.Errorf("info entries naming a purged count = %d, want 0 when nothing was purged", got)
	}
}

// TestSweeperSweepOnce_AccountsPurgeFailureLogsErrorNamingCutoff proves that
// a failure in the account-purge step is logged at error level, not warn,
// and that the entry names the cutoff it was purging against. The users
// table is renamed, rather than dropped, because other tables carry a
// foreign key to it: a drop would need CASCADE and take unrelated tables
// with it, contaminating what the other cleaners in the same sweep report.
// Covers AC-008.51 and AC-008.93.
func TestSweeperSweepOnce_AccountsPurgeFailureLogsErrorNamingCutoff(t *testing.T) {
	deps := newSweeperDeps(t)
	ctx := t.Context()

	if _, err := deps.handle.Pool().Exec(ctx, `ALTER TABLE users RENAME TO users_hidden_for_test`); err != nil {
		t.Fatalf("renaming users table: %v", err)
	}

	t.Cleanup(func() {
		if _, err := deps.handle.Pool().Exec(context.Background(), `ALTER TABLE users_hidden_for_test RENAME TO users`); err != nil {
			t.Fatalf("restoring users table: %v", err)
		}
	})

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	sweeper := NewSweeper(time.Hour, logger, deps.sess, deps.flows, deps.codes, deps.invites, time.Hour, deps.accounts)
	sweeper.sweepOnce(ctx)

	errorEntries := logs.FilterMessage("auth: sweeper purging expired accounts").All()
	if len(errorEntries) != 1 {
		t.Fatalf("got %d error entries for the accounts purge failure, want 1", len(errorEntries))
	}

	entry := errorEntries[0]

	if entry.Level != zapcore.ErrorLevel {
		t.Errorf("accounts purge failure logged at %v, want Error", entry.Level)
	}

	foundCutoff := false

	for _, f := range entry.Context {
		if f.Key == "cutoff" {
			foundCutoff = true
		}
	}

	if !foundCutoff {
		t.Error("accounts purge failure entry does not name the cutoff")
	}

	if got := infoEntriesForMessage(logs, "auth: sweep purged expired accounts"); got != 0 {
		t.Errorf("info entries naming a purged count = %d, want 0 on failure", got)
	}
}
