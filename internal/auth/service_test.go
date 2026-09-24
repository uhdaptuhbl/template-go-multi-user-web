//go:build integration

package auth

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/passkey"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// testTokenBytes is the invite token length every test invite.Service in this
// package uses.
const testTokenBytes = 32

// clock is a manually advanced clock for tests that must control the passage
// of time without sleeping.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

// newClock returns a clock starting at the current wall time, truncated to
// microsecond precision to match what Postgres round-trips.
func newClock() *clock {
	return &clock{now: time.Now().UTC().Truncate(time.Microsecond)}
}

// Now returns the clock's current time.
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

// Advance moves the clock forward by d.
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// testDeps bundles every collaborator newTestService constructs, so a test
// that needs to reach into a table Service does not expose directly (a
// session digest, a settings row) still has a handle to do it with.
type testDeps struct {
	service  *Service
	handle   *store.Handle
	users    *user.Repository
	sessions *session.Store
	roles    *authz.Repository
	invites  *invite.Service
	policy   *settings.Store
	recorder *audit.Recorder
	clock    *clock
}

// newTestService returns a Service backed by a fresh migrated database and
// every real collaborator it depends on, per this project's testing
// standard of using real types rather than mocks.
func newTestService(t *testing.T, bootstrapAdmins []string) testDeps {
	t.Helper()

	c := newClock()
	h := storetest.New(t)

	users := user.NewRepository(h, c.Now)
	sessions := session.NewStore(h, session.DefaultConfig(), c.Now)
	roles := authz.NewRepository(h, c.Now)
	checker := authz.NewChecker(roles)
	recorder := audit.NewRecorder(h, zap.NewNop(), c.Now)
	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)

	invites, err := invite.NewService(h, policy, testTokenBytes, zap.NewNop(), c.Now)
	if err != nil {
		t.Fatalf("invite.NewService() error = %v", err)
	}

	// Credentials is wired here, unlike most of AccountDeps, because
	// handleMeCredentialsDelete calls Service.RemoveCredential, which
	// dereferences it unconditionally. Providers configures the issuer these
	// tests sign in through, so the last-factor rule counts the identities
	// they create; every other AccountDeps-backed method this package's
	// shared testDeps exercises tolerates a zero value.
	accountDeps := AccountDeps{
		Credentials: passkey.NewRepository(h, c.Now),
		Providers:   newConfiguredProviderRegistry(t, "https://issuer.example"),
	}

	svc := NewService(h, users, sessions, roles, checker, recorder, invites, policy, bootstrapAdmins, zap.NewNop(), c.Now, accountDeps)

	return testDeps{
		service:  svc,
		handle:   h,
		users:    users,
		sessions: sessions,
		roles:    roles,
		invites:  invites,
		policy:   policy,
		recorder: recorder,
		clock:    c,
	}
}

// countRows returns how many rows satisfy query, which must be a SELECT
// count(*) statement.
func countRows(t *testing.T, h *store.Handle, query string, args ...any) int {
	t.Helper()

	var count int

	if err := h.Pool().QueryRow(t.Context(), query, args...).Scan(&count); err != nil {
		t.Fatalf("counting rows: %v", err)
	}

	return count
}

// setSignupPolicy applies a signup Update through the real settings.Store,
// failing the test on error.
func setSignupPolicy(t *testing.T, policy *settings.Store, update settings.Update) {
	t.Helper()

	if _, err := policy.Apply(t.Context(), update, uuid.NullUUID{}, "test:setup"); err != nil {
		t.Fatalf("settings.Apply() error = %v", err)
	}
}

// AC-008.7: an authentication whose identity resolves to an active account
// issues a session, without creating a second account.
func TestLogIn_ExistingActiveAccount_IssuesSession(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	in := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-1",
		Email:         "existing@example.com",
		EmailVerified: true,
		DisplayName:   "Existing User",
		Methods:       []string{session.MethodOIDC},
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() first call error = %v", err)
	}

	again, _, token, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogIn() second call error = %v", err)
	}

	if again.ID != created.ID {
		t.Fatalf("LogIn() second call created a different account: got %v, want %v", again.ID, created.ID)
	}

	if token == "" {
		t.Fatal("LogIn() returned an empty session token")
	}

	got := countRows(t, deps.handle, `SELECT count(*) FROM users`)
	if got != 1 {
		t.Fatalf("users row count = %d, want 1", got)
	}
}

// AC-008.47: a suspended account returns ErrSuspended and issues no session.
func TestLogIn_SuspendedAccount_ReturnsErrSuspended(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	in := Authenticated{
		Provider:    "https://issuer.example",
		Subject:     "sub-suspended",
		DisplayName: "Suspended User",
		Methods:     []string{session.MethodOIDC},
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating account error = %v", err)
	}

	if _, setErr := deps.users.SetStatus(t.Context(), created.ID, user.StatusSuspended); setErr != nil {
		t.Fatalf("SetStatus() error = %v", setErr)
	}

	before := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE user_id = $1`, created.ID)

	_, _, _, err = deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-2", "")
	if !errors.Is(err, ErrSuspended) {
		t.Fatalf("LogIn() error = %v, want ErrSuspended", err)
	}

	after := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE user_id = $1`, created.ID)
	if after != before {
		t.Fatalf("sessions row count changed from %d to %d on a refused login for a suspended account", before, after)
	}
}

// TestLogIn_SuspendedAccountFailureAuditsUserSubject covers AC-008.38: a
// login refused because ByIdentity resolved an account whose status is not
// active audits with subject "user:<id>", not signupSubject's email or
// provider form, which fits only a not-yet-existing identity.
func TestLogIn_SuspendedAccountFailureAuditsUserSubject(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	in := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-suspended-audit",
		Email:         "suspended-audit@example.com",
		EmailVerified: true,
		DisplayName:   "Suspended Audit User",
		Methods:       []string{session.MethodOIDC},
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating account error = %v", err)
	}

	if _, setErr := deps.users.SetStatus(t.Context(), created.ID, user.StatusSuspended); setErr != nil {
		t.Fatalf("SetStatus() error = %v", setErr)
	}

	_, _, _, err = deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-2", "")
	if !errors.Is(err, ErrSuspended) {
		t.Fatalf("LogIn() error = %v, want ErrSuspended", err)
	}

	wantSubject := "user:" + created.ID.String()

	count := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE subject = $1 AND outcome = 'failure'`,
		wantSubject)
	if count != 1 {
		t.Fatalf("audit row count for subject %q = %d, want 1", wantSubject, count)
	}
}

// AC-008.17: LogIn with a non-empty priorToken revokes it unconditionally
// before issuing the new session, leaving zero rows for the prior session
// even when it was already invalid. Session fixation must be impossible.
func TestLogIn_RevokesPriorSessionUnconditionally(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	in := Authenticated{
		Provider:    "https://issuer.example",
		Subject:     "sub-rotate",
		DisplayName: "Rotating User",
		Methods:     []string{session.MethodOIDC},
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	created, _, firstToken, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() first call error = %v", err)
	}

	priorDigest := session.Digest(firstToken)

	before := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE id = $1`, priorDigest)
	if before != 1 {
		t.Fatalf("sessions row count for prior token before rotation = %d, want 1", before)
	}

	_, _, secondToken, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-2", firstToken)
	if err != nil {
		t.Fatalf("LogIn() second call error = %v", err)
	}

	if secondToken == firstToken {
		t.Fatal("LogIn() issued the same token again")
	}

	after := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE id = $1`, priorDigest)
	if after != 0 {
		t.Fatalf("sessions row count for prior token after rotation = %d, want 0", after)
	}

	total := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE user_id = $1`, created.ID)
	if total != 1 {
		t.Fatalf("sessions row count for account after rotation = %d, want 1", total)
	}
}

// AC-008.9: the collision check reads inside the admission transaction, so
// a failed read has already aborted that transaction in Postgres and the
// signup cannot go on to create an account without an address. The read
// failure is reported rather than treated as "no address settled".
func TestSettleEmailTx_ReadFailureFailsTheSignup(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	tx, err := deps.handle.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	t.Cleanup(func() {
		//nolint:errcheck // the transaction is aborted by design; rollback has nothing to report.
		tx.Rollback(context.Background())
	})

	// Abort the transaction the way any failed statement inside it would.
	if _, execErr := tx.Exec(t.Context(), `SELECT 1/0`); execErr == nil {
		t.Fatal("SELECT 1/0 succeeded, want a division-by-zero error to abort the transaction")
	}

	in := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-read-failure",
		Email:         "reader@example.com",
		EmailVerified: true,
		Methods:       []string{session.MethodOIDC},
	}

	settled, err := deps.service.settleEmailTx(t.Context(), tx, in, "203.0.113.5", "req-read-failure")
	if err == nil {
		t.Fatalf("settleEmailTx() error = nil and address = %v, want the read failure reported", settled)
	}
}

// AC-008.9: an unknown identity whose verified email is already held by
// another account produces a second account with a NULL email and leaves
// the first account's email untouched.
func TestLogIn_VerifiedEmailCollision_CreatesAccountWithNullEmail(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	first := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-owner",
		Email:         "shared@example.com",
		EmailVerified: true,
		DisplayName:   "First Owner",
		Methods:       []string{session.MethodOIDC},
	}

	firstUser, _, _, err := deps.service.LogIn(t.Context(), first, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() first account error = %v", err)
	}

	second := Authenticated{
		Provider:      "https://other-issuer.example",
		Subject:       "sub-claimant",
		Email:         "shared@example.com",
		EmailVerified: true,
		DisplayName:   "Second Claimant",
		Methods:       []string{session.MethodOIDC},
	}

	secondUser, _, _, err := deps.service.LogIn(t.Context(), second, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogIn() second account error = %v", err)
	}

	if secondUser.ID == firstUser.ID {
		t.Fatal("LogIn() did not create a second account")
	}

	if secondUser.Email != nil {
		t.Fatalf("second account Email = %v, want nil", *secondUser.Email)
	}

	refetchedFirst, err := deps.users.ByID(t.Context(), firstUser.ID)
	if err != nil {
		t.Fatalf("ByID() first account error = %v", err)
	}

	if refetchedFirst.Email == nil || *refetchedFirst.Email != "shared@example.com" {
		t.Fatalf("first account Email = %v, want shared@example.com", refetchedFirst.Email)
	}

	got := countRows(t, deps.handle, `SELECT count(*) FROM users`)
	if got != 2 {
		t.Fatalf("users row count = %d, want 2", got)
	}

	// The collision writes identity.linked with an address_collision detail.
	collisionCount := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = 'identity.linked' AND outcome = 'failure' AND detail->>'reason' = 'address_collision'`)
	if collisionCount != 1 {
		t.Fatalf("identity.linked address_collision rows = %d, want 1", collisionCount)
	}
}

// TestLogIn_DeletedAccountByIdentity_ReturnsErrSuspended: an account
// soft-deleted after its first login must not fall back into signup
// admission on its next login attempt through the same identity. It must be
// refused with ErrSuspended, issue no session, and write no signup.blocked or
// identity.linked row, since the identity is not unknown, it is refused.
// Covers AC-008.46.
func TestLogIn_DeletedAccountByIdentity_ReturnsErrSuspended(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	in := Authenticated{
		Provider:    "https://issuer.example",
		Subject:     "sub-deleted",
		DisplayName: "Deleted User",
		Methods:     []string{session.MethodOIDC},
	}

	created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating account error = %v", err)
	}

	if deleteErr := deps.users.SoftDelete(t.Context(), created.ID); deleteErr != nil {
		t.Fatalf("SoftDelete() error = %v", deleteErr)
	}

	before := snapshotRowCounts(t, deps)

	_, _, _, err = deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-2", "")
	if !errors.Is(err, ErrSuspended) {
		t.Fatalf("LogIn() error = %v, want ErrSuspended", err)
	}

	assertRowCountsUnchanged(t, deps, before)

	blockedCount := countRows(t, deps.handle, `SELECT count(*) FROM audit_events WHERE action = 'signup.blocked'`)
	if blockedCount != 0 {
		t.Fatalf("signup.blocked row count = %d, want 0", blockedCount)
	}

	linkedCount := countRows(t, deps.handle, `SELECT count(*) FROM audit_events WHERE action = 'identity.linked'`)
	if linkedCount != 0 {
		t.Fatalf("identity.linked row count = %d, want 0", linkedCount)
	}
}

// TestLogInExistingUser_ActiveAccount_IssuesSession: an active account
// resolved by id (the passkey path) gets a session.
// Covers AC-008.11 and AC-008.24.
func TestLogInExistingUser_ActiveAccount_IssuesSession(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	in := Authenticated{
		Provider:    "https://issuer.example",
		Subject:     "sub-existing-active",
		DisplayName: "Existing Active",
		Methods:     []string{session.MethodOIDC},
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating account error = %v", err)
	}

	account, _, token, err := deps.service.LogInExistingUser(t.Context(), created.ID, []string{session.MethodWebAuthn}, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogInExistingUser() error = %v", err)
	}

	if account.ID != created.ID {
		t.Fatalf("LogInExistingUser() account.ID = %v, want %v", account.ID, created.ID)
	}

	if token == "" {
		t.Fatal("LogInExistingUser() returned an empty token")
	}
}

// TestLogInExistingUser_NonActiveAccount_ReturnsErrSuspendedWithNilActor: a
// suspended account and a pending
// account (including one reached only through ByIDAnyStatus's deleted-status
// path) each return ErrSuspended, issue no session, and the refusal
// audit row carries a NULL actor_id, since the caller is not yet an
// authenticated actor.
// Covers AC-008.39, AC-008.47 and AC-008.71.
func TestLogInExistingUser_NonActiveAccount_ReturnsErrSuspendedWithNilActor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		makeStatus func(t *testing.T, deps testDeps, id uuid.UUID)
	}{
		{
			name: "suspended",
			makeStatus: func(t *testing.T, deps testDeps, id uuid.UUID) {
				t.Helper()

				if _, err := deps.users.SetStatus(t.Context(), id, user.StatusSuspended); err != nil {
					t.Fatalf("SetStatus() error = %v", err)
				}
			},
		},
		{
			name: "deleted",
			makeStatus: func(t *testing.T, deps testDeps, id uuid.UUID) {
				t.Helper()

				if err := deps.users.SoftDelete(t.Context(), id); err != nil {
					t.Fatalf("SoftDelete() error = %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deps := newTestService(t, nil)

			setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

			in := Authenticated{
				Provider:    "https://issuer.example",
				Subject:     "sub-nonactive-" + tc.name,
				DisplayName: "Non Active",
				Methods:     []string{session.MethodOIDC},
			}

			created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
			if err != nil {
				t.Fatalf("LogIn() creating account error = %v", err)
			}

			tc.makeStatus(t, deps, created.ID)

			before := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE user_id = $1`, created.ID)

			_, _, _, err = deps.service.LogInExistingUser(t.Context(), created.ID, []string{session.MethodWebAuthn}, "203.0.113.5", "test-agent", "req-2", "")
			if !errors.Is(err, ErrSuspended) {
				t.Fatalf("LogInExistingUser() error = %v, want ErrSuspended", err)
			}

			after := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE user_id = $1`, created.ID)
			if after != before {
				t.Fatalf("sessions row count changed from %d to %d on a refused login", before, after)
			}

			var actorIsNull bool

			if scanErr := deps.handle.Pool().QueryRow(t.Context(),
				`SELECT actor_id IS NULL FROM audit_events WHERE action = $1 AND subject = $2 AND outcome = 'failure'`,
				audit.ActionPasskeyCompleted, "user:"+created.ID.String(),
			).Scan(&actorIsNull); scanErr != nil {
				t.Fatalf("querying refusal audit row: %v", scanErr)
			}

			if !actorIsNull {
				t.Fatal("refusal audit row actor_id is not NULL, want NULL")
			}
		})
	}
}

// TestLogInExistingUser_PriorTokenLeavesZeroRows: a non-empty priorToken
// that names an already-revoked or otherwise dead session leaves zero rows
// for it, the same unconditional revoke LogIn performs.
// Covers AC-008.17.
func TestLogInExistingUser_PriorTokenLeavesZeroRows(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	in := Authenticated{
		Provider:    "https://issuer.example",
		Subject:     "sub-prior-token",
		DisplayName: "Prior Token",
		Methods:     []string{session.MethodOIDC},
	}

	created, _, firstToken, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating account error = %v", err)
	}

	priorDigest := session.Digest(firstToken)

	_, _, secondToken, err := deps.service.LogInExistingUser(t.Context(), created.ID, []string{session.MethodWebAuthn}, "203.0.113.5", "test-agent", "req-2", firstToken)
	if err != nil {
		t.Fatalf("LogInExistingUser() error = %v", err)
	}

	if secondToken == firstToken {
		t.Fatal("LogInExistingUser() issued the same token again")
	}

	after := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE id = $1`, priorDigest)
	if after != 0 {
		t.Fatalf("sessions row count for prior token after LogInExistingUser = %d, want 0", after)
	}
}

// TestLinkIdentity_Success_ResolvesThroughByIdentity (AC-008.43): a
// successful link makes the identity resolve through ByIdentity to the
// account it was linked to.
func TestLinkIdentity_Success_ResolvesThroughByIdentity(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	in := Authenticated{
		Provider:    "https://issuer.example",
		Subject:     "sub-link-owner",
		DisplayName: "Link Owner",
		Methods:     []string{session.MethodOIDC},
	}

	owner, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating owner error = %v", err)
	}

	link := Authenticated{
		Provider:      "email",
		Subject:       "link@example.com",
		Email:         "link@example.com",
		EmailVerified: true,
	}

	if linkErr := deps.service.LinkIdentity(t.Context(), owner.ID, owner.ID, link, "203.0.113.5", "req-2"); linkErr != nil {
		t.Fatalf("LinkIdentity() error = %v, want nil", linkErr)
	}

	linkedUser, linkedIdentity, err := deps.users.ByIdentity(t.Context(), "email", "link@example.com")
	if err != nil {
		t.Fatalf("ByIdentity() error = %v, want nil", err)
	}

	if linkedUser.ID != owner.ID {
		t.Fatalf("ByIdentity() user.ID = %v, want %v", linkedUser.ID, owner.ID)
	}

	if linkedIdentity.Email == nil || *linkedIdentity.Email != "link@example.com" {
		t.Fatalf("ByIdentity() identity.Email = %v, want link@example.com", linkedIdentity.Email)
	}
}

// TestLinkIdentity_FlowUserMismatch_ReturnsErrLinkFlowMismatch (AC-008.43):
// a link ceremony finished by a session other than the one that
// started it is refused with ErrLinkFlowMismatch, and no identity row is
// created. uuid.Nil in either position is refused the same way.
func TestLinkIdentity_FlowUserMismatch_ReturnsErrLinkFlowMismatch(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	inA := Authenticated{Provider: "https://issuer.example", Subject: "sub-flow-a", DisplayName: "Flow A", Methods: []string{session.MethodOIDC}}
	accountA, _, _, err := deps.service.LogIn(t.Context(), inA, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating accountA error = %v", err)
	}

	inB := Authenticated{Provider: "https://issuer.example", Subject: "sub-flow-b", DisplayName: "Flow B", Methods: []string{session.MethodOIDC}}
	accountB, _, _, err := deps.service.LogIn(t.Context(), inB, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogIn() creating accountB error = %v", err)
	}

	link := Authenticated{Provider: "email", Subject: "flow-mismatch@example.com", Email: "flow-mismatch@example.com", EmailVerified: true}

	tests := []struct {
		name       string
		userID     uuid.UUID
		flowUserID uuid.UUID
	}{
		{name: "mismatched users", userID: accountA.ID, flowUserID: accountB.ID},
		{name: "nil userID", userID: uuid.Nil, flowUserID: accountB.ID},
		{name: "nil flowUserID", userID: accountA.ID, flowUserID: uuid.Nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			linkIdentityErr := deps.service.LinkIdentity(t.Context(), tc.userID, tc.flowUserID, link, "203.0.113.5", "req-mismatch")
			if !errors.Is(linkIdentityErr, ErrLinkFlowMismatch) {
				t.Fatalf("LinkIdentity() error = %v, want ErrLinkFlowMismatch", linkIdentityErr)
			}
		})
	}

	identityCount := countRows(t, deps.handle, `SELECT count(*) FROM identities WHERE provider = 'email' AND subject = $1`, link.Subject)
	if identityCount != 0 {
		t.Fatalf("identities row count = %d, want 0 (no row for a refused link ceremony)", identityCount)
	}
}

// TestLinkIdentity_SuspendedAccount_ReturnsErrSuspended (AC-008.43): a
// suspended account may not have an identity linked.
func TestLinkIdentity_SuspendedAccount_ReturnsErrSuspended(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	in := Authenticated{Provider: "https://issuer.example", Subject: "sub-link-suspended", DisplayName: "Link Suspended", Methods: []string{session.MethodOIDC}}

	account, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating account error = %v", err)
	}

	if _, statusErr := deps.users.SetStatus(t.Context(), account.ID, user.StatusSuspended); statusErr != nil {
		t.Fatalf("SetStatus() error = %v", statusErr)
	}

	link := Authenticated{Provider: "email", Subject: "link-suspended@example.com", Email: "link-suspended@example.com", EmailVerified: true}

	err = deps.service.LinkIdentity(t.Context(), account.ID, account.ID, link, "203.0.113.5", "req-2")
	if !errors.Is(err, ErrSuspended) {
		t.Fatalf("LinkIdentity() error = %v, want ErrSuspended", err)
	}
}

// TestLinkIdentity_AlreadyLinkedToAnotherAccount_ReturnsWrappedErrIdentityLinked
// (AC-008.43): an identity already linked to account B, when a different
// account A attempts to link the same provider and subject pair, returns the
// wrapped user.ErrIdentityLinked, and B's own link is left intact.
func TestLinkIdentity_AlreadyLinkedToAnotherAccount_ReturnsWrappedErrIdentityLinked(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	inA := Authenticated{Provider: "https://issuer.example", Subject: "sub-linked-a", DisplayName: "Linked A", Methods: []string{session.MethodOIDC}}
	accountA, _, _, err := deps.service.LogIn(t.Context(), inA, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating accountA error = %v", err)
	}

	inB := Authenticated{Provider: "https://issuer.example", Subject: "sub-linked-b", DisplayName: "Linked B", Methods: []string{session.MethodOIDC}}
	accountB, _, _, err := deps.service.LogIn(t.Context(), inB, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogIn() creating accountB error = %v", err)
	}

	shared := Authenticated{Provider: "email", Subject: "shared-link@example.com", Email: "shared-link@example.com", EmailVerified: true}

	if linkErr := deps.service.LinkIdentity(t.Context(), accountB.ID, accountB.ID, shared, "203.0.113.5", "req-b"); linkErr != nil {
		t.Fatalf("LinkIdentity() accountB error = %v, want nil", linkErr)
	}

	err = deps.service.LinkIdentity(t.Context(), accountA.ID, accountA.ID, shared, "203.0.113.5", "req-a")
	if !errors.Is(err, user.ErrIdentityLinked) {
		t.Fatalf("LinkIdentity() accountA error = %v, want wrapped user.ErrIdentityLinked", err)
	}

	linkedUser, _, err := deps.users.ByIdentity(t.Context(), "email", "shared-link@example.com")
	if err != nil {
		t.Fatalf("ByIdentity() error = %v, want nil", err)
	}

	if linkedUser.ID != accountB.ID {
		t.Fatalf("ByIdentity() user.ID = %v, want %v (account B's link must survive)", linkedUser.ID, accountB.ID)
	}
}

// TestLinkIdentity_UnverifiedEmail_StoresNullOnIdentity (AC-008.43): an
// unverified email is stored as NULL on the identity row, not as the
// asserted address.
func TestLinkIdentity_UnverifiedEmail_StoresNullOnIdentity(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	in := Authenticated{Provider: "https://issuer.example", Subject: "sub-link-unverified", DisplayName: "Link Unverified", Methods: []string{session.MethodOIDC}}

	account, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating account error = %v", err)
	}

	link := Authenticated{Provider: "totp", Subject: "sub-unverified-link", Email: "unverified-link@example.com", EmailVerified: false}

	if linkErr := deps.service.LinkIdentity(t.Context(), account.ID, account.ID, link, "203.0.113.5", "req-2"); linkErr != nil {
		t.Fatalf("LinkIdentity() error = %v, want nil", linkErr)
	}

	_, linkedIdentity, err := deps.users.ByIdentity(t.Context(), "totp", "sub-unverified-link")
	if err != nil {
		t.Fatalf("ByIdentity() error = %v, want nil", err)
	}

	if linkedIdentity.Email != nil {
		t.Fatalf("ByIdentity() identity.Email = %v, want nil (unverified address must not be stored)", *linkedIdentity.Email)
	}
}

// AC-008.36: a bootstrap-list address with EmailVerified false receives no
// admin role, while the same address verified does.
func TestLogIn_BootstrapAdmin_RequiresVerifiedEmail(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"root@example.com"})

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	unverified := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-unverified-root",
		Email:         "root@example.com",
		EmailVerified: false,
		DisplayName:   "Unverified Root",
		Methods:       []string{session.MethodOIDC},
	}

	unverifiedUser, _, _, err := deps.service.LogIn(t.Context(), unverified, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() unverified error = %v", err)
	}

	roles, err := deps.roles.RolesFor(t.Context(), unverifiedUser.ID)
	if err != nil {
		t.Fatalf("RolesFor() error = %v", err)
	}

	if slices.Contains(roles, authz.RoleAdmin) {
		t.Fatalf("unverified bootstrap address roles = %v, must not contain admin", roles)
	}

	verified := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-verified-root",
		Email:         "root@example.com",
		EmailVerified: true,
		DisplayName:   "Verified Root",
		Methods:       []string{session.MethodOIDC},
	}

	verifiedUser, _, _, err := deps.service.LogIn(t.Context(), verified, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogIn() verified error = %v", err)
	}

	roles, err = deps.roles.RolesFor(t.Context(), verifiedUser.ID)
	if err != nil {
		t.Fatalf("RolesFor() error = %v", err)
	}

	if !slices.Contains(roles, authz.RoleAdmin) {
		t.Fatalf("verified bootstrap address roles = %v, want to contain admin", roles)
	}
}

// AC-008.31, AC-008.32: a new account always holds member, and Subject resolves its
// permission to exactly invite.create; an admin's Subject resolves to every
// permission.
func TestLogIn_NewAccountHoldsMember_SubjectResolvesPermissions(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin@example.com"})

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	member := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-member",
		Email:         "member@example.com",
		EmailVerified: true,
		DisplayName:   "Member User",
		Methods:       []string{session.MethodOIDC},
	}

	memberUser, _, memberToken, err := deps.service.LogIn(t.Context(), member, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() member error = %v", err)
	}

	memberSession, err := deps.sessions.Lookup(t.Context(), memberToken)
	if err != nil {
		t.Fatalf("session.Lookup() error = %v", err)
	}

	memberSubject, err := deps.service.Subject(t.Context(), memberUser.ID, memberSession.PublicID)
	if err != nil {
		t.Fatalf("Subject() member error = %v", err)
	}

	wantMember := []string{authz.PermissionInviteCreate}
	if !slices.Equal(memberSubject.Permissions, wantMember) {
		t.Fatalf("member Subject().Permissions = %v, want %v", memberSubject.Permissions, wantMember)
	}

	admin := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-admin",
		Email:         "admin@example.com",
		EmailVerified: true,
		DisplayName:   "Admin User",
		Methods:       []string{session.MethodOIDC},
	}

	adminUser, _, adminToken, err := deps.service.LogIn(t.Context(), admin, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogIn() admin error = %v", err)
	}

	adminSession, err := deps.sessions.Lookup(t.Context(), adminToken)
	if err != nil {
		t.Fatalf("session.Lookup() error = %v", err)
	}

	adminSubject, err := deps.service.Subject(t.Context(), adminUser.ID, adminSession.PublicID)
	if err != nil {
		t.Fatalf("Subject() admin error = %v", err)
	}

	wantAdmin := []string{
		authz.PermissionAuditRead,
		authz.PermissionInviteCreate,
		authz.PermissionInviteManage,
		authz.PermissionSessionRevokeAny,
		authz.PermissionSettingsManage,
		authz.PermissionUserApprove,
		authz.PermissionUserRead,
		authz.PermissionUserRoleGrant,
		authz.PermissionUserWrite,
	}
	if !slices.Equal(adminSubject.Permissions, wantAdmin) {
		t.Fatalf("admin Subject().Permissions = %v, want %v", adminSubject.Permissions, wantAdmin)
	}
}
