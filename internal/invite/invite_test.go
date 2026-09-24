//go:build integration

package invite

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// txExecer is the transaction type RedeemTx and ValidateTx accept, named here
// so this file's withTx helper reads clearly.
type txExecer = pgx.Tx

// tokenBytesForTest is the token length every test service in this file uses.
const tokenBytesForTest = 32

// clock is a manually advanced clock for tests that must control the passage
// of time without sleeping.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

// newClock returns a clock starting at the current wall time.
func newClock() *clock {
	return &clock{now: time.Now()}
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

// newTestService returns a Service backed by a fresh migrated database and
// c's clock, together with the handle it was built from and the settings
// store backing its policy.
func newTestService(t *testing.T, c *clock) (*Service, *store.Handle) {
	t.Helper()

	h := storetest.New(t)
	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)

	svc, err := NewService(h, policy, tokenBytesForTest, zap.NewNop(), c.Now)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return svc, h
}

// insertUser inserts a minimal user row, since internal/user is a separate
// package this unit does not depend on.
func insertUser(t *testing.T, h *store.Handle) uuid.UUID {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("insertUser: generating id: %v", err)
	}

	now := time.Now()

	const insertUserQuery = `
INSERT INTO users (id, display_name, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
`

	if _, execErr := h.Pool().Exec(t.Context(), insertUserQuery, id, "test user", "active", now, now); execErr != nil {
		t.Fatalf("insertUser: inserting: %v", execErr)
	}

	return id
}

// TestCreateReturnsTokenLookupResolves covers AC-008.64: Create returns a
// token Lookup can resolve, and the stored digest is not the token itself.
func TestCreateReturnsTokenLookupResolves(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if issued.Token == "" {
		t.Fatal("Create() returned an empty token")
	}

	found, err := svc.Lookup(t.Context(), issued.Token)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	if found.ID != issued.Invite.ID {
		t.Errorf("Lookup().ID = %v, want %v", found.ID, issued.Invite.ID)
	}

	var storedHash []byte

	if scanErr := h.Pool().QueryRow(t.Context(), `SELECT token_hash FROM invites WHERE id = $1`, issued.Invite.ID).Scan(&storedHash); scanErr != nil {
		t.Fatalf("scanning stored token_hash: %v", scanErr)
	}

	if string(storedHash) == issued.Token {
		t.Error("stored token_hash equals the raw token; it must be a digest")
	}
}

// TestLookupDoesNotConsume covers AC-008.65: a second Lookup of the same
// token still resolves.
func TestLookupDoesNotConsume(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if _, lookupErr := svc.Lookup(t.Context(), issued.Token); lookupErr != nil {
		t.Fatalf("Lookup() first call error = %v", lookupErr)
	}

	if _, lookupErr := svc.Lookup(t.Context(), issued.Token); lookupErr != nil {
		t.Fatalf("Lookup() second call error = %v, want success: Lookup must not consume", lookupErr)
	}
}

// TestLookupFailsIndistinguishablyForDeadTokens covers AC-008.57: an unknown,
// an expired, a revoked, and a fully spent invite all return ErrInvalid
// without distinguishing them.
func TestLookupFailsIndistinguishablyForDeadTokens(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	unknownToken := "this-token-was-never-issued-000000000000000"

	expired, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create() expired error = %v", err)
	}

	revoked, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() revoked error = %v", err)
	}

	if _, revokeErr := svc.Revoke(t.Context(), revoked.Invite.ID, issuer, false); revokeErr != nil {
		t.Fatalf("Revoke() error = %v", revokeErr)
	}

	spent, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() spent error = %v", err)
	}

	redeemer := insertUser(t, h)

	if redeemErr := withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, spent.Invite.ID, redeemer, "user:redeemer", "")
	}); redeemErr != nil {
		t.Fatalf("RedeemTx() spending the only use, error = %v", redeemErr)
	}

	c.Advance(2 * time.Minute)

	cases := []struct {
		name  string
		token string
	}{
		{name: "unknown", token: unknownToken},
		{name: "expired", token: expired.Token},
		{name: "revoked", token: revoked.Token},
		{name: "spent", token: spent.Token},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, lookupErr := svc.Lookup(t.Context(), tt.token); !errors.Is(lookupErr, ErrInvalid) {
				t.Errorf("Lookup(%s) error = %v, want ErrInvalid", tt.name, lookupErr)
			}
		})
	}
}

// TestCreateWithZeroQuotaFails covers AC-008.66: a quota of zero always
// returns ErrQuotaExhausted. The seeded settings row already carries a zero
// invite_default_quota, so this test needs no explicit settings.Apply to
// reach it.
func TestCreateWithZeroQuotaFails(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	_, err := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1})
	if !errors.Is(err, ErrQuotaExhausted) {
		t.Errorf("Create() with quota 0, error = %v, want ErrQuotaExhausted", err)
	}
}

// TestCreateQuotaCountsOnlyLiveInvites covers AC-008.66: a quota of two
// succeeds twice and fails the third time, then succeeds again once one of
// the two is revoked, proving the quota counts live invites rather than all
// invites.
func TestCreateQuotaCountsOnlyLiveInvites(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)
	quota := 2

	if _, err := policy.Apply(t.Context(), settings.Update{InviteDefaultQuota: &quota}, uuid.NullUUID{}, "test:setup"); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	first, err := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() first, error = %v", err)
	}

	if _, createErr := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1}); createErr != nil {
		t.Fatalf("Create() second, error = %v", createErr)
	}

	if _, createErr := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1}); !errors.Is(createErr, ErrQuotaExhausted) {
		t.Fatalf("Create() third, error = %v, want ErrQuotaExhausted", createErr)
	}

	if _, revokeErr := svc.Revoke(t.Context(), first.Invite.ID, issuer, false); revokeErr != nil {
		t.Fatalf("Revoke() error = %v", revokeErr)
	}

	if _, createErr := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1}); createErr != nil {
		t.Fatalf("Create() after revoking one, error = %v, want success", createErr)
	}
}

// TestCreateQuotaCountsOnlyLiveInvitesAfterSpend covers AC-008.66, the
// non-revocation half of the same rule: a fully spent invite is no longer
// live, so it must stop consuming the issuer's quota for the rest of its TTL
// rather than locking the issuer out until it expires.
func TestCreateQuotaCountsOnlyLiveInvitesAfterSpend(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)
	quota := 1

	if _, err := policy.Apply(t.Context(), settings.Update{InviteDefaultQuota: &quota}, uuid.NullUUID{}, "test:setup"); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	first, err := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() first, error = %v", err)
	}

	if _, createErr := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1}); !errors.Is(createErr, ErrQuotaExhausted) {
		t.Fatalf("Create() second, error = %v, want ErrQuotaExhausted", createErr)
	}

	redeemer := insertUser(t, h)

	if withTxErr := withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, first.Invite.ID, redeemer, "user:redeemer", "")
	}); withTxErr != nil {
		t.Fatalf("RedeemTx() spending the only use, error = %v", withTxErr)
	}

	if _, createErr := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1}); createErr != nil {
		t.Errorf("Create() after spending the invite to exhaustion, error = %v, want success: quota should be freed", createErr)
	}
}

// TestCreateWithZeroMaxUsesDefaultsToSingleUse covers Params' doc comment: a
// zero MaxUses takes the configured default. Every other Create call in this
// suite passes MaxUses explicitly, so without this test the default could
// silently regress and every other test would still pass. With
// settings.Options{}, withOptions replaces a zero InviteDefaultMaxUses with 1,
// which is why the seeded policy's default is exactly 1 here.
// Covers AC-008.81.
func TestCreateWithZeroMaxUsesDefaultsToSingleUse(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)

	loaded, err := policy.Load(t.Context())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if issued.Invite.MaxUses != loaded.InviteDefaultMaxUses {
		t.Errorf("Create() with a zero MaxUses, invite.MaxUses = %d, want %d", issued.Invite.MaxUses, loaded.InviteDefaultMaxUses)
	}
}

// TestCreateWithNegativeMaxUsesDefaultsToSingleUse covers FIX-8: a negative
// MaxUses does not reach the max_uses > 0 CHECK constraint, where it would
// surface as a wrapped PgError rather than a sentinel and leak a constraint
// name; it takes the same default a zero MaxUses does.
// Covers AC-008.81.
func TestCreateWithNegativeMaxUsesDefaultsToSingleUse(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)

	loaded, err := policy.Load(t.Context())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: -1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if issued.Invite.MaxUses != loaded.InviteDefaultMaxUses {
		t.Errorf("Create() with a negative MaxUses, invite.MaxUses = %d, want %d", issued.Invite.MaxUses, loaded.InviteDefaultMaxUses)
	}
}

// TestCreateRejectsMaxUsesAboveCeiling covers AC-008.62.
func TestCreateRejectsMaxUsesAboveCeiling(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	_, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 100000})
	if !errors.Is(err, ErrMaxUsesTooHigh) {
		t.Errorf("Create() with an excessive MaxUses, error = %v, want ErrMaxUsesTooHigh", err)
	}
}

// TestCreateWithZeroTTLUsesConfiguredDefault covers AC-008.62.
func TestCreateWithZeroTTLUsesConfiguredDefault(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)

	loaded, err := policy.Load(t.Context())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	wantExpiry := c.Now().Add(time.Duration(loaded.InviteDefaultTTLSecs) * time.Second)

	if !issued.Invite.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", issued.Invite.ExpiresAt, wantExpiry)
	}
}

// TestValidateTxLiveAndDeadStates covers AC-008.57: ValidateTx returns the
// invite for a live one and ErrInvalid, indistinguishably, for each of the
// revoked, expired, and spent cases.
func TestValidateTxLiveAndDeadStates(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	live, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() live, error = %v", err)
	}

	if liveErr := withTx(t, h, func(tx txExecer) error {
		_, validateErr := svc.ValidateTx(t.Context(), tx, live.Invite.ID, "")
		return validateErr
	}); liveErr != nil {
		t.Errorf("ValidateTx() for a live invite, error = %v, want nil", liveErr)
	}

	expired, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create() expired, error = %v", err)
	}

	revoked, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() revoked, error = %v", err)
	}

	if _, revokeErr := svc.Revoke(t.Context(), revoked.Invite.ID, issuer, false); revokeErr != nil {
		t.Fatalf("Revoke() error = %v", revokeErr)
	}

	spent, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() spent, error = %v", err)
	}

	redeemer := insertUser(t, h)

	if withTxErr := withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, spent.Invite.ID, redeemer, "user:redeemer", "")
	}); withTxErr != nil {
		t.Fatalf("RedeemTx() spending the only use, error = %v", withTxErr)
	}

	c.Advance(2 * time.Minute)

	cases := []struct {
		name string
		id   uuid.UUID
	}{
		{name: "expired", id: expired.Invite.ID},
		{name: "revoked", id: revoked.Invite.ID},
		{name: "spent", id: spent.Invite.ID},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			withTxErr := withTx(t, h, func(tx txExecer) error {
				_, validateErr := svc.ValidateTx(t.Context(), tx, tt.id, "")
				return validateErr
			})
			if !errors.Is(withTxErr, ErrInvalid) {
				t.Errorf("ValidateTx(%s) error = %v, want ErrInvalid", tt.name, withTxErr)
			}
		})
	}
}

// TestValidateTxEmailBinding covers AC-008.58: ValidateTx on an email-bound
// invite returns ErrEmailMismatch for an empty verifiedEmail and for a
// different address, and succeeds for the bound address differing only in
// case.
func TestValidateTxEmailBinding(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, Email: "Alice@Example.com"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	cases := []struct {
		name          string
		verifiedEmail string
		wantErr       error
	}{
		{name: "empty", verifiedEmail: "", wantErr: ErrEmailMismatch},
		{name: "different address", verifiedEmail: "mallory@example.com", wantErr: ErrEmailMismatch},
		{name: "bound address differing only in case", verifiedEmail: "alice@EXAMPLE.com", wantErr: nil},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			withTxErr := withTx(t, h, func(tx txExecer) error {
				_, validateErr := svc.ValidateTx(t.Context(), tx, issued.Invite.ID, tt.verifiedEmail)
				return validateErr
			})

			if tt.wantErr == nil {
				if withTxErr != nil {
					t.Errorf("ValidateTx() error = %v, want nil", withTxErr)
				}

				return
			}

			if !errors.Is(withTxErr, tt.wantErr) {
				t.Errorf("ValidateTx() error = %v, want %v", withTxErr, tt.wantErr)
			}
		})
	}
}

// TestRedeemTxSingleUseSpendsOnce covers AC-008.65: RedeemTx on a single-use
// invite succeeds once and returns ErrInvalid the second time.
func TestRedeemTxSingleUseSpendsOnce(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	firstRedeemer := insertUser(t, h)

	if firstErr := withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, issued.Invite.ID, firstRedeemer, "user:first", "")
	}); firstErr != nil {
		t.Fatalf("RedeemTx() first call, error = %v", firstErr)
	}

	secondRedeemer := insertUser(t, h)

	err = withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, issued.Invite.ID, secondRedeemer, "user:second", "")
	})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("RedeemTx() second call, error = %v, want ErrInvalid", err)
	}
}

// concurrentRedeemers is how many goroutines
// TestRedeemTxConcurrentSingleUseSucceedsOnce launches against one invite.
// Each must acquire its own pool connection, BEGIN, and round-trip to
// Postgres before reaching the conditional UPDATE, so a start barrier that
// releases every goroutine at once, rather than a bare loop, is what makes
// their overlap at the database real instead of accidental.
const concurrentRedeemers = 8

// TestRedeemTxConcurrentSingleUseSucceedsOnce covers AC-008.65: eight
// concurrent redemptions of a single-use invite must not have more than one
// succeed. -race adds nothing to this test on its own, because the contended
// resource is a database row rather than Go memory; the barrier is what makes
// the contention real.
func TestRedeemTxConcurrentSingleUseSucceedsOnce(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	redeemers := make([]uuid.UUID, concurrentRedeemers)
	for i := range redeemers {
		redeemers[i] = insertUser(t, h)
	}

	var wg sync.WaitGroup

	var ready sync.WaitGroup

	ready.Add(concurrentRedeemers)

	start := make(chan struct{})

	results := make([]error, concurrentRedeemers)

	for i := range concurrentRedeemers {
		wg.Add(1)

		go func(slot int) {
			defer wg.Done()

			ready.Done()
			<-start

			results[slot] = withTx(t, h, func(tx txExecer) error {
				return svc.RedeemTx(t.Context(), tx, issued.Invite.ID, redeemers[slot], "user:concurrent", "")
			})
		}(i)
	}

	ready.Wait()
	close(start)
	wg.Wait()

	successes := 0

	for _, err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("RedeemTx() concurrent call, error = %v, want nil or ErrInvalid", err)
		}
	}

	if successes != 1 {
		t.Errorf("successful concurrent redemptions = %d, want 1", successes)
	}

	var uses int

	if scanErr := h.Pool().QueryRow(t.Context(), `SELECT uses FROM invites WHERE id = $1`, issued.Invite.ID).Scan(&uses); scanErr != nil {
		t.Fatalf("scanning uses: %v", scanErr)
	}

	if uses != 1 {
		t.Errorf("uses = %d, want 1", uses)
	}
}

// TestRedeemTxMultiUseSucceedsExactlyMaxUsesTimes covers AC-008.65: a
// five-use invite succeeds five times and fails the sixth.
func TestRedeemTxMultiUseSucceedsExactlyMaxUsesTimes(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 5})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	for i := range 5 {
		redeemer := insertUser(t, h)

		if redeemErr := withTx(t, h, func(tx txExecer) error {
			return svc.RedeemTx(t.Context(), tx, issued.Invite.ID, redeemer, "user:redeemer", "")
		}); redeemErr != nil {
			t.Fatalf("RedeemTx() call %d, error = %v, want success", i, redeemErr)
		}
	}

	sixthRedeemer := insertUser(t, h)

	err = withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, issued.Invite.ID, sixthRedeemer, "user:sixth", "")
	})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("RedeemTx() sixth call, error = %v, want ErrInvalid", err)
	}
}

// TestRedeemTxEmailBinding covers AC-008.58: RedeemTx on an email-bound
// invite returns ErrEmailMismatch for an empty verifiedEmail and for a
// different address, and succeeds for the bound address differing only in
// case.
func TestRedeemTxEmailBinding(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	empty, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, Email: "bob@example.com"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	redeemer1 := insertUser(t, h)

	err = withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, empty.Invite.ID, redeemer1, "user:redeemer", "")
	})
	if !errors.Is(err, ErrEmailMismatch) {
		t.Errorf("RedeemTx() with empty verifiedEmail, error = %v, want ErrEmailMismatch", err)
	}

	different, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, Email: "carol@example.com"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	redeemer2 := insertUser(t, h)

	err = withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, different.Invite.ID, redeemer2, "user:redeemer", "mallory@example.com")
	})
	if !errors.Is(err, ErrEmailMismatch) {
		t.Errorf("RedeemTx() with a different address, error = %v, want ErrEmailMismatch", err)
	}

	matching, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, Email: "dave@example.com"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	redeemer3 := insertUser(t, h)

	if withTxErr := withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, matching.Invite.ID, redeemer3, "user:redeemer", "DAVE@EXAMPLE.com")
	}); withTxErr != nil {
		t.Errorf("RedeemTx() with the bound address differing only in case, error = %v, want nil", withTxErr)
	}
}

// TestListReturnsOnlyOwnInvites covers AC-008.67 and is the ownership
// isolation test (design.md's "Authorization path") for List.
func TestListReturnsOnlyOwnInvites(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	userA := insertUser(t, h)
	userB := insertUser(t, h)

	issuedA, err := svc.Create(t.Context(), userA, "user:a", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() for A, error = %v", err)
	}

	issuedB, err := svc.Create(t.Context(), userB, "user:b", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() for B, error = %v", err)
	}

	listA, _, err := svc.List(t.Context(), userA, false, "", 50)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	foundA := false

	for _, inv := range listA {
		if inv.ID == issuedB.Invite.ID {
			t.Error("List(userA) contains userB's invite")
		}

		if inv.ID == issuedA.Invite.ID {
			foundA = true
		}
	}

	if !foundA {
		t.Error("List(userA) does not contain userA's own invite")
	}
}

// TestListWithNonPositiveLimitDoesNotPanic covers FIX-1: List(limit=0) and
// List(limit=-1) must not panic. Before the fix, listQueryAndArgs passed
// limit+1 to LIMIT with no floor: LIMIT 1 against one row made
// len(invites) <= limit false (1 <= 0), so invites[:0] followed by
// page[len(page)-1] panicked with index out of range for limit 0, and a
// negative limit panicked outright at the slice expression.
// Covers AC-008.67.
func TestListWithNonPositiveLimitDoesNotPanic(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	if _, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	tests := []struct {
		name  string
		limit int
	}{
		{name: "zero", limit: 0},
		{name: "negative", limit: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			invites, _, err := svc.List(t.Context(), issuer, false, "", tt.limit)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}

			if len(invites) == 0 {
				t.Error("List() returned no invites, want at least the one created above")
			}
		})
	}
}

// TestListClampsLimitAboveMaxPageSize covers FIX-1's ceiling: a limit above
// maxPageSize returns at most maxPageSize invites, so a caller cannot request
// an unbounded page.
// Covers AC-008.67.
func TestListClampsLimitAboveMaxPageSize(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	for range maxPageSize + 5 {
		if _, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1}); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	invites, _, err := svc.List(t.Context(), issuer, false, "", maxPageSize+1000)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(invites) > maxPageSize {
		t.Errorf("len(invites) = %d, want at most %d", len(invites), maxPageSize)
	}
}

// TestListCursorDoesNotDistinguishOtherIssuersInvite covers FIX-7: presenting
// another issuer's real invite id as a cursor must return the same result as
// presenting an id that does not exist at all. Before the fix, the cursor
// subquery resolved any invite by id regardless of created_by, so a viewer
// who guessed another issuer's invite UUID could distinguish "exists" from
// "does not exist" by whether List's outer, correctly owner-scoped query
// returned any of the viewer's own earlier invites relative to it.
// Covers AC-008.35.
func TestListCursorDoesNotDistinguishOtherIssuersInvite(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	userA := insertUser(t, h)
	userB := insertUser(t, h)

	if _, err := svc.Create(t.Context(), userA, "user:a", true, Params{MaxUses: 1}); err != nil {
		t.Fatalf("Create() for A's earlier invite, error = %v", err)
	}

	c.Advance(time.Second)

	issuedB, err := svc.Create(t.Context(), userB, "user:b", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() for B, error = %v", err)
	}

	c.Advance(time.Second)

	_, err = svc.Create(t.Context(), userA, "user:a", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() for A's later invite, error = %v", err)
	}

	withRealCursor, _, err := svc.List(t.Context(), userA, false, issuedB.Invite.ID.String(), 50)
	if err != nil {
		t.Fatalf("List() with B's real invite id as cursor, error = %v", err)
	}

	nonexistent, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}

	withUnknownCursor, _, err := svc.List(t.Context(), userA, false, nonexistent.String(), 50)
	if err != nil {
		t.Fatalf("List() with an unknown cursor, error = %v", err)
	}

	if len(withRealCursor) != len(withUnknownCursor) {
		t.Errorf("List(userA) with B's real invite id as cursor returned %d invites, want %d (the same as an unknown id), which would let A learn B's invite exists", len(withRealCursor), len(withUnknownCursor))
	}
}

// TestListWithMalformedCursorReturnsErrInvalidCursor covers AC-008.67 and
// design.md's "Interfaces" section: a cursor that is not a UUID List itself
// could have issued must be reported so the caller can answer the request
// as malformed, rather than as a server failure.
func TestListWithMalformedCursorReturnsErrInvalidCursor(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	if _, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	_, _, err := svc.List(t.Context(), issuer, false, "not-a-uuid", 50)
	if !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("List() error = %v, want errors.Is(err, ErrInvalidCursor)", err)
	}
}

// TestGetIsScopedToIssuer covers AC-008.67 and is the ownership isolation
// test (design.md's "Authorization path") for Get. Both A and B hold a row:
// if Get's owner-scoped branch matched
// nothing at all rather than the viewer's own row, this test would still pass
// on the B assertion alone, so it also arranges an invite for A and asserts A
// can read it back.
func TestGetIsScopedToIssuer(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	userA := insertUser(t, h)
	userB := insertUser(t, h)

	issuedA, err := svc.Create(t.Context(), userA, "user:a", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() for A, error = %v", err)
	}

	issuedB, err := svc.Create(t.Context(), userB, "user:b", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() for B, error = %v", err)
	}

	if _, getErr := svc.Get(t.Context(), issuedB.Invite.ID, userA, false); !errors.Is(getErr, ErrInvalid) {
		t.Errorf("Get() for B's invite as A, error = %v, want ErrInvalid", getErr)
	}

	if _, getErr := svc.Get(t.Context(), issuedB.Invite.ID, userB, false); getErr != nil {
		t.Errorf("Get() for B's own invite as B, error = %v, want nil", getErr)
	}

	if _, getErr := svc.Get(t.Context(), issuedA.Invite.ID, userA, false); getErr != nil {
		t.Errorf("Get() for A's own invite as A, error = %v, want nil", getErr)
	}
}

// TestRevokeIsScopedToIssuer covers AC-008.67 and is the ownership
// isolation test (design.md's "Authorization path") for Revoke. Both A and
// B hold a row: if Revoke's owner-scoped branch
// matched nothing at all rather than the viewer's own row, changed would
// still be false and B's row would still be live, so this test also
// arranges an invite for A and asserts A can revoke it.
func TestRevokeIsScopedToIssuer(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	userA := insertUser(t, h)
	userB := insertUser(t, h)

	issuedA, err := svc.Create(t.Context(), userA, "user:a", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() for A, error = %v", err)
	}

	issuedB, err := svc.Create(t.Context(), userB, "user:b", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() for B, error = %v", err)
	}

	changed, err := svc.Revoke(t.Context(), issuedB.Invite.ID, userA, false)
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	if changed {
		t.Error("Revoke() changed = true, want false when the caller does not own the invite")
	}

	stillLive, err := svc.Get(t.Context(), issuedB.Invite.ID, userB, false)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if stillLive.RevokedAt != nil {
		t.Error("Revoke() by a non-owner revoked B's invite")
	}

	changedA, err := svc.Revoke(t.Context(), issuedA.Invite.ID, userA, false)
	if err != nil {
		t.Fatalf("Revoke() for A's own invite, error = %v", err)
	}

	if !changedA {
		t.Error("Revoke() for A's own invite, changed = false, want true")
	}
}

// TestOutstandingCountsOnlyOwnInvites covers AC-008.66 and is the
// ownership isolation test (design.md's "Authorization path") for
// Outstanding.
func TestOutstandingCountsOnlyOwnInvites(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	userA := insertUser(t, h)
	userB := insertUser(t, h)

	if _, err := svc.Create(t.Context(), userB, "user:b", true, Params{MaxUses: 1}); err != nil {
		t.Fatalf("Create() for B, error = %v", err)
	}

	countA, err := svc.Outstanding(t.Context(), userA)
	if err != nil {
		t.Fatalf("Outstanding() error = %v", err)
	}

	if countA != 0 {
		t.Errorf("Outstanding(userA) = %d, want 0", countA)
	}

	if _, createErr := svc.Create(t.Context(), userA, "user:a", true, Params{MaxUses: 1}); createErr != nil {
		t.Fatalf("Create() for A, error = %v", createErr)
	}

	countA, err = svc.Outstanding(t.Context(), userA)
	if err != nil {
		t.Fatalf("Outstanding() error = %v", err)
	}

	if countA != 1 {
		t.Errorf("Outstanding(userA) after A's own Create = %d, want 1", countA)
	}
}

// TestRevokeIsIdempotent covers AC-008.67: Revoke twice on the viewer's own
// invite reports true then false.
func TestRevokeIsIdempotent(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	first, err := svc.Revoke(t.Context(), issued.Invite.ID, issuer, false)
	if err != nil {
		t.Fatalf("Revoke() first call, error = %v", err)
	}

	if !first {
		t.Error("Revoke() first call = false, want true")
	}

	second, err := svc.Revoke(t.Context(), issued.Invite.ID, issuer, false)
	if err != nil {
		t.Fatalf("Revoke() second call, error = %v", err)
	}

	if second {
		t.Error("Revoke() second call = true, want false")
	}
}

// TestStateIsTableDriven covers AC-008.57: State is table-driven across live,
// expired, spent, and revoked, including a revoked invite that is also
// expired, which must report revoked.
func TestStateIsTableDriven(t *testing.T) {
	t.Parallel()

	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name  string
		inv   Invite
		state string
	}{
		{
			name:  "live",
			inv:   Invite{MaxUses: 1, Uses: 0, ExpiresAt: future},
			state: stateLive,
		},
		{
			name:  "expired",
			inv:   Invite{MaxUses: 1, Uses: 0, ExpiresAt: past},
			state: stateExpired,
		},
		{
			name:  "spent",
			inv:   Invite{MaxUses: 1, Uses: 1, ExpiresAt: future},
			state: stateSpent,
		},
		{
			name:  "revoked",
			inv:   Invite{MaxUses: 1, Uses: 0, ExpiresAt: future, RevokedAt: &now},
			state: stateRevoked,
		},
		{
			name:  "revoked and expired reports revoked",
			inv:   Invite{MaxUses: 1, Uses: 0, ExpiresAt: past, RevokedAt: &now},
			state: stateRevoked,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.inv.State(now); got != tt.state {
				t.Errorf("State() = %q, want %q", got, tt.state)
			}
		})
	}
}

// TestDeleteExpiredRemovesOnlyExpiredInvites covers FIX-9: DeleteExpired
// removes an invite that expired more than retain ago and leaves a live
// invite alone. The rows it destroys are invite_redemptions rows, via
// ON DELETE CASCADE, not the invite itself surviving for readability, which
// is what this method's corrected doc comment says and its previous doc
// comment did not.
// Covers AC-008.92.
func TestDeleteExpiredRemovesOnlyExpiredInvites(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	expired, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create() expired, error = %v", err)
	}

	live, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() live, error = %v", err)
	}

	c.Advance(2 * time.Minute)

	removed, err := svc.DeleteExpired(t.Context(), time.Minute)
	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}

	if removed != 1 {
		t.Errorf("DeleteExpired() removed = %d, want 1", removed)
	}

	if _, getErr := svc.Get(t.Context(), expired.Invite.ID, issuer, false); !errors.Is(getErr, ErrInvalid) {
		t.Errorf("Get() for the expired invite after DeleteExpired, error = %v, want ErrInvalid", getErr)
	}

	if _, getErr := svc.Get(t.Context(), live.Invite.ID, issuer, false); getErr != nil {
		t.Errorf("Get() for the live invite after DeleteExpired, error = %v, want nil", getErr)
	}
}

// TestDeleteExpiredWithNegativeRetainDeletesNothingLive covers FIX-9(b): a
// negative retain is clamped to zero rather than computing a cutoff in the
// future, so it never deletes an invite that is still live.
// Covers AC-008.92.
func TestDeleteExpiredWithNegativeRetainDeletesNothingLive(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	live, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() live, error = %v", err)
	}

	if _, deleteExpiredErr := svc.DeleteExpired(t.Context(), -time.Hour); deleteExpiredErr != nil {
		t.Fatalf("DeleteExpired() error = %v", deleteExpiredErr)
	}

	if _, getErr := svc.Get(t.Context(), live.Invite.ID, issuer, false); getErr != nil {
		t.Errorf("Get() for the live invite after DeleteExpired with a negative retain, error = %v, want nil: it must not have been deleted", getErr)
	}
}

// TestDeleteExpiredKeepsRevokedInvites proves a revoked invite survives
// DeleteExpired no matter how long ago it expired, because it is the only
// record that an admission decision was made. The same call must still
// remove a plain expired, unrevoked, unspent invite past retain, so this
// test cannot pass merely because DeleteExpired deletes nothing at all.
// Covers AC-008.92.
func TestDeleteExpiredKeepsRevokedInvites(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	revoked, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create() revoked, error = %v", err)
	}

	if _, revokeErr := svc.Revoke(t.Context(), revoked.Invite.ID, issuer, false); revokeErr != nil {
		t.Fatalf("Revoke() error = %v", revokeErr)
	}

	plain, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create() plain, error = %v", err)
	}

	c.Advance(24 * time.Hour)

	removed, err := svc.DeleteExpired(t.Context(), time.Minute)
	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}

	if removed != 1 {
		t.Errorf("DeleteExpired() removed = %d, want 1", removed)
	}

	var revokedCount int

	if scanErr := h.Pool().QueryRow(t.Context(), `SELECT count(*) FROM invites WHERE id = $1`, revoked.Invite.ID).Scan(&revokedCount); scanErr != nil {
		t.Fatalf("scanning count for revoked invite: %v", scanErr)
	}

	if revokedCount != 1 {
		t.Errorf("revoked invite row count after DeleteExpired = %d, want 1: a revoked invite must survive regardless of age", revokedCount)
	}

	if _, getErr := svc.Get(t.Context(), plain.Invite.ID, issuer, false); !errors.Is(getErr, ErrInvalid) {
		t.Errorf("Get() for the plain expired invite after DeleteExpired, error = %v, want ErrInvalid", getErr)
	}
}

// TestDeleteExpiredKeepsFullySpentInvites proves a fully spent invite
// survives DeleteExpired no matter how long ago it expired, because
// invite_redemptions.invite_id is ON DELETE CASCADE and deleting the invite
// would destroy its redemption row along with it. The same call must still
// remove a plain expired, unrevoked, unspent invite past retain, so this
// test cannot pass merely because DeleteExpired deletes nothing at all.
// Covers AC-008.69 and AC-008.92.
func TestDeleteExpiredKeepsFullySpentInvites(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	spent, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create() spent, error = %v", err)
	}

	redeemer := insertUser(t, h)

	if redeemErr := withTx(t, h, func(tx txExecer) error {
		return svc.RedeemTx(t.Context(), tx, spent.Invite.ID, redeemer, "user:redeemer", "")
	}); redeemErr != nil {
		t.Fatalf("RedeemTx() spending the only use, error = %v", redeemErr)
	}

	plain, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, TTL: time.Minute})
	if err != nil {
		t.Fatalf("Create() plain, error = %v", err)
	}

	c.Advance(24 * time.Hour)

	removed, err := svc.DeleteExpired(t.Context(), time.Minute)
	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}

	if removed != 1 {
		t.Errorf("DeleteExpired() removed = %d, want 1", removed)
	}

	var inviteCount int

	if scanErr := h.Pool().QueryRow(t.Context(), `SELECT count(*) FROM invites WHERE id = $1`, spent.Invite.ID).Scan(&inviteCount); scanErr != nil {
		t.Fatalf("scanning count for spent invite: %v", scanErr)
	}

	if inviteCount != 1 {
		t.Errorf("spent invite row count after DeleteExpired = %d, want 1: a fully spent invite must survive regardless of age", inviteCount)
	}

	var redemptionCount int

	if scanErr := h.Pool().QueryRow(t.Context(), `SELECT count(*) FROM invite_redemptions WHERE invite_id = $1`, spent.Invite.ID).Scan(&redemptionCount); scanErr != nil {
		t.Fatalf("scanning count for invite_redemptions: %v", scanErr)
	}

	if redemptionCount != 1 {
		t.Errorf("invite_redemptions row count after DeleteExpired = %d, want 1: deleting the spent invite would have cascade-deleted its redemption", redemptionCount)
	}

	if _, getErr := svc.Get(t.Context(), plain.Invite.ID, issuer, false); !errors.Is(getErr, ErrInvalid) {
		t.Errorf("Get() for the plain expired invite after DeleteExpired, error = %v, want ErrInvalid", getErr)
	}
}

// TestNewServiceRejectsShortTokenBytes covers FIX-10: NewService returns
// ErrTokenBytesTooShort for a tokenBytes below minTokenBytes rather than
// silently building a service whose tokens would fail closed only at
// runtime, on the token_hash unique index.
// It cites no criterion: the token length is fixed in source, so a short one is
// a mistake reachable only from source, the fifth exception in CLAUDE.md's
// Testing Standards.
func TestNewServiceRejectsShortTokenBytes(t *testing.T) {
	t.Parallel()

	c := newClock()
	h := storetest.New(t)
	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)

	if _, err := NewService(h, policy, minTokenBytes-1, zap.NewNop(), c.Now); !errors.Is(err, ErrTokenBytesTooShort) {
		t.Errorf("NewService() error = %v, want ErrTokenBytesTooShort", err)
	}
}

// TestCreateRejectsTTLAboveMax covers AC-008.80: a requested TTL above the
// configured maximum invite lifetime is rejected as invalid rather than
// silently capped or accepted.
func TestCreateRejectsTTLAboveMax(t *testing.T) {
	t.Parallel()

	c := newClock()
	h := storetest.New(t)
	policy := settings.NewStore(h, settings.Options{InviteMaxTTL: time.Hour}, zap.NewNop(), c.Now)

	svc, err := NewService(h, policy, tokenBytesForTest, zap.NewNop(), c.Now)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	issuer := insertUser(t, h)

	_, err = svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1, TTL: 2 * time.Hour})
	if !errors.Is(err, ErrTTLTooLong) {
		t.Errorf("Create() with a TTL above the configured max, error = %v, want ErrTTLTooLong", err)
	}
}

// TestCreateCapsDefaultTTLAtMax covers AC-008.80: when the issuer names no
// TTL and the configured default invite lifetime exceeds the configured
// maximum, the invite's expiry is capped at the maximum rather than issued
// with the longer default.
func TestCreateCapsDefaultTTLAtMax(t *testing.T) {
	t.Parallel()

	c := newClock()
	h := storetest.New(t)
	// The seeded default invite lifetime is 14 days; a one-day max forces
	// Create to cap rather than use the default outright.
	policy := settings.NewStore(h, settings.Options{InviteMaxTTL: 24 * time.Hour}, zap.NewNop(), c.Now)

	svc, err := NewService(h, policy, tokenBytesForTest, zap.NewNop(), c.Now)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	issuer := insertUser(t, h)

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	wantExpiry := c.Now().Add(24 * time.Hour)
	if !issued.Invite.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", issued.Invite.ExpiresAt, wantExpiry)
	}
}

// TestCreateUsesConfiguredDefaultMaxUses covers AC-008.81: an invite issued
// without a redemption limit takes the configured default max uses, not a
// package-fixed single-use constant.
func TestCreateUsesConfiguredDefaultMaxUses(t *testing.T) {
	t.Parallel()

	c := newClock()
	h := storetest.New(t)
	policy := settings.NewStore(h, settings.Options{InviteDefaultMaxUses: 3}, zap.NewNop(), c.Now)

	svc, err := NewService(h, policy, tokenBytesForTest, zap.NewNop(), c.Now)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	issuer := insertUser(t, h)

	issued, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if issued.Invite.MaxUses != 3 {
		t.Errorf("Create() with a zero MaxUses, invite.MaxUses = %d, want 3", issued.Invite.MaxUses)
	}
}

// TestCreateReadsQuotaInsideTransaction covers AC-008.66: with a configured
// quota of one and one live invite already outstanding, Create fails with
// ErrQuotaExhausted; the same issuer with unlimitedQuota set succeeds
// regardless, because the quota check is skipped entirely rather than merely
// raised.
func TestCreateReadsQuotaInsideTransaction(t *testing.T) {
	t.Parallel()

	c := newClock()
	svc, h := newTestService(t, c)
	issuer := insertUser(t, h)

	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)
	quota := 1

	if _, err := policy.Apply(t.Context(), settings.Update{InviteDefaultQuota: &quota}, uuid.NullUUID{}, "test:setup"); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if _, err := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1}); err != nil {
		t.Fatalf("Create() first, error = %v", err)
	}

	if _, err := svc.Create(t.Context(), issuer, "user:issuer", false, Params{MaxUses: 1}); !errors.Is(err, ErrQuotaExhausted) {
		t.Errorf("Create() second with the quota exhausted, error = %v, want ErrQuotaExhausted", err)
	}

	if _, err := svc.Create(t.Context(), issuer, "user:issuer", true, Params{MaxUses: 1}); err != nil {
		t.Errorf("Create() with unlimitedQuota, error = %v, want success", err)
	}
}

// withTx runs fn inside a transaction against h, committing when fn succeeds
// and rolling back when it fails, so RedeemTx and ValidateTx can be exercised
// the way the signup admission rules actually call them: inside an open
// transaction. It
// returns any transaction-management failure rather than calling t.Fatalf,
// because t.Fatalf off the test goroutine calls runtime.Goexit on the wrong
// goroutine: a caller running withTx from a worker goroutine, such as
// TestRedeemTxConcurrentSingleUseSucceedsOnce, must be able to observe and
// report the failure on the test goroutine instead of abandoning the worker
// while whatever waits on it hangs.
func withTx(t *testing.T, h *store.Handle, fn func(tx txExecer) error) error {
	t.Helper()

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		return fmt.Errorf("withTx: beginning transaction: %w", err)
	}

	if fnErr := fn(tx); fnErr != nil {
		if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
			return fmt.Errorf("withTx: rolling back after fn error: %w: %w", fnErr, rollbackErr)
		}

		return fnErr
	}

	if commitErr := tx.Commit(t.Context()); commitErr != nil {
		return fmt.Errorf("withTx: committing transaction: %w", commitErr)
	}

	return nil
}
