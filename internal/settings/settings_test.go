//go:build integration

package settings_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// lockWaitPollInterval paces waitForLockWait's retry loop.
const lockWaitPollInterval = 20 * time.Millisecond

// lockWaitPollTimeout bounds how long waitForLockWait waits for a backend to
// report a lock wait before failing the test by name.
const lockWaitPollTimeout = 10 * time.Second

// fixedClock returns a func() time.Time that always returns t, for tests that
// need a predictable, advancing-on-demand value for Apply's updated_at.
func fixedClock(fixed time.Time) func() time.Time {
	return func() time.Time {
		return fixed
	}
}

// TestLoadReturnsSeededDefaults covers AC-008.74: Load against the seed
// migration's row returns the shipped default policy.
func TestLoadReturnsSeededDefaults(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

	got, err := store.Load(t.Context())
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	want := settings.Settings{
		SignupEnabled:         true,
		SignupRequireInvite:   true,
		SignupRequireApproval: false,
		InviteDefaultQuota:    0,
		InviteDefaultTTLSecs:  1209600,
		InviteMaxUsesLimit:    100,
		UpdatedByRef:          "anonymous",
	}

	if got.SignupEnabled != want.SignupEnabled ||
		got.SignupRequireInvite != want.SignupRequireInvite ||
		got.SignupRequireApproval != want.SignupRequireApproval ||
		got.InviteDefaultQuota != want.InviteDefaultQuota ||
		got.InviteDefaultTTLSecs != want.InviteDefaultTTLSecs ||
		got.InviteMaxUsesLimit != want.InviteMaxUsesLimit ||
		got.UpdatedByRef != want.UpdatedByRef {
		t.Errorf("Load() = %+v, want fields matching %+v", got, want)
	}

	if got.UpdatedAt.IsZero() {
		t.Errorf("Load() UpdatedAt = zero, want the seed migration's timestamp")
	}
}

// TestLoadReturnsErrMissingWhenTheRowIsGone covers AC-008.74: a settings
// table with no row is a condition Load reports rather than a zero value it
// papers over.
func TestLoadReturnsErrMissingWhenTheRowIsGone(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)

	if _, err := handle.Pool().Exec(t.Context(), `DELETE FROM settings WHERE id`); err != nil {
		t.Fatalf("deleting settings row: %v", err)
	}

	store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

	if _, err := store.Load(t.Context()); !errors.Is(err, settings.ErrMissing) {
		t.Errorf("Load() error = %v, want ErrMissing", err)
	}
}

// TestApplyChangesOnlyTheNamedField covers AC-008.74: a partial update
// touches only the field it names and leaves the other five alone.
func TestApplyChangesOnlyTheNamedField(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

	quota := 5
	_, err := store.Apply(t.Context(), settings.Update{InviteDefaultQuota: &quota}, uuid.NullUUID{}, "admin:test")
	if err != nil {
		t.Fatalf("Apply() error = %v, want nil", err)
	}

	got, err := store.Load(t.Context())
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if got.InviteDefaultQuota != 5 {
		t.Errorf("Load().InviteDefaultQuota = %d, want 5", got.InviteDefaultQuota)
	}

	if !got.SignupEnabled || !got.SignupRequireInvite || got.SignupRequireApproval ||
		got.InviteDefaultTTLSecs != 1209600 || got.InviteMaxUsesLimit != 100 {
		t.Errorf("Apply() changed a field it was not given: got %+v", got)
	}
}

// TestApplyAdvancesUpdatedAtAndRecordsUpdatedByRef covers AC-008.74: Apply
// writes updated_at from the injected clock and updated_by_ref from its
// caller.
func TestApplyAdvancesUpdatedAtAndRecordsUpdatedByRef(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	when := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), fixedClock(when))

	quota := 9
	got, err := store.Apply(t.Context(), settings.Update{InviteDefaultQuota: &quota}, uuid.NullUUID{}, "admin:carol")
	if err != nil {
		t.Fatalf("Apply() error = %v, want nil", err)
	}

	if !got.UpdatedAt.Equal(when) {
		t.Errorf("Apply().UpdatedAt = %v, want %v", got.UpdatedAt, when)
	}

	if got.UpdatedByRef != "admin:carol" {
		t.Errorf("Apply().UpdatedByRef = %q, want %q", got.UpdatedByRef, "admin:carol")
	}
}

// TestApplyRejectsAnInvalidTTLAndChangesNothing covers AC-008.74: Apply
// validates before writing, and a violation writes nothing.
func TestApplyRejectsAnInvalidTTLAndChangesNothing(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

	zero := 0
	if _, err := store.Apply(t.Context(), settings.Update{InviteDefaultTTLSecs: &zero}, uuid.NullUUID{}, "admin:test"); err == nil {
		t.Fatalf("Apply() error = nil, want an error naming invite_default_ttl_secs")
	}

	got, err := store.Load(t.Context())
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if got.InviteDefaultTTLSecs != 1209600 {
		t.Errorf("Load().InviteDefaultTTLSecs = %d, want unchanged 1209600", got.InviteDefaultTTLSecs)
	}
}

// TestApplyWrapsValidationFailuresInErrInvalidValue cites no criterion: it pins
// the error contract a caller maps to a client error. A negative quota, a non-positive TTL, and a
// non-positive max-uses limit are all indistinguishable from a database
// failure unless they carry a sentinel a caller can match with errors.Is, so
// PATCH /api/v1/admin/settings can answer 400 invalid_request rather than
// 500.
func TestApplyWrapsValidationFailuresInErrInvalidValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		update settings.Update
	}{
		{name: "negative quota", update: settings.Update{InviteDefaultQuota: new(-1)}},
		{name: "non-positive ttl", update: settings.Update{InviteDefaultTTLSecs: new(0)}},
		{name: "non-positive max uses limit", update: settings.Update{InviteMaxUsesLimit: new(0)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handle := storetest.New(t)
			store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

			_, err := store.Apply(t.Context(), tt.update, uuid.NullUUID{}, "admin:test")
			if !errors.Is(err, settings.ErrInvalidValue) {
				t.Fatalf("Apply() error = %v, want errors.Is match against ErrInvalidValue", err)
			}
		})
	}
}

// TestOverrideReportsLockedSignupEnabledOnLoad covers AC-008.75: a store
// constructed with a non-nil signupEnabledOverride reports that value from
// Load regardless of the stored column.
func TestOverrideReportsLockedSignupEnabledOnLoad(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	forced := false
	store := settings.NewStore(handle, settings.Options{SignupEnabledOverride: &forced}, zap.NewNop(), time.Now)

	got, err := store.Load(t.Context())
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if got.SignupEnabled {
		t.Errorf("Load().SignupEnabled = true, want false from the override")
	}

	locked := store.Locked()
	if len(locked) != 1 || locked[0] != "signup_enabled" {
		t.Errorf("Locked() = %v, want [\"signup_enabled\"]", locked)
	}
}

// TestOverrideLocksApplyAndLeavesOtherFieldsUnwritten covers AC-008.75: an
// Apply naming an overridden field returns ErrLocked and writes none of the
// fields the same call named.
func TestOverrideLocksApplyAndLeavesOtherFieldsUnwritten(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	forced := false
	store := settings.NewStore(handle, settings.Options{SignupEnabledOverride: &forced}, zap.NewNop(), time.Now)

	enabled := true
	quota := 42
	_, err := store.Apply(t.Context(), settings.Update{
		SignupEnabled:      &enabled,
		InviteDefaultQuota: &quota,
	}, uuid.NullUUID{}, "admin:test")
	if !errors.Is(err, settings.ErrLocked) {
		t.Fatalf("Apply() error = %v, want ErrLocked", err)
	}

	unlocked := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

	got, loadErr := unlocked.Load(t.Context())
	if loadErr != nil {
		t.Fatalf("Load() error = %v, want nil", loadErr)
	}

	if got.InviteDefaultQuota != 0 {
		t.Errorf("Load().InviteDefaultQuota = %d, want unchanged 0", got.InviteDefaultQuota)
	}
}

// TestNilOverrideWritesSignupEnabledNormally covers AC-008.75: a store with a
// nil override applies a SignupEnabled update like any other field.
func TestNilOverrideWritesSignupEnabledNormally(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

	disabled := false
	got, err := store.Apply(t.Context(), settings.Update{SignupEnabled: &disabled}, uuid.NullUUID{}, "admin:test")
	if err != nil {
		t.Fatalf("Apply() error = %v, want nil", err)
	}

	if got.SignupEnabled {
		t.Errorf("Apply().SignupEnabled = true, want false")
	}
}

// TestLoadTxSeesAnUpdateMadeEarlierInTheSameTransaction covers AC-008.61: the
// property the admission rules depend on, that a read inside a transaction
// sees that transaction's own uncommitted write.
func TestLoadTxSeesAnUpdateMadeEarlierInTheSameTransaction(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

	tx, err := handle.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}
	t.Cleanup(func() {
		// Not t.Context(): it is already cancelled by the time cleanup runs,
		// so the rollback would fail on a cancelled context rather than on
		// anything to do with the transaction.
		if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil &&
			!errors.Is(rollbackErr, pgx.ErrTxClosed) {
			t.Errorf("rolling back transaction: %v", rollbackErr)
		}
	})

	if _, execErr := tx.Exec(t.Context(), `UPDATE settings SET invite_default_quota = 3 WHERE id`); execErr != nil {
		t.Fatalf("updating settings row inside transaction: %v", execErr)
	}

	got, err := store.LoadTx(t.Context(), tx)
	if err != nil {
		t.Fatalf("LoadTx() error = %v, want nil", err)
	}

	if got.InviteDefaultQuota != 3 {
		t.Errorf("LoadTx().InviteDefaultQuota = %d, want 3 (the in-transaction write)", got.InviteDefaultQuota)
	}
}

// TestApplyRejectsDefaultTTLAboveInt32 covers AC-008.74: invite_default_ttl_secs
// is an INTEGER column, so a value above math.MaxInt32 is rejected as invalid
// rather than silently wrapping or truncating in Postgres.
func TestApplyRejectsDefaultTTLAboveInt32(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

	tooLarge := math.MaxInt32 + 1
	if _, err := store.Apply(t.Context(), settings.Update{InviteDefaultTTLSecs: &tooLarge}, uuid.NullUUID{}, "admin:test"); !errors.Is(err, settings.ErrInvalidValue) {
		t.Fatalf("Apply() error = %v, want errors.Is match against ErrInvalidValue", err)
	}

	got, err := store.Load(t.Context())
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if got.InviteDefaultTTLSecs != 1209600 {
		t.Errorf("Load().InviteDefaultTTLSecs = %d, want unchanged 1209600", got.InviteDefaultTTLSecs)
	}
}

// TestApplyRejectsIntegerSettingsAboveInt32 covers AC-008.74:
// invite_default_quota and invite_max_uses_limit are INTEGER columns like
// invite_default_ttl_secs, so a value above math.MaxInt32 is outside its
// allowed range and is rejected as invalid, leaving the row unchanged, rather
// than reaching Postgres and failing as a numeric-range error.
func TestApplyRejectsIntegerSettingsAboveInt32(t *testing.T) {
	t.Parallel()

	tooLarge := math.MaxInt32 + 1

	tests := []struct {
		name   string
		update settings.Update
	}{
		{name: "invite default quota", update: settings.Update{InviteDefaultQuota: &tooLarge}},
		{name: "invite max uses limit", update: settings.Update{InviteMaxUsesLimit: &tooLarge}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handle := storetest.New(t)
			store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

			before, err := store.Load(t.Context())
			if err != nil {
				t.Fatalf("Load() before Apply error = %v, want nil", err)
			}

			if _, applyErr := store.Apply(t.Context(), tt.update, uuid.NullUUID{}, "admin:test"); !errors.Is(applyErr, settings.ErrInvalidValue) {
				t.Fatalf("Apply() error = %v, want errors.Is match against ErrInvalidValue", applyErr)
			}

			after, err := store.Load(t.Context())
			if err != nil {
				t.Fatalf("Load() after Apply error = %v, want nil", err)
			}

			if after != before {
				t.Errorf("Load() after a rejected Apply = %+v, want unchanged %+v", after, before)
			}
		})
	}
}

// TestApplyRejectsDefaultTTLAboveInviteMaxTTL covers AC-008.80: a request to
// set the default invite lifetime longer than the configured maximum invite
// lifetime is rejected as invalid, while a value equal to the maximum is
// accepted.
func TestApplyRejectsDefaultTTLAboveInviteMaxTTL(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	store := settings.NewStore(handle, settings.Options{InviteMaxTTL: 24 * time.Hour}, zap.NewNop(), time.Now)

	tooLong := 86401
	if _, err := store.Apply(t.Context(), settings.Update{InviteDefaultTTLSecs: &tooLong}, uuid.NullUUID{}, "admin:test"); !errors.Is(err, settings.ErrInvalidValue) {
		t.Fatalf("Apply() error = %v, want errors.Is match against ErrInvalidValue", err)
	}

	atCeiling := 86400
	got, err := store.Apply(t.Context(), settings.Update{InviteDefaultTTLSecs: &atCeiling}, uuid.NullUUID{}, "admin:test")
	if err != nil {
		t.Fatalf("Apply() error = %v, want nil for a value equal to the ceiling", err)
	}

	if got.InviteDefaultTTLSecs != 86400 {
		t.Errorf("Apply().InviteDefaultTTLSecs = %d, want 86400", got.InviteDefaultTTLSecs)
	}
}

// TestLoadExposesInviteLimitsFromOptions covers AC-008.81: an invite issued
// without a redemption limit gets the configured default, which Load carries
// on every Settings value it returns, and zero in Options.InviteDefaultMaxUses
// means 1.
func TestLoadExposesInviteLimitsFromOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts settings.Options
		want int
	}{
		{name: "configured to 3", opts: settings.Options{InviteDefaultMaxUses: 3}, want: 3},
		{name: "unset defaults to 1", opts: settings.Options{}, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handle := storetest.New(t)
			store := settings.NewStore(handle, tt.opts, zap.NewNop(), time.Now)

			got, err := store.Load(t.Context())
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}

			if got.InviteDefaultMaxUses != tt.want {
				t.Errorf("Load().InviteDefaultMaxUses = %d, want %d", got.InviteDefaultMaxUses, tt.want)
			}
		})
	}
}

// waitForLockWait polls pg_stat_activity, scoped to the test's own database,
// until a backend reports wait_event_type = 'Lock', or fails the test by name
// once lockWaitPollTimeout elapses. It is the bounded-poll form CLAUDE.md's
// determinism rule requires for waiting on another goroutine's observable
// state: internal/server's pollUntil is unexported in a different package and
// so is not reachable from here.
func waitForLockWait(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	deadline := time.Now().Add(lockWaitPollTimeout)

	for {
		var count int

		err := pool.QueryRow(t.Context(), `
			SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
		`).Scan(&count)
		if err != nil {
			t.Fatalf("querying pg_stat_activity: %v", err)
		}

		if count > 0 {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("no backend entered a lock wait within %s", lockWaitPollTimeout)
		}

		time.Sleep(lockWaitPollInterval)
	}
}

// TestLoadTxBlocksAPolicyChangeUntilTheTransactionEnds covers AC-008.61: the
// signup policy is evaluated inside the account-creation transaction, which
// only stops a concurrent settings change from landing mid-ceremony if the
// FOR SHARE read genuinely blocks Apply's write until the transaction ends.
func TestLoadTxBlocksAPolicyChangeUntilTheTransactionEnds(t *testing.T) {
	t.Parallel()

	handle := storetest.New(t)
	store := settings.NewStore(handle, settings.Options{}, zap.NewNop(), time.Now)

	tx, err := handle.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}
	t.Cleanup(func() {
		// Not t.Context(): it is already cancelled by the time cleanup runs,
		// so the rollback would fail on a cancelled context rather than on
		// anything to do with the transaction.
		if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil &&
			!errors.Is(rollbackErr, pgx.ErrTxClosed) {
			t.Errorf("rolling back transaction: %v", rollbackErr)
		}
	})

	if _, loadErr := store.LoadTx(t.Context(), tx); loadErr != nil {
		t.Fatalf("LoadTx() error = %v, want nil", loadErr)
	}

	type applyResult struct {
		err error
	}

	resultCh := make(chan applyResult, 1)
	disabled := false

	go func() {
		_, applyErr := store.Apply(t.Context(), settings.Update{SignupEnabled: &disabled}, uuid.NullUUID{}, "admin:test")
		resultCh <- applyResult{err: applyErr}
	}()

	waitForLockWait(t, handle.Pool())

	select {
	case <-resultCh:
		t.Fatal("Apply() returned before the transaction ended, want it blocked on the row's FOR SHARE lock")
	default:
	}

	if commitErr := tx.Commit(t.Context()); commitErr != nil {
		t.Fatalf("Commit() error = %v, want nil", commitErr)
	}

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("Apply() error = %v, want nil", res.err)
		}
	case <-time.After(lockWaitPollTimeout):
		t.Fatal("Apply() did not return after the transaction committed")
	}
}
