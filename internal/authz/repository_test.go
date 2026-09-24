//go:build integration

package authz_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// countUserRoles returns the number of user_roles rows for userID, queried
// directly against h, for asserting a rolled-back grant left no row behind.
func countUserRoles(t *testing.T, h *store.Handle, userID uuid.UUID) int {
	t.Helper()

	var count int

	err := h.Pool().QueryRow(t.Context(), `SELECT count(*) FROM user_roles WHERE user_id = $1`, userID).Scan(&count)
	if err != nil {
		t.Fatalf("countUserRoles: %v", err)
	}

	return count
}

// TestGrantRoleTxGrantsWithinCallerTransaction covers the transactional role
// grant the signup admission rules rely on (design.md's "Signup admission
// path"): GrantRoleTx performs its grant against the caller's transaction,
// and the row is visible to that same transaction before it commits.
// Covers AC-008.31 and AC-008.61.
func TestGrantRoleTxGrantsWithinCallerTransaction(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	if grantRoleTxErr := repo.GrantRoleTx(t.Context(), tx, userID, authz.RoleMember, userID); grantRoleTxErr != nil {
		t.Fatalf("GrantRoleTx() error = %v, want nil", grantRoleTxErr)
	}

	var count int
	if scanErr := tx.QueryRow(t.Context(), `SELECT count(*) FROM user_roles WHERE user_id = $1`, userID).Scan(&count); scanErr != nil {
		t.Fatalf("querying user_roles within tx: %v", scanErr)
	}

	if count != 1 {
		t.Fatalf("user_roles row count within tx = %d, want 1", count)
	}

	if commitErr := tx.Commit(t.Context()); commitErr != nil {
		t.Fatalf("Commit() error = %v, want nil", commitErr)
	}
}

// TestGrantRoleTxRolledBackByCallerLeavesNoRow covers the transactional
// role grant the signup admission rules rely on (design.md's "Signup
// admission path"): GrantRoleTx must not begin, commit, or roll back
// anything itself, so that when the caller rolls back its transaction
// after a successful GrantRoleTx, no user_roles row survives.
// Covers AC-008.31 and AC-008.61.
func TestGrantRoleTxRolledBackByCallerLeavesNoRow(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	if grantRoleTxErr := repo.GrantRoleTx(t.Context(), tx, userID, authz.RoleMember, userID); grantRoleTxErr != nil {
		t.Fatalf("GrantRoleTx() error = %v, want nil", grantRoleTxErr)
	}

	if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
		t.Fatalf("Rollback() error = %v, want nil", rollbackErr)
	}

	if got := countUserRoles(t, h, userID); got != 0 {
		t.Fatalf("user_roles row count after rollback = %d, want 0", got)
	}
}

// TestGrantRoleTxWithUnknownRoleReturnsErrUnknownRole covers the
// transactional role grant the signup admission rules rely on (design.md's
// "Signup admission path"): GrantRoleTx returns ErrUnknownRole naming a
// role with no matching row, exactly as GrantRole does, leaving the
// caller's transaction open for the caller to roll back.
// Covers AC-008.31.
func TestGrantRoleTxWithUnknownRoleReturnsErrUnknownRole(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	err = repo.GrantRoleTx(t.Context(), tx, userID, "bogus-role", userID)
	if err == nil {
		t.Fatalf("GrantRoleTx() error = nil, want ErrUnknownRole")
	}

	if !errors.Is(err, authz.ErrUnknownRole) {
		t.Fatalf("GrantRoleTx() error = %v, want ErrUnknownRole", err)
	}

	if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
		t.Fatalf("Rollback() error = %v, want nil", rollbackErr)
	}
}

// TestGrantRoleTxIsIdempotentWhenRoleAlreadyHeld covers the transactional
// role grant the signup admission rules rely on (design.md's "Signup
// admission path"): GrantRoleTx granting a role the account already holds
// within the same transaction is not an error, matching GrantRole's
// idempotency.
// Covers AC-008.31.
func TestGrantRoleTxIsIdempotentWhenRoleAlreadyHeld(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	if grantRoleTxErr := repo.GrantRoleTx(t.Context(), tx, userID, authz.RoleMember, userID); grantRoleTxErr != nil {
		t.Fatalf("GrantRoleTx() (first) error = %v, want nil", grantRoleTxErr)
	}

	if grantRoleTxErr := repo.GrantRoleTx(t.Context(), tx, userID, authz.RoleMember, userID); grantRoleTxErr != nil {
		t.Fatalf("GrantRoleTx() (second) error = %v, want nil", grantRoleTxErr)
	}

	if commitErr := tx.Commit(t.Context()); commitErr != nil {
		t.Fatalf("Commit() error = %v, want nil", commitErr)
	}

	if got := countUserRoles(t, h, userID); got != 1 {
		t.Fatalf("user_roles row count after two grants = %d, want 1", got)
	}
}

// TestGrantRoleWithUnknownRoleReturnsErrUnknownRole covers the
// transactional role grant the signup admission rules rely on (design.md's
// "Signup admission path"): GrantRole itself, sharing its statements with
// GrantRoleTx through the shared implementation, still returns
// ErrUnknownRole for a role name with no matching row. No prior test in
// this package covered GrantRole against an unknown role name.
// Covers AC-008.31.
func TestGrantRoleWithUnknownRoleReturnsErrUnknownRole(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	err := repo.GrantRole(t.Context(), userID, "bogus-role", userID)
	if err == nil {
		t.Fatalf("GrantRole() error = nil, want ErrUnknownRole")
	}

	if !errors.Is(err, authz.ErrUnknownRole) {
		t.Fatalf("GrantRole() error = %v, want ErrUnknownRole", err)
	}
}
