//go:build integration

package passkey

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

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

// testCredential returns a fully populated Credential for userID, with every
// bool and []byte field set to a non-zero-value-shaped value so a round trip
// through the database cannot silently pass on zero values alone.
func testCredential(t *testing.T, userID uuid.UUID) Credential {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("testCredential: generating id: %v", err)
	}

	credentialID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("testCredential: generating credential id: %v", err)
	}

	return Credential{
		ID:              id,
		UserID:          userID,
		CredentialID:    credentialID[:],
		PublicKey:       []byte{0x05, 0x06, 0x07, 0x08},
		AttestationType: "none",
		Transports:      []string{"internal", "hybrid"},
		AAGUID:          []byte{0x09, 0x0a, 0x0b, 0x0c},
		SignCount:       1,
		CloneWarning:    true,
		BackupEligible:  true,
		BackupState:     true,
		Name:            "test credential",
		CreatedAt:       time.Now().UTC().Truncate(time.Microsecond),
	}
}

// TestCreateThenByCredentialIDRoundTripsUnchanged covers AC-008.23.
func TestCreateThenByCredentialIDRoundTripsUnchanged(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	userID := insertUser(t, h)
	want := testCredential(t, userID)

	if err := repo.Create(t.Context(), want); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := repo.ByCredentialID(t.Context(), want.CredentialID)
	if err != nil {
		t.Fatalf("ByCredentialID() error = %v", err)
	}

	// cmp.Diff reports every differing field at once, covering all three bool
	// fields and all three []byte fields in one assertion rather than one
	// branch per field.
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ByCredentialID() round trip mismatch (-want +got):\n%s", diff)
	}
}

// TestByCredentialIDReturnsErrNotFoundForUnknownID covers AC-008.23.
func TestByCredentialIDReturnsErrNotFoundForUnknownID(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)

	_, err := repo.ByCredentialID(t.Context(), []byte{0xff, 0xff, 0xff, 0xff})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("ByCredentialID() error = %v, want ErrNotFound", err)
	}
}

// TestRecordUseAdvancesSignCountAndSetsCloneWarning covers AC-008.25.
func TestRecordUseAdvancesSignCountAndSetsCloneWarning(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	userID := insertUser(t, h)
	cred := testCredential(t, userID)
	cred.SignCount = 1
	cred.CloneWarning = false

	if err := repo.Create(t.Context(), cred); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := repo.RecordUse(t.Context(), cred.ID, 5, true); err != nil {
		t.Fatalf("RecordUse() error = %v", err)
	}

	got, err := repo.ByCredentialID(t.Context(), cred.CredentialID)
	if err != nil {
		t.Fatalf("ByCredentialID() error = %v", err)
	}

	if got.SignCount != 5 {
		t.Errorf("SignCount = %d, want 5", got.SignCount)
	}

	if !got.CloneWarning {
		t.Error("CloneWarning = false, want true")
	}

	if got.LastUsedAt == nil {
		t.Error("LastUsedAt = nil, want set")
	}
}

// TestDeleteIsScopedToOwner is the ownership isolation test (design.md's
// "Authorization path") for Delete.
// Covers AC-008.26 and AC-008.35.
func TestDeleteIsScopedToOwner(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	userA := insertUser(t, h)
	userB := insertUser(t, h)
	credB := testCredential(t, userB)

	if err := repo.Create(t.Context(), credB); err != nil {
		t.Fatalf("Create() for B, error = %v", err)
	}

	deleted, err := repo.Delete(t.Context(), userA, credB.ID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if deleted {
		t.Error("Delete() deleted = true, want false when the caller does not own the credential")
	}

	got, err := repo.ByCredentialID(t.Context(), credB.CredentialID)
	if err != nil {
		t.Fatalf("ByCredentialID() for B's credential after A's Delete, error = %v", err)
	}

	if got.ID != credB.ID {
		t.Errorf("ID = %v, want %v", got.ID, credB.ID)
	}

	// The positive half: an owner deleting their own credential must actually
	// remove it. Without this, Delete's WHERE clause could have its id and
	// user_id arguments swapped -- a predicate that is never true -- and this
	// test would stay green while Delete silently deleted nothing, forever.
	deletedB, err := repo.Delete(t.Context(), userB, credB.ID)
	if err != nil {
		t.Fatalf("Delete() for B's own credential, error = %v", err)
	}

	if !deletedB {
		t.Error("Delete() deleted = false, want true when the caller owns the credential")
	}

	if _, byCredentialIDErr := repo.ByCredentialID(t.Context(), credB.CredentialID); !errors.Is(byCredentialIDErr, ErrNotFound) {
		t.Errorf("ByCredentialID() after owner Delete, error = %v, want ErrNotFound", byCredentialIDErr)
	}
}

// TestCreateWithDuplicateCredentialIDReturnsErrVerification covers a
// credentials_credential_id_key unique-constraint violation being mapped to
// ErrVerification, so a caller cannot distinguish "already registered
// somewhere in this system" from "accepted" through a distinct error.
// Covers AC-008.23.
func TestCreateWithDuplicateCredentialIDReturnsErrVerification(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	userA := insertUser(t, h)
	userB := insertUser(t, h)
	credA := testCredential(t, userA)
	credB := testCredential(t, userB)
	credB.CredentialID = credA.CredentialID

	if err := repo.Create(t.Context(), credA); err != nil {
		t.Fatalf("Create() for A, error = %v", err)
	}

	err := repo.Create(t.Context(), credB)
	if !errors.Is(err, ErrVerification) {
		t.Errorf("Create() with duplicate credential id, error = %v, want ErrVerification", err)
	}
}

// TestListForReturnsOnlyOwnCredentials is the ownership isolation test
// (design.md's "Authorization path") for ListFor.
// Covers AC-008.26 and AC-008.35.
func TestListForReturnsOnlyOwnCredentials(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	userA := insertUser(t, h)
	userB := insertUser(t, h)
	credA := testCredential(t, userA)
	credB := testCredential(t, userB)

	if err := repo.Create(t.Context(), credA); err != nil {
		t.Fatalf("Create() for A, error = %v", err)
	}

	if err := repo.Create(t.Context(), credB); err != nil {
		t.Fatalf("Create() for B, error = %v", err)
	}

	listA, err := repo.ListFor(t.Context(), userA)
	if err != nil {
		t.Fatalf("ListFor() error = %v", err)
	}

	foundA := false

	for _, c := range listA {
		if c.ID == credB.ID {
			t.Error("ListFor(userA) contains userB's credential")
		}

		if c.ID == credA.ID {
			foundA = true
		}
	}

	if !foundA {
		t.Error("ListFor(userA) does not contain userA's own credential")
	}
}

// TestCountForCountsZeroOneAndTwo covers the AC-008.44 last-factor rule:
// CountFor reports how many credentials an account holds.
func TestCountForCountsZeroOneAndTwo(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	userID := insertUser(t, h)

	got, err := repo.CountFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("CountFor() error = %v, want nil", err)
	}

	if got != 0 {
		t.Fatalf("CountFor() with no credentials = %d, want 0", got)
	}

	err = repo.Create(t.Context(), testCredential(t, userID))
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}

	got, err = repo.CountFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("CountFor() error = %v, want nil", err)
	}

	if got != 1 {
		t.Fatalf("CountFor() with one credential = %d, want 1", got)
	}

	err = repo.Create(t.Context(), testCredential(t, userID))
	if err != nil {
		t.Fatalf("Create() second credential error = %v, want nil", err)
	}

	got, err = repo.CountFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("CountFor() error = %v, want nil", err)
	}

	if got != 2 {
		t.Fatalf("CountFor() with two credentials = %d, want 2", got)
	}
}

// TestCountForTxCountsWithinCallerTransaction covers the AC-008.44
// last-factor rule's transactional form: CountForTx reports the same count
// CountFor would, reading against a caller-supplied transaction instead of
// the pool.
func TestCountForTxCountsWithinCallerTransaction(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	userID := insertUser(t, h)

	if err := repo.Create(t.Context(), testCredential(t, userID)); err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
			t.Logf("Rollback() error = %v", rollbackErr)
		}
	}()

	got, err := repo.CountForTx(t.Context(), tx, userID)
	if err != nil {
		t.Fatalf("CountForTx() error = %v, want nil", err)
	}

	if got != 1 {
		t.Fatalf("CountForTx() = %d, want 1", got)
	}
}

// TestDeleteTxRemovesRowAndCommits covers the transactional form of
// credential removal (AC-008.44): DeleteTx removes the row and, once the
// caller commits, the removal is visible through the ordinary pool-backed
// methods.
func TestDeleteTxRemovesRowAndCommits(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	userID := insertUser(t, h)
	cred := testCredential(t, userID)

	if err := repo.Create(t.Context(), cred); err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	deleted, err := repo.DeleteTx(t.Context(), tx, userID, cred.ID)
	if err != nil {
		t.Fatalf("DeleteTx() error = %v, want nil", err)
	}

	if !deleted {
		t.Fatalf("DeleteTx() deleted = false, want true")
	}

	if commitErr := tx.Commit(t.Context()); commitErr != nil {
		t.Fatalf("Commit() error = %v", commitErr)
	}

	if _, byCredentialIDErr := repo.ByCredentialID(t.Context(), cred.CredentialID); !errors.Is(byCredentialIDErr, ErrNotFound) {
		t.Fatalf("ByCredentialID() after committed DeleteTx, error = %v, want ErrNotFound", byCredentialIDErr)
	}
}

// TestDeleteTxIsScopedToOwner mirrors TestDeleteIsScopedToOwner for the
// transactional variant: acting through userA against userB's credential
// removes nothing.
// Covers AC-008.35.
func TestDeleteTxIsScopedToOwner(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	userA := insertUser(t, h)
	userB := insertUser(t, h)
	credB := testCredential(t, userB)

	if err := repo.Create(t.Context(), credB); err != nil {
		t.Fatalf("Create() for B, error = %v", err)
	}

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
			t.Logf("Rollback() error = %v", rollbackErr)
		}
	}()

	deleted, err := repo.DeleteTx(t.Context(), tx, userA, credB.ID)
	if err != nil {
		t.Fatalf("DeleteTx() error = %v, want nil", err)
	}

	if deleted {
		t.Fatalf("DeleteTx() deleted = true, want false when the caller does not own the credential")
	}
}
