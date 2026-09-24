//go:build integration

package user_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// strptr returns a pointer to s, for populating the *string fields on User
// and Identity from a literal.
func strptr(s string) *string {
	return new(s)
}

// newRepository returns a Repository and the store.Handle it is backed by,
// so a test may query the underlying database directly (for example to count
// rows) alongside the repository under test.
func newRepository(t *testing.T, now func() time.Time) (*user.Repository, *store.Handle) {
	t.Helper()

	h := storetest.NewWithClock(t, now)

	return user.NewRepository(h, now), h
}

// newUser returns a User with a fresh identifier and no email, ready to pass
// to CreateWithIdentity.
func newUser(displayName string) user.User {
	return user.User{
		ID:          uuid.Must(uuid.NewV7()),
		DisplayName: displayName,
		Status:      user.StatusActive,
	}
}

// newIdentity returns an Identity with a fresh identifier for the given
// provider and subject, ready to pass to CreateWithIdentity or LinkIdentity.
func newIdentity(userID uuid.UUID, provider, subject string) user.Identity {
	return user.Identity{
		ID:       uuid.Must(uuid.NewV7()),
		UserID:   userID,
		Provider: provider,
		Subject:  subject,
	}
}

// TestByIdentityReturnsNotFoundForUnknownPair covers AC-008.7: identity
// resolution goes through the provider and subject pair, and an unknown pair
// is reported as ErrNotFound rather than a zero value.
func TestByIdentityReturnsNotFoundForUnknownPair(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	_, _, err := repo.ByIdentity(t.Context(), "https://issuer.example", "unknown-subject")
	if err == nil {
		t.Fatalf("ByIdentity() error = nil, want ErrNotFound")
	}

	if !isNotFound(err) {
		t.Fatalf("ByIdentity() error = %v, want ErrNotFound", err)
	}
}

// TestCreateWithIdentityThenByIdentityReturnsSameAccount covers AC-008.8:
// creating an account and its first identity in one call makes that account
// resolvable by the identity's provider and subject pair.
func TestCreateWithIdentityThenByIdentityReturnsSameAccount(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Ada Lovelace")
	id := newIdentity(u.ID, "https://issuer.example", "subject-1")

	if err := repo.CreateWithIdentity(t.Context(), u, id); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	gotUser, gotIdentity, err := repo.ByIdentity(t.Context(), "https://issuer.example", "subject-1")
	if err != nil {
		t.Fatalf("ByIdentity() error = %v, want nil", err)
	}

	if gotUser.ID != u.ID {
		t.Fatalf("ByIdentity() user.ID = %v, want %v", gotUser.ID, u.ID)
	}

	if gotIdentity.ID != id.ID {
		t.Fatalf("ByIdentity() identity.ID = %v, want %v", gotIdentity.ID, id.ID)
	}
}

// TestCreateWithIdentityWithTakenEmailReturnsErrEmailTakenAndLeavesNoPartialRow
// covers AC-008.6: a unique-constraint violation on the account's email is
// translated to ErrEmailTaken, and the transaction leaves no partial row in
// either table.
func TestCreateWithIdentityWithTakenEmailReturnsErrEmailTakenAndLeavesNoPartialRow(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	existing := newUser("First Owner")
	existing.Email = strptr("shared@example.com")
	existingIdentity := newIdentity(existing.ID, "https://issuer.example", "subject-existing")

	if err := repo.CreateWithIdentity(t.Context(), existing, existingIdentity); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	usersBefore := countRows(t, h, "users")
	identitiesBefore := countRows(t, h, "identities")

	conflicting := newUser("Second Owner")
	conflicting.Email = strptr("Shared@Example.com")
	conflictingIdentity := newIdentity(conflicting.ID, "https://issuer.example", "subject-conflicting")

	err := repo.CreateWithIdentity(t.Context(), conflicting, conflictingIdentity)
	if err == nil {
		t.Fatalf("CreateWithIdentity() error = nil, want ErrEmailTaken")
	}

	if !isEmailTaken(err) {
		t.Fatalf("CreateWithIdentity() error = %v, want ErrEmailTaken", err)
	}

	if got := countRows(t, h, "users"); got != usersBefore {
		t.Fatalf("users row count after failed create = %d, want %d", got, usersBefore)
	}

	if got := countRows(t, h, "identities"); got != identitiesBefore {
		t.Fatalf("identities row count after failed create = %d, want %d", got, identitiesBefore)
	}
}

// TestCreateWithIdentityTxInsertsRowsVisibleWithinCallerTransaction covers
// AC-008.61: CreateWithIdentityTx performs its two inserts against the
// caller's transaction, and those rows are visible to that same transaction
// before it commits.
func TestCreateWithIdentityTxInsertsRowsVisibleWithinCallerTransaction(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	u := newUser("Grace Hopper")
	id := newIdentity(u.ID, "https://issuer.example", "subject-tx-visible")

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	if createWithIdentityTxErr := repo.CreateWithIdentityTx(t.Context(), tx, u, id); createWithIdentityTxErr != nil {
		t.Fatalf("CreateWithIdentityTx() error = %v, want nil", createWithIdentityTxErr)
	}

	var userCount int
	if scanErr := tx.QueryRow(t.Context(), "SELECT count(*) FROM users WHERE id = $1", u.ID).Scan(&userCount); scanErr != nil {
		t.Fatalf("querying users within tx: %v", scanErr)
	}

	if userCount != 1 {
		t.Fatalf("users row count within tx = %d, want 1", userCount)
	}

	var identityCount int
	if scanErr := tx.QueryRow(t.Context(), "SELECT count(*) FROM identities WHERE id = $1", id.ID).Scan(&identityCount); scanErr != nil {
		t.Fatalf("querying identities within tx: %v", scanErr)
	}

	if identityCount != 1 {
		t.Fatalf("identities row count within tx = %d, want 1", identityCount)
	}

	if commitErr := tx.Commit(t.Context()); commitErr != nil {
		t.Fatalf("Commit() error = %v, want nil", commitErr)
	}
}

// TestCreateWithIdentityTxRolledBackByCallerLeavesNoRows is the point of this
// unit: CreateWithIdentityTx must not begin, commit, or roll back anything
// itself, so that when the caller rolls back its transaction after a
// successful CreateWithIdentityTx, neither the users row nor the identities
// row survives. This is what makes it safe for a failed later step sharing
// the same transaction (an invite redemption, for example) to undo an
// account creation instead of stranding a live account.
// Covers AC-008.61.
func TestCreateWithIdentityTxRolledBackByCallerLeavesNoRows(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	u := newUser("Katherine Johnson")
	id := newIdentity(u.ID, "https://issuer.example", "subject-tx-rollback")

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	if createWithIdentityTxErr := repo.CreateWithIdentityTx(t.Context(), tx, u, id); createWithIdentityTxErr != nil {
		t.Fatalf("CreateWithIdentityTx() error = %v, want nil", createWithIdentityTxErr)
	}

	if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
		t.Fatalf("Rollback() error = %v, want nil", rollbackErr)
	}

	if got := countRows(t, h, "users"); got != 0 {
		t.Fatalf("users row count after rollback = %d, want 0", got)
	}

	if got := countRows(t, h, "identities"); got != 0 {
		t.Fatalf("identities row count after rollback = %d, want 0", got)
	}
}

// TestCreateWithIdentityTxWithTakenEmailReturnsErrEmailTaken covers
// AC-008.6: a unique-constraint violation on the account's email is
// translated to ErrEmailTaken by CreateWithIdentityTx exactly as it is by
// CreateWithIdentity, leaving the caller's transaction open for the caller
// to roll back.
func TestCreateWithIdentityTxWithTakenEmailReturnsErrEmailTaken(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	existing := newUser("First Owner")
	existing.Email = strptr("shared-tx@example.com")
	existingIdentity := newIdentity(existing.ID, "https://issuer.example", "subject-tx-existing")

	if err := repo.CreateWithIdentity(t.Context(), existing, existingIdentity); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	conflicting := newUser("Second Owner")
	conflicting.Email = strptr("Shared-Tx@Example.com")
	conflictingIdentity := newIdentity(conflicting.ID, "https://issuer.example", "subject-tx-conflicting")

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	err = repo.CreateWithIdentityTx(t.Context(), tx, conflicting, conflictingIdentity)
	if err == nil {
		t.Fatalf("CreateWithIdentityTx() error = nil, want ErrEmailTaken")
	}

	if !isEmailTaken(err) {
		t.Fatalf("CreateWithIdentityTx() error = %v, want ErrEmailTaken", err)
	}

	if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
		t.Fatalf("Rollback() error = %v, want nil", rollbackErr)
	}
}

// TestLinkIdentityAttachesSecondIdentityAndIdentitiesForReturnsBoth covers
// AC-008.10: an existing account may gain a second identity, and a listing of
// its identities reflects both.
func TestLinkIdentityAttachesSecondIdentityAndIdentitiesForReturnsBoth(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Grace Hopper")
	firstIdentity := newIdentity(u.ID, "https://issuer.example", "subject-first")

	if err := repo.CreateWithIdentity(t.Context(), u, firstIdentity); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	secondIdentity := newIdentity(u.ID, "email", "grace@example.com")

	if err := repo.LinkIdentity(t.Context(), secondIdentity); err != nil {
		t.Fatalf("LinkIdentity() error = %v, want nil", err)
	}

	identities, err := repo.IdentitiesFor(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("IdentitiesFor() error = %v, want nil", err)
	}

	if len(identities) != 2 {
		t.Fatalf("IdentitiesFor() returned %d identities, want 2", len(identities))
	}
}

// TestIdentitiesForReturnsOnlyOwnIdentities is the ownership predicate's
// test (design.md's "Authorization path"): two accounts each own one
// identity, and account A's listing must contain only A's identity, never
// B's. Covers AC-008.35.
func TestIdentitiesForReturnsOnlyOwnIdentities(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	accountA := newUser("Account A")
	identityA := newIdentity(accountA.ID, "https://issuer.example", "subject-a")

	if err := repo.CreateWithIdentity(t.Context(), accountA, identityA); err != nil {
		t.Fatalf("CreateWithIdentity(accountA) error = %v, want nil", err)
	}

	accountB := newUser("Account B")
	identityB := newIdentity(accountB.ID, "https://issuer.example", "subject-b")

	if err := repo.CreateWithIdentity(t.Context(), accountB, identityB); err != nil {
		t.Fatalf("CreateWithIdentity(accountB) error = %v, want nil", err)
	}

	identities, err := repo.IdentitiesFor(t.Context(), accountA.ID)
	if err != nil {
		t.Fatalf("IdentitiesFor() error = %v, want nil", err)
	}

	if len(identities) != 1 {
		t.Fatalf("IdentitiesFor(accountA) returned %d identities, want 1", len(identities))
	}

	if identities[0].ID != identityA.ID {
		t.Fatalf("IdentitiesFor(accountA)[0].ID = %v, want %v (account A's own identity, not account B's)", identities[0].ID, identityA.ID)
	}
}

// TestLinkIdentityWithPairBelongingToAnotherAccountReturnsErrIdentityLinked
// covers AC-008.7: a unique-constraint violation on the provider and subject
// pair is translated to ErrIdentityLinked.
func TestLinkIdentityWithPairBelongingToAnotherAccountReturnsErrIdentityLinked(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	owner := newUser("Owner")
	ownerIdentity := newIdentity(owner.ID, "https://issuer.example", "shared-subject")

	if err := repo.CreateWithIdentity(t.Context(), owner, ownerIdentity); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	other := newUser("Other")

	if err := repo.CreateWithIdentity(t.Context(), other, newIdentity(other.ID, "https://issuer.example", "other-subject")); err != nil {
		t.Fatalf("CreateWithIdentity(other) error = %v, want nil", err)
	}

	conflicting := newIdentity(other.ID, "https://issuer.example", "shared-subject")

	err := repo.LinkIdentity(t.Context(), conflicting)
	if err == nil {
		t.Fatalf("LinkIdentity() error = nil, want ErrIdentityLinked")
	}

	if !isIdentityLinked(err) {
		t.Fatalf("LinkIdentity() error = %v, want ErrIdentityLinked", err)
	}
}

// TestTwoAccountsMayBothHaveNullEmail confirms the email uniqueness index
// permits any number of accounts with no email at all, since NULL never
// equals NULL under the unique index.
// Covers AC-008.6.
func TestTwoAccountsMayBothHaveNullEmail(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	first := newUser("No Email One")
	second := newUser("No Email Two")

	if err := repo.CreateWithIdentity(t.Context(), first, newIdentity(first.ID, "https://issuer.example", "subject-one")); err != nil {
		t.Fatalf("CreateWithIdentity(first) error = %v, want nil", err)
	}

	if err := repo.CreateWithIdentity(t.Context(), second, newIdentity(second.ID, "https://issuer.example", "subject-two")); err != nil {
		t.Fatalf("CreateWithIdentity(second) error = %v, want nil", err)
	}
}

// TestByEmailMatchesCaseInsensitively cites no criterion: no request path
// calls ByEmail today, so it constrains only what source can reach,
// the fifth exception in CLAUDE.md's Testing Standards. Email lookups compare
// case-insensitively, matching the unique index.
func TestByEmailMatchesCaseInsensitively(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Case Insensitive")
	u.Email = strptr("Mixed.Case@Example.com")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-case")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	got, err := repo.ByEmail(t.Context(), "mixed.case@example.com")
	if err != nil {
		t.Fatalf("ByEmail() error = %v, want nil", err)
	}

	if got.ID != u.ID {
		t.Fatalf("ByEmail() ID = %v, want %v", got.ID, u.ID)
	}
}

// TestListPaginatesWithNoOverlapNoGap covers AC-008.72: List's returned
// cursor fetches the next page with no row repeated and no row skipped.
func TestListPaginatesWithNoOverlapNoGap(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	const total = 5

	for range total {
		u := newUser("Listed User")

		if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", u.ID.String())); err != nil {
			t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
		}
	}

	firstPage, cursor, err := repo.List(t.Context(), string(user.StatusActive), "", 3)
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(firstPage) != 3 {
		t.Fatalf("List() first page length = %d, want 3", len(firstPage))
	}

	if cursor == "" {
		t.Fatalf("List() first page cursor = %q, want non-empty", cursor)
	}

	secondPage, secondCursor, err := repo.List(t.Context(), string(user.StatusActive), cursor, 3)
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(secondPage) != 2 {
		t.Fatalf("List() second page length = %d, want 2", len(secondPage))
	}

	if secondCursor != "" {
		t.Fatalf("List() second page cursor = %q, want empty (last page)", secondCursor)
	}

	seen := make(map[uuid.UUID]bool, total)

	for _, u := range firstPage {
		seen[u.ID] = true
	}

	for _, u := range secondPage {
		if seen[u.ID] {
			t.Fatalf("List() second page repeats id %v seen on first page", u.ID)
		}

		seen[u.ID] = true
	}

	if len(seen) != total {
		t.Fatalf("List() across both pages returned %d distinct accounts, want %d", len(seen), total)
	}
}

// TestTouchIdentityAdvancesLastUsedAt confirms TouchIdentity moves an
// identity's last_used_at forward to the repository's current clock reading.
// Covers AC-008.43: the identity listing reports when each linked identity was
// last used.
func TestTouchIdentityAdvancesLastUsedAt(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Touch Target")
	id := newIdentity(u.ID, "https://issuer.example", "subject-touch")

	if err := repo.CreateWithIdentity(t.Context(), u, id); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	before, err := repo.IdentitiesFor(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("IdentitiesFor() error = %v, want nil", err)
	}

	if before[0].LastUsedAt != nil {
		t.Fatalf("IdentitiesFor() before touch LastUsedAt = %v, want nil", before[0].LastUsedAt)
	}

	current = current.Add(time.Hour)

	if touchErr := repo.TouchIdentity(t.Context(), id.ID); touchErr != nil {
		t.Fatalf("TouchIdentity() error = %v, want nil", touchErr)
	}

	after, err := repo.IdentitiesFor(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("IdentitiesFor() error = %v, want nil", err)
	}

	if after[0].LastUsedAt == nil {
		t.Fatalf("IdentitiesFor() after touch LastUsedAt = nil, want %v", current)
	}

	if !after[0].LastUsedAt.Equal(current) {
		t.Fatalf("IdentitiesFor() after touch LastUsedAt = %v, want %v", *after[0].LastUsedAt, current)
	}
}

// roleID looks up a seeded role's identifier by name, so a test can grant it
// directly against user_roles without depending on this package's own
// role-granting method, which does not exist here.
func roleID(t *testing.T, h *store.Handle, name string) uuid.UUID {
	t.Helper()

	var id uuid.UUID

	query := "SELECT id FROM roles WHERE name = $1"

	if err := h.Pool().QueryRow(t.Context(), query, name).Scan(&id); err != nil {
		t.Fatalf("looking up role %q: %v", name, err)
	}

	return id
}

// grantRole inserts a user_roles row linking userID to the named role.
func grantRole(t *testing.T, h *store.Handle, userID uuid.UUID, roleName string) {
	t.Helper()

	query := "INSERT INTO user_roles (user_id, role_id, granted_at) VALUES ($1, $2, now())"

	if _, err := h.Pool().Exec(t.Context(), query, userID, roleID(t, h, roleName)); err != nil {
		t.Fatalf("granting role %q to %v: %v", roleName, userID, err)
	}
}

// TestUpdateDisplayNameChangesNameAndAdvancesUpdatedAtLeavesCreatedAt covers
// AC-008.45: UpdateDisplayName writes the new name, advances updated_at, and
// leaves created_at untouched.
func TestUpdateDisplayNameChangesNameAndAdvancesUpdatedAtLeavesCreatedAt(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Before Name")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-displayname")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	before, err := repo.ByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want nil", err)
	}

	current = current.Add(time.Hour)

	got, err := repo.UpdateDisplayName(t.Context(), u.ID, "After Name")
	if err != nil {
		t.Fatalf("UpdateDisplayName() error = %v, want nil", err)
	}

	if got.DisplayName != "After Name" {
		t.Fatalf("UpdateDisplayName() DisplayName = %q, want %q", got.DisplayName, "After Name")
	}

	if !got.UpdatedAt.Equal(current) {
		t.Fatalf("UpdateDisplayName() UpdatedAt = %v, want %v", got.UpdatedAt, current)
	}

	if !got.CreatedAt.Equal(before.CreatedAt) {
		t.Fatalf("UpdateDisplayName() CreatedAt = %v, want %v (unchanged)", got.CreatedAt, before.CreatedAt)
	}
}

// TestUpdateDisplayNameWithWhitespaceOnlyReturnsErrInvalidDisplayName covers
// AC-008.45: a display name that is empty after trimming is rejected and the
// stored name is unchanged.
func TestUpdateDisplayNameWithWhitespaceOnlyReturnsErrInvalidDisplayName(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Original Name")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-whitespace-name")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	_, err := repo.UpdateDisplayName(t.Context(), u.ID, "   \t  ")
	if !errors.Is(err, user.ErrInvalidDisplayName) {
		t.Fatalf("UpdateDisplayName() error = %v, want ErrInvalidDisplayName", err)
	}

	got, err := repo.ByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want nil", err)
	}

	if got.DisplayName != "Original Name" {
		t.Fatalf("ByID() DisplayName = %q, want %q (unchanged)", got.DisplayName, "Original Name")
	}
}

// TestSetStatusRoundTripsActiveAndSuspended covers AC-008.47: SetStatus
// writes StatusActive and StatusSuspended and returns the updated account.
func TestSetStatusRoundTripsActiveAndSuspended(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Status Target")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-status")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	suspended, err := repo.SetStatus(t.Context(), u.ID, user.StatusSuspended)
	if err != nil {
		t.Fatalf("SetStatus(suspended) error = %v, want nil", err)
	}

	if suspended.Status != user.StatusSuspended {
		t.Fatalf("SetStatus(suspended) Status = %v, want %v", suspended.Status, user.StatusSuspended)
	}

	active, err := repo.SetStatus(t.Context(), u.ID, user.StatusActive)
	if err != nil {
		t.Fatalf("SetStatus(active) error = %v, want nil", err)
	}

	if active.Status != user.StatusActive {
		t.Fatalf("SetStatus(active) Status = %v, want %v", active.Status, user.StatusActive)
	}
}

// TestSetStatusWithDeletedOrBogusValueReturnsErrInvalidStatus covers
// AC-008.47: SetStatus refuses any target status other than active or
// suspended.
func TestSetStatusWithDeletedOrBogusValueReturnsErrInvalidStatus(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Invalid Status Target")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-invalid-status")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	for _, status := range []user.Status{user.StatusDeleted, user.Status("bogus")} {
		_, err := repo.SetStatus(t.Context(), u.ID, status)
		if !errors.Is(err, user.ErrInvalidStatus) {
			t.Fatalf("SetStatus(%q) error = %v, want ErrInvalidStatus", status, err)
		}
	}
}

// TestSetStatusAgainstPendingTargetReturnsErrIsPending covers AC-008.72:
// SetStatus refuses a target whose current status is pending, regardless of
// the requested status, and leaves the row unchanged.
func TestSetStatusAgainstPendingTargetReturnsErrIsPending(t *testing.T) {
	t.Parallel()

	for _, requested := range []user.Status{user.StatusActive, user.StatusSuspended} {
		t.Run(string(requested), func(t *testing.T) {
			t.Parallel()

			repo, _ := newRepository(t, time.Now)

			u := newUser("Pending Target")
			u.Status = user.StatusPending

			if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-pending-"+string(requested))); err != nil {
				t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
			}

			_, err := repo.SetStatus(t.Context(), u.ID, requested)
			if !errors.Is(err, user.ErrIsPending) {
				t.Fatalf("SetStatus(%q) error = %v, want ErrIsPending", requested, err)
			}

			got, err := repo.ByID(t.Context(), u.ID)
			if err != nil {
				t.Fatalf("ByID() error = %v, want nil", err)
			}

			if got.Status != user.StatusPending {
				t.Fatalf("ByID() Status = %v, want %v (unchanged)", got.Status, user.StatusPending)
			}
		})
	}
}

// TestApproveMovesPendingToActive covers AC-008.73: Approve moves a pending
// account to active, reports true, and advances updated_at.
func TestApproveMovesPendingToActive(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Pending Approve")
	u.Status = user.StatusPending

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-approve")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	current = current.Add(time.Hour)

	changed, err := repo.Approve(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Approve() error = %v, want nil", err)
	}

	if !changed {
		t.Fatalf("Approve() changed = false, want true")
	}

	got, err := repo.ByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want nil", err)
	}

	if got.Status != user.StatusActive {
		t.Fatalf("ByID() Status = %v, want %v", got.Status, user.StatusActive)
	}

	if !got.UpdatedAt.Equal(current) {
		t.Fatalf("ByID() UpdatedAt = %v, want %v", got.UpdatedAt, current)
	}
}

// TestApproveAgainstAlreadyActiveAccountReturnsFalse covers AC-008.72: two
// administrators approving the same account race harmlessly, and the second
// call reports false and changes nothing.
func TestApproveAgainstAlreadyActiveAccountReturnsFalse(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Already Active")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-already-active")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	changed, err := repo.Approve(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Approve() error = %v, want nil", err)
	}

	if changed {
		t.Fatalf("Approve() changed = true, want false (already active)")
	}
}

// TestRejectMovesPendingToDeleted covers AC-008.72: rejecting a pending
// account moves it to deleted with deleted_at set from the injected clock,
// mirroring Approve's shape for the opposite outcome.
func TestRejectMovesPendingToDeleted(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Pending Reject")
	u.Status = user.StatusPending

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-reject")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	current = current.Add(time.Hour)

	changed, err := repo.Reject(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Reject() error = %v, want nil", err)
	}

	if !changed {
		t.Fatalf("Reject() changed = false, want true")
	}

	got, err := repo.ByIDAnyStatus(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
	}

	if got.Status != user.StatusDeleted {
		t.Fatalf("ByIDAnyStatus() Status = %v, want %v", got.Status, user.StatusDeleted)
	}

	if got.DeletedAt == nil || !got.DeletedAt.Equal(current) {
		t.Fatalf("ByIDAnyStatus() DeletedAt = %v, want %v", got.DeletedAt, current)
	}
}

// TestRejectAgainstActiveAccountReturnsFalseAndLeavesItActive covers AC-008.72:
// rejection
// must be pending-only, because user.Repository.SoftDelete carries no status
// predicate and would otherwise let a holder of the approval permission
// delete any account, active or not, by calling reject on it. Rejecting an
// already-active account must report false and leave the account able to
// authenticate.
func TestRejectAgainstActiveAccountReturnsFalseAndLeavesItActive(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Already Active Reject")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-reject-active")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	changed, err := repo.Reject(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Reject() error = %v, want nil", err)
	}

	if changed {
		t.Fatalf("Reject() changed = true, want false (already active)")
	}

	got, err := repo.ByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want nil", err)
	}

	if got.Status != user.StatusActive {
		t.Fatalf("ByID() Status = %v, want %v (Reject must not touch a non-pending account)", got.Status, user.StatusActive)
	}
}

// TestListWithNoFilterOmitsDeletedAndWithDeletedReturnsExactlyThem covers
// AC-008.46: List with an empty filter returns every account but the deleted
// ones, and List with "deleted" returns exactly the deleted ones.
func TestListWithNoFilterOmitsDeletedAndWithDeletedReturnsExactlyThem(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	active := newUser("List Active")
	if err := repo.CreateWithIdentity(t.Context(), active, newIdentity(active.ID, "https://issuer.example", "subject-list-active")); err != nil {
		t.Fatalf("CreateWithIdentity(active) error = %v, want nil", err)
	}

	deleted := newUser("List Deleted")
	if err := repo.CreateWithIdentity(t.Context(), deleted, newIdentity(deleted.ID, "https://issuer.example", "subject-list-deleted")); err != nil {
		t.Fatalf("CreateWithIdentity(deleted) error = %v, want nil", err)
	}

	if err := repo.SoftDelete(t.Context(), deleted.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	noFilter, _, err := repo.List(t.Context(), "", "", 50)
	if err != nil {
		t.Fatalf("List(\"\") error = %v, want nil", err)
	}

	for _, got := range noFilter {
		if got.ID == deleted.ID {
			t.Fatalf("List(\"\") included deleted account %v", deleted.ID)
		}
	}

	deletedOnly, _, err := repo.List(t.Context(), string(user.StatusDeleted), "", 50)
	if err != nil {
		t.Fatalf("List(deleted) error = %v, want nil", err)
	}

	if len(deletedOnly) != 1 || deletedOnly[0].ID != deleted.ID {
		t.Fatalf("List(deleted) = %v, want exactly [%v]", deletedOnly, deleted.ID)
	}
}

// TestSoftDeleteSetsStatusAndDeletedAtAndHidesFromByIDAndList covers
// AC-008.46: SoftDelete sets both status and deleted_at in one statement, and
// the account then resolves for neither ByID nor the administrative listing.
func TestSoftDeleteSetsStatusAndDeletedAtAndHidesFromByIDAndList(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Soft Delete Target")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-soft-delete")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	if err := repo.SoftDelete(t.Context(), u.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	_, err := repo.ByID(t.Context(), u.ID)
	if !isNotFound(err) {
		t.Fatalf("ByID() error = %v, want ErrNotFound", err)
	}

	listed, _, err := repo.List(t.Context(), "", "", 50)
	if err != nil {
		t.Fatalf("List(\"\") error = %v, want nil", err)
	}

	for _, got := range listed {
		if got.ID == u.ID {
			t.Fatalf("List(\"\") included soft-deleted account %v", u.ID)
		}
	}
}

// TestSoftDeleteLeavesIdentitiesAndCredentialsInPlace covers AC-008.46:
// SoftDelete does not remove an account's identities, because recovery
// depends on them.
func TestSoftDeleteLeavesIdentitiesAndCredentialsInPlace(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	u := newUser("Soft Delete Keeps Identities")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-soft-delete-identities")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	if err := repo.SoftDelete(t.Context(), u.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	var identityCount int

	query := "SELECT count(*) FROM identities WHERE user_id = $1"

	if err := h.Pool().QueryRow(t.Context(), query, u.ID).Scan(&identityCount); err != nil {
		t.Fatalf("counting identities: %v", err)
	}

	if identityCount != 1 {
		t.Fatalf("identities remaining after SoftDelete = %d, want 1", identityCount)
	}
}

// TestRestoreInsideWindowClearsDeletedAt covers AC-008.52: Restore inside its
// grace window reports true and clears deleted_at.
func TestRestoreInsideWindowClearsDeletedAt(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Restore Target")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-restore")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	if err := repo.SoftDelete(t.Context(), u.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	changed, err := repo.Restore(t.Context(), u.ID, current.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Restore() error = %v, want nil", err)
	}

	if !changed {
		t.Fatalf("Restore() changed = false, want true")
	}

	got, err := repo.ByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want nil", err)
	}

	if got.DeletedAt != nil {
		t.Fatalf("ByID() DeletedAt = %v, want nil", got.DeletedAt)
	}

	if got.Status != user.StatusActive {
		t.Fatalf("ByID() Status = %v, want %v", got.Status, user.StatusActive)
	}
}

// TestRestorePastGracePeriodReturnsFalse covers AC-008.52: Restore with a
// notBefore after the row's deleted_at reports false and changes nothing.
func TestRestorePastGracePeriodReturnsFalse(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Restore Past Grace Period")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-restore-past-grace")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	if err := repo.SoftDelete(t.Context(), u.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	changed, err := repo.Restore(t.Context(), u.ID, current.Add(time.Hour))
	if err != nil {
		t.Fatalf("Restore() error = %v, want nil", err)
	}

	if changed {
		t.Fatalf("Restore() changed = true, want false (past grace period)")
	}
}

// TestPurgeDeletedBeforeRemovesRowDeletedBeforeCutoffAndCascades covers
// AC-008.51: PurgeDeletedBefore removes a row deleted before the cutoff,
// returns its id, and takes its identities, credentials, and sessions with
// it.
func TestPurgeDeletedBeforeRemovesRowDeletedBeforeCutoffAndCascades(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, h := newRepository(t, clock)

	u := newUser("Purge Target")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-purge")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	if err := repo.SoftDelete(t.Context(), u.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	ids, err := repo.PurgeDeletedBefore(t.Context(), current.Add(time.Hour))
	if err != nil {
		t.Fatalf("PurgeDeletedBefore() error = %v, want nil", err)
	}

	if len(ids) != 1 || ids[0] != u.ID {
		t.Fatalf("PurgeDeletedBefore() ids = %v, want [%v]", ids, u.ID)
	}

	for _, table := range []string{"users", "identities", "credentials", "sessions"} {
		var count int

		query := "SELECT count(*) FROM " + table + " WHERE " + userColumnFor(table) + " = $1"

		if scanErr := h.Pool().QueryRow(t.Context(), query, u.ID).Scan(&count); scanErr != nil {
			t.Fatalf("counting %s: %v", table, scanErr)
		}

		if count != 0 {
			t.Fatalf("%s rows remaining for purged account = %d, want 0", table, count)
		}
	}
}

// userColumnFor returns the column that references users.id in table, for
// TestPurgeDeletedBeforeRemovesRowDeletedBeforeCutoffAndCascades's direct
// queries against each cascading table.
func userColumnFor(table string) string {
	if table == "users" {
		return "id"
	}

	return "user_id"
}

// TestPurgeDeletedBeforeLeavesRowDeletedAfterCutoffAndActiveAccounts covers
// AC-008.51: PurgeDeletedBefore leaves a row deleted after the cutoff and
// leaves every active account alone.
func TestPurgeDeletedBeforeLeavesRowDeletedAfterCutoffAndActiveAccounts(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, h := newRepository(t, clock)

	active := newUser("Purge Leaves Active")
	if err := repo.CreateWithIdentity(t.Context(), active, newIdentity(active.ID, "https://issuer.example", "subject-purge-leaves-active")); err != nil {
		t.Fatalf("CreateWithIdentity(active) error = %v, want nil", err)
	}

	deletedAfterCutoff := newUser("Purge Leaves Recently Deleted")
	if err := repo.CreateWithIdentity(t.Context(), deletedAfterCutoff, newIdentity(deletedAfterCutoff.ID, "https://issuer.example", "subject-purge-leaves-deleted")); err != nil {
		t.Fatalf("CreateWithIdentity(deletedAfterCutoff) error = %v, want nil", err)
	}

	cutoff := current

	current = current.Add(time.Hour)

	if err := repo.SoftDelete(t.Context(), deletedAfterCutoff.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	ids, err := repo.PurgeDeletedBefore(t.Context(), cutoff)
	if err != nil {
		t.Fatalf("PurgeDeletedBefore() error = %v, want nil", err)
	}

	if len(ids) != 0 {
		t.Fatalf("PurgeDeletedBefore() ids = %v, want none", ids)
	}

	if _, byIDErr := repo.ByID(t.Context(), active.ID); byIDErr != nil {
		t.Fatalf("ByID(active) error = %v, want nil", byIDErr)
	}

	var count int

	query := "SELECT count(*) FROM users WHERE id = $1"

	if scanErr := h.Pool().QueryRow(t.Context(), query, deletedAfterCutoff.ID).Scan(&count); scanErr != nil {
		t.Fatalf("counting users: %v", scanErr)
	}

	if count != 1 {
		t.Fatalf("users rows for recently deleted account = %d, want 1", count)
	}
}

// TestSoftDeletedAccountStillHoldsItsEmailAgainstSecondAccount covers
// AC-008.46: a soft-deleted account's email address still counts against
// the unique index, so a second account cannot claim it during the grace
// period.
func TestSoftDeletedAccountStillHoldsItsEmailAgainstSecondAccount(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	first := newUser("Holds Email")
	first.Email = strptr("held@example.com")

	if err := repo.CreateWithIdentity(t.Context(), first, newIdentity(first.ID, "https://issuer.example", "subject-holds-email")); err != nil {
		t.Fatalf("CreateWithIdentity(first) error = %v, want nil", err)
	}

	if err := repo.SoftDelete(t.Context(), first.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	second := newUser("Wants Email")
	second.Email = strptr("held@example.com")

	err := repo.CreateWithIdentity(t.Context(), second, newIdentity(second.ID, "https://issuer.example", "subject-wants-email"))
	if !isEmailTaken(err) {
		t.Fatalf("CreateWithIdentity(second) error = %v, want ErrEmailTaken", err)
	}
}

// TestUnlinkIdentityRemovesOneIdentityAndLeavesTheOther covers AC-008.44:
// UnlinkIdentity removes one identity and leaves the account's other one.
func TestUnlinkIdentityRemovesOneIdentityAndLeavesTheOther(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Two Identities")
	firstIdentity := newIdentity(u.ID, "https://issuer.example", "subject-unlink-first")

	if err := repo.CreateWithIdentity(t.Context(), u, firstIdentity); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	secondIdentity := newIdentity(u.ID, "email", "unlink@example.com")

	if err := repo.LinkIdentity(t.Context(), secondIdentity); err != nil {
		t.Fatalf("LinkIdentity() error = %v, want nil", err)
	}

	removed, err := repo.UnlinkIdentity(t.Context(), u.ID, firstIdentity.ID)
	if err != nil {
		t.Fatalf("UnlinkIdentity() error = %v, want nil", err)
	}

	if !removed {
		t.Fatalf("UnlinkIdentity() removed = false, want true")
	}

	remaining, err := repo.IdentitiesFor(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("IdentitiesFor() error = %v, want nil", err)
	}

	if len(remaining) != 1 || remaining[0].ID != secondIdentity.ID {
		t.Fatalf("IdentitiesFor() = %v, want exactly [%v]", remaining, secondIdentity.ID)
	}
}

// TestUnlinkIdentityIsScopedToOwner is the ownership predicate's test
// (design.md's "Authorization path") for UnlinkIdentity: two accounts each
// own one identity, and unlinking account A's identity
// through account A must leave account B's identity in place. Covers
// AC-008.35.
func TestUnlinkIdentityIsScopedToOwner(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	accountA := newUser("Unlink Owner A")
	identityA := newIdentity(accountA.ID, "https://issuer.example", "subject-unlink-owner-a")

	if err := repo.CreateWithIdentity(t.Context(), accountA, identityA); err != nil {
		t.Fatalf("CreateWithIdentity(accountA) error = %v, want nil", err)
	}

	accountB := newUser("Unlink Owner B")
	identityB := newIdentity(accountB.ID, "https://issuer.example", "subject-unlink-owner-b")

	if err := repo.CreateWithIdentity(t.Context(), accountB, identityB); err != nil {
		t.Fatalf("CreateWithIdentity(accountB) error = %v, want nil", err)
	}

	removed, err := repo.UnlinkIdentity(t.Context(), accountA.ID, identityB.ID)
	if err != nil {
		t.Fatalf("UnlinkIdentity() error = %v, want nil", err)
	}

	if removed {
		t.Fatalf("UnlinkIdentity(accountA, identityB) removed = true, want false (not the owner)")
	}

	victim, err := repo.IdentitiesFor(t.Context(), accountB.ID)
	if err != nil {
		t.Fatalf("IdentitiesFor(accountB) error = %v, want nil", err)
	}

	if len(victim) != 1 || victim[0].ID != identityB.ID {
		t.Fatalf("IdentitiesFor(accountB) = %v, want account B's identity to survive", victim)
	}
}

// TestUpdateDisplayNameIsScopedToOwner is the ownership predicate's test
// (design.md's "Authorization path") for UpdateDisplayName: changing
// account A's display name must leave account B's display name untouched.
// Covers AC-008.45.
func TestUpdateDisplayNameIsScopedToOwner(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	accountA := newUser("Rename Owner A")
	if err := repo.CreateWithIdentity(t.Context(), accountA, newIdentity(accountA.ID, "https://issuer.example", "subject-rename-owner-a")); err != nil {
		t.Fatalf("CreateWithIdentity(accountA) error = %v, want nil", err)
	}

	accountB := newUser("Rename Owner B")
	if err := repo.CreateWithIdentity(t.Context(), accountB, newIdentity(accountB.ID, "https://issuer.example", "subject-rename-owner-b")); err != nil {
		t.Fatalf("CreateWithIdentity(accountB) error = %v, want nil", err)
	}

	if _, err := repo.UpdateDisplayName(t.Context(), accountA.ID, "Renamed A"); err != nil {
		t.Fatalf("UpdateDisplayName(accountA) error = %v, want nil", err)
	}

	victim, err := repo.ByID(t.Context(), accountB.ID)
	if err != nil {
		t.Fatalf("ByID(accountB) error = %v, want nil", err)
	}

	if victim.DisplayName != "Rename Owner B" {
		t.Fatalf("ByID(accountB) DisplayName = %q, want %q (unchanged)", victim.DisplayName, "Rename Owner B")
	}
}

// TestCountIdentitiesCountsZeroOneAndTwo covers AC-008.44: CountIdentities
// reports the number of identities linked to an account across zero, one,
// and two.
func TestCountIdentitiesCountsZeroOneAndTwo(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	u := newUser("Count Identities Target")

	insertUserOnly := "INSERT INTO users (" + usersColumnsForTest + ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"

	now := time.Now().UTC()

	if _, err := h.Pool().Exec(t.Context(), insertUserOnly, u.ID, u.DisplayName, u.Email, u.EmailVerifiedAt, u.Status, u.DeletedAt, now, now); err != nil {
		t.Fatalf("inserting account with no identities: %v", err)
	}

	zero, err := repo.CountIdentities(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("CountIdentities() error = %v, want nil", err)
	}

	if zero != 0 {
		t.Fatalf("CountIdentities() = %d, want 0", zero)
	}

	firstIdentity := newIdentity(u.ID, "https://issuer.example", "subject-count-one")

	if linkErr := repo.LinkIdentity(t.Context(), firstIdentity); linkErr != nil {
		t.Fatalf("LinkIdentity(first) error = %v, want nil", linkErr)
	}

	one, err := repo.CountIdentities(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("CountIdentities() error = %v, want nil", err)
	}

	if one != 1 {
		t.Fatalf("CountIdentities() = %d, want 1", one)
	}

	secondIdentity := newIdentity(u.ID, "email", "count-two@example.com")

	if linkErr := repo.LinkIdentity(t.Context(), secondIdentity); linkErr != nil {
		t.Fatalf("LinkIdentity(second) error = %v, want nil", linkErr)
	}

	two, err := repo.CountIdentities(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("CountIdentities() error = %v, want nil", err)
	}

	if two != 2 {
		t.Fatalf("CountIdentities() = %d, want 2", two)
	}
}

// usersColumnsForTest mirrors the column list repository.go writes with, for
// TestCountIdentitiesCountsZeroOneAndTwo's direct insert of an account with
// no identity, which CreateWithIdentity cannot express.
const usersColumnsForTest = "id, display_name, email, email_verified_at, status, deleted_at, created_at, updated_at"

// TestCountActiveAdminsCountsOnlyActiveAdmins covers AC-008.50:
// CountActiveAdmins counts an active admin, does not count a suspended
// admin, does not count a deleted admin, and does not count a member.
func TestCountActiveAdminsCountsOnlyActiveAdmins(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	activeAdmin := newUser("Active Admin")
	if err := repo.CreateWithIdentity(t.Context(), activeAdmin, newIdentity(activeAdmin.ID, "https://issuer.example", "subject-active-admin")); err != nil {
		t.Fatalf("CreateWithIdentity(activeAdmin) error = %v, want nil", err)
	}

	grantRole(t, h, activeAdmin.ID, "admin")

	suspendedAdmin := newUser("Suspended Admin")
	if err := repo.CreateWithIdentity(t.Context(), suspendedAdmin, newIdentity(suspendedAdmin.ID, "https://issuer.example", "subject-suspended-admin")); err != nil {
		t.Fatalf("CreateWithIdentity(suspendedAdmin) error = %v, want nil", err)
	}

	grantRole(t, h, suspendedAdmin.ID, "admin")

	if _, err := repo.SetStatus(t.Context(), suspendedAdmin.ID, user.StatusSuspended); err != nil {
		t.Fatalf("SetStatus(suspendedAdmin) error = %v, want nil", err)
	}

	deletedAdmin := newUser("Deleted Admin")
	if err := repo.CreateWithIdentity(t.Context(), deletedAdmin, newIdentity(deletedAdmin.ID, "https://issuer.example", "subject-deleted-admin")); err != nil {
		t.Fatalf("CreateWithIdentity(deletedAdmin) error = %v, want nil", err)
	}

	grantRole(t, h, deletedAdmin.ID, "admin")

	if err := repo.SoftDelete(t.Context(), deletedAdmin.ID); err != nil {
		t.Fatalf("SoftDelete(deletedAdmin) error = %v, want nil", err)
	}

	member := newUser("Plain Member")
	if err := repo.CreateWithIdentity(t.Context(), member, newIdentity(member.ID, "https://issuer.example", "subject-member")); err != nil {
		t.Fatalf("CreateWithIdentity(member) error = %v, want nil", err)
	}

	grantRole(t, h, member.ID, "member")

	count, err := repo.CountActiveAdmins(t.Context(), "admin")
	if err != nil {
		t.Fatalf("CountActiveAdmins() error = %v, want nil", err)
	}

	if count != 1 {
		t.Fatalf("CountActiveAdmins() = %d, want 1", count)
	}
}

// TestByEmailTxFindsRowInsertedInSameUncommittedTransaction proves
// ByEmailTx reads against the transaction it is handed rather than the pool,
// by finding a row that exists only inside an open, uncommitted transaction.
// A pool-backed read could never see this row, since it has not committed.
// Covers AC-008.61.
func TestByEmailTxFindsRowInsertedInSameUncommittedTransaction(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	u := newUser("Tx Visible Email")
	u.Email = strptr("tx-visible@example.com")
	id := newIdentity(u.ID, "https://issuer.example", "subject-tx-visible-email")

	if createErr := repo.CreateWithIdentityTx(t.Context(), tx, u, id); createErr != nil {
		t.Fatalf("CreateWithIdentityTx() error = %v, want nil", createErr)
	}

	got, err := repo.ByEmailTx(t.Context(), tx, "tx-visible@example.com")
	if err != nil {
		t.Fatalf("ByEmailTx() error = %v, want nil", err)
	}

	if got.ID != u.ID {
		t.Fatalf("ByEmailTx() ID = %v, want %v", got.ID, u.ID)
	}

	if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
		t.Fatalf("Rollback() error = %v, want nil", rollbackErr)
	}
}

// TestByEmailTxReturnsNotFoundForUnknownAddress: ByEmailTx reports
// ErrNotFound for an address no account claims, the same as ByEmail.
// Covers AC-008.9.
func TestByEmailTxReturnsNotFoundForUnknownAddress(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	_, err = repo.ByEmailTx(t.Context(), tx, "nobody@example.com")
	if !isNotFound(err) {
		t.Fatalf("ByEmailTx() error = %v, want ErrNotFound", err)
	}

	if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
		t.Fatalf("Rollback() error = %v, want nil", rollbackErr)
	}
}

// TestByIdentityReturnsDeletedAccountWithStatusDeleted: a soft-deleted
// account's identity must still resolve through ByIdentity, with
// Status reported as deleted, so a caller can refuse it with ErrSuspended
// instead of treating the identity as unknown and running signup admission.
// Covers AC-008.46.
func TestByIdentityReturnsDeletedAccountWithStatusDeleted(t *testing.T) {
	t.Parallel()

	repo, _ := newRepository(t, time.Now)

	u := newUser("Deleted Identity Owner")
	id := newIdentity(u.ID, "https://issuer.example", "subject-deleted-identity")

	if err := repo.CreateWithIdentity(t.Context(), u, id); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	if err := repo.SoftDelete(t.Context(), u.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	gotUser, _, err := repo.ByIdentity(t.Context(), "https://issuer.example", "subject-deleted-identity")
	if err != nil {
		t.Fatalf("ByIdentity() error = %v, want nil (a deleted account must still resolve)", err)
	}

	if gotUser.Status != user.StatusDeleted {
		t.Fatalf("ByIdentity() Status = %v, want %v", gotUser.Status, user.StatusDeleted)
	}
}

// isNotFound reports whether err is or wraps user.ErrNotFound.
func isNotFound(err error) bool {
	return errors.Is(err, user.ErrNotFound)
}

// isEmailTaken reports whether err is or wraps user.ErrEmailTaken.
func isEmailTaken(err error) bool {
	return errors.Is(err, user.ErrEmailTaken)
}

// isIdentityLinked reports whether err is or wraps user.ErrIdentityLinked.
func isIdentityLinked(err error) bool {
	return errors.Is(err, user.ErrIdentityLinked)
}

// countRows returns the number of rows in table, queried directly against h,
// for asserting a failed write left no partial state behind.
func countRows(t *testing.T, h *store.Handle, table string) int {
	t.Helper()

	var count int

	query := "SELECT count(*) FROM " + table

	if err := h.Pool().QueryRow(t.Context(), query).Scan(&count); err != nil {
		t.Fatalf("counting rows in %s: %v", table, err)
	}

	return count
}

// TestCountIdentitiesTxCountsWithinCallerTransaction covers the AC-008.44
// last-factor rule's transactional form: CountIdentitiesTx reports the same
// count CountIdentities would, reading against a caller-supplied transaction
// instead of the pool.
func TestCountIdentitiesTxCountsWithinCallerTransaction(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	u := newUser("Tx Count Identities")
	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-tx-count")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
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

	got, err := repo.CountIdentitiesTx(t.Context(), tx, u.ID)
	if err != nil {
		t.Fatalf("CountIdentitiesTx() error = %v, want nil", err)
	}

	if got != 1 {
		t.Fatalf("CountIdentitiesTx() = %d, want 1", got)
	}
}

// TestUnlinkIdentityTxRemovesRowAndCommits covers the transactional form of
// identity removal (AC-008.44): UnlinkIdentityTx removes the row and, once
// the caller commits, the removal is visible through the ordinary
// pool-backed methods.
func TestUnlinkIdentityTxRemovesRowAndCommits(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	u := newUser("Tx Unlink Identity")
	identity := newIdentity(u.ID, "https://issuer.example", "subject-tx-unlink")

	if err := repo.CreateWithIdentity(t.Context(), u, identity); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	removed, err := repo.UnlinkIdentityTx(t.Context(), tx, u.ID, identity.ID)
	if err != nil {
		t.Fatalf("UnlinkIdentityTx() error = %v, want nil", err)
	}

	if !removed {
		t.Fatalf("UnlinkIdentityTx() removed = false, want true")
	}

	err = tx.Commit(t.Context())
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	remaining, err := repo.IdentitiesFor(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("IdentitiesFor() error = %v, want nil", err)
	}

	if len(remaining) != 0 {
		t.Fatalf("IdentitiesFor() = %v, want none after committed UnlinkIdentityTx", remaining)
	}
}

// TestUnlinkIdentityTxIsScopedToOwner mirrors
// TestUnlinkIdentityIsScopedToOwner for the transactional variant: acting
// through account A against account B's identity removes nothing.
// Covers AC-008.35.
func TestUnlinkIdentityTxIsScopedToOwner(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	accountA := newUser("Tx Unlink Owner A")
	if err := repo.CreateWithIdentity(t.Context(), accountA, newIdentity(accountA.ID, "https://issuer.example", "subject-tx-unlink-owner-a")); err != nil {
		t.Fatalf("CreateWithIdentity(accountA) error = %v, want nil", err)
	}

	accountB := newUser("Tx Unlink Owner B")
	identityB := newIdentity(accountB.ID, "https://issuer.example", "subject-tx-unlink-owner-b")

	if err := repo.CreateWithIdentity(t.Context(), accountB, identityB); err != nil {
		t.Fatalf("CreateWithIdentity(accountB) error = %v, want nil", err)
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

	removed, err := repo.UnlinkIdentityTx(t.Context(), tx, accountA.ID, identityB.ID)
	if err != nil {
		t.Fatalf("UnlinkIdentityTx() error = %v, want nil", err)
	}

	if removed {
		t.Fatalf("UnlinkIdentityTx(accountA, identityB) removed = true, want false (not the owner)")
	}
}

// TestSoftDeleteTxSetsStatusOnceCommitted covers the transactional form of
// self-deletion (AC-008.46): SoftDeleteTx marks the account deleted once
// the caller commits.
func TestSoftDeleteTxSetsStatusOnceCommitted(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	u := newUser("Tx Soft Delete")
	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-tx-soft-delete")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	err = repo.SoftDeleteTx(t.Context(), tx, u.ID)
	if err != nil {
		t.Fatalf("SoftDeleteTx() error = %v, want nil", err)
	}

	err = tx.Commit(t.Context())
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	if _, byIDErr := repo.ByID(t.Context(), u.ID); !isNotFound(byIDErr) {
		t.Fatalf("ByID() after committed SoftDeleteTx: error = %v, want ErrNotFound", byIDErr)
	}
}

// TestSoftDeleteTxUnknownIDReturnsErrNotFound covers SoftDeleteTx's error
// path: an id matching no row reports ErrNotFound rather than succeeding
// silently.
// Covers AC-008.46.
func TestSoftDeleteTxUnknownIDReturnsErrNotFound(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
			t.Logf("Rollback() error = %v", rollbackErr)
		}
	}()

	if softDeleteErr := repo.SoftDeleteTx(t.Context(), tx, uuid.Must(uuid.NewV7())); !isNotFound(softDeleteErr) {
		t.Fatalf("SoftDeleteTx() error = %v, want ErrNotFound", softDeleteErr)
	}
}

// TestSetStatusTxRoundTripsOnceCommitted covers the transactional form of
// an administrator's status change (AC-008.47): SetStatusTx returns the
// updated row and, once committed, the change is visible through the
// ordinary pool-backed ByID.
func TestSetStatusTxRoundTripsOnceCommitted(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	u := newUser("Tx Set Status")
	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-tx-set-status")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	got, err := repo.SetStatusTx(t.Context(), tx, u.ID, user.StatusSuspended)
	if err != nil {
		t.Fatalf("SetStatusTx() error = %v, want nil", err)
	}

	if got.Status != user.StatusSuspended {
		t.Fatalf("SetStatusTx() Status = %q, want %q", got.Status, user.StatusSuspended)
	}

	err = tx.Commit(t.Context())
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	committed, err := repo.ByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want nil", err)
	}

	if committed.Status != user.StatusSuspended {
		t.Fatalf("ByID() after committed SetStatusTx: Status = %q, want %q", committed.Status, user.StatusSuspended)
	}
}

// TestSetStatusTxAgainstPendingTargetReturnsErrIsPending mirrors
// TestSetStatusAgainstPendingTargetReturnsErrIsPending for the transactional
// variant.
// Covers AC-008.72.
func TestSetStatusTxAgainstPendingTargetReturnsErrIsPending(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	u := newUser("Tx Set Status Pending")
	u.Status = user.StatusPending

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-tx-set-status-pending")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
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

	if _, setStatusTxErr := repo.SetStatusTx(t.Context(), tx, u.ID, user.StatusActive); !errors.Is(setStatusTxErr, user.ErrIsPending) {
		t.Fatalf("SetStatusTx() error = %v, want ErrIsPending", setStatusTxErr)
	}
}

// TestSetStatusAgainstDeletedTargetReturnsErrIsDeleted covers AC-008.52: the
// status route must not revive a deleted account outside the restore path,
// so SetStatus refuses a deleted target with ErrIsDeleted, for either
// requested status, and leaves status and deleted_at unchanged.
func TestSetStatusAgainstDeletedTargetReturnsErrIsDeleted(t *testing.T) {
	t.Parallel()

	for _, requested := range []user.Status{user.StatusActive, user.StatusSuspended} {
		t.Run(string(requested), func(t *testing.T) {
			t.Parallel()

			repo, _ := newRepository(t, time.Now)

			u := newUser("Deleted Target")

			if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-deleted-"+string(requested))); err != nil {
				t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
			}

			if err := repo.SoftDelete(t.Context(), u.ID); err != nil {
				t.Fatalf("SoftDelete() error = %v, want nil", err)
			}

			before, err := repo.ByIDAnyStatus(t.Context(), u.ID)
			if err != nil {
				t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
			}

			_, err = repo.SetStatus(t.Context(), u.ID, requested)
			if !errors.Is(err, user.ErrIsDeleted) {
				t.Fatalf("SetStatus(%q) error = %v, want ErrIsDeleted", requested, err)
			}

			after, err := repo.ByIDAnyStatus(t.Context(), u.ID)
			if err != nil {
				t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
			}

			if after.Status != user.StatusDeleted {
				t.Fatalf("ByIDAnyStatus() Status = %v, want %v (unchanged)", after.Status, user.StatusDeleted)
			}

			if after.DeletedAt == nil || before.DeletedAt == nil || !after.DeletedAt.Equal(*before.DeletedAt) {
				t.Fatalf("ByIDAnyStatus() DeletedAt = %v, want %v (unchanged)", after.DeletedAt, before.DeletedAt)
			}
		})
	}
}

// TestSetStatusTxAgainstDeletedTargetReturnsErrIsDeleted mirrors
// TestSetStatusAgainstDeletedTargetReturnsErrIsDeleted for the transactional
// variant, per AC-008.52.
func TestSetStatusTxAgainstDeletedTargetReturnsErrIsDeleted(t *testing.T) {
	t.Parallel()

	for _, requested := range []user.Status{user.StatusActive, user.StatusSuspended} {
		t.Run(string(requested), func(t *testing.T) {
			t.Parallel()

			repo, h := newRepository(t, time.Now)

			u := newUser("Tx Deleted Target")

			if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-tx-deleted-"+string(requested))); err != nil {
				t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
			}

			if err := repo.SoftDelete(t.Context(), u.ID); err != nil {
				t.Fatalf("SoftDelete() error = %v, want nil", err)
			}

			before, err := repo.ByIDAnyStatus(t.Context(), u.ID)
			if err != nil {
				t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
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

			if _, statusErr := repo.SetStatusTx(t.Context(), tx, u.ID, requested); !errors.Is(statusErr, user.ErrIsDeleted) {
				t.Fatalf("SetStatusTx(%q) error = %v, want ErrIsDeleted", requested, statusErr)
			}

			after, err := repo.ByIDAnyStatus(t.Context(), u.ID)
			if err != nil {
				t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
			}

			if after.Status != user.StatusDeleted {
				t.Fatalf("ByIDAnyStatus() Status = %v, want %v (unchanged)", after.Status, user.StatusDeleted)
			}

			if after.DeletedAt == nil || before.DeletedAt == nil || !after.DeletedAt.Equal(*before.DeletedAt) {
				t.Fatalf("ByIDAnyStatus() DeletedAt = %v, want %v (unchanged)", after.DeletedAt, before.DeletedAt)
			}
		})
	}
}

// TestRestoreAgainstNonDeletedStatusReturnsFalse covers AC-008.52: Restore
// matches only a row whose status is still deleted, so a row moved to
// another status through some other path cannot be revived by it. The
// literal state named by this criterion review (a row with deleted_at set
// while status is not deleted) cannot be arranged even with a direct SQL
// UPDATE: the users_deleted_at_matches_status CHECK constraint enforces
// (status = 'deleted') = (deleted_at IS NOT NULL) on every write, so
// Postgres itself refuses that row. This test exercises the same predicate
// against the DB-legal case instead: a suspended account, which always
// carries a nil deleted_at.
func TestRestoreAgainstNonDeletedStatusReturnsFalse(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Restore Wrong Status")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-restore-wrong-status")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	if _, err := repo.SetStatus(t.Context(), u.ID, user.StatusSuspended); err != nil {
		t.Fatalf("SetStatus(suspended) error = %v, want nil", err)
	}

	changed, err := repo.Restore(t.Context(), u.ID, current.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Restore() error = %v, want nil", err)
	}

	if changed {
		t.Fatalf("Restore() changed = true, want false (status is not deleted)")
	}

	after, err := repo.ByIDAnyStatus(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
	}

	if after.Status != user.StatusSuspended {
		t.Fatalf("ByIDAnyStatus() Status = %v, want %v (unchanged)", after.Status, user.StatusSuspended)
	}

	if after.DeletedAt != nil {
		t.Fatalf("ByIDAnyStatus() DeletedAt = %v, want nil (unchanged)", after.DeletedAt)
	}
}

// TestRejectSetsRejectedAt covers AC-008.78: Reject sets rejected_at from the
// injected clock in the same statement as status and deleted_at.
func TestRejectSetsRejectedAt(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Pending Reject RejectedAt")
	u.Status = user.StatusPending

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-reject-rejectedat")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	current = current.Add(time.Hour)

	changed, err := repo.Reject(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Reject() error = %v, want nil", err)
	}

	if !changed {
		t.Fatalf("Reject() changed = false, want true")
	}

	got, err := repo.ByIDAnyStatus(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
	}

	if got.RejectedAt == nil || !got.RejectedAt.Equal(current) {
		t.Fatalf("ByIDAnyStatus() RejectedAt = %v, want %v", got.RejectedAt, current)
	}
}

// TestRestoreRefusesARejectedAccount covers AC-008.78: a rejected account,
// unlike a self-deleted one, can never be restored, even within its grace
// window, and the row stays deleted.
func TestRestoreRefusesARejectedAccount(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Pending Restore Rejected")
	u.Status = user.StatusPending

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-restore-rejected")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	if _, err := repo.Reject(t.Context(), u.ID); err != nil {
		t.Fatalf("Reject() error = %v, want nil", err)
	}

	changed, err := repo.Restore(t.Context(), u.ID, current.Add(-time.Hour))
	if !errors.Is(err, user.ErrIsRejected) {
		t.Fatalf("Restore() error = %v, want ErrIsRejected", err)
	}

	if changed {
		t.Fatalf("Restore() changed = true, want false")
	}

	got, err := repo.ByIDAnyStatus(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
	}

	if got.Status != user.StatusDeleted {
		t.Fatalf("ByIDAnyStatus() Status = %v, want %v (still deleted)", got.Status, user.StatusDeleted)
	}
}

// TestRestoreStillRevivesASelfDeletedAccount is a regression guard for
// AC-008.52: adding the rejected_at IS NULL predicate to Restore's WHERE
// clause must not affect a self-deleted (never-rejected) account, whose
// rejected_at is nil, so it still restores exactly as before.
func TestRestoreStillRevivesASelfDeletedAccount(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, _ := newRepository(t, clock)

	u := newUser("Self Deleted Restore Regression")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-self-deleted-restore")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	if err := repo.SoftDelete(t.Context(), u.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v, want nil", err)
	}

	changed, err := repo.Restore(t.Context(), u.ID, current.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Restore() error = %v, want nil", err)
	}

	if !changed {
		t.Fatalf("Restore() changed = false, want true")
	}

	got, err := repo.ByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want nil", err)
	}

	if got.Status != user.StatusActive {
		t.Fatalf("ByID() Status = %v, want %v", got.Status, user.StatusActive)
	}
}

// TestMarkBootstrapAdminGrantedTxMarksOnceAndOnlyOnce covers AC-008.79: the
// first mark records the grant instant and reports a change, and a second
// mark changes nothing, so the bootstrap grant can never be recorded twice.
func TestMarkBootstrapAdminGrantedTxMarksOnceAndOnlyOnce(t *testing.T) {
	t.Parallel()

	current := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	clock := func() time.Time { return current }

	repo, h := newRepository(t, clock)

	u := newUser("Bootstrap Mark")

	if err := repo.CreateWithIdentity(t.Context(), u, newIdentity(u.ID, "https://issuer.example", "subject-bootstrap-mark")); err != nil {
		t.Fatalf("CreateWithIdentity() error = %v, want nil", err)
	}

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v, want nil", err)
	}

	first, err := repo.MarkBootstrapAdminGrantedTx(t.Context(), tx, u.ID)
	if err != nil {
		t.Fatalf("first MarkBootstrapAdminGrantedTx() error = %v, want nil", err)
	}

	second, err := repo.MarkBootstrapAdminGrantedTx(t.Context(), tx, u.ID)
	if err != nil {
		t.Fatalf("second MarkBootstrapAdminGrantedTx() error = %v, want nil", err)
	}

	if commitErr := tx.Commit(t.Context()); commitErr != nil {
		t.Fatalf("Commit() error = %v, want nil", commitErr)
	}

	if !first || second {
		t.Fatalf("MarkBootstrapAdminGrantedTx() changed = %v then %v, want true then false", first, second)
	}

	got, err := repo.ByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want nil", err)
	}

	if got.BootstrapAdminGrantedAt == nil || !got.BootstrapAdminGrantedAt.Equal(current) {
		t.Fatalf("ByID() BootstrapAdminGrantedAt = %v, want %v", got.BootstrapAdminGrantedAt, current)
	}
}

// TestCountIdentitiesFromCountsOnlyThoseProvidersForThatAccount covers
// AC-008.44: the last-factor rule counts only identities that can still
// reach an account, so CountIdentitiesFrom and its transactional form must
// count only the named providers' identities, and only the named account's.
func TestCountIdentitiesFromCountsOnlyThoseProvidersForThatAccount(t *testing.T) {
	t.Parallel()

	repo, h := newRepository(t, time.Now)

	owner := newUser("Provider Count Owner")
	if err := repo.CreateWithIdentity(t.Context(), owner, newIdentity(owner.ID, "email", "provider-count-owner@example.com")); err != nil {
		t.Fatalf("CreateWithIdentity(owner) error = %v, want nil", err)
	}

	if err := repo.LinkIdentity(t.Context(), newIdentity(owner.ID, "https://issuer.example", "provider-count-owner")); err != nil {
		t.Fatalf("LinkIdentity(owner provider) error = %v, want nil", err)
	}

	other := newUser("Provider Count Other")
	if err := repo.CreateWithIdentity(t.Context(), other, newIdentity(other.ID, "email", "provider-count-other@example.com")); err != nil {
		t.Fatalf("CreateWithIdentity(other) error = %v, want nil", err)
	}

	tests := []struct {
		name      string
		providers []string
		want      int
	}{
		{name: "one provider", providers: []string{"email"}, want: 1},
		{name: "both providers", providers: []string{"email", "https://issuer.example"}, want: 2},
		{name: "a provider the account has no identity from", providers: []string{"https://other.example"}, want: 0},
		{name: "no providers", providers: nil, want: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := repo.CountIdentitiesFrom(t.Context(), owner.ID, test.providers)
			if err != nil {
				t.Fatalf("CountIdentitiesFrom() error = %v, want nil", err)
			}

			if got != test.want {
				t.Errorf("CountIdentitiesFrom(owner, %v) = %d, want %d", test.providers, got, test.want)
			}
		})
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

	gotTx, err := repo.CountIdentitiesFromTx(t.Context(), tx, owner.ID, []string{"email"})
	if err != nil {
		t.Fatalf("CountIdentitiesFromTx() error = %v, want nil", err)
	}

	if gotTx != 1 {
		t.Errorf("CountIdentitiesFromTx(owner, [email]) = %d, want 1", gotTx)
	}
}
