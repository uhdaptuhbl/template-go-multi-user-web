//go:build integration

package authz_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// allPermissions is the sorted set of the nine seeded permission names,
// matching migration 00002_seed_roles_and_permissions.sql.
var allPermissions = []string{
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

// insertUser inserts a minimal user row directly, satisfying the foreign key
// user_roles.user_id (and, as its own granter, user_roles.granted_by) needs.
func insertUser(t *testing.T, h *store.Handle) uuid.UUID {
	t.Helper()

	id := uuid.New()
	now := time.Now().UTC()

	_, err := h.Pool().Exec(t.Context(), `
		INSERT INTO users (id, display_name, status, created_at, updated_at)
		VALUES ($1, $2, 'active', $3, $3)
	`, id, "test-user-"+id.String(), now)
	if err != nil {
		t.Fatalf("insertUser: %v", err)
	}

	return id
}

// AC-008.31, AC-008.32: a fresh member account holds exactly invite.create.
func TestPermissionsFor_Member(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	if err := repo.GrantRole(t.Context(), userID, authz.RoleMember, userID); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}

	got, err := repo.PermissionsFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("PermissionsFor: %v", err)
	}

	want := []string{authz.PermissionInviteCreate}
	if !slices.Equal(got, want) {
		t.Fatalf("PermissionsFor = %v, want %v", got, want)
	}
}

// AC-008.31, AC-008.32: an admin account has exactly the nine permission
// names, sorted.
func TestPermissionsFor_Admin(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	if err := repo.GrantRole(t.Context(), userID, authz.RoleAdmin, userID); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}

	got, err := repo.PermissionsFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("PermissionsFor: %v", err)
	}

	if !slices.Equal(got, allPermissions) {
		t.Fatalf("PermissionsFor = %v, want %v", got, allPermissions)
	}
}

// AC-008.31: Has is table-driven across each of the nine permissions for an
// admin and a member.
func TestChecker_Has(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	checker := authz.NewChecker(repo)

	adminID := insertUser(t, h)
	if err := repo.GrantRole(t.Context(), adminID, authz.RoleAdmin, adminID); err != nil {
		t.Fatalf("GrantRole admin: %v", err)
	}

	memberID := insertUser(t, h)
	if err := repo.GrantRole(t.Context(), memberID, authz.RoleMember, memberID); err != nil {
		t.Fatalf("GrantRole member: %v", err)
	}

	for _, permission := range allPermissions {
		t.Run("admin/"+permission, func(t *testing.T) {
			got, err := checker.Has(t.Context(), adminID, permission)
			if err != nil {
				t.Fatalf("Has: %v", err)
			}

			if !got {
				t.Fatalf("Has(admin, %s) = false, want true", permission)
			}
		})

		t.Run("member/"+permission, func(t *testing.T) {
			got, err := checker.Has(t.Context(), memberID, permission)
			if err != nil {
				t.Fatalf("Has: %v", err)
			}

			want := permission == authz.PermissionInviteCreate
			if got != want {
				t.Fatalf("Has(member, %s) = %v, want %v", permission, got, want)
			}
		})
	}
}

// AC-008.31: Has for an account with no roles returns false without error.
func TestChecker_Has_NoRoles(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	checker := authz.NewChecker(repo)
	userID := insertUser(t, h)

	got, err := checker.Has(t.Context(), userID, authz.PermissionUserRead)
	if err != nil {
		t.Fatalf("Has: %v", err)
	}

	if got {
		t.Fatalf("Has = true, want false")
	}
}

// AC-008.31: SetRoles replaces rather than appends.
func TestSetRoles_Replaces(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	if err := repo.SetRoles(t.Context(), userID, []string{authz.RoleMember}, userID); err != nil {
		t.Fatalf("SetRoles(member): %v", err)
	}

	if err := repo.SetRoles(t.Context(), userID, []string{authz.RoleAdmin}, userID); err != nil {
		t.Fatalf("SetRoles(admin): %v", err)
	}

	got, err := repo.RolesFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("RolesFor: %v", err)
	}

	want := []string{authz.RoleAdmin}
	if !slices.Equal(got, want) {
		t.Fatalf("RolesFor = %v, want %v", got, want)
	}
}

// AC-008.31: SetRoles with an unknown name returns ErrUnknownRole and leaves
// the prior roles intact.
func TestSetRoles_UnknownRole(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	if err := repo.SetRoles(t.Context(), userID, []string{authz.RoleMember}, userID); err != nil {
		t.Fatalf("SetRoles(member): %v", err)
	}

	err := repo.SetRoles(t.Context(), userID, []string{authz.RoleAdmin, "bogus"}, userID)
	if !errors.Is(err, authz.ErrUnknownRole) {
		t.Fatalf("SetRoles(admin, bogus) error = %v, want ErrUnknownRole", err)
	}

	got, err := repo.RolesFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("RolesFor: %v", err)
	}

	want := []string{authz.RoleMember}
	if !slices.Equal(got, want) {
		t.Fatalf("RolesFor = %v, want %v", got, want)
	}
}

// AC-008.31: GrantRole twice is idempotent.
func TestGrantRole_Idempotent(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	if err := repo.GrantRole(t.Context(), userID, authz.RoleMember, userID); err != nil {
		t.Fatalf("GrantRole (first): %v", err)
	}

	if err := repo.GrantRole(t.Context(), userID, authz.RoleMember, userID); err != nil {
		t.Fatalf("GrantRole (second): %v", err)
	}

	got, err := repo.RolesFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("RolesFor: %v", err)
	}

	want := []string{authz.RoleMember}
	if !slices.Equal(got, want) {
		t.Fatalf("RolesFor = %v, want %v", got, want)
	}
}

// AC-008.31: RolesFor returns sorted names.
func TestRolesFor_Sorted(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)
	userID := insertUser(t, h)

	if err := repo.GrantRole(t.Context(), userID, authz.RoleMember, userID); err != nil {
		t.Fatalf("GrantRole member: %v", err)
	}

	if err := repo.GrantRole(t.Context(), userID, authz.RoleAdmin, userID); err != nil {
		t.Fatalf("GrantRole admin: %v", err)
	}

	got, err := repo.RolesFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("RolesFor: %v", err)
	}

	want := []string{authz.RoleAdmin, authz.RoleMember}
	if !slices.Equal(got, want) {
		t.Fatalf("RolesFor = %v, want %v", got, want)
	}
}

// AC-008.31: RolesForEach reports each requested account's roles, sorted,
// in one read, with an empty list rather than an absent entry for an
// account holding none, and nothing for an account it was not asked about.
func TestRolesForEach_ReportsEveryRequestedAccount(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := authz.NewRepository(h, time.Now)

	both := insertUser(t, h)
	memberOnly := insertUser(t, h)
	none := insertUser(t, h)
	notAsked := insertUser(t, h)

	grants := []struct {
		userID uuid.UUID
		role   string
	}{
		{userID: both, role: authz.RoleMember},
		{userID: both, role: authz.RoleAdmin},
		{userID: memberOnly, role: authz.RoleMember},
		{userID: notAsked, role: authz.RoleAdmin},
	}

	for _, grant := range grants {
		if err := repo.GrantRole(t.Context(), grant.userID, grant.role, grant.userID); err != nil {
			t.Fatalf("GrantRole(%s): %v", grant.role, err)
		}
	}

	got, err := repo.RolesForEach(t.Context(), []uuid.UUID{both, memberOnly, none})
	if err != nil {
		t.Fatalf("RolesForEach: %v", err)
	}

	want := map[uuid.UUID][]string{
		both:       {authz.RoleAdmin, authz.RoleMember},
		memberOnly: {authz.RoleMember},
		none:       {},
	}

	// cmp.Diff tells a nil slice from an empty one, so this also pins that
	// an account with no roles gets a list that encodes as [] rather than
	// null.
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("RolesForEach mismatch (-want +got):\n%s", diff)
	}
}
