package authz_test

import (
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
)

// AC-008.34: SubjectFromContext returns false on a context carrying no
// Subject.
func TestSubjectFromContext_Absent(t *testing.T) {
	t.Parallel()

	_, ok := authz.SubjectFromContext(t.Context())
	if ok {
		t.Fatalf("SubjectFromContext ok = true, want false")
	}
}

// AC-008.32: WithSubject followed by SubjectFromContext round-trips the exact
// Subject that was stored.
func TestWithSubject_RoundTrips(t *testing.T) {
	t.Parallel()

	want := authz.Subject{
		UserID:          uuid.New(),
		SessionPublicID: uuid.New(),
		Permissions:     []string{authz.PermissionInviteCreate},
	}

	ctx := authz.WithSubject(t.Context(), want)

	got, ok := authz.SubjectFromContext(ctx)
	if !ok {
		t.Fatalf("SubjectFromContext ok = false, want true")
	}

	if got.UserID != want.UserID || got.SessionPublicID != want.SessionPublicID {
		t.Fatalf("SubjectFromContext = %+v, want %+v", got, want)
	}

	// The round trip must preserve Permissions too, not just the two
	// identifier fields checked above.
	if !slices.Equal(got.Permissions, want.Permissions) {
		t.Fatalf("SubjectFromContext Permissions = %v, want %v", got.Permissions, want.Permissions)
	}
}

// AC-008.32: HasPermission reports true only for a permission the subject
// actually carries.
func TestSubject_HasPermission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		permission string
		want       bool
	}{
		{name: "held permission", permission: authz.PermissionInviteCreate, want: true},
		{name: "unheld permission", permission: authz.PermissionUserRead, want: false},
	}

	subject := authz.Subject{
		UserID:      uuid.New(),
		Permissions: []string{authz.PermissionInviteCreate},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := subject.HasPermission(tc.permission)
			if got != tc.want {
				t.Fatalf("HasPermission(%s) = %v, want %v", tc.permission, got, tc.want)
			}
		})
	}
}
