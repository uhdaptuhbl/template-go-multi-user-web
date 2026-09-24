//go:build integration

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/otp"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/passkey"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authflow"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// accountLinkProviderKey is the configured Key for the one OIDC provider the
// identity-link tests in this file register.
const accountLinkProviderKey = "test"

// accountLinkClientID and accountLinkClientSecret are the OAuth credentials
// every identity-link test registers the fake provider with.
const accountLinkClientID = "account-link-client"
const accountLinkClientSecret = "account-link-secret"

// accountLinkKeyID is the key identifier every signed test token and the
// fake provider's published JWKS entry share.
const accountLinkKeyID = "account-link-key"

// configuredProviderKey is the OIDC provider key the factor-counting tests
// configure, so an identity it issued can still reach its account.
const configuredProviderKey = "configured"

// retiredProviderKey names a provider no test configures: an identity it
// issued stands for a provider an operator has since removed.
const retiredProviderKey = "retired"

// newConfiguredProviderRegistry returns a registry with exactly keys
// configured, for tests that only need the last-factor rule to know which
// providers exist. It has no flow store and a discovery URL nothing serves,
// so it must never be used to run a ceremony.
func newConfiguredProviderRegistry(t *testing.T, keys ...string) *oidc.Registry {
	t.Helper()

	providers := make([]oidc.ProviderConfig, 0, len(keys))
	for _, key := range keys {
		providers = append(providers, oidc.ProviderConfig{
			Key:          key,
			Issuer:       "https://issuer.invalid/" + key,
			ClientID:     "client-id",
			ClientSecret: secret.String("client-secret"),
			DisplayName:  key,
		})
	}

	registry, err := oidc.NewRegistry(oidc.Config{
		PublicOrigin: "https://app.example",
		Providers:    providers,
		ClockSkew:    configtype.Duration(30 * time.Second),
	}, nil, http.DefaultClient, zap.NewNop())
	if err != nil {
		t.Fatalf("oidc.NewRegistry() error = %v", err)
	}

	return registry
}

// accountTestDeps bundles the real collaborators an account.go test needs,
// all backed by one migrated database and one shared, manually advanced
// clock.
type accountTestDeps struct {
	service     *Service
	handle      *store.Handle
	users       *user.Repository
	roles       *authz.Repository
	sessions    *session.Store
	credentials *passkey.Repository
	recorder    *audit.Recorder
	clock       *clock
}

// newAccountTestDeps returns an accountTestDeps whose Service is configured
// with otpEnabled and gracePeriod, and with providers wired in when non-nil.
func newAccountTestDeps(t *testing.T, otpEnabled bool, gracePeriod time.Duration, providers *oidc.Registry) accountTestDeps {
	t.Helper()

	c := newClock()
	h := storetest.New(t)

	users := user.NewRepository(h, c.Now)
	sessions := session.NewStore(h, session.DefaultConfig(), c.Now)
	roles := authz.NewRepository(h, c.Now)
	checker := authz.NewChecker(roles)
	recorder := audit.NewRecorder(h, zap.NewNop(), c.Now)
	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)
	credentials := passkey.NewRepository(h, c.Now)

	invites, err := invite.NewService(h, policy, testTokenBytes, zap.NewNop(), c.Now)
	if err != nil {
		t.Fatalf("invite.NewService() error = %v", err)
	}

	accountDeps := AccountDeps{
		Credentials:        credentials,
		Providers:          providers,
		OTPEnabled:         otpEnabled,
		DeletedGracePeriod: gracePeriod,
	}

	svc := NewService(h, users, sessions, roles, checker, recorder, invites, policy, nil, zap.NewNop(), c.Now, accountDeps)

	return accountTestDeps{
		service:     svc,
		handle:      h,
		users:       users,
		roles:       roles,
		sessions:    sessions,
		credentials: credentials,
		recorder:    recorder,
		clock:       c,
	}
}

// newAccountUser inserts an active account row directly, with a verified
// email when emailVerified is true.
func newAccountUser(t *testing.T, h *store.Handle, now time.Time, emailVerified bool) uuid.UUID {
	t.Helper()

	id := uuid.New()
	email := id.String() + "@example.com"

	var verifiedAt *time.Time
	if emailVerified {
		verifiedAt = &now
	}

	const insertQuery = `
INSERT INTO users (id, display_name, email, email_verified_at, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'active', $5, $5)
`

	if _, err := h.Pool().Exec(t.Context(), insertQuery, id, "account test user", email, verifiedAt, now); err != nil {
		t.Fatalf("inserting test user: %v", err)
	}

	return id
}

// newAccountIdentity links an external identity to userID directly through
// the user repository.
func newAccountIdentity(t *testing.T, users *user.Repository, userID uuid.UUID, provider, subject string) uuid.UUID {
	t.Helper()

	id := uuid.New()

	if err := users.LinkIdentity(t.Context(), user.Identity{
		ID:       id,
		UserID:   userID,
		Provider: provider,
		Subject:  subject,
	}); err != nil {
		t.Fatalf("LinkIdentity() error = %v", err)
	}

	return id
}

// newAccountCredential registers a passkey credential for userID.
func newAccountCredential(t *testing.T, repo *passkey.Repository, userID uuid.UUID) uuid.UUID {
	t.Helper()

	id := uuid.New()

	cred := passkey.Credential{
		ID:              id,
		UserID:          userID,
		CredentialID:    []byte(id.String()),
		PublicKey:       []byte("test-public-key"),
		AttestationType: "none",
		Transports:      []string{"internal"},
		AAGUID:          []byte{},
		Name:            "test credential",
		CreatedAt:       time.Now().UTC(),
	}

	if err := repo.Create(t.Context(), cred); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	return id
}

// grantAccountAdmin grants userID the admin role, self-granted for test
// simplicity.
func grantAccountAdmin(t *testing.T, roles *authz.Repository, userID uuid.UUID) {
	t.Helper()

	if err := roles.GrantRole(t.Context(), userID, authz.RoleAdmin, userID); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}
}

// TestFactors covers AC-008.44: Factors counts credentials and identities,
// including an email-code identity while OTP is enabled, as usable
// authentication factors. A verified address with no email-code identity
// counts for nothing: an emailed code reaches an account only through that
// identity (see Factors).
func TestFactors(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, true, time.Hour, newConfiguredProviderRegistry(t, configuredProviderKey))
	now := deps.clock.Now()

	tests := []struct {
		name            string
		credentials     int
		identities      int
		emailIdentities int
		// retiredIdentities come from a provider no longer configured.
		retiredIdentities int
		emailVerified     bool
		want              int
	}{
		{name: "nothing", credentials: 0, identities: 0, emailIdentities: 0, emailVerified: false, want: 0},
		{name: "one credential", credentials: 1, identities: 0, emailIdentities: 0, emailVerified: false, want: 1},
		{name: "one identity", credentials: 0, identities: 1, emailIdentities: 0, emailVerified: false, want: 1},
		{name: "verified email counts otp", credentials: 0, identities: 0, emailIdentities: 1, emailVerified: true, want: 1},
		{name: "verified address alone counts nothing", credentials: 0, identities: 0, emailIdentities: 0, emailVerified: true, want: 0},
		{name: "identity from a removed provider counts nothing", retiredIdentities: 1, want: 0},
		{name: "everything", credentials: 2, identities: 1, emailIdentities: 1, retiredIdentities: 1, emailVerified: true, want: 4},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			userID := newAccountUser(t, deps.handle, now, tc.emailVerified)

			for range tc.credentials {
				newAccountCredential(t, deps.credentials, userID)
			}

			for i := range tc.identities {
				newAccountIdentity(t, deps.users, userID, configuredProviderKey, fmt.Sprintf("sub-%s-%d", tc.name, i))
			}

			for i := range tc.retiredIdentities {
				newAccountIdentity(t, deps.users, userID, retiredProviderKey, fmt.Sprintf("retired-%s-%d", tc.name, i))
			}

			for i := range tc.emailIdentities {
				newAccountIdentity(t, deps.users, userID, otp.Provider, fmt.Sprintf("%s-%d@example.com", userID, i))
			}

			got, err := deps.service.Factors(t.Context(), userID)
			if err != nil {
				t.Fatalf("Factors() error = %v", err)
			}

			if got != tc.want {
				t.Errorf("Factors() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestFactors_OTPDisabled_NeverCounts covers AC-008.44's OTP boundary from
// the other side: a verified email contributes nothing when OTP is disabled
// service-wide.
func TestFactors_OTPDisabled_NeverCounts(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)

	got, err := deps.service.Factors(t.Context(), userID)
	if err != nil {
		t.Fatalf("Factors() error = %v", err)
	}

	if got != 0 {
		t.Errorf("Factors() = %d, want 0 when OTP is disabled", got)
	}
}

// TestRemoveCredential_LastFactor_Refuses covers AC-008.44: removing an
// account's only credential, with no other factor available, is refused
// with ErrLastFactor and the credential survives.
func TestRemoveCredential_LastFactor_Refuses(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	credID := newAccountCredential(t, deps.credentials, userID)

	err := deps.service.RemoveCredential(t.Context(), userID, credID, "203.0.113.5", "req-1")
	if !errors.Is(err, ErrLastFactor) {
		t.Fatalf("RemoveCredential() error = %v, want ErrLastFactor", err)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM credentials WHERE id = $1`, credID); got != 1 {
		t.Errorf("credential rows = %d, want 1 (refusal must not remove it)", got)
	}
}

// TestRemoveCredential_Success_LeavesOtherFactorIntact covers AC-008.44: an
// account with two credentials may remove one, leaving the other in place,
// and the removal is audited.
func TestRemoveCredential_Success_LeavesOtherFactorIntact(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	keep := newAccountCredential(t, deps.credentials, userID)
	remove := newAccountCredential(t, deps.credentials, userID)

	if err := deps.service.RemoveCredential(t.Context(), userID, remove, "203.0.113.5", "req-1"); err != nil {
		t.Fatalf("RemoveCredential() error = %v, want nil", err)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM credentials WHERE id = $1`, remove); got != 0 {
		t.Errorf("removed credential rows = %d, want 0", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM credentials WHERE id = $1`, keep); got != 1 {
		t.Errorf("kept credential rows = %d, want 1", got)
	}

	if got := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2 AND outcome = 'success'`,
		audit.ActionPasskeyRemoved, "credential:"+remove.String()); got != 1 {
		t.Errorf("passkey.removed success audit rows = %d, want 1", got)
	}
}

// TestRemoveCredential_OTPCountsAsUsableFactor covers AC-008.44: an
// account's only credential may be removed when OTP is enabled and the
// account holds an email-code identity, because the OTP method remains a
// usable factor.
func TestRemoveCredential_OTPCountsAsUsableFactor(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, true, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	newAccountIdentity(t, deps.users, userID, otp.Provider, userID.String()+"@example.com")
	credID := newAccountCredential(t, deps.credentials, userID)

	if err := deps.service.RemoveCredential(t.Context(), userID, credID, "203.0.113.5", "req-1"); err != nil {
		t.Fatalf("RemoveCredential() error = %v, want nil", err)
	}

	got, err := deps.service.Factors(t.Context(), userID)
	if err != nil {
		t.Fatalf("Factors() error = %v", err)
	}

	if got != 1 {
		t.Errorf("Factors() after removal = %d, want 1 (the OTP factor)", got)
	}
}

// TestRemoveCredential_ConcurrentRemovals_ExactlyOneSucceeds covers
// AC-008.44 under concurrency: an account with exactly two credentials and
// no other factor cannot have both removed by two concurrent calls. Run
// with -race, this proves the account-row lock RemoveCredential takes
// serializes the two calls instead of letting each observe two factors and
// both proceed.
func TestRemoveCredential_ConcurrentRemovals_ExactlyOneSucceeds(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	credA := newAccountCredential(t, deps.credentials, userID)
	credB := newAccountCredential(t, deps.credentials, userID)

	results := make([]error, 2)

	var wg sync.WaitGroup

	wg.Go(func() {
		results[0] = deps.service.RemoveCredential(t.Context(), userID, credA, "203.0.113.5", "req-a")
	})

	wg.Go(func() {
		results[1] = deps.service.RemoveCredential(t.Context(), userID, credB, "203.0.113.5", "req-b")
	})

	wg.Wait()

	successes := 0
	refusals := 0

	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrLastFactor):
			refusals++
		default:
			t.Fatalf("RemoveCredential() unexpected error = %v", err)
		}
	}

	if successes != 1 || refusals != 1 {
		t.Fatalf("got %d successes and %d refusals, want exactly 1 of each", successes, refusals)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM credentials WHERE user_id = $1`, userID); got != 1 {
		t.Errorf("remaining credential rows = %d, want 1 (never zero)", got)
	}
}

// TestRemoveCredential_ScopedToOwner covers the ownership predicate
// (design.md's "Authorization path"): a caller acting on an account it
// does not own affects nothing, and the owner's own call still succeeds.
// Covers AC-008.26 and AC-008.35.
func TestRemoveCredential_ScopedToOwner(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)

	victim := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	victimKeep := newAccountCredential(t, deps.credentials, victim)
	victimTarget := newAccountCredential(t, deps.credentials, victim)

	attacker := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	newAccountCredential(t, deps.credentials, attacker)
	newAccountCredential(t, deps.credentials, attacker)

	// The non-owner's call: attacker is authenticated as itself but names
	// victim's credential id. It must affect nothing.
	if err := deps.service.RemoveCredential(t.Context(), attacker, victimTarget, "203.0.113.5", "req-attack"); err != nil {
		t.Fatalf("RemoveCredential() cross-account call error = %v, want nil (silent no-op)", err)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM credentials WHERE id = $1`, victimTarget); got != 1 {
		t.Errorf("victim's credential rows after cross-account call = %d, want 1 (untouched)", got)
	}

	// The owner's own call against the same credential succeeds.
	if err := deps.service.RemoveCredential(t.Context(), victim, victimTarget, "203.0.113.5", "req-owner"); err != nil {
		t.Fatalf("RemoveCredential() owner call error = %v, want nil", err)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM credentials WHERE id = $1`, victimTarget); got != 0 {
		t.Errorf("victim's credential rows after owner's own call = %d, want 0", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM credentials WHERE id = $1`, victimKeep); got != 1 {
		t.Errorf("victim's other credential rows = %d, want 1 (never touched)", got)
	}
}

// TestRemoveIdentity_LastFactor_Refuses covers AC-008.44 for identities: the
// same last-factor refusal RemoveCredential enforces.
func TestRemoveIdentity_LastFactor_Refuses(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, newConfiguredProviderRegistry(t, configuredProviderKey))
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	identityID := newAccountIdentity(t, deps.users, userID, configuredProviderKey, "sub-only")

	err := deps.service.RemoveIdentity(t.Context(), userID, identityID, "203.0.113.5", "req-1")
	if !errors.Is(err, ErrLastFactor) {
		t.Fatalf("RemoveIdentity() error = %v, want ErrLastFactor", err)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM identities WHERE id = $1`, identityID); got != 1 {
		t.Errorf("identity rows = %d, want 1 (refusal must not remove it)", got)
	}
}

// TestRemoveIdentity_Success_LeavesOtherFactorIntact covers AC-008.44: an
// account with a credential and an identity may remove the identity,
// leaving the credential in place.
func TestRemoveIdentity_Success_LeavesOtherFactorIntact(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, newConfiguredProviderRegistry(t, configuredProviderKey))
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	credID := newAccountCredential(t, deps.credentials, userID)
	identityID := newAccountIdentity(t, deps.users, userID, configuredProviderKey, "sub-removable")

	if err := deps.service.RemoveIdentity(t.Context(), userID, identityID, "203.0.113.5", "req-1"); err != nil {
		t.Fatalf("RemoveIdentity() error = %v, want nil", err)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM identities WHERE id = $1`, identityID); got != 0 {
		t.Errorf("removed identity rows = %d, want 0", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM credentials WHERE id = $1`, credID); got != 1 {
		t.Errorf("credential rows = %d, want 1 (untouched)", got)
	}
}

// TestRemoval_CountsOnlyMethodsThatReachTheAccount covers AC-008.44: an
// emailed code reaches an account only through an identity keyed on
// (otp.Provider, address), never through the account's own verified address
// (ADR 0012 forbids resolving a login by email), so a verified address is
// not itself a way in, and an email identity is one only while email codes
// are enabled. Likewise an identity from a provider that is no longer
// configured cannot sign anyone in. Each case would leave the account with
// no method that reaches it, so each removal is refused and the target
// survives.
func TestRemoval_CountsOnlyMethodsThatReachTheAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		otpEnabled bool
		// arrange returns the account and a function removing its target.
		arrange func(t *testing.T, deps accountTestDeps) (uuid.UUID, func(uuid.UUID) error, string, uuid.UUID)
	}{
		{
			name:       "sole email identity with codes enabled",
			otpEnabled: true,
			arrange: func(t *testing.T, deps accountTestDeps) (uuid.UUID, func(uuid.UUID) error, string, uuid.UUID) {
				t.Helper()

				userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
				identityID := newAccountIdentity(t, deps.users, userID, otp.Provider, userID.String()+"@example.com")

				return userID, func(id uuid.UUID) error {
					return deps.service.RemoveIdentity(t.Context(), id, identityID, "203.0.113.5", "req-1")
				}, `SELECT count(*) FROM identities WHERE id = $1`, identityID
			},
		},
		{
			name:       "sole provider identity beside a verified address",
			otpEnabled: true,
			arrange: func(t *testing.T, deps accountTestDeps) (uuid.UUID, func(uuid.UUID) error, string, uuid.UUID) {
				t.Helper()

				userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
				identityID := newAccountIdentity(t, deps.users, userID, configuredProviderKey, "sub-"+userID.String())

				return userID, func(id uuid.UUID) error {
					return deps.service.RemoveIdentity(t.Context(), id, identityID, "203.0.113.5", "req-1")
				}, `SELECT count(*) FROM identities WHERE id = $1`, identityID
			},
		},
		{
			name:       "sole credential beside an email identity with codes disabled",
			otpEnabled: false,
			arrange: func(t *testing.T, deps accountTestDeps) (uuid.UUID, func(uuid.UUID) error, string, uuid.UUID) {
				t.Helper()

				userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
				newAccountIdentity(t, deps.users, userID, otp.Provider, userID.String()+"@example.com")
				credID := newAccountCredential(t, deps.credentials, userID)

				return userID, func(id uuid.UUID) error {
					return deps.service.RemoveCredential(t.Context(), id, credID, "203.0.113.5", "req-1")
				}, `SELECT count(*) FROM credentials WHERE id = $1`, credID
			},
		},
		{
			name:       "sole credential beside an identity from a removed provider",
			otpEnabled: true,
			arrange: func(t *testing.T, deps accountTestDeps) (uuid.UUID, func(uuid.UUID) error, string, uuid.UUID) {
				t.Helper()

				userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
				newAccountIdentity(t, deps.users, userID, retiredProviderKey, "sub-"+userID.String())
				credID := newAccountCredential(t, deps.credentials, userID)

				return userID, func(id uuid.UUID) error {
					return deps.service.RemoveCredential(t.Context(), id, credID, "203.0.113.5", "req-1")
				}, `SELECT count(*) FROM credentials WHERE id = $1`, credID
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deps := newAccountTestDeps(t, tc.otpEnabled, time.Hour, newConfiguredProviderRegistry(t, configuredProviderKey))
			userID, remove, countQuery, targetID := tc.arrange(t, deps)

			err := remove(userID)
			if !errors.Is(err, ErrLastFactor) {
				t.Fatalf("removal error = %v, want ErrLastFactor", err)
			}

			if got := countRows(t, deps.handle, countQuery, targetID); got != 1 {
				t.Errorf("target rows = %d, want 1 (refusal must not remove it)", got)
			}
		})
	}
}

// TestUpdateDisplayName_Success covers AC-008.45: an account may change its
// own display name.
func TestUpdateDisplayName_Success(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	updated, err := deps.service.UpdateDisplayName(t.Context(), userID, "New Name", "203.0.113.5", "req-1")
	if err != nil {
		t.Fatalf("UpdateDisplayName() error = %v", err)
	}

	if updated.DisplayName != "New Name" {
		t.Errorf("UpdateDisplayName() DisplayName = %q, want %q", updated.DisplayName, "New Name")
	}

	if got := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionUserUpdated, "user:"+userID.String()); got != 1 {
		t.Errorf("user.updated audit rows = %d, want 1", got)
	}
}

// TestDeleteAccount_LastAdmin_Refuses covers AC-008.50: an administrator
// deleting itself when it is the sole active administrator is refused with
// ErrLastAdmin, and the account is left untouched.
func TestDeleteAccount_LastAdmin_Refuses(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	grantAccountAdmin(t, deps.roles, adminID)

	err := deps.service.DeleteAccount(t.Context(), adminID, "203.0.113.5", "req-1")
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("DeleteAccount() error = %v, want ErrLastAdmin", err)
	}

	account, err := deps.users.ByID(t.Context(), adminID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want nil (account must still exist and be active)", err)
	}

	if account.Status != user.StatusActive {
		t.Errorf("account status = %q, want active", account.Status)
	}
}

// TestDeleteAccount_Success_RevokesSessionsPreventsLoginRetainsRows covers
// AC-008.46: deleting an account revokes every session it holds and
// prevents it from authenticating, while its identities and credentials
// survive until the grace period elapses.
func TestDeleteAccount_Success_RevokesSessionsPreventsLoginRetainsRows(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	credID := newAccountCredential(t, deps.credentials, userID)
	identityID := newAccountIdentity(t, deps.users, userID, "https://issuer.example", "sub-deleted")

	if _, _, err := deps.sessions.Issue(t.Context(), userID, "203.0.113.5", "ua", nil); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if err := deps.service.DeleteAccount(t.Context(), userID, "203.0.113.5", "req-1"); err != nil {
		t.Fatalf("DeleteAccount() error = %v, want nil", err)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE user_id = $1`, userID); got != 0 {
		t.Errorf("session rows = %d, want 0 (revoked)", got)
	}

	if _, err := deps.users.ByID(t.Context(), userID); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("ByID() error = %v, want ErrNotFound (deleted accounts do not resolve)", err)
	}

	account, err := deps.users.ByIDAnyStatus(t.Context(), userID)
	if err != nil {
		t.Fatalf("ByIDAnyStatus() error = %v", err)
	}

	if account.Status != user.StatusDeleted {
		t.Errorf("account status = %q, want deleted", account.Status)
	}

	_, _, _, err = deps.service.LogInExistingUser(t.Context(), userID, []string{session.MethodWebAuthn}, "203.0.113.5", "ua", "req-2", "")
	if !errors.Is(err, ErrSuspended) {
		t.Errorf("LogInExistingUser() error = %v, want ErrSuspended (a deleted account may not authenticate)", err)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM credentials WHERE id = $1`, credID); got != 1 {
		t.Errorf("credential rows = %d, want 1 (retained until the grace period elapses)", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM identities WHERE id = $1`, identityID); got != 1 {
		t.Errorf("identity rows = %d, want 1 (retained until the grace period elapses)", got)
	}
}

// TestRestoreAccount_WithinGracePeriod_Succeeds covers AC-008.52: a deleted
// account still within its grace period may be restored to active.
func TestRestoreAccount_WithinGracePeriod_Succeeds(t *testing.T) {
	t.Parallel()

	const grace = time.Hour

	deps := newAccountTestDeps(t, false, grace, nil)
	actorID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	subjectID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	if err := deps.service.DeleteAccount(t.Context(), subjectID, "203.0.113.5", "req-delete"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}

	// Advance partway into the grace period: RestoreAccount must compare
	// against now minus the grace period, not against now itself, or this
	// still-eligible restore would be refused.
	deps.clock.Advance(grace / 2)

	restored, err := deps.service.RestoreAccount(t.Context(), actorID, subjectID, "203.0.113.5", "req-restore")
	if err != nil {
		t.Fatalf("RestoreAccount() error = %v, want nil", err)
	}

	if restored.Status != user.StatusActive {
		t.Errorf("restored account status = %q, want active", restored.Status)
	}

	if got := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionUserRestored, "user:"+subjectID.String()); got != 1 {
		t.Errorf("user.restored audit rows = %d, want 1", got)
	}
}

// TestRestoreAccount_OutsideGracePeriod_ReturnsErrGraceExpired covers
// AC-008.51 and AC-008.52's negative side: restoration is refused once the
// account is old enough for the sweeper to purge.
func TestRestoreAccount_OutsideGracePeriod_ReturnsErrGraceExpired(t *testing.T) {
	t.Parallel()

	const grace = time.Minute

	deps := newAccountTestDeps(t, false, grace, nil)
	actorID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	subjectID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	if err := deps.service.DeleteAccount(t.Context(), subjectID, "203.0.113.5", "req-delete"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}

	deps.clock.Advance(2 * grace)

	_, err := deps.service.RestoreAccount(t.Context(), actorID, subjectID, "203.0.113.5", "req-restore")
	if !errors.Is(err, ErrGraceExpired) {
		t.Fatalf("RestoreAccount() error = %v, want ErrGraceExpired", err)
	}
}

// TestRestoreAccount_UnknownID_ReturnsErrGraceExpired covers AC-008.52: an
// unknown account identifier is refused identically to an expired one, so
// the route is not a probe for which accounts once existed.
func TestRestoreAccount_UnknownID_ReturnsErrGraceExpired(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	actorID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	_, err := deps.service.RestoreAccount(t.Context(), actorID, uuid.New(), "203.0.113.5", "req-restore")
	if !errors.Is(err, ErrGraceExpired) {
		t.Fatalf("RestoreAccount() error = %v, want ErrGraceExpired", err)
	}
}

// TestPurgeExpired_RemovesExpiredLeavesInWindowAndSurvivesAsActorRef covers
// AC-008.51 and AC-008.53: an account past its grace period is permanently
// removed while one still within it survives, and the user.purged audit
// event it recorded keeps naming the removed account by actor_ref even
// though the row the actor_id foreign key pointed to is gone.
func TestPurgeExpired_RemovesExpiredLeavesInWindowAndSurvivesAsActorRef(t *testing.T) {
	t.Parallel()

	const grace = time.Minute

	deps := newAccountTestDeps(t, false, grace, nil)
	t0 := deps.clock.Now()

	expired := newAccountUser(t, deps.handle, t0, false)
	if err := deps.users.SoftDelete(t.Context(), expired); err != nil {
		t.Fatalf("SoftDelete(expired) error = %v", err)
	}

	deps.clock.Advance(2 * grace)

	inWindow := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	if err := deps.users.SoftDelete(t.Context(), inWindow); err != nil {
		t.Fatalf("SoftDelete(inWindow) error = %v", err)
	}

	purged, err := deps.service.PurgeExpired(t.Context())
	if err != nil {
		t.Fatalf("PurgeExpired() error = %v", err)
	}

	if purged != 1 {
		t.Fatalf("PurgeExpired() = %d, want 1", purged)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM users WHERE id = $1`, expired); got != 0 {
		t.Errorf("expired account rows = %d, want 0", got)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM users WHERE id = $1`, inWindow); got != 1 {
		t.Errorf("in-window account rows = %d, want 1", got)
	}

	var actorIsNull bool

	var actorRef string

	err = deps.handle.Pool().QueryRow(t.Context(),
		`SELECT actor_id IS NULL, actor_ref FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionUserPurged, "user:"+expired.String(),
	).Scan(&actorIsNull, &actorRef)
	if err != nil {
		t.Fatalf("querying user.purged audit row: %v", err)
	}

	if !actorIsNull {
		t.Error("user.purged actor_id is not NULL after the account it named was removed")
	}

	if actorRef != "user:"+expired.String() {
		t.Errorf("user.purged actor_ref = %q, want %q (must survive the account's removal)", actorRef, "user:"+expired.String())
	}
}

// TestPurgeExpired_ZeroGracePeriod_PurgesImmediately covers AC-008.51's
// boundary: a zero grace period treats every deleted account as eligible as
// soon as any time has passed since deletion.
func TestPurgeExpired_ZeroGracePeriod_PurgesImmediately(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, 0, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	if err := deps.users.SoftDelete(t.Context(), userID); err != nil {
		t.Fatalf("SoftDelete() error = %v", err)
	}

	deps.clock.Advance(time.Minute)

	purged, err := deps.service.PurgeExpired(t.Context())
	if err != nil {
		t.Fatalf("PurgeExpired() error = %v", err)
	}

	if purged != 1 {
		t.Fatalf("PurgeExpired() = %d, want 1", purged)
	}
}

// TestSetStatus_SelfAction_Refuses covers the self-action refusal an
// administrator's own status change is subject to: an actor cannot suspend
// or reactivate itself through this path.
// Covers AC-008.47.
func TestSetStatus_SelfAction_Refuses(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	_, err := deps.service.SetStatus(t.Context(), userID, userID, user.StatusSuspended, "203.0.113.5", "req-1")
	if !errors.Is(err, ErrSelfAction) {
		t.Fatalf("SetStatus() error = %v, want ErrSelfAction", err)
	}
}

// TestSetStatus_LastAdmin_Refuses covers AC-008.50: suspending the sole
// active administrator is refused with ErrLastAdmin.
func TestSetStatus_LastAdmin_Refuses(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	actorID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	grantAccountAdmin(t, deps.roles, adminID)

	_, err := deps.service.SetStatus(t.Context(), actorID, adminID, user.StatusSuspended, "203.0.113.5", "req-1")
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("SetStatus() error = %v, want ErrLastAdmin", err)
	}

	account, err := deps.users.ByID(t.Context(), adminID)
	if err != nil {
		t.Fatalf("ByID() error = %v", err)
	}

	if account.Status != user.StatusActive {
		t.Errorf("account status = %q, want active (refusal must not suspend it)", account.Status)
	}
}

// TestSetStatus_Suspend_RevokesSessions covers AC-008.47: suspending an
// account revokes every session it holds.
func TestSetStatus_Suspend_RevokesSessions(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	actorID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	subjectID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	if _, _, err := deps.sessions.Issue(t.Context(), subjectID, "203.0.113.5", "ua", nil); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	updated, err := deps.service.SetStatus(t.Context(), actorID, subjectID, user.StatusSuspended, "203.0.113.5", "req-1")
	if err != nil {
		t.Fatalf("SetStatus() error = %v, want nil", err)
	}

	if updated.Status != user.StatusSuspended {
		t.Errorf("updated account status = %q, want suspended", updated.Status)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE user_id = $1`, subjectID); got != 0 {
		t.Errorf("session rows = %d, want 0 (revoked)", got)
	}
}

// TestSetStatus_Reactivate_RecordsAudit covers AC-008.47: reactivating a
// suspended account records user.reactivated.
func TestSetStatus_Reactivate_RecordsAudit(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	actorID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	subjectID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	if _, err := deps.users.SetStatus(t.Context(), subjectID, user.StatusSuspended); err != nil {
		t.Fatalf("SetStatus() setup error = %v", err)
	}

	updated, err := deps.service.SetStatus(t.Context(), actorID, subjectID, user.StatusActive, "203.0.113.5", "req-1")
	if err != nil {
		t.Fatalf("SetStatus() error = %v, want nil", err)
	}

	if updated.Status != user.StatusActive {
		t.Errorf("updated account status = %q, want active", updated.Status)
	}

	if got := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionUserReactivated, "user:"+subjectID.String()); got != 1 {
		t.Errorf("user.reactivated audit rows = %d, want 1", got)
	}
}

// TestStartIdentityLink_NilProviders_ReturnsErrUnknownProvider covers
// AC-008.43: with no OpenID Connect provider configured, StartIdentityLink
// refuses rather than panicking on a nil Providers.
func TestStartIdentityLink_NilProviders_ReturnsErrUnknownProvider(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	_, _, err := deps.service.StartIdentityLink(t.Context(), userID, "test")
	if !errors.Is(err, oidc.ErrUnknownProvider) {
		t.Fatalf("StartIdentityLink() error = %v, want oidc.ErrUnknownProvider", err)
	}
}

// TestFinishIdentityLink_NilProviders_ReturnsErrUnknownProvider is
// StartIdentityLink's nil-Providers case mirrored for FinishIdentityLink.
// Covers AC-008.43.
func TestFinishIdentityLink_NilProviders_ReturnsErrUnknownProvider(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	err := deps.service.FinishIdentityLink(t.Context(), userID, "test", "state", "code", "binding", "203.0.113.5", "req-1")
	if !errors.Is(err, oidc.ErrUnknownProvider) {
		t.Fatalf("FinishIdentityLink() error = %v, want oidc.ErrUnknownProvider", err)
	}
}

// newAccountLinkRegistry returns an oidc.Registry backed by h, the same
// handle the account Service under test uses, so a link ceremony's flow row
// and the account row it names live in the same database.
func newAccountLinkRegistry(t *testing.T, h *store.Handle, srv *httptest.Server) *oidc.Registry {
	t.Helper()

	flows := authflow.NewStore(h, time.Minute, time.Now)

	cfg := oidc.Config{
		PublicOrigin: "https://app.example",
		Providers: []oidc.ProviderConfig{
			{
				Key:          accountLinkProviderKey,
				Issuer:       srv.URL,
				ClientID:     accountLinkClientID,
				ClientSecret: secret.String(accountLinkClientSecret),
				Scopes:       []string{"profile"},
				DisplayName:  "Test Provider",
			},
		},
		ClockSkew: configtype.Duration(30 * time.Second),
	}

	registry, err := oidc.NewRegistry(cfg, flows, srv.Client(), zap.NewNop())
	if err != nil {
		t.Fatalf("oidc.NewRegistry() error = %v", err)
	}

	return registry
}

// linkedAccountDeps holds one account Service wired to a real oidc.Registry
// pointed at a fake identity provider, all backed by one database, for the
// identity-link tests that must drive a full ceremony end to end.
type linkedAccountDeps struct {
	accountTestDeps
	srv     *httptest.Server
	tokenEP *accountLinkTokenEndpoint
	priv    *rsa.PrivateKey
}

// newLinkedAccountDeps returns a linkedAccountDeps ready to drive a
// StartIdentityLink/FinishIdentityLink ceremony.
func newLinkedAccountDeps(t *testing.T) linkedAccountDeps {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newAccountLinkProviderServer(t, priv.Public())

	c := newClock()
	h := storetest.New(t)

	users := user.NewRepository(h, c.Now)
	sessions := session.NewStore(h, session.DefaultConfig(), c.Now)
	roles := authz.NewRepository(h, c.Now)
	checker := authz.NewChecker(roles)
	recorder := audit.NewRecorder(h, zap.NewNop(), c.Now)
	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), c.Now)
	credentials := passkey.NewRepository(h, c.Now)

	invites, err := invite.NewService(h, policy, testTokenBytes, zap.NewNop(), c.Now)
	if err != nil {
		t.Fatalf("invite.NewService() error = %v", err)
	}

	registry := newAccountLinkRegistry(t, h, srv)

	accountDeps := AccountDeps{
		Credentials: credentials,
		Providers:   registry,
	}

	svc := NewService(h, users, sessions, roles, checker, recorder, invites, policy, nil, zap.NewNop(), c.Now, accountDeps)

	return linkedAccountDeps{
		accountTestDeps{
			service:     svc,
			handle:      h,
			users:       users,
			roles:       roles,
			sessions:    sessions,
			credentials: credentials,
			recorder:    recorder,
			clock:       c,
		},
		srv,
		tokenEP,
		priv,
	}
}

// TestFinishIdentityLink_MatchingSession_Links covers AC-008.43: a link
// ceremony finished by the same session that started it attaches the
// identity to that account.
func TestFinishIdentityLink_MatchingSession_Links(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	authURL, binding, err := deps.service.StartIdentityLink(t.Context(), userID, accountLinkProviderKey)
	if err != nil {
		t.Fatalf("StartIdentityLink() error = %v", err)
	}

	nonce, state := parseAccountLinkAuthURL(t, authURL)

	claims := buildAccountLinkClaims(deps.srv.URL, "sub-matching", nonce, time.Now().Add(time.Hour))
	deps.tokenEP.setIDToken(oidctest.SignIDToken(deps.priv, accountLinkKeyID, goidc.RS256, claims))

	err = deps.service.FinishIdentityLink(t.Context(), userID, accountLinkProviderKey, state, "test-code", binding, "203.0.113.5", "req-1")
	if err != nil {
		t.Fatalf("FinishIdentityLink() error = %v, want nil", err)
	}

	linkedUser, _, err := deps.users.ByIdentity(t.Context(), accountLinkProviderKey, "sub-matching")
	if err != nil {
		t.Fatalf("ByIdentity() error = %v, want nil", err)
	}

	if linkedUser.ID != userID {
		t.Fatalf("ByIdentity() user.ID = %v, want %v", linkedUser.ID, userID)
	}
}

// TestFinishIdentityLink_MismatchedSession_RefusesNothingLinked covers
// amendment C's inverted case: a link ceremony finished under a session
// other than the one that started it is refused with ErrLinkFlowMismatch,
// and no identity row is created for either account.
// Covers AC-008.43.
func TestFinishIdentityLink_MismatchedSession_RefusesNothingLinked(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	starter := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	other := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	authURL, binding, err := deps.service.StartIdentityLink(t.Context(), starter, accountLinkProviderKey)
	if err != nil {
		t.Fatalf("StartIdentityLink() error = %v", err)
	}

	nonce, state := parseAccountLinkAuthURL(t, authURL)

	claims := buildAccountLinkClaims(deps.srv.URL, "sub-mismatched", nonce, time.Now().Add(time.Hour))
	deps.tokenEP.setIDToken(oidctest.SignIDToken(deps.priv, accountLinkKeyID, goidc.RS256, claims))

	err = deps.service.FinishIdentityLink(t.Context(), other, accountLinkProviderKey, state, "test-code", binding, "203.0.113.5", "req-1")
	if !errors.Is(err, ErrLinkFlowMismatch) {
		t.Fatalf("FinishIdentityLink() error = %v, want ErrLinkFlowMismatch", err)
	}

	if got := countRows(t, deps.handle,
		`SELECT count(*) FROM identities WHERE provider = $1 AND subject = $2`,
		accountLinkProviderKey, "sub-mismatched"); got != 0 {
		t.Errorf("identity rows = %d, want 0 (a session mismatch must link nothing)", got)
	}
}

// TestFinishIdentityLink_LoginKindFlow_Refused covers AC-008.43: a state
// issued by a login ceremony (Start, not StartLink) cannot be finished
// through FinishIdentityLink.
func TestFinishIdentityLink_LoginKindFlow_Refused(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	authURL, binding, err := deps.service.accounts.Providers.Start(t.Context(), accountLinkProviderKey, uuid.NullUUID{})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	nonce, state := parseAccountLinkAuthURL(t, authURL)

	claims := buildAccountLinkClaims(deps.srv.URL, "sub-login-kind", nonce, time.Now().Add(time.Hour))
	deps.tokenEP.setIDToken(oidctest.SignIDToken(deps.priv, accountLinkKeyID, goidc.RS256, claims))

	err = deps.service.FinishIdentityLink(t.Context(), userID, accountLinkProviderKey, state, "test-code", binding, "203.0.113.5", "req-1")
	if err == nil {
		t.Fatal("FinishIdentityLink() error = nil, want an error refusing a login-kind flow")
	}
}

// TestFinishIdentityLink_IdentityOwnedByAnotherAccount_RefusesNothingLinked
// covers AC-008.43: an identity already linked to a different account
// refuses with the wrapped user.ErrIdentityLinked, and that account's link
// survives.
func TestFinishIdentityLink_IdentityOwnedByAnotherAccount_RefusesNothingLinked(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	owner := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	claimant := newAccountUser(t, deps.handle, deps.clock.Now(), false)

	newAccountIdentity(t, deps.users, owner, accountLinkProviderKey, "sub-owned-elsewhere")

	authURL, binding, err := deps.service.StartIdentityLink(t.Context(), claimant, accountLinkProviderKey)
	if err != nil {
		t.Fatalf("StartIdentityLink() error = %v", err)
	}

	nonce, state := parseAccountLinkAuthURL(t, authURL)

	claims := buildAccountLinkClaims(deps.srv.URL, "sub-owned-elsewhere", nonce, time.Now().Add(time.Hour))
	deps.tokenEP.setIDToken(oidctest.SignIDToken(deps.priv, accountLinkKeyID, goidc.RS256, claims))

	err = deps.service.FinishIdentityLink(t.Context(), claimant, accountLinkProviderKey, state, "test-code", binding, "203.0.113.5", "req-1")
	if !errors.Is(err, user.ErrIdentityLinked) {
		t.Fatalf("FinishIdentityLink() error = %v, want wrapped user.ErrIdentityLinked", err)
	}

	linkedUser, _, err := deps.users.ByIdentity(t.Context(), accountLinkProviderKey, "sub-owned-elsewhere")
	if err != nil {
		t.Fatalf("ByIdentity() error = %v", err)
	}

	if linkedUser.ID != owner {
		t.Fatalf("ByIdentity() user.ID = %v, want %v (the original owner's link must survive)", linkedUser.ID, owner)
	}
}

// accountLinkTokenEndpoint is a minimal http.Handler standing in for a
// provider's token endpoint: it always returns the identity token most
// recently set on it, ignoring the PKCE and client-credential checks the
// oidc package's own tests already cover in full.
type accountLinkTokenEndpoint struct {
	mu      sync.Mutex
	idToken string
}

// setIDToken replaces the identity token the next token exchange returns.
func (e *accountLinkTokenEndpoint) setIDToken(token string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.idToken = token
}

// ServeHTTP implements http.Handler, always returning a token response
// carrying the currently configured identity token.
func (e *accountLinkTokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	e.mu.Lock()
	idToken := e.idToken
	e.mu.Unlock()

	body, err := json.Marshal(map[string]any{
		"access_token": "test-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	if _, writeErr := w.Write(body); writeErr != nil {
		return
	}
}

// newAccountLinkProviderServer starts a fake identity provider serving
// discovery, a JWKS advertising pub under accountLinkKeyID, and a token
// endpoint whose response is controlled by the returned
// accountLinkTokenEndpoint.
func newAccountLinkProviderServer(t *testing.T, pub any) (*httptest.Server, *accountLinkTokenEndpoint) {
	t.Helper()

	discovery := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: pub, KeyID: accountLinkKeyID, Algorithm: goidc.RS256},
		},
	}

	tokenEP := &accountLinkTokenEndpoint{}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", discovery)
	mux.Handle("/keys", discovery)
	mux.Handle("/token", tokenEP)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	discovery.SetIssuer(srv.URL)

	return srv, tokenEP
}

// parseAccountLinkAuthURL extracts the nonce and state query parameters
// StartIdentityLink's authorization URL carries.
func parseAccountLinkAuthURL(t *testing.T, authURL string) (string, string) {
	t.Helper()

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parsing authorization URL: %v", err)
	}

	query := parsed.Query()

	return query.Get("nonce"), query.Get("state")
}

// buildAccountLinkClaims renders a raw identity token claims payload for the
// fake provider to sign and return.
func buildAccountLinkClaims(issuer, subject, nonce string, exp time.Time) string {
	return fmt.Sprintf(`{
		"iss": %q,
		"aud": %q,
		"sub": %q,
		"nonce": %q,
		"exp": %d,
		"email": "linked@example.com",
		"email_verified": true,
		"name": "Linked Identity"
	}`, issuer, accountLinkClientID, subject, nonce, exp.Unix())
}

// TestConcurrentDemotionsOfTheLastTwoAdminsLeaveOne covers AC-008.50: with
// exactly two active administrators, two concurrent ReplaceRoles calls that
// each remove admin from a different one of them cannot both succeed.
// Exactly one is applied, the other is refused with ErrLastAdmin, and one
// active administrator remains, whichever goroutine runs first.
func TestConcurrentDemotionsOfTheLastTwoAdminsLeaveOne(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	actorID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	adminA := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	adminB := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	grantAccountAdmin(t, deps.roles, adminA)
	grantAccountAdmin(t, deps.roles, adminB)

	targets := []uuid.UUID{adminA, adminB}
	results := make([]error, len(targets))
	start := make(chan struct{})

	var wg sync.WaitGroup

	for i, target := range targets {
		wg.Go(func() {
			<-start

			_, results[i] = deps.service.ReplaceRoles(t.Context(), actorID, target, []string{authz.RoleMember})
		})
	}

	close(start)
	wg.Wait()

	successes := 0
	refusals := 0

	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrLastAdmin):
			refusals++
		default:
			t.Fatalf("ReplaceRoles() unexpected error = %v", err)
		}
	}

	if successes != 1 || refusals != 1 {
		t.Fatalf("got %d successes and %d ErrLastAdmin refusals, want exactly 1 of each", successes, refusals)
	}

	activeAdmins, err := deps.users.CountActiveAdmins(t.Context(), authz.RoleAdmin)
	if err != nil {
		t.Fatalf("CountActiveAdmins() error = %v", err)
	}

	if activeAdmins != 1 {
		t.Fatalf("active admins after concurrent demotions = %d, want 1", activeAdmins)
	}
}
