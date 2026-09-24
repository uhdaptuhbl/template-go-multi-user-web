//go:build integration

package auth

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// armedClock returns a fixed base time until armed, after which its next
// jumpAfter calls still return base and every call after that returns base
// advanced by jumpBy. It exists to engineer, deterministically and without
// sleeping, the one timing window Postgres' row locking otherwise makes
// unreachable: a token still live when signup admission rule 5 (design.md's
// "Signup admission path") validates it but expired by the time rule 8
// redeems it a moment later in the same transaction.
type armedClock struct {
	mu        sync.Mutex
	base      time.Time
	armed     bool
	calls     int
	jumpAfter int
	jumpBy    time.Duration
}

// Now returns base until Arm is called, and afterward returns base for the
// first jumpAfter calls and base.Add(jumpBy) for every call after that.
func (c *armedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.armed {
		return c.base
	}

	c.calls++
	if c.calls > c.jumpAfter {
		return c.base.Add(c.jumpBy)
	}

	return c.base
}

// Arm switches Now into its counting mode: the next jumpAfter calls still
// return base, and every call after that jumps forward by jumpBy.
func (c *armedClock) Arm(jumpAfter int, jumpBy time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.armed = true
	c.calls = 0
	c.jumpAfter = jumpAfter
	c.jumpBy = jumpBy
}

// rowCounts is a snapshot of every table the signup admission rules write
// to, so a refusal can be shown to have changed none of them rather than
// merely to have left one particular identity unclaimed.
type rowCounts struct {
	users             int
	identities        int
	sessions          int
	inviteRedemptions int
}

// snapshotRowCounts reads the current row count of every table rowCounts
// tracks.
func snapshotRowCounts(t *testing.T, deps testDeps) rowCounts {
	t.Helper()

	return rowCounts{
		users:             countRows(t, deps.handle, `SELECT count(*) FROM users`),
		identities:        countRows(t, deps.handle, `SELECT count(*) FROM identities`),
		sessions:          countRows(t, deps.handle, `SELECT count(*) FROM sessions`),
		inviteRedemptions: countRows(t, deps.handle, `SELECT count(*) FROM invite_redemptions`),
	}
}

// assertRowCountsUnchanged fails the test unless every table rowCounts
// tracks holds exactly as many rows as it did in before.
func assertRowCountsUnchanged(t *testing.T, deps testDeps, before rowCounts) {
	t.Helper()

	after := snapshotRowCounts(t, deps)
	if after != before {
		t.Fatalf("row counts changed on a refused signup: before = %+v, after = %+v", before, after)
	}
}

// newAuthenticated returns an Authenticated whose Provider and Subject are
// unique to this call, for tests that need a fresh identity per case.
func newAuthenticated(t *testing.T) Authenticated {
	t.Helper()

	id := uuid.NewString()

	return Authenticated{
		Provider:    "https://issuer.example",
		Subject:     "sub-" + id,
		DisplayName: "Test User",
		Methods:     []string{session.MethodOIDC},
	}
}

// AC-008.55, AC-008.60: signup disabled refuses admission, leaving zero rows in users
// and identities, and records signup.blocked with the refusing rule.
func TestAdmitAccount_SignupDisabled(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(false)})

	in := newAuthenticated(t)
	// An asserted but unverified address: the subject must still name the
	// provider, so an address nobody verified never reaches the audit log.
	in.Email = "unverified.subject@example.com"
	in.EmailVerified = false

	before := snapshotRowCounts(t, deps)

	_, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if !errors.Is(err, ErrSignupDisabled) {
		t.Fatalf("LogIn() error = %v, want ErrSignupDisabled", err)
	}

	assertRowCountsUnchanged(t, deps, before)
	assertSignupBlockedRule(t, deps, blockedRuleSignupDisabled)
	assertSignupBlockedSubject(t, deps, "provider:"+in.Provider)
}

// TestAdmitAccount_SignupBlockedSubject_VerifiedEmailUsesEmailSubject: when
// the issuer asserted a verified address, signup.blocked's subject names
// that address rather than the provider, the other half of the pair
// TestAdmitAccount_SignupDisabled proves.
// Covers AC-008.60.
func TestAdmitAccount_SignupBlockedSubject_VerifiedEmailUsesEmailSubject(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(false)})

	in := newAuthenticated(t)
	in.Email = "Blocked.Subject@Example.com"
	in.EmailVerified = true

	_, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if !errors.Is(err, ErrSignupDisabled) {
		t.Fatalf("LogIn() error = %v, want ErrSignupDisabled", err)
	}

	assertSignupBlockedSubject(t, deps, "email:blocked.subject@example.com")
}

// AC-008.56: an invite required with none carried refuses admission with
// ErrInviteRequired, leaving zero rows in users and identities.
func TestAdmitAccount_InviteRequired_NoInviteCarried(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	in := newAuthenticated(t)

	before := snapshotRowCounts(t, deps)

	_, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if !errors.Is(err, ErrInviteRequired) {
		t.Fatalf("LogIn() error = %v, want ErrInviteRequired", err)
	}

	assertRowCountsUnchanged(t, deps, before)
	assertSignupBlockedRule(t, deps, blockedRuleInviteRequired)
}

// AC-008.60: an input that violates both signup_disabled and
// invite_required is refused by the earlier rule, signup_disabled, proving
// the signup admission rules are evaluated in order rather than in some
// other sequence that would report invite_required instead.
func TestAdmitAccount_OrderedRules_SignupDisabledBeforeInviteRequired(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(false), SignupRequireInvite: new(true)})

	in := newAuthenticated(t)

	before := snapshotRowCounts(t, deps)

	_, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if !errors.Is(err, ErrSignupDisabled) {
		t.Fatalf("LogIn() error = %v, want ErrSignupDisabled (the earlier rule), got %v", ErrSignupDisabled, err)
	}

	if errors.Is(err, ErrInviteRequired) {
		t.Fatalf("LogIn() error also matches ErrInviteRequired; the earlier rule must be the only one reported")
	}

	assertRowCountsUnchanged(t, deps, before)
	assertSignupBlockedRule(t, deps, blockedRuleSignupDisabled)
}

// TestAdmitAccount_Rule7Failure_LeavesNoRowsAndWritesNoSignupBlocked: a
// failure during signup admission rule 7 (creating the account, its
// identity, and its member grant) is a failure, not a refusal. It must roll
// back every row, must not be reported as ErrInviteInvalid, and must write no
// signup.blocked row, because nothing about admission policy refused this
// signup: the database simply could not perform the grant.
//
// The failure is manufactured deterministically by deleting the "member"
// role row from this test's own throwaway database before calling LogIn, so
// GrantRoleTx fails with authz.ErrUnknownRole after CreateWithIdentityTx has
// already written the account and identity rows within the same
// transaction.
// Covers AC-008.60 and AC-008.61.
func TestAdmitAccount_Rule7Failure_LeavesNoRowsAndWritesNoSignupBlocked(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	if _, err := deps.handle.Pool().Exec(t.Context(), `DELETE FROM roles WHERE name = 'member'`); err != nil {
		t.Fatalf("deleting member role: %v", err)
	}

	in := newAuthenticated(t)

	before := snapshotRowCounts(t, deps)

	_, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err == nil {
		t.Fatal("LogIn() error = nil, want a rule 7 failure")
	}

	if errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("LogIn() error = %v, must not be ErrInviteInvalid: this is a failure, not a refusal", err)
	}

	assertRowCountsUnchanged(t, deps, before)

	blockedCount := countRows(t, deps.handle, `SELECT count(*) FROM audit_events WHERE action = 'signup.blocked'`)
	if blockedCount != 0 {
		t.Fatalf("signup.blocked row count = %d, want 0: a rule 7 failure is not a refusal", blockedCount)
	}
}

// AC-008.56, AC-008.57: an expired, a revoked, and a fully spent invite each
// return ErrInviteInvalid, indistinguishably. This test additionally
// requires the three returned errors to carry identical .Error() text and the
// three signup.blocked rows to carry identical detail, since a caller must
// not be able to distinguish the three variants by any observable means.
func TestAdmitAccount_InviteInvalid_Variants(t *testing.T) {
	t.Parallel()

	errorTexts := make(map[string]string)
	details := make(map[string]string)

	tests := []struct {
		name  string
		setup func(t *testing.T, deps testDeps, issuer uuid.UUID) uuid.UUID
	}{
		{
			name: "expired",
			setup: func(t *testing.T, deps testDeps, issuer uuid.UUID) uuid.UUID {
				t.Helper()

				issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1, TTL: time.Second})
				if err != nil {
					t.Fatalf("Create() error = %v", err)
				}

				deps.clock.Advance(2 * time.Second)

				return issued.Invite.ID
			},
		},
		{
			name: "revoked",
			setup: func(t *testing.T, deps testDeps, issuer uuid.UUID) uuid.UUID {
				t.Helper()

				issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1})
				if err != nil {
					t.Fatalf("Create() error = %v", err)
				}

				if _, revokeErr := deps.invites.Revoke(t.Context(), issued.Invite.ID, issuer, false); revokeErr != nil {
					t.Fatalf("Revoke() error = %v", revokeErr)
				}

				return issued.Invite.ID
			},
		},
		{
			name: "spent",
			setup: func(t *testing.T, deps testDeps, issuer uuid.UUID) uuid.UUID {
				t.Helper()

				issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1})
				if err != nil {
					t.Fatalf("Create() error = %v", err)
				}

				spender := newAuthenticated(t)
				spender.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

				setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

				if _, _, _, logInErr := deps.service.LogIn(t.Context(), spender, "203.0.113.5", "test-agent", "req-spend", ""); logInErr != nil {
					t.Fatalf("LogIn() spending invite error = %v", logInErr)
				}

				return issued.Invite.ID
			},
		},
	}

	for _, tc := range tests {
		// Deliberately not t.Parallel() here: this test compares each
		// variant's error text and signup.blocked detail across all three
		// cases after the loop, which needs them collected before it can
		// run rather than racing sibling subtests for the same map.
		t.Run(tc.name, func(t *testing.T) {
			deps := newTestService(t, nil)
			setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

			issuer := createTestAdmin(t, deps)
			inviteID := tc.setup(t, deps, issuer)

			in := newAuthenticated(t)
			in.InviteID = uuid.NullUUID{UUID: inviteID, Valid: true}

			before := snapshotRowCounts(t, deps)

			_, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
			if !errors.Is(err, ErrInviteInvalid) {
				t.Fatalf("LogIn() error = %v, want ErrInviteInvalid", err)
			}

			assertRowCountsUnchanged(t, deps, before)
			// Each variant's refusal names the invite_invalid rule.
			assertSignupBlockedRule(t, deps, blockedRuleInviteInvalid)

			errorTexts[tc.name] = err.Error()

			var detail string

			if scanErr := deps.handle.Pool().QueryRow(t.Context(),
				`SELECT detail::text FROM audit_events WHERE action = 'signup.blocked'`,
			).Scan(&detail); scanErr != nil {
				t.Fatalf("querying signup.blocked detail: %v", scanErr)
			}

			details[tc.name] = detail
		})
	}

	// The three variants must be indistinguishable by error text or by the
	// detail their signup.blocked row carries.
	var wantText, wantDetail string

	for _, tc := range tests {
		gotText, gotDetail := errorTexts[tc.name], details[tc.name]

		if wantText == "" {
			wantText, wantDetail = gotText, gotDetail

			continue
		}

		if gotText != wantText {
			t.Fatalf("variant %q error text = %q, want %q (same as the other variants)", tc.name, gotText, wantText)
		}

		if gotDetail != wantDetail {
			t.Fatalf("variant %q signup.blocked detail = %q, want %q (same as the other variants)", tc.name, gotDetail, wantDetail)
		}
	}
}

// AC-008.58: an invite bound to an address with EmailVerified false returns
// ErrInviteEmailMismatch, while the same invite with that address verified
// succeeds.
func TestAdmitAccount_InviteEmailBinding(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuer := createTestAdmin(t, deps)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{Email: "bound@example.com", MaxUses: 2})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	unverified := newAuthenticated(t)
	unverified.Email = "bound@example.com"
	unverified.EmailVerified = false
	unverified.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	_, _, _, err = deps.service.LogIn(t.Context(), unverified, "203.0.113.5", "test-agent", "req-1", "")
	if !errors.Is(err, ErrInviteEmailMismatch) {
		t.Fatalf("LogIn() unverified error = %v, want ErrInviteEmailMismatch", err)
	}

	assertZeroAccountRows(t, deps, unverified)
	// The refusal names its rule.
	assertSignupBlockedRule(t, deps, blockedRuleInviteEmailMismatch)

	verified := newAuthenticated(t)
	verified.Email = "bound@example.com"
	verified.EmailVerified = true
	verified.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	created, _, _, err := deps.service.LogIn(t.Context(), verified, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogIn() verified error = %v", err)
	}

	if created.Email == nil || *created.Email != "bound@example.com" {
		t.Fatalf("created account Email = %v, want bound@example.com", created.Email)
	}

	// An invite-admitted account's user.created names "invite", and its
	// invite.redeemed row records success against the invite.
	assertUserCreatedDetail(t, deps, created.ID, admittedByInvite)

	var redeemedOutcome string

	if scanErr := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT outcome::text FROM audit_events WHERE action = 'invite.redeemed' AND subject = $1`,
		"invite:"+issued.Invite.ID.String(),
	).Scan(&redeemedOutcome); scanErr != nil {
		t.Fatalf("querying invite.redeemed row: %v", scanErr)
	}

	if redeemedOutcome != string(audit.OutcomeSuccess) {
		t.Fatalf("invite.redeemed outcome = %q, want %q", redeemedOutcome, audit.OutcomeSuccess)
	}
}

// AC-008.71, AC-008.73: signup_require_approval creates the account pending,
// returns ErrApprovalPending, and leaves zero rows in sessions; the same
// account authenticates normally once active.
func TestAdmitAccount_RequireApproval(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{
		SignupEnabled:         new(true),
		SignupRequireInvite:   new(false),
		SignupRequireApproval: new(true),
	})

	in := newAuthenticated(t)

	_, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if !errors.Is(err, ErrApprovalPending) {
		t.Fatalf("LogIn() error = %v, want ErrApprovalPending", err)
	}

	created, _, err := deps.users.ByIdentity(t.Context(), in.Provider, in.Subject)
	if err != nil {
		t.Fatalf("ByIdentity() error = %v", err)
	}

	if created.Status != user.StatusPending {
		t.Fatalf("account Status = %v, want %v", created.Status, user.StatusPending)
	}

	sessionCount := countRows(t, deps.handle, `SELECT count(*) FROM sessions WHERE user_id = $1`, created.ID)
	if sessionCount != 0 {
		t.Fatalf("sessions row count for pending account = %d, want 0", sessionCount)
	}

	if _, approveErr := deps.users.Approve(t.Context(), created.ID); approveErr != nil {
		t.Fatalf("Approve() error = %v", approveErr)
	}

	activated, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogIn() after approval error = %v", err)
	}

	if activated.ID != created.ID {
		t.Fatalf("LogIn() after approval resolved a different account: got %v, want %v", activated.ID, created.ID)
	}
}

// AC-008.59: a bootstrap-list address with a verified email succeeds while
// signup is disabled and an invite is required, which is the deadlock case
// the exemption exists to break.
func TestAdmitAccount_BootstrapExemption_BreaksDeadlock(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"root@example.com"})
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(false), SignupRequireInvite: new(true)})

	in := newAuthenticated(t)
	in.Email = "root@example.com"
	in.EmailVerified = true

	created, _, token, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	if token == "" {
		t.Fatal("LogIn() returned an empty token for the bootstrap admin")
	}

	if created.Status != user.StatusActive {
		t.Fatalf("bootstrap account Status = %v, want %v", created.Status, user.StatusActive)
	}

	assertUserCreatedDetail(t, deps, created.ID, admittedByBootstrap)
}

// TestAdmitAccount_BootstrapExemption_RequiresVerifiedAddress: an UNVERIFIED
// bootstrap-list address never receives rule 1's exemption, so it is
// refused exactly like any other signup attempted while signup is
// disabled, and creates nothing.
// Covers AC-008.59.
func TestAdmitAccount_BootstrapExemption_RequiresVerifiedAddress(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"root@example.com"})
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(false)})

	in := newAuthenticated(t)
	in.Email = "root@example.com"
	in.EmailVerified = false

	before := snapshotRowCounts(t, deps)

	_, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if !errors.Is(err, ErrSignupDisabled) {
		t.Fatalf("LogIn() error = %v, want ErrSignupDisabled", err)
	}

	assertRowCountsUnchanged(t, deps, before)
}

// TestAdmitAccount_BootstrapExemption_RequiresSettledAddress: rule 1 checks
// the settled address, not merely the asserted one. A verified
// bootstrap-list address that an existing account already holds must not
// receive the exemption: the settled address is nil (a collision), so the
// signup goes through rules 2 through 9 like anyone else's and is refused by
// signup_disabled instead of silently succeeding through rule 1.
// Covers AC-008.59.
func TestAdmitAccount_BootstrapExemption_RequiresSettledAddress(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"root@example.com"})
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	holder := newAuthenticated(t)
	holder.Email = "root@example.com"
	holder.EmailVerified = true

	if _, _, _, err := deps.service.LogIn(t.Context(), holder, "203.0.113.5", "test-agent", "req-holder", ""); err != nil {
		t.Fatalf("LogIn() seeding existing holder error = %v", err)
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(false)})

	claimant := newAuthenticated(t)
	claimant.Email = "root@example.com"
	claimant.EmailVerified = true

	before := snapshotRowCounts(t, deps)

	_, _, _, err := deps.service.LogIn(t.Context(), claimant, "203.0.113.5", "test-agent", "req-claimant", "")
	if !errors.Is(err, ErrSignupDisabled) {
		t.Fatalf("LogIn() error = %v, want ErrSignupDisabled (rule 1 must not have exempted this signup)", err)
	}

	assertRowCountsUnchanged(t, deps, before)
}

// TestAdmitAccount_WhitespaceAndCaseNormalizedBeforeCollisionCheck: a
// verified email with surrounding whitespace and mixed case that
// matches an existing account's address, once normalized, is treated as a
// collision and the new account carries a NULL email, exactly as an
// already-lowercased exact match would be.
// Covers AC-008.9.
func TestAdmitAccount_WhitespaceAndCaseNormalizedBeforeCollisionCheck(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	first := newAuthenticated(t)
	first.Email = "normalize@example.com"
	first.EmailVerified = true

	if _, _, _, err := deps.service.LogIn(t.Context(), first, "203.0.113.5", "test-agent", "req-1", ""); err != nil {
		t.Fatalf("LogIn() seeding first account error = %v", err)
	}

	second := newAuthenticated(t)
	second.Email = "  Normalize@Example.COM  "
	second.EmailVerified = true

	created, _, _, err := deps.service.LogIn(t.Context(), second, "203.0.113.5", "test-agent", "req-2", "")
	if err != nil {
		t.Fatalf("LogIn() second account error = %v", err)
	}

	if created.Email != nil {
		t.Fatalf("second account Email = %v, want nil (whitespace/case-normalized collision)", *created.Email)
	}

	// An unattributed, open signup's user.created names "open".
	assertUserCreatedDetail(t, deps, created.ID, admittedByOpen)
}

// TestAdmitAccount_ConcurrentRedemption_SingleUseInvite_ConditionalUpdateSerializes
// covers AC-008.65 and AC-008.69: a single-use invite redeemed concurrently from
// two goroutines yields exactly one account and exactly one
// invite_redemptions row. This does not, by itself, prove ValidateTx's FOR
// UPDATE row lock is what serializes the two attempts: RedeemTx's own
// conditional UPDATE (`WHERE ... uses < max_uses`) alone is sufficient to
// produce this outcome, since only one of two concurrent UPDATEs can win the
// row and see uses still below max_uses. Renamed from
// TestAdmitAccount_ConcurrentRedemption_SingleUseInvite, which claimed more
// than this test demonstrates.
func TestAdmitAccount_ConcurrentRedemption_SingleUseInvite_ConditionalUpdateSerializes(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuer := createTestAdmin(t, deps)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	first := newAuthenticated(t)
	first.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	second := newAuthenticated(t)
	second.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	// A start barrier, closed only once both goroutines have reached it, so
	// the two LogIn calls race each other rather than one racing ahead while
	// the other is still being scheduled.
	ready := make(chan struct{})

	var readyCount atomic.Int32

	results := make(chan error, 2)

	var wg sync.WaitGroup

	wg.Go(func() {
		if readyCount.Add(1) == 2 {
			close(ready)
		}

		<-ready

		_, _, _, loginErr := deps.service.LogIn(t.Context(), first, "203.0.113.5", "test-agent", "req-a", "")
		results <- loginErr
	})

	wg.Go(func() {
		if readyCount.Add(1) == 2 {
			close(ready)
		}

		<-ready

		_, _, _, loginErr := deps.service.LogIn(t.Context(), second, "203.0.113.5", "test-agent", "req-b", "")
		results <- loginErr
	})

	wg.Wait()
	close(results)

	successes := 0

	for loginErr := range results {
		switch {
		case loginErr == nil:
			successes++
		case errors.Is(loginErr, ErrInviteInvalid):
			if loginErr.Error() != ErrInviteInvalid.Error() {
				t.Fatalf("concurrent LogIn() losing error = %q, want exactly %q", loginErr.Error(), ErrInviteInvalid.Error())
			}
		default:
			t.Fatalf("concurrent LogIn() error = %v, want nil or ErrInviteInvalid", loginErr)
		}
	}

	if successes != 1 {
		t.Fatalf("successful concurrent signups = %d, want 1", successes)
	}

	userCount := countRows(t, deps.handle, `SELECT count(*) FROM identities WHERE provider = $1 AND subject = ANY($2)`,
		first.Provider, []string{first.Subject, second.Subject})
	if userCount != 1 {
		t.Fatalf("identities row count across both attempts = %d, want 1", userCount)
	}

	redemptionCount := countRows(t, deps.handle, `SELECT count(*) FROM invite_redemptions WHERE invite_id = $1`, issued.Invite.ID)
	if redemptionCount != 1 {
		t.Fatalf("invite_redemptions row count = %d, want 1", redemptionCount)
	}
}

// AC-008.57: a dead invite carried while signup_require_invite is false
// still creates the account and records invite.redeemed with outcome
// failure, rather than blocking the signup.
func TestAdmitAccount_DeadInvite_NotRequired_StillCreatesAccount(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuer := createTestAdmin(t, deps)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1, TTL: time.Second})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	deps.clock.Advance(2 * time.Second)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	in := newAuthenticated(t)
	in.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	if created.ID == uuid.Nil {
		t.Fatal("LogIn() did not create an account for the dead-invite, invite-not-required case")
	}

	var outcome string

	if queryRowErr := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT outcome FROM audit_events WHERE action = 'invite.redeemed' AND subject = $1`,
		"invite:"+issued.Invite.ID.String(),
	).Scan(&outcome); queryRowErr != nil {
		t.Fatalf("querying invite.redeemed audit row: %v", queryRowErr)
	}

	if outcome != "failure" {
		t.Fatalf("invite.redeemed outcome = %q, want failure", outcome)
	}

	usesCount := countRows(t, deps.handle, `SELECT uses FROM invites WHERE id = $1`, issued.Invite.ID)
	if usesCount != 0 {
		t.Fatalf("invite uses = %d, want 0 (unattributed signup must not spend a use)", usesCount)
	}
}

// AC-008.54: an invite carried by an authentication whose identity already
// resolves is ignored: it is never validated or spent.
func TestAdmitAccount_InviteIgnoredForExistingIdentity(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	in := newAuthenticated(t)

	created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if err != nil {
		t.Fatalf("LogIn() creating account error = %v", err)
	}

	issued, err := deps.invites.Create(t.Context(), created.ID, "user:"+created.ID.String(), true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	in.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	if _, _, _, logInErr := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-2", ""); logInErr != nil {
		t.Fatalf("LogIn() second call error = %v", logInErr)
	}

	uses := countRows(t, deps.handle, `SELECT uses FROM invites WHERE id = $1`, issued.Invite.ID)
	if uses != 0 {
		t.Fatalf("invite uses = %d, want 0 (an existing identity's login must not spend it)", uses)
	}
}

// AC-008.54: the signup policy decides whether an authentication may create
// an account only at account creation, so an authentication that already
// resolves to an existing active identity logs in under any restrictive
// policy without that policy being applied to it.
func TestLogIn_ExistingIdentity_IgnoresSignupPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]settings.Update{
		"signup disabled": {SignupEnabled: new(false)},
		"invite required, none presented": {
			SignupEnabled:       new(true),
			SignupRequireInvite: new(true),
		},
		"approval required": {
			SignupEnabled:         new(true),
			SignupRequireApproval: new(true),
		},
	}

	for name, restrictivePolicy := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			deps := newTestService(t, nil)
			setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false), SignupRequireApproval: new(false)})

			in := newAuthenticated(t)

			created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
			if err != nil {
				t.Fatalf("LogIn() creating account error = %v", err)
			}

			before := snapshotRowCounts(t, deps)

			setSignupPolicy(t, deps.policy, restrictivePolicy)

			again, _, token, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-2", "")
			if err != nil {
				t.Fatalf("LogIn() second call error = %v, want nil", err)
			}

			if token == "" {
				t.Fatal("LogIn() returned an empty session token")
			}

			if again.ID != created.ID {
				t.Fatalf("LogIn() second call resolved to a different account: got %v, want %v", again.ID, created.ID)
			}

			if again.Status != user.StatusActive {
				t.Fatalf("LogIn() second call account status = %q, want %q", again.Status, user.StatusActive)
			}

			after := snapshotRowCounts(t, deps)
			if after.users != before.users || after.identities != before.identities {
				t.Fatalf("row counts changed on an existing identity's login: before = %+v, after = %+v", before, after)
			}

			blocked := countRows(t, deps.handle, `SELECT count(*) FROM audit_events WHERE action = 'signup.blocked'`)
			if blocked != 0 {
				t.Fatalf("signup.blocked rows = %d, want 0", blocked)
			}
		})
	}
}

// This is the primary obligation test: it proves that admitAccount itself,
// reached only through the public LogIn entry point, rolls back its own
// transaction when RedeemTx fails after Create already wrote the account and
// identity rows, so a dead token can never leave a live account behind.
//
// ValidateTx's row lock makes this sequence unreachable through any
// interleaving of two real callers, which is exactly what
// TestAdmitAccount_ConcurrentRedemption_SingleUseInvite demonstrates: the
// loser is always refused at rule 5, before Create ever runs. To exercise
// rule 8's own failure branch honestly, this test manufactures the one
// timing window Postgres' locking otherwise closes: a token still live when
// rule 5 validates it, expired by the time rule 8's RedeemTx re-reads it a
// moment later in the same transaction. It fakes only the clock, which is a
// process boundary this project's testing standard permits faking; every
// other collaborator, including the token's own row lock, is real.
// Covers AC-008.61 and AC-008.65.
func TestLogIn_RedeemFailureAfterValidate_RollsBackAccount(t *testing.T) {
	t.Parallel()

	baseClock := newClock()
	h := storetest.New(t)

	users := user.NewRepository(h, baseClock.Now)
	sessions := session.NewStore(h, session.DefaultConfig(), baseClock.Now)
	roles := authz.NewRepository(h, baseClock.Now)
	checker := authz.NewChecker(roles)
	recorder := audit.NewRecorder(h, zap.NewNop(), baseClock.Now)
	policy := settings.NewStore(h, settings.Options{}, zap.NewNop(), baseClock.Now)

	inviteClock := &armedClock{base: baseClock.Now()}

	invites, err := invite.NewService(h, policy, testTokenBytes, zap.NewNop(), inviteClock.Now)
	if err != nil {
		t.Fatalf("invite.NewService() error = %v", err)
	}

	svc := NewService(h, users, sessions, roles, checker, recorder, invites, policy, nil, zap.NewNop(), baseClock.Now, AccountDeps{})
	deps := testDeps{service: svc, handle: h, users: users, sessions: sessions, roles: roles, invites: invites, policy: policy, recorder: recorder, clock: baseClock}

	setSignupPolicy(t, policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuer := createTestAdmin(t, deps)

	// Created while inviteClock is unarmed, so every Now() call Create
	// issues returns exactly baseClock's current time and the invite's
	// expiry lands exactly one second after it.
	issued, err := invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1, TTL: time.Second})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Arm for exactly the two Now() calls admitAccount's remaining path
	// makes against this invite: rule 5's ValidateTx (call 1, still
	// unjumped, so the token reads live) and rule 8's RedeemTx (call 2,
	// jumped two seconds past the one-second expiry, so its conditional
	// UPDATE affects zero rows and it returns invite.ErrInvalid).
	inviteClock.Arm(1, 2*time.Second)

	in := newAuthenticated(t)
	in.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	before := snapshotRowCounts(t, deps)

	_, _, _, err = svc.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-1", "")
	if !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("LogIn() error = %v, want ErrInviteInvalid", err)
	}

	// A rule 8 refusal returns the bare sentinel, not one joined or wrapped
	// with the underlying RedeemTx cause.
	if err.Error() != ErrInviteInvalid.Error() {
		t.Fatalf("LogIn() error text = %q, want exactly %q", err.Error(), ErrInviteInvalid.Error())
	}

	assertRowCountsUnchanged(t, deps, before)
	assertZeroAccountRows(t, deps, in)
	assertSignupBlockedRule(t, deps, blockedRuleInviteInvalid)

	redemptionCount := countRows(t, h, `SELECT count(*) FROM invite_redemptions WHERE invite_id = $1`, issued.Invite.ID)
	if redemptionCount != 0 {
		t.Fatalf("invite_redemptions row count = %d, want 0", redemptionCount)
	}
}

// This is a lower-level obligation test: it proves that createAdmittedAccount
// commits none of its own writes, so a caller that rolls back its
// transaction after createAdmittedAccount fails is rolling back the whole
// account, not merely the redemption. It manufactures the failure directly,
// inside a transaction the test itself owns, by spending the invite's last
// use with a raw statement between validation and redemption.
// TestLogIn_RedeemFailureAfterValidate_RollsBackAccount above is the test
// that proves admitAccount itself performs this rollback when reached
// through the public LogIn entry point.
// Covers AC-008.61 and AC-008.65.
func TestCreateAdmittedAccount_RedeemFailureRollsBackCreate(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuer := createTestAdmin(t, deps)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	in := newAuthenticated(t)
	in.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	tx, err := deps.handle.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	if _, validateTxErr := deps.invites.ValidateTx(t.Context(), tx, issued.Invite.ID, ""); validateTxErr != nil {
		t.Fatalf("ValidateTx() error = %v", validateTxErr)
	}

	// Manufacture the failure: spend the invite's only use from within the
	// same transaction, so RedeemTx's own conditional UPDATE affects zero
	// rows when createAdmittedAccount calls it below.
	if _, execErr := tx.Exec(t.Context(), `UPDATE invites SET uses = max_uses WHERE id = $1`, issued.Invite.ID); execErr != nil {
		t.Fatalf("forcing invite exhaustion: %v", execErr)
	}

	_, createErr := deps.service.createAdmittedAccount(t.Context(), tx, in, nil, user.StatusActive, true, "", deps.clock.Now())
	if createErr == nil {
		t.Fatal("createAdmittedAccount() error = nil, want a redemption failure")
	}

	if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
		t.Fatalf("Rollback() error = %v", rollbackErr)
	}

	userCount := countRows(t, deps.handle, `SELECT count(*) FROM identities WHERE provider = $1 AND subject = $2`, in.Provider, in.Subject)
	if userCount != 0 {
		t.Fatalf("identities row count after rollback = %d, want 0: the account must not survive a failed redemption", userCount)
	}

	usersCount := countRows(t, deps.handle, `SELECT count(*) FROM users WHERE display_name = $1`, in.DisplayName)
	// display_name is shared across every newAuthenticated identity in this
	// test file, so this assertion only holds within this test's own
	// isolated database; that isolation is exactly what storetest.New
	// provides per test.
	if usersCount != 0 {
		t.Fatalf("users row count after rollback = %d, want 0: the account must not survive a failed redemption", usersCount)
	}
}

// createTestAdmin inserts and returns an account holding admin, so tests
// that issue invites have an issuer to attribute them to.
func createTestAdmin(t *testing.T, deps testDeps) uuid.UUID {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generating admin id: %v", err)
	}

	now := deps.clock.Now()

	const insertUserQuery = `
INSERT INTO users (id, display_name, status, created_at, updated_at)
VALUES ($1, $2, 'active', $3, $3)
`

	if _, execErr := deps.handle.Pool().Exec(t.Context(), insertUserQuery, id, "test admin", now); execErr != nil {
		t.Fatalf("inserting admin: %v", execErr)
	}

	if grantRoleErr := deps.roles.GrantRole(t.Context(), id, "admin", id); grantRoleErr != nil {
		t.Fatalf("granting admin role: %v", grantRoleErr)
	}

	return id
}

// assertZeroAccountRows fails the test unless in's identity has no matching
// row in identities. in.Subject is unique per newAuthenticated call, and
// CreateWithIdentityTx always inserts a user and its identity together, so
// the absence of the identity row is exactly the absence of the account a
// refused admission must not have created, precise even when other accounts
// already exist in the same database, as callers that issue an invite
// through createTestAdmin's own account do.
func assertZeroAccountRows(t *testing.T, deps testDeps, in Authenticated) {
	t.Helper()

	identityCount := countRows(t, deps.handle, `SELECT count(*) FROM identities WHERE provider = $1 AND subject = $2`, in.Provider, in.Subject)
	if identityCount != 0 {
		t.Fatalf("identities row count = %d, want 0", identityCount)
	}
}

// assertSignupBlockedRule fails the test unless exactly one signup.blocked
// row exists naming rule in its detail.
func assertSignupBlockedRule(t *testing.T, deps testDeps, rule string) {
	t.Helper()

	count := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = 'signup.blocked' AND detail->>'rule' = $1`, rule)
	if count != 1 {
		t.Fatalf("signup.blocked rows with rule %q = %d, want 1", rule, count)
	}
}

// assertUserCreatedDetail fails the test unless exactly one user.created
// row exists for userID naming rule in its detail.
func assertUserCreatedDetail(t *testing.T, deps testDeps, userID uuid.UUID, rule string) {
	t.Helper()

	var subject string

	if idErr := deps.handle.Pool().QueryRow(t.Context(), `SELECT 'user:' || $1::text`, userID).Scan(&subject); idErr != nil {
		t.Fatalf("building subject: %v", idErr)
	}

	count := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = 'user.created' AND subject = $1 AND detail->>'rule' = $2`,
		subject, rule)
	if count != 1 {
		t.Fatalf("user.created rows for %s with rule %q = %d, want 1", subject, rule, count)
	}
}

// assertSignupBlockedSubject fails the test unless exactly one
// signup.blocked row carries wantSubject.
func assertSignupBlockedSubject(t *testing.T, deps testDeps, wantSubject string) {
	t.Helper()

	count := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = 'signup.blocked' AND subject = $1`, wantSubject)
	if count != 1 {
		t.Fatalf("signup.blocked rows with subject %q = %d, want 1", wantSubject, count)
	}
}

// logInBootstrapCandidate logs in a fresh identity asserting the verified
// address email through svc and returns the resolved account.
func logInBootstrapCandidate(t *testing.T, svc *Service, subject, email string) user.User {
	t.Helper()

	in := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       subject,
		Email:         email,
		EmailVerified: true,
		DisplayName:   "Bootstrap Candidate",
		Methods:       []string{session.MethodOIDC},
	}

	account, _, _, err := svc.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-"+subject, "")
	if err != nil {
		t.Fatalf("LogIn(%s) error = %v", subject, err)
	}

	return account
}

// holdsRole reports whether userID currently holds role, failing the test
// when the roles cannot be read.
func holdsRole(t *testing.T, deps testDeps, userID uuid.UUID, role string) bool {
	t.Helper()

	roles, err := deps.roles.RolesFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("RolesFor() error = %v", err)
	}

	return slices.Contains(roles, role)
}

// TestBootstrapAccountCreatedAtSignupHoldsAdminAndIsMarked covers AC-008.36
// and AC-008.79: a bootstrap-list address signing in for the first time is
// created holding admin, recorded as having received the bootstrap grant,
// and audited with exactly one role.granted row naming the list.
func TestBootstrapAccountCreatedAtSignupHoldsAdminAndIsMarked(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"root@example.com"})
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	created := logInBootstrapCandidate(t, deps.service, "sub-bootstrap-first", "root@example.com")

	if !holdsRole(t, deps, created.ID, authz.RoleAdmin) {
		t.Fatal("bootstrap account does not hold admin after its first sign-in")
	}

	stored, err := deps.users.ByID(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v", err)
	}

	if stored.BootstrapAdminGrantedAt == nil {
		t.Fatal("stored BootstrapAdminGrantedAt = nil, want the creation instant")
	}

	grants := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2 AND detail->>'reason' = 'bootstrap_admin_list'`,
		audit.ActionRoleGranted, "user:"+created.ID.String())
	if grants != 1 {
		t.Fatalf("%s rows with reason bootstrap_admin_list = %d, want 1", audit.ActionRoleGranted, grants)
	}
}

// TestBootstrapAdminIsNotRegrantedAfterDemotion covers AC-008.79: once a
// bootstrap administrator has been demoted by another administrator, signing
// in again does not give it admin back.
//
// The bootstrap account signs up before any other administrator exists, so
// it still qualifies for rule 1's exemption (AC-008.36 as amended); the
// second administrator is created afterward. Originally this test created
// the second administrator first and still expected the bootstrap-listed
// address to receive admin on signup, which encoded the old requirement
// that the list is always exempt. AC-008.36 was amended so the list is
// exempt only while no active administrator exists; the order here changed
// to match, without weakening either assertion below.
func TestBootstrapAdminIsNotRegrantedAfterDemotion(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"root@example.com"})

	bootstrapAccount := logInBootstrapCandidate(t, deps.service, "sub-bootstrap-demoted", "root@example.com")
	if !holdsRole(t, deps, bootstrapAccount.ID, authz.RoleAdmin) {
		t.Fatal("bootstrap account does not hold admin after its first sign-in")
	}

	secondAdminID, _ := issueSession(t, deps, "sub-bootstrap-second-admin")
	if err := deps.roles.GrantRole(t.Context(), secondAdminID, authz.RoleAdmin, secondAdminID); err != nil {
		t.Fatalf("granting second admin: %v", err)
	}

	if err := deps.roles.SetRoles(t.Context(), bootstrapAccount.ID, []string{authz.RoleMember}, secondAdminID); err != nil {
		t.Fatalf("demoting bootstrap account: %v", err)
	}

	logInBootstrapCandidate(t, deps.service, "sub-bootstrap-demoted", "root@example.com")

	if holdsRole(t, deps, bootstrapAccount.ID, authz.RoleAdmin) {
		t.Fatal("demoted bootstrap account holds admin again after signing in, want it to stay demoted")
	}
}

// TestBootstrapListIgnoredWhileAnActiveAdminExists covers AC-008.36 and
// AC-008.79 as amended 2026-09-24: once an active administrator exists, a
// bootstrap-listed address receives no exemption and goes through the
// ordinary admission rules exactly like an unlisted address. Signup disabled
// refuses it with ErrSignupDisabled and creates nothing; signup enabled
// admits it as an ordinary member holding neither admin nor the bootstrap
// grant marker.
func TestBootstrapListIgnoredWhileAnActiveAdminExists(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"root@example.com"})

	adminID, _ := issueSession(t, deps, "sub-existing-admin")
	if err := deps.roles.GrantRole(t.Context(), adminID, authz.RoleAdmin, adminID); err != nil {
		t.Fatalf("granting existing admin: %v", err)
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(false)})

	refused := newAuthenticated(t)
	refused.Email = "root@example.com"
	refused.EmailVerified = true

	before := snapshotRowCounts(t, deps)

	_, _, _, err := deps.service.LogIn(t.Context(), refused, "203.0.113.5", "test-agent", "req-refused", "")
	if !errors.Is(err, ErrSignupDisabled) {
		t.Fatalf("LogIn() error = %v, want ErrSignupDisabled (the bootstrap list must not exempt it)", err)
	}

	assertRowCountsUnchanged(t, deps, before)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	admitted := newAuthenticated(t)
	admitted.Email = "root@example.com"
	admitted.EmailVerified = true

	created, _, _, err := deps.service.LogIn(t.Context(), admitted, "203.0.113.5", "test-agent", "req-admitted", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	if holdsRole(t, deps, created.ID, authz.RoleAdmin) {
		t.Fatal("listed address gained admin through the bootstrap list while an active admin already existed")
	}

	stored, err := deps.users.ByID(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("ByID() error = %v", err)
	}

	if stored.BootstrapAdminGrantedAt != nil {
		t.Fatal("stored BootstrapAdminGrantedAt is set, want nil: the bootstrap list must not have granted it")
	}
}

// TestPurgedBootstrapAdminDoesNotRegainAdminOnReSignup covers AC-008.79: it
// reproduces S1's attack sequence at the service and repository level. A
// bootstrap administrator, demoted while a second administrator remains
// active, is soft-deleted and then purged past its grace period; signing in
// again with the same address must not regain admin, because the second
// administrator is still active when the re-signup runs rule 1.
func TestPurgedBootstrapAdminDoesNotRegainAdminOnReSignup(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"root@example.com"})

	bootstrapAccount := logInBootstrapCandidate(t, deps.service, "sub-bootstrap-purged", "root@example.com")
	if !holdsRole(t, deps, bootstrapAccount.ID, authz.RoleAdmin) {
		t.Fatal("bootstrap account does not hold admin after its first sign-in")
	}

	secondAdminID, _ := issueSession(t, deps, "sub-purge-second-admin")
	if err := deps.roles.GrantRole(t.Context(), secondAdminID, authz.RoleAdmin, secondAdminID); err != nil {
		t.Fatalf("granting second admin: %v", err)
	}

	if err := deps.roles.SetRoles(t.Context(), bootstrapAccount.ID, []string{authz.RoleMember}, secondAdminID); err != nil {
		t.Fatalf("demoting bootstrap account: %v", err)
	}

	if err := deps.service.DeleteAccount(t.Context(), bootstrapAccount.ID, "203.0.113.5", "req-delete"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}

	deps.clock.Advance(time.Hour)

	if _, err := deps.users.PurgeDeletedBefore(t.Context(), deps.clock.Now()); err != nil {
		t.Fatalf("PurgeDeletedBefore() error = %v", err)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM users WHERE id = $1`, bootstrapAccount.ID); got != 0 {
		t.Fatalf("purged bootstrap account rows = %d, want 0", got)
	}

	readmitted := logInBootstrapCandidate(t, deps.service, "sub-bootstrap-purged", "root@example.com")

	if readmitted.ID == bootstrapAccount.ID {
		t.Fatal("re-signup resolved the purged account id, want a fresh account")
	}

	if holdsRole(t, deps, readmitted.ID, authz.RoleAdmin) {
		t.Fatal("re-signup after purge regained admin through the bootstrap list, want the ordinary admission rules")
	}
}

// TestConcurrentFirstBootstrapSignupsGrantOneAdmin covers AC-008.36: on an
// instance with no administrator yet, two different bootstrap-listed
// addresses signing up concurrently produce exactly one active
// administrator, because each one takes the last-admin advisory lock before
// counting active administrators, serializing the two decisions.
func TestConcurrentFirstBootstrapSignupsGrantOneAdmin(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"root-a@example.com", "root-b@example.com"})
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	subjects := []string{"sub-concurrent-a", "sub-concurrent-b"}
	emails := []string{"root-a@example.com", "root-b@example.com"}
	errs := make([]error, len(subjects))
	start := make(chan struct{})

	var wg sync.WaitGroup

	for i := range subjects {
		wg.Go(func() {
			<-start

			in := Authenticated{
				Provider:      "https://issuer.example",
				Subject:       subjects[i],
				Email:         emails[i],
				EmailVerified: true,
				DisplayName:   "Bootstrap Candidate",
				Methods:       []string{session.MethodOIDC},
			}

			_, _, _, errs[i] = deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-"+subjects[i], "")
		})
	}

	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("LogIn(%s) error = %v", subjects[i], err)
		}
	}

	activeAdmins, err := deps.users.CountActiveAdmins(t.Context(), authz.RoleAdmin)
	if err != nil {
		t.Fatalf("CountActiveAdmins() error = %v", err)
	}

	if activeAdmins != 1 {
		t.Fatalf("active admins after concurrent first bootstrap signups = %d, want 1", activeAdmins)
	}
}

// TestExistingAccountAddedToBootstrapListIsNotGrantedAtLogin covers
// AC-008.79: the bootstrap list grants admin only when it creates an account,
// so an account created before its address joined the list does not gain
// admin when it later signs in.
func TestExistingAccountAddedToBootstrapListIsNotGrantedAtLogin(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	existing := logInBootstrapCandidate(t, deps.service, "sub-later-listed", "later@example.com")

	listed := NewService(deps.handle, deps.users, deps.sessions, deps.roles, authz.NewChecker(deps.roles), deps.recorder,
		deps.invites, deps.policy, []string{"later@example.com"}, zap.NewNop(), deps.clock.Now, AccountDeps{})

	logInBootstrapCandidate(t, listed, "sub-later-listed", "later@example.com")

	if holdsRole(t, deps, existing.ID, authz.RoleAdmin) {
		t.Fatal("existing account gained admin at login after its address joined the bootstrap list")
	}
}

// installAuditTriggerBlocking installs a Postgres trigger on audit_events
// that raises an exception when an inserted row's action equals
// blockedAction, so a test can engineer an audit append failure partway
// through a signup's transaction and observe that the whole signup rolls
// back with it. It registers its own cleanup, dropping the trigger and its
// function once the test ends.
func installAuditTriggerBlocking(t *testing.T, deps testDeps, blockedAction string) {
	t.Helper()

	createFunc := "CREATE OR REPLACE FUNCTION block_audit_action_test() RETURNS trigger AS $trg$\n" +
		"BEGIN\n" +
		"    IF NEW.action = '" + blockedAction + "' THEN\n" +
		"        RAISE EXCEPTION 'test: blocking audit row for action %', NEW.action;\n" +
		"    END IF;\n" +
		"    RETURN NEW;\n" +
		"END;\n" +
		"$trg$ LANGUAGE plpgsql;"

	if _, err := deps.handle.Pool().Exec(t.Context(), createFunc); err != nil {
		t.Fatalf("creating trigger function: %v", err)
	}

	const createTrigger = `
CREATE TRIGGER block_audit_action_test
BEFORE INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION block_audit_action_test();
`

	if _, err := deps.handle.Pool().Exec(t.Context(), createTrigger); err != nil {
		t.Fatalf("creating trigger: %v", err)
	}

	t.Cleanup(func() {
		if _, err := deps.handle.Pool().Exec(context.Background(), `DROP TRIGGER IF EXISTS block_audit_action_test ON audit_events`); err != nil {
			t.Errorf("dropping trigger: %v", err)
		}

		if _, err := deps.handle.Pool().Exec(context.Background(), `DROP FUNCTION IF EXISTS block_audit_action_test()`); err != nil {
			t.Errorf("dropping trigger function: %v", err)
		}
	})
}

// auditRequestID returns the request_id recorded on the sole audit_events
// row matching action and subject, failing the test unless the read
// succeeds.
func auditRequestID(t *testing.T, deps testDeps, action, subject string) string {
	t.Helper()

	var requestID string

	if err := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT request_id FROM audit_events WHERE action = $1 AND subject = $2`, action, subject).Scan(&requestID); err != nil {
		t.Fatalf("reading request id for %s %s: %v", action, subject, err)
	}

	return requestID
}

// TestSignupAuditRowsRollBackWithTheSignup covers AC-008.38: when the
// user.created audit append itself fails partway through a signup's
// transaction, the whole signup rolls back, leaving no users row, no
// identities row, no invite.redeemed row, and the invite's uses count
// unchanged (AC-008.61).
func TestSignupAuditRowsRollBackWithTheSignup(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuer := createTestAdmin(t, deps)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	installAuditTriggerBlocking(t, deps, audit.ActionUserCreated)

	in := newAuthenticated(t)
	in.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	before := snapshotRowCounts(t, deps)

	if _, _, _, loginErr := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-blocked", ""); loginErr == nil {
		t.Fatal("LogIn() error = nil, want the blocked user.created append to fail the signup")
	}

	assertRowCountsUnchanged(t, deps, before)

	redeemedCount := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionInviteRedeemed, "invite:"+issued.Invite.ID.String())
	if redeemedCount != 0 {
		t.Fatalf("invite.redeemed rows = %d, want 0", redeemedCount)
	}

	var uses int
	if scanErr := deps.handle.Pool().QueryRow(t.Context(), `SELECT uses FROM invites WHERE id = $1`, issued.Invite.ID).Scan(&uses); scanErr != nil {
		t.Fatalf("reading invite uses: %v", scanErr)
	}

	if uses != 0 {
		t.Fatalf("invite uses = %d, want 0 (unchanged by a rolled-back signup)", uses)
	}
}

// TestSignupWritesCreatedAndRedeemedInOneTransaction covers AC-008.69: after
// a successful invite signup, both the user.created and invite.redeemed
// rows exist and carry the same request id, showing they committed together
// as part of the same transaction (AC-008.61).
func TestSignupWritesCreatedAndRedeemedInOneTransaction(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuer := createTestAdmin(t, deps)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	in := newAuthenticated(t)
	in.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	const requestID = "req-same-tx"

	created, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", requestID, "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	userCreatedRequestID := auditRequestID(t, deps, audit.ActionUserCreated, "user:"+created.ID.String())
	inviteRedeemedRequestID := auditRequestID(t, deps, audit.ActionInviteRedeemed, "invite:"+issued.Invite.ID.String())

	if userCreatedRequestID != requestID || inviteRedeemedRequestID != requestID {
		t.Fatalf("request ids = %q, %q, want both %q", userCreatedRequestID, inviteRedeemedRequestID, requestID)
	}
}

// TestIdentityLinkedAuditDoesNotSurviveARolledBackSignup covers AC-008.38:
// identity.linked, written mid-transaction when a verified address collides
// with an existing account, does not survive when a later failure in the
// same transaction rolls the whole signup back (AC-008.61).
func TestIdentityLinkedAuditDoesNotSurviveARolledBackSignup(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	first := newAuthenticated(t)
	first.Email = "collide@example.com"
	first.EmailVerified = true

	if _, _, _, err := deps.service.LogIn(t.Context(), first, "203.0.113.5", "test-agent", "req-first", ""); err != nil {
		t.Fatalf("LogIn() seeding first account error = %v", err)
	}

	installAuditTriggerBlocking(t, deps, audit.ActionUserCreated)

	second := newAuthenticated(t)
	second.Email = "collide@example.com"
	second.EmailVerified = true

	if _, _, _, err := deps.service.LogIn(t.Context(), second, "203.0.113.5", "test-agent", "req-second", ""); err == nil {
		t.Fatal("LogIn() error = nil, want the blocked user.created append to fail the signup")
	}

	linkedCount := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionIdentityLinked, "email:"+second.Email)
	if linkedCount != 0 {
		t.Fatalf("identity.linked rows for %s = %d, want 0", second.Email, linkedCount)
	}

	identityCount := countRows(t, deps.handle,
		`SELECT count(*) FROM identities WHERE provider = $1 AND subject = $2`, second.Provider, second.Subject)
	if identityCount != 0 {
		t.Fatalf("identities row count for second attempt = %d, want 0", identityCount)
	}
}
