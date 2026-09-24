package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// admittedByBootstrap, admittedByOpen, and admittedByInvite name the rule
// that admitted a new account, recorded in the detail of its user.created
// event.
const admittedByBootstrap = "bootstrap"
const admittedByOpen = "open"
const admittedByInvite = "invite"

// blockedRuleSignupDisabled, blockedRuleInviteRequired,
// blockedRuleInviteInvalid, and blockedRuleInviteEmailMismatch name the rule
// that refused a signup, recorded in the detail of its signup.blocked event.
const blockedRuleSignupDisabled = "signup_disabled"
const blockedRuleInviteRequired = "invite_required"
const blockedRuleInviteInvalid = "invite_invalid"
const blockedRuleInviteEmailMismatch = "invite_email_mismatch"

// detailKeyRule names the key both the signup.blocked and user.created
// events carry their rule name under.
const detailKeyRule = "rule"

// ErrSignupDisabled reports an authentication that would have created an
// account while self-service signup is switched off.
var ErrSignupDisabled = errors.New("signup disabled")

// ErrInviteRequired reports a signup attempted without an invite while one
// is required.
var ErrInviteRequired = errors.New("invite required")

// ErrInviteInvalid reports an invite that is unknown, expired, spent, or
// revoked. It does not distinguish them.
var ErrInviteInvalid = errors.New("invite invalid")

// ErrInviteEmailMismatch reports an invite bound to an address the
// authentication did not verifiably assert.
var ErrInviteEmailMismatch = errors.New("invite address mismatch")

// ErrApprovalPending reports an account that was created but may not
// authenticate until an administrator approves it.
var ErrApprovalPending = errors.New("account awaiting approval")

// redeemFailureError marks a createAdmittedAccount failure as having
// occurred during rule 8's RedeemTx call (design.md's "Signup admission
// path"), rather than during rule 7's account creation, so admitAccount can
// attribute the failure to the correct rule instead of treating every
// createAdmittedAccount error the same way.
type redeemFailureError struct {
	err error
}

// Error returns the wrapped redemption failure's message.
func (e *redeemFailureError) Error() string {
	return e.err.Error()
}

// Unwrap returns the wrapped redemption failure, so errors.Is and errors.As
// see through this marker to the underlying invite error.
func (e *redeemFailureError) Unwrap() error {
	return e.err
}

// admitAccount applies LogIn's steps 4 and 5, which settle the email address
// a new account would carry, and then the nine ordered admission rules from
// design.md's "Signup admission path", which decide whether an account is
// created at all. It is called only when the authentication resolves to no
// existing identity. Every rule from settlement through rule 9 runs inside
// one transaction (AC-008.61), so a policy change or invite revocation
// mid-ceremony cannot be raced; the one exception is the signup.blocked row
// a refusal writes, which is appended after the rollback, in its own
// statement.
func (s *Service) admitAccount(ctx context.Context, in Authenticated, clientIP, requestID string) (user.User, error) {
	subject := signupSubject(in)

	tx, err := s.handle.Pool().Begin(ctx)
	if err != nil {
		return user.User{}, fmt.Errorf("auth: beginning signup transaction: %w", err)
	}

	// A backstop against a future return path that forgets to roll back
	// explicitly. It is a no-op after an explicit Commit or Rollback, both
	// of which leave pgx.ErrTxClosed for this call to see and ignore;
	// anything else is a real failure and is logged rather than discarded.
	defer func() {
		rollbackCtx := context.WithoutCancel(ctx)
		if rollbackErr := tx.Rollback(rollbackCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			s.logger.Error("auth: rolling back signup transaction in deferred backstop", zap.Error(rollbackErr))
		}
	}()

	// LogIn steps 4 and 5: settle the email this account would carry, inside
	// the same transaction that will create it (AC-008.61).
	settledEmail, err := s.settleEmailTx(ctx, tx, in, clientIP, requestID)
	if err != nil {
		return user.User{}, err
	}

	// Rule 1: bootstrap exemption, checked against the settled address
	// rather than the merely asserted one. A provider may reassign an
	// address, so an issuer asserting a verified address that an existing
	// account already holds must not receive the exemption and must go
	// through rules 2 through 9 like anyone else (ADR 0012; design.md's
	// "Signup admission path" rule 1).
	if handled, bootstrapUser, bootstrapErr := s.rule1BootstrapAdmission(ctx, tx, in, settledEmail, clientIP, requestID); handled {
		return bootstrapUser, bootstrapErr
	}

	// Rules 2 through 4: read the policy within this transaction, and
	// refuse when signup is disabled or an invite is required but none was
	// carried.
	policy, err := s.checkSignupPolicy(ctx, tx, in, subject, clientIP, requestID)
	if err != nil {
		return user.User{}, err
	}

	verifiedEmail := ""
	if in.EmailVerified {
		verifiedEmail = in.Email
	}

	// Rules 5 and 6: invite validity and its email binding, both settled by
	// one re-read under the row lock ValidateTx takes.
	live, err := s.resolveInviteState(ctx, tx, in, subject, clientIP, requestID, verifiedEmail, policy.SignupRequireInvite)
	if err != nil {
		return user.User{}, err
	}

	admittedBy := admittedByOpen
	if live {
		admittedBy = admittedByInvite
	}

	status := user.StatusActive
	if policy.SignupRequireApproval {
		status = user.StatusPending
	}

	// Rules 7 and 8: create the account, its identity, and its member
	// grant, then spend the token if one is live.
	createdUser, createErr := s.createAdmittedAccount(ctx, tx, in, settledEmail, status, live, verifiedEmail, s.now().UTC())
	if createErr != nil {
		return user.User{}, s.handleCreateFailure(ctx, tx, subject, clientIP, requestID, createErr)
	}

	// Signup's own audit trail commits or rolls back with the account it
	// describes, so it is written here, before Commit, rather than after it.
	if auditErr := s.recordSignupAuditTx(ctx, tx, createdUser, in.InviteID, admittedBy, live, clientIP, requestID); auditErr != nil {
		return user.User{}, errors.Join(auditErr, wrapRollbackErr(tx.Rollback(ctx)))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return user.User{}, fmt.Errorf("auth: committing signup transaction: %w", commitErr)
	}

	return admittedAccountResult(createdUser, status)
}

// checkSignupPolicy applies signup admission rules 2 through 4 (design.md's
// "Signup admission path"): it reads the signup policy within tx and
// refuses when signup is disabled or an invite is required but in carries
// none.
func (s *Service) checkSignupPolicy(ctx context.Context, tx pgx.Tx, in Authenticated, subject, clientIP, requestID string) (settings.Settings, error) {
	policy, err := s.policy.LoadTx(ctx, tx)
	if err != nil {
		return settings.Settings{}, errors.Join(fmt.Errorf("auth: loading signup policy: %w", err), wrapRollbackErr(tx.Rollback(ctx)))
	}

	if !policy.SignupEnabled {
		return settings.Settings{}, s.blockSignup(ctx, tx, subject, clientIP, requestID, blockedRuleSignupDisabled, ErrSignupDisabled)
	}

	if policy.SignupRequireInvite && !in.InviteID.Valid {
		return settings.Settings{}, s.blockSignup(ctx, tx, subject, clientIP, requestID, blockedRuleInviteRequired, ErrInviteRequired)
	}

	return policy, nil
}

// handleCreateFailure attributes a createAdmittedAccount failure to the
// correct signup admission rule: a rule 8 refusal (invite.ErrInvalid or
// invite.ErrEmailMismatch) is handled by handleRedeemFailure; anything else
// is a rule 7 failure, rolled back and wrapped with no signup.blocked row.
func (s *Service) handleCreateFailure(ctx context.Context, tx pgx.Tx, subject, clientIP, requestID string, createErr error) error {
	if redeemErr, ok := errors.AsType[*redeemFailureError](createErr); ok {
		return s.handleRedeemFailure(ctx, tx, subject, clientIP, requestID, redeemErr.err)
	}

	return errors.Join(fmt.Errorf("auth: creating account: %w", createErr), wrapRollbackErr(tx.Rollback(ctx)))
}

// handleRedeemFailure applies signup admission rule 8's refusal branches: a
// RedeemTx failure that matches invite.ErrInvalid or invite.ErrEmailMismatch
// is a refusal, so it rolls back, writes signup.blocked, logs the underlying
// cause, and returns the bare sentinel; any other RedeemTx failure is a
// failure rather than a refusal, so it rolls back and returns a wrapped
// error with no signup.blocked row.
func (s *Service) handleRedeemFailure(ctx context.Context, tx pgx.Tx, subject, clientIP, requestID string, cause error) error {
	switch {
	case errors.Is(cause, invite.ErrInvalid):
		s.logger.Error("auth: redeeming invite after validation", zap.Error(cause))

		return s.blockSignup(ctx, tx, subject, clientIP, requestID, blockedRuleInviteInvalid, ErrInviteInvalid)
	case errors.Is(cause, invite.ErrEmailMismatch):
		s.logger.Error("auth: redeeming invite after validation", zap.Error(cause))

		return s.blockSignup(ctx, tx, subject, clientIP, requestID, blockedRuleInviteEmailMismatch, ErrInviteEmailMismatch)
	default:
		return errors.Join(fmt.Errorf("auth: spending invite: %w", cause), wrapRollbackErr(tx.Rollback(ctx)))
	}
}

// recordSignupAuditTx appends user.created against tx, naming admittedBy as
// the admitting rule, and, when inviteID is valid, invite.redeemed with
// outcome success when live and failure otherwise. Both rows commit or roll
// back with the account they describe: a RecordTx failure here is returned
// unwrapped so admitAccount can roll tx back and fail the signup.
func (s *Service) recordSignupAuditTx(ctx context.Context, tx pgx.Tx, createdUser user.User, inviteID uuid.NullUUID, admittedBy string, live bool, clientIP, requestID string) error {
	if err := s.recordAuditTx(ctx, tx, audit.ActionUserCreated, &createdUser.ID, "user:"+createdUser.ID.String(), audit.OutcomeSuccess, clientIP, requestID,
		s.auditDetail(map[string]any{detailKeyRule: admittedBy})); err != nil {
		return err
	}

	if !inviteID.Valid {
		return nil
	}

	outcome := audit.OutcomeSuccess
	if !live {
		outcome = audit.OutcomeFailure
	}

	return s.recordAuditTx(ctx, tx, audit.ActionInviteRedeemed, &createdUser.ID, "invite:"+inviteID.UUID.String(), outcome, clientIP, requestID, nil)
}

// admittedAccountResult applies signup admission rule 9 (design.md's
// "Signup admission path") once an admitted account's transaction,
// including its audit trail, has committed: a pending account is reported
// through ErrApprovalPending and issues no session.
func admittedAccountResult(createdUser user.User, status user.Status) (user.User, error) {
	if status == user.StatusPending {
		return user.User{}, ErrApprovalPending
	}

	return createdUser, nil
}

// recordAuditTx appends an audit event against tx, so it commits or rolls
// back with the change it describes, wrapping any append failure with
// context naming the action. Signup's own events use this path rather than
// recordAudit's best-effort one.
func (s *Service) recordAuditTx(ctx context.Context, tx pgx.Tx, action string, actorID *uuid.UUID, subject string, outcome audit.Outcome, clientIP, requestID string, detail []byte) error {
	if err := s.recorder.RecordTx(ctx, tx, audit.Event{
		ActorID:   actorID,
		Subject:   subject,
		Action:    action,
		Outcome:   outcome,
		ClientIP:  parseClientIP(clientIP),
		RequestID: requestID,
		Detail:    detail,
	}); err != nil {
		return fmt.Errorf("auth: recording %s audit event: %w", action, err)
	}

	return nil
}

// resolveInviteState applies signup admission rules 5 and 6 (design.md's
// "Signup admission path") against tx and reports whether a live invite was
// carried. When it returns a non-nil error, tx has already been rolled back
// and the error is ready to return from admitAccount unchanged.
func (s *Service) resolveInviteState(ctx context.Context, tx pgx.Tx, in Authenticated, subject, clientIP, requestID, verifiedEmail string, requireInvite bool) (bool, error) {
	if !in.InviteID.Valid {
		return false, nil
	}

	_, err := s.inviteService.ValidateTx(ctx, tx, in.InviteID.UUID, verifiedEmail)

	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, invite.ErrEmailMismatch):
		return false, s.blockSignup(ctx, tx, subject, clientIP, requestID, blockedRuleInviteEmailMismatch, ErrInviteEmailMismatch)
	case errors.Is(err, invite.ErrInvalid):
		if requireInvite {
			return false, s.blockSignup(ctx, tx, subject, clientIP, requestID, blockedRuleInviteInvalid, ErrInviteInvalid)
		}
		// A dead token when none is required does not block the signup:
		// the account is created unattributed.
		return false, nil
	default:
		return false, errors.Join(fmt.Errorf("auth: validating invite: %w", err), wrapRollbackErr(tx.Rollback(ctx)))
	}
}

// rule1BootstrapAdmission applies signup admission rule 1 (design.md's
// "Signup admission path") against tx: when settledEmail is on the
// bootstrap list and the exemption still applies (AC-008.36, AC-008.79 as
// amended: no active administrator exists yet), it creates the account
// through createBootstrapAccount and reports handled true, with tx already
// committed or rolled back by the time it returns. Otherwise it reports
// handled false and leaves tx open and untouched, so admitAccount continues
// on to rules 2 through 9. A non-nil error is only meaningful when handled
// is true.
func (s *Service) rule1BootstrapAdmission(ctx context.Context, tx pgx.Tx, in Authenticated, settledEmail *string, clientIP, requestID string) (bool, user.User, error) {
	if settledEmail == nil || !s.isBootstrapAdmin(*settledEmail) {
		return false, user.User{}, nil
	}

	exempt, err := s.bootstrapExemptionAppliesTx(ctx, tx)
	if err != nil {
		return true, user.User{}, errors.Join(err, wrapRollbackErr(tx.Rollback(ctx)))
	}

	if !exempt {
		return false, user.User{}, nil
	}

	createdUser, err := s.createBootstrapAccount(ctx, tx, in, settledEmail, clientIP, requestID)

	return true, createdUser, err
}

// bootstrapExemptionAppliesTx reports whether rule 1's bootstrap exemption
// still applies to this signup: it takes the last-admin advisory lock and
// counts active administrators, both against tx, matching the pattern
// account.go's DeleteAccount, SetStatus, and ReplaceRoles already use for the
// same lock and count. Holding the lock to commit means two concurrent first
// signups from two listed addresses on an empty instance serialize: the
// first to commit becomes admin, and the second sees one active
// administrator and reports false. The bootstrap list exists only to create
// the first administrator; once one exists, further administrators are
// granted by an administrator, so a count of one or more reports false
// (AC-008.36, AC-008.79 as amended). It does not commit or roll back tx.
func (s *Service) bootstrapExemptionAppliesTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lastAdminAdvisoryLockKey); err != nil {
		return false, fmt.Errorf("auth: acquiring last-admin lock for bootstrap exemption: %w", err)
	}

	activeAdmins, err := s.users.CountActiveAdminsTx(ctx, tx, authz.RoleAdmin)
	if err != nil {
		return false, fmt.Errorf("auth: counting active admins for bootstrap exemption: %w", err)
	}

	return activeAdmins == 0, nil
}

// createBootstrapAccount admits an account through signup admission rule 1
// (design.md's "Signup admission path"), unconditionally active regardless
// of the signup policy. It runs against the caller's already-open
// transaction tx rather than beginning its own (AC-008.61), since
// settlement and rule 1 both already ran against it. The
// same transaction grants the account admin and records that the bootstrap
// administrator list granted it, which is the only place that list ever
// grants admin (AC-008.36, AC-008.79): a later login never does, so an
// administrator who demotes a bootstrap account is not overruled. A failure
// in the grant or the mark rolls back and fails the signup.
func (s *Service) createBootstrapAccount(ctx context.Context, tx pgx.Tx, in Authenticated, settledEmail *string, clientIP, requestID string) (user.User, error) {
	createdUser, err := s.createAdmittedAccount(ctx, tx, in, settledEmail, user.StatusActive, false, "", s.now().UTC())
	if err != nil {
		return user.User{}, errors.Join(fmt.Errorf("auth: creating bootstrap account: %w", err), wrapRollbackErr(tx.Rollback(ctx)))
	}

	grantedUser, err := s.grantBootstrapAdminTx(ctx, tx, createdUser.ID)
	if err != nil {
		return user.User{}, errors.Join(err, wrapRollbackErr(tx.Rollback(ctx)))
	}

	// The bootstrap path's own audit trail commits or rolls back with the
	// account it describes, so it is written here, before Commit, rather
	// than after it.
	if auditErr := s.recordAuditTx(ctx, tx, audit.ActionUserCreated, &grantedUser.ID, "user:"+grantedUser.ID.String(), audit.OutcomeSuccess, clientIP, requestID,
		s.auditDetail(map[string]any{detailKeyRule: admittedByBootstrap})); auditErr != nil {
		return user.User{}, errors.Join(auditErr, wrapRollbackErr(tx.Rollback(ctx)))
	}

	if auditErr := s.recordAuditTx(ctx, tx, audit.ActionRoleGranted, &grantedUser.ID, "user:"+grantedUser.ID.String(), audit.OutcomeSuccess, clientIP, requestID,
		s.auditDetail(map[string]any{"reason": "bootstrap_admin_list"})); auditErr != nil {
		return user.User{}, errors.Join(auditErr, wrapRollbackErr(tx.Rollback(ctx)))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return user.User{}, fmt.Errorf("auth: committing bootstrap signup transaction: %w", commitErr)
	}

	return grantedUser, nil
}

// grantBootstrapAdminTx grants the just-created account userID admin,
// self-granted, and marks it as having received the bootstrap grant, both
// against tx. It returns the account as tx now sees it, carrying
// BootstrapAdminGrantedAt. It does not commit or roll back tx.
func (s *Service) grantBootstrapAdminTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (user.User, error) {
	if err := s.roles.GrantRoleTx(ctx, tx, userID, authz.RoleAdmin, userID); err != nil {
		return user.User{}, fmt.Errorf("auth: granting bootstrap admin role: %w", err)
	}

	marked, err := s.users.MarkBootstrapAdminGrantedTx(ctx, tx, userID)
	if err != nil {
		return user.User{}, fmt.Errorf("auth: marking bootstrap admin grant: %w", err)
	}

	if !marked {
		return user.User{}, fmt.Errorf("auth: marking bootstrap admin grant: account %s not marked", userID)
	}

	granted, err := s.users.ByIDTx(ctx, tx, userID)
	if err != nil {
		return user.User{}, fmt.Errorf("auth: loading bootstrap account after grant: %w", err)
	}

	return granted, nil
}

// createAdmittedAccount performs signup admission rules 7 and 8 (design.md's
// "Signup admission path") against tx: it inserts the account and its first
// identity, grants it member, and, when live is true, spends one use of the
// token named by in.InviteID. It does not commit or roll back tx; applying
// the ordered admission rules around it is the caller's business. A failure
// during rule 8's RedeemTx call is wrapped in *redeemFailureError so the
// caller can attribute it to the correct rule; a failure before that point
// is returned as a plain wrapped error.
func (s *Service) createAdmittedAccount(ctx context.Context, tx pgx.Tx, in Authenticated, settledEmail *string, status user.Status, live bool, verifiedEmail string, now time.Time) (user.User, error) {
	userID, err := uuid.NewV7()
	if err != nil {
		return user.User{}, fmt.Errorf("auth: generating account id: %w", err)
	}

	identityID, err := uuid.NewV7()
	if err != nil {
		return user.User{}, fmt.Errorf("auth: generating identity id: %w", err)
	}

	var emailVerifiedAt *time.Time
	if settledEmail != nil {
		emailVerifiedAt = &now
	}

	newUser := user.User{
		ID:              userID,
		DisplayName:     in.DisplayName,
		Email:           settledEmail,
		EmailVerifiedAt: emailVerifiedAt,
		Status:          status,
	}

	var identityEmail *string

	if in.Email != "" {
		email := in.Email
		identityEmail = &email
	}

	newIdentity := user.Identity{
		ID:         identityID,
		UserID:     userID,
		Provider:   in.Provider,
		Subject:    in.Subject,
		Email:      identityEmail,
		LastUsedAt: &now,
	}

	if createWithIdentityTxErr := s.users.CreateWithIdentityTx(ctx, tx, newUser, newIdentity); createWithIdentityTxErr != nil {
		return user.User{}, fmt.Errorf("auth: creating account: %w", createWithIdentityTxErr)
	}

	if grantRoleTxErr := s.roles.GrantRoleTx(ctx, tx, userID, authz.RoleMember, userID); grantRoleTxErr != nil {
		return user.User{}, fmt.Errorf("auth: granting member role: %w", grantRoleTxErr)
	}

	if live {
		userRef := "user:" + userID.String()

		if redeemTxErr := s.inviteService.RedeemTx(ctx, tx, in.InviteID.UUID, userID, userRef, verifiedEmail); redeemTxErr != nil {
			return user.User{}, &redeemFailureError{err: fmt.Errorf("auth: spending invite: %w", redeemTxErr)}
		}
	}

	return newUser, nil
}

// settleEmailTx applies LogIn's steps 4 and 5 against tx, inside the same
// transaction as the rest of admission (AC-008.61): an unverified address
// settles nothing, and a verified address already held by another account
// also settles nothing, recording identity.linked with outcome failure
// against tx so the row commits or rolls back with the signup. A verified
// address held by no other account is returned, already lowercased by
// LogIn's own normalization. A non-nil error means the collision read or the
// identity.linked append failed; the caller must roll tx back and fail the
// signup.
func (s *Service) settleEmailTx(ctx context.Context, tx pgx.Tx, in Authenticated, clientIP, requestID string) (*string, error) {
	if !in.EmailVerified || in.Email == "" {
		//nolint:nilnil // a nil address with a nil error is "nothing settled", not a failure: the unverified/empty case is never an error.
		return nil, nil
	}

	_, err := s.users.ByEmailTx(ctx, tx, in.Email)

	switch {
	case err == nil:
		if auditErr := s.recordAuditTx(ctx, tx, audit.ActionIdentityLinked, nil, "email:"+in.Email, audit.OutcomeFailure, clientIP, requestID,
			s.auditDetail(map[string]any{"reason": "address_collision"})); auditErr != nil {
			return nil, auditErr
		}

		//nolint:nilnil // a nil address with a nil error is "nothing settled", not a failure: a collision settles no address without failing the signup.
		return nil, nil
	case errors.Is(err, user.ErrNotFound):
		email := in.Email

		return &email, nil
	default:
		// A failed read has already aborted tx in Postgres, so the signup
		// cannot continue without an address; every later statement in it
		// would fail with a less useful error.
		return nil, fmt.Errorf("auth: checking address collision: %w", err)
	}
}

// blockSignup rolls back tx and records signup.blocked with detail naming
// rule: the block itself is appended after the rollback, in its own
// statement, since a row written inside the rolled-back transaction would
// be rolled back with it.
func (s *Service) blockSignup(ctx context.Context, tx pgx.Tx, subject, clientIP, requestID, rule string, sentinel error) error {
	if err := wrapRollbackErr(tx.Rollback(ctx)); err != nil {
		s.logger.Error("auth: rolling back signup transaction", zap.Error(err))
	}

	s.recordAudit(ctx, audit.ActionSignupBlocked, nil, subject, audit.OutcomeFailure, clientIP, requestID,
		s.auditDetail(map[string]any{detailKeyRule: rule}))

	return sentinel
}

// wrapRollbackErr wraps a transaction rollback failure with context, or
// returns nil when the rollback succeeded.
func wrapRollbackErr(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("auth: rolling back signup transaction: %w", err)
}
