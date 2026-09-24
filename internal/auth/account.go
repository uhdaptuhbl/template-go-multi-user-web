package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/otp"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// ErrLastFactor reports a removal that would leave an account unable to sign
// in.
var ErrLastFactor = errors.New("last authentication factor")

// ErrLastAdmin reports an action that would leave no active administrator.
// Nothing was changed; a caller should answer 409 conflict.
var ErrLastAdmin = errors.New("last active administrator")

// ErrSelfAction reports an administrative action an actor may not take on
// itself.
var ErrSelfAction = errors.New("action not permitted on self")

// ErrGraceExpired reports a restore attempted after the grace period, or an
// unknown account identifier, which RestoreAccount reports identically so
// the route is not a probe for which accounts once existed.
var ErrGraceExpired = errors.New("grace period expired")

// lastAdminAdvisoryLockKey is the pg_advisory_xact_lock key DeleteAccount,
// SetStatus, and ReplaceRoles hold for their whole transaction, serializing
// them against each other so two concurrent calls cannot each observe an
// active-admin count of two and both proceed. It is an arbitrary constant
// with no meaning beyond identifying this one lock.
const lastAdminAdvisoryLockKey int64 = 0x64797363_75767261

// Factors reports how many usable authentication methods an account has: its
// registered credentials plus the external identities that can still reach
// it. An emailed code reaches an account only through an identity keyed on
// (otp.Provider, address), never through the account's own verified address,
// because a login is never resolved by email (ADR 0012). So a verified
// address counts for nothing on its own, an email-code identity counts only
// while email codes are enabled, and a provider identity counts only while
// its provider is still configured.
func (s *Service) Factors(ctx context.Context, userID uuid.UUID) (int, error) {
	if _, err := s.users.ByIDAnyStatus(ctx, userID); err != nil {
		return 0, fmt.Errorf("auth: loading account for factor count: %w", err)
	}

	credCount, err := s.accounts.Credentials.CountFor(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("auth: counting credentials for factor count: %w", err)
	}

	identCount, err := s.users.CountIdentitiesFrom(ctx, userID, s.signInProviders())
	if err != nil {
		return 0, fmt.Errorf("auth: counting identities for factor count: %w", err)
	}

	return credCount + identCount, nil
}

// signInProviders returns the identity providers an identity can currently
// sign in through: every configured OpenID Connect provider, plus
// otp.Provider while email codes are enabled.
func (s *Service) signInProviders() []string {
	var providers []string

	if s.accounts.Providers != nil {
		providers = s.accounts.Providers.Keys()
	}

	if s.accounts.OTPEnabled {
		providers = append(providers, otp.Provider)
	}

	return providers
}

// countFactorsTx counts userID's usable authentication methods within tx, as
// Factors does, for the removal paths that must count and remove in one
// transaction.
func (s *Service) countFactorsTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int, error) {
	credCount, err := s.accounts.Credentials.CountForTx(ctx, tx, userID)
	if err != nil {
		return 0, fmt.Errorf("auth: counting credentials: %w", err)
	}

	identCount, err := s.users.CountIdentitiesFromTx(ctx, tx, userID, s.signInProviders())
	if err != nil {
		return 0, fmt.Errorf("auth: counting identities: %w", err)
	}

	return credCount + identCount, nil
}

// lockAccount locks the account row within tx with SELECT ... FOR UPDATE, so
// RemoveCredential and RemoveIdentity can count an account's factors and
// remove one in a single transaction that serializes against a concurrent
// removal for the same account.
func lockAccount(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	var id uuid.UUID

	err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return user.ErrNotFound
		}

		return fmt.Errorf("auth: locking account row: %w", err)
	}

	return nil
}

// rollbackTx rolls tx back, wrapping any failure with context, for the
// explicit-join pattern this repo's error composition standard requires
// instead of a defer trick, since named returns are banned here.
func rollbackTx(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Rollback(ctx); err != nil {
		return fmt.Errorf("auth: rolling back transaction: %w", err)
	}

	return nil
}

// RemoveCredential deletes one of the account's passkeys, refusing with
// ErrLastFactor when it is the only way that account can sign in. The count
// and the removal run in one transaction, holding the account row locked, so
// two concurrent removals cannot each observe two factors and both proceed.
func (s *Service) RemoveCredential(ctx context.Context, userID, credentialID uuid.UUID, clientIP, requestID string) error {
	tx, err := s.handle.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("auth: beginning credential removal transaction: %w", err)
	}

	if lockErr := lockAccount(ctx, tx, userID); lockErr != nil {
		return errors.Join(lockErr, rollbackTx(ctx, tx))
	}

	factors, err := s.countFactorsTx(ctx, tx, userID)
	if err != nil {
		return errors.Join(err, rollbackTx(ctx, tx))
	}

	if factors <= 1 {
		// Rolled back before the audit write, not after: the audit write
		// takes its own connection from the same pool this transaction's
		// FOR UPDATE lock is still holding one of, and auditing first would
		// deadlock a concurrent caller waiting on that lock against a pool
		// with no spare connection left to give it.
		rollbackErr := rollbackTx(ctx, tx)

		s.recordAudit(ctx, audit.ActionPasskeyRemoved, &userID, "credential:"+credentialID.String(), audit.OutcomeFailure, clientIP, requestID, nil)

		return errors.Join(ErrLastFactor, rollbackErr)
	}

	removed, err := s.accounts.Credentials.DeleteTx(ctx, tx, userID, credentialID)
	if err != nil {
		return errors.Join(fmt.Errorf("auth: deleting credential: %w", err), rollbackTx(ctx, tx))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return fmt.Errorf("auth: committing credential removal: %w", commitErr)
	}

	if removed {
		s.recordAudit(ctx, audit.ActionPasskeyRemoved, &userID, "credential:"+credentialID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)
	}

	return nil
}

// RemoveIdentity detaches one of the account's external identities, refusing
// with ErrLastFactor on the same grounds and with the same single-transaction
// serialization RemoveCredential uses.
func (s *Service) RemoveIdentity(ctx context.Context, userID, identityID uuid.UUID, clientIP, requestID string) error {
	tx, err := s.handle.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("auth: beginning identity removal transaction: %w", err)
	}

	if lockErr := lockAccount(ctx, tx, userID); lockErr != nil {
		return errors.Join(lockErr, rollbackTx(ctx, tx))
	}

	factors, err := s.countFactorsTx(ctx, tx, userID)
	if err != nil {
		return errors.Join(err, rollbackTx(ctx, tx))
	}

	if factors <= 1 {
		// Rolled back before the audit write; see RemoveCredential's
		// matching comment for why the order matters under concurrency.
		rollbackErr := rollbackTx(ctx, tx)

		s.recordAudit(ctx, audit.ActionIdentityUnlinked, &userID, "identity:"+identityID.String(), audit.OutcomeFailure, clientIP, requestID, nil)

		return errors.Join(ErrLastFactor, rollbackErr)
	}

	removed, err := s.users.UnlinkIdentityTx(ctx, tx, userID, identityID)
	if err != nil {
		return errors.Join(fmt.Errorf("auth: unlinking identity: %w", err), rollbackTx(ctx, tx))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return fmt.Errorf("auth: committing identity removal: %w", commitErr)
	}

	if removed {
		s.recordAudit(ctx, audit.ActionIdentityUnlinked, &userID, "identity:"+identityID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)
	}

	return nil
}

// UpdateDisplayName changes the signed-in account's display name.
func (s *Service) UpdateDisplayName(ctx context.Context, userID uuid.UUID, displayName, clientIP, requestID string) (user.User, error) {
	updated, err := s.users.UpdateDisplayName(ctx, userID, displayName)
	if err != nil {
		return user.User{}, fmt.Errorf("auth: updating display name: %w", err)
	}

	s.recordAudit(ctx, audit.ActionUserUpdated, &userID, "user:"+userID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)

	return updated, nil
}

// DeleteAccount soft-deletes the signed-in account and revokes every session
// it holds, refusing with ErrLastAdmin when it is the last active
// administrator. The record survives until the grace period elapses, so the
// deletion is reversible through RestoreAccount until then. The last-admin
// check, the soft delete, and the session revocation run in one transaction
// holding the last-admin advisory lock, so a concurrent DeleteAccount or
// SetStatus cannot race it.
func (s *Service) DeleteAccount(ctx context.Context, userID uuid.UUID, clientIP, requestID string) error {
	tx, err := s.handle.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("auth: beginning account deletion transaction: %w", err)
	}

	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lastAdminAdvisoryLockKey)
	if err != nil {
		return errors.Join(fmt.Errorf("auth: acquiring last-admin lock: %w", err), rollbackTx(ctx, tx))
	}

	var conflict bool

	conflict, err = s.targetIsLastAdmin(ctx, tx, userID)
	if err != nil {
		return errors.Join(err, rollbackTx(ctx, tx))
	}

	if conflict {
		return errors.Join(ErrLastAdmin, rollbackTx(ctx, tx))
	}

	err = s.users.SoftDeleteTx(ctx, tx, userID)
	if err != nil {
		return errors.Join(fmt.Errorf("auth: soft deleting account: %w", err), rollbackTx(ctx, tx))
	}

	revoked, err := s.sessions.RevokeAllForTx(ctx, tx, userID)
	if err != nil {
		return errors.Join(fmt.Errorf("auth: revoking sessions on deletion: %w", err), rollbackTx(ctx, tx))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return fmt.Errorf("auth: committing account deletion: %w", commitErr)
	}

	s.logger.Debug("auth: revoked sessions on account deletion", zap.Int64("revoked", revoked))

	s.recordAudit(ctx, audit.ActionUserDeleted, &userID, "user:"+userID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)

	return nil
}

// RestoreAccount returns a deleted account to active on an administrator's
// behalf, refusing with ErrGraceExpired once the account is old enough for
// the sweeper to purge. It does not resurrect sessions: the account signs in
// again. The eligibility window is evaluated by the same statement that
// performs the write, so it cannot race the sweeper. It also propagates
// user.ErrIsRejected unchanged, per AC-008.78: a rejected account is final
// and RestoreAccount refuses to revive it regardless of the grace window.
func (s *Service) RestoreAccount(ctx context.Context, actorID, subjectID uuid.UUID, clientIP, requestID string) (user.User, error) {
	notBefore := s.now().Add(-s.accounts.DeletedGracePeriod).UTC()

	restored, err := s.users.Restore(ctx, subjectID, notBefore)
	if err != nil {
		return user.User{}, fmt.Errorf("auth: restoring account: %w", err)
	}

	if !restored {
		return user.User{}, ErrGraceExpired
	}

	account, err := s.users.ByID(ctx, subjectID)
	if err != nil {
		return user.User{}, fmt.Errorf("auth: loading restored account: %w", err)
	}

	s.recordAudit(ctx, audit.ActionUserRestored, &actorID, "user:"+subjectID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)

	return account, nil
}

// PurgeExpired permanently removes every account whose grace period has
// elapsed, recording user.purged for each, and returns how many it removed.
// The sweeper calls it; nothing else should. Every account about to be
// purged is looked up and audited before the purge runs, because
// audit_events.actor_id has a foreign key to users(id): an insert naming a
// row that no longer exists would violate it, while the rows already written
// survive the purge with actor_id nulled by ON DELETE SET NULL.
func (s *Service) PurgeExpired(ctx context.Context) (int, error) {
	cutoff := s.purgeCutoff()

	pending, err := s.users.PendingPurge(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("auth: listing accounts pending purge: %w", err)
	}

	for _, id := range pending {
		s.recordAudit(ctx, audit.ActionUserPurged, &id, "user:"+id.String(), audit.OutcomeSuccess, "", "", nil)
	}

	purged, err := s.users.PurgeDeletedBefore(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("auth: purging expired accounts: %w", err)
	}

	return len(purged), nil
}

// purgeCutoff returns the instant PurgeExpired and the sweeper's failure log
// both use as the deleted-account grace boundary, so the two cannot disagree
// on what "expired" means.
func (s *Service) purgeCutoff() time.Time {
	return s.now().Add(-s.accounts.DeletedGracePeriod).UTC()
}

// SetStatus suspends or reactivates an account on an administrator's behalf,
// refusing with ErrLastAdmin when suspending would leave no active
// administrator, with ErrSelfAction when actor and subject are the same, and
// with user.ErrIsDeleted, propagated unchanged from SetStatusTx, when the
// target is already deleted: reviving it must go through RestoreAccount
// instead, which enforces the grace window this method does not know about.
// Suspension revokes every session the account holds in the same transaction
// as the status change and the last-admin check, holding the last-admin
// advisory lock, so a concurrent DeleteAccount or SetStatus cannot race it.
func (s *Service) SetStatus(ctx context.Context, actorID, subjectID uuid.UUID, status user.Status, clientIP, requestID string) (user.User, error) {
	if actorID == subjectID {
		return user.User{}, ErrSelfAction
	}

	tx, err := s.handle.Pool().Begin(ctx)
	if err != nil {
		return user.User{}, fmt.Errorf("auth: beginning status change transaction: %w", err)
	}

	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lastAdminAdvisoryLockKey)
	if err != nil {
		return user.User{}, errors.Join(fmt.Errorf("auth: acquiring last-admin lock: %w", err), rollbackTx(ctx, tx))
	}

	if status == user.StatusSuspended {
		var conflict bool

		conflict, err = s.targetIsLastAdmin(ctx, tx, subjectID)
		if err != nil {
			return user.User{}, errors.Join(err, rollbackTx(ctx, tx))
		}

		if conflict {
			return user.User{}, errors.Join(ErrLastAdmin, rollbackTx(ctx, tx))
		}
	}

	updated, err := s.users.SetStatusTx(ctx, tx, subjectID, status)
	if err != nil {
		return user.User{}, errors.Join(fmt.Errorf("auth: updating account status: %w", err), rollbackTx(ctx, tx))
	}

	var revoked int64

	if status == user.StatusSuspended {
		revoked, err = s.sessions.RevokeAllForTx(ctx, tx, subjectID)
		if err != nil {
			return user.User{}, errors.Join(fmt.Errorf("auth: revoking sessions on suspension: %w", err), rollbackTx(ctx, tx))
		}
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return user.User{}, fmt.Errorf("auth: committing status change: %w", commitErr)
	}

	if status == user.StatusSuspended {
		s.logger.Debug("auth: revoked sessions on account suspension", zap.Int64("revoked", revoked))
		s.recordAudit(ctx, audit.ActionUserSuspended, &actorID, "user:"+subjectID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)
	} else {
		s.recordAudit(ctx, audit.ActionUserReactivated, &actorID, "user:"+subjectID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)
	}

	return updated, nil
}

// StartIdentityLink begins an OpenID Connect ceremony that will attach a new
// identity to the signed-in account, returning the provider URL to redirect
// to and the raw binding secret the caller must set as a short-lived cookie,
// exactly as oidc.Registry.Start documents. It returns oidc.ErrUnknownProvider
// when no provider is configured or provider names one that is not.
func (s *Service) StartIdentityLink(ctx context.Context, userID uuid.UUID, provider string) (string, string, error) {
	if s.accounts.Providers == nil {
		return "", "", oidc.ErrUnknownProvider
	}

	authURL, binding, err := s.accounts.Providers.StartLink(ctx, provider, userID)
	if err != nil {
		return "", "", fmt.Errorf("auth: starting identity link: %w", err)
	}

	return authURL, binding, nil
}

// FinishIdentityLink completes an identity-link ceremony, attaching the
// verified identity to the account the flow was started for. sessionUserID
// is the currently signed-in account; LinkIdentity refuses a mismatch
// between it and the flow's account with ErrLinkFlowMismatch and records
// identity.linked on both success and failure, so this method does not
// duplicate that check. FinishIdentityLink never issues or changes a
// session: linking is not a login.
func (s *Service) FinishIdentityLink(ctx context.Context, sessionUserID uuid.UUID, provider, state, code, binding, clientIP, requestID string) error {
	if s.accounts.Providers == nil {
		return oidc.ErrUnknownProvider
	}

	claims, flowUserID, err := s.accounts.Providers.FinishLink(ctx, provider, state, code, binding)
	if err != nil {
		return fmt.Errorf("auth: finishing identity link: %w", err)
	}

	in := Authenticated{
		Provider:      provider,
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   claims.Name,
	}

	return s.LinkIdentity(ctx, sessionUserID, flowUserID, in, clientIP, requestID)
}

// ReplaceRoles replaces targetID's roles with exactly nextRoles on actorID's
// behalf and returns the roles the account held before, so the caller can
// audit what was added and removed. It refuses with ErrLastAdmin, changing
// nothing, when the change would remove admin from the last active
// administrator (AC-008.50). The role read, the last-admin check, and the
// write run in one transaction holding the last-admin advisory lock, so a
// concurrent ReplaceRoles, DeleteAccount, or SetStatus cannot race it. It
// propagates authz.ErrUnknownRole, changing nothing, for a role name that
// does not exist. It does not itself check that targetID names an existing
// account; the caller resolves the target first.
func (s *Service) ReplaceRoles(ctx context.Context, actorID, targetID uuid.UUID, nextRoles []string) ([]string, error) {
	tx, err := s.handle.Pool().Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: beginning role replacement transaction: %w", err)
	}

	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lastAdminAdvisoryLockKey)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("auth: acquiring last-admin lock: %w", err), rollbackTx(ctx, tx))
	}

	previousRoles, err := s.roles.RolesForTx(ctx, tx, targetID)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("auth: loading current roles: %w", err), rollbackTx(ctx, tx))
	}

	if slices.Contains(previousRoles, authz.RoleAdmin) && !slices.Contains(nextRoles, authz.RoleAdmin) {
		var conflict bool

		conflict, err = lastAdminConflict(ctx, tx, s.users, targetID)
		if err != nil {
			return nil, errors.Join(err, rollbackTx(ctx, tx))
		}

		if conflict {
			return nil, errors.Join(ErrLastAdmin, rollbackTx(ctx, tx))
		}
	}

	err = s.roles.SetRolesTx(ctx, tx, targetID, nextRoles, actorID)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("auth: setting roles: %w", err), rollbackTx(ctx, tx))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return nil, fmt.Errorf("auth: committing role replacement: %w", commitErr)
	}

	return previousRoles, nil
}

// targetIsLastAdmin reports whether targetID holds the admin role and, per
// lastAdminConflict, is the sole remaining active administrator, reading
// within tx. It exists so DeleteAccount and SetStatus share one
// role-lookup-then-conflict-check sequence instead of each nesting the same
// two checks inline.
func (s *Service) targetIsLastAdmin(ctx context.Context, tx pgx.Tx, targetID uuid.UUID) (bool, error) {
	roles, err := s.roles.RolesForTx(ctx, tx, targetID)
	if err != nil {
		return false, fmt.Errorf("auth: loading roles for last-admin check: %w", err)
	}

	if !slices.Contains(roles, authz.RoleAdmin) {
		return false, nil
	}

	return lastAdminConflict(ctx, tx, s.users, targetID)
}

// lastAdminConflict reports whether targetID is the sole remaining active
// account holding admin, which refuses an action that would leave the
// administrator set empty. It only reports true when the target is
// currently active: consult AC-008.50. It reads within tx, which the caller
// must already hold the last-admin advisory lock in. DeleteAccount,
// SetStatus, and ReplaceRoles all share this one implementation rather than
// three copies that can drift.
func lastAdminConflict(ctx context.Context, tx pgx.Tx, users *user.Repository, targetID uuid.UUID) (bool, error) {
	targetAccount, err := users.ByIDTx(ctx, tx, targetID)
	if err != nil {
		return false, fmt.Errorf("auth: loading target account for last-admin check: %w", err)
	}

	if targetAccount.Status != user.StatusActive {
		return false, nil
	}

	activeAdmins, err := users.CountActiveAdminsTx(ctx, tx, authz.RoleAdmin)
	if err != nil {
		return false, fmt.Errorf("auth: counting active admins: %w", err)
	}

	return activeAdmins <= 1, nil
}
