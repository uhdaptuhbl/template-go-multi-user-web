package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
)

// usersColumns names the columns selected from the users table, in the order
// User's db tags expect them.
const usersColumns = "id, display_name, email, email_verified_at, status, deleted_at, created_at, updated_at, rejected_at, bootstrap_admin_granted_at"

// identitiesColumns names the columns selected from the identities table, in
// the order Identity's db tags expect them.
const identitiesColumns = "id, user_id, provider, subject, email, created_at, last_used_at"

// constraintEmailUnique is the unique index enforcing that no two accounts
// share a case-folded email address.
const constraintEmailUnique = "users_email_lower_key"

// constraintIdentityUnique is the unique index enforcing that a provider and
// subject pair identifies at most one account.
const constraintIdentityUnique = "identities_provider_subject_key"

// uniqueViolationCode is the Postgres SQLState code for a unique-constraint
// violation.
const uniqueViolationCode = "23505"

// ErrInvalidDisplayName reports that a display name was empty after
// trimming surrounding whitespace, so the caller's write was rejected rather
// than storing an unusable name.
var ErrInvalidDisplayName = errors.New("display name must not be empty")

// ErrInvalidStatus reports that SetStatus was asked to write a status other
// than StatusActive or StatusSuspended.
var ErrInvalidStatus = errors.New("status must be active or suspended")

// ErrIsPending reports that SetStatus was asked to change an account whose
// current status is StatusPending. Approval must go through
// Repository.Approve instead.
var ErrIsPending = errors.New("account is pending approval")

// ErrIsDeleted reports that SetStatus or SetStatusTx was asked to change an
// account whose current status is StatusDeleted. Writing active or suspended
// over a deleted row would silently revive it while leaving deleted_at set,
// bypassing both the restore grace window and the sweeper's purge. A caller
// must go through Repository.Restore instead, which enforces the grace
// window itself.
var ErrIsDeleted = errors.New("account is deleted")

// ErrIsRejected reports that the target account was rejected from the approval queue. A caller
// should answer 409 conflict.
var ErrIsRejected = errors.New("user: account was rejected")

// Repository reads and writes accounts and their external identities.
type Repository struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewRepository returns a repository backed by h.
func NewRepository(h *store.Handle, now func() time.Time) *Repository {
	return &Repository{
		pool: h.Pool(),
		now:  now,
	}
}

// ByID returns the account with the given identifier, or ErrNotFound. A
// deleted account resolves for no caller of ByID; Restore and the purge
// reach a deleted account through their own statements instead.
func (r *Repository) ByID(ctx context.Context, id uuid.UUID) (User, error) {
	return byID(ctx, r.pool, id)
}

// ByIDTx is ByID against the caller-supplied transaction tx instead of the
// pool, so a caller that must read an account and act on what it read can do
// both inside one transaction.
//
//nolint:revive // Deliberately receiver-less, like ByEmailTx: it sits beside ByID as its Tx pair.
func (r *Repository) ByIDTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (User, error) {
	return byID(ctx, tx, id)
}

// byID runs the shared ByID query against q, which is either the
// repository's pool or a caller-supplied transaction.
func byID(ctx context.Context, q querier, id uuid.UUID) (User, error) {
	query := "SELECT " + usersColumns + " FROM users WHERE id = $1 AND status <> 'deleted'"

	rows, err := q.Query(ctx, query, id)
	if err != nil {
		return User{}, fmt.Errorf("user: querying account by id: %w", err)
	}

	u, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[User])
	if err != nil {
		return User{}, translateReadErr(err, "user: collecting account by id")
	}

	return u, nil
}

// querier is satisfied by both *pgxpool.Pool and pgx.Tx, so a read and its
// Tx variant (ByID and ByIDTx, ByEmail and ByEmailTx, CountActiveAdmins and
// CountActiveAdminsTx) can share one query against either.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// byEmail runs the shared ByEmail query against q, which is either the
// repository's pool or a caller-supplied transaction.
func byEmail(ctx context.Context, q querier, email string) (User, error) {
	query := "SELECT " + usersColumns + " FROM users WHERE lower(email) = lower($1)"

	rows, err := q.Query(ctx, query, email)
	if err != nil {
		return User{}, fmt.Errorf("user: querying account by email: %w", err)
	}

	u, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[User])
	if err != nil {
		return User{}, translateReadErr(err, "user: collecting account by email")
	}

	return u, nil
}

// ByEmail returns the account claiming the address, compared case-insensitively,
// or ErrNotFound.
func (r *Repository) ByEmail(ctx context.Context, email string) (User, error) {
	return byEmail(ctx, r.pool, email)
}

// ByEmailTx returns the account claiming the address, compared
// case-insensitively, or ErrNotFound, reading against the caller-supplied
// transaction tx rather than the pool. It exists so a caller settling an
// address as part of a larger admission decision can do so inside the same
// transaction that later creates the account, closing the window in which a
// concurrent signup could claim the same address between the check and the
// insert. It takes no receiver-held state: it is a Repository method, rather
// than a package function, only so it sits alongside ByEmail as the pair
// CreateWithIdentity and CreateWithIdentityTx already establish the pattern
// for.
//
//nolint:revive // Deliberately receiver-less: see the doc comment above.
func (r *Repository) ByEmailTx(ctx context.Context, tx pgx.Tx, email string) (User, error) {
	return byEmail(ctx, tx, email)
}

// ByIdentity returns the account and identity for a provider and subject
// pair, or ErrNotFound. It is the only lookup authentication uses. The
// account is returned whatever its status, including deleted: callers must
// check Status themselves, because a deleted account's identity must be
// reported as suspended rather than treated as unknown and sent through
// signup admission.
func (r *Repository) ByIdentity(ctx context.Context, provider, subject string) (User, Identity, error) {
	identityQuery := "SELECT " + identitiesColumns + " FROM identities WHERE provider = $1 AND subject = $2"

	identityRows, err := r.pool.Query(ctx, identityQuery, provider, subject)
	if err != nil {
		return User{}, Identity{}, fmt.Errorf("user: querying identity by provider and subject: %w", err)
	}

	identity, err := pgx.CollectExactlyOneRow(identityRows, pgx.RowToStructByName[Identity])
	if err != nil {
		return User{}, Identity{}, translateReadErr(err, "user: collecting identity by provider and subject")
	}

	u, err := r.ByIDAnyStatus(ctx, identity.UserID)
	if err != nil {
		return User{}, Identity{}, fmt.Errorf("user: loading account for identity: %w", err)
	}

	return u, identity, nil
}

// ByIDAnyStatus returns the account with the given identifier regardless of
// its status, including deleted, or ErrNotFound. It exists for authentication
// paths that must distinguish an account that is gone from one that is merely
// active, so a deleted or suspended account can be refused with ErrSuspended
// rather than treated as though it never existed.
func (r *Repository) ByIDAnyStatus(ctx context.Context, id uuid.UUID) (User, error) {
	query := "SELECT " + usersColumns + " FROM users WHERE id = $1"

	rows, err := r.pool.Query(ctx, query, id)
	if err != nil {
		return User{}, fmt.Errorf("user: querying account by id: %w", err)
	}

	u, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[User])
	if err != nil {
		return User{}, translateReadErr(err, "user: collecting account by id")
	}

	return u, nil
}

// List returns a page of accounts ordered by identifier, starting after cursor
// when it is non-empty, together with the cursor for the next page or an empty
// string when the page is the last. An empty status returns every account but
// the deleted ones; a status of "deleted" returns exactly the deleted ones.
func (r *Repository) List(ctx context.Context, status, cursor string, limit int) ([]User, string, error) {
	var statusFilter any
	if status != "" {
		statusFilter = status
	}

	var rows pgx.Rows

	var err error

	if cursor == "" {
		query := "SELECT " + usersColumns + " FROM users WHERE ($1::text IS NULL OR status = $1) AND ($1 = 'deleted' OR status <> 'deleted') ORDER BY id ASC LIMIT $2"

		rows, err = r.pool.Query(ctx, query, statusFilter, limit+1)
	} else {
		after, parseErr := uuid.Parse(cursor)
		if parseErr != nil {
			return nil, "", fmt.Errorf("user: parsing list cursor: %w", parseErr)
		}

		query := "SELECT " + usersColumns + " FROM users WHERE ($1::text IS NULL OR status = $1) AND ($1 = 'deleted' OR status <> 'deleted') AND id > $2 ORDER BY id ASC LIMIT $3"

		rows, err = r.pool.Query(ctx, query, statusFilter, after, limit+1)
	}

	if err != nil {
		return nil, "", fmt.Errorf("user: querying account list: %w", err)
	}

	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[User])
	if err != nil {
		return nil, "", fmt.Errorf("user: collecting account list: %w", err)
	}

	if len(users) <= limit {
		return users, "", nil
	}

	page := users[:limit]

	return page, page[len(page)-1].ID.String(), nil
}

// CreateWithIdentityTx inserts an account and its first identity against the
// caller-supplied transaction tx, performing exactly the two inserts
// CreateWithIdentity performs. It does not begin, commit, or roll back tx:
// rollback is the caller's business, because the caller is the one who knows
// whether later steps sharing tx (an invite redemption, for example) also
// succeeded.
func (r *Repository) CreateWithIdentityTx(ctx context.Context, tx pgx.Tx, u User, id Identity) error {
	now := r.now().UTC()

	userQuery := "INSERT INTO users (" + usersColumns + ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"

	_, err := tx.Exec(ctx, userQuery, u.ID, u.DisplayName, u.Email, u.EmailVerifiedAt, u.Status, u.DeletedAt, now, now, u.RejectedAt, u.BootstrapAdminGrantedAt)
	if err != nil {
		return translateWriteErr(err, "user: inserting account")
	}

	identityQuery := "INSERT INTO identities (" + identitiesColumns + ") VALUES ($1, $2, $3, $4, $5, $6, $7)"

	_, err = tx.Exec(ctx, identityQuery, id.ID, id.UserID, id.Provider, id.Subject, id.Email, now, id.LastUsedAt)
	if err != nil {
		return translateWriteErr(err, "user: inserting identity")
	}

	return nil
}

// CreateWithIdentity inserts an account and its first identity in one
// transaction, so a failure cannot leave an account nobody can log in to.
func (r *Repository) CreateWithIdentity(ctx context.Context, u User, id Identity) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("user: beginning create transaction: %w", err)
	}

	if createWithIdentityTxErr := r.CreateWithIdentityTx(ctx, tx, u, id); createWithIdentityTxErr != nil {
		rollbackErr := tx.Rollback(ctx)

		return errors.Join(createWithIdentityTxErr, wrapRollbackErr(rollbackErr))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return fmt.Errorf("user: committing create transaction: %w", commitErr)
	}

	return nil
}

// Update writes the mutable fields of an account and advances its updated_at.
func (r *Repository) Update(ctx context.Context, u User) error {
	now := r.now().UTC()

	query := "UPDATE users SET display_name = $1, email = $2, email_verified_at = $3, status = $4, deleted_at = $5, updated_at = $6 WHERE id = $7"

	_, err := r.pool.Exec(ctx, query, u.DisplayName, u.Email, u.EmailVerifiedAt, u.Status, u.DeletedAt, now, u.ID)
	if err != nil {
		return translateWriteErr(err, "user: updating account")
	}

	return nil
}

// LinkIdentity attaches an identity to an existing account, returning
// ErrIdentityLinked when the provider and subject pair already belongs to
// another account.
func (r *Repository) LinkIdentity(ctx context.Context, id Identity) error {
	now := r.now().UTC()

	query := "INSERT INTO identities (" + identitiesColumns + ") VALUES ($1, $2, $3, $4, $5, $6, $7)"

	_, err := r.pool.Exec(ctx, query, id.ID, id.UserID, id.Provider, id.Subject, id.Email, now, id.LastUsedAt)
	if err != nil {
		return translateWriteErr(err, "user: linking identity")
	}

	return nil
}

// IdentitiesFor returns every identity linked to an account.
func (r *Repository) IdentitiesFor(ctx context.Context, userID uuid.UUID) ([]Identity, error) {
	query := "SELECT " + identitiesColumns + " FROM identities WHERE user_id = $1 ORDER BY created_at ASC"

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("user: querying identities for account: %w", err)
	}

	identities, err := pgx.CollectRows(rows, pgx.RowToStructByName[Identity])
	if err != nil {
		return nil, fmt.Errorf("user: collecting identities for account: %w", err)
	}

	return identities, nil
}

// TouchIdentity advances an identity's last_used_at to now.
func (r *Repository) TouchIdentity(ctx context.Context, identityID uuid.UUID) error {
	now := r.now().UTC()

	query := "UPDATE identities SET last_used_at = $1 WHERE id = $2"

	if _, err := r.pool.Exec(ctx, query, now, identityID); err != nil {
		return fmt.Errorf("user: touching identity: %w", err)
	}

	return nil
}

// UpdateDisplayName sets an account's display name and advances updated_at,
// scoped to id so the statement cannot touch another account.
func (r *Repository) UpdateDisplayName(ctx context.Context, id uuid.UUID, displayName string) (User, error) {
	trimmed := strings.TrimSpace(displayName)
	if trimmed == "" {
		return User{}, ErrInvalidDisplayName
	}

	now := r.now().UTC()

	query := "UPDATE users SET display_name = $1, updated_at = $2 WHERE id = $3 RETURNING " + usersColumns

	rows, err := r.pool.Query(ctx, query, trimmed, now, id)
	if err != nil {
		return User{}, fmt.Errorf("user: updating display name: %w", err)
	}

	u, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[User])
	if err != nil {
		return User{}, translateReadErr(err, "user: collecting account after display name update")
	}

	return u, nil
}

// SetStatus sets an account's status and advances updated_at. It returns the
// updated account so a caller can render it without a second read. It
// refuses with ErrIsPending against a pending target and with ErrIsDeleted
// against a deleted one, changing nothing in either case: a deleted account
// can only be revived through Repository.Restore, which enforces the grace
// window this method does not know about.
func (r *Repository) SetStatus(ctx context.Context, id uuid.UUID, status Status) (User, error) {
	if status != StatusActive && status != StatusSuspended {
		return User{}, ErrInvalidStatus
	}

	current, err := r.ByIDAnyStatus(ctx, id)
	if err != nil {
		return User{}, fmt.Errorf("user: loading account before status change: %w", err)
	}

	if current.Status == StatusPending {
		return User{}, ErrIsPending
	}

	if current.Status == StatusDeleted {
		return User{}, ErrIsDeleted
	}

	now := r.now().UTC()

	query := "UPDATE users SET status = $1, updated_at = $2 WHERE id = $3 RETURNING " + usersColumns

	rows, err := r.pool.Query(ctx, query, status, now, id)
	if err != nil {
		return User{}, fmt.Errorf("user: updating account status: %w", err)
	}

	u, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[User])
	if err != nil {
		return User{}, translateReadErr(err, "user: collecting account after status update")
	}

	return u, nil
}

// SoftDelete marks an account deleted, setting status and deleted_at from the
// injected clock in one statement. The row and its identities and credentials
// survive so the deletion can be undone; the caller revokes its sessions.
func (r *Repository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	now := r.now().UTC()

	query := "UPDATE users SET status = 'deleted', deleted_at = $1, updated_at = $1 WHERE id = $2"

	tag, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("user: soft deleting account: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Approve moves an account from StatusPending to StatusActive and advances
// updated_at. It matches only rows whose status is still pending, so two
// administrators approving the same account race harmlessly and the second
// reports false. It is a separate method from SetStatus deliberately: SetStatus
// refuses a pending target so that approval cannot happen through the ordinary
// status route, and a method that refuses pending targets cannot also be the
// one that approves them.
func (r *Repository) Approve(ctx context.Context, id uuid.UUID) (bool, error) {
	now := r.now().UTC()

	query := "UPDATE users SET status = $1, updated_at = $2 WHERE id = $3 AND status = $4"

	tag, err := r.pool.Exec(ctx, query, StatusActive, now, id, StatusPending)
	if err != nil {
		return false, fmt.Errorf("user: approving account: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// Reject moves an account from StatusPending to StatusDeleted, setting
// deleted_at and updated_at from the injected clock in one statement. It
// matches only rows whose status is still pending, mirroring Approve's
// race-free shape: two administrators rejecting the same account race
// harmlessly and the second reports false. Rejection reuses SoftDelete's
// status and deleted_at combination rather than a distinct rejected state, so
// the sweeper's existing purge-by-deleted-status path disposes of a rejected
// account without any change to that path. It is a separate method from
// SoftDelete deliberately, for the same reason Approve is separate from
// SetStatus: a caller holding only the approval permission must not be able
// to delete an account that is not pending. It also sets rejected_at, in the
// same statement, to the same instant: Restore consults that column to
// refuse ever reviving a rejected account, per AC-008.78.
func (r *Repository) Reject(ctx context.Context, id uuid.UUID) (bool, error) {
	now := r.now().UTC()

	query := "UPDATE users SET status = $1, deleted_at = $2, rejected_at = $2, updated_at = $2 WHERE id = $3 AND status = $4"

	tag, err := r.pool.Exec(ctx, query, StatusDeleted, now, id, StatusPending)
	if err != nil {
		return false, fmt.Errorf("user: rejecting account: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// Restore returns a deleted account to active, clearing deleted_at. It
// matches only rows whose status is still deleted, whose deleted_at is at or
// after notBefore, and whose rejected_at is nil, so it can only ever revive a
// row that is actually deleted and was never rejected: an account past its
// grace period cannot be revived a moment before the sweeper reaches it, and
// a rejected account, per AC-008.78, can never be revived at all. When the
// update matches no row, Restore reads the row to tell a rejected account
// apart from every other reason the update could have matched nothing: it
// returns ErrIsRejected for a rejected row, and otherwise reports false with
// a nil error exactly as before.
func (r *Repository) Restore(ctx context.Context, id uuid.UUID, notBefore time.Time) (bool, error) {
	now := r.now().UTC()

	query := "UPDATE users SET status = $1, deleted_at = NULL, updated_at = $2" +
		" WHERE id = $3 AND status = $4 AND deleted_at >= $5 AND rejected_at IS NULL"

	tag, err := r.pool.Exec(ctx, query, StatusActive, now, id, StatusDeleted, notBefore)
	if err != nil {
		return false, fmt.Errorf("user: restoring account: %w", err)
	}

	if tag.RowsAffected() > 0 {
		return true, nil
	}

	rejected, err := r.isRejected(ctx, id)
	if err != nil {
		return false, err
	}

	if rejected {
		return false, ErrIsRejected
	}

	return false, nil
}

// isRejected reports whether the account identified by id was rejected from
// the approval queue, so Restore can tell that terminal case apart from
// every other reason its update might have matched no row. An unknown id
// reports false, preserving Restore's existing behavior for that case.
func (r *Repository) isRejected(ctx context.Context, id uuid.UUID) (bool, error) {
	var rejectedAt *time.Time

	err := r.pool.QueryRow(ctx, "SELECT rejected_at FROM users WHERE id = $1", id).Scan(&rejectedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}

		return false, fmt.Errorf("user: checking rejection status: %w", err)
	}

	return rejectedAt != nil, nil
}

// PurgeDeletedBefore permanently removes every account deleted before cutoff,
// returning their identifiers so the caller can audit each one, and how many
// it removed. Identities, credentials, and sessions go with them through
// ON DELETE CASCADE rather than through separate statements, so a partial
// purge is not representable.
func (r *Repository) PurgeDeletedBefore(ctx context.Context, cutoff time.Time) ([]uuid.UUID, error) {
	query := "DELETE FROM users WHERE status = 'deleted' AND deleted_at < $1 RETURNING id"

	rows, err := r.pool.Query(ctx, query, cutoff)
	if err != nil {
		return nil, fmt.Errorf("user: purging deleted accounts: %w", err)
	}

	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("user: collecting purged account ids: %w", err)
	}

	return ids, nil
}

// PendingPurge returns the identifiers of every account PurgeDeletedBefore
// would remove for the same cutoff, without removing them, so a caller can
// record an audit event naming each account while its row still exists:
// audit_events.actor_id carries a foreign key to users(id), and an insert
// naming a row already gone would violate it.
func (r *Repository) PendingPurge(ctx context.Context, cutoff time.Time) ([]uuid.UUID, error) {
	query := "SELECT id FROM users WHERE status = 'deleted' AND deleted_at < $1"

	rows, err := r.pool.Query(ctx, query, cutoff)
	if err != nil {
		return nil, fmt.Errorf("user: listing accounts pending purge: %w", err)
	}

	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("user: collecting accounts pending purge: %w", err)
	}

	return ids, nil
}

// UnlinkIdentity removes one identity, scoped to userID so a caller cannot
// detach an identity it does not own. It reports whether a row was removed.
func (r *Repository) UnlinkIdentity(ctx context.Context, userID, identityID uuid.UUID) (bool, error) {
	query := "DELETE FROM identities WHERE id = $1 AND user_id = $2"

	tag, err := r.pool.Exec(ctx, query, identityID, userID)
	if err != nil {
		return false, fmt.Errorf("user: unlinking identity: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// CountIdentities returns how many external identities an account holds.
func (r *Repository) CountIdentities(ctx context.Context, userID uuid.UUID) (int, error) {
	query := "SELECT count(*) FROM identities WHERE user_id = $1"

	var count int

	if err := r.pool.QueryRow(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("user: counting identities: %w", err)
	}

	return count, nil
}

// CountIdentitiesTx is CountIdentities reading against the caller-supplied
// transaction tx instead of the pool, so a caller enforcing the last-factor
// rule can count identities in the same transaction that locks the account
// row and removes one, closing the race two concurrent removals could
// otherwise win. It takes no receiver-held state: it is a Repository method,
// rather than a package function, only so it sits alongside CountIdentities
// as the pair ByEmail and ByEmailTx already establish the pattern for.
//
//nolint:revive // Deliberately receiver-less: see the doc comment above.
func (r *Repository) CountIdentitiesTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int, error) {
	query := "SELECT count(*) FROM identities WHERE user_id = $1"

	var count int

	if err := tx.QueryRow(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("user: counting identities in transaction: %w", err)
	}

	return count, nil
}

// CountIdentitiesFrom returns how many of an account's identities were
// issued by one of providers. The last-factor rule uses it to count only the
// identities that can still reach the account: those from a configured
// provider, and email-code identities only while email codes are enabled.
// An empty providers counts nothing.
func (r *Repository) CountIdentitiesFrom(ctx context.Context, userID uuid.UUID, providers []string) (int, error) {
	return countIdentitiesFrom(ctx, r.pool, userID, providers)
}

// CountIdentitiesFromTx is CountIdentitiesFrom reading against the
// caller-supplied transaction tx instead of the pool, for the same reason
// CountIdentitiesTx exists.
//
//nolint:revive // Deliberately receiver-less: see CountIdentitiesTx's doc comment.
func (r *Repository) CountIdentitiesFromTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, providers []string) (int, error) {
	return countIdentitiesFrom(ctx, tx, userID, providers)
}

// countIdentitiesFrom runs the shared CountIdentitiesFrom query against q,
// which is either the repository's pool or a caller-supplied transaction.
func countIdentitiesFrom(ctx context.Context, q querier, userID uuid.UUID, providers []string) (int, error) {
	query := "SELECT count(*) FROM identities WHERE user_id = $1 AND provider = ANY($2)"

	var count int

	if err := q.QueryRow(ctx, query, userID, providers).Scan(&count); err != nil {
		return 0, fmt.Errorf("user: counting identities by provider: %w", err)
	}

	return count, nil
}

// UnlinkIdentityTx is UnlinkIdentity against the caller-supplied transaction
// tx instead of the pool. It takes no receiver-held state: it is a
// Repository method, rather than a package function, only so it sits
// alongside UnlinkIdentity as the pair ByEmail and ByEmailTx already
// establish the pattern for.
//
//nolint:revive // Deliberately receiver-less: see the doc comment above.
func (r *Repository) UnlinkIdentityTx(ctx context.Context, tx pgx.Tx, userID, identityID uuid.UUID) (bool, error) {
	query := "DELETE FROM identities WHERE id = $1 AND user_id = $2"

	tag, err := tx.Exec(ctx, query, identityID, userID)
	if err != nil {
		return false, fmt.Errorf("user: unlinking identity in transaction: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// SoftDeleteTx is SoftDelete against the caller-supplied transaction tx
// instead of the pool.
func (r *Repository) SoftDeleteTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	now := r.now().UTC()

	query := "UPDATE users SET status = 'deleted', deleted_at = $1, updated_at = $1 WHERE id = $2"

	tag, err := tx.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("user: soft deleting account in transaction: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// SetStatusTx is SetStatus against the caller-supplied transaction tx
// instead of the pool. It refuses with ErrIsPending and ErrIsDeleted under
// the same conditions SetStatus does.
func (r *Repository) SetStatusTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, status Status) (User, error) {
	if status != StatusActive && status != StatusSuspended {
		return User{}, ErrInvalidStatus
	}

	var currentStatus Status

	if err := tx.QueryRow(ctx, "SELECT status FROM users WHERE id = $1", id).Scan(&currentStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}

		return User{}, fmt.Errorf("user: loading account before status change in transaction: %w", err)
	}

	if currentStatus == StatusPending {
		return User{}, ErrIsPending
	}

	if currentStatus == StatusDeleted {
		return User{}, ErrIsDeleted
	}

	now := r.now().UTC()

	query := "UPDATE users SET status = $1, updated_at = $2 WHERE id = $3 RETURNING " + usersColumns

	rows, err := tx.Query(ctx, query, status, now, id)
	if err != nil {
		return User{}, fmt.Errorf("user: updating account status in transaction: %w", err)
	}

	u, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[User])
	if err != nil {
		return User{}, translateReadErr(err, "user: collecting account after status update in transaction")
	}

	return u, nil
}

// MarkBootstrapAdminGrantedTx records, against the caller-supplied
// transaction tx, that the bootstrap administrator list has granted the
// account admin, stamping bootstrap_admin_granted_at with the repository
// clock in UTC. It changes nothing and reports false when the account was
// already marked (or does not exist), so the list can grant an account admin
// at most once. It does not begin, commit, or roll back tx.
func (r *Repository) MarkBootstrapAdminGrantedTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	now := r.now().UTC()

	query := "UPDATE users SET bootstrap_admin_granted_at = $2, updated_at = $2 WHERE id = $1 AND bootstrap_admin_granted_at IS NULL"

	tag, err := tx.Exec(ctx, query, id, now)
	if err != nil {
		return false, fmt.Errorf("user: marking bootstrap admin grant in transaction: %w", err)
	}

	return tag.RowsAffected() == 1, nil
}

// CountActiveAdmins returns how many active accounts hold the named role. It
// exists so the callers that must refuse to remove the last administrator can
// ask one question instead of listing every admin.
func (r *Repository) CountActiveAdmins(ctx context.Context, roleName string) (int, error) {
	return countActiveAdmins(ctx, r.pool, roleName)
}

// CountActiveAdminsTx is CountActiveAdmins against the caller-supplied
// transaction tx instead of the pool, so a last-administrator check can count
// inside the same transaction as the change it guards.
//
//nolint:revive // Deliberately receiver-less, like ByEmailTx: it sits beside CountActiveAdmins as its Tx pair.
func (r *Repository) CountActiveAdminsTx(ctx context.Context, tx pgx.Tx, roleName string) (int, error) {
	return countActiveAdmins(ctx, tx, roleName)
}

// countActiveAdmins runs the shared CountActiveAdmins query against q, which
// is either the repository's pool or a caller-supplied transaction.
func countActiveAdmins(ctx context.Context, q querier, roleName string) (int, error) {
	query := "SELECT count(*) FROM user_roles" +
		" JOIN roles ON roles.id = user_roles.role_id" +
		" JOIN users ON users.id = user_roles.user_id" +
		" WHERE roles.name = $1 AND users.status = $2"

	var count int

	if err := q.QueryRow(ctx, query, roleName, StatusActive).Scan(&count); err != nil {
		return 0, fmt.Errorf("user: counting active admins: %w", err)
	}

	return count, nil
}

// translateReadErr converts pgx.ErrNoRows into ErrNotFound and wraps any
// other error from a read with opDesc.
func translateReadErr(err error, opDesc string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}

	return fmt.Errorf("%s: %w", opDesc, err)
}

// translateWriteErr converts a unique-constraint violation on the email or
// identity indexes into the matching sentinel error, and wraps any other
// error from a write with opDesc.
func translateWriteErr(err error, opDesc string) error {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if ok && pgErr.Code == uniqueViolationCode {
		switch pgErr.ConstraintName {
		case constraintEmailUnique:
			return ErrEmailTaken
		case constraintIdentityUnique:
			return ErrIdentityLinked
		}
	}

	return fmt.Errorf("%s: %w", opDesc, err)
}

// wrapRollbackErr wraps a transaction rollback failure with context, or
// returns nil when the rollback succeeded.
func wrapRollbackErr(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("user: rolling back create transaction: %w", err)
}
