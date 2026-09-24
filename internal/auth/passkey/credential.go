package passkey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
)

// ErrNotFound reports that no credential matched.
var ErrNotFound = errors.New("credential not found")

// constraintCredentialIDUnique is the unique index enforcing that no two
// stored credentials share a WebAuthn credential identifier.
const constraintCredentialIDUnique = "credentials_credential_id_key"

// uniqueViolationCode is the Postgres SQLSTATE code for a unique-constraint
// violation.
const uniqueViolationCode = "23505"

// Credential is a registered WebAuthn credential. CredentialID, PublicKey, and
// AAGUID hold raw bytes in BYTEA columns, with no text encoding step applied
// on their way into or out of the database.
type Credential struct {
	ID              uuid.UUID  `db:"id"`
	UserID          uuid.UUID  `db:"user_id"`
	CredentialID    []byte     `db:"credential_id"`
	PublicKey       []byte     `db:"public_key"`
	AttestationType string     `db:"attestation_type"`
	Transports      []string   `db:"transports"`
	AAGUID          []byte     `db:"aaguid"`
	SignCount       int64      `db:"sign_count"`
	CloneWarning    bool       `db:"clone_warning"`
	BackupEligible  bool       `db:"backup_eligible"`
	BackupState     bool       `db:"backup_state"`
	Name            string     `db:"name"`
	CreatedAt       time.Time  `db:"created_at"`
	LastUsedAt      *time.Time `db:"last_used_at"`
}

// Repository reads and writes registered credentials.
type Repository struct {
	handle *store.Handle
	now    func() time.Time
}

// NewRepository returns a repository backed by h, using now as its clock.
func NewRepository(h *store.Handle, now func() time.Time) *Repository {
	return &Repository{handle: h, now: now}
}

// ByCredentialID returns the credential with the given WebAuthn credential
// identifier, or ErrNotFound.
func (r *Repository) ByCredentialID(ctx context.Context, credentialID []byte) (Credential, error) {
	const query = `
SELECT id, user_id, credential_id, public_key, attestation_type, transports, aaguid,
  sign_count, clone_warning, backup_eligible, backup_state, name, created_at, last_used_at
FROM credentials
WHERE credential_id = $1
`

	rows, err := r.handle.Pool().Query(ctx, query, credentialID)
	if err != nil {
		return Credential{}, fmt.Errorf("passkey: querying credential: %w", err)
	}

	cred, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[Credential])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Credential{}, ErrNotFound
		}

		return Credential{}, fmt.Errorf("passkey: scanning credential: %w", err)
	}

	return cred, nil
}

// ListFor returns every credential belonging to an account.
func (r *Repository) ListFor(ctx context.Context, userID uuid.UUID) ([]Credential, error) {
	const query = `
SELECT id, user_id, credential_id, public_key, attestation_type, transports, aaguid,
  sign_count, clone_warning, backup_eligible, backup_state, name, created_at, last_used_at
FROM credentials
WHERE user_id = $1
ORDER BY created_at
`

	rows, err := r.handle.Pool().Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("passkey: listing credentials: %w", err)
	}

	creds, err := pgx.CollectRows(rows, pgx.RowToStructByName[Credential])
	if err != nil {
		return nil, fmt.Errorf("passkey: scanning credentials: %w", err)
	}

	return creds, nil
}

// Create inserts a credential. It returns ErrVerification when the
// credential identifier is already registered against any account, so a
// caller cannot use this path to tell "already registered somewhere in this
// system" apart from "accepted" through a distinct, more specific error.
func (r *Repository) Create(ctx context.Context, c Credential) error {
	const query = `
INSERT INTO credentials (id, user_id, credential_id, public_key, attestation_type, transports, aaguid,
  sign_count, clone_warning, backup_eligible, backup_state, name, created_at, last_used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
`

	if _, err := r.handle.Pool().Exec(ctx, query,
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.AttestationType, c.Transports, c.AAGUID,
		c.SignCount, c.CloneWarning, c.BackupEligible, c.BackupState, c.Name, c.CreatedAt, c.LastUsedAt,
	); err != nil {
		pgErr, ok := errors.AsType[*pgconn.PgError](err)
		if ok && pgErr.Code == uniqueViolationCode && pgErr.ConstraintName == constraintCredentialIDUnique {
			return ErrVerification
		}

		return fmt.Errorf("passkey: inserting credential: %w", err)
	}

	return nil
}

// Delete removes a credential, scoped to userID so a caller cannot delete a
// credential it does not own. It reports whether a row was deleted. The bool
// exists for the ownership isolation test (design.md's "Authorization
// path"), which has to assert that acting against another account's
// credential affected nothing; the route answers 204 either way, so a
// caller cannot use it to probe for a credential's existence.
func (r *Repository) Delete(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	const query = `DELETE FROM credentials WHERE id = $1 AND user_id = $2`

	tag, err := r.handle.Pool().Exec(ctx, query, id, userID)
	if err != nil {
		return false, fmt.Errorf("passkey: deleting credential: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// DeleteTx is Delete against the caller-supplied transaction tx instead of
// the pool, so a caller enforcing the last-factor rule can remove a
// credential in the same transaction that locked the account row and counted
// its factors, closing the race two concurrent removals could otherwise win.
// It takes no receiver-held state: it is a Repository method, rather than a
// package function, only so it sits alongside Delete as the pair ByEmail and
// ByEmailTx in internal/user already establish the pattern for.
//
//nolint:revive // Deliberately receiver-less: see the doc comment above.
func (r *Repository) DeleteTx(ctx context.Context, tx pgx.Tx, userID, id uuid.UUID) (bool, error) {
	const query = `DELETE FROM credentials WHERE id = $1 AND user_id = $2`

	tag, err := tx.Exec(ctx, query, id, userID)
	if err != nil {
		return false, fmt.Errorf("passkey: deleting credential in transaction: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// CountFor returns how many credentials an account holds, for the last-factor
// rule.
func (r *Repository) CountFor(ctx context.Context, userID uuid.UUID) (int, error) {
	const query = `SELECT count(*) FROM credentials WHERE user_id = $1`

	var count int

	if err := r.handle.Pool().QueryRow(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("passkey: counting credentials: %w", err)
	}

	return count, nil
}

// CountForTx is CountFor reading against the caller-supplied transaction tx
// instead of the pool. It takes no receiver-held state: it is a Repository
// method, rather than a package function, only so it sits alongside CountFor
// as the pair ByEmail and ByEmailTx in internal/user already establish the
// pattern for.
//
//nolint:revive // Deliberately receiver-less: see the doc comment above.
func (r *Repository) CountForTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int, error) {
	const query = `SELECT count(*) FROM credentials WHERE user_id = $1`

	var count int

	if err := tx.QueryRow(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("passkey: counting credentials in transaction: %w", err)
	}

	return count, nil
}

// RecordUse advances a credential's sign count and last_used_at, and sets its
// clone warning when set is true.
func (r *Repository) RecordUse(ctx context.Context, id uuid.UUID, signCount int64, cloneWarning bool) error {
	const query = `
UPDATE credentials
SET sign_count = $2, clone_warning = $3, last_used_at = $4
WHERE id = $1
`

	if _, err := r.handle.Pool().Exec(ctx, query, id, signCount, cloneWarning, r.now()); err != nil {
		return fmt.Errorf("passkey: recording credential use: %w", err)
	}

	return nil
}
