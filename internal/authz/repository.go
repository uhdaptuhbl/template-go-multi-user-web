package authz

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

// ErrUnknownRole reports a role name with no matching row.
var ErrUnknownRole = errors.New("unknown role")

// Repository reads and writes the role and permission assignments.
type Repository struct {
	handle *store.Handle
	now    func() time.Time
}

// NewRepository returns a repository backed by h, using now as its clock.
func NewRepository(h *store.Handle, now func() time.Time) *Repository {
	return &Repository{handle: h, now: now}
}

// PermissionsFor returns the distinct permission names an account holds
// through its roles, sorted.
func (r *Repository) PermissionsFor(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.handle.Pool().Query(ctx, `
		SELECT DISTINCT p.name
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1
		ORDER BY p.name
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("authz: querying permissions: %w", err)
	}

	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("authz: collecting permissions: %w", err)
	}

	return names, nil
}

// RolesFor returns the role names an account holds, sorted.
func (r *Repository) RolesFor(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return rolesFor(ctx, r.handle.Pool(), userID)
}

// RolesForEach returns the sorted role names each of userIDs holds, keyed by
// account, in one query. Every requested account has an entry, empty rather
// than absent when it holds no roles, so a listing can report a page of
// accounts without one query per account.
func (r *Repository) RolesForEach(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	rolesByUser := make(map[uuid.UUID][]string, len(userIDs))

	for _, userID := range userIDs {
		rolesByUser[userID] = []string{}
	}

	rows, err := r.handle.Pool().Query(ctx, `
		SELECT ur.user_id, r.name
		FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = ANY($1)
		ORDER BY ur.user_id, r.name
	`, userIDs)
	if err != nil {
		return nil, fmt.Errorf("authz: querying roles for accounts: %w", err)
	}

	var userID uuid.UUID

	var name string

	_, err = pgx.ForEachRow(rows, []any{&userID, &name}, func() error {
		rolesByUser[userID] = append(rolesByUser[userID], name)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("authz: collecting roles for accounts: %w", err)
	}

	return rolesByUser, nil
}

// RolesForTx is RolesFor against the caller-supplied transaction tx instead
// of the pool, so a caller can read an account's roles and replace them in
// one transaction.
//
//nolint:revive // Deliberately receiver-less: it sits beside RolesFor as its Tx pair.
func (r *Repository) RolesForTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]string, error) {
	return rolesFor(ctx, tx, userID)
}

// rowsQuerier is the subset of *pgxpool.Pool and pgx.Tx that rolesFor needs,
// so RolesFor and RolesForTx share one query.
type rowsQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// rolesFor returns the role names userID holds, sorted, read through db.
func rolesFor(ctx context.Context, db rowsQuerier, userID uuid.UUID) ([]string, error) {
	rows, err := db.Query(ctx, `
		SELECT r.name
		FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.name
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("authz: querying roles: %w", err)
	}

	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("authz: collecting roles: %w", err)
	}

	return names, nil
}

// SetRoles replaces an account's roles with exactly roleNames, recording
// grantedBy, in one transaction. It returns ErrUnknownRole naming the first
// name that does not exist, without changing anything.
func (r *Repository) SetRoles(ctx context.Context, userID uuid.UUID, roleNames []string, grantedBy uuid.UUID) error {
	tx, err := r.handle.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("authz: beginning transaction: %w", err)
	}

	if setRolesTxErr := r.SetRolesTx(ctx, tx, userID, roleNames, grantedBy); setRolesTxErr != nil {
		return errors.Join(setRolesTxErr, wrapRollbackErr(tx.Rollback(ctx)))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return fmt.Errorf("authz: committing role change: %w", commitErr)
	}

	return nil
}

// SetRolesTx replaces an account's roles with exactly roleNames, recording
// grantedBy, within the caller-supplied transaction tx. It returns
// ErrUnknownRole naming the first name that does not exist, before changing
// anything. It does not begin, commit, or roll back tx: on any error the
// caller must roll tx back.
func (r *Repository) SetRolesTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, roleNames []string, grantedBy uuid.UUID) error {
	roleIDs, err := resolveRoleIDs(ctx, tx, roleNames)
	if err != nil {
		return err
	}

	if _, execErr := tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1`, userID); execErr != nil {
		return fmt.Errorf("authz: clearing roles: %w", execErr)
	}

	grantedAt := r.now()

	for _, roleID := range roleIDs {
		if _, execErr := tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, granted_at, granted_by)
			VALUES ($1, $2, $3, $4)
		`, userID, roleID, grantedAt, grantedBy); execErr != nil {
			return fmt.Errorf("authz: granting role: %w", execErr)
		}
	}

	return nil
}

// execQueryRower is the subset of *pgxpool.Pool and pgx.Tx that grantRole
// needs, so its statements can run against either a bare pool or a caller's
// transaction.
type execQueryRower interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// GrantRole adds one role to an account, recording grantedBy. Granting a role
// the account already holds is not an error.
func (r *Repository) GrantRole(ctx context.Context, userID uuid.UUID, roleName string, grantedBy uuid.UUID) error {
	return grantRole(ctx, r.handle.Pool(), r.now, userID, roleName, grantedBy)
}

// GrantRoleTx adds one role to an account within the caller-supplied
// transaction tx, recording grantedBy. Granting a role the account already
// holds is not an error. It does not begin, commit, or roll back tx:
// rollback is the caller's business, because the caller is the one who knows
// whether later steps sharing tx also succeeded.
func (r *Repository) GrantRoleTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, roleName string, grantedBy uuid.UUID) error {
	return grantRole(ctx, tx, r.now, userID, roleName, grantedBy)
}

// grantRole adds one role to an account, recording grantedBy, against db,
// which may be a bare pool or a caller's transaction. Granting a role the
// account already holds is not an error.
func grantRole(ctx context.Context, db execQueryRower, now func() time.Time, userID uuid.UUID, roleName string, grantedBy uuid.UUID) error {
	var roleID uuid.UUID

	err := db.QueryRow(ctx, `SELECT id FROM roles WHERE name = $1`, roleName).Scan(&roleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrUnknownRole, roleName)
		}

		return fmt.Errorf("authz: looking up role %s: %w", roleName, err)
	}

	_, err = db.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id, granted_at, granted_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, userID, roleID, now(), grantedBy)
	if err != nil {
		return fmt.Errorf("authz: granting role %s: %w", roleName, err)
	}

	return nil
}

// roleRow is the scan target for resolving role names to their ids.
type roleRow struct {
	ID   uuid.UUID `db:"id"`
	Name string    `db:"name"`
}

// resolveRoleIDs looks up the ids for roleNames within tx and returns them in
// the same order as roleNames. It returns ErrUnknownRole naming the first
// entry in roleNames with no matching row.
func resolveRoleIDs(ctx context.Context, tx pgx.Tx, roleNames []string) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT id, name FROM roles WHERE name = ANY($1)`, roleNames)
	if err != nil {
		return nil, fmt.Errorf("authz: querying roles: %w", err)
	}

	found, err := pgx.CollectRows(rows, pgx.RowToStructByName[roleRow])
	if err != nil {
		return nil, fmt.Errorf("authz: collecting roles: %w", err)
	}

	byName := make(map[string]uuid.UUID, len(found))
	for _, row := range found {
		byName[row.Name] = row.ID
	}

	ids := make([]uuid.UUID, 0, len(roleNames))

	for _, name := range roleNames {
		id, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownRole, name)
		}

		ids = append(ids, id)
	}

	return ids, nil
}

// wrapRollbackErr wraps a transaction rollback failure with context, or
// returns nil when the rollback succeeded.
func wrapRollbackErr(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("authz: rolling back role change: %w", err)
}
