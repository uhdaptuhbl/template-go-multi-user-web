//go:build integration

package migrations_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/migrations"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// openRaw opens a raw database/sql connection to dsn, closed when t finishes.
// storetest.NewPool already applies the embedded migrations once to build
// cfg, so tests use this to reach into the same schema and exercise Apply and
// Version directly against what storetest built.
func openRaw(t *testing.T, dsn string) *sql.DB {
	t.Helper()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v, want nil", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("db.Close() error = %v, want nil", closeErr)
		}
	})

	return db
}

// TestApplyReachesVersion6AndIsIdempotent covers AC-008.3: applying the
// embedded migrations, which storetest.NewPool already did once to build cfg
// against an empty schema, brings the schema to version 6, and applying them
// again is a no-op rather than an error.
func TestApplyReachesVersion6AndIsIdempotent(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)
	db := openRaw(t, cfg.DSN.Expose())

	version, err := migrations.Version(t.Context(), db)
	if err != nil {
		t.Fatalf("Version() error = %v, want nil", err)
	}

	if version != 6 {
		t.Errorf("Version() = %d, want 6", version)
	}

	if applyErr := migrations.Apply(t.Context(), db, zap.NewNop()); applyErr != nil {
		t.Errorf("second Apply() error = %v, want nil (idempotent)", applyErr)
	}

	version, err = migrations.Version(t.Context(), db)
	if err != nil {
		t.Fatalf("Version() error = %v, want nil", err)
	}

	if version != 6 {
		t.Errorf("Version() after second Apply() = %d, want 6", version)
	}
}

// TestApplyCreatesEveryTableFromMigration1 covers AC-008.1: every table named
// in 00001_users_and_auth.sql exists after migrating.
func TestApplyCreatesEveryTableFromMigration1(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)
	db := openRaw(t, cfg.DSN.Expose())

	tables := []string{
		"users", "identities", "credentials", "sessions", "auth_flows",
		"settings", "invites", "invite_redemptions", "otp_codes",
		"roles", "permissions", "role_permissions", "user_roles", "audit_events",
	}

	for _, table := range tables {
		var count int

		err := db.QueryRowContext(t.Context(),
			`SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1`,
			table,
		).Scan(&count)
		if err != nil {
			t.Fatalf("querying information_schema.tables for %s: %v", table, err)
		}

		if count != 1 {
			t.Errorf("table %s exists = %d, want 1", table, count)
		}
	}
}

// TestSeedRolesAndPermissions covers AC-008.31: the seed leaves
// exactly 2 roles, 9 permissions, 10 role_permissions rows, and exactly 1 row
// pairing member with a permission, which is invite.create.
func TestSeedRolesAndPermissions(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)
	db := openRaw(t, cfg.DSN.Expose())

	var roleCount int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM roles`).Scan(&roleCount); err != nil {
		t.Fatalf("counting roles: %v", err)
	}

	if roleCount != 2 {
		t.Errorf("roles count = %d, want 2", roleCount)
	}

	var permCount int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM permissions`).Scan(&permCount); err != nil {
		t.Fatalf("counting permissions: %v", err)
	}

	if permCount != 9 {
		t.Errorf("permissions count = %d, want 9", permCount)
	}

	var rolePermCount int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM role_permissions`).Scan(&rolePermCount); err != nil {
		t.Fatalf("counting role_permissions: %v", err)
	}

	if rolePermCount != 10 {
		t.Errorf("role_permissions count = %d, want 10", rolePermCount)
	}

	var memberPermCount int

	err := db.QueryRowContext(t.Context(), `
		SELECT count(*) FROM role_permissions
		JOIN roles ON roles.id = role_permissions.role_id
		WHERE roles.name = 'member'
	`).Scan(&memberPermCount)
	if err != nil {
		t.Fatalf("counting member role_permissions: %v", err)
	}

	if memberPermCount != 1 {
		t.Errorf("member role_permissions count = %d, want 1", memberPermCount)
	}

	var memberPermName string

	err = db.QueryRowContext(t.Context(), `
		SELECT permissions.name FROM role_permissions
		JOIN roles ON roles.id = role_permissions.role_id
		JOIN permissions ON permissions.id = role_permissions.permission_id
		WHERE roles.name = 'member'
	`).Scan(&memberPermName)
	if err != nil {
		t.Fatalf("reading member's sole permission: %v", err)
	}

	if memberPermName != "invite.create" {
		t.Errorf("member's sole permission = %q, want %q", memberPermName, "invite.create")
	}
}

// TestSeedSettingsRow covers AC-008.74: the settings row exists exactly once
// and carries the shipped friends-and-family defaults.
func TestSeedSettingsRow(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)
	db := openRaw(t, cfg.DSN.Expose())

	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM settings`).Scan(&count); err != nil {
		t.Fatalf("counting settings: %v", err)
	}

	if count != 1 {
		t.Fatalf("settings row count = %d, want 1", count)
	}

	var signupEnabled bool
	var signupRequireInvite bool
	var signupRequireApproval bool
	var inviteDefaultQuota int
	var inviteDefaultTTLSecs int
	var inviteMaxUsesLimit int
	var updatedByRef string

	err := db.QueryRowContext(t.Context(), `
		SELECT signup_enabled, signup_require_invite, signup_require_approval,
		       invite_default_quota, invite_default_ttl_secs, invite_max_uses_limit, updated_by_ref
		FROM settings
	`).Scan(
		&signupEnabled, &signupRequireInvite, &signupRequireApproval,
		&inviteDefaultQuota, &inviteDefaultTTLSecs, &inviteMaxUsesLimit, &updatedByRef,
	)
	if err != nil {
		t.Fatalf("reading settings row: %v", err)
	}

	if !signupEnabled {
		t.Error("signup_enabled = false, want true")
	}

	if !signupRequireInvite {
		t.Error("signup_require_invite = false, want true")
	}

	if signupRequireApproval {
		t.Error("signup_require_approval = true, want false")
	}

	if inviteDefaultQuota != 0 {
		t.Errorf("invite_default_quota = %d, want 0", inviteDefaultQuota)
	}

	if inviteDefaultTTLSecs != 1209600 {
		t.Errorf("invite_default_ttl_secs = %d, want 1209600", inviteDefaultTTLSecs)
	}

	if inviteMaxUsesLimit != 100 {
		t.Errorf("invite_max_uses_limit = %d, want 100", inviteMaxUsesLimit)
	}

	if updatedByRef != "anonymous" {
		t.Errorf("updated_by_ref = %q, want %q", updatedByRef, "anonymous")
	}
}

// TestApplyAgainstACorruptedMigrationTableReturnsAWrappedError covers
// AC-008.4: a migration table that has lost its record of what has already
// run makes Apply collide with the tables that already exist, and Apply
// reports that as a wrapped error rather than panicking.
func TestApplyAgainstACorruptedMigrationTableReturnsAWrappedError(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)
	db := openRaw(t, cfg.DSN.Expose())

	if _, err := db.ExecContext(t.Context(), `TRUNCATE goose_db_version`); err != nil {
		t.Fatalf("TRUNCATE goose_db_version: %v", err)
	}

	err := migrations.Apply(t.Context(), db, zap.NewNop())
	if err == nil {
		t.Fatal("Apply() error = nil, want an error against a corrupted migration table")
	}

	if !strings.HasPrefix(err.Error(), "migrations: applying migrations:") {
		t.Errorf("Apply() error = %q, want it wrapped with the migrations package's own context", err.Error())
	}

	if errors.Unwrap(err) == nil {
		t.Error("errors.Unwrap(Apply() error) = nil, want the underlying goose error preserved")
	}
}

// TestNativeColumnTypesReachTheDatabase covers AC-008.1: the native Postgres
// type mapping described in the schema actually reached the database, rather
// than being a claim only a document makes.
func TestNativeColumnTypesReachTheDatabase(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)
	db := openRaw(t, cfg.DSN.Expose())

	tests := []struct {
		table  string
		column string
		want   string
	}{
		{table: "users", column: "id", want: "uuid"},
		{table: "users", column: "created_at", want: "timestamp with time zone"},
		{table: "sessions", column: "id", want: "bytea"},
		{table: "credentials", column: "clone_warning", want: "boolean"},
		{table: "sessions", column: "methods", want: "jsonb"},
		{table: "audit_events", column: "client_ip", want: "inet"},
	}

	for _, tt := range tests {
		var dataType string

		err := db.QueryRowContext(t.Context(), `
			SELECT data_type FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
		`, tt.table, tt.column).Scan(&dataType)
		if err != nil {
			t.Fatalf("querying column type for %s.%s: %v", tt.table, tt.column, err)
		}

		if dataType != tt.want {
			t.Errorf("%s.%s data_type = %q, want %q", tt.table, tt.column, dataType, tt.want)
		}
	}
}

// TestMigration4AddsFollowUpColumnsAndIndexes covers AC-008.1: migration
// 00004 adds the two new users columns, replaces the audit_events cursor
// index with a compound (occurred_at, id) index, and updates the member
// role's description to mention invites.
func TestMigration4AddsFollowUpColumnsAndIndexes(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)
	db := openRaw(t, cfg.DSN.Expose())

	columns := []string{"rejected_at", "bootstrap_admin_granted_at"}
	for _, column := range columns {
		var count int

		err := db.QueryRowContext(t.Context(),
			`SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = $1`,
			column,
		).Scan(&count)
		if err != nil {
			t.Fatalf("querying information_schema.columns for users.%s: %v", column, err)
		}

		if count != 1 {
			t.Errorf("users.%s exists = %d, want 1", column, count)
		}
	}

	var indexCount int

	err := db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'audit_events_occurred_at_id_idx'`,
	).Scan(&indexCount)
	if err != nil {
		t.Fatalf("querying pg_indexes for audit_events_occurred_at_id_idx: %v", err)
	}

	if indexCount != 1 {
		t.Errorf("index audit_events_occurred_at_id_idx exists = %d, want 1", indexCount)
	}

	var memberDescription string

	err = db.QueryRowContext(t.Context(), `SELECT description FROM roles WHERE name = 'member'`).Scan(&memberDescription)
	if err != nil {
		t.Fatalf("reading member role description: %v", err)
	}

	if !strings.Contains(memberDescription, "invites") {
		t.Errorf("member role description = %q, want it to contain %q", memberDescription, "invites")
	}
}

// TestMigration5AddsSessionCookieIssuedAt covers AC-008.77: migration 00005
// adds sessions.cookie_issued_at as a NOT NULL column, backfilled from
// created_at for any row that predates the migration.
func TestMigration5AddsSessionCookieIssuedAt(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)
	db := openRaw(t, cfg.DSN.Expose())

	var dataType, isNullable string

	err := db.QueryRowContext(t.Context(), `
		SELECT data_type, is_nullable FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'sessions' AND column_name = 'cookie_issued_at'
	`).Scan(&dataType, &isNullable)
	if err != nil {
		t.Fatalf("querying information_schema.columns for sessions.cookie_issued_at: %v", err)
	}

	if dataType != "timestamp with time zone" {
		t.Errorf("sessions.cookie_issued_at data_type = %q, want %q", dataType, "timestamp with time zone")
	}

	if isNullable != "NO" {
		t.Errorf("sessions.cookie_issued_at is_nullable = %q, want %q", isNullable, "NO")
	}
}

// TestMigration6AddsOTPCodeBinding covers AC-008.82: migration 00006 adds
// otp_codes.binding_hash as a NOT NULL column and the compound
// (email, binding_hash) index a bound code lookup relies on.
func TestMigration6AddsOTPCodeBinding(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)
	db := openRaw(t, cfg.DSN.Expose())

	var dataType, isNullable string

	err := db.QueryRowContext(t.Context(), `
		SELECT data_type, is_nullable FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'otp_codes' AND column_name = 'binding_hash'
	`).Scan(&dataType, &isNullable)
	if err != nil {
		t.Fatalf("querying information_schema.columns for otp_codes.binding_hash: %v", err)
	}

	if dataType != "bytea" {
		t.Errorf("otp_codes.binding_hash data_type = %q, want %q", dataType, "bytea")
	}

	if isNullable != "NO" {
		t.Errorf("otp_codes.binding_hash is_nullable = %q, want %q", isNullable, "NO")
	}

	var indexCount int

	err = db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'otp_codes_email_binding_idx'`,
	).Scan(&indexCount)
	if err != nil {
		t.Fatalf("querying pg_indexes for otp_codes_email_binding_idx: %v", err)
	}

	if indexCount != 1 {
		t.Errorf("index otp_codes_email_binding_idx exists = %d, want 1", indexCount)
	}
}
