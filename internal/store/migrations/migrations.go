package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sync"

	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
)

// FS holds the embedded migration files, so the binary carries its own schema
// and needs no files on disk to bootstrap a database.
//
//go:embed *.sql
var FS embed.FS

// applyMu serializes calls to Apply and Version. goose configures its
// dialect, base filesystem, and logger through its own package-level state
// rather than through a value passed to Up or GetDBVersionContext, so any two
// of these calls running at the same time would race on that state. storetest
// calls Apply once per test, and tests commonly run in parallel, so this
// package provides the serialization goose does not.
var applyMu sync.Mutex

// Apply brings db up to the latest schema version using the embedded
// migrations. It is a no-op when the database is already current, and returns
// a wrapped error naming the migration that failed otherwise. db is a
// database/sql handle because goose has no pgx-native driver; it is the only
// reason one exists in this service.
func Apply(ctx context.Context, db *sql.DB, logger *zap.Logger) error {
	applyMu.Lock()
	defer applyMu.Unlock()

	goose.SetBaseFS(FS)
	goose.SetLogger(&gooseLogger{logger: logger})

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("migrations: setting dialect: %w", err)
	}

	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("migrations: applying migrations: %w", err)
	}

	return nil
}

// Version reports the schema version currently applied to db.
func Version(ctx context.Context, db *sql.DB) (int64, error) {
	applyMu.Lock()
	defer applyMu.Unlock()

	version, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return 0, fmt.Errorf("migrations: reading schema version: %w", err)
	}

	return version, nil
}

// gooseLogger routes goose's own log output through a zap logger rather than
// stdout, since forbidigo forbids anything that writes to stdout directly.
type gooseLogger struct {
	logger *zap.Logger
}

// Fatalf logs a fatal goose message through zap. It does not exit the
// process: goose's library code never calls it in the code paths Apply
// exercises, and a migration runner that can terminate the process from a log
// call is worse than one that simply returns the error it was already about
// to return.
func (l *gooseLogger) Fatalf(format string, v ...any) {
	l.logger.Error(fmt.Sprintf(format, v...))
}

// Printf logs an informational goose message through zap.
func (l *gooseLogger) Printf(format string, v ...any) {
	l.logger.Info(fmt.Sprintf(format, v...))
}
