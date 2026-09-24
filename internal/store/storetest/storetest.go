package storetest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/migrations"
)

// envTestDSN names the environment variable that, when set, points storetest
// at an already-running Postgres server instead of starting a disposable
// container.
const envTestDSN = "SERVICE_TEST_DB_DSN"

// containerImage is the Postgres image used for the disposable test
// container.
const containerImage = "postgres:16-alpine"

// containerHandle is the disposable container itself. It is nil whenever no
// container is running, which is both before the first test starts one and
// after the last test using one tears it down.
var containerHandle *postgres.PostgresContainer

// containerDSN is the base connection string for the disposable container.
var containerDSN string

// errContainerStart is the error from starting the disposable container. It is
// not a sentinel: its value comes from whatever startContainer returned, not
// from a fixed error this package defines. Once set it is never cleared, so a
// server that cannot be started is diagnosed once rather than retried by every
// test in the run.
var errContainerStart error

// containerMu guards containerHandle, containerDSN, errContainerStart and
// containerRefs together. They are one piece of state and must be read and
// written as one.
var containerMu sync.Mutex

// containerRefs counts the tests currently using the disposable container.
// Parallel top-level tests can finish in any order, so the container cannot
// simply be torn down by whichever test happened to start it: it is torn
// down only when the last test still holding a reference finishes.
var containerRefs int

// New returns a handle to a fresh, fully migrated Postgres database scoped to
// t, torn down when t finishes. Tests use a real database rather than a mock,
// which is this project's stated testing standard.
//
// It obtains a server one of two ways. When SERVICE_TEST_DB_DSN is set it
// connects there and gives the test its own schema, which is the fast path and
// the one CI takes, since CI already runs Postgres as a service container.
// Otherwise it starts a disposable container with testcontainers-go. When
// neither a DSN nor a Docker daemon is available it calls t.Skip naming
// SERVICE_TEST_DB_DSN, so a missing database is an environmental skip rather
// than a failure.
func New(t *testing.T) *store.Handle {
	t.Helper()

	return newHandle(t, time.Now)
}

// NewWithClock is New with an explicit clock, for tests that advance time.
// store has no clock hook of its own yet, so now currently only seeds the
// per-test schema name; it is accepted here so that every clock-driven test
// already goes through this one canonical construction path once store grows
// one.
func NewWithClock(t *testing.T, now func() time.Time) *store.Handle {
	t.Helper()

	return newHandle(t, now)
}

// NewPool returns the same database as New but as a raw configuration, for the
// store package's own tests, which are testing the thing New is built on.
func NewPool(t *testing.T) store.Config {
	t.Helper()

	cfg := schemaConfig(t, time.Now)
	migrateDSN(t, cfg.DSN.Expose())

	return cfg
}

// NewUnmigratedPool returns a fresh, uniquely schemad Postgres configuration
// like NewPool, but without applying any migration to it. It is for tests of
// migration-on-start behavior: a caller that wants to observe a process or a
// package apply migrations itself, rather than exercising an already-migrated
// schema, needs a schema no prior call has touched.
func NewUnmigratedPool(t *testing.T) store.Config {
	t.Helper()

	return schemaConfig(t, time.Now)
}

// newHandle creates and migrates a per-test schema and opens a store.Handle
// against it.
func newHandle(t *testing.T, now func() time.Time) *store.Handle {
	t.Helper()

	cfg := schemaConfig(t, now)
	migrateDSN(t, cfg.DSN.Expose())

	handle, err := store.Open(t.Context(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("storetest: opening store: %v", err)
	}
	t.Cleanup(handle.Close)

	return handle
}

// schemaConfig creates a uniquely named schema on the target Postgres server,
// drops it in t.Cleanup, and returns a store.Config whose DSN routes every
// connection's search_path to it. The DSN is assumed to be in URL form
// (postgres://...), which is the only form this repository's own
// configuration ever produces or accepts.
func schemaConfig(t *testing.T, now func() time.Time) store.Config {
	t.Helper()

	baseDSN := serverDSN(t)
	schema := schemaName(now)

	adminDB, err := sql.Open("pgx", baseDSN)
	if err != nil {
		t.Fatalf("storetest: opening admin connection: %v", err)
	}
	defer func() {
		if closeErr := adminDB.Close(); closeErr != nil {
			t.Errorf("storetest: closing admin connection: %v", closeErr)
		}
	}()

	if _, execContextErr := adminDB.ExecContext(t.Context(), `CREATE SCHEMA "`+schema+`"`); execContextErr != nil {
		t.Fatalf("storetest: creating schema %s: %v", schema, execContextErr)
	}

	t.Cleanup(func() {
		dropDB, openErr := sql.Open("pgx", baseDSN)
		if openErr != nil {
			t.Errorf("storetest: opening connection to drop schema %s: %v", schema, openErr)

			return
		}
		defer func() {
			if closeErr := dropDB.Close(); closeErr != nil {
				t.Errorf("storetest: closing drop connection: %v", closeErr)
			}
		}()

		if _, execContextErr := dropDB.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS "`+schema+`" CASCADE`); execContextErr != nil {
			t.Errorf("storetest: dropping schema %s: %v", schema, execContextErr)
		}
	})

	cfg := store.DefaultConfig()
	cfg.DSN = secret.String(withSearchPath(baseDSN, schema))

	return cfg
}

// migrateDSN opens dsn and applies every embedded migration to it.
func migrateDSN(t *testing.T, dsn string) {
	t.Helper()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("storetest: opening migration connection: %v", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("storetest: closing migration connection: %v", closeErr)
		}
	}()

	if applyErr := migrations.Apply(t.Context(), db, zap.NewNop()); applyErr != nil {
		t.Fatalf("storetest: applying migrations: %v", applyErr)
	}
}

// schemaName derives a unique, valid Postgres identifier for a per-test
// schema, combining now so the name carries the clock reading a test was
// created under, and a random suffix so uniqueness never depends on the
// clock's resolution.
func schemaName(now func() time.Time) string {
	return fmt.Sprintf("test_%d_%s", now().UnixNano(), strings.ReplaceAll(uuid.New().String(), "-", ""))
}

// serverDSN resolves the Postgres server storetest runs its per-test schemas
// against, preferring SERVICE_TEST_DB_DSN and falling back to a disposable
// container. It calls t.Skip if neither is available.
func serverDSN(t *testing.T) string {
	t.Helper()

	if dsn := os.Getenv(envTestDSN); dsn != "" {
		return dsn
	}

	containerMu.Lock()

	// Start a container when none is running. This is deliberately not a
	// sync.Once: the container is torn down when the last test using it
	// finishes, so a run whose tests execute sequentially tears it down
	// between every pair of tests and must be able to start another. A
	// sync.Once would start the first container and then hand every later
	// test the address of a container that had already been terminated.
	if containerHandle == nil && errContainerStart == nil {
		containerHandle, containerDSN, errContainerStart = startContainer()
	}

	if errContainerStart != nil {
		var startErr = errContainerStart
		containerMu.Unlock()
		t.Skipf(
			"storetest: %s is not set and a disposable Postgres container could not be started: %v; set %s to run these tests",
			envTestDSN, startErr, envTestDSN,
		)

		return ""
	}

	containerRefs++

	var dsn = containerDSN

	containerMu.Unlock()

	t.Cleanup(func() {
		containerMu.Lock()
		containerRefs--
		var last = containerRefs == 0
		var ctr = containerHandle

		if last {
			containerHandle = nil
			containerDSN = ""
		}

		containerMu.Unlock()

		if !last {
			return
		}

		if err := ctr.Terminate(context.Background()); err != nil {
			t.Errorf("storetest: terminating postgres container: %v", err)
		}
	})

	return dsn
}

// startContainer starts the disposable Postgres container reused by every
// test in this process that needs one.
func startContainer() (*postgres.PostgresContainer, string, error) {
	ctx := context.Background()

	ctr, err := postgres.Run(ctx, containerImage, postgres.BasicWaitStrategies())
	if err != nil {
		return nil, "", fmt.Errorf("starting postgres container: %w", err)
	}

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, "", fmt.Errorf("obtaining postgres container connection string: %w", err)
	}

	return ctr, dsn, nil
}

// withSearchPath appends a search_path query parameter to dsn, so every
// connection opened from it defaults to schema rather than public.
func withSearchPath(dsn, schema string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}

	return dsn + sep + "search_path=" + url.QueryEscape(schema)
}
