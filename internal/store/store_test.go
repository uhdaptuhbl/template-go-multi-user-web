//go:build integration

package store_test

import (
	"net"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// testConfig returns a Config pointed at the disposable Postgres storetest
// starts for t, with pool limits distinct enough from DefaultConfig's that a
// test asserting the resolved limits could not pass by accident.
func testConfig(t *testing.T) store.Config {
	t.Helper()

	cfg := storetest.NewPool(t)
	cfg.MaxConns = 7
	cfg.MinConns = 1
	cfg.ConnectTimeout = configtype.Duration(2 * time.Second)

	return cfg
}

// unreachableDSN returns a connection string pointing at a TCP port on
// localhost that is guaranteed to be closed: it binds an ephemeral port and
// closes the listener immediately, so nothing answers on it for the rest of
// the test.
func unreachableDSN(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v, want nil", err)
	}

	var addr, ok = listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", listener.Addr())
	}

	var port = addr.Port

	if closeErr := listener.Close(); closeErr != nil {
		t.Fatalf("listener.Close() error = %v, want nil", closeErr)
	}

	return "postgres://user:pass@127.0.0.1:" + strconv.Itoa(port) + "/testdb?sslmode=disable"
}

// TestOpenSucceedsAndPingsAReachableDatabase covers AC-008.1: the store can
// open a pool against a real Postgres and verify it is reachable.
func TestOpenSucceedsAndPingsAReachableDatabase(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t)

	handle, err := store.Open(t.Context(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("Open() error = %v, want nil", err)
	}
	t.Cleanup(handle.Close)

	if pingErr := handle.Ping(t.Context()); pingErr != nil {
		t.Errorf("Ping() error = %v, want nil", pingErr)
	}
}

// TestOpenFailsWithinConnectTimeoutAgainstAClosedPort covers AC-008.2 and
// AC-008.5: a connection string that cannot be reached fails startup with a
// wrapped error, bounded by the configured connect timeout rather than
// hanging.
func TestOpenFailsWithinConnectTimeoutAgainstAClosedPort(t *testing.T) {
	t.Parallel()

	cfg := store.DefaultConfig()
	cfg.DSN = secret.String(unreachableDSN(t))
	cfg.ConnectTimeout = configtype.Duration(2 * time.Second)

	deadline := time.Now().Add(10 * time.Second)

	_, err := store.Open(t.Context(), cfg, zap.NewNop())
	if err == nil {
		t.Fatal("Open() error = nil, want an error for an unreachable database")
	}

	if time.Now().After(deadline) {
		t.Errorf("Open() took longer than %v, want it bounded by ConnectTimeout", 10*time.Second)
	}
}

// TestPingOnAClosedHandleReturnsAnError covers AC-008.5: a handle that has
// already released its pool cannot be used to claim the database is
// reachable.
func TestPingOnAClosedHandleReturnsAnError(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t)

	handle, err := store.Open(t.Context(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("Open() error = %v, want nil", err)
	}

	handle.Close()

	if pingErr := handle.Ping(t.Context()); pingErr == nil {
		t.Error("Ping() error = nil, want an error on a closed handle")
	}
}

// TestSQLDBAnswersSelectOne covers AC-008.1: the database/sql view goose
// migrates through answers an ordinary query against the same pool.
func TestSQLDBAnswersSelectOne(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t)

	handle, err := store.Open(t.Context(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("Open() error = %v, want nil", err)
	}
	t.Cleanup(handle.Close)

	sqlDB := handle.SQLDB()
	t.Cleanup(func() {
		if closeErr := sqlDB.Close(); closeErr != nil {
			t.Errorf("sqlDB.Close() error = %v, want nil", closeErr)
		}
	})

	var got int
	if scanErr := sqlDB.QueryRowContext(t.Context(), "SELECT 1").Scan(&got); scanErr != nil {
		t.Fatalf("QueryRowContext(SELECT 1) error = %v, want nil", scanErr)
	}

	if got != 1 {
		t.Errorf("SELECT 1 = %d, want 1", got)
	}
}

// TestOpenAppliesTheResolvedPoolLimits covers AC-008.1: the limits Open hands
// to the pool are the ones Config resolved to, not pgxpool's own defaults.
func TestOpenAppliesTheResolvedPoolLimits(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t)

	handle, err := store.Open(t.Context(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("Open() error = %v, want nil", err)
	}
	t.Cleanup(handle.Close)

	resolved := handle.Pool().Config()

	if resolved.MaxConns != cfg.MaxConns {
		t.Errorf("resolved MaxConns = %d, want %d", resolved.MaxConns, cfg.MaxConns)
	}

	if resolved.MinConns != cfg.MinConns {
		t.Errorf("resolved MinConns = %d, want %d", resolved.MinConns, cfg.MinConns)
	}

	if resolved.MaxConnLifetime != cfg.MaxConnLifetime.Duration() {
		t.Errorf("resolved MaxConnLifetime = %v, want %v", resolved.MaxConnLifetime, cfg.MaxConnLifetime.Duration())
	}

	if resolved.MaxConnIdleTime != cfg.MaxConnIdleTime.Duration() {
		t.Errorf("resolved MaxConnIdleTime = %v, want %v", resolved.MaxConnIdleTime, cfg.MaxConnIdleTime.Duration())
	}
}
