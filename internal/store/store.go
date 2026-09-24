package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/zap"
)

// Handle owns the Postgres connection pool. It is the single value every
// repository in this service is constructed from.
type Handle struct {
	pool *pgxpool.Pool
}

// Open parses the configured connection string, applies the pool limits, opens
// the pool, and verifies it with a ping bounded by the configured connect
// timeout. It returns an error rather than a half-open handle if the database
// cannot be reached, because a process that cannot read its own accounts must
// not serve traffic.
func Open(ctx context.Context, cfg Config, logger *zap.Logger) (*Handle, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN.Expose())
	if err != nil {
		return nil, fmt.Errorf("store: parsing connection string: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime.Duration()
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime.Duration()
	poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout.Duration()

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("store: opening connection pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout.Duration())
	defer cancel()

	if pingErr := pool.Ping(pingCtx); pingErr != nil {
		pool.Close()

		return nil, fmt.Errorf("store: pinging database: %w", pingErr)
	}

	logger.Info("store: connected to database",
		zap.String("host", poolCfg.ConnConfig.Host),
		zap.Uint16("port", poolCfg.ConnConfig.Port),
		zap.String("database", poolCfg.ConnConfig.Database),
		zap.Int32("max_conns", poolCfg.MaxConns),
		zap.Int32("min_conns", poolCfg.MinConns),
		zap.Duration("max_conn_lifetime", poolCfg.MaxConnLifetime),
		zap.Duration("max_conn_idle_time", poolCfg.MaxConnIdleTime),
	)

	return &Handle{pool: pool}, nil
}

// Pool returns the underlying pool for repositories to issue queries against.
func (h *Handle) Pool() *pgxpool.Pool {
	return h.pool
}

// Ping verifies the database is reachable within ctx's deadline. The readiness
// endpoint calls it, so it must be cheap and must not retry.
func (h *Handle) Ping(ctx context.Context) error {
	if err := h.pool.Ping(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}

	return nil
}

// SQLDB returns a database/sql view of the pool this handle already owns, for
// the migration runner alone. goose has no pgx-native driver, so this is the
// one place database/sql appears in this service. It opens no new connections.
// The caller closes the returned handle; doing so does not close the pool.
func (h *Handle) SQLDB() *sql.DB {
	return stdlib.OpenDBFromPool(h.pool)
}

// Close releases the connection pool.
func (h *Handle) Close() {
	h.pool.Close()
}
