// Package database owns the PostgreSQL connection pool and its lifecycle.
//
// It exposes *sql.DB rather than a wrapper: repositories in
// internal/repository/postgres consume it directly, and hiding the standard
// pool behind an interface would buy nothing — the swap point that matters is
// the repository port, not the driver.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	// pgx's database/sql adapter. Registered for its side effect only: the rest
	// of the codebase speaks database/sql, so nothing else imports pgx.
	//
	// Why database/sql and not native pgx — pgvector works through it via
	// driver.Valuer/sql.Scanner, and if COPY or LISTEN/NOTIFY are ever needed,
	// swapping to native pgx happens behind the repository port without a single
	// service changing. See docs/adr/0008.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/bishal05das/aegisops-ai/internal/config"
)

// Config is the subset of settings the pool needs.
type Config struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	// ConnectTimeout bounds the initial reachability check.
	ConnectTimeout time.Duration
}

// FromAppConfig derives pool settings from the application configuration.
func FromAppConfig(c *config.Config) Config {
	return Config{
		DSN:             c.Postgres.DSN(),
		MaxOpenConns:    c.Postgres.MaxConns,
		MaxIdleConns:    c.Postgres.MinConns,
		ConnMaxLifetime: c.Postgres.ConnMaxLifetime,
		// Shorter than the lifetime: an idle connection is worth reclaiming long
		// before it is old enough to be recycled for staleness.
		ConnMaxIdleTime: 5 * time.Minute,
		ConnectTimeout:  10 * time.Second,
	}
}

// Open creates the pool and verifies the database is reachable.
//
// sql.Open is lazy — it validates the DSN and returns without connecting — so a
// wrong host or password would otherwise surface at the first query, long after
// the process has announced itself as started. The explicit ping here turns that
// into a startup failure, which is what a supervisor can act on.
func Open(ctx context.Context, cfg Config, log *slog.Logger) (*sql.DB, error) {
	const op = "database.Open"

	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("%s: parse DSN: %w", op, err)
	}

	// MaxOpenConns is the important one. Postgres allocates a backend process
	// per connection, so an unbounded pool multiplied by replicas exhausts
	// max_connections and locks everyone out — including the migration runner
	// that would fix it.
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	// Lifetime recycling matters behind a connection proxy or a failover: a
	// long-lived connection can outlive the backend it was routed to.
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%s: ping: %w", op, err)
	}

	if log != nil {
		log.Info("postgres pool ready",
			"max_open_conns", cfg.MaxOpenConns,
			"max_idle_conns", cfg.MaxIdleConns,
			"conn_max_lifetime", cfg.ConnMaxLifetime.String(),
		)
	}
	return db, nil
}

// Stats renders pool statistics for a metrics endpoint or a debug log.
//
// WaitCount and WaitDuration are the pair worth alerting on: a rising wait means
// requests are queuing for a connection, which shows up to users as latency long
// before it shows up as an error.
func Stats(db *sql.DB) map[string]any {
	s := db.Stats()
	return map[string]any{
		"max_open_connections": s.MaxOpenConnections,
		"open_connections":     s.OpenConnections,
		"in_use":               s.InUse,
		"idle":                 s.Idle,
		"wait_count":           s.WaitCount,
		"wait_duration_ms":     s.WaitDuration.Milliseconds(),
		"max_idle_closed":      s.MaxIdleClosed,
		"max_lifetime_closed":  s.MaxLifetimeClosed,
	}
}

// HealthCheck verifies the pool can still serve a query.
//
// A round trip rather than a bare Ping: Ping can be satisfied by a cached
// connection state, whereas `SELECT 1` proves the backend is actually
// responding to statements.
func HealthCheck(ctx context.Context, db *sql.DB) error {
	const op = "database.HealthCheck"

	var one int
	if err := db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if one != 1 {
		return fmt.Errorf("%s: SELECT 1 returned %d", op, one)
	}
	return nil
}
