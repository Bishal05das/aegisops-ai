package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/bishal05das/aegisops-ai/internal/preflight"
)

// PoolCheck reports whether the application's own connection pool can serve a
// query.
//
// This supersedes the TCP-level preflight.PostgresCheck for readiness. That one
// proves a PostgreSQL backend is listening; this proves *our pool* can reach it
// — which is the question readiness actually asks. A pool exhausted by leaked
// connections, or holding credentials the server has since revoked, passes the
// handshake probe and fails every real query.
//
// It also surfaces pool saturation: a rising wait count means requests are
// queuing for a connection, which reaches users as latency long before it
// reaches them as an error.
type PoolCheck struct {
	db *sql.DB
}

// NewPoolCheck builds a readiness probe over an existing pool.
func NewPoolCheck(db *sql.DB) *PoolCheck { return &PoolCheck{db: db} }

var _ preflight.Check = (*PoolCheck)(nil)

// Name implements preflight.Check.
func (c *PoolCheck) Name() string { return "postgres" }

// Target implements preflight.Check.
func (c *PoolCheck) Target() string { return "application connection pool" }

// Severity implements preflight.Check. The control plane cannot serve an
// incident without its system of record.
func (c *PoolCheck) Severity() preflight.Severity { return preflight.Required }

// Hint implements preflight.Check.
func (c *PoolCheck) Hint() string {
	return "check `make dev-logs SVC=postgres`, and that AEGIS_PG_* matches a running instance"
}

// Probe implements preflight.Check.
func (c *PoolCheck) Probe(ctx context.Context) (string, error) {
	if err := HealthCheck(ctx, c.db); err != nil {
		return "", err
	}

	s := c.db.Stats()
	detail := fmt.Sprintf("pool healthy (%d/%d in use, %d idle)",
		s.InUse, s.MaxOpenConnections, s.Idle)

	// Saturation is degraded, not failed: the database is answering, but
	// requests are queuing. Reporting it as a hard failure would pull the
	// replica out of rotation and push its load onto pools that are just as
	// saturated, turning a slowdown into an outage.
	if s.WaitCount > 0 && s.InUse >= s.MaxOpenConnections {
		return detail, fmt.Errorf(
			"%w: connection pool is saturated (%d waits totalling %s); "+
				"raise AEGIS_PG_MAX_CONNS or find the query holding connections",
			preflight.ErrDegraded, s.WaitCount, s.WaitDuration)
	}
	return detail, nil
}

// MigrationCheck reports whether the schema is at the version this binary
// expects.
//
// A binary running against a schema older than its migrations is the classic
// rolling-deploy failure: the new code queries a column the old schema lacks,
// and every request 500s. Readiness catching it keeps that replica out of
// rotation instead of serving errors.
type MigrationCheck struct {
	db       *sql.DB
	expected int
}

// NewMigrationCheck builds a schema-version probe.
func NewMigrationCheck(db *sql.DB, expectedVersion int) *MigrationCheck {
	return &MigrationCheck{db: db, expected: expectedVersion}
}

var _ preflight.Check = (*MigrationCheck)(nil)

// Name implements preflight.Check.
func (c *MigrationCheck) Name() string { return "schema" }

// Target implements preflight.Check.
func (c *MigrationCheck) Target() string { return fmt.Sprintf("schema version %d", c.expected) }

// Severity implements preflight.Check.
func (c *MigrationCheck) Severity() preflight.Severity { return preflight.Required }

// Hint implements preflight.Check.
func (c *MigrationCheck) Hint() string { return "run `make db-migrate`" }

// Probe implements preflight.Check.
func (c *MigrationCheck) Probe(ctx context.Context) (string, error) {
	var applied sql.NullInt64
	err := c.db.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&applied)
	if err != nil {
		return "", fmt.Errorf("read schema version (has the schema ever been migrated?): %w", err)
	}

	current := int(applied.Int64)
	switch {
	case !applied.Valid || current == 0:
		return "", fmt.Errorf("no migrations have been applied; the schema is empty")
	case current < c.expected:
		return "", fmt.Errorf(
			"schema is at version %d but this build expects %d; queries will reference columns that do not exist",
			current, c.expected)
	case current > c.expected:
		// A newer schema usually means a rollback left an older binary running.
		// Additive migrations make this survivable, so it is a warning — but a
		// loud one, because the assumption does not always hold.
		return fmt.Sprintf("schema version %d", current),
			fmt.Errorf("%w: schema is at version %d, ahead of this build's %d; "+
				"this binary may be an unrolled-back deployment",
				preflight.ErrDegraded, current, c.expected)
	default:
		return fmt.Sprintf("schema version %d", current), nil
	}
}
