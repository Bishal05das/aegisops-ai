// Package migrate applies versioned SQL migrations.
//
// Hand-written rather than golang-migrate or goose, for three reasons that
// matter here more than the ~250 lines cost:
//
//   - **The advisory lock.** Two replicas starting simultaneously must not both
//     run migrations. Postgres session-level advisory locks make this a
//     three-line guarantee, and getting it wrong is how a rolling deploy
//     corrupts a schema.
//   - **Checksum verification.** Editing a migration that has already been
//     applied is a silent divergence: the file says one thing, the database
//     holds another, and nothing complains until a query fails in production.
//     Recording a checksum turns that into a startup error.
//   - **No dependency.** A migration runner is small, and owning it means the
//     failure modes are ours to reason about.
package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// lockID is the key for pg_advisory_lock. Arbitrary but fixed: any process
// migrating this schema must use the same number, so it lives here rather than
// in configuration where it could drift between deployments.
const lockID int64 = 0x4145_4749_5300_0001 // "AEGIS" + 1

// Direction is the direction of travel.
type Direction string

// Migration directions.
const (
	Up   Direction = "up"
	Down Direction = "down"
)

// Migration is one versioned schema change.
type Migration struct {
	Version int
	Name    string
	UpSQL   string
	DownSQL string
	// Checksum covers the up SQL only. Down migrations are edited far more
	// freely (they are rarely run outside development) and holding them to the
	// same immutability would create friction for no safety gain.
	Checksum string
}

// AppliedMigration is a row of the schema_migrations table.
type AppliedMigration struct {
	Version    int
	Name       string
	Checksum   string
	AppliedAt  time.Time
	DurationMS int64
}

// Status pairs a known migration with its applied state.
type Status struct {
	Version   int
	Name      string
	Applied   bool
	AppliedAt time.Time
	// ChecksumMismatch means the file changed after being applied — the
	// database and the repository now disagree about what the schema is.
	ChecksumMismatch bool
}

// filenamePattern matches "0001_identity.up.sql".
var filenamePattern = regexp.MustCompile(`^(\d+)_([a-z0-9_]+)\.(up|down)\.sql$`)

// Load reads and pairs migrations from an embedded filesystem.
func Load(fsys fs.FS, dir string) ([]Migration, error) {
	const op = "migrate.Load"

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("%s: read %s: %w", op, dir, err)
	}

	type pair struct {
		name string
		up   string
		down string
	}
	byVersion := map[int]*pair{}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := filenamePattern.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf(
				"%s: %q does not match NNNN_name.(up|down).sql", op, e.Name())
		}

		version, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %q has a non-numeric version: %w", op, e.Name(), err)
		}
		if version < 1 {
			return nil, fmt.Errorf("%s: %q has version %d; versions start at 1", op, e.Name(), version)
		}

		// path.Join, not string concatenation: embed.FS rejects "./name", and
		// io/fs paths are always slash-separated and unrooted regardless of OS.
		body, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: read %s: %w", op, e.Name(), err)
		}

		p := byVersion[version]
		if p == nil {
			p = &pair{name: m[2]}
			byVersion[version] = p
		}
		if p.name != m[2] {
			return nil, fmt.Errorf(
				"%s: version %d has conflicting names %q and %q", op, version, p.name, m[2])
		}
		if m[3] == "up" {
			p.up = string(body)
		} else {
			p.down = string(body)
		}
	}

	out := make([]Migration, 0, len(byVersion))
	for version, p := range byVersion {
		if strings.TrimSpace(p.up) == "" {
			return nil, fmt.Errorf("%s: version %d (%s) has no up migration", op, version, p.name)
		}
		out = append(out, Migration{
			Version:  version,
			Name:     p.name,
			UpSQL:    p.up,
			DownSQL:  p.down,
			Checksum: checksum(p.up),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })

	// Gaps mean a migration was deleted or never committed. Applying 1, 2 then
	// 4 leaves a database that no clean run can reproduce, so refuse.
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf(
				"%s: migration versions must be contiguous from 1; found %d where %d was expected",
				op, m.Version, i+1)
		}
	}
	return out, nil
}

func checksum(s string) string {
	// Normalise line endings so a checkout on Windows does not report every
	// migration as modified.
	sum := sha256.Sum256([]byte(strings.ReplaceAll(s, "\r\n", "\n")))
	return hex.EncodeToString(sum[:])
}

// Runner applies migrations to a database.
type Runner struct {
	db         *sql.DB
	migrations []Migration
	log        *slog.Logger
}

// New builds a Runner. Pass nil for log to discard output.
func New(db *sql.DB, migrations []Migration, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Runner{db: db, migrations: migrations, log: log}
}

// ErrDirtyChecksum reports that an applied migration's file has since changed.
var ErrDirtyChecksum = errors.New("migration checksum mismatch")

// createTableSQL bootstraps the ledger. It is not itself a migration: something
// has to exist before versions can be tracked.
const createTableSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER     PRIMARY KEY,
    name        TEXT        NOT NULL,
    checksum    TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms BIGINT      NOT NULL DEFAULT 0
)`

// Up applies every pending migration in order.
//
// The whole run holds a session advisory lock, so a second replica starting at
// the same moment blocks here rather than racing. Each migration then runs in
// its own transaction: a failure rolls that one back cleanly and leaves every
// earlier migration applied, which is what makes a partial failure recoverable
// by fixing the file and re-running.
func (r *Runner) Up(ctx context.Context) error {
	const op = "migrate.Runner.Up"

	conn, release, err := r.lock(ctx)
	if err != nil {
		return err
	}
	defer release()

	if _, bootErr := conn.ExecContext(ctx, createTableSQL); bootErr != nil {
		return fmt.Errorf("%s: create schema_migrations: %w", op, bootErr)
	}

	applied, err := r.appliedOn(ctx, conn)
	if err != nil {
		return err
	}
	if err := r.verifyChecksums(applied); err != nil {
		return err
	}

	pending := 0
	for _, m := range r.migrations {
		if _, done := applied[m.Version]; done {
			continue
		}
		if err := r.applyOne(ctx, conn, m); err != nil {
			return err
		}
		pending++
	}

	if pending == 0 {
		r.log.Debug("schema is up to date", "version", r.latestVersion())
	} else {
		r.log.Info("migrations applied", "count", pending, "version", r.latestVersion())
	}
	return nil
}

// applyOne runs a single migration inside its own transaction.
func (r *Runner) applyOne(ctx context.Context, conn *sql.Conn, m Migration) error {
	const op = "migrate.Runner.applyOne"
	start := time.Now()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: begin %04d_%s: %w", op, m.Version, m.Name, err)
	}
	// Safe after Commit: a rollback on a committed transaction is a no-op, and
	// this guarantees no path leaves the transaction open.
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.UpSQL); err != nil {
		return fmt.Errorf("%s: apply %04d_%s: %w", op, m.Version, m.Name, err)
	}

	elapsed := time.Since(start).Milliseconds()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, duration_ms) VALUES ($1, $2, $3, $4)`,
		m.Version, m.Name, m.Checksum, elapsed,
	); err != nil {
		return fmt.Errorf("%s: record %04d_%s: %w", op, m.Version, m.Name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s: commit %04d_%s: %w", op, m.Version, m.Name, err)
	}

	r.log.Info("migration applied",
		"version", m.Version, "name", m.Name, "duration_ms", elapsed)
	return nil
}

// Down rolls back the most recent `steps` migrations, newest first.
//
// Kept deliberately blunt: it refuses when a migration has no down SQL rather
// than skipping it, because a partial rollback that silently leaves some
// objects behind is worse than no rollback at all.
func (r *Runner) Down(ctx context.Context, steps int) error {
	const op = "migrate.Runner.Down"
	if steps <= 0 {
		return fmt.Errorf("%s: steps must be positive, got %d", op, steps)
	}

	conn, release, err := r.lock(ctx)
	if err != nil {
		return err
	}
	defer release()

	applied, err := r.appliedOn(ctx, conn)
	if err != nil {
		return err
	}

	// Newest first.
	ordered := make([]Migration, len(r.migrations))
	copy(ordered, r.migrations)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Version > ordered[j].Version })

	rolled := 0
	for _, m := range ordered {
		if rolled >= steps {
			break
		}
		if _, done := applied[m.Version]; !done {
			continue
		}
		if strings.TrimSpace(m.DownSQL) == "" {
			return fmt.Errorf("%s: %04d_%s has no down migration; refusing a partial rollback",
				op, m.Version, m.Name)
		}
		if err := r.revertOne(ctx, conn, m); err != nil {
			return err
		}
		rolled++
	}

	r.log.Info("migrations rolled back", "count", rolled)
	return nil
}

func (r *Runner) revertOne(ctx context.Context, conn *sql.Conn, m Migration) error {
	const op = "migrate.Runner.revertOne"

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: begin %04d_%s: %w", op, m.Version, m.Name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.DownSQL); err != nil {
		return fmt.Errorf("%s: revert %04d_%s: %w", op, m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM schema_migrations WHERE version = $1`, m.Version); err != nil {
		return fmt.Errorf("%s: unrecord %04d_%s: %w", op, m.Version, m.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s: commit revert %04d_%s: %w", op, m.Version, m.Name, err)
	}

	r.log.Info("migration reverted", "version", m.Version, "name", m.Name)
	return nil
}

// Status reports each known migration's applied state, including any whose file
// has changed since it was applied.
func (r *Runner) Status(ctx context.Context) ([]Status, error) {
	const op = "migrate.Runner.Status"

	if _, err := r.db.ExecContext(ctx, createTableSQL); err != nil {
		return nil, fmt.Errorf("%s: create schema_migrations: %w", op, err)
	}
	applied, err := r.applied(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]Status, 0, len(r.migrations))
	for _, m := range r.migrations {
		s := Status{Version: m.Version, Name: m.Name}
		if a, ok := applied[m.Version]; ok {
			s.Applied = true
			s.AppliedAt = a.AppliedAt
			s.ChecksumMismatch = a.Checksum != m.Checksum
		}
		out = append(out, s)
	}
	return out, nil
}

// verifyChecksums refuses to proceed when an applied migration has been edited.
//
// Silently continuing is the dangerous option: the file and the database now
// describe different schemas, and the divergence surfaces later as a query
// failing in production against a column that the repository says exists.
func (r *Runner) verifyChecksums(applied map[int]AppliedMigration) error {
	const op = "migrate.Runner.verifyChecksums"

	for _, m := range r.migrations {
		a, ok := applied[m.Version]
		if !ok || a.Checksum == m.Checksum {
			continue
		}
		return fmt.Errorf(
			"%s: %w: %04d_%s was applied on %s with checksum %s but the file now hashes to %s. "+
				"Editing an applied migration diverges the database from the repository; "+
				"add a new migration instead",
			op, ErrDirtyChecksum, m.Version, m.Name,
			a.AppliedAt.Format(time.RFC3339), short(a.Checksum), short(m.Checksum))
	}
	return nil
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

func (r *Runner) applied(ctx context.Context) (map[int]AppliedMigration, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT version, name, checksum, applied_at, duration_ms FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("migrate: query schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanApplied(rows)
}

func (r *Runner) appliedOn(ctx context.Context, conn *sql.Conn) (map[int]AppliedMigration, error) {
	rows, err := conn.QueryContext(ctx,
		`SELECT version, name, checksum, applied_at, duration_ms FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("migrate: query schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanApplied(rows)
}

func scanApplied(rows *sql.Rows) (map[int]AppliedMigration, error) {
	out := map[int]AppliedMigration{}
	for rows.Next() {
		var a AppliedMigration
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt, &a.DurationMS); err != nil {
			return nil, fmt.Errorf("migrate: scan schema_migrations: %w", err)
		}
		out[a.Version] = a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: iterate schema_migrations: %w", err)
	}
	return out, nil
}

// lock takes a session-level advisory lock on a dedicated connection.
//
// Session-level rather than transaction-level: the lock must span several
// independent transactions (one per migration), which a transaction-scoped lock
// cannot do. That means it must be released explicitly, hence the returned
// closure and the dedicated *sql.Conn — returning the connection to the pool
// while still holding the lock would leak it to an unrelated query.
func (r *Runner) lock(ctx context.Context) (*sql.Conn, func(), error) {
	const op = "migrate.Runner.lock"

	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: acquire connection: %w", op, err)
	}

	r.log.Debug("waiting for the migration advisory lock", "lock_id", lockID)
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("%s: acquire advisory lock: %w", op, err)
	}

	release := func() {
		// A fresh context: ctx may already be cancelled, and failing to unlock
		// would block every future migration until the connection is reaped.
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, lockID); err != nil {
			r.log.Warn("failed to release the migration advisory lock",
				"error", err, "lock_id", lockID)
		}
		_ = conn.Close()
	}
	return conn, release, nil
}

func (r *Runner) latestVersion() int {
	if len(r.migrations) == 0 {
		return 0
	}
	return r.migrations[len(r.migrations)-1].Version
}
