// Package postgres implements the repository ports against PostgreSQL.
//
// Every type here is an adapter: it depends on the domain and on database/sql,
// and nothing depends on it except the composition root. Swapping the whole
// package for an in-memory implementation is a one-line change in main.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// executor is the subset of *sql.DB and *sql.Tx that repositories use.
//
// Depending on this rather than on a concrete type is what lets one repository
// method run identically inside or outside a transaction. Note it is
// context-taking only: there is deliberately no Exec or Query without a ctx, so
// a query that ignores cancellation cannot be written by accident.
type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// txKey is unexported so no package outside this one can plant a transaction on
// a context or read the one that is there.
type txKey struct{}

// withTx stores a transaction on the context.
func withTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// txFrom returns the transaction carried by ctx, if any.
func txFrom(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(*sql.Tx)
	return tx, ok && tx != nil
}

// TxManager runs functions inside a database transaction.
type TxManager struct {
	db *sql.DB
}

// NewTxManager builds a transaction manager over a pool.
func NewTxManager(db *sql.DB) *TxManager { return &TxManager{db: db} }

var _ ports.TxManager = (*TxManager)(nil)

// WithinTx runs fn inside a transaction, committing on success and rolling back
// on any error or panic.
//
// Three behaviours worth stating explicitly:
//
//   - **Nesting joins rather than nests.** A WithinTx inside a WithinTx reuses
//     the outer transaction. Postgres has no true nested transactions, and a
//     savepoint has different rollback semantics than a caller writing
//     `WithinTx` would expect — an inner rollback would leave the outer
//     transaction alive, which is almost never what the code reads as.
//   - **A panic rolls back and re-panics.** Swallowing it would leave the
//     caller believing the work committed.
//   - **The callback's error is returned unwrapped**, so errors.Is still
//     matches the domain sentinels the caller is checking for.
func (m *TxManager) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	const op = "postgres.TxManager.WithinTx"

	if _, already := txFrom(ctx); already {
		return fn(ctx)
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: begin: %w", op, err)
	}

	// A named return would let us inspect the error here, but an explicit flag
	// keeps the panic path unambiguous.
	committed := false
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := fn(withTx(ctx, tx)); err != nil {
		return err // unwrapped, so errors.Is still works
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s: commit: %w", op, err)
	}
	committed = true
	return nil
}

// base carries the pool and resolves the right executor per call.
type base struct {
	db *sql.DB
}

// exec returns the transaction on the context, or the pool when there is none.
// This one method is what makes every repository transaction-agnostic.
func (b base) exec(ctx context.Context) executor {
	if tx, ok := txFrom(ctx); ok {
		return tx
	}
	return b.db
}

// Postgres SQLSTATE codes worth distinguishing.
const (
	codeUniqueViolation     = "23505"
	codeForeignKeyViolation = "23503"
	codeCheckViolation      = "23514"
	codeNotNullViolation    = "23502"
)

// sqlStateError is the minimal surface of pgconn.PgError we need.
//
// Declared as an interface rather than importing pgx: repositories then depend
// only on database/sql, and swapping the driver does not ripple through error
// handling. Every Postgres driver worth using exposes SQLState().
type sqlStateError interface {
	SQLState() string
	Error() string
}

// sqlState extracts the SQLSTATE from a driver error, or "" if it is not one.
func sqlState(err error) string {
	var se sqlStateError
	if errors.As(err, &se) {
		return se.SQLState()
	}
	return ""
}

// isUniqueViolation reports whether err is a duplicate-key error.
func isUniqueViolation(err error) bool { return sqlState(err) == codeUniqueViolation }

// isCheckViolation reports whether err is a CHECK constraint failure, which
// means the database rejected something the domain should have caught first.
func isCheckViolation(err error) bool { return sqlState(err) == codeCheckViolation }

// Note: audit_logs' append-only trigger raises P0001, but no code path here can
// trigger it — neither the port nor the adapter exposes an update or delete for
// the ledger. It is exercised directly by TestAuditLedgerIsAppendOnlyInTheDatabase,
// which issues raw SQL to prove the database refuses it independently of Go.
