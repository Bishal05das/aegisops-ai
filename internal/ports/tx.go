package ports

import "context"

// TxManager runs a function inside a database transaction.
//
// The signature is the interesting part: the transaction is carried *on the
// context*, not passed as an argument.
//
//	err := tx.WithinTx(ctx, func(ctx context.Context) error {
//	    if err := incidents.Update(ctx, inc); err != nil { return err }
//	    return audit.Append(ctx, entry)   // same transaction
//	})
//
// The obvious alternative — threading a *sql.Tx through every service method —
// drags a database type into signatures all the way up the call stack, which
// means the domain and the use cases would depend on database/sql. That breaks
// the dependency rule the whole architecture rests on, and makes every service
// untestable without a real database.
//
// Carrying it on the context keeps repository methods identical whether they run
// inside a transaction or not: each one pulls its executor from the context and
// falls back to the pool. Services compose freely; only the adapter knows.
//
// This matters for correctness, not just tidiness. An execution row and its
// audit entry must commit together or not at all — a harness that executed an
// action but failed to record it is worse than one that did neither.
//
// Implementations must:
//
//   - roll back and re-panic if the callback panics, never leaving a
//     transaction open
//   - return the callback's error unchanged, so errors.Is still works on it
//   - refuse to nest silently: a WithinTx inside a WithinTx joins the existing
//     transaction rather than opening a second one, since Postgres has no true
//     nested transactions and a savepoint has different rollback semantics than
//     the caller would expect
type TxManager interface {
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}
