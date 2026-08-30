package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// AuditRepo is the append-only ledger.
//
// There is no Update and no Delete, here or on the port. The database enforces
// the same thing with a trigger, so a bug, a migration or a hand-typed UPDATE in
// psql are all refused. A ledger's value comes from being immutable, and a
// convention is not immutability.
type AuditRepo struct {
	base
}

// NewAuditRepo builds the adapter.
func NewAuditRepo(db *sql.DB) *AuditRepo { return &AuditRepo{base{db: db}} }

var _ ports.AuditRepository = (*AuditRepo)(nil)

// auditLockID serialises sequence assignment across every writer.
//
// Distinct from the migration lock so a long migration cannot block audit
// writes, and vice versa.
const auditLockID int64 = 0x4145_4749_5300_0002 // "AEGIS" + 2

const auditColumns = `
	id, seq, occurred_at, actor_type, actor_id, actor_name,
	action, resource_type, resource_id, incident_id, tool_call_id,
	outcome, reason, params, result, error,
	request_id, build_version, prev_hash, hash`

// Append writes one entry, assigning its sequence and linking the hash chain.
//
// Why this needs a lock at all: the chain is only meaningful if entry N commits
// against the hash of entry N-1. Two writers reading `max(seq)` concurrently
// would both compute a chain from the same predecessor, and one would either
// fail the unique index or — if the index were missing — produce a fork that
// verification could not distinguish from tampering.
//
// pg_advisory_xact_lock is transaction-scoped, so it releases on commit or
// rollback with no explicit unlock and no risk of leaking the lock on a panic.
// It serialises only the audit ledger, and the critical section is a single
// round trip.
func (r *AuditRepo) Append(ctx context.Context, e *harness.AuditEntry) error {
	const op = "postgres.AuditRepo.Append"

	if err := e.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	params, err := marshalJSON(e.Params)
	if err != nil {
		return fmt.Errorf("%s: encode params: %w", op, err)
	}
	result, err := marshalJSON(e.Result)
	if err != nil {
		return fmt.Errorf("%s: encode result: %w", op, err)
	}

	// Appending must be atomic with reading the predecessor, so it always runs
	// in a transaction. If the caller already opened one — the common case,
	// since an execution and its audit row must commit together — this joins it.
	write := func(ctx context.Context) error {
		ex := r.exec(ctx)

		if _, err := ex.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, auditLockID); err != nil {
			return fmt.Errorf("%s: acquire ledger lock: %w", op, err)
		}

		var prevSeq int64
		var prevHash []byte
		err := ex.QueryRowContext(ctx,
			`SELECT seq, hash FROM audit_logs ORDER BY seq DESC LIMIT 1`).Scan(&prevSeq, &prevHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%s: read ledger head: %w", op, err)
		}
		// On an empty ledger the genesis entry chains from nil, which VerifyChain
		// mirrors by starting with a nil hash.

		e.Seq = prevSeq + 1
		e.PrevHash = prevHash
		e.Hash = e.ComputeHash(prevHash)

		_, err = ex.ExecContext(ctx, `
			INSERT INTO audit_logs (
				id, seq, occurred_at, actor_type, actor_id, actor_name,
				action, resource_type, resource_id, incident_id, tool_call_id,
				outcome, reason, params, result, error,
				request_id, build_version, prev_hash, hash
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
			e.ID, e.Seq, e.OccurredAt, e.ActorType, nullID(e.ActorID), e.ActorName,
			e.Action, e.ResourceType, e.ResourceID,
			nullIDPtr(e.IncidentID), nullIDPtr(e.ToolCallID),
			string(e.Outcome), e.Reason, params, result, e.Error,
			e.RequestID, e.BuildVersion, e.PrevHash, e.Hash,
		)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%s: %w: ledger sequence %d already exists", op, shared.ErrConflict, e.Seq)
			}
			return fmt.Errorf("%s: %w", op, err)
		}
		return nil
	}

	if _, inTx := txFrom(ctx); inTx {
		return write(ctx)
	}
	return NewTxManager(r.db).WithinTx(ctx, write)
}

// List returns a filtered page of ledger entries, newest first.
func (r *AuditRepo) List(ctx context.Context, f ports.AuditFilter, p ports.Page) (ports.PageResult[*harness.AuditEntry], error) {
	const op = "postgres.AuditRepo.List"
	var zero ports.PageResult[*harness.AuditEntry]

	p = p.Normalise()
	var where []string
	var args []any

	if f.IncidentID != nil {
		args = append(args, *f.IncidentID)
		where = append(where, fmt.Sprintf("incident_id = $%d", len(args)))
	}
	if f.ActorID != nil {
		args = append(args, *f.ActorID)
		where = append(where, fmt.Sprintf("actor_id = $%d", len(args)))
	}
	if f.ActorType != "" {
		args = append(args, f.ActorType)
		where = append(where, fmt.Sprintf("actor_type = $%d", len(args)))
	}
	if f.Action != "" {
		args = append(args, f.Action)
		where = append(where, fmt.Sprintf("action = $%d", len(args)))
	}
	if len(f.Outcomes) > 0 {
		args = append(args, stringsOf(f.Outcomes))
		where = append(where, fmt.Sprintf("outcome = ANY($%d)", len(args)))
	}
	if f.Since != nil {
		args = append(args, *f.Since)
		where = append(where, fmt.Sprintf("occurred_at >= $%d", len(args)))
	}
	if f.Until != nil {
		args = append(args, *f.Until)
		where = append(where, fmt.Sprintf("occurred_at <= $%d", len(args)))
	}

	// The ledger's own sequence is the cursor: monotonic, unique and already
	// indexed, so no composite key or timestamp tiebreak is needed.
	if p.Cursor != "" {
		before, err := strconv.ParseInt(p.Cursor, 10, 64)
		if err != nil {
			return zero, fmt.Errorf("%s: %w: cursor %q is not a sequence number",
				op, shared.ErrValidation, p.Cursor)
		}
		args = append(args, before)
		where = append(where, fmt.Sprintf("seq < $%d", len(args)))
	}

	args = append(args, p.Limit+1)
	query := `SELECT ` + auditColumns + ` FROM audit_logs` + whereClause(where) +
		` ORDER BY seq DESC LIMIT $` + strconv.Itoa(len(args))

	rows, err := r.exec(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]*harness.AuditEntry, 0, p.Limit)
	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("%s: iterate: %w", op, err)
	}

	res := ports.PageResult[*harness.AuditEntry]{Items: items}
	if len(items) > p.Limit {
		res.Items = items[:p.Limit]
		res.HasMore = true
		res.NextCursor = strconv.FormatInt(res.Items[len(res.Items)-1].Seq, 10)
	}
	return res, nil
}

// VerifyChain recomputes the hash chain over a sequence range.
//
// This is what makes the chain worth having. Rows are read in ascending order
// and each hash is recomputed from its predecessor; a mismatch means the row was
// edited or one before it was removed.
//
// The starting hash is read from the entry immediately before fromSeq, so a
// range can be verified without walking the ledger from the beginning.
func (r *AuditRepo) VerifyChain(ctx context.Context, fromSeq, toSeq int64) (harness.ChainVerification, error) {
	const op = "postgres.AuditRepo.VerifyChain"

	if fromSeq < 1 {
		fromSeq = 1
	}
	if toSeq > 0 && toSeq < fromSeq {
		return harness.ChainVerification{}, fmt.Errorf(
			"%s: %w: toSeq %d is before fromSeq %d", op, shared.ErrValidation, toSeq, fromSeq)
	}

	// The predecessor's hash anchors the range. Absent (fromSeq is 1, or the
	// ledger is empty) the chain starts from nil, matching Append's genesis.
	var startHash []byte
	err := r.exec(ctx).QueryRowContext(ctx,
		`SELECT hash FROM audit_logs WHERE seq < $1 ORDER BY seq DESC LIMIT 1`, fromSeq).Scan(&startHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return harness.ChainVerification{}, fmt.Errorf("%s: read anchor: %w", op, err)
	}

	query := `SELECT ` + auditColumns + ` FROM audit_logs WHERE seq >= $1`
	args := []any{fromSeq}
	if toSeq > 0 {
		args = append(args, toSeq)
		query += ` AND seq <= $2`
	}
	query += ` ORDER BY seq ASC`

	rows, err := r.exec(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return harness.ChainVerification{}, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*harness.AuditEntry
	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			return harness.ChainVerification{}, fmt.Errorf("%s: %w", op, err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return harness.ChainVerification{}, fmt.Errorf("%s: iterate: %w", op, err)
	}

	// A gap in the sequence is a removed row. The hash comparison would catch
	// it too, but naming it precisely is far more useful to an investigator
	// than "hash mismatch at 57".
	for i, e := range entries {
		want := fromSeq + int64(i)
		if e.Seq != want {
			return harness.ChainVerification{
				Checked:     len(entries),
				Valid:       false,
				BrokenAtSeq: want,
				Reason: fmt.Sprintf(
					"ledger sequence %d is missing; entries jump from %d to %d",
					want, want-1, e.Seq),
			}, nil
		}
	}

	return harness.VerifyChain(entries, startHash), nil
}

// LatestSeq returns the highest assigned sequence, or 0 on an empty ledger.
func (r *AuditRepo) LatestSeq(ctx context.Context) (int64, error) {
	const op = "postgres.AuditRepo.LatestSeq"

	var seq sql.NullInt64
	if err := r.exec(ctx).QueryRowContext(ctx,
		`SELECT max(seq) FROM audit_logs`).Scan(&seq); err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	if !seq.Valid {
		return 0, nil
	}
	return seq.Int64, nil
}

func scanAuditEntry(s rowScanner) (*harness.AuditEntry, error) {
	var (
		e             harness.AuditEntry
		actorID       sql.Null[shared.ID]
		incidentID    sql.Null[shared.ID]
		toolCallID    sql.Null[shared.ID]
		outcome       string
		params, resul []byte
	)
	err := s.Scan(
		&e.ID, &e.Seq, &e.OccurredAt, &e.ActorType, &actorID, &e.ActorName,
		&e.Action, &e.ResourceType, &e.ResourceID, &incidentID, &toolCallID,
		&outcome, &e.Reason, &params, &resul, &e.Error,
		&e.RequestID, &e.BuildVersion, &e.PrevHash, &e.Hash,
	)
	if err != nil {
		return nil, err
	}

	e.Outcome = harness.Outcome(outcome)
	if actorID.Valid {
		e.ActorID = actorID.V
	}
	if incidentID.Valid {
		id := incidentID.V
		e.IncidentID = &id
	}
	if toolCallID.Valid {
		id := toolCallID.V
		e.ToolCallID = &id
	}
	if err := unmarshalJSON(params, &e.Params); err != nil {
		return nil, fmt.Errorf("decode params: %w", err)
	}
	if err := unmarshalJSON(resul, &e.Result); err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}
	return &e, nil
}

// nullIDPtr converts an optional ID pointer to SQL NULL.
func nullIDPtr(id *shared.ID) any {
	if id == nil || id.IsZero() {
		return nil
	}
	return *id
}

// nullString converts an empty string to SQL NULL.
//
// Needed where a column is nullable with a uniqueness constraint: Postgres
// treats NULLs as distinct, so a NULL idempotency key does not collide with
// another NULL, whereas many rows carrying ” would.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
