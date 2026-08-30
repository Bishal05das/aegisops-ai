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

// ToolCallRepo persists agent intents and their execution records.
//
// This is the table that answers "what did the AI try to do, and what happened".
// Rows are written for refusals as well as executions, so it is also the record
// of everything the harness stopped.
type ToolCallRepo struct {
	base
}

// NewToolCallRepo builds the adapter.
func NewToolCallRepo(db *sql.DB) *ToolCallRepo { return &ToolCallRepo{base{db: db}} }

var _ ports.ToolCallRepository = (*ToolCallRepo)(nil)

const toolCallColumns = `
	id, incident_id, task_id, agent_id, agent_name, tool, action, params, reason,
	confidence, risk, decision, decided_by, decided_at, decision_note,
	idempotency_key, created_at`

// Create inserts a request in its pending state.
func (r *ToolCallRepo) Create(ctx context.Context, req *harness.ToolCallRequest) error {
	const op = "postgres.ToolCallRepo.Create"

	if err := req.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	params, err := marshalJSON(req.Params)
	if err != nil {
		return fmt.Errorf("%s: encode params: %w", op, err)
	}

	_, err = r.exec(ctx).ExecContext(ctx, `
		INSERT INTO tool_calls (
			id, incident_id, task_id, agent_id, agent_name, tool, action, params, reason,
			confidence, risk, decision, decided_by, decided_at, decision_note,
			idempotency_key, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		req.ID, req.IncidentID, nullIDPtr(req.TaskID), req.AgentID, req.AgentName,
		req.Tool, req.Action, params, req.Reason, req.Confidence,
		nullString(string(req.Risk)), string(req.Decision), nullIDPtr(req.DecidedBy),
		req.DecidedAt, req.DecisionNote, nullString(req.IdempotencyKey), req.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			// Either the ID or the idempotency key collided. Both mean the same
			// thing to a caller: this request already exists, do not make a
			// second one.
			return fmt.Errorf("%s: %w: tool call %s", op, shared.ErrAlreadyExists, req.ID)
		}
		if sqlState(err) == codeForeignKeyViolation {
			return fmt.Errorf("%s: %w: incident %s, agent %s or task does not exist",
				op, shared.ErrNotFound, req.IncidentID, req.AgentID)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Get returns one request.
func (r *ToolCallRepo) Get(ctx context.Context, id shared.ID) (*harness.ToolCallRequest, error) {
	const op = "postgres.ToolCallRepo.Get"

	req, err := scanToolCall(r.exec(ctx).QueryRowContext(ctx,
		`SELECT `+toolCallColumns+` FROM tool_calls WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w: tool call %s", op, shared.ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return req, nil
}

// GetByIdempotencyKey returns the request a key already produced.
//
// This is what stops a redelivered tool.requested event from restarting a
// container twice: the second attempt finds the first request and reuses its
// decision instead of proposing again.
func (r *ToolCallRepo) GetByIdempotencyKey(ctx context.Context, key string) (*harness.ToolCallRequest, error) {
	const op = "postgres.ToolCallRepo.GetByIdempotencyKey"

	if key == "" {
		// An empty key would match every row whose key is NULL, which is most of
		// them. Refusing is safer than returning an arbitrary unrelated request.
		return nil, fmt.Errorf("%s: %w: the idempotency key is empty", op, shared.ErrNotFound)
	}

	req, err := scanToolCall(r.exec(ctx).QueryRowContext(ctx,
		`SELECT `+toolCallColumns+` FROM tool_calls WHERE idempotency_key = $1`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w: no tool call for key %q", op, shared.ErrNotFound, key)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return req, nil
}

// Update writes the harness's verdict.
//
// Only the decision fields and the assigned risk are writable. The agent's
// proposal — tool, action, params, reason — is immutable after insert, and
// deliberately so: those are what a human reviews when approving, and a schema
// that permitted rewriting them would let an approved request execute something
// other than what was approved.
func (r *ToolCallRepo) Update(ctx context.Context, req *harness.ToolCallRequest) error {
	const op = "postgres.ToolCallRepo.Update"

	if err := req.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	res, err := r.exec(ctx).ExecContext(ctx, `
		UPDATE tool_calls SET
			risk = $1, decision = $2, decided_by = $3, decided_at = $4, decision_note = $5
		WHERE id = $6`,
		nullString(string(req.Risk)), string(req.Decision), nullIDPtr(req.DecidedBy),
		req.DecidedAt, req.DecisionNote, req.ID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return requireOneRow(op, res, shared.ErrNotFound, "tool call "+req.ID.String())
}

// List returns a filtered page, newest first.
//
// Descending because the commonest reads are an operator's approval queue and a
// responder asking what just happened. Both want the most recent first, unlike
// the task list, which reads as a narrative.
func (r *ToolCallRepo) List(ctx context.Context, f ports.ToolCallFilter, p ports.Page) (ports.PageResult[*harness.ToolCallRequest], error) {
	const op = "postgres.ToolCallRepo.List"
	var zero ports.PageResult[*harness.ToolCallRequest]

	p = p.Normalise()
	var where []string
	var args []any

	if f.IncidentID != nil {
		args = append(args, *f.IncidentID)
		where = append(where, fmt.Sprintf("incident_id = $%d", len(args)))
	}
	if f.AgentID != nil {
		args = append(args, *f.AgentID)
		where = append(where, fmt.Sprintf("agent_id = $%d", len(args)))
	}
	if len(f.Decisions) > 0 {
		args = append(args, stringsOf(f.Decisions))
		where = append(where, fmt.Sprintf("decision = ANY($%d)", len(args)))
	}
	if len(f.Risks) > 0 {
		args = append(args, stringsOf(f.Risks))
		where = append(where, fmt.Sprintf("risk = ANY($%d)", len(args)))
	}
	if f.PendingApproval {
		// A literal rather than a parameter: the value is a compile-time
		// constant of the domain, not caller input.
		where = append(where, "decision = 'awaiting_approval'")
	}
	if p.Cursor != "" {
		ts, id, err := decodeCursor(p.Cursor)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		args = append(args, ts, id)
		where = append(where, fmt.Sprintf("(created_at, id) < ($%d, $%d)", len(args)-1, len(args)))
	}

	args = append(args, p.Limit+1)
	query := `SELECT ` + toolCallColumns + ` FROM tool_calls` + whereClause(where) +
		` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args))

	rows, err := r.exec(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]*harness.ToolCallRequest, 0, p.Limit)
	for rows.Next() {
		req, err := scanToolCall(rows)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		items = append(items, req)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("%s: iterate: %w", op, err)
	}

	res := ports.PageResult[*harness.ToolCallRequest]{Items: items}
	if len(items) > p.Limit {
		res.Items = items[:p.Limit]
		res.HasMore = true
		last := res.Items[len(res.Items)-1]
		res.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	return res, nil
}

// SaveExecution records what happened when the tool ran.
//
// The unique constraint on tool_call_id is doing security work, not tidiness:
// it is what makes a double execution impossible to record and therefore visible
// when attempted. A caller that receives ErrAlreadyExists learns that something
// else already ran this call.
func (r *ToolCallRepo) SaveExecution(ctx context.Context, e *harness.Execution) error {
	const op = "postgres.ToolCallRepo.SaveExecution"

	if err := e.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err := r.exec(ctx).ExecContext(ctx, `
		INSERT INTO executions (
			id, tool_call_id, status, dry_run, exit_code, stdout, stderr,
			truncated, error, started_at, finished_at, duration_ms, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		e.ID, e.ToolCallID, string(e.Status), e.DryRun, e.ExitCode, e.Stdout, e.Stderr,
		e.Truncated, e.Error, e.StartedAt, e.FinishedAt, e.DurationMS, e.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%s: %w: tool call %s has already been executed",
				op, shared.ErrAlreadyExists, e.ToolCallID)
		}
		if sqlState(err) == codeForeignKeyViolation {
			return fmt.Errorf("%s: %w: tool call %s does not exist",
				op, shared.ErrNotFound, e.ToolCallID)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// GetExecution returns a tool call's execution record.
func (r *ToolCallRepo) GetExecution(ctx context.Context, toolCallID shared.ID) (*harness.Execution, error) {
	const op = "postgres.ToolCallRepo.GetExecution"

	var (
		e        harness.Execution
		status   string
		exitCode sql.Null[int]
	)
	err := r.exec(ctx).QueryRowContext(ctx, `
		SELECT id, tool_call_id, status, dry_run, exit_code, stdout, stderr,
		       truncated, error, started_at, finished_at, duration_ms, created_at
		FROM executions WHERE tool_call_id = $1`, toolCallID).
		Scan(&e.ID, &e.ToolCallID, &status, &e.DryRun, &exitCode, &e.Stdout, &e.Stderr,
			&e.Truncated, &e.Error, &e.StartedAt, &e.FinishedAt, &e.DurationMS, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w: no execution for tool call %s",
			op, shared.ErrNotFound, toolCallID)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	e.Status = harness.ExecStatus(status)
	if exitCode.Valid {
		code := exitCode.V
		e.ExitCode = &code
	}
	return &e, nil
}

func scanToolCall(s rowScanner) (*harness.ToolCallRequest, error) {
	var (
		req       harness.ToolCallRequest
		taskID    sql.Null[shared.ID]
		decidedBy sql.Null[shared.ID]
		risk      sql.NullString
		idemKey   sql.NullString
		decision  string
		params    []byte
	)
	err := s.Scan(
		&req.ID, &req.IncidentID, &taskID, &req.AgentID, &req.AgentName,
		&req.Tool, &req.Action, &params, &req.Reason, &req.Confidence,
		&risk, &decision, &decidedBy, &req.DecidedAt, &req.DecisionNote,
		&idemKey, &req.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	req.Decision = harness.Decision(decision)
	req.Risk = harness.Risk(risk.String)
	req.IdempotencyKey = idemKey.String
	if taskID.Valid {
		id := taskID.V
		req.TaskID = &id
	}
	if decidedBy.Valid {
		id := decidedBy.V
		req.DecidedBy = &id
	}
	if err := unmarshalJSON(params, &req.Params); err != nil {
		return nil, fmt.Errorf("decode params: %w", err)
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	return &req, nil
}
