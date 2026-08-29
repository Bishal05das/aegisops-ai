package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// TaskRepo persists agent tasks.
//
// Deferred from Phase 3 on purpose: writing it then would have meant writing it
// against guessed requirements. The orchestrator now exists and its needs are
// known, so the queries here serve real call sites.
type TaskRepo struct {
	base
}

// NewTaskRepo builds the adapter.
func NewTaskRepo(db *sql.DB) *TaskRepo { return &TaskRepo{base{db: db}} }

var _ ports.TaskRepository = (*TaskRepo)(nil)

const taskColumns = `
	id, incident_id, agent_id, parent_task_id, type, status,
	input, output, error, attempts, started_at, finished_at, created_at, updated_at`

// Create inserts a task.
//
// Written before the agent runs, not after, so a crash mid-investigation leaves
// a `running` row rather than no record at all — the difference between "an
// agent was working and did not finish" and silence.
func (r *TaskRepo) Create(ctx context.Context, t *agent.Task) error {
	const op = "postgres.TaskRepo.Create"

	if err := t.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	input, err := marshalJSON(t.Input)
	if err != nil {
		return fmt.Errorf("%s: encode input: %w", op, err)
	}
	output, err := marshalJSON(t.Output)
	if err != nil {
		return fmt.Errorf("%s: encode output: %w", op, err)
	}

	_, err = r.exec(ctx).ExecContext(ctx, `
		INSERT INTO agent_tasks (
			id, incident_id, agent_id, parent_task_id, type, status,
			input, output, error, attempts, started_at, finished_at, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		t.ID, t.IncidentID, t.AgentID, nullIDPtr(t.ParentID), t.Type, string(t.Status),
		input, output, t.Error, t.Attempts, t.StartedAt, t.FinishedAt, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%s: %w: task %s", op, shared.ErrAlreadyExists, t.ID)
		}
		if sqlState(err) == codeForeignKeyViolation {
			// Names both candidates: an agent that was never registered is by
			// far the commonest cause, and a bare FK error sends someone
			// looking at the wrong table.
			return fmt.Errorf("%s: %w: incident %s or agent %s does not exist",
				op, shared.ErrNotFound, t.IncidentID, t.AgentID)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Get returns one task.
func (r *TaskRepo) Get(ctx context.Context, id shared.ID) (*agent.Task, error) {
	const op = "postgres.TaskRepo.Get"

	t, err := scanTask(r.exec(ctx).QueryRowContext(ctx,
		`SELECT `+taskColumns+` FROM agent_tasks WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w: task %s", op, shared.ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return t, nil
}

// Update writes a task's mutable fields.
//
// No optimistic locking, unlike incidents, and the asymmetry is deliberate: a
// task has exactly one writer — the goroutine running that agent — so there is
// no concurrent update to lose. Adding a version column would cost a round trip
// to defend against a race that cannot occur.
func (r *TaskRepo) Update(ctx context.Context, t *agent.Task) error {
	const op = "postgres.TaskRepo.Update"

	if err := t.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	output, err := marshalJSON(t.Output)
	if err != nil {
		return fmt.Errorf("%s: encode output: %w", op, err)
	}

	res, err := r.exec(ctx).ExecContext(ctx, `
		UPDATE agent_tasks SET
			status = $1, output = $2, error = $3, attempts = $4,
			started_at = $5, finished_at = $6, updated_at = $7
		WHERE id = $8`,
		string(t.Status), output, t.Error, t.Attempts,
		t.StartedAt, t.FinishedAt, t.UpdatedAt, t.ID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return requireOneRow(op, res, shared.ErrNotFound, "task "+t.ID.String())
}

// List returns a filtered page of tasks, oldest first.
//
// Ascending because a task list is read as a narrative — what the agents did, in
// the order they did it — unlike incidents, where the newest matters most.
func (r *TaskRepo) List(ctx context.Context, f ports.TaskFilter, p ports.Page) (ports.PageResult[*agent.Task], error) {
	const op = "postgres.TaskRepo.List"
	var zero ports.PageResult[*agent.Task]

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
	if len(f.Statuses) > 0 {
		args = append(args, stringsOf(f.Statuses))
		where = append(where, fmt.Sprintf("status = ANY($%d)", len(args)))
	}
	if p.Cursor != "" {
		ts, id, err := decodeCursor(p.Cursor)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		args = append(args, ts, id)
		where = append(where, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}

	args = append(args, p.Limit+1)
	query := `SELECT ` + taskColumns + ` FROM agent_tasks` + whereClause(where) +
		` ORDER BY created_at ASC, id ASC LIMIT $` + strconv.Itoa(len(args))

	rows, err := r.exec(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]*agent.Task, 0, p.Limit)
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		items = append(items, t)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("%s: iterate: %w", op, err)
	}

	res := ports.PageResult[*agent.Task]{Items: items}
	if len(items) > p.Limit {
		res.Items = items[:p.Limit]
		res.HasMore = true
		last := res.Items[len(res.Items)-1]
		res.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	return res, nil
}

func scanTask(s rowScanner) (*agent.Task, error) {
	var (
		t             agent.Task
		status        string
		parentID      sql.Null[shared.ID]
		input, output []byte
	)
	err := s.Scan(
		&t.ID, &t.IncidentID, &t.AgentID, &parentID, &t.Type, &status,
		&input, &output, &t.Error, &t.Attempts,
		&t.StartedAt, &t.FinishedAt, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	t.Status = agent.TaskStatus(status)
	if parentID.Valid {
		id := parentID.V
		t.ParentID = &id
	}
	if err := unmarshalJSON(input, &t.Input); err != nil {
		return nil, fmt.Errorf("decode input: %w", err)
	}
	if err := unmarshalJSON(output, &t.Output); err != nil {
		return nil, fmt.Errorf("decode output: %w", err)
	}
	if t.Input == nil {
		t.Input = map[string]any{}
	}
	if t.Output == nil {
		t.Output = map[string]any{}
	}
	return &t, nil
}
