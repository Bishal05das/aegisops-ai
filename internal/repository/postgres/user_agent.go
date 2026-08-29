package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------

// UserRepo persists user accounts.
type UserRepo struct {
	base
}

// NewUserRepo builds the adapter.
func NewUserRepo(db *sql.DB) *UserRepo { return &UserRepo{base{db: db}} }

var _ ports.UserRepository = (*UserRepo)(nil)

const userColumns = `id, email, name, role, password_hash, active, last_login_at, created_at, updated_at`

// Create inserts a user.
func (r *UserRepo) Create(ctx context.Context, u *user.User) error {
	const op = "postgres.UserRepo.Create"

	if err := u.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err := r.exec(ctx).ExecContext(ctx, `
		INSERT INTO users (id, email, name, role, password_hash, active, last_login_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		u.ID, u.Email, u.Name, string(u.Role), u.PasswordHash, u.Active,
		u.LastLoginAt, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%s: %w: a user with email %q already exists", op, shared.ErrAlreadyExists, u.Email)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Get returns one user by ID.
func (r *UserRepo) Get(ctx context.Context, id user.ID) (*user.User, error) {
	const op = "postgres.UserRepo.Get"

	u, err := scanUser(r.exec(ctx).QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w: user %s", op, shared.ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return u, nil
}

// GetByEmail is the authentication lookup.
//
// The address is normalised here rather than trusting the caller: this is the
// one query where a case mismatch means a valid login is rejected, and relying
// on every call site to remember would eventually fail.
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	const op = "postgres.UserRepo.GetByEmail"

	u, err := scanUser(r.exec(ctx).QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = $1`, user.NormaliseEmail(email)))
	if errors.Is(err, sql.ErrNoRows) {
		// Deliberately does not echo the address back: this error can reach an
		// unauthenticated caller, and confirming which addresses exist is user
		// enumeration.
		return nil, fmt.Errorf("%s: %w: no such user", op, shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return u, nil
}

// Update writes a user's mutable fields.
func (r *UserRepo) Update(ctx context.Context, u *user.User) error {
	const op = "postgres.UserRepo.Update"

	if err := u.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	res, err := r.exec(ctx).ExecContext(ctx, `
		UPDATE users SET email = $1, name = $2, role = $3, password_hash = $4,
		                 active = $5, updated_at = $6
		WHERE id = $7`,
		u.Email, u.Name, string(u.Role), u.PasswordHash, u.Active, u.UpdatedAt, u.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%s: %w: email %q is taken", op, shared.ErrAlreadyExists, u.Email)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return requireOneRow(op, res, shared.ErrNotFound, "user "+u.ID.String())
}

// List returns a page of users, oldest first.
func (r *UserRepo) List(ctx context.Context, p ports.Page) (ports.PageResult[*user.User], error) {
	const op = "postgres.UserRepo.List"
	var zero ports.PageResult[*user.User]

	p = p.Normalise()
	args := []any{}
	var where []string

	if p.Cursor != "" {
		ts, id, err := decodeCursor(p.Cursor)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		args = append(args, ts, id)
		where = append(where, "(created_at, id) > ($1, $2)")
	}

	args = append(args, p.Limit+1)
	query := `SELECT ` + userColumns + ` FROM users` + whereClause(where) +
		` ORDER BY created_at ASC, id ASC LIMIT $` + strconv.Itoa(len(args))

	rows, err := r.exec(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]*user.User, 0, p.Limit)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		items = append(items, u)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("%s: iterate: %w", op, err)
	}

	res := ports.PageResult[*user.User]{Items: items}
	if len(items) > p.Limit {
		res.Items = items[:p.Limit]
		res.HasMore = true
		last := res.Items[len(res.Items)-1]
		res.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	return res, nil
}

// RecordLogin stamps a successful authentication.
//
// A targeted UPDATE rather than a read-modify-write through Update: logins are
// frequent and concurrent, and rewriting the whole row would let two sessions
// clobber an unrelated field.
func (r *UserRepo) RecordLogin(ctx context.Context, id user.ID, at time.Time) error {
	const op = "postgres.UserRepo.RecordLogin"

	res, err := r.exec(ctx).ExecContext(ctx,
		`UPDATE users SET last_login_at = $1, updated_at = $1 WHERE id = $2`, at, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return requireOneRow(op, res, shared.ErrNotFound, "user "+id.String())
}

func scanUser(s rowScanner) (*user.User, error) {
	var (
		u    user.User
		role string
		hash []byte
	)
	err := s.Scan(&u.ID, &u.Email, &u.Name, &role, &hash, &u.Active,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.Role = user.Role(role)
	u.PasswordHash = hash
	return &u, nil
}

// -----------------------------------------------------------------------------
// Agents
// -----------------------------------------------------------------------------

// AgentRepo persists agent registrations.
type AgentRepo struct {
	base
}

// NewAgentRepo builds the adapter.
func NewAgentRepo(db *sql.DB) *AgentRepo { return &AgentRepo{base{db: db}} }

var _ ports.AgentRepository = (*AgentRepo)(nil)

const agentColumns = `id, name, kind, description, enabled, config, created_at, updated_at`

// Create inserts an agent registration.
func (r *AgentRepo) Create(ctx context.Context, a *agent.Agent) error {
	const op = "postgres.AgentRepo.Create"

	if err := a.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	config, err := marshalJSON(a.Config)
	if err != nil {
		return fmt.Errorf("%s: encode config: %w", op, err)
	}

	_, err = r.exec(ctx).ExecContext(ctx, `
		INSERT INTO agents (id, name, kind, description, enabled, config, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.ID, a.Name, string(a.Kind), a.Description, a.Enabled, config, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%s: %w: agent %q", op, shared.ErrAlreadyExists, a.Name)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Get returns one agent by ID.
func (r *AgentRepo) Get(ctx context.Context, id agent.ID) (*agent.Agent, error) {
	const op = "postgres.AgentRepo.Get"

	a, err := scanAgent(r.exec(ctx).QueryRowContext(ctx,
		`SELECT `+agentColumns+` FROM agents WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w: agent %s", op, shared.ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return a, nil
}

// GetByName returns one agent by its unique name.
func (r *AgentRepo) GetByName(ctx context.Context, name string) (*agent.Agent, error) {
	const op = "postgres.AgentRepo.GetByName"

	a, err := scanAgent(r.exec(ctx).QueryRowContext(ctx,
		`SELECT `+agentColumns+` FROM agents WHERE name = $1`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w: agent %q", op, shared.ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return a, nil
}

// List returns every registered agent, by name.
//
// Unpaginated: the roster is seven rows and closed by a CHECK constraint.
// Pagination here would be ceremony.
func (r *AgentRepo) List(ctx context.Context) ([]*agent.Agent, error) {
	const op = "postgres.AgentRepo.List"

	rows, err := r.exec(ctx).QueryContext(ctx,
		`SELECT `+agentColumns+` FROM agents ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*agent.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: iterate: %w", op, err)
	}
	return out, nil
}

// Update writes an agent's mutable fields.
func (r *AgentRepo) Update(ctx context.Context, a *agent.Agent) error {
	const op = "postgres.AgentRepo.Update"

	if err := a.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	config, err := marshalJSON(a.Config)
	if err != nil {
		return fmt.Errorf("%s: encode config: %w", op, err)
	}

	res, err := r.exec(ctx).ExecContext(ctx, `
		UPDATE agents SET name = $1, kind = $2, description = $3, enabled = $4,
		                  config = $5, updated_at = $6
		WHERE id = $7`,
		a.Name, string(a.Kind), a.Description, a.Enabled, config, a.UpdatedAt, a.ID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return requireOneRow(op, res, shared.ErrNotFound, "agent "+a.ID.String())
}

// Upsert registers an agent or updates it in place, keyed on name.
//
// The orchestrator calls this at startup so the roster is reconciled from code.
// A seed migration would drift the moment an agent's description changed, and
// would need a new migration for every such edit.
//
// The row's own ID and created_at are preserved on conflict: rewriting them
// would orphan every agent_task and tool_call that references this agent.
func (r *AgentRepo) Upsert(ctx context.Context, a *agent.Agent) error {
	const op = "postgres.AgentRepo.Upsert"

	if err := a.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	config, err := marshalJSON(a.Config)
	if err != nil {
		return fmt.Errorf("%s: encode config: %w", op, err)
	}

	err = r.exec(ctx).QueryRowContext(ctx, `
		INSERT INTO agents (id, name, kind, description, enabled, config, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (name) DO UPDATE SET
			kind        = EXCLUDED.kind,
			description = EXCLUDED.description,
			config      = EXCLUDED.config,
			updated_at  = EXCLUDED.updated_at
		RETURNING id, created_at`,
		a.ID, a.Name, string(a.Kind), a.Description, a.Enabled, config, a.CreatedAt, a.UpdatedAt,
	).Scan(&a.ID, &a.CreatedAt)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func scanAgent(s rowScanner) (*agent.Agent, error) {
	var (
		a      agent.Agent
		kind   string
		config []byte
	)
	if err := s.Scan(&a.ID, &a.Name, &kind, &a.Description, &a.Enabled, &config,
		&a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, err
	}
	a.Kind = agent.Kind(kind)
	if err := unmarshalJSON(config, &a.Config); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if a.Config == nil {
		a.Config = map[string]any{}
	}
	return &a, nil
}

// requireOneRow turns a zero-row UPDATE into a typed error.
//
// database/sql reports success for an UPDATE that matched nothing, which is
// almost never what a caller means — they asked to modify a specific row, and
// it was not there.
func requireOneRow(op string, res sql.Result, sentinel error, subject string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: rows affected: %w", op, err)
	}
	if n == 0 {
		return fmt.Errorf("%s: %w: %s", op, sentinel, subject)
	}
	return nil
}
